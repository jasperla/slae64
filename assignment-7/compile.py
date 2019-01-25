#!/usr/bin/env python3
#
# Copyright (c) 2019 Jasper Lievisse Adriaanse <j@jasper.la>
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

import argparse
import base64
import os.path
import re
import subprocess
import sys

from Crypto.Cipher import ChaCha20
import Crypto.Random


class Compile():
  def __init__(self, file, define, linker, compiler, wrapper):
    self.sourcefile = file
    self.basename = os.path.basename(self.sourcefile.replace('.nasm', ''))
    self.objectfile = '{}.o'.format(self.basename)
    self.define = define
    self.linker = linker
    self.compiler = compiler
    self.bytecode = []

    if wrapper:
      self.wrapper = 'shellcode-{}.c'.format(self.basename)
      self.wrapper_output = 'shellcode-{}'.format(self.basename)
    else:
      self.wrapper = None

    self.check_progs()

  def check_progs(self):
    # Ensure the required binaries are available:
    progs = ['nasm', self.linker]

    if self.wrapper:
      progs.append(self.compiler)

    for p in progs:
      try:
        subprocess.call([p, '-v'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
      except Exception as e:
        err('Required binary for {} not found'.format(p))

  def assemble(self):
    info('Assembling {}'.format(self.sourcefile))

    cmd = ['nasm', '-felf64', '-o', self.objectfile, self.sourcefile]

    if self.define:
      cmd.append('-D{}'.format(self.define))

    try:
      subprocess.check_output(cmd, stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError as e:
      err('Invoked command "{}" failed!\n    Captured output: {}\n   '.format(' '.join(cmd), str(e.output.strip())))

  def link(self):
    info('Linking {}'.format(self.objectfile))

    cmd = [self.linker, '-o', self.basename, self.objectfile]
    try:
      subprocess.check_output(cmd, stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError as e:
      err('Invoked command "{}" failed!\n    Captured output: {}\n   '.format(' '.join(cmd), str(e.output.strip())))

  def dumpcode(self):
    info('Extracting and analyzing byte code')
    nulls_found = False

    try:
        p = subprocess.Popen('objdump -D -M intel {}'.format(self.objectfile).split(), stdout=subprocess.PIPE)
        for line in p.stdout:
            line = line.decode()
            m = re.match('^\s+\w+:\t(.*?)\s+(\t|\n)', line)
            if m:
                code = m.groups()[0]
                [self.bytecode.append(x) for x in code.split()]
    except Exception as e:
        err('Failed to extract bytecode from {}: {}'.format(self.objectfile, e))

    if '00' in self.bytecode:
        warn('NULL bytes were found, are you sure this is ok?')
    else:
        ok('No NULL bytes found')

    info('Shellcode length: {}'.format(len(self.bytecode)))

    # Turn the bytecode list into a string such as '\x90\x90'
    self.shellcode = ''.join(['\\x{}'.format(x) for x in self.bytecode])

  def compilec(self, verbose_wrapper=True, cleanup=False):
    if not self.wrapper:
      err('You called the wrapper compile function but the wrapper is disabled.')

    info('Compiling {}'.format(self.wrapper))

    if verbose_wrapper:
      wrapper_template = f"""
#include <stdio.h>
#include <string.h>

char code[] = "{self.shellcode}";

int
main(int argc, int argv[]) {{
  printf("Shellcode length: %ld\\n", strlen(code));
  (*(void (*)()) code)();
  return 0;
}}
"""
    else:
      wrapper_template = f"""
#include <stdio.h>
#include <string.h>

char code[] = "{self.shellcode}";

int
main(int argc, int argv[]) {{
  (*(void (*)()) code)();
  return 0;
}}
"""

    fh = open(self.wrapper, 'w')
    fh.write(wrapper_template)
    fh.close()

    # Compile the wrapper
    cmd = [self.compiler, '-o', self.wrapper_output, '-fno-stack-protector', '-z', 'execstack', self.wrapper]
    try:
      subprocess.check_output(cmd, stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError as e:
      err('Invoked command "{}" failed!\n    Captured output: {}\n   '.format(' '.join(cmd), str(e.output.strip())))

    if cleanup:
      try:
        os.unlink(self.wrapper)
      except Exception as e:
        err('Failed to cleanup after compiling wrapper')

  def compile(self):
    self.assemble()
    self.link()
    self.dumpcode()
    if self.wrapper:
       self.compilec()


class Crypter():
  def __init__(self, key, nonce, filename, shellcode, compiler):
    self.key = key
    self.nonce = nonce
    self.filename = filename
    self.shellcode = shellcode
    self.compiler = compiler

  def encrypt(self):
    key = Crypto.Random.get_random_bytes(32)
    info('Generated key (base64 encoded): {}'.format(base64.b64encode(key).decode('utf-8')))
    cipher = ChaCha20.new(key = key)

    try:
      encrypted_code = cipher.encrypt(self.shellcode.encode('ascii'))
    except Exception as e:
      err('Failed to encrypt: {}'.format(e))

    nonce = base64.b64encode(cipher.nonce).decode('utf-8')
    info('Nonce (base64 encoded): {}'.format(nonce))

    output_file = os.path.basename(self.filename.replace('.nasm', '.enc'))

    try:
      fh = open(output_file, 'wb')
      fh.write(encrypted_code)
      fh.close()
    except Exception as e:
      err('Failed to write encrypted bytecode to {}: {}'.format(output_file, e))
    else:
      info('Saved encrypted bytecode to {}'.format(output_file))

  def decrypt(self):
    try:
      fh = open(self.filename, 'rb')
      encrypted_code = fh.read()
      fh.close()
    except Exception as e:
      err('Failed to read encrypted bytefrom from {}: {}'.format(self.filename, e))

    bin_name = os.path.basename(self.filename.replace('.enc', '.bin'))

    key = base64.b64decode(self.key)
    nonce = base64.b64decode(self.nonce)
    decipher = ChaCha20.new(key=key, nonce=nonce)
    self.compiler.shellcode = decipher.decrypt(encrypted_code).decode('utf-8')
    self.compiler.wrapper_output = bin_name
    self.compiler.compilec(verbose_wrapper=False, cleanup=True)

    info('Decrypted shellcode compiled to {}'.format(bin_name))


def err(msg, return_code=1):
  print('[-] {}'.format(msg))
  if return_code:
    sys.exit(return_code)

def warn(msg):
    err(msg, None)

def info(msg):
  print('[*] {}'.format(msg))

def ok(msg):
  print('[+] {}'.format(msg))

def main():
  parser = argparse.ArgumentParser()

  # compile arguments
  parser.add_argument('-D', '--define', required=False,
    help='Define to pass to NASM when assembling code for specific operating system')
  parser.add_argument('-l', '--linker', default='ld')
  parser.add_argument('-c', '--compiler', default='cc')
  parser.add_argument('-w', '--enable-wrapper', action='store_true', default=True,
    help='Compile a shellcode wrapper')

  # crypter arguments
  mode_group = parser.add_mutually_exclusive_group()
  mode_group.add_argument('-d', '--decrypt', action='store_true',
    help='Decrypt shellcode with the provided key and nonce')
  mode_group.add_argument('-e', '--encrypt', action='store_true',
    help='Encrypt shellcode from the provided file with the provided key')
  parser.add_argument('-k', '--key')
  parser.add_argument('-n', '--nonce')

  parser.add_argument('file', nargs=1,
    help='NASM source file or file containing encrypted bytecode')
  args = parser.parse_args()

  file = args.file[0]

  if not os.path.exists(file):
    err('Provided file "{}" does not exist'.format(file))

  if not (args.decrypt or args.encrypt):
    info('Switching to compile mode')
    c = Compile(file, args.define, args.linker, args.compiler, args.enable_wrapper)
    c.compile()
  else:
    info('Switching to crypter mode')
    if args.decrypt and not (args.key and args.nonce):
      err('--key and --nonce required when decrypting')
    elif args.encrypt and args.key:
      warn('--key is ignored; we will generate one for you')

    compiler = Compile(file, args.define, args.linker, args.compiler, args.enable_wrapper)

    if args.encrypt:
      compiler.assemble()
      compiler.link()
      compiler.dumpcode()

      crypter = Crypter(args.key, None, file, compiler.shellcode, None)
      crypter.encrypt()
    else:
      decrypter = Crypter(args.key, args.nonce, file, None, compiler)
      decrypter.decrypt()


if __name__ == '__main__':
  main()
