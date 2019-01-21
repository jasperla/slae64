#!/usr/bin/env python3
#
# Custom encoder/decoder with two schemes: off-by-one and shifter.
# Created for the SLAE64 course by Jasper Lievisse Adriaanse


import argparse
import math
import sys

class OffByOne():
  def __init__(self, shellcode, marker):
    self.shellcode = shellcode
    self.result = []
    self.marker = marker
  
  def encode(self):
    for idx, x in enumerate(self.shellcode):
      self.result += [hex(int(x, 16) + 1)]
  
  def decode(self):
    for idx, x in enumerate(self.shellcode):
      self.result += [hex(int(x, 16) - 1)]

class Shifter():
  def __init__(self, shellcode, marker):
    self.shellcode = shellcode
    self.result = []
    self.marker = marker
    self.shiftby = 2

  def encode(self):
    for idx, x in enumerate(self.shellcode):
      c = int(x, 16)
      self.result += [hex(((c & 0xff) >> self.shiftby % 8) | (c << (8 - (self.shiftby % 8)) & 0xff))]

  def decode(self):
    for idx, x in enumerate(self.shellcode):
      p = int(x, 16)
      self.result += [hex(((p << (self.shiftby % 8)) & 0xff) | ((p & 0xff) >> (8 - (self.shiftby % 8))))]


class Zipper():
  def __init__(self, shellcode, marker):
    self.shellcode = shellcode
    self.result = []
    self.marker = marker

  def encode(self):
    # Split input into two lists, left and right. If we cannot split it
    # into two equal parts ensure the left side is longer so we can know
    # to apply padding to the right side if needed.
    length = len(self.shellcode)
    middle = math.ceil(length / 2)

    left = self.shellcode[:middle]
    right = self.shellcode[middle:]

    for idx, x in enumerate(left):
      self.result += [left[idx]]

      # As NOPs can be considered indicators of shellcode, should we pad
      # the right side with instructions which are functionally NOPs instead?
      if idx > len(right)-1:
        self.result += ['0x90']
      else:
        self.result += [right[idx]]
  
  def decode(self):
    # Decoding works as follows:
    # - create two empty lists (left and right)
    # - if our current position is odd, item goes in left, right otherwise
    # - if the right side contains any padding, remove that
    # - finally concat the lists to obtain the original shellcode
    left = []
    right = []

    for idx, x in enumerate(self.shellcode):
      if idx % 2:
        if x == '0x90':
          continue
        right += [x]
      else:
        left += [x]
    
    self.result = left + right


class Formatter():
  def __init__(self):
    # c: \x90 \x91
    # hexdump: 90 91
    # nasm: 0x90,0x91
    # simple: 0x90 0x91
    self.supported = ['c', 'hexdump', 'nasm', 'simple']
  
  def is_supported(self, format):
    return format in self.supported

  def emit(self, format, code):
    if not self.is_supported(format):
      return None

    if format == 'c':
      return ''.join(map(lambda x: x.replace('0x', '\\x'), code))
    elif format == 'hexdump':
      return ' '.join(map(lambda x: x.replace('0x', ''), code))
    if format == 'nasm':
      return ','.join(code)
    elif format == 'simple':
      return ' '.join(code)


def main():
  parser = argparse.ArgumentParser()

  mode_group = parser.add_mutually_exclusive_group()
  mode_group.add_argument('-e', '--encode', action='store_true')
  mode_group.add_argument('-d', '--decode', action='store_true')
  parser.add_argument('-m', '--marker', help="Define marker word in form of \'0xf0 0x0d\'")
  # parser.add_argument('-I', '--include-decoder', action='store_true', help='Also emit the decoder for this shellcode')

  encoder_group = parser.add_mutually_exclusive_group()
  encoder_group.add_argument('--offbyone', action='store_true')
  encoder_group.add_argument('--shifter', action='store_true')

  parser.add_argument('shellcode', nargs='+' , help="Provide shellcode in form of: \'0x90 0x90...\'")
  parser.add_argument('-f', '--format', default='simple', help='Set output format')
  args = parser.parse_args()

  formatter = Formatter()

  if not formatter.is_supported(args.format.lower()):
    print('[-] Unrecognized output format: {}'.format(args.format))
    sys.exit(1)

  if not args.marker:
    marker = ''
  else:
    marker = args.marker

  # Default to using the Off-by-one endcoder
  if args.shifter:
    encoder = Shifter(args.shellcode, marker)
  else:
    encoder = OffByOne(args.shellcode, marker)

  # Default the mode to encoding  
  if args.decode:
    encoder.decode()
  else:
    encoder.encode()

  print(formatter.emit(args.format, encoder.result))

if __name__ == '__main__':
  main()
