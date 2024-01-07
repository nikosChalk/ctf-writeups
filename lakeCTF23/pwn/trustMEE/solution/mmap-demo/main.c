// gcc main.c -o main && ./main

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/mman.h>

#define ABS(x,y) ( (x) > (y) ? ( (x)-(y) ) : ( (y)-(x) ) )

int main() {

    char *addr1 = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    char *addr2 = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    char *addr3 = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    printf("Base mmap addr: 0x%lx\n", (uint64_t)addr1);
    printf(" [*] mmap addr1: 0x%lx\n", (uint64_t)addr1);
    printf(" [*] mmap addr2: 0x%lx\n", (uint64_t)addr2);
    printf(" [*] mmap addr3: 0x%lx\n", (uint64_t)addr3);
    printf("ABS(addr1-addr2) = 0x%lx\n", ABS(addr1, addr2));
    printf("ABS(addr2-addr3) = 0x%lx\n", ABS(addr2, addr3));

    return 0;
}