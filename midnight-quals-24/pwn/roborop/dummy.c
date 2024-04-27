

#include <stdlib.h>
#include <sys/mman.h>
#include <stdio.h>
#include <dlfcn.h>

typedef void (*srand_t)(unsigned int __seed);
typedef int (*rand_t)(void);

int main(int argc, char * argv[]) {
    if (argc != 2) {
        printf("Invalid arguments\n");
        return 1;
    }
    int seed = atoi(argv[1]);
    int *addr = mmap(NULL, 0x10000000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS , -1, 0);
    if(!addr)
        perror("mmap");
    printf("%p\n", addr);

    void *libc_handle = dlopen("./libc.so.6", RTLD_LAZY);
    if(!libc_handle) {
        printf("dlopen: %s\n", dlerror());
        return 1;
    }
    srand_t srand_func = dlsym(libc_handle, "srand");
    if(!srand_func)
        printf("dlsym srand: %s\n", dlerror());
    rand_t rand_func = dlsym(libc_handle, "rand");
    if(!rand_func)
        printf("dlsym srand: %s\n", dlerror());

    srand_func(seed);
    for(int i=0; i<0x4000000; i++) {
        int r = rand_func();
        addr[i] = r;
    }
    if(dlclose(libc_handle) != 0)
        printf("dlclose: %s\n", dlerror());
    return 0;
}
