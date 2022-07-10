

#include <sys/mman.h>
#include <linux/mman.h> //MAP_UNINITIALIZED
#include <assert.h>
#include <string.h>
#include <stdio.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

void test1() {
    void *res = mmap(NULL, 0x1000, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    assert(res);

    printf("mmaped at %p\n", res);
    memset(res, 0x41, 0x1000);

    void *overlap = mmap(res, 0x1000, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED|MAP_UNINITIALIZED, -1, 0);
    printf("overlap: %p\n", overlap);

    /*
     * Hypothesis: Remapping at the same area might keep the previous contents
     * Result: This did not happen
     */
}

void test2() {
    struct stat mybuf;

    void *res = mmap(NULL, 0x1000, PROT_NONE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    assert(res);

    //CWD contains "test" file (aka this binary)
    int syscall_res;
    syscall_res = stat("test", &mybuf);
    printf("Valid   syscall result: %d\n", syscall_res);

    syscall_res = stat("test", res);
    printf("Invalid syscall result: %d\n", syscall_res);

    /*
     * Hypothesis stat(const char *pathname, struct stat *statbuf); with a valid pathname and a PROT_NONE statbuf might be our side-channel
     * Result: This WORKS!
     * Valid   syscall result: 0
     * Invalid syscall result: -1
     */
}

int main() {
    test2();
    return 0;
}
