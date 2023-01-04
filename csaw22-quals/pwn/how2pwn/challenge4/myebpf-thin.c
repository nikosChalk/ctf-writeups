
#include <linux/seccomp.h>
#include <unistd.h>
#include <syscall.h>
#include <sys/prctl.h>
#include <linux/filter.h>
#include <string.h>
#include <sys/ioctl.h>
#include <stddef.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <stdio.h>
#include <sys/mman.h>

void panic(char *s){
    write(STDOUT_FILENO, s, strlen(s));
    _exit(1);
}

void init(){
    setvbuf(stdin,  0, 2, 0);
    setvbuf(stdout, 0, 2, 0);
    setvbuf(stderr,  0, 2, 0);
    int ret = 0 ;
    ret = syscall(__NR_prctl,PR_SET_NO_NEW_PRIVS, 1,0,0,0);
    if(ret!=0)
        panic("[-] PR_SET_NO_NEW_PRIVS FAIL");
}

void sandbox(){
    // challenge setting
    // This sandbox only allows __NR_seccomp __NR_fork __NR_ioctl __NR_exit
    // and it would trace all other syscalls
    struct sock_filter strict_filter[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS,offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_seccomp, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_fork, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_ioctl, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_exit, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
		// BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_write, 0, 1),
        // BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
		// BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_open, 0, 1),
        // BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
		// BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_read, 0, 1),
        // BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
		// BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_close, 0, 1),
        // BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRACE), //SECCOMP_RET_TRACE, SECCOMP_RET_KILL
    };
    struct sock_fprog prog = {
        .len = sizeof(strict_filter) / sizeof(strict_filter[0]),
        .filter = strict_filter,
    };
    // Apply the filter. 
    int ret = syscall(__NR_seccomp,SECCOMP_SET_MODE_FILTER,0,&prog);
    if(ret!=0)
        panic("[-] SECCOMP_SET_MODE_FILTER FAIL");
    puts("[+] Sandbox On");
}

void exploit(){
    // installs a seccomp filter that generates user-space notifications (SECCOMP_RET_USER_NOTIF) always
    struct sock_filter strict_filter[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS,offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_seccomp, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_fork, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_ioctl, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_exit, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
    };
    struct sock_fprog prog = {
        .len = sizeof(strict_filter) / sizeof(strict_filter[0]),
        .filter = strict_filter,
    };
    // Apply the filter. 
    int listening_fd = syscall(
        __NR_seccomp,SECCOMP_SET_MODE_FILTER,SECCOMP_FILTER_FLAG_NEW_LISTENER,&prog
    ); //assume success

    pid_t child = syscall(__NR_fork);
    if(child == 0) {
        //child - supervisor. Still cannot make arbitrary syscalls since it has installed the
        //original seccomp filter
        struct seccomp_notif_sizes sizes;
        syscall(__NR_seccomp,SECCOMP_GET_NOTIF_SIZES,0,&sizes);

        char notif_buffer [sizes.seccomp_notif];        //type: struct seccomp_notif
        char response_buffer[sizes.seccomp_notif_resp]; //type: struct seccomp_notif_resp

        while(1) {
            memset(notif_buffer, 0, sizes.seccomp_notif);
            memset(response_buffer, 0, sizes.seccomp_notif_resp);

            ioctl(listening_fd, SECCOMP_IOCTL_NOTIF_RECV, notif_buffer);  //blocking

            struct seccomp_notif *notif_req = (struct seccomp_notif*)notif_buffer;
            struct seccomp_notif_resp *notif_resp = (struct seccomp_notif_resp*)response_buffer;

            notif_resp->id = notif_req->id;
            notif_resp->error = 0;
            notif_resp->flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
            notif_resp->val = 0;
            ioctl(listening_fd, SECCOMP_IOCTL_NOTIF_SEND, response_buffer);
        }
    } else {
        //parent - target. syscalls are delegated to the supervisor
        close(listening_fd);
        syscall(__NR_write, STDOUT_FILENO, "[+] Hacked Sandbox On\n", 22);
    }
}

int main(){
    init();
    // To make exploit script easier, our shellcode would be on 0xcafe000
    char *buf = mmap((void *)0xcafe000,0x1000,7,0x21,0,0);
    if((size_t)buf!=0xcafe000)
        panic("Fail to mmap");
    puts("Welcome!");
    //read(0, buf, 0x1000);
    //void (* p )(); 
    //p = (void (*)())buf;
    sandbox();
    exploit();

    return 1;
}
