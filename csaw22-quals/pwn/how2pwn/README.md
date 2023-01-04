# how2pwn

Categories: Pwn

Description:
> ???
> 
>author: ??
>
>[challenge files](public/)
> 

**Tags:** pwn, seccomp/eBPF filters, mastering shellcode

This is a series of 4 pwn challenges that incrementally get more difficult. In order to access each challenge, you need to have solved the previous one as each challenge, except the first, requires a password (ticket). The 4 challenges are about writing shellcode and are summarized bellow:

* [Challenge 1](challenge1/README.md): Simple `execve` shellcode
  * required ticket: `-`
* [Challenge 2](challenge2/README.md): Simple 2-stage shellcode. First stage performs a `read` syscall to read the 2nd and larger `execve` stage.
  * required ticket: `764fce03d863b5155db4af260374acc1`
* [Challenge 3](challenge3/README.md): seccomp blacklist filter bypass by switching to 32-bit x86 assembly and invoking `int 0x80`.
  * required ticket: `8e7bd9e37e38a85551d969e29b77e1ce`
* [Challenge 4](challenge4/README.md): seccomp whitelist filter bypass using the `seccomp_unotify` mechanism.
  * required ticket: `7a01505a0cfefc2f8249cb24e01a2890`

Final flag: `flag{8d13cfa357978684be9809172d3033ce739015f5}`

## Takeaways

The biggest takeaways here are mastering shellcode writing and seccomp filters understanding.

* PIE shellcode
* Using `shellcraft` from pwntools
* Switch to 32-bit x86 assembly from 64-bit x86_64 assembly and vice versa
* 2-stage shellcode
* Use `hbreak` (hardware breakpoints) when dealing with shellcode, especially when you have self-modifying code or RWX regions.
* When you hijack the control flow, always check your current registers for values that are convenient to your exploitation.
* [Elaborate guide to seccomp filters](https://n132.github.io/2022/07/03/Guide-of-Seccomp-in-CTF.html) and how seccomp filters work
* `64` vs `x32` vs `i386` Linux x86_64 syscall ABI
