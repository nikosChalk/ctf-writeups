# minimal-template.py
# A minimal custom template for binary exploitation that uses pwntools.
# Run:
#   python minimal-template.py [DEBUG] [GDB]
from pwn import *

# Set up pwntools for the correct architecture. See `context.binary/arch/bits/endianness` for more
context.binary = elfexe = ELF('./smash-baby')
print(context)

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
# continue
'''.format(**locals())

arguments = []
io = start(arguments)
io.interactive()
io.close()
