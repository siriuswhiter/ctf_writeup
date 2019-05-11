from pwn import *

sh = process('./candystore')


def login(idx,prof,mon):
	sh.sendlineafter('ID> ',idx)
	sh.sendlineafter('Profile> ',prof)
	sh.sendlineafter('> $',mon)



login('admin','aa','0')


sh.interactive()
