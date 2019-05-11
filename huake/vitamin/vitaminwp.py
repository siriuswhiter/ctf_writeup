from pwn import *
context.log_level='debug'
sh = process('./vitamin')
libc = ELF('./vitamin')

sys_addr = 0x400d58

def create(formula):
	sh.recvuntil("Give me your choice:\n")
	sh.sendline('1')
	sh.recvuntil("Give me your formula:\n")
	sh.sendline(formula)

def delete():
	sh.recvuntil("Give me your choice:\n")
	sh.sendline('2')

def change(formula):
	sh.recvuntil("Give me your choice:\n")
	sh.sendline("3")
	sh.recvuntil("Give me your formula:\n")
	sh.sendline(formula)


create('aaaaaaaaaaaaa')

gdb.attach(sh)
sh.interactive()

