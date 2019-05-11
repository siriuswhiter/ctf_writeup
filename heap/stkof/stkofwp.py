from pwn import *

sh = process('./stkof')
elf = ELF('./stkof')

def alloc(length):
    sh.sendline("1")
    sh.sendline(str(length))

def edit(idx,content):
    sh.sendline("2")
    sh.sendline(str(idx))
    sh.sendline(str(len(content)))
    sh.sendline(content)

def free(idx):
    sh.sendline("3")
    sh.sendline(str(idx))

alloc(0x100)  #1
alloc(0x30)   #2
alloc(0x30)   #3
alloc(0x100)

gdb.attach(sh)
sh.interactive()



