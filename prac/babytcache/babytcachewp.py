from pwn import *

sh = process('./babytcache')

def add(content):
	sh.sendlineafter('>','1')
	sh.sendlineafter(':',content)

def delete(idx):
	sh.sendlineafter('>','2')
	sh.sendlineafter(':',str(idx))

def show(idx):
        sh.sendlineafter('>','3')
        sh.sendlineafter(':',str(idx))




