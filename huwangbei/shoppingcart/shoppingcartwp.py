from pwn import *
sh = process('./task_shoppingCart')



sh.recv()
sh.sendline('1')
gdb.attach(sh)
