#!/usr/bin/python2.7
# coding:utf-8
# 请勿修改整体模板，check 函数中内容需要根据题目进行完善
# eg: python check.py 192.168.8.101 8888
from sys import *
from pwn import *
import time

host = argv[1]
port = int(argv[2])
timeout = 30

# except return Correct/Error info, not return another info
context.log_level = 'critical'

def getIO():
    return remote(host, port, timeout=timeout)#process("./tinynote")#

def check1():
    try:
        p = getIO()
	p.recvuntil('> ')
        p.sendline('1')
        info = p.recv()
        if info != 'Input Your Note Size: ':
            raise Exception, "Size error"
        p.sendline('20')
        info = p.recv()
        if info != 'Input Your No.0 Note: \n':
            raise Exception, "Note error"
	p.sendline('aaa')
    except Exception as e:
        raise Exception, "Add note error, "+str(e)
    return True

# simple all defend check
def check2():
    try:
        p = getIO()
	p.recvuntil('> ')
        p.sendline('1')
        info = p.recv()
        if info != 'Input Your Note Size: ':
            raise Exception, "Size error"
        p.sendline('20')
        info = p.recv()
        if info != 'Input Your No.0 Note: \n':
            raise Exception, "Note error"
	p.sendline('aaa')
    except Exception as e:
        raise Exception, "Add note error, "+str(e)
	p.recv()
        p.sendline('2')
        info = p.recv()
        if info != 'Input your note index: ':
            raise Exception, "index error"
        p.sendline('0')
    except Exception as e:
        raise Exception, "show note error, "+str(e)
    return True

# if want to add check, Please insert function like check3(p),check4(p) ...
def check3():
    try:
        p = getIO()
	p.recvuntil('> ')
        p.sendline('1')
        info = p.recv()
        if info != 'Input Your Note Size: ':
            raise Exception, "Size error"
        p.sendline('20')
        info = p.recv()
        if info != 'Input Your No.0 Note: \n':
            raise Exception, "Note error"
	p.sendline('aaa')
    except Exception as e:
        raise Exception, "Add note error, "+str(e)

	p.recv()
        p.sendline('3')
        info = p.recv()
        if info != 'Input your note index: ':
            raise Exception, "Size error"
        p.sendline('0')
        info = p.recv()
        if info != 'Input your note new size: ':
            raise Exception, "Note error"
	p.sendline('20')
        info = p.recv()
        if info != 'Input Your No.0 Note: \n':
            raise Exception, "Note error"
    except Exception as e:
        raise Exception, "edit note error, "+str(e)
    return True


def check4():
    try:
        p = getIO()
	p.recvuntil('> ')
        p.sendline('1')
        info = p.recv()
        if info != 'Input Your Note Size: ':
            raise Exception, "Size error"
        p.sendline('20')
        info = p.recv()
        if info != 'Input Your No.0 Note: \n':
            raise Exception, "Note error"
	p.sendline('aaa')
    except Exception as e:
        raise Exception, "Add note error, "+str(e)
	p.recv()
        p.sendline('4')
        info = p.recv()
        if info != 'Input your note index: ':
            raise Exception, "index error"
        p.sendline('0')
    except Exception as e:
        raise Exception, "delete note error, "+str(e)
    return True

def checker():
    try:
        # add your check function name
        if check1():	
		print '1 ok'
		if check2():
			print '2 ok'
			if check3():
				print '3 ok'
				if check4():
					print '4 ok'
            				return (True, "IP: "+host+" OK")
    except Exception as e:
        return (False, "IP: "+host+" is down, "+str(e))

if __name__ == '__main__':
    print(checker())

