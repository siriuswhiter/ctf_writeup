a = [0x28,0x57,0x64 ,0x6B ,0x93,0x8F ,0x65 ,0x51 ,0xE3 ,0x53 ,0xE4 ,0x4E ,0x1A ,0xFF]
b = [0x1b,0x1c,0x17,0x46,0xf4,0xfd,0x20,0x30,0xb7,0x0c,0x8e,0x7e,0x78,0xde]
c = ''
for i in range(len(a)):
	c += chr(a[i]^b[i])

print c
	
