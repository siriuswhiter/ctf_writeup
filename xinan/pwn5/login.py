s = '~vzi}'

pa = ''
for i in range(len(s)):
	print hex(ord(s[len(s)-i-1]))
	pa += chr(ord(s[len(s)-i-1])^0x1b)


print pa
