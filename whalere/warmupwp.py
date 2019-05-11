a = 'LDYVLQMZHuY:|cQ[^Qyo|cQ{~QYO\\CQ[^/s'
b = ''
for i in range(len(a)):
	b += chr(ord(a[i]) ^ 0xe)

print b


