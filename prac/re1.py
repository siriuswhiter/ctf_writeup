st = "~}|{zyxwvutsrqponmlkjihgfedcba`_^]\[ZYXWVUTSRQPONMLKJIHGFEDCBA@?>=<;:9876543210/.-,+*)('&%$#\"!"

aim = "DDCTF{reverseME}"
s = ''
for i in range(len(aim)):
	for j in range(len(st)):
		if(st[j]==aim[i]):
			s+= chr(j+0x20)
			print s		
