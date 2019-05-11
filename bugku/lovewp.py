import base64

string='e3nifIH9b_C@n@dH'
unstring = ''
for i in range(len(string)):
	unstring += chr(ord(string[i])-i)

flag = base64.b64decode(unstring)
print flag
