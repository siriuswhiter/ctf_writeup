a = 'abcdefghiABCDEFGHIJKLMNjklmn0123456789opqrstuvwxyzOPQRSTUVWXYZ'

b = 'KanXueCTF2019JustForhappy'
array = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'

c = '' 

for i in range(len(b)):
	for j in range(len(a)):
		if b[i]== a[j]:
			c += array[j]
print c	
