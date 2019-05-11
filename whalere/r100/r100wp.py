import numpy as np
a= np.array[3][8] = [[D,u,f,h,b,m,f][p,G,'`',i,m,o,s][e,w,U,g,l,p,t]]
a1 = ''
for i in range(12):
	a1 += chr(ord(a[i%3][2*(i/3)])-1)

print a1 
