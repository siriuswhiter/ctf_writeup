#include <stdio.h>
#include <malloc.h>

int main(){
	int *p = malloc(0x80);
	int *q = malloc(0x100);
	int *o = malloc(0x100);
	int *z = malloc(0x10);

	free(p);
	//free(o);
	
	int a;
	gets(a);
	return 0;
}
