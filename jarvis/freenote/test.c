#include <stdio.h>
#include <malloc.h>

int main()
{
	char *p = malloc(0x80);
	char *q = malloc(0x80);
	printf("%p",p);
	printf("%p",q);
	free(q);
	gets(p);
	char *i = realloc(p,0x100);
	printf("%p",i);
	gets(i);
	char *e = malloc(0x80);
	printf("%p",e);
	return 0;
}
