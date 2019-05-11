#include<stdio.h>

int main()
{
	int i;
	int seed;
	scanf("%d",&seed);
	srand(seed);
	for(i = 0; i < 100; i++)
	{
    		printf("%d ",rand());
   	}
	printf("\n");
}
