#include <stdio.h>
#include <time.h>

int main()
{
	int seed = time(0)/10; //0x093af34d;
	srand(seed);
	for(int i=0;i<100;i++)
	{
		int t = rand();
		printf("time: %d\n",time(0));
		printf("seed: %d\n",seed);
		printf("rand: %d\n\n",t);
	}

	return 0;
}

