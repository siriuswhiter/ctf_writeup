#include<stdio.h>
#include<time.h>

int main(){
	srand(0);
	int a;
	for(int i=0;i<50;i++){ 
		a = rand()%6 +1;
		printf("%d\n",a);
	}
	return 0;
}	
