#include <stdio.h>

int main(){
	char a[3][8] = {{'D','u','f','h','b','m','f'},{'p','G','`','i','m','o','s'},{'e','w','U','g','l','p','t'}};
	char b[40];
	for(int i =0;i<12;i++){
		b[i] = a[i%3][2*(i/3)] -1;
	}
	printf("%s",b);

	return 0;
}

