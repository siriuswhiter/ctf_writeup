#include<stdio.h>
#include <stdlib.h>
#include <string.h>

//int create_inuse,delete_inuse,show_inuse,edit_inuse,fill_inuse=0;
void *buf[0x10];


void menu()
{
  puts("-- gctf- -NewHeap --\n1 - Create\n2 - Edit\n3 - Show\n4 - Delete\n5 - Exit");
}

void setup(){
  setvbuf(stdin, 0LL, 2, 0LL);
  setvbuf(stdout, 0LL, 2, 0LL);
  alarm(0x50u);
}


int create(){ 
  int result;
  for(int i=0;i<10;i++){
  	if(!buf[i]){
	  buf[i] = malloc(0x60);
  	  result = printf("chunk %d Create Done!\n",i);
	  break;
	}
  }
  return result;
}

int edit(){
  int result,idx;
  puts("which chunk you want to edit? ");
  scanf("%d",&idx);
  if(buf[idx]){
  	printf("Content? ");
  	result = read(0, buf[idx], 0x40uLL);
  }else{
	  printf("chunk %d didn't exist\n",idx);
  }
  return result;
}


int show(){
  int result,idx;
  puts("which chunk you want to show? ");
  scanf("%d",&idx);
  if(buf[idx]){
  	result = printf("Content: %s\n", buf[idx]);
  }else{
	printf("chunk %d didn't exist\n",idx);
  } 

  return result;
}


int delete()
{
  int result,idx; 
  puts("which chunk you want to delete? ");
  scanf("%d",&idx);
  if(buf[idx]){
	puts("deleting...");
  	free(buf[idx]);                            
  	result = puts("Delete Done!");
  }else{
	printf("chunk %d didn't exist\n",idx);
  }

  return result;
}


int main(){
  int idx;
  char s[8];
  setup();
  puts("You have some choice:\n");
  while(1){
    menu();
    printf("> ");

    memset(&s,0,8);
    read(0,&s,8);
    idx = atoi(s);

    switch(idx)
    {
	case 1:create();break;
	case 2:edit();break;
	case 3:show();break;	
	case 4:delete();break;
	case 5:exit(0);
    }
}
  return 0;	
}




