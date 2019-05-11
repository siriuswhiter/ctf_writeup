#include<stdio.h>
#include <stdlib.h>
#include <string.h>

int create_inuse,delete_inuse,show_inuse,edit_inuse,fill_inuse=0;
void *buf;


void menu()
{
  puts("-- gctf- -BabyHeap --\n1 - Create\n2 - Edit\n3 - Show\n4 - Delete\n5 - Exit");
}

void setup(){
  setvbuf(stdin, 0LL, 2, 0LL);
  setvbuf(stdout, 0LL, 2, 0LL);
  alarm(0x50u);
}


int create(){ 
  int result;
  if(create_inuse==0){
	  buf = malloc(0x60);
	  
	  result = puts("Create Done!");
	  create_inuse = 1;
  }else{
	printf("Cannot create any more!\n");
  }	
  return result;
}

int edit(){
  int result;
  if(edit_inuse==0){
	  printf("Content? ");
	  result = read(0, buf, 0x40uLL);
	  edit_inuse = 1LL;
  }else{
	printf("Cannot edit any more!\n");
  }
  return result;  
}


int show(){
  int result;
  if(show_inuse==0){
	  result = printf("Content: %s\n", buf);
	  show_inuse = 1LL;
  }else{
	printf("Cannot show any more!\n");
  }
  return result;
}


int delete()
{
  int result; 
  if(delete_inuse==0){
	  free(buf);                            
	  result = puts("Delete Done!");
	  create_inuse = 0LL;
	  delete_inuse = 1LL;
  }else{
	printf("Cannot delete any more!\n");
  }
  return result;
}


int backdoor()
{
  if(fill_inuse==0){
	  buf = malloc(0x60uLL);
	  printf("It might be a backdoor,but might be not ,you can try to Fill ");
	  read(0, buf, 0x40uLL);
  	  return fill_inuse++ + 1;
  }else{
	printf("Backdoor has been found!!\n");
  }
  return 0;
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
	case 0x3f:backdoor();break;
    }
}
  return 0;	
}



