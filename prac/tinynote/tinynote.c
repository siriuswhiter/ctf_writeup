//gcc tinynote.c  -z now -o tinynote
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


typedef struct Str{
    size_t size;
    size_t inuse;
	char * ptr;
}S;

S s[20];

int main(){
	setup();
    init();

    while(1){
        menu();
        printf("> ");
        char a[2];
        read(0,a,2);
        int idx = atoi(a);

        switch (idx)
        {
        case 1:add();break;
        case 2:show();break;
        case 3:edit();break;
        case 4:dele();break;
        case 5:exit(0);
        default: break;
        }
    }
    

	return 0;
}


void setup(){
    setbuf(stdin,NULL);
    setbuf(stdout,NULL);
    setbuf(stderr,NULL);
    alarm(0x40);
}


void init(){
    for(int i=0;i<20;i++){
        s[i].size=0;
        s[i].inuse=0;
        s[i].ptr=NULL;
    }
    return;
}


void menu(){
    printf("#--------Welcome To Tiny Note--------#\n\
#---      1. Add a note           ---#\n\
#---      2. Show  note           ---#\n\
#---      3. Edit a note          ---#\n\
#---      4. Delete note          ---#\n\
#---      5. Exit                 ---#\n\
#------------------------------------#\n\
");
}

void get_str(char *ptr,int size){
    int tmp=0;
    if(size<0){
        return;
    }

    for(int i=0;i<size;i++){
        read(0,(ptr+i),1);
        tmp = i;
        if(*(ptr+i)=='\n'){
            break;
        }
    }
    *(ptr+tmp+1)=0;
    return;
}


void add(){
    int idx;
    int size;
    char *ptr;

	for(int i=0;i<20;i++){
        if(!s[i].inuse){
            idx = i;
            break;
        }
    }

    printf("Input Your Note Size: ");
    scanf("%d",&size);
    if(size<0){
        printf("Wrong size!\n");
        return;
    }else if(size>0x200){
        size = 0x200;
    }

    s[idx].size = size;
    s[idx].inuse = 1;
    ptr = calloc(size,sizeof(char));
    s[idx].ptr = ptr;
    printf("Input Your No.%d Note: \n",idx);
    get_str(ptr,size);
    printf("Done\n");

}



void show(){
    int idx;
    int size;
    char *ptr;

    printf("Input your note index: ");
    scanf("%d",&idx);
    if(idx<0 ||  idx>20|| !s[idx].inuse ){
        printf("Note does not exist!!\n");
        return;
    }
    if(s[idx].inuse){
        write(1,s[idx].ptr,s[idx].size);
    }
}

void edit(){
    int idx;
    int size;

    printf("Input your note index: ");
    scanf("%d",&idx);
    if(idx<0 || idx>20|| !s[idx].inuse ){
        printf("Note does not exist!!\n");
        return;
    }

    if(s[idx].inuse){
        printf("Input your note new size: ");
        scanf("%d", &size);
        if(size<0){
            printf("Wrong size!\n");
        }else if(size>s[idx].size){
            size = s[idx].size;
        }
    }
    s[idx].size=size;
    printf("Input Your No.%d Note: \n",idx);
    get_str(s[idx].ptr,size);
    printf("Done\n");
}



void dele(){
    int idx;
    int size;
    char *ptr;

    printf("Input your note index: ");
    scanf("%d",&idx);
    if(idx<0 || idx>20||!s[idx].inuse ){
        printf("Note does not exist!!\n");
        return;
    }

    if(s[idx].inuse){
        free(s[idx].ptr);
        s[idx].ptr=NULL;
        s[idx].inuse=0;
        s[idx].size=0;
    }
}