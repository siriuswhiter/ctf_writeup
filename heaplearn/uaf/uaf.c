#include <stdio.h>
#include <stdlib.h>
typedef void (*func_ptr)(char *);
void evil_fuc(char command[])
{
system(command);
}
void echo(char content[])
{
printf("%s",content);
}
int main()
{
    func_ptr *p1=(func_ptr*)malloc(4*sizeof(int));
    printf("malloc addr: %p\n",p1);
    p1[3]=echo;
    p1[3]("hello world\n");
    free(p1); //在这里free了p1,但并未将p1置空,导致后续可以再使用p1指针
    p1[3]("hello again\n"); //p1指针未被置空,虽然free了,但仍可使用.只是其内存块是被标记为空闲状态
    func_ptr *p2=(func_ptr*)malloc(4*sizeof(int));//malloc在free一块内存后,再次申请同样大小的指针会把刚刚释放的内存分配出来.
    printf("malloc addr: %p\n",p2);
    printf("malloc addr: %p\n",p1);//p2与p1指针指向的内存为同一地址
    p2[3]=evil_fuc; //在这里将p1指针里面保存的echo函数指针覆盖成为了evil_func指针.
    p1[3]("/bin/sh");
    return 0;
}
