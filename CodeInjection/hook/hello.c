#include <stdio.h>
#include <stdlib.h>


void __attribute__((constructor)) entry()
{
    printf("Hello there, you are hooked by me!\n");
}