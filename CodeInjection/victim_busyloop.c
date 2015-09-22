#include <stdbool.h>
#include <stdio.h>
#include <unistd.h>


int main()
{
    int iter = 0;
    while (true) {
        printf("Enter the %dth loop\n", iter);
        sleep(1);
        iter++;
    }

    return 0;
}