#include <iostream>
#include <asm_site.h>


int main()
{
    int var = 0;
    AsmFunction(&var);
    std::cout << var << std::endl;
    return 0;
}