#include <iostream>
#include <asm_site.h>


int main()
{
    Table tbl;
    AsmFunction(&tbl);
    std::cout << tbl.m_First << std::endl;
    std::cout << tbl.m_Second << std::endl;
    std::cout << tbl.m_Third << std::endl;

    return 0;
}