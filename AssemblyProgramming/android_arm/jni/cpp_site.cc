#include <iostream>
#include <stdint.h>
#include "bridge.h"


int main()
{
    Table tbl;
    int res = AsmFunction(&tbl);
    std::cout << "[+] In main " << tbl.m_First << std::endl;
    std::cout << "[+] In main " << tbl.m_Second << std::endl;
    std::cout << "[+] In main " << tbl.m_Third << std::endl;
    std::cout << "[+] In main " << tbl.m_Forth << std::endl;
    std::cout << "[+] Result " << res << std::endl;
    return 0;
}


int CFunction(int op1, int op2, int op3, int op4, int op5)
{
    int res = op1 + op2 + op3 + op4 + op5;
    std::cout << "[+] In C site " << op1 << std::endl;
    std::cout << "[+] In C site " << op2 << std::endl;
    std::cout << "[+] In C site " << op3 << std::endl;
    std::cout << "[+] In C site " << op4 << std::endl;
    std::cout << "[+] In C site " << op5 << std::endl;
    return res;
}
