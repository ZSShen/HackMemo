#include <iostream>
#include <bridge.h>


int main()
{
    Table tbl;
    AsmFunction(&tbl);
    std::cout << "[+] In main " << tbl.m_First << std::endl;
    std::cout << "[+] In main " << tbl.m_Second << std::endl;
    std::cout << "[+] In main " << tbl.m_Third << std::endl;
    std::cout << "[+] In main " << tbl.m_Forth << std::endl;
    return 0;
}


int CFunction(int op1, int op2, int op3)
{
    int res = op1 + op2 + op3;
    std::cout << "[+] In C site " << op1 << std::endl;
    std::cout << "[+] In C site " << op2 << std::endl;
    std::cout << "[+] In C site " << op3 << std::endl;
    return res;
}