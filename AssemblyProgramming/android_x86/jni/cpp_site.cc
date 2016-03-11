#include <iostream>
#include <stdint.h>
#include "bridge.h"
#include "inline.h"


thread_local uint32_t backup_eax;
thread_local uint32_t backup_esi;
void CallBack();


class Class
{
  public:
    uintptr_t Function(uint32_t, void*);
};

uintptr_t Class::Function(uint32_t integer, void* object)
{
    std::cout << integer << ' ' << object << std::endl;
    uintptr_t res = 1234;
    return res;
}


int main()
{
    Class clazz;
    uintptr_t res = clazz.Function(21, nullptr);

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


uintptr_t TLSIntervention(uint32_t eax, uint32_t esi)
{
    backup_eax = eax;
    backup_esi = esi;
    std::cout << "[+] eax=" << backup_eax << std::endl;
    std::cout << "[+] esi=" << backup_esi << std::endl;
    return reinterpret_cast<uintptr_t>(CallBack);
}


void CallBack()
{
    std::cout << "Call back by assembly side." << std::endl;
}