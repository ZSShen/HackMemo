#ifndef _BRIDGE_H_
#define _BRIDGE_H_


struct Table
{
    int m_First;
    int m_Second;
    int m_Third;
    int m_Forth;
};

extern void AsmFunction(Table*) __asm__("AsmFunction");
extern "C" int CFunction(int, int, int);
extern "C" uintptr_t TLSIntervention(uint32_t, uint32_t);


#endif