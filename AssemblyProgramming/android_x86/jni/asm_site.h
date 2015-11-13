#ifndef __ASM_SITE_H_
#define __ASM_SITE_H_


struct Table
{
    int m_First;
    int m_Second;
    int m_Third;
};

extern void AsmFunction(Table*) __asm__("AsmFunction");


#endif