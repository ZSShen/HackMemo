
# Constant Definition
.equ OFST_FIRST, 0
.equ OFST_SECOND, 4
.equ OFST_THIRD, 8


.section .text

.global AsmFunction
.type AsmFunction, @function
AsmFunction:
    push %ebp
    movl %esp, %ebp
    pusha
    pushf

    movl 8(%ebp), %esi

    movl $OFST_FIRST, OFST_FIRST(%esi)
    movl $OFST_SECOND, OFST_SECOND(%esi)
    movl $OFST_THIRD, OFST_THIRD(%esi)

    #movl %fs:OFST_FIRST, %eax
    #movl %eax, OFST_FIRST(%esi)
    #movl %fs:OFST_SECOND, %eax
    #movl %eax, OFST_SECOND(%esi)
    #movl %fs:OFST_THIRD, %eax
    #movl %eax, OFST_THIRD(%esi)

    popf
    popa
    leave
    ret
