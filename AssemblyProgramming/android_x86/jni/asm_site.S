
.section .text

.global AsmFunction
.type AsmFunction, @function

AsmFunction:
    push %ebp
    movl %esp, %ebp

    movl 8(%ebp), %esi
    movl $0x1234, 0(%esi)

    leave
    ret
