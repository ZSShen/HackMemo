
# Constant definition
.equ OFST_FIRST, 0
.equ OFST_SECOND, 4
.equ OFST_THIRD, 8
.equ OFST_FORTH, 12


# Link with C site
.global CFunction
.global TLSIntervention


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

    push %esi
    subl $12, %esp
    movl $OFST_THIRD, OFST_FIRST(%esp)
    movl $OFST_SECOND, OFST_SECOND(%esp)
    movl $OFST_FIRST, OFST_THIRD(%esp)
    call CFunction
    addl $12, %esp
    pop %esi
    movl %eax, OFST_FORTH(%esi)

    # Call to TLS testing.
    movl $12345, %eax
    movl $67890, %esi
    push %esi
    push %eax
    call TLSIntervention
    add $8, %esp

    # Invoke Cpp site callback.
    call *%eax

    popf
    popa
    leave
    ret
