
# Constant definition
.equ OFST_FIRST, 0
.equ OFST_SECOND, 4
.equ OFST_THIRD, 8
.equ OFST_FORTH, 12


# Link with C site
.global CFunction


.section .text

.global AsmFunction
AsmFunction:
    mov r1, #12
    str r1, [r0, #OFST_FIRST]

    mov r1, #34
    str r1, [r0, #OFST_SECOND]

    mov r1, #56
    str r1, [r0, #OFST_THIRD]

    mov r1, #78
    str r1, [r0, #OFST_FORTH]

    # Call the CFunction
    push {lr}

    mov r0, #5
    push {r0}

    mov r0, #1
    mov r1, #2
    mov r2, #3
    mov r3, #4

    bl CFunction

    add sp, sp, #4

    pop {lr}

    bx lr
