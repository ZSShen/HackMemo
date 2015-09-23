global _start

section .text

_start:
    jmp DLOPEN_ADDR             ; Jump to DLOPEN_ADDR

MAIN:
    pop rax                     ; Pop the return address which is actually the
                                ; address of "the address of dlopen()"
    push rbp
    mov rbp, rsp

    push 0x2
    mov rbx, rax
    add rbx, 0x8
    push rbx
    call [rax]

    add rsp, 0x10
    pop rbp

    int 0x3                     ; Fire a software interrupt

DLOPEN_ADDR:
    call MAIN                   ; we jump back to MAIN, but since we use "call",
                                ; that means the return address, which is the
                                ; address of "the address of dlopen()", is pushed
                                ; onto the stack. Note that this address should
                                ; be updated at runtime.

    ; To be updated 8 byte address of dlopen()
    ; To be updated library path string
