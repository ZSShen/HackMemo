global _start

section .text

_start:
    jmp DLOPEN_ADDR             ; Jump to DLOPEN_ADDR

MAIN:
    pop r9                      ; Pop the return address which is actually the
                                ; address of "the address of dlopen()"

    xor rsi, rsi
    xor rdi, rdi
    mov rsi, 0x1
    mov rdi, r9
    add rdi, 0x8

    mov r9, qword[r9]
    push r9
    call r9

    ;mov rsi, r9
    ;add rsi, 0x8
    ;mov rax, 0x1
    ;mov rdi, 0x1
    ;mov rdx, 0x10
    ;syscall

    pop r9

    int 0x3                     ; Fire a software interrupt

DLOPEN_ADDR:
    call MAIN                   ; we jump back to MAIN, but since we use "call",
                                ; that means the return address, which is the
                                ; address of "the address of dlopen()", is pushed
                                ; onto the stack. Note that this address should
                                ; be updated at runtime.

    ; To be updated 8 byte address of dlopen()
    ; To be updated library path string
