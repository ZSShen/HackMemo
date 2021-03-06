global _start

section .text

_start:
    jmp MESSAGE                 ; Jump to MESSAGE

MAIN:
    pop rsi                     ; Pop the return address which is actually the
                                ; address of "Hello, World!\n"
    mov rax, 0x1
    mov rdi, 0x1
    mov rdx, 0xe
    syscall

    int 0x3                     ; Fire a software interrupt

MESSAGE:
    call MAIN                   ; we jump back to MAIN, but since we use "call",
                                ; that means the return address, which is the
                                ; address of "Hello, World!\n", is pushed onto
                                ; the stack.
    db "Hello, World!", 0xa
