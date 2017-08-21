.global syscall6r
syscall6r:
	mov 8(%rsp), %rax
	mov %rcx, %r10
	syscall
	ret

.global syscall5r
syscall5r:
	mov %r9, %rax
	mov %rcx, %r10
	syscall
	ret

.global syscall4r
syscall4r:
	mov %r8, %rax
	mov %rcx, %r10
	syscall
	ret

.global syscall3r
syscall3r:
	mov %rcx, %rax
	syscall
	ret

.global syscall2r
syscall2r:
	mov %rdx, %rax
	syscall
	ret

.global syscall1r
syscall1r:
	mov %rsi, %rax
	syscall
	ret

.global syscall0r
syscall0r:
	mov %rdi, %rax
	syscall
	ret
