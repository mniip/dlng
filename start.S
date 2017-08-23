.section .text

.global _start
_start:
	lea (%rsp), %rdi
	callq dlng_main

.global start_program
start_program:
	mov %rdi, %rsp
	mov $0, %rdx
	jmp *%rsi
