.section .text

.global _start
_start:
	lea (%rsp), %rdi
	callq dlng_main

.global start_program
start_program:
	mov %rdi, %rsp
	jmp *%rsi
