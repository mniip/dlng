.section .text

.global _start
_start:
	lea (%rsp), %rdi
	callq dlng_main
