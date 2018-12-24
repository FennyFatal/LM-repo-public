.intel_syntax noprefix

.text

.globl syscall
syscall:
	xor rax, rax

_end:
	ret
