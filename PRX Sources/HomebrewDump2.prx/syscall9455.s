	.section .rodata
	.global syscall9455
	.type   syscall9455, @object
	.align  4
syscall9455:
	.incbin "./syscall9455.elf"
syscall9455_end:
	.global syscall9455_size
	.type   syscall9455_size, @object
	.align  4
syscall9455_size:
	.int    syscall9455_end - syscall9455