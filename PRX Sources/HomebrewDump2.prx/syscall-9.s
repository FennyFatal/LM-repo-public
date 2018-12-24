	.section .rodata
	.global syscall9505
	.type   syscall9505, @object
	.align  4
syscall9505:
	.incbin "./syscall-9.elf"
syscall9505_end:
	.global syscall9505_size
	.type   syscall9505_size, @object
	.align  4
syscall9505_size:
	.int    syscall9505_end - syscall9505