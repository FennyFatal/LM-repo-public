	.section .rodata
	.global kpayload455
	.type   kpayload455, @object
	.align  4
kpayload455:
	.incbin "./jkpatch455/kpayload455.elf"
kpayload455_end:
	.global kpayload455_size
	.type   kpayload455_size, @object
	.align  4
kpayload455_size:
	.int    kpayload455_end - kpayload455