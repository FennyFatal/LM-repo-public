	.section .rodata
	.global kpayload505
	.type   kpayload505, @object
	.align  4
kpayload505:
	.incbin "./jkpatch505/kpayload505.elf"
kpayload505_end:
	.global kpayload505_size
	.type   kpayload505_size, @object
	.align  4
kpayload505_size:
	.int    kpayload505_end - kpayload505