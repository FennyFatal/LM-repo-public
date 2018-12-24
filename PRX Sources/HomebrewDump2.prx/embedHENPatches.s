	.section .rodata
	.global HENPatches
	.type   HENPatches, @object
	.align  4
HENPatches:
	.incbin "HENPatches.bin"
HENPatches_end:
	.global HENPatches_size
	.type   HENPatches_size, @object
	.align  4
HENPatches_size:
	.int    HENPatches_end - HENPatches
