	.section .rodata
	.global remoteplay505
	.type   remoteplay505, @object
	.align  4
remoteplay505:
	.incbin "./remoteplaypatch.elf"
remoteplay505_end:
	.global remoteplay505_size
	.type   remoteplay505_size, @object
	.align  4
remoteplay505_size:
	.int    remoteplay505_end - remoteplay505