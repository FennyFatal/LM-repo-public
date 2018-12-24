    .section .rodata
    .global kexecs
    .type   kexecs, @object
    .align  4
kexecs:
    .incbin "kexecs.bin"
kexecs_end:
    .global kexecs_size
    .type   kexecs_size, @object
    .align  4
kexecs_size:
    .int kexecs_end - kexecs

