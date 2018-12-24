    .section .rodata
    .global kexec_ps4z
    .type   kexec_ps4z, @object
    .align  4
kexec_ps4z:
    .incbin "kexecz.bin"
kexec_endz:
    .global kexec_sizez
    .type   kexec_sizez, @object
    .align  4
kexec_sizez:
    .int    kexec_endz - kexec_ps4z