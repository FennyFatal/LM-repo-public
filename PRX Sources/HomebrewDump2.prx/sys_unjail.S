    .section .rodata
    .global sys_unjails
    .type   sys_unjails, @object
    .align  4
sys_unjails:
    .incbin "sys_unjail.bin"
sys_unjails_end:
    .global sys_unjail_size
    .type   sys_unjail_size, @object
    .align  4
sys_unjail_size:
    .int    sys_unjails_end - sys_unjails