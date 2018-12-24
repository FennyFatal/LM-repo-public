ENTRY(FTPStart)

SECTIONS {
    /* We don't do GOT relocation and rely on nothing ending up using the GOT
     * (-fno-common helps here) */
    /DISCARD/ : { *(.comment) *(.got) }
    _start = .;
    .init : { *(.init) *(.init.*) }
    .text : { *(.text) *(.text.*) }
    .data : { *(.data) *(.data.*) }
    .rodata : { *(.rodata) *(.rodata.*) }
    .bss : { *(.bss) *(.bss.*) *(COMMON)}
    .footer : { LONG(0xdeadbeef) } /* make sure .bss is padded out in raw binary */
    _end = .;
}