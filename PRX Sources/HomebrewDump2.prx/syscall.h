

#pragma once

#define	SYSCALL(name, number)	\
	__asm__(".intel_syntax noprefix"); \
	__asm__(".globl " #name ""); \
	__asm__("" #name ":"); \
	__asm__("movq rax, " #number ""); \
	__asm__("jmp syscall_macro"); \

/* PS4 FreeBSD Linux-Style Syscall implementation [64 bit]. */
long syscall(long n, ...);
