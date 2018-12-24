/* golden */
/* 1/2/2018 */

#include "resolve.h"

#define	KERN_XFAST_SYSCALL	0x1C0	

void resolve() {
	uint8_t* kernbase = (uint8_t*)(__readmsr(0xC0000082) - KERN_XFAST_SYSCALL);
	M_TEMP = (void *)(kernbase + __M_TEMP);

#define r(name, offset) name = (void *)(kernbase + offset)
	//r(printf, __printf);
	r(k_malloc, __malloc);
	r(k_free, __free);
	r(k_memcpy, __memcpy);
	r(k_memset, __memset);
	r(k_memcmp, __memcmp);
	r(k_strlen, __strlen);
}
