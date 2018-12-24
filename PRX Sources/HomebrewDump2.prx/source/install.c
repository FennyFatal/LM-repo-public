/* LM */
/* 9/7/2018 */

#include "install.h"
#include "elf.h"
#define	KERN_XFAST_SYSCALL	0x1C0


int install_payload(struct thread *td, void *payload, size_t psize) {
	uint8_t* kernbase = (uint8_t*)(__readmsr(0xC0000082) - KERN_XFAST_SYSCALL);
	int(*printfkernel)(const char *fmt, ...) = (void *)(kernbase + 0x0436040);
	vm_offset_t (*kmem_alloc)(vm_map_t map, vm_size_t size) = (void *)(kernbase + __kmem_alloc);
	vm_map_t kernel_map = *(vm_map_t *)(kernbase + __kernel_map);

	size_t msize = 0;
	if (elf_mapped_size(payload, &msize)) {
		printfkernel("[jkpatch] install_payload: elf_mapped_size failed!\n");
		return 1;
	}

	int s = (msize + 0x3FFFull) & ~0x3FFFull;

	cpu_disable_wp();
	*(uint8_t *)(kernbase + 0xFCD48) = 7; // VM_PROT_ALL;
	*(uint8_t *)(kernbase + 0xFCD56) = 7; // VM_PROT_ALL;
	cpu_enable_wp();

	void *payloadbase = (void *)kmem_alloc(kernel_map, s);
	if (!payloadbase) {
		printfkernel("[jkpatch] install_payload: kmem_alloc failed!\n");
		// need to set protection back to VM_PROT_DEFAULT...
		return 1;
	}

	cpu_disable_wp();
	*(uint8_t *)(kernbase + 0xFCD48) = 3; // VM_PROT_DEFAULT;
	*(uint8_t *)(kernbase + 0xFCD56) = 3; // VM_PROT_DEFAULT;
	cpu_enable_wp();

	// load the elf
	int r = 0;
	int (*payload_entry)(void *p);

	if ((r = load_elf(payload, psize, payloadbase, msize, (void **)&payload_entry))) {
		printfkernel("[jkpatch] install_payload: load_elf failed (r: %i)!\n", r);
		return 1;
	}

	// call entry
	if (payload_entry(NULL)) {
		return 1;
	}

	printfkernel("[jkpatch] payload loaded at 0x%llX\n", payloadbase);

	return 0;
}
