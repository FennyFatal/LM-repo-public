#include "ps4.h"
#include "defines.h"
#include "debug.h"
#include "dump.h"
#include "ps4.h"
#include "lv2.h"
#include "freebsd.h"
//#include "C:\Program Files (x86)\SCE\ORBIS SDKs\4.500\target\include\sys\ioccom.h"
//#include "elf.h"
//#include "elfs.h"
#include "elf64.h"
#define X86_CR0_WP (1 << 16)
#define PA_TO_DM(x) (((uintptr_t)x) | kern.dmap_base);
#define	KERN_XFAST_SYSCALL 0x1C0
#define KERN_PROCESS_ASLR 0x194875
#define KERN_PRISON_0 0x10986A0
#define KERN_ROOTVNODE 0x22C1A70
#define KERN_PRIV_CHECK 0x14A3990
#define KERN_PRIV_CHECK_CRED 0x2300B88
#define KERN_ALLOW_SYSTEM_LEVEL_DEBUGGING 0x1173D
#define KERN_COPYOUT 0x1EA630
#define KERN_COPYIN 0x1EA710
#define KERN_ALLPROC 0x2382FF8
#define KERN_PRINTF 0x436040
#define KERN_PROC_RWMEM 0x30D150
#define KERN_CREATE_THREAD 0x1BE1F0
#define KERN_KILLPROC 0xD41C0
#include "elfloader/network.h"
#include "elfloader/server.h"
#include "elfloader/util.h"
//#include "webvita.h"
#define R_X86_64_JUMP_SLOT 7
#define SERVER_TCP_PORT (9997)

//

int ioctls(int fd, unsigned long com, void *data)
{ 
	return syscall(54, fd, com, data); 
}

int kexecsx(void* func, void *user_arg) {
	return syscall(11, func, user_arg);
}

#define	KERN_KMEM_ALLOC 0xFCC80
#define	KERN_KMEM_FREE 0xFCE50
#define KERN_KERNEL_MAP 0x1AC60E0

#define KERN_VMSPACE_ACQUIRE_REF 0x19EF90
#define KERN_VM_MAP_LOCK_READ 0x19f140
#define KERN_VM_MAP_UNLOCK_READ 0x19f190
#define	KERN_VMSPACE_ALLOC 0x19eb20
#define	KERN_VMSPACE_FREE 0x19edc0
#define KERN_VM_MAP_LOOKUP_ENTRY 0x19F760
#define KERN_VM_MAP_FINDSPACE 0x1A1F60
#define KERN_VM_MAP_INSERT 0x1A0280
#define KERN_VM_MAP_UNLOCK 0x19F060
#define KERN_VM_MAP_LOCK 0x19EFF0
#define KERN_VM_MAP_DELETE 0x1A19D0

#define KERN_M_TEMP 0x14B4110
#define KERN_FREE 0x10E460
#define KERN_MALLOC 0x10E250
#define KERN_STRCPY 0x8F250
#define KERN_STRCMP 0x1D0FD0
#define KERN_STRNCMP 0x1B8FE0
#define KERN_STRLEN 0x3B71A0
#define KERN_MEMCPY 0x1EA530
#define KERN_MEMSET 0x3205C0


#define KERN_SYS_MMAP 0x13D230
#define KERN_SYS_OPEN 0x33B990
#define KERN_SYS_DYNLIB_LOAD_PRX 0x237930

#define KERN_SYSENTS 0x107C610


#define ALIGN(size, alignment) \
    (((size) + ((alignment) - 1)) & ~((alignment) - 1))
#define ALIGN_PAGE(size) \
    ALIGN(size, 0x4000)

#define ELF_IDENT_SIZE 0x10

#define ELF_IDENT_MAG0  0
#define ELF_IDENT_MAG1  1
#define ELF_IDENT_MAG2  2
#define ELF_IDENT_MAG3  3
#define ELF_IDENT_CLASS 4
#define ELF_IDENT_DATA  5

#define ELF_CLASS_64 2
#define ELF_DATA_LSB 1

#define ELF_TYPE_NONE 0
#define ELF_TYPE_EXEC 2

#define ELF_MACHINE_X86_64 0x3E

#define ELF_PHDR_TYPE_NULL 0x0
#define ELF_PHDR_TYPE_LOAD 0x1
#define ELF_PHDR_TYPE_SCE_DYNLIBDATA 0x61000000
#define ELF_PHDR_TYPE_SCE_RELRO 0x61000010
#define ELF_PHDR_TYPE_SCE_COMMENT 0x6FFFFF00
#define ELF_PHDR_TYPE_SCE_VERSION 0x6FFFFF01

#define ELF_PHDR_FLAG_X 0x1
#define ELF_PHDR_FLAG_W 0x2
#define ELF_PHDR_FLAG_R 0x4

#define ELF_ET_EXEC 0x2
#define ELF_ET_SCE_EXEC 0xFE00
#define ELF_ET_SCE_EXEC_ASLR 0xFE10
#define ELF_ET_SCE_DYNAMIC 0xFE18
#define ELF_IDENT_SIZE 0x10

#define LDR_SUCCESS			0
#define LDR_INVALID_ELF		1
#define LDR_SIZE_ERROR		2
#define LDR_MAP_ERROR		3
#define LDR_RELOC_ERROR		4
#define EI_NIDENT 16

#include "kernel.h"
#include "elf64.h"
#include "magic505.h"
#include "elf.h"
#include "elfs.h"
//#include "elfz.h"
#include "elf_common.h"
#include "c:\Users\sethk\Desktop\HomebrewDump\elfloader\elf.h"


#include "kernel.h"
#include "elf.h"
#include "elfs.h"
#include "elf64.h"
#include "x86.h"
#include "magic.h"
#include "magic505.h"
#include "magic455.h"

#define ASSERT_STRSIZE(struc, size) \
    _Static_assert(sizeof( struc ) == (size), "size of " #struc " != " #size )

typedef struct {
	Elf64_Word  sh_name;
	Elf64_Word  sh_type;
	Elf64_Xword sh_flags;
	Elf64_Addr  sh_addr;
	Elf64_Off   sh_offset;
	Elf64_Xword sh_size;
	Elf64_Word  sh_link;
	Elf64_Word  sh_info;
	Elf64_Xword sh_addralign;
	Elf64_Xword sh_entsize;
} Elf64_Shdr;

typedef struct {
	unsigned char	e_ident[EI_NIDENT];	
	Elf64_Half	e_type;		
	Elf64_Half	e_machine;	
	Elf64_Word	e_version;	
	Elf64_Addr	e_entry;	
	Elf64_Off	e_phoff;	
	Elf64_Off	e_shoff;	
	Elf64_Word	e_flags;	
	Elf64_Half	e_ehsize;	
	Elf64_Half	e_phentsize;	
	Elf64_Half	e_phnum;	
	Elf64_Half	e_shentsize;	
	Elf64_Half	e_shnum;	
	Elf64_Half	e_shstrndx;	
} Elf64_Ehdr;

int sceUserMainThreadPriority = 700;

size_t sceUserMainThreadStackSize = 512 * 1024;
//size_t sceLibcHeapSize = 256 * 1024 * 1024;

struct ksym_t kern;
int(*early_printf)(const char *fmt, ...) = NULL;

#define eprintf(...) do { if (early_printf) early_printf(__VA_ARGS__); } while(0)

#ifdef NO_SYMTAB

#define RESOLVE_NOERR(name) do { \
    if (kern_off_ ## name == 0) { \
        kern.name = 0; \
    } else { \
        kern.name = (void *)(kern.kern_base + kern_off_ ## name); \
    } \
} while (0);

#define RESOLVE(name) do { \
    if (kern_off_ ## name == 0) { \
        return 0; \
    } \
    RESOLVE_NOERR(name) \
} while (0);

#else

#define KERNSIZE    0x2000000

static const u8 ELF_IDENT[9] = "\x7f" "ELF\x02\x01\x01\x09\x00";
static struct Elf64_Sym *symtab;
static char *strtab;
static size_t strtab_size;

static Elf64_Ehdr *find_kern_ehdr(void)
{
	// Search for the kernel copy embedded in ubios, then follow it to see
	// where it was relocated to
	for (uintptr_t p = kern.kern_base; p < kern.kern_base + KERNSIZE; p += PAGE_SIZE) {
		Elf64_Ehdr *ehdr = (Elf64_Ehdr *)p;
		if (!memcmp(ehdr->e_ident, ELF_IDENT, sizeof(ELF_IDENT))) {
			for (size_t i = 0; i < ehdr->e_phnum; i++) {
				  Elf64_Phdr *phdr = (Elf64_Phdr *)(p + ehdr->e_phoff) + i;
				if (phdr->p_type == PT_PHDR) {
					return (Elf64_Ehdr *)(phdr->p_vaddr - ehdr->e_phoff);
				}
			}
		}
	}
	return NULL;
}

static struct Elf64_Dyn *elf_get_dyn(Elf64_Ehdr *ehdr)
{
	 Elf64_Phdr *phdr = ( Elf64_Phdr *)((uintptr_t)ehdr + ehdr->e_phoff);
	for (size_t i = 0; i < ehdr->e_phnum; i++, phdr++) {
		if (phdr->p_type == PT_DYNAMIC) {
			return (struct Elf64_Dyn *)phdr->p_vaddr;
		}
	}
	return NULL;
}

static int elf_parse_dyn(struct Elf64_Dyn *dyn)
{
	for (Elf64_Dyn *dp = dyn; dp->d_tag != DT_NULL; dp++) {
		switch (dp->d_tag) {
		case DT_SYMTAB:
			symtab = (struct Elf64_Sym *)dp->d_un.d_ptr;
			break;
		case DT_STRTAB:
			strtab = (char *)dp->d_un.d_ptr;
			break;
		case DT_STRSZ:
			strtab_size = dp->d_un.d_val;
			break;
		}
	}
	return symtab && strtab && strtab_size;
}


#define RESOLVE_NOERR(name) (kern.name = kernel_resolve(#name))
#define RESOLVEs(name) if (!RESOLVE_NOERR(name)) return 0;

#endif


#define	M_WAITOK 0x0002
#define	M_ZERO   0x0100

#define	VM_MEMATTR_DEFAULT		0x06

static volatile int _global_test = 0;




#define kdlsym_addr_memset  0x003205C0

#define kdlsym_addr_icc_nvs_read 0x00395830
#define kdlsym_addr_sceSblGetEAPInternalPartitionKey 0x006256E0

#include "kernel.h"
#include "linux_boot.h"
#include "x86.h"
#include "kexec.h"
#include "firmware.h"
#include "string.h"


struct payload_info
{
	uint64_t uaddr;
};


#include "magic505.h"
#include "magic455.h"
#include "AMD.h"
#include "freebsd.h"
#include "utilities.h"
#include "resolve.h"

/*#define EI_NIDENT 16


#define	PT_DYNAMIC  2
#define PT_PHDR     6

#define	DT_NULL     0
#define	DT_STRTAB   5
#define	DT_SYMTAB   6
#define	DT_STRSZ    10*/




#define DEBUG_SOCKET
#include "defines.h"

// thank you osdev for some help



static inline Elf64_Phdr *elf_pheader(struct Elf64_Ehdr *hdr) {
	if (!hdr->e_phoff) {
		return NULL;
	}

	return (Elf64_Phdr *)((uint64_t)hdr + hdr->e_phoff);
}
static inline Elf64_Phdr *elf_segment(struct Elf64_Ehdr *hdr, int idx) {
	uint64_t addr = (uint64_t)elf_pheader(hdr);
	if (!addr) {
		return NULL;
	}

	return (Elf64_Phdr *)(addr + (hdr->e_phentsize * idx));
}
static inline Elf64_Shdr *elf_sheader(struct Elf64_Ehdr *hdr) {
	if (!hdr->e_shoff) {
		return NULL;
	}

	return (Elf64_Shdr *)((uint64_t)hdr + hdr->e_shoff);
}
static inline Elf64_Shdr *elf_section(struct Elf64_Ehdr *hdr, int idx) {
	uint64_t addr = (uint64_t)elf_sheader(hdr);
	if (!addr) {
		return NULL;
	}

	return (Elf64_Shdr *)(addr + (hdr->e_shentsize * idx));
}


int elf_mapped_size(void *elf, size_t *msize) {
	struct Elf64_Ehdr *ehdr = (struct Elf64_Ehdr *)elf;

	// check magic
	if (memcmp(ehdr->e_ident, ElfMagic, 4)) {
		return LDR_INVALID_ELF;
	}

	size_t s = 0;

	 Elf64_Phdr *phdr = elf_pheader(ehdr);
	if (phdr) {
		// use segments
		for (int i = 0; i < ehdr->e_phnum; i++) {
			 Elf64_Phdr *phdr = elf_segment(ehdr, i);

			uint64_t delta = phdr->p_paddr + phdr->p_memsz;
			if (delta > s) {
				s = delta;
			}
		}
	}
	else {
		// use sections
		for (int i = 0; i < ehdr->e_shnum; i++) {
			Elf64_Shdr *shdr = elf_section(ehdr, i);

			uint64_t delta = shdr->sh_addr + shdr->sh_size;
			if (delta > s) {
				s = delta;
			}
		}
	}

	if (msize) {
		*msize = s;
	}

	return LDR_SUCCESS;
}

int map_elf(void *elf, void *exec) {
	struct Elf64_Ehdr *ehdr = (struct Elf64_Ehdr *)elf;

	Elf64_Phdr *phdr = elf_pheader(ehdr);
	if (phdr) {
		// use segments
		for (int i = 0; i < ehdr->e_phnum; i++) {
			 Elf64_Phdr *phdr = elf_segment(ehdr, i);

			if (phdr->p_filesz) {
				memcpy((uint8_t *)exec + phdr->p_paddr, (uint8_t *)elf + phdr->p_offset, phdr->p_filesz);
			}

			if (phdr->p_memsz - phdr->p_filesz) {
				memset((uint8_t *)exec + phdr->p_paddr + phdr->p_filesz, NULL, phdr->p_memsz - phdr->p_filesz);
			}
		}
	}
	else {
		// use sections
		for (int i = 0; i < ehdr->e_shnum; i++) {
			Elf64_Shdr *shdr = elf_section(ehdr, i);

			if (!(shdr->sh_flags & SHF_ALLOC)) {
				continue;
			}

			if (shdr->sh_size) {
				memcpy((uint8_t *)exec + shdr->sh_addr, (uint8_t *)elf + shdr->sh_offset, shdr->sh_size);
			}
		}
	}

	return LDR_SUCCESS;
}

int relocate_elf(void *elf, void *exec) {
	struct Elf64_Ehdr *ehdr = (struct Elf64_Ehdr *)elf;

	for (int i = 0; i < ehdr->e_shnum; i++) {
		Elf64_Shdr *shdr = elf_section(ehdr, i);

		// check table
		if (shdr->sh_type == SHT_REL) {
			// process each entry in the table
			for (int j = 0; j < shdr->sh_size / shdr->sh_entsize; j++) {
				struct Elf64_Rela *reltab = &((struct Elf64_Rela *)((uint64_t)ehdr + shdr->sh_offset))[j];
				uint8_t **ref = (uint8_t **)((uint8_t *)exec + reltab->r_offset);

				switch (ELF64_R_TYPE(reltab->r_info)) {
				case R_X86_64_RELATIVE:
					*ref = (uint8_t *)exec + reltab->r_addend;
					break;
				case R_X86_64_64:
				case R_X86_64_JUMP_SLOT:
				case R_X86_64_GLOB_DAT:
					// TODO: relocations
					break;
				}
			}
		}
	}

	return LDR_SUCCESS;
}

int load_elf(void *elf, size_t size, void *exec, size_t msize, void **entry) {
	// check arguments
	if (!elf || !exec || !size || !msize) {
		return LDR_INVALID_ELF;
	}

	struct Elf64_Ehdr *ehdr = (struct Elf64_Ehdr *)elf;

	// check magic
	if (memcmp(ehdr->e_ident, ElfMagic, 4)) {
		return LDR_INVALID_ELF;
	}

	// only support relocatable elfs rn lol
	if (ehdr->e_type != ET_REL && ehdr->e_type != ET_DYN) {
		return LDR_INVALID_ELF;
	}

	size_t s = 0;
	if (elf_mapped_size(elf, &s)) {
		return LDR_SIZE_ERROR;
	}

	if (s > msize) {
		return LDR_SIZE_ERROR;
	}

	if (map_elf(elf, exec)) {
		return LDR_MAP_ERROR;
	}

	if (relocate_elf(elf, exec)) {
		return LDR_RELOC_ERROR;
	}

	if (entry) {
		*entry = (void *)((uint64_t)exec + ehdr->e_entry);
	}

	return LDR_SUCCESS;
}


//its good

#define	SEEK_SET	0
#define	SEEK_CUR	1
#define	SEEK_END	2

#include "unjail.h"
#include "x86-64.h"
//#include "stdio.h"
#include "C:\Program Files (x86)\SCE\ORBIS SDKs\4.500\target\include\kernel.h"
#include "magics.h"
#include "dump.h"
#include "lv2.h"
#include "definess.h"
#include "stdlib.h"
//#include "_mmap.h"
#include "stdio.h"
//#include "definez.h"
#include "stdlib.h"
#include "string.h"
#include "_pthread.h"
#include "c:\Program Files (x86)\SCE\ORBIS SDKs\4.500\target\include\time.h"
#include "elf64.h"
#include "sys/dirent.h"
#include "netinet/in.h"
#include "netinet/tcp.h"
#include "sys/socket.h"
//#include <C:\Users\sethk\Desktop\oni-framework-master\include\oni/config.h>
//#include <C:\Users\sethk\Desktop\oni-framework-master\include\oni/messaging/message.h>
//#include <C:\Users\sethk\Desktop\oni-framework-master\include\oni/messaging/messagemanager.h>
//#include <C:\Users\sethk\Desktop\oni-framework-master\include\oni/utils/kdlsym.h>
//#include <C:\Users\sethk\Desktop\oni-framework-master\include\oni/utils/logger.h>
//#include <C:\Users\sethk\Desktop\oni-framework-master\include\oni/utils/memory/allocator.h>
//#include <C:\Users\sethk\Desktop\oni-framework-master\include\oni/utils/sys_wrappers.h>
//#include <C:\Users\sethk\Desktop\oni-framework-master\include\oni/utils/cpu.h>
//#include <sys/ioctl.h>
#include "elf_common.h"
//#include "kdumper/kernel_utils.h"
#include "Modded_SDK/libPS4/include/ps4.h"

#include "C:\Users\sethk\Desktop\HomebrewDump\include\assert.h"

#define	SEEK_SET	0
#define	SEEK_CUR	1
#define	SEEK_END	2


#include "defines.h"

#include "pup.h"
#include "pupup.h"



#define MAP_POPULATE    0x8000

int getdents(int fd, char *buf, size_t count)
{
	return syscall(272, fd, buf, count);
}

typedef uint8_t  u8;
typedef uint32_t u32;
typedef uint64_t uint64_t;

typedef void(*BinEntryPoint)();

static const u32 PAGE_SZ = 0x1000;         // 4kb page size on ps4

										   /* golden */
										   /* 1/2/2018 */

struct EAP_PartKey_t {
	uint8_t encrypted[0x60];
	uint8_t key[0x20];
};

ssize_t write(int fd, const void *buf, size_t count)
{
	return syscall(4, fd, buf, count);
}


off_t lseek(int fd, off_t offset, int origin)
{
	return syscall(478, fd, offset, origin);
}

int mprotects(void *addr, size_t len, int prot)
{
	return syscall(74, addr, len, prot);
}

#define KERNEL_CHUNK_SIZE	0x1000
#define KERNEL_CHUNK_NUMBER	0x69B8
// order: (to avoid kernel panic by reading not allocated memory)
#define	KERN_405_XFAST_SYSCALL		0x30EB30	// #3
#define	KERN_455_XFAST_SYSCALL		0x3095D0	// #2
#define	KERN_501_XFAST_SYSCALL		0x1C0		// #1
#define	KERN_505_XFAST_SYSCALL		0x1C0		// #1

#define KERN_405_PRISON_0		0xF26010
#define KERN_455_PRISON_0		0x10399B0
#define KERN_501_PRISON_0		0x10986A0
#define KERN_505_PRISON_0		0x10986A0

#define KERN_405_ROOTVNODE		0x206D250
#define KERN_455_ROOTVNODE		0x21AFA30
#define KERN_501_ROOTVNODE		0x22C19F0
#define KERN_505_ROOTVNODE		0x22C1A70

#define KERN_405_PRINTF			0x347580
#define KERN_455_PRINTF			0x17F30
#define KERN_501_PRINTF			0x435C70
#define KERN_505_PRINTF			0x436040

#define KERN_405_COPYIN			0x286DF0

#define KERN_405_COPYOUT		0x286D70
#define KERN_455_COPYOUT		0x14A7B0
#define KERN_501_COPYOUT		0x1EA520
#define KERN_505_COPYOUT		0x1EA630

#define KERN_405_MEMSET_ALIGNED		0
#define KERN_455_MEMSET_ALIGNED		0x302BD0
#define KERN_501_MEMSET_ALIGNED		0x3201F0
#define KERN_505_MEMSET_ALIGNED		0x3205C0

#define KERN_405_BZERO_ALIGNED		0x286C30
#define KERN_455_BZERO_ALIGNED		0x14A570
#define KERN_501_BZERO_ALIGNED		0x1EA360
#define KERN_505_BZERO_ALIGNED		0x1EA470

int nmount(struct iovec *iov, uint32_t niov, int flags)
{
	return syscall(378, iov, niov, flags);
}

void *mmap(void *addr, size_t len, int prot, int flags, int fd, off_t offset)
{
	return (void *)(syscall(477, addr, len, prot, flags, fd, offset));
}

int munmap(void *addr, size_t len)
{
	return syscall(73, addr, len);
}

struct ran_args
{
	uint64_t uaddr;
	uint64_t kaddr;
};


typedef struct {
	int index;
	uint64_t fileoff;
	size_t bufsz;
	size_t filesz;
	int enc;
} SegmentBufInfo;

int stat(const char *path, struct stat *sb)
{
	return syscall(188, path, sb);
}

void print_phdr( Elf64_Phdr *phdr) {}

#define printf_notification(...) \
	do { \
		char message[256]; \
		snprintf(message, sizeof(message), ##__VA_ARGS__); \
		sceSysUtilSendSystemNotificationWithText(222, message); \
	} while (0)

#define TRUE 1
#define FALSE 0

#define devclass_get_devices 0x312660
#define devclass_find 0x312020

/*void dumpfile(char *name, uint8_t *raw, size_t size) {
	FILE *fd = fopen(name, "wb");
	if (fd != NULL) {
		fwrite(raw, 1, size, fd);
		fclose(fd);
	}
	else {
		////////////printfsocket("dump err.\n");
	}
}

void print_phdr( Elf64_Phdr *phdr) {
	////////////printfsocket("=================================\n");
	////////////printfsocket("     p_type %08x\n", phdr->p_type);
	////////////printfsocket("     p_flags %08x\n", phdr->p_flags);
	////////////printfsocket("     p_offset %016llx\n", phdr->p_offset);
	////////////printfsocket("     p_vaddr %016llx\n", phdr->p_vaddr);
	////////////printfsocket("     p_paddr %016llx\n", phdr->p_paddr);
	////////////printfsocket("     p_filesz %016llx\n", phdr->p_filesz);
	////////////printfsocket("     p_memsz %016llx\n", phdr->p_memsz);
	////////////printfsocket("     p_align %016llx\n", phdr->p_align);
}


int read_decrypt_segment(int fd, uint64_t index, uint64_t offset, size_t size, uint8_t *out) {
	uint64_t realOffset = (index << 32) | offset;
	uint8_t *addr = (uint8_t*)mmap(0, size, PROT_READ, MAP_PRIVATE | 0x80000, fd, realOffset);
	if (addr != MAP_FAILED) {
		memcpy(out, addr, size);
		munmap(addr, size);
		return TRUE;
	}
	else {
		////////////printfsocket("mmap segment [%d] err(%d) : %s\n", index, errno, strerror(errno));
		return FALSE;
	}
}



int is_segment_in_other_segment( Elf64_Phdr *phdr, int index,  Elf64_Phdr *phdrs, int num) {
	for (int i = 0; i < num; i += 1) {
		 Elf64_Phdr *p = &phdrs[i];
		if (i != index) {
			if (p->p_filesz > 0) {
				// ////////////printfsocket("offset : %016x,  toffset : %016x\n", phdr->p_offset, p->p_offset);
				// ////////////printfsocket("offset : %016x,  toffset + size : %016x\n", phdr->p_offset, p->p_offset + p->p_filesz);
				if ((phdr->p_offset >= p->p_offset) && ((phdr->p_offset + phdr->p_filesz) <= (p->p_offset + p->p_filesz))) {
					return TRUE;
				}
			}
		}
	}
	return FALSE;
}



SegmentBufInfo *parse_phdr( Elf64_Phdr *phdrs, int num, int *segBufNum) {
	////////////printfsocket("segment num : %d\n", num);
	SegmentBufInfo *infos = (SegmentBufInfo *)malloc(sizeof(SegmentBufInfo) * num);
	int segindex = 0;
	for (int i = 0; i < num; i += 1) {
		 Elf64_Phdr *phdr = &phdrs[i];
		// print_phdr(phdr);

		if (phdr->p_filesz > 0 && phdr->p_type != 0x6fffff01) {
			if (!is_segment_in_other_segment(phdr, i, phdrs, num)) {
				SegmentBufInfo *info = &infos[segindex];
				segindex += 1;
				info->index = i;
				info->bufsz = (phdr->p_filesz + (phdr->p_align - 1)) & (~(phdr->p_align - 1));
				info->filesz = phdr->p_filesz;
				info->fileoff = phdr->p_offset;

				// ////////////printfsocket("seg buf info %d -->\n", segindex);
				// ////////////printfsocket("    index : %d\n    bufsz : 0x%016llX\n", info->index, info->bufsz);
				// ////////////printfsocket("    filesz : 0x%016llX\n    fileoff : 0x%016llX\n", info->filesz, info->fileoff);
			}
		}
	}
	*segBufNum = segindex;
	return infos;
}


void do_dump(char *saveFile, int fd, SegmentBufInfo *segBufs, int segBufNum, Elf64_Ehdr *ehdr) {
	FILE *sf = fopen(saveFile, "wb");
	if (sf != NULL) {
		size_t elfsz = 0x40 + ehdr->e_phnum * sizeof( Elf64_Phdr);
		////////////printfsocket("elf header + phdr size : 0x%08X\n", elfsz);
		fwrite(ehdr, elfsz, 1, sf);

		for (int i = 0; i < segBufNum; i += 1) {
			////////////printfsocket("sbuf index : %d, offset : 0x%016x, bufsz : 0x%016x, filesz : 0x%016x\n", segBufs[i].index, segBufs[i].fileoff, segBufs[i].bufsz, segBufs[i].filesz);
			uint8_t *buf = (uint8_t*)malloc(segBufs[i].bufsz);
			memset(buf, 0, segBufs[i].bufsz);
			if (read_decrypt_segment(fd, segBufs[i].index, 0, segBufs[i].filesz, buf)) {
				fseek(sf, segBufs[i].fileoff, SEEK_SET);
				fwrite(buf, segBufs[i].bufsz, 1, sf);
			}
			free(buf);
		}
		fclose(sf);
	}
	else {
		////////////printfsocket("fopen %s err : %s\n", saveFile, strerror(errno));
	}
}



void decrypt_and_dump_self(char *selfFile, char *saveFile) {

	// patch for decrypting

	////////////printfsocket("applying patches\n");

	int fd = open(selfFile, O_RDONLY, 0);
	if (fd != -1) {
		void *addr = mmap(0, 0x4000, PROT_READ, MAP_PRIVATE, fd, 0);
		if (addr != MAP_FAILED) {
			////////////printfsocket("mmap %s : %p\n", selfFile, addr);

			uint16_t snum = *(uint16_t*)((uint8_t*)addr + 0x18);
			Elf64_Ehdr *ehdr = (Elf64_Ehdr *)((uint8_t*)addr + 0x20 + snum * 0x20);
			////////////printfsocket("ehdr : %p\n", ehdr);

			 Elf64_Phdr *phdrs = ( Elf64_Phdr *)((uint8_t *)ehdr + 0x40);
			////////////printfsocket("phdrs : %p\n", phdrs);

			int segBufNum = 0;
			SegmentBufInfo *segBufs = parse_phdr(phdrs, ehdr->e_phnum, &segBufNum);
			do_dump(saveFile, fd, segBufs, segBufNum, ehdr);
			////////////printfsocket("dump completed\n");

			free(segBufs);
			munmap(addr, 0x4000);
		}
		else {
			////////////printfsocket("mmap file %s err : %s\n", selfFile, strerror(errno));
		}
	}
	else {
		////////////printfsocket("open %s err : %s\n", selfFile, strerror(errno));
	}
	// set it back to normal

	////////////printfsocket("restoring kernel\n");
}*/

void *(*k_malloc)(unsigned long size, void *type, int flags);
void(*k_free)(void *addr, void *type);
void(*k_memcpy)(void *dst, const void *src, size_t len);
void *(*k_memset)(void * ptr, int value, size_t num);
int(*k_memcmp)(const void * ptr1, const void * ptr2, size_t num);
size_t(*k_strlen)(const char *str);

struct jkuap {
	uint64_t sycall;
	void *payload;
	size_t psize;
};

extern uint8_t kpayload505[];
extern int32_t kpayload505_size;

extern uint8_t kpayload455[];
extern int32_t kpayload455_size;


extern uint8_t remoteplay505[];
extern int32_t remoteplay505_size;


#include <libdbg.h>


#define DECRYPT_SIZE 0x100000

_Bool read_decrypt_segment(int fd, uint64_t index, uint64_t offset, size_t size, uint8_t *out)
{
	uint8_t *outPtr = out;
	uint64_t outSize = size;
	uint64_t realOffset = (index << 32) | offset;
	while (outSize > 0)
	{
		size_t bytes = (outSize > DECRYPT_SIZE) ? DECRYPT_SIZE : outSize;
		uint8_t *addr = (uint8_t*)mmap(0, bytes, PROT_READ, MAP_PRIVATE | 0x80000, fd, realOffset);
		if (addr != MAP_FAILED)
		{
			memcpy(outPtr, addr, bytes);
			munmap(addr, bytes);
		}
		else
		{
			////printfsocket("mmap segment [%d] err(%d) : %s\n", index, errno, strerror(errno));
			return FALSE;
		}
		outPtr += bytes;
		outSize -= bytes;
		realOffset += bytes;
	}
	return TRUE;
}

int is_segment_in_other_segment( Elf64_Phdr *phdr, int index,  Elf64_Phdr *phdrs, int num) {
	for (int i = 0; i < num; i += 1) {
		 Elf64_Phdr *p = &phdrs[i];
		if (i != index) {
			if (p->p_filesz > 0) {
				////printfsocket("offset : %016x,  toffset : %016x\n", phdr->p_offset, p->p_offset);
				////printfsocket("offset : %016x,  toffset + size : %016x\n", phdr->p_offset, p->p_offset + p->p_filesz);
				if ((phdr->p_offset >= p->p_offset) && ((phdr->p_offset + phdr->p_filesz) <= (p->p_offset + p->p_filesz))) {
					return TRUE;
				}
			}
		}
	}
	return FALSE;
}

SegmentBufInfo *parse_phdr( Elf64_Phdr *phdrs, int num, int *segBufNum) {
	////printfsocket("segment num : %d\n", num);
	SegmentBufInfo *infos = (SegmentBufInfo *)malloc(sizeof(SegmentBufInfo) * num);
	int segindex = 0;
	for (int i = 0; i < num; i += 1) {
		 Elf64_Phdr *phdr = &phdrs[i];
		print_phdr(phdr);

		if (phdr->p_filesz > 0) {
			if ((!is_segment_in_other_segment(phdr, i, phdrs, num)) || (phdr->p_type == 0x6fffff01)) {
				SegmentBufInfo *info = &infos[segindex];
				segindex += 1;
				info->index = i;
				info->bufsz = (phdr->p_filesz + (phdr->p_align - 1)) & (~(phdr->p_align - 1));
				info->filesz = phdr->p_filesz;
				info->fileoff = phdr->p_offset;
				info->enc = (phdr->p_type != 0x6fffff01) ? TRUE : FALSE;

				////printfsocket("seg buf info %d -->\n", segindex);
				////printfsocket("    index : %d\n    bufsz : 0x%016llX\n", info->index, info->bufsz);
				////printfsocket("    filesz : 0x%016llX\n    fileoff : 0x%016llX\n", info->filesz, info->fileoff);
			}
		}
	}
	*segBufNum = segindex;
	return infos;
}

void do_dump(char *saveFile, int fd, SegmentBufInfo *segBufs, int segBufNum, Elf64_Ehdr *ehdr) {
	int sf = open(saveFile, O_WRONLY | O_CREAT | O_TRUNC, 0777);
	if (sf != -1) {
		size_t elfsz = 0x40 + ehdr->e_phnum * sizeof( Elf64_Phdr);
		////printfsocket("elf header + phdr size : 0x%08X\n", elfsz);
		write(sf, ehdr, elfsz);

		for (int i = 0; i < segBufNum; i += 1) {
			////printfsocket("sbuf index : %d, offset : 0x%016x, bufsz : 0x%016x, filesz : 0x%016x, enc : %d\n", segBufs[i].index, segBufs[i].fileoff, segBufs[i].bufsz, segBufs[i].filesz, segBufs[i].enc);
			uint8_t *buf = (uint8_t*)malloc(segBufs[i].bufsz);
			memset(buf, 0, segBufs[i].bufsz);
			if (segBufs[i].enc)
			{
				if (read_decrypt_segment(fd, segBufs[i].index, 0, segBufs[i].filesz, buf)) {
					lseek(sf, segBufs[i].fileoff, SEEK_SET);
					write(sf, buf, segBufs[i].bufsz);
				}
			}
			else
			{
				lseek(fd, -segBufs[i].filesz, SEEK_END);
				read(fd, buf, segBufs[i].filesz);
				lseek(sf, segBufs[i].fileoff, SEEK_SET);
				write(sf, buf, segBufs[i].filesz);
			}
			free(buf);
		}
		close(sf);
	}
	else {
		////printfsocket("open %s err : %s\n", saveFile, strerror(errno));
	}
}

void decrypt_and_dump_self(char *selfFile, char *saveFile) {
	int fd = open(selfFile, O_RDONLY, 0);
	if (fd != -1) {
		void *addr = mmap(0, 0x4000, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
		if (addr != MAP_FAILED) {
			////printfsocket("mmap %s : %p\n", selfFile, addr);

			uint16_t snum = *(uint16_t*)((uint8_t*)addr + 0x18);
			Elf64_Ehdr *ehdr = (Elf64_Ehdr *)((uint8_t*)addr + 0x20 + snum * 0x20);
			////printfsocket("ehdr : %p\n", ehdr);

			// shdr fix
			ehdr->e_shoff = ehdr->e_shentsize = ehdr->e_shnum = ehdr->e_shstrndx = 0;

			 Elf64_Phdr *phdrs = ( Elf64_Phdr *)((uint8_t *)ehdr + 0x40);
			////printfsocket("phdrs : %p\n", phdrs);

			int segBufNum = 0;
			SegmentBufInfo *segBufs = parse_phdr(phdrs, ehdr->e_phnum, &segBufNum);
			do_dump(saveFile, fd, segBufs, segBufNum, ehdr);
			////printfsocket("dump completed\n");

			free(segBufs);
			munmap(addr, 0x4000);
		}
		else {
			////printfsocket("mmap file %s err : %s\n", selfFile, strerror(errno));
		}
		close(fd);
	
	}
	else {
		////printfsocket("open %s err : %s\n", selfFile, strerror(errno));
	}
}

void decrypt_and_dump_selfs(char selfFile, char saveFile) {
	int fd = open(selfFile, O_RDONLY, 0);
	if (fd != -1) {
		void *addr = mmap(0, 0x4000, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
		if (addr != MAP_FAILED) {
			////printfsocket("mmap %s : %p\n", selfFile, addr);

			uint16_t snum = *(uint16_t*)((uint8_t*)addr + 0x18);
			Elf64_Ehdr *ehdr = (Elf64_Ehdr *)((uint8_t*)addr + 0x20 + snum * 0x20);
			////printfsocket("ehdr : %p\n", ehdr);

			// shdr fix
			ehdr->e_shoff = ehdr->e_shentsize = ehdr->e_shnum = ehdr->e_shstrndx = 0;

			Elf64_Phdr *phdrs = (Elf64_Phdr *)((uint8_t *)ehdr + 0x40);
			////printfsocket("phdrs : %p\n", phdrs);

			int segBufNum = 0;
			SegmentBufInfo *segBufs = parse_phdr(phdrs, ehdr->e_phnum, &segBufNum);
			do_dump(saveFile, fd, segBufs, segBufNum, ehdr);
			////printfsocket("dump completed\n");

			free(segBufs);
			munmap(addr, 0x4000);
		}
		else {
			////printfsocket("mmap file %s err : %s\n", selfFile, strerror(errno));
		}
		close(fd);

	}
	else {
		////printfsocket("open %s err : %s\n", selfFile, strerror(errno));
	}
}




int mkdir(const char *pathname, mode_t mode)
{
	return syscall(136, pathname, mode);
}

int rmdir(const char *path)
{
	return syscall(137, path);
}


int rename(const char *oldpath, const char *newpath)
{
	return syscall(128, oldpath, newpath);
}


int readlink(const char *path, char *buf, int bufsiz)
{
	return syscall(58, path, buf, bufsiz);
}


int unlink(const char *pathname)
{
	return syscall(10, pathname);
}

int open(const char *path, int flags, int mode)
{
	return syscall(5, path, flags, mode);
}




int close(int fd)
{
	return syscall(6, fd);
}




ssize_t read(int fd, void *buf, size_t nbyte)
{
	return syscall(3, fd, buf, nbyte);
}

struct kpayload_get_fw_version_info
{
	uint64_t uaddr;
};

struct kpayload_get_fw_version_args
{
	void* syscall_handler;
	struct kpayload_get_fw_version_info* kpayload_get_fw_version_info;
};

struct kpayload_jailbreak_info
{
	uint64_t fw_version;
};

struct kpayload_jailbreak_args
{
	void* syscall_handler;
	struct kpayload_jailbreak_info* kpayload_jailbreak_info;
};

struct kpayload_get_kbase_info
{
	uint64_t fw_version;
	uint64_t uaddr;
};

struct kpayload_get_kbase_args
{
	void* syscall_handler;
	struct kpayload_get_kbase_info* kpayload_get_kbase_info;
};

struct kpayload_kernel_dumper_info
{
	uint64_t fw_version;
	uint64_t uaddr;
	uint64_t kaddr;
	size_t size;
};

struct kpayload_kernel_dumper_args
{
	void* syscall_handler;
	struct kpayload_kernel_dumper_info* kpayload_kernel_dumper_info;
};


int kpayload_get_fw_version(struct thread *td, struct kpayload_get_fw_version_args* args) {

	void* kbase = 0;

	int(*copyout)(const void *kaddr, void *uaddr, size_t len) = 0;

	uint64_t fw_version = 0x666;

	// Kernel base resolving followed by kern_printf resolving
	if (!memcmp((char*)(&((uint8_t*)__readmsr(0xC0000082))[-KERN_505_XFAST_SYSCALL]), (char[4]) { 0x7F, 0x45, 0x4C, 0x46 }, 4)) {
		kbase = &((uint8_t*)__readmsr(0xC0000082))[-KERN_505_XFAST_SYSCALL];
		//if (!memcmp((char*)(kbase + KERN_505_PRINTF), (char[12]) { 0x55, 0x48, 0x89, 0xE5, 0x53, 0x48, 0x83, 0xEC, 0x58, 0x48, 0x8D, 0x1D }, 12)) {
		fw_version = 0x505;
		copyout = (void *)(kbase + KERN_505_COPYOUT);
	}
	else if (!memcmp((char*)(&((uint8_t*)__readmsr(0xC0000082))[-KERN_455_XFAST_SYSCALL]), (char[4]) { 0x7F, 0x45, 0x4C, 0x46 }, 4)) {
		kbase = &((uint8_t*)__readmsr(0xC0000082))[-KERN_455_XFAST_SYSCALL];
		fw_version = 0x455;
		copyout = (void *)(kbase + KERN_455_COPYOUT);
	}
	else if (!memcmp((char*)(&((uint8_t*)__readmsr(0xC0000082))[-KERN_405_XFAST_SYSCALL]), (char[4]) { 0x7F, 0x45, 0x4C, 0x46 }, 4)) {
		kbase = &((uint8_t*)__readmsr(0xC0000082))[-KERN_405_XFAST_SYSCALL];
		fw_version = 0x405;
		copyout = (void *)(kbase + KERN_405_COPYOUT);
	}
	else return -1;

	// Put the fw version in userland so we can use it later
	uint64_t uaddr = args->kpayload_get_fw_version_info->uaddr;
	copyout(&fw_version, (uint64_t*)uaddr, 8);

	return 0;
}


uint64_t get_fw_version(void) {
	uint64_t fw_version = 0x666;
	uint64_t* fw_version_ptr = mmap(NULL, 8, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0); // Allocate a buffer in userland
	struct kpayload_get_fw_version_info kpayload_get_fw_version_info;
	kpayload_get_fw_version_info.uaddr = (uint64_t)fw_version_ptr;
	kexec(&kpayload_get_fw_version, &kpayload_get_fw_version_info);
	memcpy(&fw_version, fw_version_ptr, 8);
	munmap(fw_version_ptr, 8);
	return fw_version;
}

int kpayload_jailbreak(struct thread *td, struct kpayload_jailbreak_args* args) {

	struct filedesc* fd;
	struct ucred* cred;
	fd = td->td_proc->p_fd;
	cred = td->td_proc->p_ucred;

	void* kbase;
	uint8_t* kernel_ptr;
	void** got_prison0;
	void** got_rootvnode;

	uint64_t fw_version = args->kpayload_jailbreak_info->fw_version;

	if (fw_version == 0x405) {
		// Kernel base resolving
		kbase = &((uint8_t*)__readmsr(0xC0000082))[-KERN_405_XFAST_SYSCALL];

		// Kernel pointers resolving
		kernel_ptr = (uint8_t*)kbase;
		got_prison0 = (void**)&kernel_ptr[KERN_405_PRISON_0];
		got_rootvnode = (void**)&kernel_ptr[KERN_405_ROOTVNODE];
	}
	else if (fw_version == 0x455) {
		// Kernel base resolving
		kbase = &((uint8_t*)__readmsr(0xC0000082))[-KERN_455_XFAST_SYSCALL];

		// Kernel pointers resolving
		kernel_ptr = (uint8_t*)kbase;
		got_prison0 = (void**)&kernel_ptr[KERN_455_PRISON_0];
		got_rootvnode = (void**)&kernel_ptr[KERN_455_ROOTVNODE];
	}
	else if (fw_version == 0x501) {
		// Kernel base resolving
		kbase = &((uint8_t*)__readmsr(0xC0000082))[-KERN_501_XFAST_SYSCALL];

		// Kernel pointers resolving
		kernel_ptr = (uint8_t*)kbase;
		got_prison0 = (void**)&kernel_ptr[KERN_501_PRISON_0];
		got_rootvnode = (void**)&kernel_ptr[KERN_501_ROOTVNODE];
	}
	else if (fw_version == 0x505) {
		// Kernel base resolving
		kbase = &((uint8_t*)__readmsr(0xC0000082))[-KERN_505_XFAST_SYSCALL];

		// Kernel pointers resolving
		kernel_ptr = (uint8_t*)kbase;
		got_prison0 = (void**)&kernel_ptr[KERN_505_PRISON_0];
		got_rootvnode = (void**)&kernel_ptr[KERN_505_ROOTVNODE];
	}
	else return -1;

	cred->cr_uid = 0;
	cred->cr_ruid = 0;
	cred->cr_rgid = 0;
	cred->cr_groups[0] = 0;

	cred->cr_prison = *got_prison0;
	fd->fd_rdir = fd->fd_jdir = *got_rootvnode;

	// Escalate ucred privs, needed for userland access to the filesystem e.g mounting & decrypting files
	void *td_ucred = *(void **)(((char *)td) + 304); // p_ucred == td_ucred

													 // sceSblACMgrIsSystemUcred
	uint64_t *sonyCred = (uint64_t *)(((char *)td_ucred) + 96);
	*sonyCred = 0xffffffffffffffff;

	// sceSblACMgrGetDeviceAccessType
	uint64_t *sceProcessAuthorityId = (uint64_t *)(((char *)td_ucred) + 88);
	*sceProcessAuthorityId = 0x3800000000000010; // SceShellcore paid

												 // sceSblACMgrHasSceProcessCapability
	uint64_t *sceProcCap = (uint64_t *)(((char *)td_ucred) + 104);
	*sceProcCap = 0xffffffffffffffff; // Max capability

	return 0;
}


int kpayload_get_kbase(struct thread *td, struct kpayload_get_kbase_args* args) {

	void* kbase;

	int(*copyout)(const void *kaddr, void *uaddr, size_t len);

	uint64_t fw_version = args->kpayload_get_kbase_info->fw_version;

	if (fw_version == 0x405) {
		// Kernel base resolving
		kbase = &((uint8_t*)__readmsr(0xC0000082))[-KERN_405_XFAST_SYSCALL];

		// Kernel functions resolving
		copyout = (void *)(kbase + KERN_405_COPYOUT);
	}
	else if (fw_version == 0x455) {
		// Kernel base resolving
		kbase = &((uint8_t*)__readmsr(0xC0000082))[-KERN_455_XFAST_SYSCALL];

		// Kernel functions resolving
		copyout = (void *)(kbase + KERN_455_COPYOUT);
	}
	else if (fw_version == 0x505) {
		// Kernel base resolving
		kbase = &((uint8_t*)__readmsr(0xC0000082))[-KERN_505_XFAST_SYSCALL];

		// Kernel functions resolving
		copyout = (void *)(kbase + KERN_505_COPYOUT);
	}
	else return -1;

	// Put the kernel base in userland so we can use it later
	uint64_t uaddr = args->kpayload_get_kbase_info->uaddr;
	copyout(&kbase, (uint64_t*)uaddr, 8);

	return 0;
}


int kpayload_kernel_dumper(struct thread *td, struct kpayload_kernel_dumper_args* args) {

	void* kbase;

	int(*copyout)(const void *kaddr, void *uaddr, size_t len);

	uint64_t fw_version = args->kpayload_kernel_dumper_info->fw_version;

	if (fw_version == 0x405) {
		// Kernel base resolving
		kbase = &((uint8_t*)__readmsr(0xC0000082))[-KERN_405_XFAST_SYSCALL];

		// Kernel functions resolving
		//int (*printfkernel)(const char *fmt, ...) = (void *)(kbase + KERN_405_PRINTF);
		copyout = (void *)(kbase + KERN_405_COPYOUT);
	}
	else if (fw_version == 0x455) {
		// Kernel base resolving
		kbase = &((uint8_t*)__readmsr(0xC0000082))[-KERN_455_XFAST_SYSCALL];

		// Kernel functions resolving
		//int (*printfkernel)(const char *fmt, ...) = (void *)(kbase + KERN_455_PRINTF);
		copyout = (void *)(kbase + KERN_455_COPYOUT);
	}
	else if (fw_version == 0x501) {
		// Kernel base resolving
		kbase = &((uint8_t*)__readmsr(0xC0000082))[-KERN_501_XFAST_SYSCALL];

		// Kernel functions resolving
		//int (*printfkernel)(const char *fmt, ...) = (void *)(kbase + KERN_501_PRINTF);
		copyout = (void *)(kbase + KERN_501_COPYOUT);
	}
	else if (fw_version == 0x505) {
		// Kernel base resolving
		kbase = &((uint8_t*)__readmsr(0xC0000082))[-KERN_505_XFAST_SYSCALL];

		// Kernel functions resolving
		//int (*printfkernel)(const char *fmt, ...) = (void *)(kbase + KERN_505_PRINTF);
		//int(*copyout)(const void *kaddr, void *uaddr, size_t len);

		copyout = (void *)(kbase + KERN_505_COPYOUT);
	}
	else return -1;

	// Pull in arguments
	uint64_t kaddr = args->kpayload_kernel_dumper_info->kaddr;
	uint64_t uaddr = args->kpayload_kernel_dumper_info->uaddr;
	size_t size = args->kpayload_kernel_dumper_info->size;

	// Copyout into userland memory from the kaddr we specify
	int cpRet = copyout((uint64_t*)kaddr, (uint64_t*)uaddr, size);

	// If mapping doesn't exist then zero out that memory
	if (cpRet == -1) {
		//printfkernel("zero out userland memory at 0x%016llx\n", kaddr);
		memset((uint64_t*)uaddr, 0, size);
	}

	return cpRet;
}


int jailbreak(uint64_t fw_version) {
	struct kpayload_jailbreak_info kpayload_jailbreak_info;
	kpayload_jailbreak_info.fw_version = fw_version;
	kexec(&kpayload_jailbreak, &kpayload_jailbreak_info);
	return 0;
}

uint64_t get_kbases(uint64_t fw_version) {
	uint64_t kbase = -1;
	uint64_t* kbase_ptr = mmap(NULL, 8, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0); // Allocate a buffer in userland
	struct kpayload_get_kbase_info kpayload_get_kbase_info;
	kpayload_get_kbase_info.fw_version = fw_version;
	kpayload_get_kbase_info.uaddr = (uint64_t)kbase_ptr;
	kexec(&kpayload_get_kbase, &kpayload_get_kbase_info);
	memcpy(&kbase, kbase_ptr, 8);
	munmap(kbase_ptr, 8);
	return kbase;
}

uint64_t dump_kernel(uint64_t fw_version, uint64_t kaddr, uint64_t* dump, size_t size) {
	struct kpayload_kernel_dumper_info kpayload_kernel_dumper_info;
	kpayload_kernel_dumper_info.fw_version = fw_version;
	kpayload_kernel_dumper_info.kaddr = kaddr;
	kpayload_kernel_dumper_info.uaddr = (uint64_t)dump;
	kpayload_kernel_dumper_info.size = size;
	kexec(&kpayload_kernel_dumper, &kpayload_kernel_dumper_info);
	return 0;
}

// this might still be useful
void logprintf(const char *format, ...)
{
	char buff[1024]; // lol
	memset(buff, 0, 1024);

	va_list args;
	va_start(args, format);
	vsprintf(buff, format, args);
	va_end(args);


	FILE *f = fopen("/mnt/usb0/log_file.txt", "a+");
	if (f) {
		fprintf(f, buff);
		fclose(f);
	}
}


void klog(const char *format, ...)	// didn't notice before, the addrs aren't aligned and deff not correct
{
	char *buff[1024];
	memset(buff, 0, 1024);

	va_list args;
	va_start(args, format);
	vsprintf(buff, format, args);
	va_end(args);



	int fd = open("/dev/klog", O_WRONLY, 0600);             // O_DIRECT | Open the device with read/write access
	if (fd < 0) {
		perror("Failed to open the device...");		// idk if we have perror, doesn't matter we'll find out 
		return ;
	}

	char *t = buff;
	while (0 != *t) write(fd, t++, 1);
	close(fd);

///* WTF/>
	fd = open("/dev/ttyu0", O_WRONLY, 0600);             // O_DIRECT | Open the device with read/write access
	if (fd < 0) {
		perror("Failed to open the device...");		// idk if we have perror, doesn't matter we'll find out 
		return;
	}

	t = buff;
	while (0 != *t) write(fd, t++, 1);
	close(fd);
//*/
}

/*struct kpayload_get_fw_version_info
{
uint64_t uaddr;
};



struct kpayload_get_fw_version_args
{
void* syscall_handler;
struct kpayload_get_fw_version_info* kpayload_get_fw_version_info;
};
//static devclass_t acpi_tz_devclass;
//typedef struct devclass		*devclass_t;
//typedef struct device *device_t;


struct kpayload_jailbreak_info

{
uint64_t fw_version;
};



struct kpayload_jailbreak_args

{
void* syscall_handler;
struct kpayload_jailbreak_info* kpayload_jailbreak_info;
};



struct kpayload_get_kbase_info

{
uint64_t fw_version;
uint64_t uaddr;
};



struct kpayload_get_kbase_args

{
void* syscall_handler;
struct kpayload_get_kbase_info* kpayload_get_kbase_info;

};



struct kpayload_kernel_dumper_info

{

uint64_t fw_version;
uint64_t uaddr;
uint64_t kaddr;
size_t size;

};

struct spoofone_info

{
uint64_t fw_version;

};

struct spoofone_args

{

void* syscall_handler;

struct spoofone_info* spoofone_info;

};

struct kpayload_kernel_dumper_args

{

void* syscall_handler;

struct kpayload_kernel_dumper_info* kpayload_kernel_dumper_info;

};*/


#define PATH_MAX 255
#define HiAlAzif 0x4F8D10
#define recoverymode 0x2010000
#define	KERN_PRINTF		0x0436040
#define	KERN_BASE_PTR 		0x00001C0
#define	KERN_COPYOUT		0x01ea630
#define	KERN_BZERO		0x01ea510 
#define	KERN_PRISON0 		0x10986A0
#define	KERN_ROOTVNODE 		0x22C1A70
#define KERN_DUMPSIZE 		108806144
#define kdlsym_addr_icc_nvs_read 0x00395830
#define kdlsym_addr_sceSblGetEAPInternalPartitionKey 0x006256E0
#define	KERN_405_XFAST_SYSCALL		0x30EB30	// #3
#define	KERN_455_XFAST_SYSCALL		0x3095D0	// #2
#define	KERN_501_XFAST_SYSCALL		0x1C0		// #1
#define	KERN_505_XFAST_SYSCALL		0x1C0		// #1
#define KERN_405_PRISON_0		0xF26010
#define KERN_455_PRISON_0		0x10399B0
#define KERN_501_PRISON_0		0x10986A0
#define KERN_505_PRISON_0		0x10986A0
#define KERN_405_ROOTVNODE		0x206D250
#define KERN_455_ROOTVNODE		0x21AFA30
#define KERN_501_ROOTVNODE		0x22C19F0
#define KERN_505_ROOTVNODE		0x22C1A70
#define KERN_405_PRINTF			0x347580
#define KERN_455_PRINTF			0x17F30
#define KERN_501_PRINTF			0x435C70
#define KERN_505_PRINTF			0x436040
#define KERN_405_COPYIN			0x286DF0
#define KERN_405_COPYOUT		0x286D70
#define KERN_455_COPYOUT		0x14A7B0
#define KERN_501_COPYOUT		0x1EA520
#define KERN_505_COPYOUT		0x1EA630
#define KERN_405_MEMSET_ALIGNED		0
#define KERN_455_MEMSET_ALIGNED		0x302BD0
#define KERN_501_MEMSET_ALIGNED		0x3201F0
#define KERN_505_MEMSET_ALIGNED		0x3205C0
#define KERN_405_BZERO_ALIGNED		0x286C30
#define KERN_455_BZERO_ALIGNED		0x14A570
#define KERN_501_BZERO_ALIGNED		0x1EA360
#define KERN_505_BZERO_ALIGNED		0x1EA470

#define PAGE_SIZE 16348
#define KERN_DUMPITER KERN_DUMPSIZE / PAGE_SIZE 	// can only dump a page at at time so we need to iterate
//#define KERN_FILEPATH "/mnt/usb0/kernel.bin"		// file path if debug socket isnt defined

#define IP(a, b, c, d) (((a) << 0) + ((b) << 8) + ((c) << 16) + ((d) << 24))

#define	CTL_KERN	1				/* "high kernel": proc, limits */
#define	KERN_PROC	14				/* struct: process entries */
#define	KERN_PROC_VMMAP	32				/* VM map entries for process */
#define	KERN_PROC_PID	1	

/*struct acpi_tz_softc {
void *tz_dev;
void tz_handle;
int      tz_temperature;
int      tz_active;
int      tz_requested;
int      tz_thflags;
int      tz_flags;
void *tz_cooling_started;
void *tz_sysctl_ctx;
void *tz_sysctl_tree;
void *tz_event;

void tz_zone;
int      tz_validchecks;
int      tz_insane_tmp_notified;

void *tz_cooling_proc;
int      tz_cooling_proc_running;
int      tz_cooling_enabled;
int      tz_cooling_active;
int      tz_cooling_updated;
int      tz_cooling_saved_freq;
};*/

int(*sceKernelGetIdPs)(void* ret);
int(*sceKernelGetOpenPsIdForSystem)(void* ret);

int64_t sys_dynlib_load_prx(char* prxPath, int* moduleID)
{
	return (int64_t)syscall4(594, prxPath, 0, moduleID, 0);
}

int64_t sys_dynlib_unload_prx(int64_t prxID)
{
	return (int64_t)syscall1(595, (void*)prxID);
}


int64_t sys_dynlib_dlsym(int64_t moduleHandle, const char* functionName, void *destFuncOffset)
{
	return (int64_t)syscall3(591, (void*)moduleHandle, (void*)functionName, destFuncOffset);
}

int unmounts(const char *dir, int flags)
{
	return syscall(22, dir, flags);
}

int nmounts(struct iovec *iov, uint32_t niov, int flags)
{
	return syscall(378, iov, niov, flags);
}

typedef struct DIR DIR;
struct dirent *(*readdir)(DIR *dirp);
int(*closedir)(DIR *dirp);
DIR *(*opendir)(const char *filename);

void Libc(void) {

	int moduleIds = 2;

	sys_dynlib_load_prx("libSceLibcInternal.sprx", &moduleIds);

	sys_dynlib_dlsym(moduleIds, "opendir", &opendir);
	sys_dynlib_dlsym(moduleIds, "readdir", &readdir);
	sys_dynlib_dlsym(moduleIds, "closedir", &closedir);
}
//int64_t AvailableSpace{
//get; 
//}


void tt(void) {

	int moduleIds = 2;

	sys_dynlib_load_prx("libSceLibcInternal.sprx", &moduleIds);

	sys_dynlib_dlsym(moduleIds, "sprintf", &sprintf);

}

static void build_iovec(struct iovec** iov, int* iovlen, const char* name, const void* val, size_t len) {
	int i;


	if (*iovlen < 0)
		return;

	i = *iovlen;
	*iov = realloc(*iov, sizeof **iov * (i + 2));
	if (*iov == NULL) {
		*iovlen = -1;
		return;
	}

	(*iov)[i].iov_base = strdup(name);
	(*iov)[i].iov_len = strlen(name) + 1;
	++i;

	(*iov)[i].iov_base = (void*)val;
	if (len == (size_t)-1) {
		if (val != NULL)
			len = strlen(val) + 1;
		else
			len = 0;
	}

	(*iov)[i].iov_len = (int)len;

	*iovlen = ++i;
}

static int mount_large_fs(const char* device, const char* mountpoint, const char* fstype, const char* mode, unsigned int flags) {


	struct iovec* iov = NULL;
	int iovlen = 0;

	build_iovec(&iov, &iovlen, "fstype", fstype, -1);
	build_iovec(&iov, &iovlen, "fspath", mountpoint, -1);
	build_iovec(&iov, &iovlen, "from", device, -1);
	build_iovec(&iov, &iovlen, "large", "yes", -1);
	build_iovec(&iov, &iovlen, "timezone", "static", -1);
	build_iovec(&iov, &iovlen, "async", "", -1);
	build_iovec(&iov, &iovlen, "ignoreacl", "", -1);

	if (mode) {
		build_iovec(&iov, &iovlen, "dirmask", mode, -1);
		build_iovec(&iov, &iovlen, "mask", mode, -1);
	}
	return nmounts(iov, iovlen, flags);
}

/*// This is how we decrypt the EAP Internal partition key for usage with mounting on PC
int(*sceSblGetEAPInternalPartitionKey)(unsigned char *encBuffer, unsigned char *decBzffer) = kdlsym(sceSblGetEAPInternalPartitionKey);

memset(request->key, 0, sizeof(request->key));
memset(request->encrypted, 0, sizeof(request->encrypted));

struct utility_dumphddkeys_t
{
uint8_t encrypted[0x60];
uint8_t key[0x20];
};

enum UtilityCmds
{
OrbisUtils_DumpHddKeys = 0xA5020F62,
OrbisUtils_ToggleASLR = 0xE6572B02,
};

void *Thread_f(void* arg) {
for (;;) {

}
}*/

///////////////////////////////////////////////////////////////////////////////////////////// FTP START//////////////////////////////////////////////////////////////////////

#define AF_INET 0x0002

#define IN_ADDR_ANY 0

#define SOCK_STREAM 1
#define SOCK_DGRAM 2

#define SOL_SOCKET 0xffff
#define SO_NBIO 0x1200

#define MSG_DONTWAIT 0x80
#define MSG_WAITALL 0x40

#define IPPROTO_TCP 6
#define TCP_NODELAY 1

enum {
	SCE_NET_IPPROTO_IP = 0,
	SCE_NET_IPPROTO_ICMP = 1,
	SCE_NET_IPPROTO_IGMP = 2,
	SCE_NET_IPPROTO_TCP = 6,
	SCE_NET_IPPROTO_UDP = 17,
	SCE_NET_SOL_SOCKET = 0xffff
};

enum {
	SCE_NET_SO_REUSEADDR = 0x00000004,
};

enum {
	SCE_NET_ERROR_EINTR = 0x80410104,
};

enum {
	SCE_NET_SOCKET_ABORT_FLAG_RCV_PRESERVATION = 0x00000001,
	SCE_NET_SOCKET_ABORT_FLAG_SND_PRESERVATION = 0x00000002
};



typedef unsigned int socklen_t;

/* info code */
#define SCE_NET_CTL_INFO_DEVICE			1
#define SCE_NET_CTL_INFO_ETHER_ADDR		2
#define SCE_NET_CTL_INFO_MTU			3
#define SCE_NET_CTL_INFO_LINK			4
#define SCE_NET_CTL_INFO_BSSID			5
#define SCE_NET_CTL_INFO_SSID			6
#define SCE_NET_CTL_INFO_WIFI_SECURITY		7
#define SCE_NET_CTL_INFO_RSSI_DBM		8
#define SCE_NET_CTL_INFO_RSSI_PERCENTAGE	9
#define SCE_NET_CTL_INFO_CHANNEL		10
#define SCE_NET_CTL_INFO_IP_CONFIG		11
#define SCE_NET_CTL_INFO_DHCP_HOSTNAME		12
#define SCE_NET_CTL_INFO_PPPOE_AUTH_NAME	13
#define SCE_NET_CTL_INFO_IP_ADDRESS		14
#define SCE_NET_CTL_INFO_NETMASK		15
#define SCE_NET_CTL_INFO_DEFAULT_ROUTE		16
#define SCE_NET_CTL_INFO_PRIMARY_DNS		17
#define SCE_NET_CTL_INFO_SECONDARY_DNS		18
#define SCE_NET_CTL_INFO_HTTP_PROXY_CONFIG	19
#define SCE_NET_CTL_INFO_HTTP_PROXY_SERVER	20
#define SCE_NET_CTL_INFO_HTTP_PROXY_PORT	21
#define SCE_NET_CTL_INFO_RESERVED1		22
#define SCE_NET_CTL_INFO_RESERVED2		23

#define SCE_NET_ETHER_ADDR_LEN 6

typedef struct SceNetEtherAddr {
	uint8_t data[SCE_NET_ETHER_ADDR_LEN];
} SceNetEtherAddr;

#define SCE_NET_CTL_SSID_LEN		(32 + 1)
#define SCE_NET_CTL_HOSTNAME_LEN	(255 + 1)
#define SCE_NET_CTL_AUTH_NAME_LEN	(127 + 1)
#define SCE_NET_CTL_IPV4_ADDR_STR_LEN	(16)

typedef union SceNetCtlInfo {
	uint32_t device;
	SceNetEtherAddr ether_addr;
	uint32_t mtu;
	uint32_t link;
	SceNetEtherAddr bssid;
	char ssid[SCE_NET_CTL_SSID_LEN];
	uint32_t wifi_security;
	uint8_t rssi_dbm;
	uint8_t rssi_percentage;
	uint8_t channel;
	uint32_t ip_config;
	char dhcp_hostname[SCE_NET_CTL_HOSTNAME_LEN];
	char pppoe_auth_name[SCE_NET_CTL_AUTH_NAME_LEN];
	char ip_address[SCE_NET_CTL_IPV4_ADDR_STR_LEN];
	char netmask[SCE_NET_CTL_IPV4_ADDR_STR_LEN];
	char default_route[SCE_NET_CTL_IPV4_ADDR_STR_LEN];
	char primary_dns[SCE_NET_CTL_IPV4_ADDR_STR_LEN];
	char secondary_dns[SCE_NET_CTL_IPV4_ADDR_STR_LEN];
	uint32_t http_proxy_config;
	char http_proxy_server[SCE_NET_CTL_HOSTNAME_LEN];
	uint16_t http_proxy_port;
} SceNetCtlInfo;


typedef void(*ftps4_log_cb_t)(const char *);

/* Extended functionality */

#define FTPS4_EOL "\r\n"

typedef enum {
	FTP_DATA_CONNECTION_NONE,
	FTP_DATA_CONNECTION_ACTIVE,
	FTP_DATA_CONNECTION_PASSIVE,
} DataConnectionType;

typedef struct ftps4_client_info {
	/* Client number */
	int num;
	/* Thread UID */
	ScePthread thid;
	/* Control connection socket FD */
	int ctrl_sockfd;
	/* Data connection attributes */
	int data_sockfd;
	DataConnectionType data_con_type;
	struct sockaddr_in data_sockaddr;
	/* PASV mode client socket */
	struct sockaddr_in pasv_sockaddr;
	int pasv_sockfd;
	/* Remote client net info */
	struct sockaddr_in addr;
	/* Receive buffer attributes */
	int n_recv;
	char recv_buffer[512];
	/* Points to the character after the first space */
	const char *recv_cmd_args;
	/* Current working directory */
	char cur_path[PATH_MAX];
	/* Rename path */
	char rename_path[PATH_MAX];
	/* Client list */
	struct ftps4_client_info *next;
	struct ftps4_client_info *prev;
	/* Offset for transfer resume */
	unsigned int restore_point;
} ftps4_client_info_t;

#define UNUSED(x) (void)(x)

#define NET_INIT_SIZE (64 * 1024)
#define DEFAULT_FILE_BUF_SIZE (4 * 1024 * 1024)

#define FTP_DEFAULT_PATH   "/"

#define MAX_COMMANDS 32


typedef void(*cmd_dispatch_func)(ftps4_client_info_t *client); // Command handler


static struct {
	const char *cmd;
	cmd_dispatch_func func;
	int valid;
} command_dispatchers[MAX_COMMANDS];

static int ftp_initialized = 0;
static unsigned int file_buf_size;
static struct in_addr ps4_addr;
static unsigned short int ps4_port;
static ScePthread server_thid;
static int server_sockfd;
static int number_clients = 0;
static ftps4_client_info_t *client_list = NULL;
static ScePthreadMutex client_list_mtx;

#define client_send_ctrl_msg(cl, str) \
	sceNetSend(cl->ctrl_sockfd, str, strlen(str), 0)

static inline void client_send_data_msg(ftps4_client_info_t *client, const char *str)
{
	if (client->data_con_type == FTP_DATA_CONNECTION_ACTIVE) {
		sceNetSend(client->data_sockfd, str, strlen(str), 0);
	}
	else {
		sceNetSend(client->pasv_sockfd, str, strlen(str), 0);
	}
}

static inline int client_recv_data_raw(ftps4_client_info_t *client, void *buf, unsigned int len)
{
	if (client->data_con_type == FTP_DATA_CONNECTION_ACTIVE) {
		return sceNetRecv(client->data_sockfd, buf, len, 0);
	}
	else {
		return sceNetRecv(client->pasv_sockfd, buf, len, 0);
	}
}

static inline void client_send_data_raw(ftps4_client_info_t *client, const void *buf, unsigned int len)
{
	if (client->data_con_type == FTP_DATA_CONNECTION_ACTIVE) {
		sceNetSend(client->data_sockfd, buf, len, 0);
	}
	else {
		sceNetSend(client->pasv_sockfd, buf, len, 0);
	}
}

static int file_exists(const char *path)
{
	struct stat s;
	return (stat(path, &s) >= 0);
}



static void cmd_NOOP_func(ftps4_client_info_t *client)
{
	client_send_ctrl_msg(client, "200 No operation ;)" FTPS4_EOL);
}

static void cmd_USER_func(ftps4_client_info_t *client)
{
	client_send_ctrl_msg(client, "331 Username OK, need password b0ss." FTPS4_EOL);
}

static void cmd_PASS_func(ftps4_client_info_t *client)
{
	client_send_ctrl_msg(client, "230 User logged in!" FTPS4_EOL);
}

static void cmd_QUIT_func(ftps4_client_info_t *client)
{
	client_send_ctrl_msg(client, "221 Goodbye senpai :'(" FTPS4_EOL);
}

static void cmd_SYST_func(ftps4_client_info_t *client)
{
	client_send_ctrl_msg(client, "215 UNIX Type: L8" FTPS4_EOL);
}

static void cmd_PASV_func(ftps4_client_info_t *client)
{
	int ret;
	UNUSED(ret);

	char cmd[512];
	unsigned int namelen;
	struct sockaddr_in picked;

	/* Create data mode socket name */
	char data_socket_name[64];
	sprintf(data_socket_name, "FTPS4_client_%i_data_socket",
		client->num);

	/* Create the data socket */
	client->data_sockfd = sceNetSocket(data_socket_name,
		AF_INET,
		SOCK_STREAM,
		0);

	//DEBUG("PASV data socket fd: %d\n", client->data_sockfd);

	/* Fill the data socket address */
	client->data_sockaddr.sin_len = sizeof(client->data_sockaddr);
	client->data_sockaddr.sin_family = AF_INET;
	client->data_sockaddr.sin_addr.s_addr = sceNetHtonl(IN_ADDR_ANY);
	/* Let the PS4 choose a port */
	client->data_sockaddr.sin_port = sceNetHtons(0);

	/* Bind the data socket address to the data socket */
	ret = sceNetBind(client->data_sockfd,
		(struct sockaddr *)&client->data_sockaddr,
		sizeof(client->data_sockaddr));
	//DEBUG("sceNetBind(): 0x%08X\n", ret);

	/* Start listening */
	ret = sceNetListen(client->data_sockfd, 128);
	//DEBUG("sceNetListen(): 0x%08X\n", ret);

	/* Get the port that the PS4 has chosen */
	namelen = sizeof(picked);
	sceNetGetsockname(client->data_sockfd, (struct sockaddr *)&picked,
		&namelen);

	//DEBUG("PASV mode port: 0x%04X\n", picked.sin_port);

	/* Build the command */
	sprintf(cmd, "227 Entering Passive Mode (%hhu,%hhu,%hhu,%hhu,%hhu,%hhu)" FTPS4_EOL,
		(ps4_addr.s_addr >> 0) & 0xFF,
		(ps4_addr.s_addr >> 8) & 0xFF,
		(ps4_addr.s_addr >> 16) & 0xFF,
		(ps4_addr.s_addr >> 24) & 0xFF,
		(picked.sin_port >> 0) & 0xFF,
		(picked.sin_port >> 8) & 0xFF);

	client_send_ctrl_msg(client, cmd);

	/* Set the data connection type to passive! */
	client->data_con_type = FTP_DATA_CONNECTION_PASSIVE;
}

static void cmd_PORT_func(ftps4_client_info_t *client)
{
	unsigned char data_ip[4];
	unsigned char porthi, portlo;
	unsigned short data_port;
	char ip_str[16];
	struct in_addr data_addr;
	int n;

	if (!client->recv_cmd_args) {
		client_send_ctrl_msg(client, "500 Syntax error, command unrecognized." FTPS4_EOL);
		return;
	}

	n = sscanf(client->recv_cmd_args, "%hhu,%hhu,%hhu,%hhu,%hhu,%hhu",
		&data_ip[0], &data_ip[1], &data_ip[2], &data_ip[3],
		&porthi, &portlo);
	if (n != 6) {
		client_send_ctrl_msg(client, "500 Syntax error, command unrecognized." FTPS4_EOL);
		return;
	}

	data_port = portlo + porthi * 256;

	/* Convert to an X.X.X.X IP string */
	sprintf(ip_str, "%d.%d.%d.%d",
		data_ip[0], data_ip[1], data_ip[2], data_ip[3]);

	/* Convert the IP to a struct in_addr */
	sceNetInetPton(AF_INET, ip_str, &data_addr);

	//DEBUG("PORT connection to client's IP: %s Port: %d\n", ip_str, data_port);

	/* Create data mode socket name */
	char data_socket_name[64];
	sprintf(data_socket_name, "FTPS4_client_%i_data_socket",
		client->num);

	/* Create data mode socket */
	client->data_sockfd = sceNetSocket(data_socket_name,
		AF_INET,
		SOCK_STREAM,
		0);


	/* Prepare socket address for the data connection */
	client->data_sockaddr.sin_len = sizeof(client->data_sockaddr);
	client->data_sockaddr.sin_family = AF_INET;
	client->data_sockaddr.sin_addr = data_addr;
	client->data_sockaddr.sin_port = sceNetHtons(data_port);

	/* Set the data connection type to active! */
	client->data_con_type = FTP_DATA_CONNECTION_ACTIVE;

	client_send_ctrl_msg(client, "200 PORT command successful!" FTPS4_EOL);
}

static void client_open_data_connection(ftps4_client_info_t *client)
{
	int ret;
	UNUSED(ret);

	unsigned int addrlen;

	if (client->data_con_type == FTP_DATA_CONNECTION_ACTIVE) {
		/* Connect to the client using the data socket */
		ret = sceNetConnect(client->data_sockfd,
			(struct sockaddr *)&client->data_sockaddr,
			sizeof(client->data_sockaddr));

		//DEBUG("sceNetConnect(): 0x%08X\n", ret);
	}
	else {
		/* Listen to the client using the data socket */
		addrlen = sizeof(client->pasv_sockaddr);
		client->pasv_sockfd = sceNetAccept(client->data_sockfd,
			(struct sockaddr *)&client->pasv_sockaddr,
			&addrlen);
		//DEBUG("PASV client fd: 0x%08X\n", client->pasv_sockfd);
	}
}

static void client_close_data_connection(ftps4_client_info_t *client)
{
	sceNetSocketClose(client->data_sockfd);
	/* In passive mode we have to close the client pasv socket too */
	if (client->data_con_type == FTP_DATA_CONNECTION_PASSIVE) {
		sceNetSocketClose(client->pasv_sockfd);
	}
	client->data_con_type = FTP_DATA_CONNECTION_NONE;
}

static char file_type_char(mode_t mode)
{
	return S_ISBLK(mode) ? 'b' :
		S_ISCHR(mode) ? 'c' :
		S_ISREG(mode) ? '-' :
		S_ISDIR(mode) ? 'd' :
		S_ISFIFO(mode) ? 'p' :
		S_ISSOCK(mode) ? 's' :
		S_ISLNK(mode) ? 'l' : ' ';
}

static int gen_list_format(char *out, int n, mode_t file_mode, unsigned long long file_size,
	const struct tm file_tm, const char *file_name, const char *link_name, const struct tm cur_tm)
{
	static const char num_to_month[][4] = {
		"Jan", "Feb", "Mar", "Apr", "May", "Jun",
		"Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
	};

	char yt[6];

	if (cur_tm.tm_year == file_tm.tm_year) {
		snprintf(yt, sizeof(yt), "%02d:%02d", file_tm.tm_hour, file_tm.tm_min);
	}
	else {
		snprintf(yt, sizeof(yt), "%04d", 1900 + file_tm.tm_year);
	}

#define LIST_FMT "%c%c%c%c%c%c%c%c%c%c 1 ps4 ps4 %llu %s %2d %s %s"
#define LIST_ARGS \
			file_type_char(file_mode), \
			file_mode & 0400 ? 'r' : '-', \
			file_mode & 0200 ? 'w' : '-', \
			file_mode & 0100 ? (S_ISDIR(file_mode) ? 's' : 'x') : (S_ISDIR(file_mode) ? 'S' : '-'), \
			file_mode & 040 ? 'r' : '-', \
			file_mode & 020 ? 'w' : '-', \
			file_mode & 010 ? (S_ISDIR(file_mode) ? 's' : 'x') : (S_ISDIR(file_mode) ? 'S' : '-'), \
			file_mode & 04 ? 'r' : '-', \
			file_mode & 02 ? 'w' : '-', \
			file_mode & 01 ? (S_ISDIR(file_mode) ? 's' : 'x') : (S_ISDIR(file_mode) ? 'S' : '-'), \
			file_size, \
			num_to_month[file_tm.tm_mon%12], \
			file_tm.tm_mday, \
			yt, \
			file_name

	if (!S_ISLNK(file_mode) || link_name[0] == '\0') {
		return snprintf(out, n, LIST_FMT FTPS4_EOL, LIST_ARGS);
	}
	else {
		return snprintf(out, n, LIST_FMT " -> %s" FTPS4_EOL, LIST_ARGS, link_name);
	}

#undef LIST_ARGS
#undef LIST_FMT
}

static void send_LIST(ftps4_client_info_t *client, const char *path)
{
	char buffer[512];
	uint8_t* dentbuf;
	size_t dentbufsize;
	int dfd, dentsize, err, readlinkerr;
	struct dirent *dent, *dend;
	struct stat st;
	time_t cur_time;
	struct tm tm, cur_tm;

	if (stat(path, &st) < 0) {
		client_send_ctrl_msg(client, "550 Invalid directory." FTPS4_EOL);
		return;
	}

	dentbufsize = st.st_blksize;
	//DEBUG("dent buffer size = %lx\n", dentbufsize);

	dfd = open(path, O_RDONLY, 0);
	if (dfd < 0) {
		client_send_ctrl_msg(client, "550 Invalid directory." FTPS4_EOL);
		return;
	}

	dentbuf = (uint8_t*)malloc(dentbufsize);
	memset(dentbuf, 0, dentbufsize);

	client_send_ctrl_msg(client, "150 Opening ASCII mode data transfer for LIST." FTPS4_EOL);

	client_open_data_connection(client);

	time(&cur_time);
	gmtime_s(&cur_time, &cur_tm);

	while ((dentsize = getdents(dfd, (char*)dentbuf, dentbufsize)) > 0) {
		dent = (struct dirent *)dentbuf;
		dend = (struct dirent *)(&dentbuf[dentsize]);

		while (dent != dend) {
			if (dent->d_name[0] != '\0') {
				char full_path[PATH_MAX];
				snprintf(full_path, sizeof(full_path), "%s/%s", path, dent->d_name);

				err = stat(full_path, &st);

				if (err == 0) {
					char link_path[PATH_MAX];
					if (S_ISLNK(st.st_mode)) {
						if ((readlinkerr = readlink(full_path, link_path, sizeof(link_path))) > 0) {
							link_path[readlinkerr] = 0;
						}
						else {
							link_path[0] = 0;
						}
					}

					gmtime_s(&st.st_ctim.tv_sec, &tm);
					gen_list_format(buffer, sizeof(buffer),
						st.st_mode,
						st.st_size,
						tm,
						dent->d_name,
						S_ISLNK(st.st_mode) && link_path[0] != '\0' ? link_path : NULL,
						cur_tm);

					client_send_data_msg(client, buffer);
					memset(buffer, 0, sizeof(buffer));
				}
				else {
					//DEBUG("%s stat returned %d\n", full_path, errno);
				}
			}
			else {
				//DEBUG("got empty dent\n");
			}
			dent = (struct dirent *)((void *)dent + dent->d_reclen);
		}
		memset(dentbuf, 0, dentbufsize);
	}

	close(dfd);
	free(dentbuf);

	//DEBUG("Done sending LIST\n");

	client_close_data_connection(client);
	client_send_ctrl_msg(client, "226 Transfer complete." FTPS4_EOL);
}

static void cmd_LIST_func(ftps4_client_info_t *client)
{
	char list_path[PATH_MAX];
	int list_cur_path = 1;
	int n = !client->recv_cmd_args
		? 0
		: sscanf(client->recv_cmd_args, "%[^\r\n\t]", list_path);

	if (n > 0 && file_exists(list_path))
		list_cur_path = 0;

	if (list_cur_path)
		send_LIST(client, client->cur_path);
	else
		send_LIST(client, list_path);
}

static void cmd_PWD_func(ftps4_client_info_t *client)
{
	char msg[PATH_MAX];
	snprintf(msg, sizeof(msg), "257 \"%s\" is the current directory." FTPS4_EOL, client->cur_path);
	client_send_ctrl_msg(client, msg);
}

static void dir_up(char *path)
{
	char *pch;
	size_t len_in = strlen(path);
	if (len_in == 1) {
	root:
		strcpy(path, "/");
		return;
	}
	pch = strrchr(path, '/');
	if (pch == path)
		goto root;
	*pch = '\0';
}

static void cmd_CWD_func(ftps4_client_info_t *client)
{
	char cmd_path[PATH_MAX];
	char tmp_path[PATH_MAX];
	int pd;
	int n = !client->recv_cmd_args
		? 0
		: sscanf(client->recv_cmd_args, "%[^\r\n\t]", cmd_path);

	if (n < 1) {
		client_send_ctrl_msg(client, "500 Syntax error, command unrecognized." FTPS4_EOL);
	}
	else {
		if (strcmp(cmd_path, "/") == 0) {
			strcpy(client->cur_path, cmd_path);
		}
		else  if (strcmp(cmd_path, "..") == 0) {
			dir_up(client->cur_path);
		}
		else {
			if (cmd_path[0] == '/') { /* Full path */
				strcpy(tmp_path, cmd_path);
			}
			else { /* Change dir relative to current dir */
				if (strcmp(client->cur_path, "/") == 0)
					snprintf(tmp_path, sizeof(tmp_path), "%s%s", client->cur_path, cmd_path);
				else
					snprintf(tmp_path, sizeof(tmp_path), "%s/%s", client->cur_path, cmd_path);
			}

			/* If the path is not "/", check if it exists */
			if (strcmp(tmp_path, "/") != 0) {
				/* Check if the path exists */
				pd = open(tmp_path, O_RDONLY, 0);
				if (pd < 0) {
					client_send_ctrl_msg(client, "550 Invalid directory." FTPS4_EOL);
					return;
				}
				close(pd);
			}
			strcpy(client->cur_path, tmp_path);
		}
		client_send_ctrl_msg(client, "250 Requested file action okay, completed." FTPS4_EOL);
	}
}

static void cmd_TYPE_func(ftps4_client_info_t *client)
{
	char data_type;
	char format_control[8];
	int n_args = !client->recv_cmd_args
		? 0
		: sscanf(client->recv_cmd_args, "%c %s", &data_type, format_control);

	if (n_args > 0) {
		switch (data_type) {
		case 'A':
		case 'I':
			client_send_ctrl_msg(client, "200 Okay" FTPS4_EOL);
			break;
		case 'E':
		case 'L':
		default:
			client_send_ctrl_msg(client, "504 Error: bad parameters?" FTPS4_EOL);
			break;
		}
	}
	else {
		client_send_ctrl_msg(client, "504 Error: bad parameters?" FTPS4_EOL);
	}
}

static void cmd_CDUP_func(ftps4_client_info_t *client)
{
	dir_up(client->cur_path);
	client_send_ctrl_msg(client, "200 Command okay." FTPS4_EOL);
}

static void send_file(ftps4_client_info_t *client, const char *path)
{
	unsigned char *buffer;
	int fd;
	unsigned int bytes_read;

	//DEBUG("Opening: %s\n", path);

	if ((fd = open(path, O_RDONLY, 0)) >= 0) {

		lseek(fd, client->restore_point, SEEK_SET);

		buffer = malloc(file_buf_size);
		if (buffer == NULL) {
			client_send_ctrl_msg(client, "550 Could not allocate memory." FTPS4_EOL);
			return;
		}

		client_open_data_connection(client);
		client_send_ctrl_msg(client, "150 Opening Image mode data transfer." FTPS4_EOL);

		while ((bytes_read = read(fd, buffer, file_buf_size)) > 0) {
			client_send_data_raw(client, buffer, bytes_read);
		}

		close(fd);
		free(buffer);
		client->restore_point = 0;
		client_send_ctrl_msg(client, "226 Transfer completed." FTPS4_EOL);
		client_close_data_connection(client);

	}
	else {
		client_send_ctrl_msg(client, "550 File not found." FTPS4_EOL);
	}
}

/* This function generates a FTP full-path valid path with the input path (relative or absolute)
* from RETR, STOR, DELE, RMD, MKD, RNFR and RNTO commands */
static void gen_ftp_fullpath(ftps4_client_info_t *client, char *path, size_t path_size)
{
	char cmd_path[PATH_MAX];
	int n = !client->recv_cmd_args
		? 0
		: sscanf(client->recv_cmd_args, "%[^\r\n\t]", cmd_path);

	if (n < 1) {
		client_send_ctrl_msg(client, "500 Syntax error, command unrecognized." FTPS4_EOL);
		return;
	}

	if (cmd_path[0] == '/') {
		/* Full path */
		strncpy(path, cmd_path, path_size);
	}
	else {
		/* The file is relative to current dir, so
		* append the file to the current path */
		snprintf(path, path_size, "%s/%s", client->cur_path, cmd_path);
	}
}

/*static void cmd_RETR_func(ftps4_client_info_t *client)
{
char dest_path[PATH_MAX];
gen_ftp_fullpath(client, dest_path, sizeof(dest_path));

if (is_self(dest_path))
{
decrypt_and_dump_self(dest_path, "/user/temp.self");
send_file(client, "/user/temp.self");
unlink("/user/temp.self");
}
else
{
send_file(client, dest_path);
}
}*/

static void receive_file(ftps4_client_info_t *client, const char *path)
{
	unsigned char *buffer;
	int fd;
	unsigned int bytes_recv;

	//DEBUG("Opening: %s\n", path);

	int mode = O_CREAT | O_RDWR;
	/* if we resume broken - append missing part
	* else - overwrite file */
	if (client->restore_point) {
		mode = mode | O_APPEND;
	}
	else {
		mode = mode | O_TRUNC;
	}

	if ((fd = open(path, mode, 0777)) >= 0) {

		buffer = malloc(file_buf_size);
		if (buffer == NULL) {
			client_send_ctrl_msg(client, "550 Could not allocate memory." FTPS4_EOL);
			return;
		}

		client_open_data_connection(client);
		client_send_ctrl_msg(client, "150 Opening Image mode data transfer." FTPS4_EOL);

		while ((bytes_recv = client_recv_data_raw(client, buffer, file_buf_size)) > 0) {
			write(fd, buffer, bytes_recv);
		}

		close(fd);
		free(buffer);
		client->restore_point = 0;
		if (bytes_recv == 0) {
			client_send_ctrl_msg(client, "226 Transfer completed." FTPS4_EOL);
		}
		else {
			unlink(path);
			client_send_ctrl_msg(client, "426 Connection closed; transfer aborted." FTPS4_EOL);
		}
		client_close_data_connection(client);

	}
	else {
		client_send_ctrl_msg(client, "550 File not found." FTPS4_EOL);
	}
}

static void cmd_STOR_func(ftps4_client_info_t *client)
{
	char dest_path[PATH_MAX];
	gen_ftp_fullpath(client, dest_path, sizeof(dest_path));
	receive_file(client, dest_path);
}

static void delete_file(ftps4_client_info_t *client, const char *path)
{
	//DEBUG("Deleting: %s\n", path);

	if (unlink(path) >= 0) {
		client_send_ctrl_msg(client, "226 File deleted." FTPS4_EOL);
	}
	else {
		client_send_ctrl_msg(client, "550 Could not delete the file." FTPS4_EOL);
	}
}

static void cmd_DELE_func(ftps4_client_info_t *client)
{
	char dest_path[PATH_MAX];
	gen_ftp_fullpath(client, dest_path, sizeof(dest_path));
	delete_file(client, dest_path);
}

static void delete_dir(ftps4_client_info_t *client, const char *path)
{
	int ret;
	//DEBUG("Deleting: %s\n", path);
	ret = rmdir(path);
	if (ret >= 0) {
		client_send_ctrl_msg(client, "226 Directory deleted." FTPS4_EOL);
	}
	else if (errno == 66) { /* ENOTEMPTY */
		client_send_ctrl_msg(client, "550 Directory is not empty." FTPS4_EOL);
	}
	else {
		client_send_ctrl_msg(client, "550 Could not delete the directory." FTPS4_EOL);
	}
}

static void cmd_RMD_func(ftps4_client_info_t *client)
{
	char dest_path[PATH_MAX];
	gen_ftp_fullpath(client, dest_path, sizeof(dest_path));
	delete_dir(client, dest_path);
}

static void create_dir(ftps4_client_info_t *client, const char *path)
{
	//DEBUG("Creating: %s\n", path);

	if (mkdir(path, 0777) >= 0) {
		client_send_ctrl_msg(client, "226 Directory created." FTPS4_EOL);
	}
	else {
		client_send_ctrl_msg(client, "550 Could not create the directory." FTPS4_EOL);
	}
}

static void cmd_MKD_func(ftps4_client_info_t *client)
{
	char dest_path[PATH_MAX];
	gen_ftp_fullpath(client, dest_path, sizeof(dest_path));
	create_dir(client, dest_path);
}

static void cmd_RNFR_func(ftps4_client_info_t *client)
{
	char from_path[PATH_MAX];
	/* Get the origin filename */
	gen_ftp_fullpath(client, from_path, sizeof(from_path));

	/* Check if the file exists */
	if (!file_exists(from_path)) {
		client_send_ctrl_msg(client, "550 The file doesn't exist." FTPS4_EOL);
		return;
	}
	/* The file to be renamed is the received path */
	strcpy(client->rename_path, from_path);
	client_send_ctrl_msg(client, "350 I need the destination name b0ss." FTPS4_EOL);
}

static void cmd_RNTO_func(ftps4_client_info_t *client)
{
	char path_to[PATH_MAX];
	/* Get the destination filename */
	gen_ftp_fullpath(client, path_to, sizeof(path_to));

	//DEBUG("Renaming: %s to %s\n", client->rename_path, path_to);

	if (rename(client->rename_path, path_to) < 0) {
		client_send_ctrl_msg(client, "550 Error renaming the file." FTPS4_EOL);
	}

	client_send_ctrl_msg(client, "226 Rename completed." FTPS4_EOL);
}

static void cmd_SIZE_func(ftps4_client_info_t *client)
{
	struct stat s;
	char path[PATH_MAX];
	char cmd[64];
	/* Get the filename to retrieve its size */
	gen_ftp_fullpath(client, path, sizeof(path));

	/* Check if the file exists */
	if (stat(path, &s) < 0) {
		client_send_ctrl_msg(client, "550 The file doesn't exist." FTPS4_EOL);
		return;
	}
	/* Send the size of the file */
	sprintf(cmd, "213 %lld" FTPS4_EOL, s.st_size);
	client_send_ctrl_msg(client, cmd);
}

static void cmd_REST_func(ftps4_client_info_t *client)
{
	char cmd[64];
	sscanf(client->recv_buffer, "%*[^ ] %d", &client->restore_point);
	sprintf(cmd, "350 Resuming at %d" FTPS4_EOL, client->restore_point);
	client_send_ctrl_msg(client, cmd);
}

static void cmd_FEAT_func(ftps4_client_info_t *client)
{
	/*So client would know that we support resume */
	client_send_ctrl_msg(client, "211-extensions" FTPS4_EOL);
	client_send_ctrl_msg(client, "REST STREAM" FTPS4_EOL);
	client_send_ctrl_msg(client, "211 end" FTPS4_EOL);
}

static void cmd_APPE_func(ftps4_client_info_t *client)
{
	/* set restore point to not 0
	restore point numeric value only matters if we RETR file from ps4.
	If we STOR or APPE, it is only used to indicate that we want to resume
	a broken transfer */
	client->restore_point = -1;
	char dest_path[PATH_MAX];
	gen_ftp_fullpath(client, dest_path, sizeof(dest_path));
	receive_file(client, dest_path);
}

static cmd_dispatch_func get_dispatch_func(const char *cmd)
{
	int i;
	// Check for commands
	for (i = 0; i < MAX_COMMANDS; i++) {
		if (command_dispatchers[i].valid) {
			if (strcmp(cmd, command_dispatchers[i].cmd) == 0) {
				return command_dispatchers[i].func;
			}
		}
	}
	return NULL;
}

static void client_list_add(ftps4_client_info_t *client)
{
	/* Add the client at the front of the client list */
	scePthreadMutexLock(&client_list_mtx);

	if (client_list == NULL) { /* List is empty */
		client_list = client;
		client->prev = NULL;
		client->next = NULL;
	}
	else {
		client->next = client_list;
		client->next->prev = client;
		client->prev = NULL;
		client_list = client;
	}
	client->restore_point = 0;
	number_clients++;

	scePthreadMutexUnlock(&client_list_mtx);
}

static void client_list_delete(ftps4_client_info_t *client)
{
	/* Remove the client from the client list */
	scePthreadMutexLock(&client_list_mtx);

	if (client->prev) {
		client->prev->next = client->next;
	}
	if (client->next) {
		client->next->prev = client->prev;
	}
	if (client == client_list) {
		client_list = client->next;
	}

	number_clients--;

	scePthreadMutexUnlock(&client_list_mtx);
}

static void client_list_thread_end()
{
	ftps4_client_info_t *it, *next;
	ScePthread client_thid;
	const int data_abort_flags = SCE_NET_SOCKET_ABORT_FLAG_RCV_PRESERVATION |
		SCE_NET_SOCKET_ABORT_FLAG_SND_PRESERVATION;

	/* Iterate over the client list and close their sockets */
	scePthreadMutexLock(&client_list_mtx);

	it = client_list;

	while (it) {
		next = it->next;
		client_thid = it->thid;

		/* Abort the client's control socket, only abort
		* receiving data so we can still send control messages */
		sceNetSocketAbort(it->ctrl_sockfd,
			SCE_NET_SOCKET_ABORT_FLAG_RCV_PRESERVATION);

		/* If there's an open data connection, abort it */
		if (it->data_con_type != FTP_DATA_CONNECTION_NONE) {
			sceNetSocketAbort(it->data_sockfd, data_abort_flags);
			if (it->data_con_type == FTP_DATA_CONNECTION_PASSIVE) {
				sceNetSocketAbort(it->pasv_sockfd, data_abort_flags);
			}
		}

		/* Wait until the client threads ends */
		scePthreadJoin(client_thid, NULL);

		it = next;
	}

	scePthreadMutexUnlock(&client_list_mtx);
}

static void *client_thread(void *arg)
{
	char cmd[16];
	cmd_dispatch_func dispatch_func;
	ftps4_client_info_t *client = (ftps4_client_info_t *)arg;

	//DEBUG("Client thread %i started!\n", client->num);

	client_send_ctrl_msg(client, "220 FTPS4 Server ready." FTPS4_EOL);

	while (1) {
		memset(client->recv_buffer, 0, sizeof(client->recv_buffer));

		client->n_recv = sceNetRecv(client->ctrl_sockfd, client->recv_buffer, sizeof(client->recv_buffer), 0);
		if (client->n_recv > 0) {

			//////////printfsocket("\t%i> %s", client->num, client->recv_buffer);

			/* The command is the first chars until the first space */
			sscanf(client->recv_buffer, "%s", cmd);

			client->recv_cmd_args = strchr(client->recv_buffer, ' ');
			if (client->recv_cmd_args)
				client->recv_cmd_args++; /* Skip the space */

										 /* Wait 1 ms before sending any data */
			sceKernelUsleep(1 * 1000);

			if ((dispatch_func = get_dispatch_func(cmd))) {
				dispatch_func(client);
			}
			else {
				client_send_ctrl_msg(client, "502 Sorry, command not implemented. :(" FTPS4_EOL);
			}

		}
		else if (client->n_recv == 0) {
			/* Value 0 means connection closed by the remote peer */
			//////////printfsocket("Connection closed by the client %i.\n", client->num);
			/* Delete itself from the client list */
			client_list_delete(client);
			break;
		}
		else if (client->n_recv == SCE_NET_ERROR_EINTR) {
			/* Socket aborted (ftps4_fini() called) */
			//////////printfsocket("Client %i socket aborted.\n", client->num);
			break;
		}
		else {
			/* Other errors */
			//////////printfsocket("Client %i socket error: 0x%08X\n", client->num, client->n_recv);
			client_list_delete(client);
			break;
		}
	}

	/* Close the client's socket */
	sceNetSocketClose(client->ctrl_sockfd);

	/* If there's an open data connection, close it */
	if (client->data_con_type != FTP_DATA_CONNECTION_NONE) {
		sceNetSocketClose(client->data_sockfd);
		if (client->data_con_type == FTP_DATA_CONNECTION_PASSIVE) {
			sceNetSocketClose(client->pasv_sockfd);
		}
	}

	//DEBUG("Client thread %i exiting!\n", client->num);

	free(client);

	scePthreadExit(NULL);
	return NULL;
}

static void *server_thread(void *arg)
{
	int ret, enable;
	UNUSED(ret);

	struct sockaddr_in serveraddr;

	//DEBUG("Server thread started!\n");

	/* Create server socket */
	server_sockfd = sceNetSocket("FTPS4_server_sock",
		AF_INET,
		SOCK_STREAM,
		0);

	//DEBUG("Server socket fd: %d\n", server_sockfd);

	enable = 1;
	sceNetSetsockopt(server_sockfd, SCE_NET_SOL_SOCKET, SCE_NET_SO_REUSEADDR, &enable, sizeof(enable));

	/* Fill the server's address */
	serveraddr.sin_len = sizeof(serveraddr);
	serveraddr.sin_family = AF_INET;
	serveraddr.sin_addr.s_addr = sceNetHtonl(IN_ADDR_ANY);
	serveraddr.sin_port = sceNetHtons(ps4_port);

	/* Bind the server's address to the socket */
	ret = sceNetBind(server_sockfd, (struct sockaddr *)&serveraddr, sizeof(serveraddr));
	//DEBUG("sceNetBind(): 0x%08X\n", ret);

	/* Start listening */
	ret = sceNetListen(server_sockfd, 128);
	//DEBUG("sceNetListen(): 0x%08X\n", ret);

	while (1) {
		/* Accept clients */
		struct sockaddr_in clientaddr;
		int client_sockfd;
		unsigned int addrlen = sizeof(clientaddr);

		//DEBUG("Waiting for incoming connections...\n");

		client_sockfd = sceNetAccept(server_sockfd, (struct sockaddr *)&clientaddr, &addrlen);
		if (client_sockfd >= 0) {
			//DEBUG("New connection, client fd: 0x%08X\n", client_sockfd);

			/* Get the client's IP address */
			char remote_ip[16];
			sceNetInetNtop(AF_INET,
				&clientaddr.sin_addr.s_addr,
				remote_ip,
				sizeof(remote_ip));


			/* Allocate the ftps4_client_info_t struct for the new client */
			ftps4_client_info_t *client = malloc(sizeof(*client));
			client->num = number_clients;
			client->ctrl_sockfd = client_sockfd;
			client->data_con_type = FTP_DATA_CONNECTION_NONE;
			strcpy(client->cur_path, FTP_DEFAULT_PATH);
			memcpy(&client->addr, &clientaddr, sizeof(client->addr));

			/* Add the new client to the client list */
			client_list_add(client);

			/* Create a new thread for the client */
			char client_thread_name[64];
			sprintf(client_thread_name, "ORBISMAN_client_%i_thread",
				number_clients);

			/* Create a new thread for the client */
			scePthreadCreate(&client->thid, NULL, client_thread, client, client_thread_name);

			//DEBUG("Client %i thread UID: 0x%08X\n", number_clients, client->thid);

			number_clients++;
		}
		else if (client_sockfd == SCE_NET_ERROR_EINTR) {
			//////////printfsocket("Server socket aborted.\n");
			break;
		}
		else {
			/* if sceNetAccept returns < 0, it means that the listening
			* socket has been closed, this means that we want to
			* finish the server thread */
			//DEBUG("Server socket closed, 0x%08X\n", client_sockfd);
			break;
		}
	}

	//DEBUG("Server thread exiting!\n");

	/* Causing a crash? */
	/*scePthreadExit(NULL);*/
	return NULL;
}

#define add_command(name) ftps4_ext_add_command(#name, cmd_##name##_func)
int ftps4_init(const char *ip, unsigned short int port)
{
	int i;

	if (ftp_initialized) {
		return -1;
	}

	file_buf_size = DEFAULT_FILE_BUF_SIZE;

	/* Save the listening port of the PS4 to a global variable */
	ps4_port = port;

	/* Save the IP of the PS4 to a global variable */
	sceNetInetPton(AF_INET, ip, &ps4_addr);

	/* Create the client list mutex */
	scePthreadMutexInit(&client_list_mtx, NULL, "FTPS4_client_list_mutex");
	//DEBUG("Client list mutex UID: 0x%08X\n", client_list_mtx);

	for (i = 0; i < MAX_COMMANDS; i++) {
		command_dispatchers[i].valid = 0;
	}

	/* Add commands */
	add_command(NOOP);
	add_command(USER);
	add_command(PASS);
	add_command(QUIT);
	add_command(SYST);
	add_command(PASV);
	add_command(PORT);
	add_command(LIST);
	add_command(PWD);
	add_command(CWD);
	add_command(TYPE);
	add_command(CDUP);
	add_command(STOR);
	add_command(DELE);
	add_command(RMD);
	add_command(MKD);
	add_command(RNFR);
	add_command(RNTO);
	add_command(SIZE);
	add_command(REST);
	add_command(FEAT);
	add_command(APPE);

	/* Create server thread */
	scePthreadCreate(&server_thid, NULL, server_thread, NULL, "FTPS4_server_thread");
	//DEBUG("Server thread UID: 0x%08X\n", server_thid);

	ftp_initialized = 1;

	return 0;
}

void ftps4_fini()
{
	if (ftp_initialized) {
		/* Necessary to get sceNetAccept to notice the close on PS4? */
		sceNetSocketAbort(server_sockfd, 0);
		/* In order to "stop" the blocking sceNetAccept,
		* we have to close the server socket; this way
		* the accept call will return an error */
		sceNetSocketClose(server_sockfd);

		/* Wait until the server threads ends */
		scePthreadJoin(server_thid, NULL);

		/* To close the clients we have to do the same:
		* we have to iterate over all the clients
		* and shutdown their sockets */
		client_list_thread_end();

		/* Delete the client list mutex */
		scePthreadMutexDestroy(client_list_mtx);

		client_list = NULL;
		number_clients = 0;

		ftp_initialized = 0;
	}
}

int ftps4_is_initialized()
{
	return ftp_initialized;
}

void ftps4_set_file_buf_size(unsigned int size)
{
	file_buf_size = size;
}

int ftps4_ext_add_command(const char *cmd, cmd_dispatch_func func)
{
	int i;
	for (i = 0; i < MAX_COMMANDS; i++) {
		if (!command_dispatchers[i].valid) {
			command_dispatchers[i].cmd = cmd;
			command_dispatchers[i].func = func;
			command_dispatchers[i].valid = 1;
			return 1;
		}
	}
	return 0;
}

int ftps4_ext_del_command(const char *cmd)
{
	int i;
	for (i = 0; i < MAX_COMMANDS; i++) {
		if (strcmp(cmd, command_dispatchers[i].cmd) == 0) {
			command_dispatchers[i].valid = 0;
			return 1;
		}
	}
	return 0;
}

void ftps4_ext_client_send_ctrl_msg(ftps4_client_info_t *client, const char *msg)
{
	client_send_ctrl_msg(client, msg);
}

void ftps4_ext_client_send_data_msg(ftps4_client_info_t *client, const char *str)
{
	client_send_data_msg(client, str);
}

void ftps4_gen_ftp_fullpath(ftps4_client_info_t *client, char *path, size_t path_size)
{
	gen_ftp_fullpath(client, path, path_size);
}


int get_ip_address(char *ip_address)
{
	int ret;
	SceNetCtlInfo info;

	ret = sceNetCtlInit();
	if (ret < 0)
		goto error;

	ret = sceNetCtlGetInfo(SCE_NET_CTL_INFO_IP_ADDRESS, &info);
	if (ret < 0)
		goto error;

	memcpy(ip_address, info.ip_address, sizeof(info.ip_address));

	sceNetCtlTerm();

	return ret;

error:
	ip_address = NULL;
	return -1;
}
///////////////////////////////////////////////////////////////////// END /////////////////////////////////////////////////////////////////////////////////////////////

int hexDumpKern(const void *data, size_t size, uint64_t kbase) {

	unsigned char *d = (unsigned char *)data;
	size_t consoleSize = 16;
	char b[consoleSize + 3];
	size_t i;

	// hook kernel print for uart hex dumping
	//int(*printf)(const char *fmt, ...) = (void *)(kbase + KERN_PRINTF);

	if (data == NULL) {
		return -1;
	}
	b[0] = '|';
	b[consoleSize + 1] = '|';
	b[consoleSize + 2] = '\0';

	printf("\n-------HEX DUMP------\n");
	for (i = 0; i < size; i++)
	{
		if ((i % consoleSize) == 0)
		{
			if (i != 0) {
				printf("  %s\n", b);
			}
			printf("%016lx ", (unsigned char *)data + i);
		}

		if (i % consoleSize == 8)
			printf(" ");
		printf(" %02x", d[i]);

		if (d[i] >= ' ' && d[i] <= '~')
			b[i % consoleSize + 1] = d[i];

		else
			b[i % consoleSize + 1] = '.';
	}

	while ((i % consoleSize) != 0)
	{

		if (i % consoleSize == 8)
			printf("    ");

		else
			printf("   ");
		b[i % consoleSize + 1] = '.';
		i++;
	}

	printf("  %s\n", b);
	return 0;
}

void copyFile(char *sourcefile, char* destfile)
{
	int src = open(sourcefile, O_RDONLY, 0);
	if (src != -1)
	{
		int out = open(destfile, O_WRONLY | O_CREAT | O_TRUNC, 0777);
		if (out != -1)
		{
			size_t bytes;
			char *buffer = malloc(65536);
			if (buffer != NULL)
			{
				while (0 < (bytes = read(src, buffer, 65536)))
					write(out, buffer, bytes);
				free(buffer);
			}
			close(out);
		}
		else {
		}
		close(src);
	}
	else {
	}
}



//void custom_SHUTDOWN(ftps4_client_info_t *client) {
//ftps4_ext_client_send_ctrl_msg(client, "200 Shutting down..." FTPS4_EOL);
//run = 0;
//}

/*int
sys_reboot(struct thread *td, struct reboot_args *uap)
{
int error;

error = 0;
#ifdef MAC
error = mac_system_check_reboot(td->td_ucred, uap->opt);
#endif
if (error == 0)
error = priv_check(td, PRIV_REBOOT);
if (error == 0) {
if (uap->opt & RB_REROOT)
error = kern_reroot();
else
kern_reboot(uap->opt);
}
return (error);
}*/



#define SELF_MAGIC	0x1D3D154F
#define ELF_MAGIC	0x464C457F

#define UNUSED(x) (void)(x)

#define KERN_PROCESS_ASLR 0x194875  = 0xEB
#define NET_INIT_SIZE (64 * 1024)
#define DEFAULT_FILE_BUF_SIZE (4 * 1024 * 1024)

#define errno (* __error())
#define TRUE 1
#define FALSE 0

#define O_RDONLY  0x0000
#define O_WRONLY  0x0001
#define O_RDWR    0x0002
#define O_ACCMODE 0x0003

#define	O_NONBLOCK 0x0004		/* no delay */
#define	O_APPEND   0x0008		/* set append mode */
#define	O_CREAT    0x0200		/* create if nonexistent */
#define	O_TRUNC    0x0400		/* truncate to zero length */
#define	O_EXCL     0x0800		/* error if already exists */

#define S_ISDIR(m)  (((m) & 0170000) == 0040000)
#define S_ISCHR(m)  (((m) & 0170000) == 0020000)
#define S_ISBLK(m)  (((m) & 0170000) == 0060000)
#define S_ISREG(m)  (((m) & 0170000) == 0100000)
#define S_ISFIFO(m) (((m) & 0170000) == 0010000)
#define S_ISLNK(m)  (((m) & 0170000) == 0120000)
#define S_ISSOCK(m) (((m) & 0170000) == 0140000)
#define S_ISWHT(m)  (((m) & 0170000) == 0160000)

#define	KERN_PRINTF		0x0436040
#define	KERN_BASE_PTR 		0x00001C0
#define	KERN_COPYOUT		0x01ea630
#define	KERN_BZERO		0x01ea510 
#define	KERN_PRISON0 		0x10986A0
#define	KERN_ROOTVNODE 		0x22C1A70
#define	KERN_UART_ENABLE 		0	// mira takes care of this

#define KERN_DUMPSIZE 		108806144	// can change if you want but may crash if you hit critical code in gpu memory

#define FTP_DEFAULT_PATH   "/"
#define IN_ADDR_ANY 0
#define MAX_CUSTOM_COMMANDS 16

#define __devkit_id                                     0x8101
#define __target_id_0                                   0x1CD068C
#define __target_id_1                                   0x236B7FC
#define __target_id_2                                   0x200151C
#define __mmap_self_0                                   0x31EE40
#define __mmap_self_0                                   0x117B0
#define __mmap_self_1                                   0x117B1
#define __mmap_self_2                                   0x117B2
#define __mmap_self_3                                   0x117C0
#define __mmap_self_4                                   0x117C1
#define __mmap_self_5                                   0x117C2
#define __mmap_self_6                                   0x13EF2F
#define __mmap_self_7                                   0x13EF30
#define __mmap_self_8                                   0x13EF31
#define __mmap_self_9                                   0x13EF32
#define __mmap_self_10                                  0x13EF33
#define __mmap_self_patch_0                             0xB0
#define __mmap_self_patch_1                             0x01
#define __mmap_self_patch_2                             0xC3
#define __mmap_self_patch_4                             0x31
#define __mmap_self_patch_5                             0xC0
#define __mmap_self_patch_6                             0x90
#define PROT_READ PROT_CPU_READ
#define PROT_CPU_READ 1
#define MAP_FAILED (void *)-1

#define	KERN_XFAST_SYSCALL	0x1C0		// 5.05
#define KERN_PRISON_0		0x10986A0
#define KERN_ROOTVNODE		0x22C1A70

#define KERN_PMAP_PROTECT	0x2E3090
#define KERN_PMAP_PROTECT_P	0x2E30D4
#define KERN_PMAP_STORE		0x22CB570
#define MAP_PRIVATE 2

#define DT_HASH_SEGMENT		0xB5EF30
#define KERN_FILEPATH "/mnt/usb0/kernel.bin"


int bugreport()
{
	//syscall(11, uartoff);
	int moduleId = -1;
	sys_dynlib_load_prx("libSceSysUtil.sprx", &moduleId);

	// This header doesn't work in > 5.00
	int(*sceSysUtilSendSystemNotificationWithText)(int messageType, char* message) = NULL;

	sys_dynlib_dlsym(moduleId, "sceSysUtilSendSystemNotificationWithText", &sceSysUtilSendSystemNotificationWithText);

	char* initMessage = "Bug Report Uploaded!";
	sceSysUtilSendSystemNotificationWithText(222, initMessage);

	sys_dynlib_unload_prx(moduleId);

	return 0;
}

int connectionfaild()
{
	//syscall(11, uartoff);
	int moduleId = -1;
	sys_dynlib_load_prx("libSceSysUtil.sprx", &moduleId);

	// This header doesn't work in > 5.00
	int(*sceSysUtilSendSystemNotificationWithText)(int messageType, char* message) = NULL;

	sys_dynlib_dlsym(moduleId, "sceSysUtilSendSystemNotificationWithText", &sceSysUtilSendSystemNotificationWithText);

	char* initMessage = "Connection Failed";
	sceSysUtilSendSystemNotificationWithText(222, initMessage);

	sys_dynlib_unload_prx(moduleId);

	return 0;
}

int nousbnote()
{

	int moduleId = -1;
	sys_dynlib_load_prx("libSceSysUtil.sprx", &moduleId);


	// This header doesn't work in > 5.00
	int(*sceSysUtilSendSystemNotificationWithText)(int messageType, char* message) = NULL;

	sys_dynlib_dlsym(moduleId, "sceSysUtilSendSystemNotificationWithText", &sceSysUtilSendSystemNotificationWithText);

	char* initMessage = "No USB detected!!!";
	sceSysUtilSendSystemNotificationWithText(222, initMessage);

	sys_dynlib_unload_prx(moduleId);


	return 0;
}

void sysctlbyname1()
{
	int moduleId = 1;
	int(*sysctlbyname)(const char *name, void *oldp, size_t *oldlenp, const void *newp, size_t newlen) = NULL;
	sys_dynlib_dlsym(moduleId, "sysctlbyname", &sysctlbyname);
}


int autoloadnote()
{

	int moduleId = -1;
	sys_dynlib_load_prx("libSceSysUtil.sprx", &moduleId);


	// This header doesn't work in > 5.00
	int(*sceSysUtilSendSystemNotificationWithText)(int messageType, char* message) = NULL;

	sys_dynlib_dlsym(moduleId, "sceSysUtilSendSystemNotificationWithText", &sceSysUtilSendSystemNotificationWithText);

	char* initMessage = "Auto-Load Enabled";
	sceSysUtilSendSystemNotificationWithText(222, initMessage);


	return 0;
}

int disbaledautoloadnote()
{

	int moduleId = -1;
	sys_dynlib_load_prx("libSceSysUtil.sprx", &moduleId);


	// This header doesn't work in > 5.00
	int(*sceSysUtilSendSystemNotificationWithText)(int messageType, char* message) = NULL;

	sys_dynlib_dlsym(moduleId, "sceSysUtilSendSystemNotificationWithText", &sceSysUtilSendSystemNotificationWithText);

	char* initMessage = "Auto-Load Disabled";
	sceSysUtilSendSystemNotificationWithText(222, initMessage);


	return 0;
}

int elfloadernote()
{

	int moduleId = -1;
	sys_dynlib_load_prx("libSceSysUtil.sprx", &moduleId);


	// This header doesn't work in > 5.00
	int(*sceSysUtilSendSystemNotificationWithText)(int messageType, char* message) = NULL;

	sys_dynlib_dlsym(moduleId, "sceSysUtilSendSystemNotificationWithText", &sceSysUtilSendSystemNotificationWithText);

	char* initMessage = "ELF Loader Loaded\n If you want to cancel close the App";
	sceSysUtilSendSystemNotificationWithText(222, initMessage);


	return 0;
}

extern char syscall9505[];
extern unsigned syscall9505_size;

extern char syscall9455[];
extern unsigned syscall9455_size;



extern char sys_unjails[];
extern unsigned sys_unjail_size;

int sys_unjail1(struct thread *td) {

	//Starting kpayload...

	struct ucred* cred;
	struct filedesc* fd;

	fd = td->td_proc->p_fd;
	cred = td->td_proc->p_ucred;

	//Reading kernel_base...
	void* kernel_base = &((uint8_t*)__readmsr(0xC0000082))[-KERN_XFAST_SYSCALL];
	uint8_t* kernel_ptr = (uint8_t*)kernel_base;
	void** got_prison0 = (void**)&kernel_ptr[0x10986a0];
	void** got_rootvnode = (void**)&kernel_ptr[0x22c1a70];

	//Resolve kernel functions...
	int(*copyout)(const void *kaddr, void *uaddr, size_t len) = (void *)(kernel_base + 0x1ea630);
	int(*printfkernel)(const char *fmt, ...) = (void *)(kernel_base + 0x436040);
	int(*copyin)(const void *uaddr, void *kaddr, size_t len) = (void *)(kernel_base + 0x1ea710);

	cred->cr_uid = 0;
	cred->cr_ruid = 0;
	cred->cr_rgid = 0;
	cred->cr_groups[0] = 0;

	cred->cr_prison = *got_prison0;
	fd->fd_rdir = fd->fd_jdir = *got_rootvnode;



	void* (*kmemcpy)(void *destination, const void * source, size_t num) = (void *)(kernel_base + 0x1EA530);


	//Disable write protection...
	cpu_disable_wp();

	printfkernel("WP Disabled\n");

	// TODO: label and explain patches
	*(uint8_t *)(kernel_base + 0x1CD0686) |= 0x14;
	*(uint8_t *)(kernel_base + 0x1CD06A9) |= 0x3;
	*(uint8_t *)(kernel_base + 0x1CD06AA) |= 0x1;
	*(uint8_t *)(kernel_base + 0x1CD06C8) |= 0x1;


	// disable sysdump_perform_dump_on_fatal_trap
	// will continue execution and give more information on crash, such as rip
	*(uint8_t *)(kernel_base + 0x7673E0) = 0xC3;

	kmemcpy((void *)(kernel_base + 0x1A3C08), "\x90\x90\x90\x90\x90\x90", 6);
	*(uint8_t *)(kernel_base + 0xFCD48) = 7; // VM_PROT_ALL;
	*(uint8_t *)(kernel_base + 0xFCD56) = 7; // VM_PROT_ALL;

	printfkernel("Patches Done\n");

	//Kexec init
	void *DT_HASH_SEGMENTs = (void *)(kernel_base + 0xB5EF30); 
	memcpy(DT_HASH_SEGMENTs, sys_unjails, sys_unjail_size);

	void(*kexec_init)(void *, void *) = DT_HASH_SEGMENTs;

	//kexec_init((void *)(kernel_base + 0x436040), NULL);
	kexec_init((void *)(kernel_base + 0x436040), NULL);
	//kexec_init((void *)NULL , NULL);

	printfkernel("thing Done\n");

	printfkernel("kernel base is:0x%016llx\n", kernel_base);

	cpu_enable_wp();

	printfkernel("WP Enabled\n");

	return 0;
}


int kdump(struct thread *td, struct kdump_args* args) {

	struct ucred* cred;
	struct filedesc* fd;

	void* kbase = 0;

	uint64_t fw_version = 0x666;

	if (!memcmp((char*)(&((uint8_t*)__readmsr(0xC0000082))[-KERN_XFAST_SYSCALL]), (char[4]) { 0x7F, 0x45, 0x4C, 0x46 }, 4)) {

		kbase = &((uint8_t*)__readmsr(0xC0000082))[-KERN_XFAST_SYSCALL];
		fw_version = 0x505;
	}

	else if (!memcmp((char*)(&((uint8_t*)__readmsr(0xC0000082))[-KERN_455_XFAST_SYSCALL]), (char[4]) { 0x7F, 0x45, 0x4C, 0x46 }, 4)) {

		kbase = &((uint8_t*)__readmsr(0xC0000082))[-KERN_455_XFAST_SYSCALL];
		fw_version = 0x455;

	}

	else return -1;

	if (fw_version == 0x505) {

		// Kernel pointers resolving

		// hook our kernel functions
		void* kbase = &((uint8_t*)__readmsr(0xC0000082))[-KERN_BASE_PTR];

		int(*printfkernel)(const char *fmt, ...) = (void *)(kbase + KERN_PRINTF);
		int(*copyout)(const void *kaddr, void *uaddr, size_t len) = (void *)(kbase + KERN_COPYOUT);
		void(*bzero)(void *b, size_t len) = (void *)(kbase + KERN_BZERO);
		printfkernel("FW 5.05 Looping\n");
		// pull in our arguments
		uint64_t kaddr = args->payload_info_dumper->kaddr;
		uint64_t uaddr = args->payload_info_dumper->uaddr;

		// run copyout into userland memory for the kaddr we specify
		int cpRet = copyout(kaddr, uaddr, PAGE_SIZE);

		// if mapping doesnt exist zero out that mem
		if (cpRet == -1) {
			printfkernel("bzero at 0x%016llx\n", kaddr);
			bzero(uaddr, PAGE_SIZE);
			return cpRet;
		}

		return cpRet;
	}

	else if (fw_version == 0x455) {


		void* kbase = &((uint8_t*)__readmsr(0xC0000082))[-0x3095d0];
		int(*printfkernel)(const char *fmt, ...) = (void *)(kbase + 0x17F30);
		int(*copyout)(const void *kaddr, void *uaddr, size_t len) = (void *)(kbase + 0x14A7B0);
		void(*bzero)(void *b, size_t len) = (void *)(kbase + 0x014A610);
		int(*copyin)(const void *uaddr, void *kaddr, size_t len) = (void *)(kbase + 0x14A890);

		printfkernel("FW 4.55 Looping\n");

		// pull in our arguments
		uint64_t kaddr = args->payload_info_dumper->kaddr;
		uint64_t uaddr = args->payload_info_dumper->uaddr;

		// run copyout into userland memory for the kaddr we specify
		int cpRet = copyout(kaddr, uaddr, 16348);

		// if mapping doesnt exist zero out that mem
		if (cpRet == -1) {
			printfkernel("bzero at 0x%016llx\n", kaddr);
			bzero(uaddr, 16348);
			return cpRet;
		}
		return cpRet;
	}
	else return -1;
}



void notifye(char *message)
{
	char buffer[512];
	sprintf(buffer, "%s\n\n\n\n\n\n\n", message);
	sceSysUtilSendSystemNotificationWithText(0x81, buffer);
}

uint64_t rdmsr(unsigned int msr_index) {
	uint32_t low, high;
	__asm__ __volatile__("rdmsr" : "=a" (low), "=d" (high) : "c" (msr_index));
	return (low | ((uint64_t)high << 32));
}

uint8_t* get_kptr() {
	return (uint8_t *)(rdmsr(0xC0000082) - KERN_XFAST_SYSCALL);
}

// Unjail 4.05
void *unjail405(struct thread *td) {
	struct ucred* cred;
	struct filedesc* fd;

	fd = td->td_proc->p_fd;
	cred = td->td_proc->p_ucred;

	void* kbase = &((uint8_t*)__readmsr(0xC0000082))[-0x30EB30];
	uint8_t* kernel_ptr = (uint8_t*)kbase;
	void** got_prison0 = (void**)&kernel_ptr[0xF26010];
	void** got_rootvnode = (void**)&kernel_ptr[0x206D250];

	cred->cr_uid = 0;
	cred->cr_ruid = 0;
	cred->cr_rgid = 0;
	cred->cr_groups[0] = 0;
	cred->cr_prison = *got_prison0;
	fd->fd_rdir = fd->fd_jdir = *got_rootvnode;

	// escalate ucred privs, needed for access to the filesystem ie* mounting & decrypting files
	void *td_ucred = *(void **)(((char *)td) + 304); // p_ucred == td_ucred

													 // sceSblACMgrIsSystemUcred
	uint64_t *sonyCred = (uint64_t *)(((char *)td_ucred) + 96);
	*sonyCred = 0xffffffffffffffff;

	// sceSblACMgrGetDeviceAccessType
	uint64_t *sceProcType = (uint64_t *)(((char *)td_ucred) + 88);
	*sceProcType = 0x3801000000000013; // Max access

									   // sceSblACMgrHasSceProcessCapability
	uint64_t *sceProcCap = (uint64_t *)(((char *)td_ucred) + 104);
	*sceProcCap = 0xffffffffffffffff; // Sce Process
	return 0;
}

// Unjail 455
void *unjail455(struct thread *td) {
	struct ucred* cred;
	struct filedesc* fd;

	fd = td->td_proc->p_fd;
	cred = td->td_proc->p_ucred;

	void* kbase = &((uint8_t*)__readmsr(0xC0000082))[-0x3095D0];
	uint8_t* kernel_ptr = (uint8_t*)kbase;
	void** got_prison0 = (void**)&kernel_ptr[0x10399B0];
	void** got_rootvnode = (void**)&kernel_ptr[0x21AFA30];

	cred->cr_uid = 0;
	cred->cr_ruid = 0;
	cred->cr_rgid = 0;
	cred->cr_groups[0] = 0;
	cred->cr_prison = *got_prison0;
	fd->fd_rdir = fd->fd_jdir = *got_rootvnode;

	// escalate ucred privs, needed for access to the filesystem ie* mounting & decrypting files
	void *td_ucred = *(void **)(((char *)td) + 304); // p_ucred == td_ucred

													 // sceSblACMgrIsSystemUcred
	uint64_t *sonyCred = (uint64_t *)(((char *)td_ucred) + 96);
	*sonyCred = 0xffffffffffffffff;

	// sceSblACMgrGetDeviceAccessType
	uint64_t *sceProcType = (uint64_t *)(((char *)td_ucred) + 88);
	*sceProcType = 0x3801000000000013; // Max access

									   // sceSblACMgrHasSceProcessCapability
	uint64_t *sceProcCap = (uint64_t *)(((char *)td_ucred) + 104);
	*sceProcCap = 0xffffffffffffffff; // Sce Process	

	int(*printfkernel)(const char *fmt, ...) = (void *)(kbase + 0x17F30);

	return 0;
}

// Unjail 500
void *unjail500(struct thread *td) {
	struct ucred* cred;
	struct filedesc* fd;

	fd = td->td_proc->p_fd;
	cred = td->td_proc->p_ucred;

	void* kbase = &((uint8_t*)__readmsr(0xC0000082))[0x1C0];
	uint8_t* kernel_ptr = (uint8_t*)kbase;
	void** got_prison0 = (void**)&kernel_ptr[0x10986A0];
	void** got_rootvnode = (void**)&kernel_ptr[0x22C19F0];

	cred->cr_uid = 0;
	cred->cr_ruid = 0;
	cred->cr_rgid = 0;
	cred->cr_groups[0] = 0;

	cred->cr_prison = *got_prison0;
	fd->fd_rdir = fd->fd_jdir = *got_rootvnode;

	// escalate ucred privs, needed for access to the filesystem ie* mounting & decrypting files
	void *td_ucred = *(void **)(((char *)td) + 304); // p_ucred == td_ucred

													 // sceSblACMgrIsSystemUcred
	uint64_t *sonyCred = (uint64_t *)(((char *)td_ucred) + 96);
	*sonyCred = 0xffffffffffffffff;

	// sceSblACMgrGetDeviceAccessType
	uint64_t *sceProcType = (uint64_t *)(((char *)td_ucred) + 88);
	*sceProcType = 0x3801000000000013; // Max access

									   // sceSblACMgrHasSceProcessCapability
	uint64_t *sceProcCap = (uint64_t *)(((char *)td_ucred) + 104);
	*sceProcCap = 0xffffffffffffffff; // Sce Process	*/
	return 0;
}

// Unjail 505
void *unjail505(struct thread *td) {

	struct ucred* cred;
	struct filedesc* fd;

	void* kbase = 0;
	uint8_t* kernel_ptr;
	void** got_prison0;
	void** got_rootvnode;


	fd = td->td_proc->p_fd;
	cred = td->td_proc->p_ucred;

	uint64_t fw_version = 0x999;

	if (!memcmp((char*)(&((uint8_t*)__readmsr(0xC0000082))[-KERN_505_XFAST_SYSCALL]), (char[4]) { 0x7F, 0x45, 0x4C, 0x46 }, 4)) {

		kbase = &((uint8_t*)__readmsr(0xC0000082))[-KERN_505_XFAST_SYSCALL];


		fw_version = 0x505;

	}

	else if (!memcmp((char*)(&((uint8_t*)__readmsr(0xC0000082))[-KERN_455_XFAST_SYSCALL]), (char[4]) { 0x7F, 0x45, 0x4C, 0x46 }, 4)) {

		kbase = &((uint8_t*)__readmsr(0xC0000082))[-KERN_455_XFAST_SYSCALL];

		fw_version = 0x455;
	}

	else if (!memcmp((char*)(&((uint8_t*)__readmsr(0xC0000082))[-KERN_455_XFAST_SYSCALL]), (char[4]) { 0x7F, 0x45, 0x4C, 0x46 }, 4)) {

		kbase = &((uint8_t*)__readmsr(0xC0000082))[-KERN_455_XFAST_SYSCALL];

		fw_version = 0x455;

	}
	else if (!memcmp((char*)(&((uint8_t*)__readmsr(0xC0000082))[-KERN_405_XFAST_SYSCALL]), (char[4]) { 0x7F, 0x45, 0x4C, 0x46 }, 4)) {
		fw_version = 0x405;

	}
	else return -1;

	if (fw_version == 0x505) {

		int(*printfkernel)(const char *fmt, ...) = (void *)(kbase + 0x436040);
		printfkernel("FW Version 5.05 Detected\n");
	}

	else if (fw_version == 0x405) {

		int(*printfkernel)(const char *fmt, ...) = (void *)(kbase + KERN_405_PRINTF);
		printfkernel("FW Version 4.05 Detected\n");

	}
	else if (fw_version == 0x455) {

		int(*printfkernel)(const char *fmt, ...) = (void *)(kbase + KERN_455_PRINTF);
		printfkernel("FW Version 4.55 Detected\n");

	}
	else if (fw_version == 0x501) {

		int(*printfkernel)(const char *fmt, ...) = (void *)(kbase + KERN_501_PRINTF);
		printfkernel("FW Version 5.05 Detected\n");
	}
	else return -1;


	if (fw_version == 0x405) {


		// Kernel pointers resolving

		kernel_ptr = (uint8_t*)kbase;
		got_prison0 = (void**)&kernel_ptr[KERN_405_PRISON_0];
		got_rootvnode = (void**)&kernel_ptr[KERN_405_ROOTVNODE];

	}
	else if (fw_version == 0x455) {

		// Kernel pointers resolving

		kernel_ptr = (uint8_t*)kbase;
		got_prison0 = (void**)&kernel_ptr[KERN_455_PRISON_0];
		got_rootvnode = (void**)&kernel_ptr[KERN_455_ROOTVNODE];

	}
	else if (fw_version == 0x501) {

		// Kernel pointers resolving

		kernel_ptr = (uint8_t*)kbase;
		got_prison0 = (void**)&kernel_ptr[KERN_501_PRISON_0];
		got_rootvnode = (void**)&kernel_ptr[KERN_501_ROOTVNODE];

	}
	else if (fw_version == 0x505) {

		// Kernel pointers resolving

		kernel_ptr = (uint8_t*)kbase;
		got_prison0 = (void**)&kernel_ptr[KERN_505_PRISON_0];
		got_rootvnode = (void**)&kernel_ptr[KERN_505_ROOTVNODE];

	}
	else return -1;

	cred->cr_uid = 0;
	cred->cr_ruid = 0;
	cred->cr_rgid = 0;
	cred->cr_groups[0] = 0;
	cred->cr_prison = *got_prison0;
	fd->fd_rdir = fd->fd_jdir = *got_rootvnode;

	// Escalate ucred privs, needed for userland access to the filesystem e.g mounting & decrypting files

	void *td_ucred = *(void **)(((char *)td) + 304); // p_ucred == td_ucred

	uint64_t *sonyCred = (uint64_t *)(((char *)td_ucred) + 96);
	*sonyCred = 0xffffffffffffffff;

	// sceSblACMgrGetDeviceAccessType
	*(uint64_t *)(td_ucred + 0x60) = 0xFFFFFFFFFFFFFFFF;
	*(uint64_t *)(td_ucred + 0x58) = 0x3801000000000013;
	*(uint64_t *)(td_ucred + 0x68) = 0xFFFFFFFFFFFFFFFF;

	uint64_t *sceProcessAuthorityId = (uint64_t *)(((char *)td_ucred) + 88);
	*sceProcessAuthorityId = 0x3800000000000010; // SceShellcore paid
												 // sceSblACMgrHasSceProcessCapability

	uint64_t *sceProcCap = (uint64_t *)(((char *)td_ucred) + 104);
	*sceProcCap = 0xffffffffffffffff; // Max capability

	if (fw_version == 0x505) {

		// Kernel pointers resolving

		kernel_ptr = (uint8_t*)kbase;
		got_prison0 = (void**)&kernel_ptr[KERN_505_PRISON_0];
		got_rootvnode = (void**)&kernel_ptr[KERN_505_ROOTVNODE];

		int(*copyout)(const void *kaddr, void *uaddr, size_t len);

		copyout = (void *)(kbase + KERN_505_COPYOUT);

		cpu_disable_wp();

		*(uint8_t *)(kbase + 0xFCD48) = 3; // VM_PROT_DEFAULT;
		*(uint8_t *)(kbase + 0xFCD56) = 3; // VM_PROT_DEFAULT;

											  // patch vm_map_protect check
		memcpy((void *)(kbase + 0x1A3C08), "\x90\x90\x90\x90\x90\x90", 6);

		// Disable ptrace check

		kernel_ptr[0x30D9AA] = 0xEB;

		// Disable process aslr
		*(uint16_t*)&kernel_ptr[0x194875] = 0x9090;

		// Allow sys_dynlib_dlsym in all processes.
		*(uint16_t *)(kbase + 0x237F3B) = 0x01C1;
		//*(uint16_t *)(kbase + 0x237F3B) = 0x101C;

		// Don't restrict dynlib information.
		*(uint64_t *)(kbase + 0x2B2620) = 0x9090909090C3C031;

		// Allow usage of mangled symbols in dynlib_do_dlsym().
		*(uint16_t *)(kbase + 0x2AFB47) = 0x9090;
		*(uint16_t *)(kbase + 0x2AFB47 + 2) = 0x9090;
		*(uint16_t *)(kbase + 0x2AFB47 + 4) = 0x9090;

		*(uint32_t *)(kbase + 0x19ECEB0) = 0;

		*(uint8_t*)(kbase + 0x117B0) = 0xB0;
		*(uint8_t*)(kbase + 0x117B1) = 0x01;
		*(uint8_t*)(kbase + 0x117B2) = 0xC3;

		*(uint8_t*)(kbase + 0x117C0) = 0xB0;
		*(uint8_t*)(kbase + 0x117C1) = 0x01;
		*(uint8_t*)(kbase + 0x117C2) = 0xC3;

		*(uint8_t*)(kbase + 0x13F03F) = 0x31;
		*(uint8_t*)(kbase + 0x13F040) = 0xC0;
		*(uint8_t*)(kbase + 0x13F041) = 0x90;
		*(uint8_t*)(kbase + 0x13F042) = 0x90;
		*(uint8_t*)(kbase + 0x13F043) = 0x90;

		cpu_enable_wp();
		//5.05
		//int(*copyin)(const void *uaddr, void *kaddr, size_t len) = (void *)(kbase + 0x001EA710);
	}
	else if (fw_version == 0x455) {


		kernel_ptr = (uint8_t*)kbase;
		got_prison0 = (void**)&kernel_ptr[KERN_455_PRISON_0];
		got_rootvnode = (void**)&kernel_ptr[KERN_455_ROOTVNODE];

		int(*copyout)(const void *kaddr, void *uaddr, size_t len);

		copyout = (void *)(kbase + KERN_455_COPYOUT);

		cpu_disable_wp();


		*(uint8_t*)(kbase + 0x143BF2) = 0x90; //0x0F
		*(uint8_t*)(kbase + 0x143BF3) = 0xE9; //0x84
		*(uint8_t*)(kbase + 0x143E0E) = 0x90; //0x74
		*(uint8_t*)(kbase + 0x143E0F) = 0x90; //0x0C

		cpu_enable_wp();

		//4.55
		//int(*copyin)(const void *uaddr, void *kaddr, size_t len) = (void *)(kbase + 0x0014A890);

	}

	return 0;

}


void *sys_unjail(struct thread *td) {

	struct ucred* cred;
	struct filedesc* fd;

	void* kbase = 0;
	uint8_t* kernel_ptr;
	void** got_prison0;
	void** got_rootvnode;


	fd = td->td_proc->p_fd;
	cred = td->td_proc->p_ucred;

	uint64_t fw_version = 0x999;

	if (!memcmp((char*)(&((uint8_t*)__readmsr(0xC0000082))[-KERN_505_XFAST_SYSCALL]), (char[4]) { 0x7F, 0x45, 0x4C, 0x46 }, 4)) {

		kbase = &((uint8_t*)__readmsr(0xC0000082))[-KERN_505_XFAST_SYSCALL];


		fw_version = 0x505;

	}

	else if (!memcmp((char*)(&((uint8_t*)__readmsr(0xC0000082))[-KERN_455_XFAST_SYSCALL]), (char[4]) { 0x7F, 0x45, 0x4C, 0x46 }, 4)) {

		kbase = &((uint8_t*)__readmsr(0xC0000082))[-KERN_455_XFAST_SYSCALL];

		fw_version = 0x455;
	}

	else if (!memcmp((char*)(&((uint8_t*)__readmsr(0xC0000082))[-KERN_455_XFAST_SYSCALL]), (char[4]) { 0x7F, 0x45, 0x4C, 0x46 }, 4)) {

		kbase = &((uint8_t*)__readmsr(0xC0000082))[-KERN_455_XFAST_SYSCALL];

		fw_version = 0x455;

	}
	else if (!memcmp((char*)(&((uint8_t*)__readmsr(0xC0000082))[-KERN_405_XFAST_SYSCALL]), (char[4]) { 0x7F, 0x45, 0x4C, 0x46 }, 4)) {
		fw_version = 0x405;

	}
	else return -1;

	if (fw_version == 0x505) {

		int(*printfkernel)(const char *fmt, ...) = (void *)(kbase + 0x436040);
		printfkernel("Syscall 9 Unjail invoked\n");
		printfkernel("FW Version 5.05 Detected\n");
	}

	else if (fw_version == 0x405) {

		int(*printfkernel)(const char *fmt, ...) = (void *)(kbase + KERN_405_PRINTF);
		printfkernel("FW Version 4.05 Detected\n");

	}
	else if (fw_version == 0x455) {

		int(*printfkernel)(const char *fmt, ...) = (void *)(kbase + KERN_455_PRINTF);
		printfkernel("Syscall 9 Unjail invoked\n");
		printfkernel("FW Version 4.55 Detected\n");

	}
	else if (fw_version == 0x501) {

		int(*printfkernel)(const char *fmt, ...) = (void *)(kbase + KERN_501_PRINTF);
		printfkernel("Syscall 9 Unjail invoked\n");
		printfkernel("FW Version 5.05 Detected\n");
	}
	else return -1;


	if (fw_version == 0x405) {


		// Kernel pointers resolving

		kernel_ptr = (uint8_t*)kbase;
		got_prison0 = (void**)&kernel_ptr[KERN_405_PRISON_0];
		got_rootvnode = (void**)&kernel_ptr[KERN_405_ROOTVNODE];

	}
	else if (fw_version == 0x455) {

		// Kernel pointers resolving

		kernel_ptr = (uint8_t*)kbase;
		got_prison0 = (void**)&kernel_ptr[KERN_455_PRISON_0];
		got_rootvnode = (void**)&kernel_ptr[KERN_455_ROOTVNODE];

	}
	else if (fw_version == 0x501) {

		// Kernel pointers resolving

		kernel_ptr = (uint8_t*)kbase;
		got_prison0 = (void**)&kernel_ptr[KERN_501_PRISON_0];
		got_rootvnode = (void**)&kernel_ptr[KERN_501_ROOTVNODE];

	}
	else if (fw_version == 0x505) {

		// Kernel pointers resolving

		kernel_ptr = (uint8_t*)kbase;
		got_prison0 = (void**)&kernel_ptr[KERN_505_PRISON_0];
		got_rootvnode = (void**)&kernel_ptr[KERN_505_ROOTVNODE];

	}
	else return -1;

	cred->cr_uid = 0;
	cred->cr_ruid = 0;
	cred->cr_rgid = 0;
	cred->cr_groups[0] = 0;
	cred->cr_prison = *got_prison0;
	fd->fd_rdir = fd->fd_jdir = *got_rootvnode;

	// Escalate ucred privs, needed for userland access to the filesystem e.g mounting & decrypting files

	void *td_ucred = *(void **)(((char *)td) + 304); // p_ucred == td_ucred

	uint64_t *sonyCred = (uint64_t *)(((char *)td_ucred) + 96);
	*sonyCred = 0xffffffffffffffff;

	// sceSblACMgrGetDeviceAccessType
	*(uint64_t *)(td_ucred + 0x60) = 0xFFFFFFFFFFFFFFFF;
	*(uint64_t *)(td_ucred + 0x58) = 0x3801000000000013;
	*(uint64_t *)(td_ucred + 0x68) = 0xFFFFFFFFFFFFFFFF;

	uint64_t *sceProcessAuthorityId = (uint64_t *)(((char *)td_ucred) + 88);
	*sceProcessAuthorityId = 0x3800000000000010; // SceShellcore paid
												 // sceSblACMgrHasSceProcessCapability

	uint64_t *sceProcCap = (uint64_t *)(((char *)td_ucred) + 104);
	*sceProcCap = 0xffffffffffffffff; // Max capability

	if (fw_version == 0x505) {

		// Kernel pointers resolving

		kernel_ptr = (uint8_t*)kbase;
		got_prison0 = (void**)&kernel_ptr[KERN_505_PRISON_0];
		got_rootvnode = (void**)&kernel_ptr[KERN_505_ROOTVNODE];

		int(*copyout)(const void *kaddr, void *uaddr, size_t len);

		copyout = (void *)(kbase + KERN_505_COPYOUT);

		cpu_disable_wp();

		*(uint8_t *)(kbase + 0xFCD48) = 3; // VM_PROT_DEFAULT;
		*(uint8_t *)(kbase + 0xFCD56) = 3; // VM_PROT_DEFAULT;

										   // patch vm_map_protect check
		memcpy((void *)(kbase + 0x1A3C08), "\x90\x90\x90\x90\x90\x90", 6);

		// Disable ptrace check

		kernel_ptr[0x30D9AA] = 0xEB;

		// Disable process aslr
		*(uint16_t*)&kernel_ptr[0x194875] = 0x9090;

		// Allow sys_dynlib_dlsym in all processes.
		*(uint16_t *)(kbase + 0x237F3B) = 0x01C1;
		//*(uint16_t *)(kbase + 0x237F3B) = 0x101C;

		// Don't restrict dynlib information.
		*(uint64_t *)(kbase + 0x2B2620) = 0x9090909090C3C031;

		// Allow usage of mangled symbols in dynlib_do_dlsym().
		*(uint16_t *)(kbase + 0x2AFB47) = 0x9090;
		*(uint16_t *)(kbase + 0x2AFB47 + 2) = 0x9090;
		*(uint16_t *)(kbase + 0x2AFB47 + 4) = 0x9090;

		*(uint32_t *)(kbase + 0x19ECEB0) = 0;

		*(uint8_t*)(kbase + 0x117B0) = 0xB0;
		*(uint8_t*)(kbase + 0x117B1) = 0x01;
		*(uint8_t*)(kbase + 0x117B2) = 0xC3;

		*(uint8_t*)(kbase + 0x117C0) = 0xB0;
		*(uint8_t*)(kbase + 0x117C1) = 0x01;
		*(uint8_t*)(kbase + 0x117C2) = 0xC3;

		*(uint8_t*)(kbase + 0x13F03F) = 0x31;
		*(uint8_t*)(kbase + 0x13F040) = 0xC0;
		*(uint8_t*)(kbase + 0x13F041) = 0x90;
		*(uint8_t*)(kbase + 0x13F042) = 0x90;
		*(uint8_t*)(kbase + 0x13F043) = 0x90;

		cpu_enable_wp();
	}
	else if (fw_version == 0x455) {


		kernel_ptr = (uint8_t*)kbase;
		got_prison0 = (void**)&kernel_ptr[KERN_455_PRISON_0];
		got_rootvnode = (void**)&kernel_ptr[KERN_455_ROOTVNODE];

		int(*copyout)(const void *kaddr, void *uaddr, size_t len);

		copyout = (void *)(kbase + KERN_455_COPYOUT);

		cpu_disable_wp();


		*(uint8_t*)(kbase + 0x143BF2) = 0x90; //0x0F
		*(uint8_t*)(kbase + 0x143BF3) = 0xE9; //0x84
		*(uint8_t*)(kbase + 0x143E0E) = 0x90; //0x74
		*(uint8_t*)(kbase + 0x143E0F) = 0x90; //0x0C

		cpu_enable_wp();

	}

	return 0;

}
// Unjail 505
void *debugon(struct thread *td) {

	void* kbase = 0;
	uint64_t fw_version = 0x666;

	if (!memcmp((char*)(&((uint8_t*)__readmsr(0xC0000082))[-KERN_505_XFAST_SYSCALL]), (char[4]) { 0x7F, 0x45, 0x4C, 0x46 }, 4)) {

		kbase = &((uint8_t*)__readmsr(0xC0000082))[-KERN_505_XFAST_SYSCALL];
		fw_version = 0x505;

	}

	else if (!memcmp((char*)(&((uint8_t*)__readmsr(0xC0000082))[-KERN_455_XFAST_SYSCALL]), (char[4]) { 0x7F, 0x45, 0x4C, 0x46 }, 4)) {

		kbase = &((uint8_t*)__readmsr(0xC0000082))[-KERN_455_XFAST_SYSCALL];
		fw_version = 0x455;
	}

	else if (!memcmp((char*)(&((uint8_t*)__readmsr(0xC0000082))[-KERN_405_XFAST_SYSCALL]), (char[4]) { 0x7F, 0x45, 0x4C, 0x46 }, 4)) {
		fw_version = 0x405;

	}
	else return -1;

	if (fw_version == 0x505) {

		int(*printfkernel)(const char *fmt, ...) = (void *)(kbase + 0x436040);
		printfkernel("FW Version 5.05 Detected\n");
	}

	else if (fw_version == 0x405) {

		int(*printfkernel)(const char *fmt, ...) = (void *)(kbase + KERN_405_PRINTF);
		printfkernel("FW Version 4.05 Detected\n");

	}
	else if (fw_version == 0x455) {

		int(*printfkernel)(const char *fmt, ...) = (void *)(kbase + KERN_455_PRINTF);
		printfkernel("FW Version 4.55 Detected\n");

	}
	else if (fw_version == 0x501) {

		int(*printfkernel)(const char *fmt, ...) = (void *)(kbase + KERN_501_PRINTF);
		printfkernel("FW Version 5.05 Detected\n");
	}
	else return -1;



	if (fw_version == 0x505) {


		cpu_disable_wp();
		// Allow sys_dynlib_dlsym in all processes.
		*(uint16_t *)(kbase + 0x237F3B) = 0x01C1;
		//*(uint16_t *)(kbase + 0x237F3B) = 0x101C;

		// Don't restrict dynlib information.
		*(uint64_t *)(kbase + 0x2B2620) = 0x9090909090C3C031;

		// Allow usage of mangled symbols in dynlib_do_dlsym().
		*(uint16_t *)(kbase + 0x2AFB47) = 0x9090;
		*(uint16_t *)(kbase + 0x2AFB47 + 2) = 0x9090;
		*(uint16_t *)(kbase + 0x2AFB47 + 4) = 0x9090;

		cpu_enable_wp();
	}

	else if (fw_version == 0x405) {


		cpu_disable_wp();


		cpu_enable_wp();
	}

	else if (fw_version == 0x455) {

		cpu_disable_wp();


		cpu_enable_wp();
	}

	else if (fw_version == 0x501) {

		cpu_disable_wp();


		cpu_enable_wp();
	}
	else return -1;

	return 0;
}

int dumpsflash()
{
	copyFile("/mnt/usb0/test.txt", "/update/test.txt");

}

void *debugoff(struct thread *td) {


	void* kbase = 0;
	uint64_t fw_version = 0x666;

	if (!memcmp((char*)(&((uint8_t*)__readmsr(0xC0000082))[-KERN_505_XFAST_SYSCALL]), (char[4]) { 0x7F, 0x45, 0x4C, 0x46 }, 4)) {

		kbase = &((uint8_t*)__readmsr(0xC0000082))[-KERN_505_XFAST_SYSCALL];


		fw_version = 0x505;

	}

	else if (!memcmp((char*)(&((uint8_t*)__readmsr(0xC0000082))[-KERN_455_XFAST_SYSCALL]), (char[4]) { 0x7F, 0x45, 0x4C, 0x46 }, 4)) {

		kbase = &((uint8_t*)__readmsr(0xC0000082))[-KERN_455_XFAST_SYSCALL];

		fw_version = 0x455;
	}

	else if (!memcmp((char*)(&((uint8_t*)__readmsr(0xC0000082))[-KERN_455_XFAST_SYSCALL]), (char[4]) { 0x7F, 0x45, 0x4C, 0x46 }, 4)) {

		kbase = &((uint8_t*)__readmsr(0xC0000082))[-KERN_455_XFAST_SYSCALL];

		fw_version = 0x455;

	}
	else if (!memcmp((char*)(&((uint8_t*)__readmsr(0xC0000082))[-KERN_405_XFAST_SYSCALL]), (char[4]) { 0x7F, 0x45, 0x4C, 0x46 }, 4)) {
		fw_version = 0x405;

	}
	else return -1;

	if (fw_version == 0x505) {

		int(*printfkernel)(const char *fmt, ...) = (void *)(kbase + 0x436040);
		printfkernel("FW Version 5.05 Detected\n");
	}

	else if (fw_version == 0x405) {

		int(*printfkernel)(const char *fmt, ...) = (void *)(kbase + KERN_405_PRINTF);
		printfkernel("FW Version 4.05 Detected\n");

	}
	else if (fw_version == 0x455) {

		int(*printfkernel)(const char *fmt, ...) = (void *)(kbase + KERN_455_PRINTF);
		printfkernel("FW Version 4.55 Detected\n");

	}
	else if (fw_version == 0x501) {

		int(*printfkernel)(const char *fmt, ...) = (void *)(kbase + KERN_501_PRINTF);
		printfkernel("FW Version 5.05 Detected\n");
	}
	else return -1;



	if (fw_version == 0x505) {


		cpu_disable_wp();
		// Allow sys_dynlib_dlsym in all processes.
		*(uint16_t *)(kbase + 0x237F3B) = 0x01C1;
		//*(uint16_t *)(kbase + 0x237F3B) = 0x101C;

		// Don't restrict dynlib information.
		*(uint64_t *)(kbase + 0x2B2620) = 0x9090909090C3C031;

		// Allow usage of mangled symbols in dynlib_do_dlsym().
		*(uint16_t *)(kbase + 0x2AFB47) = 0x9090;
		*(uint16_t *)(kbase + 0x2AFB47 + 2) = 0x9090;
		*(uint16_t *)(kbase + 0x2AFB47 + 4) = 0x9090;

		cpu_enable_wp();
	}

	else if (fw_version == 0x405) {


		cpu_disable_wp();


		cpu_enable_wp();
	}

	else if (fw_version == 0x455) {

		cpu_disable_wp();


		cpu_enable_wp();
	}

	else if (fw_version == 0x501) {

		cpu_disable_wp();


		cpu_enable_wp();
	}
	else return -1;

	return 0;
}

void *spoofdevkit(struct thread *td) {


	void* kbase = 0;
	uint64_t fw_version = 0x666;

	if (!memcmp((char*)(&((uint8_t*)__readmsr(0xC0000082))[-KERN_505_XFAST_SYSCALL]), (char[4]) { 0x7F, 0x45, 0x4C, 0x46 }, 4)) {

		kbase = &((uint8_t*)__readmsr(0xC0000082))[-KERN_505_XFAST_SYSCALL];


		fw_version = 0x505;

	}

	else if (!memcmp((char*)(&((uint8_t*)__readmsr(0xC0000082))[-KERN_455_XFAST_SYSCALL]), (char[4]) { 0x7F, 0x45, 0x4C, 0x46 }, 4)) {

		kbase = &((uint8_t*)__readmsr(0xC0000082))[-KERN_455_XFAST_SYSCALL];

		fw_version = 0x455;
	}

	else if (!memcmp((char*)(&((uint8_t*)__readmsr(0xC0000082))[-KERN_455_XFAST_SYSCALL]), (char[4]) { 0x7F, 0x45, 0x4C, 0x46 }, 4)) {

		kbase = &((uint8_t*)__readmsr(0xC0000082))[-KERN_455_XFAST_SYSCALL];

		fw_version = 0x455;

	}
	else if (!memcmp((char*)(&((uint8_t*)__readmsr(0xC0000082))[-KERN_405_XFAST_SYSCALL]), (char[4]) { 0x7F, 0x45, 0x4C, 0x46 }, 4)) {
		fw_version = 0x405;

	}
	else return -1;

	if (fw_version == 0x505) {

		int(*printfkernel)(const char *fmt, ...) = (void *)(kbase + 0x436040);
		printfkernel("FW Version 5.05 Detected\n");
	}

	else if (fw_version == 0x405) {

		int(*printfkernel)(const char *fmt, ...) = (void *)(kbase + KERN_405_PRINTF);
		printfkernel("FW Version 4.05 Detected\n");

	}
	else if (fw_version == 0x455) {

		int(*printfkernel)(const char *fmt, ...) = (void *)(kbase + KERN_455_PRINTF);
		printfkernel("FW Version 4.55 Detected\n");

	}
	else if (fw_version == 0x501) {

		int(*printfkernel)(const char *fmt, ...) = (void *)(kbase + KERN_501_PRINTF);
		printfkernel("FW Version 5.05 Detected\n");
	}
	else return -1;



	if (fw_version == 0x505) {


		cpu_disable_wp();
		// Allow sys_dynlib_dlsym in all processes.
		*(uint16_t *)(kbase + 0x237F3B) = 0x01C1;
		//*(uint16_t *)(kbase + 0x237F3B) = 0x101C;

		// Don't restrict dynlib information.
		*(uint64_t *)(kbase + 0x2B2620) = 0x9090909090C3C031;

		// Allow usage of mangled symbols in dynlib_do_dlsym().
		*(uint16_t *)(kbase + 0x2AFB47) = 0x9090;
		*(uint16_t *)(kbase + 0x2AFB47 + 2) = 0x9090;
		*(uint16_t *)(kbase + 0x2AFB47 + 4) = 0x9090;
		*(uint16_t *)(kbase + __target_id_0) = 0x8101;
		*(uint16_t *)(kbase + __target_id_1) = 0x8101;

		cpu_enable_wp();
	}

	else if (fw_version == 0x405) {


		cpu_disable_wp();
		*(uint16_t *)(kbase + 0x1FE59E4) = 0x8101;
		*(uint16_t *)(kbase + 0X1FE5A2C) = 0x8101;
		*(uint16_t *)(kbase + 0x200151C) = 0x8101;

		cpu_enable_wp();
	}

	else if (fw_version == 0x455) {

		cpu_disable_wp();
		*(uint16_t *)(kbase + 0x1AF82C4) = 0x8101;
		*(uint16_t *)(kbase + 0X1AF85A4) = 0x8101;
		*(uint16_t *)(kbase + 0x1B6D08C) = 0x8101;

		cpu_enable_wp();
	}

	else if (fw_version == 0x501) {

		cpu_disable_wp();
		// spoofer
		*(uint32_t *)(kbase + 0x14A63F0) = 0x5550001;

		cpu_enable_wp();
	}
	else return -1;

	return 0;
}

void *parentcontrol(struct thread *td) {

	void* kbase = 0;
	//uint8_t* kernel_ptr;
	uint64_t fw_version = 0x666;
	uint64_t(*sceRegMgrSetInt)(uint32_t regId, int value);

	if (!memcmp((char*)(&((uint8_t*)__readmsr(0xC0000082))[-KERN_505_XFAST_SYSCALL]), (char[4]) { 0x7F, 0x45, 0x4C, 0x46 }, 4)) {

		kbase = &((uint8_t*)__readmsr(0xC0000082))[-KERN_505_XFAST_SYSCALL];
		fw_version = 0x505;

	}

	else if (!memcmp((char*)(&((uint8_t*)__readmsr(0xC0000082))[-KERN_455_XFAST_SYSCALL]), (char[4]) { 0x7F, 0x45, 0x4C, 0x46 }, 4)) {

		kbase = &((uint8_t*)__readmsr(0xC0000082))[-KERN_455_XFAST_SYSCALL];

		fw_version = 0x455;
	}

	else return -1;

	if (fw_version == 0x505) {

		int(*printfkernel)(const char *fmt, ...) = (void *)(kbase + 0x436040);
		printfkernel("FW Version 5.05 Detected\n");
	}

	else if (fw_version == 0x405) {

		int(*printfkernel)(const char *fmt, ...) = (void *)(kbase + KERN_405_PRINTF);
		printfkernel("FW Version 4.05 Detected\n");

	}
	else if (fw_version == 0x455) {

		int(*printfkernel)(const char *fmt, ...) = (void *)(kbase + KERN_455_PRINTF);
		printfkernel("FW Version 4.55 Detected\n");

	}
	else return -1;



	if (fw_version == 0x505) {
		uint8_t* kernel_ptr = (uint8_t*)kbase;
		*(void**)(&sceRegMgrSetInt) = &kernel_ptr[HiAlAzif];

		//printfkernel("Done, now try reg...\n");

		sceRegMgrSetInt(0x3800800, 1);
		sceRegMgrSetInt(0x3800600, 0);
		sceRegMgrSetInt(0x3800700, 0);
		sceRegMgrSetInt(0x3800500, 0);
		sceRegMgrSetInt(0x3800400, 0);
		sceRegMgrSetInt(0x3800100, 0);

		//printfkernel("NULL\n");

		cpu_disable_wp();
		// Allow sys_dynlib_dlsym in all processes.
		*(uint16_t *)(kbase + 0x237F3B) = 0x01C1;
		//*(uint16_t *)(kbase + 0x237F3B) = 0x101C;

		// Don't restrict dynlib information.
		*(uint64_t *)(kbase + 0x2B2620) = 0x9090909090C3C031;

		// Allow usage of mangled symbols in dynlib_do_dlsym().
		*(uint16_t *)(kbase + 0x2AFB47) = 0x9090;
		*(uint16_t *)(kbase + 0x2AFB47 + 2) = 0x9090;
		*(uint16_t *)(kbase + 0x2AFB47 + 4) = 0x9090;
		cpu_enable_wp();
	}

	else if (fw_version == 0x405) {
		uint8_t* kernel_ptr = (uint8_t*)kbase;
		*(void**)(&sceRegMgrSetInt) = &kernel_ptr[0x4CEAB0];

		//printfkernel("Done, now try reg...\n");

		sceRegMgrSetInt(0x3800800, 1);
		sceRegMgrSetInt(0x3800600, 0);
		sceRegMgrSetInt(0x3800700, 0);
		sceRegMgrSetInt(0x3800500, 0);
		sceRegMgrSetInt(0x3800400, 0);
		sceRegMgrSetInt(0x3800100, 0);

		//	printfkernel("NULL\n");
	}

	else if (fw_version == 0x455) {
		uint8_t* kernel_ptr = (uint8_t*)kbase;
		*(void**)(&sceRegMgrSetInt) = &kernel_ptr[0x4D6F00];

		//	printfkernel("Done, now try reg...\n");

		sceRegMgrSetInt(0x3800800, 1);
		sceRegMgrSetInt(0x3800600, 0);
		sceRegMgrSetInt(0x3800700, 0);
		sceRegMgrSetInt(0x3800500, 0);
		sceRegMgrSetInt(0x3800400, 0);
		sceRegMgrSetInt(0x3800100, 0);

		//printfkernel("NULL\n");
	}
	else return -1;

	return 0;
}

void *recovery(struct thread *td) {

	struct ucred* cred;
	struct filedesc* fd;
	void* kbase = 0;
	uint8_t* kernel_ptr;
	void** got_prison0;
	void** got_rootvnode;


	uint64_t fw_version = 0x666;
	uint64_t(*sceRegMgrSetInt)(uint32_t regId, int value);

	if (!memcmp((char*)(&((uint8_t*)__readmsr(0xC0000082))[-KERN_505_XFAST_SYSCALL]), (char[4]) { 0x7F, 0x45, 0x4C, 0x46 }, 4)) {

		kbase = &((uint8_t*)__readmsr(0xC0000082))[-KERN_505_XFAST_SYSCALL];


		fw_version = 0x505;

	}

	else if (!memcmp((char*)(&((uint8_t*)__readmsr(0xC0000082))[-KERN_455_XFAST_SYSCALL]), (char[4]) { 0x7F, 0x45, 0x4C, 0x46 }, 4)) {

		kbase = &((uint8_t*)__readmsr(0xC0000082))[-KERN_455_XFAST_SYSCALL];

		fw_version = 0x455;
	}

	else if (!memcmp((char*)(&((uint8_t*)__readmsr(0xC0000082))[-KERN_455_XFAST_SYSCALL]), (char[4]) { 0x7F, 0x45, 0x4C, 0x46 }, 4)) {

		kbase = &((uint8_t*)__readmsr(0xC0000082))[-KERN_455_XFAST_SYSCALL];

		fw_version = 0x455;

	}
	else if (!memcmp((char*)(&((uint8_t*)__readmsr(0xC0000082))[-KERN_405_XFAST_SYSCALL]), (char[4]) { 0x7F, 0x45, 0x4C, 0x46 }, 4)) {
		fw_version = 0x405;

	}
	else return -1;

	if (fw_version == 0x505) {

		int(*printfkernel)(const char *fmt, ...) = (void *)(kbase + 0x436040);
		printfkernel("FW Version 5.05 Detected\n");
	}

	else if (fw_version == 0x405) {

		int(*printfkernel)(const char *fmt, ...) = (void *)(kbase + KERN_405_PRINTF);
		printfkernel("FW Version 4.05 Detected\n");

	}
	else if (fw_version == 0x455) {

		int(*printfkernel)(const char *fmt, ...) = (void *)(kbase + KERN_455_PRINTF);
		printfkernel("FW Version 4.55 Detected\n");

	}
	else if (fw_version == 0x501) {

		int(*printfkernel)(const char *fmt, ...) = (void *)(kbase + KERN_501_PRINTF);
		printfkernel("FW Version 5.05 Detected\n");
	}
	else return -1;



	if (fw_version == 0x505) {
		kernel_ptr = (uint8_t*)kbase;
		*(void**)(&sceRegMgrSetInt) = &kernel_ptr[HiAlAzif];

		//printfkernel("Done, now try reg...\n");

		sceRegMgrSetInt(recoverymode, 1);

		//printfkernel("NULL\n");

		cpu_disable_wp();
		// Allow sys_dynlib_dlsym in all processes.
		*(uint16_t *)(kbase + 0x237F3B) = 0x01C1;
		//*(uint16_t *)(kbase + 0x237F3B) = 0x101C;

		// Don't restrict dynlib information.
		*(uint64_t *)(kbase + 0x2B2620) = 0x9090909090C3C031;

		// Allow usage of mangled symbols in dynlib_do_dlsym().
		*(uint16_t *)(kbase + 0x2AFB47) = 0x9090;
		*(uint16_t *)(kbase + 0x2AFB47 + 2) = 0x9090;
		*(uint16_t *)(kbase + 0x2AFB47 + 4) = 0x9090;
		cpu_enable_wp();
	}

	else if (fw_version == 0x405) {
		kernel_ptr = (uint8_t*)kbase;
		*(void**)(&sceRegMgrSetInt) = &kernel_ptr[0x4CEAB0];

		//printfkernel("Done, now try reg...\n");

		sceRegMgrSetInt(recoverymode, 1);

		//printfkernel("NULL\n");
	}

	else if (fw_version == 0x455) {
		kernel_ptr = (uint8_t*)kbase;
		*(void**)(&sceRegMgrSetInt) = &kernel_ptr[0x4D6F00];

		//printfkernel("Done, now try reg...\n");

		sceRegMgrSetInt(recoverymode, 1);

		//printfkernel("NULL\n");
	}

	else if (fw_version == 0x501) {

		cpu_disable_wp();
		// spoofer
		*(uint32_t *)(kbase + 0x14A63F0) = 0x5550001;

		cpu_enable_wp();
	}
	else return -1;

	return 0;
}

int kills()
{
	int pid = syscall(20);
	int signum = 0;
	return syscall(37, pid, signum);
}

void *shutdowne(struct thread *td) {

	struct ucred* cred;
	struct filedesc* fd;
	uint64_t fw_version = 0x666;

	void* kbase = 0;
	uint8_t* kernel_ptr;
	void** got_prison0;
	void** got_rootvnode;

	//uint64_t *(sceRegMgrSetInt)(uint32_t regId, int value) = NULL;

	uint64_t(*sceRegMgrSetInt)(uint32_t regId, int value);

	fd = td->td_proc->p_fd;
	cred = td->td_proc->p_ucred;

	if (!memcmp((char*)(&((uint8_t*)__readmsr(0xC0000082))[-KERN_505_XFAST_SYSCALL]), (char[4]) { 0x7F, 0x45, 0x4C, 0x46 }, 4)) {

		kbase = &((uint8_t*)__readmsr(0xC0000082))[-KERN_505_XFAST_SYSCALL];


		fw_version = 0x505;

	}

	else if (!memcmp((char*)(&((uint8_t*)__readmsr(0xC0000082))[-KERN_455_XFAST_SYSCALL]), (char[4]) { 0x7F, 0x45, 0x4C, 0x46 }, 4)) {

		kbase = &((uint8_t*)__readmsr(0xC0000082))[-KERN_455_XFAST_SYSCALL];

		fw_version = 0x455;
	}

	else if (!memcmp((char*)(&((uint8_t*)__readmsr(0xC0000082))[-KERN_455_XFAST_SYSCALL]), (char[4]) { 0x7F, 0x45, 0x4C, 0x46 }, 4)) {

		kbase = &((uint8_t*)__readmsr(0xC0000082))[-KERN_455_XFAST_SYSCALL];

		fw_version = 0x455;

	}
	else if (!memcmp((char*)(&((uint8_t*)__readmsr(0xC0000082))[-KERN_405_XFAST_SYSCALL]), (char[4]) { 0x7F, 0x45, 0x4C, 0x46 }, 4)) {
		fw_version = 0x405;

	}
	else return -1;


	if (fw_version == 0x405) {


		// Kernel pointers resolving

		kernel_ptr = (uint8_t*)kbase;
		got_prison0 = (void**)&kernel_ptr[KERN_405_PRISON_0];
		got_rootvnode = (void**)&kernel_ptr[KERN_405_ROOTVNODE];

	}
	else if (fw_version == 0x455) {

		// Kernel pointers resolving

		kernel_ptr = (uint8_t*)kbase;
		got_prison0 = (void**)&kernel_ptr[KERN_455_PRISON_0];
		got_rootvnode = (void**)&kernel_ptr[KERN_455_ROOTVNODE];

	}
	else if (fw_version == 0x501) {

		// Kernel pointers resolving

		kernel_ptr = (uint8_t*)kbase;
		got_prison0 = (void**)&kernel_ptr[KERN_501_PRISON_0];
		got_rootvnode = (void**)&kernel_ptr[KERN_501_ROOTVNODE];

	}
	else if (fw_version == 0x505) {

		// Kernel pointers resolving

		kernel_ptr = (uint8_t*)kbase;
		got_prison0 = (void**)&kernel_ptr[KERN_505_PRISON_0];
		got_rootvnode = (void**)&kernel_ptr[KERN_505_ROOTVNODE];

	}
	else return -1;

	cred->cr_uid = 0;
	cred->cr_ruid = 0;
	cred->cr_rgid = 0;
	cred->cr_groups[0] = 0;
	cred->cr_prison = *got_prison0;
	fd->fd_rdir = fd->fd_jdir = *got_rootvnode;

	// Escalate ucred privs, needed for userland access to the filesystem e.g mounting & decrypting files

	void *td_ucred = *(void **)(((char *)td) + 304); // p_ucred == td_ucred

	uint64_t *sonyCred = (uint64_t *)(((char *)td_ucred) + 96);
	*sonyCred = 0xffffffffffffffff;

	// sceSblACMgrGetDeviceAccessType

	uint64_t *sceProcessAuthorityId = (uint64_t *)(((char *)td_ucred) + 88);
	*sceProcessAuthorityId = 0x3800000000000010; // SceShellcore paid
												 // sceSblACMgrHasSceProcessCapability

	uint64_t *sceProcCap = (uint64_t *)(((char *)td_ucred) + 104);
	*sceProcCap = 0xffffffffffffffff; // Max capability

	return 0;

}


void *spooftestkit(struct thread *td) {

	void* kbase = 0;
	uint64_t fw_version = 0x666;

	if (!memcmp((char*)(&((uint8_t*)__readmsr(0xC0000082))[-KERN_505_XFAST_SYSCALL]), (char[4]) { 0x7F, 0x45, 0x4C, 0x46 }, 4)) {

		kbase = &((uint8_t*)__readmsr(0xC0000082))[-KERN_505_XFAST_SYSCALL];


		fw_version = 0x505;

	}

	else if (!memcmp((char*)(&((uint8_t*)__readmsr(0xC0000082))[-KERN_455_XFAST_SYSCALL]), (char[4]) { 0x7F, 0x45, 0x4C, 0x46 }, 4)) {

		kbase = &((uint8_t*)__readmsr(0xC0000082))[-KERN_455_XFAST_SYSCALL];

		fw_version = 0x455;
	}

	else if (!memcmp((char*)(&((uint8_t*)__readmsr(0xC0000082))[-KERN_455_XFAST_SYSCALL]), (char[4]) { 0x7F, 0x45, 0x4C, 0x46 }, 4)) {

		kbase = &((uint8_t*)__readmsr(0xC0000082))[-KERN_455_XFAST_SYSCALL];

		fw_version = 0x455;

	}
	else if (!memcmp((char*)(&((uint8_t*)__readmsr(0xC0000082))[-KERN_405_XFAST_SYSCALL]), (char[4]) { 0x7F, 0x45, 0x4C, 0x46 }, 4)) {
		fw_version = 0x405;

	}
	else return -1;

	if (fw_version == 0x505) {

		int(*printfkernel)(const char *fmt, ...) = (void *)(kbase + 0x436040);
		printfkernel("FW Version 5.05 Detected\n");
	}

	else if (fw_version == 0x405) {

		int(*printfkernel)(const char *fmt, ...) = (void *)(kbase + KERN_405_PRINTF);
		printfkernel("FW Version 4.05 Detected\n");

	}
	else if (fw_version == 0x455) {

		int(*printfkernel)(const char *fmt, ...) = (void *)(kbase + KERN_455_PRINTF);
		printfkernel("FW Version 4.55 Detected\n");

	}
	else if (fw_version == 0x501) {

		int(*printfkernel)(const char *fmt, ...) = (void *)(kbase + KERN_501_PRINTF);
		printfkernel("FW Version 5.05 Detected\n");
	}
	else return -1;



	if (fw_version == 0x505) {


		cpu_disable_wp();
		// Allow sys_dynlib_dlsym in all processes.
		*(uint16_t *)(kbase + 0x237F3B) = 0x01C1;
		//*(uint16_t *)(kbase + 0x237F3B) = 0x101C;

		// Don't restrict dynlib information.
		*(uint64_t *)(kbase + 0x2B2620) = 0x9090909090C3C031;

		// Allow usage of mangled symbols in dynlib_do_dlsym().
		*(uint16_t *)(kbase + 0x2AFB47) = 0x9090;
		*(uint16_t *)(kbase + 0x2AFB47 + 2) = 0x9090;
		*(uint16_t *)(kbase + 0x2AFB47 + 4) = 0x9090;
		*(uint16_t *)(kbase + __target_id_0) = 0x8201;
		*(uint16_t *)(kbase + __target_id_1) = 0x8201;

		cpu_enable_wp();
	}

	else if (fw_version == 0x405) {


		cpu_disable_wp();
		*(uint16_t *)(kbase + 0x1FE59E4) = 0x8201;
		*(uint16_t *)(kbase + 0X1FE5A2C) = 0x8201;
		*(uint16_t *)(kbase + 0x200151C) = 0x8201;

		cpu_enable_wp();
	}

	else if (fw_version == 0x455) {

		cpu_disable_wp();
		*(uint16_t *)(kbase + 0x1AF82C4) = 0x8201;
		*(uint16_t *)(kbase + 0X1AF85A4) = 0x8201;
		*(uint16_t *)(kbase + 0x1B6D08C) = 0x8201;

		cpu_enable_wp();
	}

	else if (fw_version == 0x501) {

		cpu_disable_wp();
		// spoofer
		*(uint32_t *)(kbase + 0x14A63F0) = 0x5550001;

		cpu_enable_wp();
	}
	else return -1;

	return 0;
}

void *spoofretail(struct thread *td) {


	void* kbase = 0;
	uint64_t fw_version = 0x666;

	if (!memcmp((char*)(&((uint8_t*)__readmsr(0xC0000082))[-KERN_505_XFAST_SYSCALL]), (char[4]) { 0x7F, 0x45, 0x4C, 0x46 }, 4)) {

		kbase = &((uint8_t*)__readmsr(0xC0000082))[-KERN_505_XFAST_SYSCALL];


		fw_version = 0x505;

	}

	else if (!memcmp((char*)(&((uint8_t*)__readmsr(0xC0000082))[-KERN_455_XFAST_SYSCALL]), (char[4]) { 0x7F, 0x45, 0x4C, 0x46 }, 4)) {

		kbase = &((uint8_t*)__readmsr(0xC0000082))[-KERN_455_XFAST_SYSCALL];

		fw_version = 0x455;
	}

	else if (!memcmp((char*)(&((uint8_t*)__readmsr(0xC0000082))[-KERN_455_XFAST_SYSCALL]), (char[4]) { 0x7F, 0x45, 0x4C, 0x46 }, 4)) {

		kbase = &((uint8_t*)__readmsr(0xC0000082))[-KERN_455_XFAST_SYSCALL];

		fw_version = 0x455;

	}
	else if (!memcmp((char*)(&((uint8_t*)__readmsr(0xC0000082))[-KERN_405_XFAST_SYSCALL]), (char[4]) { 0x7F, 0x45, 0x4C, 0x46 }, 4)) {
		fw_version = 0x405;

	}
	else return -1;

	if (fw_version == 0x505) {

		int(*printfkernel)(const char *fmt, ...) = (void *)(kbase + 0x436040);
		printfkernel("FW Version 5.05 Detected\n");
	}

	else if (fw_version == 0x405) {

		int(*printfkernel)(const char *fmt, ...) = (void *)(kbase + KERN_405_PRINTF);
		printfkernel("FW Version 4.05 Detected\n");

	}
	else if (fw_version == 0x455) {

		int(*printfkernel)(const char *fmt, ...) = (void *)(kbase + KERN_455_PRINTF);
		printfkernel("FW Version 4.55 Detected\n");

	}
	else if (fw_version == 0x501) {

		int(*printfkernel)(const char *fmt, ...) = (void *)(kbase + KERN_501_PRINTF);
		printfkernel("FW Version 5.05 Detected\n");
	}
	else return -1;



	if (fw_version == 0x505) {


		cpu_disable_wp();
		// Allow sys_dynlib_dlsym in all processes.
		*(uint16_t *)(kbase + 0x237F3B) = 0x01C1;
		//*(uint16_t *)(kbase + 0x237F3B) = 0x101C;

		// Don't restrict dynlib information.
		*(uint64_t *)(kbase + 0x2B2620) = 0x9090909090C3C031;

		// Allow usage of mangled symbols in dynlib_do_dlsym().
		*(uint16_t *)(kbase + 0x2AFB47) = 0x9090;
		*(uint16_t *)(kbase + 0x2AFB47 + 2) = 0x9090;
		*(uint16_t *)(kbase + 0x2AFB47 + 4) = 0x9090;
		*(uint16_t *)(kbase + __target_id_0) = 0x8301;
		*(uint16_t *)(kbase + __target_id_1) = 0x8301;

		cpu_enable_wp();
	}

	else if (fw_version == 0x405) {


		cpu_disable_wp();
		*(uint16_t *)(kbase + 0x1FE59E4) = 0x8301;
		*(uint16_t *)(kbase + 0X1FE5A2C) = 0x8301;
		*(uint16_t *)(kbase + 0x200151C) = 0x8301;

		cpu_enable_wp();
	}

	else if (fw_version == 0x455) {

		cpu_disable_wp();
		*(uint16_t *)(kbase + 0x1AF82C4) = 0x8301;
		*(uint16_t *)(kbase + 0X1AF85A4) = 0x8301;
		*(uint16_t *)(kbase + 0x1B6D08C) = 0x8301;

		cpu_enable_wp();
	}

	else if (fw_version == 0x501) {

		cpu_disable_wp();
		// spoofer
		*(uint32_t *)(kbase + 0x14A63F0) = 0x5550001;

		cpu_enable_wp();
	}
	else return -1;

	return 0;
}

int note()
{

	//int64_t moduleId = sys_dynlib_load_prx("libSceSysUtil.sprx");
	int(*sceSysUtilSendSystemNotificationWithText)(int messageType, char* message) = 0;

	sys_dynlib_dlsym("libSceSysUtil.sprx", "sceSysUtilSendSystemNotificationWithText", &sceSysUtilSendSystemNotificationWithText);
	char* initMessage = "Mira Project Loaded\nRPC Server Port: 9999\nkLog Server Port: 9998\n";
	sceSysUtilSendSystemNotificationWithText(36, initMessage);

	return 0;
}

void *spoofone(struct thread *td) {

	void* kbase = 0;
	uint64_t fw_version = 0x666;

	if (!memcmp((char*)(&((uint8_t*)__readmsr(0xC0000082))[-KERN_505_XFAST_SYSCALL]), (char[4]) { 0x7F, 0x45, 0x4C, 0x46 }, 4)) {

		kbase = &((uint8_t*)__readmsr(0xC0000082))[-KERN_505_XFAST_SYSCALL];


		fw_version = 0x505;

	}

	else if (!memcmp((char*)(&((uint8_t*)__readmsr(0xC0000082))[-KERN_455_XFAST_SYSCALL]), (char[4]) { 0x7F, 0x45, 0x4C, 0x46 }, 4)) {

		kbase = &((uint8_t*)__readmsr(0xC0000082))[-KERN_455_XFAST_SYSCALL];

		fw_version = 0x455;
	}

	else if (!memcmp((char*)(&((uint8_t*)__readmsr(0xC0000082))[-KERN_455_XFAST_SYSCALL]), (char[4]) { 0x7F, 0x45, 0x4C, 0x46 }, 4)) {

		kbase = &((uint8_t*)__readmsr(0xC0000082))[-KERN_455_XFAST_SYSCALL];

		fw_version = 0x455;

	}
	else if (!memcmp((char*)(&((uint8_t*)__readmsr(0xC0000082))[-KERN_405_XFAST_SYSCALL]), (char[4]) { 0x7F, 0x45, 0x4C, 0x46 }, 4)) {
		fw_version = 0x405;

	}
	else return -1;

	if (fw_version == 0x505) {

		int(*printfkernel)(const char *fmt, ...) = (void *)(kbase + 0x436040);
		printfkernel("FW Version 5.05 Detected\n");
	}

	else if (fw_version == 0x405) {

		int(*printfkernel)(const char *fmt, ...) = (void *)(kbase + KERN_405_PRINTF);
		printfkernel("FW Version 4.05 Detected\n");

	}
	else if (fw_version == 0x455) {

		int(*printfkernel)(const char *fmt, ...) = (void *)(kbase + KERN_455_PRINTF);
		printfkernel("FW Version 4.55 Detected\n");

	}
	else if (fw_version == 0x501) {

		int(*printfkernel)(const char *fmt, ...) = (void *)(kbase + KERN_501_PRINTF);
		printfkernel("FW Version 5.05 Detected\n");
	}
	else return -1;



	if (fw_version == 0x505) {


		cpu_disable_wp();
		// Allow sys_dynlib_dlsym in all processes.
		*(uint16_t *)(kbase + 0x237F3B) = 0x01C1;
		//*(uint16_t *)(kbase + 0x237F3B) = 0x101C;

		// Don't restrict dynlib information.
		*(uint64_t *)(kbase + 0x2B2620) = 0x9090909090C3C031;

		// Allow usage of mangled symbols in dynlib_do_dlsym().
		*(uint16_t *)(kbase + 0x2AFB47) = 0x9090;
		*(uint16_t *)(kbase + 0x2AFB47 + 2) = 0x9090;
		*(uint16_t *)(kbase + 0x2AFB47 + 4) = 0x9090;
		// spoofer
		*(uint32_t *)(kbase + 0x14A63F0) = 0x5050001;

		cpu_enable_wp();
	}

	else if (fw_version == 0x405) {


		cpu_disable_wp();
		// spoofer
		*(uint32_t *)(kbase + 0x1344618) = 0x5050001;

		cpu_enable_wp();
	}

	else if (fw_version == 0x455) {

		cpu_disable_wp();
		// spoofer
		*(uint32_t *)(kbase + 0x144B600) = 0x4550001;

		cpu_enable_wp();
	}

	else if (fw_version == 0x501) {

		cpu_disable_wp();
		// spoofer
		*(uint32_t *)(kbase + 0x14A63F0) = 0x5010001;

		cpu_enable_wp();
	}
	else return -1;

	return 0;
}

void *spooftwo(struct thread *td) {
	void* kbase = 0;
	uint64_t fw_version = 0x666;

	if (!memcmp((char*)(&((uint8_t*)__readmsr(0xC0000082))[-KERN_505_XFAST_SYSCALL]), (char[4]) { 0x7F, 0x45, 0x4C, 0x46 }, 4)) {

		kbase = &((uint8_t*)__readmsr(0xC0000082))[-KERN_505_XFAST_SYSCALL];


		fw_version = 0x505;

	}

	else if (!memcmp((char*)(&((uint8_t*)__readmsr(0xC0000082))[-KERN_455_XFAST_SYSCALL]), (char[4]) { 0x7F, 0x45, 0x4C, 0x46 }, 4)) {

		kbase = &((uint8_t*)__readmsr(0xC0000082))[-KERN_455_XFAST_SYSCALL];

		fw_version = 0x455;
	}

	else if (!memcmp((char*)(&((uint8_t*)__readmsr(0xC0000082))[-KERN_455_XFAST_SYSCALL]), (char[4]) { 0x7F, 0x45, 0x4C, 0x46 }, 4)) {

		kbase = &((uint8_t*)__readmsr(0xC0000082))[-KERN_455_XFAST_SYSCALL];

		fw_version = 0x455;

	}
	else if (!memcmp((char*)(&((uint8_t*)__readmsr(0xC0000082))[-KERN_405_XFAST_SYSCALL]), (char[4]) { 0x7F, 0x45, 0x4C, 0x46 }, 4)) {
		fw_version = 0x405;

	}
	else return -1;

	if (fw_version == 0x505) {

		int(*printfkernel)(const char *fmt, ...) = (void *)(kbase + 0x436040);
		printfkernel("FW Version 5.05 Detected\n");
	}

	else if (fw_version == 0x405) {

		int(*printfkernel)(const char *fmt, ...) = (void *)(kbase + KERN_405_PRINTF);
		printfkernel("FW Version 4.05 Detected\n");

	}
	else if (fw_version == 0x455) {

		int(*printfkernel)(const char *fmt, ...) = (void *)(kbase + KERN_455_PRINTF);
		printfkernel("FW Version 4.55 Detected\n");

	}
	else if (fw_version == 0x501) {

		int(*printfkernel)(const char *fmt, ...) = (void *)(kbase + KERN_501_PRINTF);
		printfkernel("FW Version 5.05 Detected\n");
	}
	else return -1;



	if (fw_version == 0x505) {


		cpu_disable_wp();
		// Allow sys_dynlib_dlsym in all processes.
		*(uint16_t *)(kbase + 0x237F3B) = 0x01C1;
		//*(uint16_t *)(kbase + 0x237F3B) = 0x101C;

		// Don't restrict dynlib information.
		*(uint64_t *)(kbase + 0x2B2620) = 0x9090909090C3C031;

		// Allow usage of mangled symbols in dynlib_do_dlsym().
		*(uint16_t *)(kbase + 0x2AFB47) = 0x9090;
		*(uint16_t *)(kbase + 0x2AFB47 + 2) = 0x9090;
		*(uint16_t *)(kbase + 0x2AFB47 + 4) = 0x9090;
		// spoofer
		*(uint32_t *)(kbase + 0x14A63F0) = 0x5550001;

		cpu_enable_wp();
	}

	else if (fw_version == 0x405) {


		cpu_disable_wp();
		// spoofer
		*(uint32_t *)(kbase + 0x1344618) = 0x5550001;

		cpu_enable_wp();
	}

	else if (fw_version == 0x455) {

		cpu_disable_wp();
		// spoofer
		*(uint32_t *)(kbase + 0x144B600) = 0x5550001;

		cpu_enable_wp();
	}

	else if (fw_version == 0x501) {

		cpu_disable_wp();
		// spoofer
		*(uint32_t *)(kbase + 0x14A63F0) = 0x5550001;

		cpu_enable_wp();
	}
	else return -1;

	return 0;
}

void *spoofthere(struct thread *td) {
	void* kbase = 0;
	uint64_t fw_version = 0x666;

	if (!memcmp((char*)(&((uint8_t*)__readmsr(0xC0000082))[-KERN_505_XFAST_SYSCALL]), (char[4]) { 0x7F, 0x45, 0x4C, 0x46 }, 4)) {

		kbase = &((uint8_t*)__readmsr(0xC0000082))[-KERN_505_XFAST_SYSCALL];


		fw_version = 0x505;

	}

	else if (!memcmp((char*)(&((uint8_t*)__readmsr(0xC0000082))[-KERN_455_XFAST_SYSCALL]), (char[4]) { 0x7F, 0x45, 0x4C, 0x46 }, 4)) {

		kbase = &((uint8_t*)__readmsr(0xC0000082))[-KERN_455_XFAST_SYSCALL];

		fw_version = 0x455;
	}

	else if (!memcmp((char*)(&((uint8_t*)__readmsr(0xC0000082))[-KERN_455_XFAST_SYSCALL]), (char[4]) { 0x7F, 0x45, 0x4C, 0x46 }, 4)) {

		kbase = &((uint8_t*)__readmsr(0xC0000082))[-KERN_455_XFAST_SYSCALL];

		fw_version = 0x455;

	}
	else if (!memcmp((char*)(&((uint8_t*)__readmsr(0xC0000082))[-KERN_405_XFAST_SYSCALL]), (char[4]) { 0x7F, 0x45, 0x4C, 0x46 }, 4)) {
		fw_version = 0x405;

	}
	else return -1;

	if (fw_version == 0x505) {

		int(*printfkernel)(const char *fmt, ...) = (void *)(kbase + 0x436040);
		printfkernel("FW Version 5.05 Detected\n");
	}

	else if (fw_version == 0x405) {

		int(*printfkernel)(const char *fmt, ...) = (void *)(kbase + KERN_405_PRINTF);
		printfkernel("FW Version 4.05 Detected\n");

	}
	else if (fw_version == 0x455) {

		int(*printfkernel)(const char *fmt, ...) = (void *)(kbase + KERN_455_PRINTF);
		printfkernel("FW Version 4.55 Detected\n");

	}
	else if (fw_version == 0x501) {

		int(*printfkernel)(const char *fmt, ...) = (void *)(kbase + KERN_501_PRINTF);
		printfkernel("FW Version 5.05 Detected\n");
	}
	else return -1;



	if (fw_version == 0x505) {


		cpu_disable_wp();
		// Allow sys_dynlib_dlsym in all processes.
		*(uint16_t *)(kbase + 0x237F3B) = 0x01C1;
		//*(uint16_t *)(kbase + 0x237F3B) = 0x101C;

		// Don't restrict dynlib information.
		*(uint64_t *)(kbase + 0x2B2620) = 0x9090909090C3C031;

		// Allow usage of mangled symbols in dynlib_do_dlsym().
		*(uint16_t *)(kbase + 0x2AFB47) = 0x9090;
		*(uint16_t *)(kbase + 0x2AFB47 + 2) = 0x9090;
		*(uint16_t *)(kbase + 0x2AFB47 + 4) = 0x9090;
		// spoofer
		*(uint32_t *)(kbase + 0x14A63F0) = 0x5550001;

		cpu_enable_wp();
	}

	else if (fw_version == 0x405) {


		cpu_disable_wp();
		// spoofer
		*(uint32_t *)(kbase + 0x1344618) = 0x9990001;

		cpu_enable_wp();
	}

	else if (fw_version == 0x455) {

		cpu_disable_wp();
		// spoofer
		*(uint32_t *)(kbase + 0x144B600) = 0x9990001;

		cpu_enable_wp();
	}

	else if (fw_version == 0x501) {

		cpu_disable_wp();
		// spoofer
		*(uint32_t *)(kbase + 0x14A63F0) = 0x9990001;

		cpu_enable_wp();
	}
	else return -1;

	return 0;
}

void *uartoff(struct thread *td) {
	void* kbase = 0;
	uint64_t fw_version = 0x666;

	if (!memcmp((char*)(&((uint8_t*)__readmsr(0xC0000082))[-KERN_505_XFAST_SYSCALL]), (char[4]) { 0x7F, 0x45, 0x4C, 0x46 }, 4)) {

		kbase = &((uint8_t*)__readmsr(0xC0000082))[-KERN_505_XFAST_SYSCALL];


		fw_version = 0x505;

	}

	else if (!memcmp((char*)(&((uint8_t*)__readmsr(0xC0000082))[-KERN_455_XFAST_SYSCALL]), (char[4]) { 0x7F, 0x45, 0x4C, 0x46 }, 4)) {

		kbase = &((uint8_t*)__readmsr(0xC0000082))[-KERN_455_XFAST_SYSCALL];

		fw_version = 0x455;
	}

	else if (!memcmp((char*)(&((uint8_t*)__readmsr(0xC0000082))[-KERN_455_XFAST_SYSCALL]), (char[4]) { 0x7F, 0x45, 0x4C, 0x46 }, 4)) {

		kbase = &((uint8_t*)__readmsr(0xC0000082))[-KERN_455_XFAST_SYSCALL];

		fw_version = 0x455;

	}
	else if (!memcmp((char*)(&((uint8_t*)__readmsr(0xC0000082))[-KERN_405_XFAST_SYSCALL]), (char[4]) { 0x7F, 0x45, 0x4C, 0x46 }, 4)) {
		fw_version = 0x405;

	}
	else return -1;

	if (fw_version == 0x505) {

		int(*printfkernel)(const char *fmt, ...) = (void *)(kbase + 0x436040);
		printfkernel("FW Version 5.05 Detected\n");
	}

	else if (fw_version == 0x405) {

		int(*printfkernel)(const char *fmt, ...) = (void *)(kbase + KERN_405_PRINTF);
		printfkernel("FW Version 4.05 Detected\n");

	}
	else if (fw_version == 0x455) {

		int(*printfkernel)(const char *fmt, ...) = (void *)(kbase + KERN_455_PRINTF);
		printfkernel("FW Version 4.55 Detected\n");

	}
	else if (fw_version == 0x501) {

		int(*printfkernel)(const char *fmt, ...) = (void *)(kbase + KERN_501_PRINTF);
		printfkernel("FW Version 5.05 Detected\n");
	}
	else return -1;



	if (fw_version == 0x505) {


		cpu_disable_wp();
		// Allow sys_dynlib_dlsym in all processes.
		*(uint16_t *)(kbase + 0x237F3B) = 0x01C1;
		//*(uint16_t *)(kbase + 0x237F3B) = 0x101C;

		// Don't restrict dynlib information.
		*(uint64_t *)(kbase + 0x2B2620) = 0x9090909090C3C031;

		// Allow usage of mangled symbols in dynlib_do_dlsym().
		*(uint16_t *)(kbase + 0x2AFB47) = 0x9090;
		*(uint16_t *)(kbase + 0x2AFB47 + 2) = 0x9090;
		*(uint16_t *)(kbase + 0x2AFB47 + 4) = 0x9090;
		// spoofer
		*(uint32_t *)(kbase + 0x19ECEB0) = 1;

		cpu_enable_wp();
	}

	else if (fw_version == 0x405) {


		cpu_disable_wp();
		*(char *)(kbase + 0x186b0a0) = 1;

		cpu_enable_wp();
	}

	else if (fw_version == 0x455) {

		cpu_disable_wp();
		*(char *)(kbase + 0x1997BC8) = 1;

		cpu_enable_wp();
	}

	else if (fw_version == 0x501) {

		cpu_disable_wp();
		// spoofer
		*(uint32_t *)(kbase + 0x14A63F0) = 0x5550001;

		cpu_enable_wp();
	}
	else return -1;

	return 0;
}

void *uarton(struct thread *td) {
	void* kbase = 0;
	uint64_t fw_version = 0x666;

	if (!memcmp((char*)(&((uint8_t*)__readmsr(0xC0000082))[-KERN_505_XFAST_SYSCALL]), (char[4]) { 0x7F, 0x45, 0x4C, 0x46 }, 4)) {

		kbase = &((uint8_t*)__readmsr(0xC0000082))[-KERN_505_XFAST_SYSCALL];


		fw_version = 0x505;

	}

	else if (!memcmp((char*)(&((uint8_t*)__readmsr(0xC0000082))[-KERN_455_XFAST_SYSCALL]), (char[4]) { 0x7F, 0x45, 0x4C, 0x46 }, 4)) {

		kbase = &((uint8_t*)__readmsr(0xC0000082))[-KERN_455_XFAST_SYSCALL];

		fw_version = 0x455;
	}

	else if (!memcmp((char*)(&((uint8_t*)__readmsr(0xC0000082))[-KERN_455_XFAST_SYSCALL]), (char[4]) { 0x7F, 0x45, 0x4C, 0x46 }, 4)) {

		kbase = &((uint8_t*)__readmsr(0xC0000082))[-KERN_455_XFAST_SYSCALL];

		fw_version = 0x455;

	}
	else if (!memcmp((char*)(&((uint8_t*)__readmsr(0xC0000082))[-KERN_405_XFAST_SYSCALL]), (char[4]) { 0x7F, 0x45, 0x4C, 0x46 }, 4)) {
		fw_version = 0x405;

	}
	else return -1;

	if (fw_version == 0x505) {

		int(*printfkernel)(const char *fmt, ...) = (void *)(kbase + 0x436040);
		printfkernel("FW Version 5.05 Detected\n");
	}

	else if (fw_version == 0x405) {

		int(*printfkernel)(const char *fmt, ...) = (void *)(kbase + KERN_405_PRINTF);
		printfkernel("FW Version 4.05 Detected\n");

	}
	else if (fw_version == 0x455) {

		int(*printfkernel)(const char *fmt, ...) = (void *)(kbase + KERN_455_PRINTF);
		printfkernel("FW Version 4.55 Detected\n");

	}
	else if (fw_version == 0x501) {

		int(*printfkernel)(const char *fmt, ...) = (void *)(kbase + KERN_501_PRINTF);
		printfkernel("FW Version 5.05 Detected\n");
	}
	else return -1;



	if (fw_version == 0x505) {


		cpu_disable_wp();
		// Allow sys_dynlib_dlsym in all processes.
		*(uint16_t *)(kbase + 0x237F3B) = 0x01C1;
		//*(uint16_t *)(kbase + 0x237F3B) = 0x101C;

		// Don't restrict dynlib information.
		*(uint64_t *)(kbase + 0x2B2620) = 0x9090909090C3C031;

		// Allow usage of mangled symbols in dynlib_do_dlsym().
		*(uint16_t *)(kbase + 0x2AFB47) = 0x9090;
		*(uint16_t *)(kbase + 0x2AFB47 + 2) = 0x9090;
		*(uint16_t *)(kbase + 0x2AFB47 + 4) = 0x9090;
		// spoofer
		*(uint32_t *)(kbase + 0x19ECEB0) = 0;

		cpu_enable_wp();
	}

	else if (fw_version == 0x405) {


		cpu_disable_wp();
		*(char *)(kbase + 0x186b0a0) = 0;

		cpu_enable_wp();
	}

	else if (fw_version == 0x455) {

		cpu_disable_wp();
		*(char *)(kbase + 0x1997BC8) = 0;

		cpu_enable_wp();
	}

	else if (fw_version == 0x501) {

		cpu_disable_wp();


		cpu_enable_wp();
	}
	else return -1;

	return 0;
}

void *mmapp(struct thread *td) {
	uint8_t mmap_self[11];
	struct ucred* cred;
	struct filedesc* fd;

	fd = td->td_proc->p_fd;
	cred = td->td_proc->p_ucred;

	void* kbase = &((uint8_t*)__readmsr(0xC0000082))[-KERN_XFAST_SYSCALL];
	uint8_t* kernel_ptr = (uint8_t*)kbase;
	void** got_prison0 = (void**)&kernel_ptr[KERN_PRISON_0];
	void** got_rootvnode = (void**)&kernel_ptr[KERN_ROOTVNODE];

	cred->cr_uid = 0;
	cred->cr_ruid = 0;
	cred->cr_rgid = 0;
	cred->cr_groups[0] = 0;

	cred->cr_prison = *got_prison0;
	fd->fd_rdir = fd->fd_jdir = *got_rootvnode;

	// escalate ucred privs, needed for access to the filesystem ie* mounting & decrypting files
	void *td_ucred = *(void **)(((char *)td) + 304); // p_ucred == td_ucred

													 // sceSblACMgrIsSystemUcred
	uint64_t *sonyCred = (uint64_t *)(((char *)td_ucred) + 96);
	*sonyCred = 0xffffffffffffffff;

	// sceSblACMgrGetDeviceAccessType
	uint64_t *sceProcType = (uint64_t *)(((char *)td_ucred) + 88);
	*sceProcType = 0x3801000000000013; // Max access

									   // sceSblACMgrHasSceProcessCapability
	uint64_t *sceProcCap = (uint64_t *)(((char *)td_ucred) + 104);
	*sceProcCap = 0xffffffffffffffff; // Sce Process

									  // Disable write protection

	int(*printfkernel)(const char *fmt, ...) = (void *)(kbase + 0x436040);


	cpu_disable_wp();
	printfkernel("Attempting Proccess MMAP Patches\n");
	printfkernel("Attempting ASLR\n");
	//Process ASLR
	*(uint16_t*)(kbase + 0x194875) = 0x9090;
	printfkernel("Porccess ASLR Successful\n");
	printfkernel("Attempting kmem_alloc\n");
	//kmem_alloc to map RWX
	*(uint16_t*)(kbase + 0xFCD48) = 0x7;
	printfkernel("kmem_alloc Successful\n");
	printfkernel("Attempting debug dlsym\n");
	//debug dlsym
	*(uint16_t*)(kbase + 0x237E95) = 0x50;
	printfkernel("debug dlsym Successful\n");
	*(uint8_t*)(kbase + 0x117B0) = 0xB0;
	*(uint8_t*)(kbase + 0x117B1) = 0x01;
	*(uint8_t*)(kbase + 0x117B2) = 0xC3;

	*(uint8_t*)(kbase + 0x117C0) = 0xB0;
	*(uint8_t*)(kbase + 0x117C1) = 0x01;
	*(uint8_t*)(kbase + 0x117C2) = 0xC3;

	*(uint8_t*)(kbase + 0x13F03F) = 0x31;
	*(uint8_t*)(kbase + 0x13F040) = 0xC0;
	*(uint8_t*)(kbase + 0x13F041) = 0x90;
	*(uint8_t*)(kbase + 0x13F042) = 0x90;
	*(uint8_t*)(kbase + 0x13F043) = 0x90;

	printfkernel("MMAP SuccessfulL\n");

	cpu_enable_wp();

	return 0;
}

//void mmappw() {

//decrypt_and_dump_self("/system/vsh/SceShellCore.elf", "/mnt/usb0/");

//}


void *testmenu(struct thread *td) {
	uint8_t mmap_self[11];
	uint8_t* ptrKernel = get_kptr();
	struct ucred* cred;
	struct filedesc* fd;

	fd = td->td_proc->p_fd;
	cred = td->td_proc->p_ucred;

	void* kbase = &((uint8_t*)__readmsr(0xC0000082))[-KERN_XFAST_SYSCALL];
	uint8_t* kernel_ptr = (uint8_t*)kbase;
	void** got_prison0 = (void**)&kernel_ptr[KERN_PRISON_0];
	void** got_rootvnode = (void**)&kernel_ptr[KERN_ROOTVNODE];

	cred->cr_uid = 0;
	cred->cr_ruid = 0;
	cred->cr_rgid = 0;
	cred->cr_groups[0] = 0;

	cred->cr_prison = *got_prison0;
	fd->fd_rdir = fd->fd_jdir = *got_rootvnode;

	// escalate ucred privs, needed for access to the filesystem ie* mounting & decrypting files
	void *td_ucred = *(void **)(((char *)td) + 304); // p_ucred == td_ucred

													 // sceSblACMgrIsSystemUcred
	uint64_t *sonyCred = (uint64_t *)(((char *)td_ucred) + 96);
	*sonyCred = 0xffffffffffffffff;

	// sceSblACMgrGetDeviceAccessType
	uint64_t *sceProcType = (uint64_t *)(((char *)td_ucred) + 88);
	*sceProcType = 0x3801000000000013; // Max access

									   // sceSblACMgrHasSceProcessCapability
	uint64_t *sceProcCap = (uint64_t *)(((char *)td_ucred) + 104);
	*sceProcCap = 0xffffffffffffffff; // Sce Process

									  // Disable write protection

	int(*printfkernel)(const char *fmt, ...) = (void *)(kbase + 0x436040);



	cpu_disable_wp();
	printfkernel("Attempting Proccess MMAP Patches\n");
	// allow kmem_alloc to map rwx

	*(uint8_t*)(kbase + 0x117B0) = 0xB0;
	*(uint8_t*)(kbase + 0x117B1) = 0x01;
	*(uint8_t*)(kbase + 0x117B2) = 0xC3;

	*(uint8_t*)(kbase + 0x117C0) = 0xB0;
	*(uint8_t*)(kbase + 0x117C1) = 0x01;
	*(uint8_t*)(kbase + 0x117C2) = 0xC3;

	*(uint8_t*)(kbase + 0x13EF2F) = 0x31;
	*(uint8_t*)(kbase + 0x13EF30) = 0xC0;
	*(uint8_t*)(kbase + 0x13EF31) = 0x90;
	*(uint8_t*)(kbase + 0x13EF32) = 0x90;
	*(uint8_t*)(kbase + 0x13EF33) = 0x90;

	printfkernel("MMAP SuccessfulL\n");

	cpu_enable_wp();


	return 0;
}

int _main(struct thread *td)
{

	return 0;
}

int dumps()
{
	//crypt_and_dump_self("/mini-syscore.elf", "/update");
}

int spoofdevkitnote()
{

	int moduleId = -1;
	sys_dynlib_load_prx("libSceSysUtil.sprx", &moduleId);

	// This header doesn't work in > 5.00
	int(*sceSysUtilSendSystemNotificationWithText)(int messageType, char* message) = NULL;

	sys_dynlib_dlsym(moduleId, "sceSysUtilSendSystemNotificationWithText", &sceSysUtilSendSystemNotificationWithText);

	char* initMessage = "Spoofed to Devkit";
	sceSysUtilSendSystemNotificationWithText(222, initMessage);

	sys_dynlib_unload_prx(moduleId);


	return 0;
}

int installnote()
{

	int moduleId = -1;
	sys_dynlib_load_prx("libSceSysUtil.sprx", &moduleId);

	// This header doesn't work in > 5.00
	int(*sceSysUtilSendSystemNotificationWithText)(int messageType, char* message) = NULL;

	sys_dynlib_dlsym(moduleId, "sceSysUtilSendSystemNotificationWithText", &sceSysUtilSendSystemNotificationWithText);

	char* initMessage = "Installed UB Lite";
	sceSysUtilSendSystemNotificationWithText(222, initMessage);

	sys_dynlib_unload_prx(moduleId);


	return 0;
}

int uninstallnote()
{

	int moduleId = -1;
	sys_dynlib_load_prx("libSceSysUtil.sprx", &moduleId);

	// This header doesn't work in > 5.00
	int(*sceSysUtilSendSystemNotificationWithText)(int messageType, char* message) = NULL;

	sys_dynlib_dlsym(moduleId, "sceSysUtilSendSystemNotificationWithText", &sceSysUtilSendSystemNotificationWithText);

	char* initMessage = "Uninstalled UB Lite";
	sceSysUtilSendSystemNotificationWithText(222, initMessage);

	sys_dynlib_unload_prx(moduleId);


	return 0;
}

int sflashdumpnote()
{

	int moduleId = -1;
	sys_dynlib_load_prx("libSceSysUtil.sprx", &moduleId);

	// This header doesn't work in > 5.00
	int(*sceSysUtilSendSystemNotificationWithText)(int messageType, char* message) = NULL;

	sys_dynlib_dlsym(moduleId, "sceSysUtilSendSystemNotificationWithText", &sceSysUtilSendSystemNotificationWithText);

	char* initMessage = "l";
	sceSysUtilSendSystemNotificationWithText(222, initMessage);

	sys_dynlib_unload_prx(moduleId);


	return 0;
}

int parentcontrolnote()
{

	//syscall(11, &spoofdevkit);

	int moduleId = -1;
	sys_dynlib_load_prx("libSceSysUtil.sprx", &moduleId);

	// This header doesn't work in > 5.00
	int(*sceSysUtilSendSystemNotificationWithText)(int messageType, char* message) = NULL;

	sys_dynlib_dlsym(moduleId, "sceSysUtilSendSystemNotificationWithText", &sceSysUtilSendSystemNotificationWithText);

	char* initMessage = "Parent Controls removed";
	sceSysUtilSendSystemNotificationWithText(222, initMessage);

	sys_dynlib_unload_prx(moduleId);

	//syscall1(55, 0);


	return 0;
}

int reboot()
{
	syscall1(55, 0);

	return 0;
}




int backupnote()
{

	//syscall(11, &spoofdevkit);

	int moduleId = -1;
	sys_dynlib_load_prx("libSceSysUtil.sprx", &moduleId);

	// This header doesn't work in > 5.00
	int(*sceSysUtilSendSystemNotificationWithText)(int messageType, char* message) = NULL;

	sys_dynlib_dlsym(moduleId, "sceSysUtilSendSystemNotificationWithText", &sceSysUtilSendSystemNotificationWithText);

	char* initMessage = "Backed Up!";
	sceSysUtilSendSystemNotificationWithText(222, initMessage);

	sys_dynlib_unload_prx(moduleId);


	return 0;
}

int restorednote()
{

	//syscall(11, &spoofdevkit);

	int moduleId = -1;
	sys_dynlib_load_prx("libSceSysUtil.sprx", &moduleId);

	// This header doesn't work in > 5.00
	int(*sceSysUtilSendSystemNotificationWithText)(int messageType, char* message) = NULL;

	sys_dynlib_dlsym(moduleId, "sceSysUtilSendSystemNotificationWithText", &sceSysUtilSendSystemNotificationWithText);

	char* initMessage = "Restored -- Power Off you PS4";
	sceSysUtilSendSystemNotificationWithText(222, initMessage);

	sys_dynlib_unload_prx(moduleId);


	return 0;
}


int spooftestkitnote()
{
	//syscall(11, &spooftestkit);

	int moduleId = -1;
	sys_dynlib_load_prx("libSceSysUtil.sprx", &moduleId);

	// This header doesn't work in > 5.00
	int(*sceSysUtilSendSystemNotificationWithText)(int messageType, char* message) = NULL;

	sys_dynlib_dlsym(moduleId, "sceSysUtilSendSystemNotificationWithText", &sceSysUtilSendSystemNotificationWithText);

	char* initMessage = "Spoofed to Testkit";
	sceSysUtilSendSystemNotificationWithText(222, initMessage);

	sys_dynlib_unload_prx(moduleId);



	return 0;
}

int spoofretailnote()
{

	//syscall(11, spoofretail);

	int moduleId = -1;

	sys_dynlib_load_prx("libSceSysUtil.sprx", &moduleId);

	// This header doesn't work in > 5.00
	int(*sceSysUtilSendSystemNotificationWithText)(int messageType, char* message) = NULL;

	sys_dynlib_dlsym(moduleId, "sceSysUtilSendSystemNotificationWithText", &sceSysUtilSendSystemNotificationWithText);

	char* initMessage = "Spoofed to Retail";
	sceSysUtilSendSystemNotificationWithText(222, initMessage);

	sys_dynlib_unload_prx(moduleId);


	return 0;
}


int spoofonenote()
{



	int moduleId = -1;
	sys_dynlib_load_prx("libSceSysUtil.sprx", &moduleId);

	// This header doesn't work in > 5.00
	int(*sceSysUtilSendSystemNotificationWithText)(int messageType, char* message) = NULL;

	sys_dynlib_dlsym(moduleId, "sceSysUtilSendSystemNotificationWithText", &sceSysUtilSendSystemNotificationWithText);

	char* initMessage = "Spoofed to 5.05";
	sceSysUtilSendSystemNotificationWithText(222, initMessage);

	sys_dynlib_unload_prx(moduleId);

	return 0;
}


int spooftwonote()
{
	//syscall(11, spooftwo);

	int moduleId = -1;
	sys_dynlib_load_prx("libSceSysUtil.sprx", &moduleId);

	// This header doesn't work in > 5.00
	int(*sceSysUtilSendSystemNotificationWithText)(int messageType, char* message) = NULL;

	sys_dynlib_dlsym(moduleId, "sceSysUtilSendSystemNotificationWithText", &sceSysUtilSendSystemNotificationWithText);

	char* initMessage = "Spoofed to 5.55";
	sceSysUtilSendSystemNotificationWithText(222, initMessage);

	sys_dynlib_unload_prx(moduleId);

	return 0;
}


int spooftherenote()
{

	//syscall(11, spoofthere);

	int moduleId = -1;
	sys_dynlib_load_prx("libSceSysUtil.sprx", &moduleId);

	// This header doesn't work in > 5.00
	int(*sceSysUtilSendSystemNotificationWithText)(int messageType, char* message) = NULL;

	sys_dynlib_dlsym(moduleId, "sceSysUtilSendSystemNotificationWithText", &sceSysUtilSendSystemNotificationWithText);

	char* initMessage = "Spoofed to 9.99";
	sceSysUtilSendSystemNotificationWithText(222, initMessage);

	sys_dynlib_unload_prx(moduleId);

	return 0;
}


int debugonnote()
{

	//syscall(11, debugon);

	int moduleId = -1;
	sys_dynlib_load_prx("libSceSysUtil.sprx", &moduleId);

	// This header doesn't work in > 5.00
	int(*sceSysUtilSendSystemNotificationWithText)(int messageType, char* message) = NULL;

	sys_dynlib_dlsym(moduleId, "sceSysUtilSendSystemNotificationWithText", &sceSysUtilSendSystemNotificationWithText);

	char* initMessage = "Debug On";
	sceSysUtilSendSystemNotificationWithText(222, initMessage);

	sys_dynlib_unload_prx(moduleId);

	return 0;
}


int uartonnote()
{
	//syscall(11, uarton);

	int moduleId = -1;
	sys_dynlib_load_prx("libSceSysUtil.sprx", &moduleId);

	// This header doesn't work in > 5.00
	int(*sceSysUtilSendSystemNotificationWithText)(int messageType, char* message) = NULL;

	sys_dynlib_dlsym(moduleId, "sceSysUtilSendSystemNotificationWithText", &sceSysUtilSendSystemNotificationWithText);

	char* initMessage = "UART Enabled";
	sceSysUtilSendSystemNotificationWithText(222, initMessage);

	sys_dynlib_unload_prx(moduleId);

	return 0;
}


int uartoffnote()
{
	//syscall(11, uartoff);
	int moduleId = -1;
	sys_dynlib_load_prx("libSceSysUtil.sprx", &moduleId);

	// This header doesn't work in > 5.00
	int(*sceSysUtilSendSystemNotificationWithText)(int messageType, char* message) = NULL;

	sys_dynlib_dlsym(moduleId, "sceSysUtilSendSystemNotificationWithText", &sceSysUtilSendSystemNotificationWithText);

	char* initMessage = "UART Disabled";
	sceSysUtilSendSystemNotificationWithText(222, initMessage);

	sys_dynlib_unload_prx(moduleId);

	return 0;
}

int kpayloads(struct thread *td, struct kpayload_args* args) {

	struct ucred* cred;
	struct filedesc* fd;

	void* kbase = 0;
	uint8_t* kernel_ptr;
	void** got_prison0;
	void** got_rootvnode;
	int(*copyout)(const void *kaddr, void *uaddr, size_t len) = 0;


	fd = td->td_proc->p_fd;
	cred = td->td_proc->p_ucred;

	uint64_t fw_version = 0x666;

	if (!memcmp((char*)(&((uint8_t*)__readmsr(0xC0000082))[-KERN_505_XFAST_SYSCALL]), (char[4]) { 0x7F, 0x45, 0x4C, 0x46 }, 4)) {

		kbase = &((uint8_t*)__readmsr(0xC0000082))[-KERN_505_XFAST_SYSCALL];
		fw_version = 0x505;
		copyout = (void *)(kbase + KERN_505_COPYOUT);
		
	 int (*icc_query)(void* msg_in, void* msg_out) = (void*)(kbase + 0x43540);  

    // Buzzer 


    char* message_beep = calloc(1, 0x7F0); 

    message_beep[0] = 0x0;  
    message_beep[1] = 0x9;  
    message_beep[2] = 0x0;  
    message_beep[3] = 0x0;  
    message_beep[4] = 0x0;  
    message_beep[5] = 0x0;  
    message_beep[6] = 0x0;  
    message_beep[7] = 0x0;  
    message_beep[8] = 0x0; 
    message_beep[9] = 0x20; 

    icc_query(message_beep, message_beep);
	}

	else if (!memcmp((char*)(&((uint8_t*)__readmsr(0xC0000082))[-KERN_455_XFAST_SYSCALL]), (char[4]) { 0x7F, 0x45, 0x4C, 0x46 }, 4)) {

		kbase = &((uint8_t*)__readmsr(0xC0000082))[-KERN_455_XFAST_SYSCALL];
		fw_version = 0x455;
		copyout = (void *)(kbase + KERN_455_COPYOUT);

	}


	else if (!memcmp((char*)(&((uint8_t*)__readmsr(0xC0000082))[-KERN_405_XFAST_SYSCALL]), (char[4]) { 0x7F, 0x45, 0x4C, 0x46 }, 4)) {
		fw_version = 0x405;
		//copyout = (void *)(kbase + KERN_405_COPYOUT);

	}
	else return -1;

	if (fw_version == 0x505) {

		int(*printfkernel)(const char *fmt, ...) = (void *)(kbase + 0x436040);
		printfkernel("FW Version 5.05 Detected\n");	// It always says this ... never did ...
	}

	else if (fw_version == 0x405) {

		int(*printfkernel)(const char *fmt, ...) = (void *)(kbase + KERN_405_PRINTF);
		printfkernel("FW Version 4.05 Detected\n");

	}
	else if (fw_version == 0x455) {

		int(*printfkernel)(const char *fmt, ...) = (void *)(kbase + KERN_455_PRINTF);
		printfkernel("FW Version 4.55 Detected\n");

	}
	else if (fw_version == 0x501) {

		int(*printfkernel)(const char *fmt, ...) = (void *)(kbase + KERN_501_PRINTF);
		printfkernel("FW Version 5.05 Detected\n");
	}
	else return -1;


	if (fw_version == 0x505) {

		// Kernel pointers resolving

		kernel_ptr = (uint8_t*)kbase;
		got_prison0 = (void**)&kernel_ptr[KERN_505_PRISON_0];
		got_rootvnode = (void**)&kernel_ptr[KERN_505_ROOTVNODE];

		cpu_disable_wp();
		// Allow sys_dynlib_dlsym in all processes.
		*(uint16_t *)(kbase + 0x237F3B) = 0x01C1;
		//*(uint16_t *)(kbase + 0x237F3B) = 0x101C;

		// Don't restrict dynlib information.
		*(uint64_t *)(kbase + 0x2B2620) = 0x9090909090C3C031;

		// Allow usage of mangled symbols in dynlib_do_dlsym().
		*(uint16_t *)(kbase + 0x2AFB47) = 0x9090;
		*(uint16_t *)(kbase + 0x2AFB47 + 2) = 0x9090; 
		*(uint16_t *)(kbase + 0x2AFB47 + 4) = 0x9090;
		//Debug trophies
		//*(uint16_t *)(kbase + debug) = 0x31C0909090;

		*(uint32_t *)(kbase + 0x19ECEB0) = 0;

		cpu_enable_wp();

	}

	else if (fw_version == 0x405) {


		// Kernel pointers resolving

		kernel_ptr = (uint8_t*)kbase;
		got_prison0 = (void**)&kernel_ptr[KERN_405_PRISON_0];
		got_rootvnode = (void**)&kernel_ptr[KERN_405_ROOTVNODE];

	}
	else if (fw_version == 0x455) {

		// Kernel pointers resolving

		kernel_ptr = (uint8_t*)kbase;
		got_prison0 = (void**)&kernel_ptr[KERN_455_PRISON_0];
		got_rootvnode = (void**)&kernel_ptr[KERN_455_ROOTVNODE];
		//copyout = (void *)(kbase + KERN_455_COPYOUT);

	}
	else return -1;

	cred->cr_uid = 0;
	cred->cr_ruid = 0;
	cred->cr_rgid = 0;
	cred->cr_groups[0] = 0;
	cred->cr_prison = *got_prison0;
	fd->fd_rdir = fd->fd_jdir = *got_rootvnode;

	// Escalate ucred privs, needed for userland access to the filesystem e.g mounting & decrypting files

	void *td_ucred = *(void **)(((char *)td) + 304); // p_ucred == td_ucred

	uint64_t *sonyCred = (uint64_t *)(((char *)td_ucred) + 96);
	*sonyCred = 0xffffffffffffffff;

	// sceSblACMgrGetDeviceAccessType

	uint64_t *sceProcessAuthorityId = (uint64_t *)(((char *)td_ucred) + 88);
	*sceProcessAuthorityId = 0x3800000000000010; // SceShellcore paid
												 // sceSblACMgrHasSceProcessCapability

	uint64_t *sceProcCap = (uint64_t *)(((char *)td_ucred) + 104);
	*sceProcCap = 0xffffffffffffffff; // Max capability

	uint64_t uaddr = args->payload_info->uaddr;


	copyout(&kbase, uaddr, 8);

	return 0;

}

int kpayloadsss(struct thread *td, struct kpayload_args* args) {

	struct ucred* cred;
	struct filedesc* fd;

	fd = td->td_proc->p_fd;
	cred = td->td_proc->p_ucred;


	void* kbase = &((uint8_t*)__readmsr(0xC0000082))[-KERN_BASE_PTR];
	uint8_t* kernel_ptr = (uint8_t*)kbase;
	void** got_prison0 = (void**)&kernel_ptr[KERN_PRISON0];
	void** got_rootvnode = (void**)&kernel_ptr[KERN_ROOTVNODE];

	// resolve kernel functions

	int(*printfkernel)(const char *fmt, ...) = (void *)(kbase + KERN_PRINTF);
	int(*copyout)(const void *kaddr, void *uaddr, size_t len) = (void *)(kbase + KERN_COPYOUT);

	cred->cr_uid = 0;
	cred->cr_ruid = 0;
	cred->cr_rgid = 0;
	cred->cr_groups[0] = 0;

	cred->cr_prison = *got_prison0;
	fd->fd_rdir = fd->fd_jdir = *got_rootvnode;

	// escalate ucred privs, needed for access to the filesystem ie* mounting & decrypting files
	void *td_ucred = *(void **)(((char *)td) + 304); // p_ucred == td_ucred

													 // sceSblACMgrIsSystemUcred
	uint64_t *sonyCred = (uint64_t *)(((char *)td_ucred) + 96);
	*sonyCred = 0xffffffffffffffff;

	// sceSblACMgrGetDeviceAccessType
	uint64_t *sceProcType = (uint64_t *)(((char *)td_ucred) + 88);
	*sceProcType = 0x3801000000000013; // Max access

									   // sceSblACMgrHasSceProcessCapability
	uint64_t *sceProcCap = (uint64_t *)(((char *)td_ucred) + 104);
	*sceProcCap = 0xffffffffffffffff; // Sce Process

									  //struct acpi_tz_softc *sc;
									  /*struct acpi_tz_softc *sc;
									  int devclass_get_devices(devclass_t dc, device_t **devlistp, int *devcountp);
									  devclass_t thl = devclass_find("acpi_thermal")
									  device_t *devs;
									  int devcount, i;
									  devclass_get_devices(acpi_tz_devclass, &devs, &devcount);

									  for (i = 0; i < devcount; i++) {
									  sc = device_get_softc(devs[i]);
									  if (!acpi_tz_get_temperature(sc)) {
									  // Do something with sc->tz_temperature
									  }
									  }

									  acpi_tz_get_temperature(sc);
									  printfkernel("%d", sc->tz_temperature);*/

	cpu_disable_wp();
	// Allow sys_dynlib_dlsym in all processes.
	*(uint16_t *)(kbase + 0x237F3B) = 0x01C1;
	//*(uint16_t *)(kbase + 0x237F3B) = 0x101C;

	// Don't restrict dynlib information.
	*(uint64_t *)(kbase + 0x2B2620) = 0x9090909090C3C031;

	// Allow usage of mangled symbols in dynlib_do_dlsym().
	*(uint16_t *)(kbase + 0x2AFB47) = 0x9090;
	*(uint16_t *)(kbase + 0x2AFB47 + 2) = 0x9090;
	*(uint16_t *)(kbase + 0x2AFB47 + 4) = 0x9090;

	*(uint32_t *)(kbase + 0x19ECEB0) = 0;

	cpu_enable_wp();

	return 0;
}

int wipenote()
{
	//syscall(11, uartoff);
	int moduleId = -1;
	sys_dynlib_load_prx("libSceSysUtil.sprx", &moduleId);

	// This header doesn't work in > 5.00
	int(*sceSysUtilSendSystemNotificationWithText)(int messageType, char* message) = NULL;

	sys_dynlib_dlsym(moduleId, "sceSysUtilSendSystemNotificationWithText", &sceSysUtilSendSystemNotificationWithText);

	char* initMessage = "Wiped!";
	sceSysUtilSendSystemNotificationWithText(222, initMessage);

	sys_dynlib_unload_prx(moduleId);

	return 0;
}

int dumpnote()
{
	//syscall(11, uartoff);
	int moduleId = -1;
	sys_dynlib_load_prx("libSceSysUtil.sprx", &moduleId);

	// This header doesn't work in > 5.00
	int(*sceSysUtilSendSystemNotificationWithText)(int messageType, char* message) = NULL;

	sys_dynlib_dlsym(moduleId, "sceSysUtilSendSystemNotificationWithText", &sceSysUtilSendSystemNotificationWithText);

	char* initMessage = "Dumped and Writen to USB0\n Keep this Safe!";
	sceSysUtilSendSystemNotificationWithText(222, initMessage);

	sys_dynlib_unload_prx(moduleId);

	return 0;
}

int dumped_and_decrypted_note()
{
	//syscall(11, uartoff);
	int moduleId = -1;
	sys_dynlib_load_prx("libSceSysUtil.sprx", &moduleId);

	// This header doesn't work in > 5.00
	int(*sceSysUtilSendSystemNotificationWithText)(int messageType, char* message) = NULL;

	sys_dynlib_dlsym(moduleId, "sceSysUtilSendSystemNotificationWithText", &sceSysUtilSendSystemNotificationWithText);

	char* initMessage = "Dumped and Decrypted\n Saved to USB0\n Keep this Safe!";
	sceSysUtilSendSystemNotificationWithText(222, initMessage);

	sys_dynlib_unload_prx(moduleId);

	return 0;
}

int dump_shellcore()
{
	int moduleId = -1;
	sys_dynlib_load_prx("libSceSysUtil.sprx", &moduleId);

	// This header doesn't work in > 5.00
	int(*sceSysUtilSendSystemNotificationWithText)(int messageType, char* message) = NULL;

	sys_dynlib_dlsym(moduleId, "sceSysUtilSendSystemNotificationWithText", &sceSysUtilSendSystemNotificationWithText);

	decrypt_and_dump_self("/system/vsh/SceShellCore.elf", "/mnt/usb0/SceShellCore.elf");

	char* initMessage = "Dumped Saved to USB0\n Keep this Safe!";
	sceSysUtilSendSystemNotificationWithText(222, initMessage);
	return 0;
}

#include <sys/types.h>
#include <sys/dirent.h> 

void t_dir(const char *path)
{
	int moduleId = -1;
	sys_dynlib_load_prx("libSceSysUtil.sprx", &moduleId);

	// This header doesn't work in > 5.00
	int(*sceSysUtilSendSystemNotificationWithText)(int messageType, char* message) = NULL;

	sys_dynlib_dlsym(moduleId, "sceSysUtilSendSystemNotificationWithText", &sceSysUtilSendSystemNotificationWithText);

	FILE *f;
#if 0
	///////////////////////////////////
	int(*sceKernelGetIdPs)(void* ret);
	int moduleIds = 0;

	sys_dynlib_load_prx("libkernel.sprx", &moduleIds);

	sys_dynlib_dlsym(moduleIds, "sceKernelGetIdPs", &sceKernelGetIdPs);

	char buffer[10024];
	unsigned char* idps = malloc(64);
	memset(idps, 0, 64);
	sceKernelGetIdPs(idps);

	char idps_buf[255];
	for (int i = 0; i<16; i++) {
		sprintf(idps_buf + strlen(idps_buf), "%02x", idps[i]);
	}

	sprintf(buffer, "Partial IDPS: %s\n\n Dumped and Written to USB0\n Keep this Safe!", idps_buf);

	/////////////////////////CID TO FILE////////////////////////////////////
	FILE *outfiles;
#endif



	// open file for writing 
	f = fopen("/mnt/usb0/idps_test.txt", "a+");
	if (!f) {
		char* initMessage2 = "failed";
		sceSysUtilSendSystemNotificationWithText(222, initMessage2);
	}

	fprintf(f, "---------------- trying to open PATH: \"%s\" ", path);


	// it didn't write, it won't append? .........
	fprintf(f, "-----------------TEST444--------------------------");
	fflush(f);

	char subpath[1024];
	//DIR* dir = opendir(path);


	int dir = open(path, O_DIRECTORY | O_RDONLY, 0777); // octal no  x
	if (dir == -1) {
		fprintf(f, " Error: bsd open()\n");
		fflush(f);// h
		fclose(f);
		return; // haha
	}

	fprintf(f, "\nLS \"%s\"\n{\n", path);
	fprintf(f, "-----------------TEST--------------------------");
	fflush(f);
	fclose(f);


	uint8_t buff[sizeof(struct dirent)];
	struct dirent *dent = (struct dirent*)buff;

	int rs = 0;
	while (0 != (rs = sceKernelGetdents(dir, buff, sizeof(struct dirent))))
	{
		if ('.' == dent->d_name[0]) continue;
		sprintf(subpath, "%s%s/", path, dent->d_name);

		//fprintf(f, " Entry: \"%s\" \n", subpath);// dent->d_name);

		switch (dent->d_type)
		{
		case DT_DIR:

			//        printf(" Entry: \"%s\" \n", subpath); // dent->d_name);
			t_dir(subpath);
			break;

		case DT_REG:
			// DUMP ME
			// dumpfile(subpath)
		{
			f = fopen("/mnt/usb0/idps_test.txt", "at+");
			fprintf(f, " ----- reg file \n");

			char dumppath[1024];
			sprintf(dumppath, "/mnt/usb0/dumpfs/%s", subpath); // have to check this , should only double up //'s
			const char *dn = dent->d_name;
			if (strstr(dn, ".bin") || strstr(dn, ".prx")) { // etc , dll exe prx sprx , if you don't use the . it will match any occurance, so prx will match sprx ( or a file named prx.bin )
				decrypt_and_dump_self(subpath, dumppath);

				fprintf(f, " @@@@@@ DUMPING FILE ####### \n");
			}
			fclose(f);
			// would be too many notifications
		}
		break;

		case DT_BLK:
			// HDD OR FLASH - maybe another day
			break;

		} // etc etc ... very little code, simple method
	}

	//fprintf(f,"\n} end \"%s\"\n", path);
	//fclose(f);

	close(dir);
	return;
}

int mount_rw()
{

	int moduleId = -1;
	sys_dynlib_load_prx("libSceSysUtil.sprx", &moduleId);

	// This header doesn't work in > 5.00
	int(*sceSysUtilSendSystemNotificationWithText)(int messageType, char* message) = NULL;

	sys_dynlib_dlsym(moduleId, "sceSysUtilSendSystemNotificationWithText", &sceSysUtilSendSystemNotificationWithText);

	mount_large_fs("/dev/da0x1.crypt", "/preinst2", "exfatfs", "511", MNT_UPDATE);
	mount_large_fs("/dev/da0x4.crypt", "/system", "exfatfs", "511", MNT_UPDATE);
	mount_large_fs("/dev/da0x5.crypt", "/system_ex", "exfatfs", "511", MNT_UPDATE);
	mount_large_fs("/dev/da0x9.crypt", "/system_data", "exfatfs", "511", MNT_UPDATE);
	mount_large_fs("/dev/md0", "/", "exfatfs", "511", MNT_UPDATE);
	mount_large_fs("/dev/md0.crypt", "/", "exfatfs", "511", MNT_UPDATE);
	mount_large_fs("/dev/da0x0.crypt", "/preinst", "exfatfs", "511", MNT_UPDATE);

	char* initMessage2 = "⚠ Mounted RW\n ALL System folders are now writable ";
	sceSysUtilSendSystemNotificationWithText(222, initMessage2);

	return 0;
}

int off_mount_rw()
{

	int moduleId = -1;
	sys_dynlib_load_prx("libSceSysUtil.sprx", &moduleId);

	// This header doesn't work in > 5.00
	int(*sceSysUtilSendSystemNotificationWithText)(int messageType, char* message) = NULL;

	sys_dynlib_dlsym(moduleId, "sceSysUtilSendSystemNotificationWithText", &sceSysUtilSendSystemNotificationWithText);

	mount_large_fs("/dev/da0x1.crypt", "/preinst2", "exfatfs", "511", MNT_RDONLY);
	mount_large_fs("/dev/da0x4.crypt", "/system", "exfatfs", "511", MNT_RDONLY);
	mount_large_fs("/dev/da0x5.crypt", "/system_ex", "exfatfs", "511", MNT_RDONLY);
	mount_large_fs("/dev/da0x9.crypt", "/system_data", "exfatfs", "511", MNT_RDONLY);
	mount_large_fs("/dev/md0", "/", "exfatfs", "511", MNT_RDONLY);
	mount_large_fs("/dev/md0.crypt", "/", "exfatfs", "511", MNT_RDONLY);
	mount_large_fs("/dev/da0x0.crypt", "/preinst", "exfatfs", "511", MNT_RDONLY);

	char* initMessage2 = "R/W Off\n Your Safe";
	sceSysUtilSendSystemNotificationWithText(222, initMessage2);

	return 0;
}



int dump_part(uint64_t partNo)
{
	size_t rdSz=0, wrSz=0;
	char da0[128];
	char devPath[1024], outPath[1024];



	// da0x[1-9] , 5b, 6x[0-2], 1[2-5] 

	if (partNo == 0) partNo++;
	if (partNo < 10)
		sprintf(da0, "da0x%1d", partNo);
	else {
		if (partNo < 15)
			sprintf(da0, "da0x%2d", partNo);	// 10 && 11 will fail
	}


	sprintf(devPath, "/dev/%s", da0);
	sprintf(outPath, "/mnt/usb0/part_%s.bin", da0);
	
	klog("dump_part device %s >> %s\n", devPath, outPath);


	int in = open(devPath, O_RDONLY, 0600);
	if (!in) return -1;

	int out = open(outPath, O_WRONLY, 0600);
	if (!out) return -2;

	klog("dump_part files opened\n");	// last run

	const static uint64_t secSize = 512;
	uint8_t secBuff[secSize];

	do {
		rdSz = read(in, secBuff, secSize);
		wrSz = write(out, secBuff, secSize);

	} while (rdSz == secSize);

	klog("dump_part finished\n");

	close(out);
	close(in);
	return 0;
}



#define FTP_PORT 21




extern char kexecs[];
extern unsigned kexecs_size;

extern char kexec_ps4z[];
extern unsigned kexec_sizez;


int kpayloadz(struct thread *td, struct kpayload_args* args) {

	//Starting kpayload...
	struct ucred* cred;
	struct filedesc* fd;

	void* kbase = 0;
	uint8_t* kernel_ptr;
	void** got_prison0;
	void** got_rootvnode;


	fd = td->td_proc->p_fd;
	cred = td->td_proc->p_ucred;

	uint64_t fw_version = 0x999;

	if (!memcmp((char*)(&((uint8_t*)__readmsr(0xC0000082))[-KERN_505_XFAST_SYSCALL]), (char[4]) { 0x7F, 0x45, 0x4C, 0x46 }, 4)) {

		kbase = &((uint8_t*)__readmsr(0xC0000082))[-KERN_505_XFAST_SYSCALL];


		fw_version = 0x505;

	}

	else if (!memcmp((char*)(&((uint8_t*)__readmsr(0xC0000082))[-KERN_455_XFAST_SYSCALL]), (char[4]) { 0x7F, 0x45, 0x4C, 0x46 }, 4)) {

		kbase = &((uint8_t*)__readmsr(0xC0000082))[-KERN_455_XFAST_SYSCALL];

		fw_version = 0x455;
	}

	else if (!memcmp((char*)(&((uint8_t*)__readmsr(0xC0000082))[-KERN_455_XFAST_SYSCALL]), (char[4]) { 0x7F, 0x45, 0x4C, 0x46 }, 4)) {

		kbase = &((uint8_t*)__readmsr(0xC0000082))[-KERN_455_XFAST_SYSCALL];

		fw_version = 0x455;

	}
	else if (!memcmp((char*)(&((uint8_t*)__readmsr(0xC0000082))[-KERN_405_XFAST_SYSCALL]), (char[4]) { 0x7F, 0x45, 0x4C, 0x46 }, 4)) {
		fw_version = 0x405;

	}
	else return -1;

	if (fw_version == 0x505) {

		int(*printfkernel)(const char *fmt, ...) = (void *)(kbase + 0x436040);
		printfkernel("FW Version 5.05 Detected\n");
	}

	else if (fw_version == 0x405) {

		int(*printfkernel)(const char *fmt, ...) = (void *)(kbase + KERN_405_PRINTF);
		printfkernel("FW Version 4.05 Detected\n");

	}
	else if (fw_version == 0x455) {

		int(*printfkernel)(const char *fmt, ...) = (void *)(kbase + KERN_455_PRINTF);
		printfkernel("FW Version 4.55 Detected\n");

	}
	else if (fw_version == 0x501) {

		int(*printfkernel)(const char *fmt, ...) = (void *)(kbase + KERN_501_PRINTF);
		printfkernel("FW Version 5.05 Detected\n");
	}
	else return -1;


	if (fw_version == 0x405) {


		// Kernel pointers resolving

		kernel_ptr = (uint8_t*)kbase;
		got_prison0 = (void**)&kernel_ptr[KERN_405_PRISON_0];
		got_rootvnode = (void**)&kernel_ptr[KERN_405_ROOTVNODE];

	}
	else if (fw_version == 0x455) {

		// Kernel pointers resolving

		kernel_ptr = (uint8_t*)kbase;
		got_prison0 = (void**)&kernel_ptr[KERN_455_PRISON_0];
		got_rootvnode = (void**)&kernel_ptr[KERN_455_ROOTVNODE];

	}
	else if (fw_version == 0x501) {

		// Kernel pointers resolving

		kernel_ptr = (uint8_t*)kbase;
		got_prison0 = (void**)&kernel_ptr[KERN_501_PRISON_0];
		got_rootvnode = (void**)&kernel_ptr[KERN_501_ROOTVNODE];

	}
	else if (fw_version == 0x505) {

		// Kernel pointers resolving

		kernel_ptr = (uint8_t*)kbase;
		got_prison0 = (void**)&kernel_ptr[KERN_505_PRISON_0];
		got_rootvnode = (void**)&kernel_ptr[KERN_505_ROOTVNODE];

	}
	else return -1;

	cred->cr_uid = 0;
	cred->cr_ruid = 0;
	cred->cr_rgid = 0;
	cred->cr_groups[0] = 0;
	cred->cr_prison = *got_prison0;
	fd->fd_rdir = fd->fd_jdir = *got_rootvnode;

	// Escalate ucred privs, needed for userland access to the filesystem e.g mounting & decrypting files

	void *td_ucred = *(void **)(((char *)td) + 304); // p_ucred == td_ucred

	uint64_t *sonyCred = (uint64_t *)(((char *)td_ucred) + 96);
	*sonyCred = 0xffffffffffffffff;

	// sceSblACMgrGetDeviceAccessType

	uint64_t *sceProcessAuthorityId = (uint64_t *)(((char *)td_ucred) + 88);
	*sceProcessAuthorityId = 0x3800000000000010; // SceShellcore paid
												 // sceSblACMgrHasSceProcessCapability

	uint64_t *sceProcCap = (uint64_t *)(((char *)td_ucred) + 104);
	*sceProcCap = 0xffffffffffffffff; // Max capability

	if (fw_version == 0x505) {

		kernel_ptr = (uint8_t*)kbase;
		got_prison0 = (void**)&kernel_ptr[KERN_505_PRISON_0];
		got_rootvnode = (void**)&kernel_ptr[KERN_505_ROOTVNODE];


		int(*copyout)(const void *kaddr, void *uaddr, size_t len) = (void *)(kbase + KERN_505_COPYOUT);


		cpu_disable_wp();
		//Kexec init
		void *DT_HASH_SEGMENTs = (void *)(kbase + 0xB5EF30); // I know it's for 4.55 but I think it will works
		memcpy(DT_HASH_SEGMENTs, kexecs, kexecs_size);

		void(*kexecs_inits)(void *, void *) = DT_HASH_SEGMENTs;

		kexecs_inits((void *)(kbase + 0x436040), NULL);

		int(*printfkernel)(const char *fmt, ...) = (void *)(kbase + 0x436040);

		// Say hello and put the kernel base in userland to we can use later
		printfkernel("5.05 Linux!\n");

		printfkernel("kernel base is:0x%016llx\n", kbase);

		uint64_t uaddr;

		memcpy(&uaddr, &args[2], 8);

		copyout(&kbase, uaddr, 8);

	}
	else if (fw_version == 0x455) {


		kernel_ptr = (uint8_t*)kbase;
		got_prison0 = (void**)&kernel_ptr[KERN_455_PRISON_0];
		got_rootvnode = (void**)&kernel_ptr[KERN_455_ROOTVNODE];

		int(*printfkernel)(const char *fmt, ...) = (void *)(kbase + KERN_455_PRINTF);

		int(*copyout)(const void *kaddr, void *uaddr, size_t len) = (void *)(kbase + KERN_455_COPYOUT);

		cpu_disable_wp();


		//Kexec init
		void *DT_HASH_SEGMENTs = (void *)(kbase + 0xB1D820);
		memcpy(DT_HASH_SEGMENTs, kexec_ps4z, kexec_sizez);

		void(*kexecz_init)(void *, void *) = DT_HASH_SEGMENTs;

		kexecz_init((void *)(kbase + 0x17F30), NULL);

		// Say hello and put the kernel base in userland to we can use later
		printfkernel("\nLinux 4.55\n");

		printfkernel("kernel base is:0x%016llx\n", kbase);

		uint64_t uaddr;
		memcpy(&uaddr, &args[2], 8);

		//printfkernel("uaddr is:0x%016llx\n", uaddr);

		copyout(&kbase, uaddr, 8);

	}

	return 0;

}


void usbthing()
{


	////////printfsocket("Open bzImage file from USB\n");
	
	FILE *fkernel = fopen("/mnt/usb0/bzImage", "r");

	fseek(fkernel, 0L, SEEK_END);
	int kernelsize = ftell(fkernel);
	fseek(fkernel, 0L, SEEK_SET);

	////////printfsocket("Open initramfs file from USB\n");
	FILE *finitramfs = fopen("/mnt/usb0/initramfs.cpio.gz", "r");


	fseek(finitramfs, 0L, SEEK_END);
	int initramfssize = ftell(finitramfs);
	fseek(finitramfs, 0L, SEEK_SET);

	////////printfsocket("kernelsize = %d\n", kernelsize);
	////////printfsocket("initramfssize = %d\n", initramfssize);

	////////printfsocket("Checks if the files are here\n");
	if (kernelsize == 0 || initramfssize == 0) {
		////////printfsocket("no file error im dead");
		fclose(fkernel);
		fclose(finitramfs);
		return;
	}

	void *kernel, *initramfs;
	char *cmd_line = "panic=0 clocksource=tsc radeon.dpm=0 console=tty0 console=ttyS0,115200n8 "
		"console=uart8250,mmio32,0xd0340000 video=HDMI-A-1:1920x1080-24@60 "
		"consoleblank=0 net.ifnames=0 drm.debug=0";

	kernel = malloc(kernelsize);
	initramfs = malloc(initramfssize);

	////////printfsocket("kernel = %llp\n", kernel);
	////////printfsocket("initramfs = %llp\n", initramfs);

	fread(kernel, kernelsize, 1, fkernel);
	fread(initramfs, initramfssize, 1, finitramfs);

	fclose(fkernel);
	fclose(finitramfs);

	//Call sys_kexec (153 syscall)
	syscall(153, kernel, kernelsize, initramfs, initramfssize, cmd_line);

	free(kernel);
	free(initramfs);

	//Reboot PS4
	int evf = syscall(540, "SceSysCoreReboot");
	syscall(546, evf, 0x4000, 0);
	syscall(541, evf);
	syscall(37, 1, 30);

}

int linux() {

	uint64_t* dump = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);

	int sRet = syscall(11, kpayloadz, dump);

	usbthing();

	return 0;

}


int eapkey()
{
	int moduleId = -1;
	sys_dynlib_load_prx("libSceSysUtil.sprx", &moduleId);

	// This header doesn't work in > 5.00
	int(*sceSysUtilSendSystemNotificationWithText)(int messageType, char* message) = NULL;

	sys_dynlib_dlsym(moduleId, "sceSysUtilSendSystemNotificationWithText", &sceSysUtilSendSystemNotificationWithText);

	uint64_t fw_version = get_fw_version();


	uint64_t* dump = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	uint64_t filedump = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);

	// well they are doing HEX your not , nah its something else ... like libc won't use the map
	// patch some things in the kernel (sandbox, prison, debug settings etc..)

	struct payload_info payload_info;

	payload_info.uaddr = dump;

	kexec(&kpayloads, &payload_info);

	uint64_t kbase;
	memcpy(&kbase, dump, 8);


	uint64_t pos = 0;
	struct payload_info_dumper payload_info_dumper;

	struct EAP_PartKey_t *pkey = (struct EAP_PartKey_t *)(filedump + 0x20);


	if (fw_version == 0x505)
	{
		payload_info_dumper.kaddr = kbase + 0x2790C90;
		
	}

	else if (fw_version == 0x455)
	{
		payload_info_dumper.kaddr = kbase + 0x258CCD0;
	}
	else return -1;

	klog("FW_VER is :0x%02X\n", fw_version);

	payload_info_dumper.uaddr = filedump;


	// call our copyout wrapper and send the userland buffer over socket
	kexec(&kdump, &payload_info_dumper);

	//brb
#define EAPKEY_FILEPATH "/mnt/usb0/eap_key_multi.bin"


	uint8_t* vin = (uint8_t*)filedump;
	uint8_t* vout = (uint8_t*)filedump + 0x100;
	for (int i = 0; i<16; i++) { vout[i] = vin[15 - i]; (vout + 0x10)[i] = (vin + 0x10)[15 - i]; }

	int fd = open(EAPKEY_FILEPATH, O_WRONLY | O_CREAT | O_TRUNC, 0777);

	if (fw_version == 0x505)
	{
		
		klog("**************************************\n");
		klog("*Welcome to the EAPKey Multi-FW Dumper*\n");
		klog("*Your Detected FW is 5.05*\n");
		klog("*So it will be saved as eap_key_multi.bin\n*");
		klog("*Made by LM and Znullptr\n*");
		klog("****************************************\n");
	}

	else if (fw_version == 0x455)
	{
		klog("**************************************\n");
		klog("*Welcome to the EAPKey Multi-FW Dumper*\n");
		klog("*Your Detected FW is 4.55*\n");
		klog("*So it will be saved as eap_key_multi.bin\n*");
		klog("*Made by LM and Znullptr\n*");
		klog("****************************************");
	}
	else return -1;

	if (fd > 0)
	{
		write(fd, vout, 0x20); // Write the userland buffer to USB
		close(fd);
		char* initMessage = "EAP Key (HEX) Dumped to USB0\n\n Keep this safe!";
		sceSysUtilSendSystemNotificationWithText(222, initMessage);
	}
	else {

	}
	return 0;
}
//0x258CCD0


int eap455()
{

	int moduleId = -1;
	sys_dynlib_load_prx("libSceSysUtil.sprx", &moduleId);

	// This header doesn't work in > 5.00
	int(*sceSysUtilSendSystemNotificationWithText)(int messageType, char* message) = NULL;

	sys_dynlib_dlsym(moduleId, "sceSysUtilSendSystemNotificationWithText", &sceSysUtilSendSystemNotificationWithText);


	uint64_t* dump = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	uint64_t filedump = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);

	// well they are doing HEX your not , nah its something else ... like libc won't use the map
	// patch some things in the kernel (sandbox, prison, debug settings etc..)

	struct payload_info payload_info;

	payload_info.uaddr = dump;

	kexec(&kpayloads, &payload_info);

	uint64_t kbase;
	memcpy(&kbase, dump, 8);


	uint64_t pos = 0;
	struct payload_info_dumper payload_info_dumper;

	struct EAP_PartKey_t *pkey = (struct EAP_PartKey_t *)(filedump + 0x20);

	payload_info_dumper.kaddr = kbase + 0x258CCD0;
	payload_info_dumper.uaddr = filedump;


	// call our copyout wrapper and send the userland buffer over socket
	kexec(&kdump, &payload_info_dumper);

	//brb
#define EAPKEY_FILEPATH "/mnt/usb0/eap_key_455.bin"


	uint8_t* vin = (uint8_t*)filedump;
	uint8_t* vout = (uint8_t*)filedump + 0x100;
	for (int i = 0; i<16; i++) { vout[i] = vin[15 - i]; (vout + 0x10)[i] = (vin + 0x10)[15 - i]; }

	int fd = open(EAPKEY_FILEPATH, O_WRONLY | O_CREAT | O_TRUNC, 0777);

	if (fd > 0)
	{
		write(fd, vout, 0x20); // Write the userland buffer to USB
		close(fd);
		char* initMessage = "EAP Key (HEX) Dumped to USB0\n\n Keep this safe!";
		sceSysUtilSendSystemNotificationWithText(222, initMessage);
	}
	else {

	}
	return 0;
}

static void decrypt_dirs(char *sourcedir, char* destdir)
{
	Libc();
	DIR *dir;
	struct dirent *dp;
	struct stat info;
	char src_path[1024], dst_path[1024];

	dir = opendir(sourcedir);
	if (!dir)
		return;

	//mkdir(destdir, 0777);

	while ((dp = readdir(dir)) != NULL)
	{
		if (!strcmp(dp->d_name, ".") || !strcmp(dp->d_name, ".."))
		{
			// do nothing (straight logic)
		}
		else
		{
			sprintf(src_path, "%s/%s", sourcedir, dp->d_name);
			sprintf(dst_path, "%s/%s", destdir, dp->d_name);
			if (!stat(src_path, &info))
			{
				if (S_ISDIR(info.st_mode))
				{
					decrypt_dirs(src_path, dst_path);
				}
				else
					if (S_ISREG(info.st_mode))
					{
						if (is_self(src_path))
							decrypt_and_dump_self(src_path, dst_path);
					}
			}
		}
	}
	closedir(dir);
}


static void decrypt_dir(char *sourcedir, char* destdir)
{
	Libc();
	DIR *dir;
	struct dirent *dp;
	struct stat info;
	char src_path[1024], dst_path[1024];

	dir = opendir(sourcedir);
	if (!dir)
		return;

	mkdir(destdir, 0777);

	while ((dp = readdir(dir)) != NULL)
	{
		if (!strcmp(dp->d_name, ".") || !strcmp(dp->d_name, ".."))
		{
			// do nothing (straight logic)
		}
		else
		{
			sprintf(src_path, "%s/%s", sourcedir, dp->d_name);
			sprintf(dst_path, "%s/%s", destdir, dp->d_name);
			if (!stat(src_path, &info))
			{
				if (S_ISDIR(info.st_mode))
				{
					decrypt_dir(src_path, dst_path);
				}
				else
					if (S_ISREG(info.st_mode))
					{
						if (is_self(src_path))
							decrypt_and_dump_self(src_path, dst_path);
					}
			}
		}
	}
	closedir(dir);
}



int test33()
{

	int moduleId = -1;
	sys_dynlib_load_prx("libSceSysUtil.sprx", &moduleId);

	// This header doesn't work in > 5.00
	int(*sceSysUtilSendSystemNotificationWithText)(int messageType, char* message) = NULL;

	sys_dynlib_dlsym(moduleId, "sceSysUtilSendSystemNotificationWithText", &sceSysUtilSendSystemNotificationWithText);


	char title_id[64];
	char usb_name[64];
	char usb_path[64];
	char cfg_path[64];
	char msg[64];
	int progress;


	//title_id


	/*sprintf(msg, "Start dumping\n%s to %s", title_id, usb_name);
	sceSysUtilSendSystemNotificationWithText(222, msg);

	sceKernelSleep(5);

	dump_game(title_id, usb_path);
	sceSysUtilSendSystemNotificationWithText(222, msg);

	sceKernelSleep(10);*/

	return 0;
}


int kdumper() {  // yes, fine dumps see


	int moduleId = -1;
	sys_dynlib_load_prx("libSceSysUtil.sprx", &moduleId);

	// This header doesn't work in > 5.00
	int(*sceSysUtilSendSystemNotificationWithText)(int messageType, char* message) = NULL;

	sys_dynlib_dlsym(moduleId, "sceSysUtilSendSystemNotificationWithText", &sceSysUtilSendSystemNotificationWithText);


	char* initMessage = "Start -- App will Unfreeze once Done\n 40 Secs Remaining\n Depending on your USB";
	sceSysUtilSendSystemNotificationWithText(222, initMessage);

	uint64_t* dump = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	uint64_t filedump = mmap(NULL, KERN_DUMPSIZE, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);

	// patch some things in the kernel (sandbox, prison, debug settings etc..)

	char* initMessage22 = "USB Found";
	sceSysUtilSendSystemNotificationWithText(222, initMessage22);

	struct payload_info payload_info;

	payload_info.uaddr = dump;

	kexec(&kpayloads, &payload_info);

	uint64_t kbase;
	memcpy(&kbase, dump, 8);


	uint64_t pos = 0;
	struct payload_info_dumper payload_info_dumper;

	char* initMessage7 = ("Dump Started");
	sceSysUtilSendSystemNotificationWithText(222, initMessage7);

	for (int i = 0; i < KERN_DUMPITER; i++) {

		payload_info_dumper.kaddr = kbase + pos;
		payload_info_dumper.uaddr = filedump + pos;

		// call our copyout wrapper and send the userland buffer over socket
		kexec(&kdump, &payload_info_dumper);

		pos = pos + PAGE_SIZE;
	}

	char* initMessage9 = ("Dump Done, Copying....");
	sceSysUtilSendSystemNotificationWithText(222, initMessage9);
	// write to file		
	int fd = open(KERN_FILEPATH, O_WRONLY | O_CREAT | O_TRUNC, 0777);

	if (fd == -1)
	{
		char* initMessage88 = ("Cant make File");
		sceSysUtilSendSystemNotificationWithText(222, initMessage88);
	}

	else
	{
		write(fd, filedump, KERN_DUMPSIZE); // Write the userland buffer to USB

		char* initMessage8w8 = ("Kernel Written to USB0");
		sceSysUtilSendSystemNotificationWithText(222, initMessage8w8);
		close(fd);
	}

	munmap(dump, PAGE_SIZE);
	munmap(filedump, KERN_DUMPSIZE);

	return 0;
}

int rip()
{


	int moduleId = -1;
	sys_dynlib_load_prx("libSceSysUtil.sprx", &moduleId);

	// This header doesn't work in > 5.00
	int(*sceSysUtilSendSystemNotificationWithText)(int messageType, char* message) = NULL;

	sys_dynlib_dlsym(moduleId, "sceSysUtilSendSystemNotificationWithText", &sceSysUtilSendSystemNotificationWithText);


	char* initMessage33 = "Start";
	sceSysUtilSendSystemNotificationWithText(222, initMessage33);


	struct stat st;
	stat("/mnt/usb0/file.bin", &st);

	int fd = open("/mnt/usb0/file.bin", 0, 0);
	void* executable = mmap(NULL, st.st_size, PROT_READ | PROT_EXEC, MAP_PRIVATE | MAP_POPULATE, fd, 0);
	close(fd);

	int(*payloadEntry)(void) = (void*)executable;
	payloadEntry();

	return 0;
}

int FTPStart()
{
	char ip_address[SCE_NET_CTL_IPV4_ADDR_STR_LEN];
	char msg[64];

	char* initMessage22 = "2222222";
	sceSysUtilSendSystemNotificationWithText(222, initMessage22);

	char* initMessage444 = "333333";
	sceSysUtilSendSystemNotificationWithText(222, initMessage444);

	int ret = get_ip_address(ip_address);

	char* initMessage4424 = "444444";
	sceSysUtilSendSystemNotificationWithText(222, initMessage4424);

	//sprintf(msg, "PS4 listening on\nIP %s Port %i", ip_address, FTP_PORT);

	ftps4_init(ip_address, FTP_PORT);

	return 0;
}

int dump_all()
{
	Libc();
	int moduleId = -1;
	sys_dynlib_load_prx("libSceSysUtil.sprx", &moduleId);

	// This header doesn't work in > 5.00
	int(*sceSysUtilSendSystemNotificationWithText)(int messageType, char* message) = NULL;

	sys_dynlib_dlsym(moduleId, "sceSysUtilSendSystemNotificationWithText", &sceSysUtilSendSystemNotificationWithText);

	char* initMessage2 = "System Dump Start, May take a while";
	sceSysUtilSendSystemNotificationWithText(222, initMessage2);

	decrypt_dir("/", "/mnt/usb0/PS4_FS");

	char* initMessage3 = "Done, Saved to USB0";
	sceSysUtilSendSystemNotificationWithText(222, initMessage3);

}

int decrypttemp()
{
	decrypt_dirs("/user/app/NPXX33382/tmp/", "/user/app/NPXX33382/tmp/decrypted/");//NPXX33382
}

int decrypttempfs()
{
	decrypt_dirs("/user/app/NPXX33382/tmp/", "/user/app/NPXX33382/tmp/decrypted/");//NPXX33382
}

int jk()
{

	int moduleId = -1;
	sys_dynlib_load_prx("libSceSysUtil.sprx", &moduleId);

	// This header doesn't work in > 5.00
	int(*sceSysUtilSendSystemNotificationWithText)(int messageType, char* message) = NULL;

	sys_dynlib_dlsym(moduleId, "sceSysUtilSendSystemNotificationWithText", &sceSysUtilSendSystemNotificationWithText);

	//sprintf("test", "ll");

	char* initMessage33 = "Start";
	sceSysUtilSendSystemNotificationWithText(222, initMessage33);

	int fd = open("/mnt/usb0/file.bin", 0, 0);


	struct stat st;
	stat("/mnt/usb0/file.bin", &st);


	if (!fd)
	{
		char* initMessage33 = "error1";
		sceSysUtilSendSystemNotificationWithText(222, initMessage33);

		return -1;

	}

	else {
		//st.st_size



		void* executable = mmap(NULL, st.st_size, PROT_READ | PROT_EXEC, MAP_ANONYMOUS, fd, 0);


		if (!executable)
		{
			char* initMessage33 = "error";
			sceSysUtilSendSystemNotificationWithText(222, initMessage33);

			return -1;

		}

		else {

			close(fd);

			int(*payloadEntry)(void) = (void*)executable;
			payloadEntry();
		}

		return 0;
	}
}
typedef struct _decrypt_header_args
{
	void* buffer;
	size_t length;
	int type;
}
decrypt_header_args;
CHECK_SIZE(decrypt_header_args, 24);

int translate_type(int type)
{
	switch (type)
	{
	case 0:
	case 3: return 0;
	case 1:
	case 4: return 1;
	case 2:
	case 5: return 2;
	}
	return 0;
}

int ioctlss(int fd, unsigned long com, void *data) 
{ 
	return syscall(54, fd, com, data);
}

int pupup_decrypt_header(int fd, void* buffer, size_t length, int type)
{
	klog("eswasa)\n");
	decrypt_header_args args;
	klog("eswasa)\n");
	memset(&args, 0, sizeof(args));
	klog("eswasa)\n");
	args.buffer = buffer,
		klog("eswasa)\n");
		args.length = length;
		klog("eswasa)\n");
	args.type = translate_type(type);
	klog("eswasa)\n");
	return ioctls(fd, 0xC0184401, &args);
	//klog("eswasaend)\n");
}

typedef struct _verify_segment_args
{
	uint16_t index;
	void* buffer;
	size_t length;
}
verify_segment_args;
CHECK_SIZE(verify_segment_args, 24);

int pupup_verify_segment(int fd, uint16_t index, void* buffer, size_t length,
	int additional)
{
	verify_segment_args args;
	memset(&args, 0, sizeof(args));
	args.index = index;
	args.buffer = buffer,
		args.length = length;
	int op = additional != 0 ? 0xC0184402 : 0xC0184403;
	return ioctl(fd, op, &args);
}

typedef struct _decrypt_segment_args
{
	uint16_t index;
	void* buffer;
	size_t length;
}
decrypt_segment_args;
CHECK_SIZE(decrypt_segment_args, 24);

int pupup_decrypt_segment(int fd, uint16_t index, void* buffer, size_t length)
{
	decrypt_segment_args args;
	memset(&args, 0, sizeof(args));
	args.index = index;
	args.buffer = buffer,
		args.length = length;
	return ioctl(fd, 0xC0184404, &args);
}

typedef struct _decrypt_segment_block_args
{
	uint16_t entry_index;
	uint16_t block_index;
	void* block_buffer;
	size_t block_length;
	void* table_buffer;
	size_t table_length;
}
decrypt_segment_block_args;
CHECK_SIZE(decrypt_segment_block_args, 40);

int pupup_decrypt_segment_block(int fd,
	uint16_t entry_index,
	uint16_t block_index, void* block_buffer,
	size_t block_length,
	void* table_buffer, size_t table_length)
{
	decrypt_segment_block_args args;
	memset(&args, 0, sizeof(args));
	args.entry_index = entry_index;
	args.block_index = block_index;
	args.block_buffer = block_buffer,
		args.block_length = block_length;
	args.table_buffer = table_buffer;
	args.table_length = table_length;
	return ioctl(fd, 0xC0284405, &args);
}


typedef struct _decrypt_state
{
	off_t input_base_offset;
	FILE* input_file;
	off_t output_base_offset;
	FILE* output_file;
	int device_fd;
	int pup_type;
}
decrypt_state;

int verify_segment(const decrypt_state state,
	int index, pup_segment* segment, int additional)
{
	int result;
	uint8_t* buffer = NULL;

	buffer = memalign(0x4000, segment->compressed_size);
	fseek(state.input_file, state.input_base_offset + segment->offset, SEEK_SET);
	int read = fread(buffer, segment->compressed_size, 1, state.input_file);
	if (read != 1)
	{
		result = -1;
		goto end;
	}

	result = pupup_verify_segment(state.device_fd, index, buffer,
		segment->compressed_size, additional);
	if (result != 0)
	{
		klog("Failed to verify segment #%d!%d\n", index, errno);
		////printfsocket("Failed to verify segment #%d! %d\n", index, errno);
		goto end;
	}

end:
	if (buffer != NULL)
	{
		free(buffer);
	}

	return result;
}

int verify_segments(const decrypt_state state,
	pup_segment* segments, int segment_count)
{
	int result = 0;

	for (int i = 0; i < segment_count; i++)
	{
		pup_segment* segment = &segments[i];
		if ((segment->flags & 0xF0000000) == 0xE0000000)
		{

			result = verify_segment(state, i, segment, 1);
			if (result < 0)
			{
				goto end;
			}
		}
	}

	for (int i = 0; i < segment_count; i++)
	{
		pup_segment* segment = &segments[i];
		if ((segment->flags & 0xF0000000) == 0xF0000000)
		{
			result = verify_segment(state, i, segment, 0);
			if (result < 0)
			{
				goto end;
			}
		}
	}

end:
	return result;
}

int decrypt_segment(const decrypt_state state,
	uint16_t index, pup_segment* segment)
{
	int result = -1;
	uint8_t* buffer = NULL;

	buffer = memalign(0x4000, segment->compressed_size);
	fseek(state.input_file,
		state.input_base_offset + segment->offset, SEEK_SET);
	fseek(state.output_file,
		state.output_base_offset + segment->offset, SEEK_SET);

	int is_compressed = (segment->flags & 8) != 0 ? 1 : 0;

	size_t remaining_size = segment->compressed_size;
	if (is_compressed == 1)
	{
		remaining_size &= ~0xFull;
	}

	if (remaining_size > 0)
	{
		size_t padding_size = segment->compressed_size & 0xF;
		size_t encrypted_size = remaining_size;

		if (segment->compressed_size < remaining_size)
		{
			encrypted_size = segment->compressed_size;
		}

		int read = fread(buffer, encrypted_size, 1, state.input_file);
		if (read != 1)
		{
			////printfsocket("Failed to read segment #%d! #%d\n", index, read);
			klog("Failed to read segment #%d! #%d\n", index, read);
			result = -1;
			goto end;
		}

		result = pupup_decrypt_segment(state.device_fd,
			index, buffer, encrypted_size);
		if (result != 0)
		{
			////printfsocket("Failed to decrypt segment #%d! %d\n", index, errno);
			klog("Failed to decrypt segment #%d! %d\n", index, errno);
			goto end;
		}

		int unencrypted_size = remaining_size - padding_size;
		if (is_compressed == 0 || encrypted_size != remaining_size)
		{
			unencrypted_size = encrypted_size;
		}

		fwrite(buffer, unencrypted_size, 1, state.output_file);
	}

end:
	if (buffer != NULL)
	{
		free(buffer);
	}

	return result;
}

int decrypt_segment_blocks(const decrypt_state state,
	uint16_t index, pup_segment* segment,
	uint16_t table_index, pup_segment* table_segment)
{
	int result = -1;
	uint8_t* table_buffer = NULL;
	uint8_t* block_buffer = NULL;

	size_t table_length = table_segment->compressed_size;
	table_buffer = memalign(0x4000, table_length);
	fseek(state.input_file,
		state.input_base_offset + table_segment->offset, SEEK_SET);

	int read = fread(table_buffer, table_length, 1, state.input_file);
	if (read != 1)
	{
		////printfsocket("  Failed to read table for segment #%d! %d\n", index, read);
		klog("  Failed to read table for segment #%d! %d\n", index, read);
		result = -1;
		goto end;
	}

	////printfsocket("  Decrypting table #%d for segment #%d\n", table_index, index);
	klog("  Decrypting table #%d for segment #%d\n", table_index, index);
	result = pupup_decrypt_segment(state.device_fd,
		table_index, table_buffer, table_length);
	if (result != 0)
	{
		goto end;
	}

	int is_compressed = (segment->flags & 8) != 0 ? 1 : 0;

	size_t block_size = 1 << (((segment->flags & 0xF000) >> 12) + 12);
	size_t block_count = (block_size + segment->uncompressed_size - 1)
		/ block_size;

	size_t tail_size = segment->uncompressed_size % block_size;
	if (tail_size == 0)
	{
		tail_size = block_size;
	}

	pup_block_info* block_infos = NULL;
	if (is_compressed == 1)
	{
		size_t valid_table_length = block_count * (32 + sizeof(pup_block_info));
		if (valid_table_length != table_length)
		{
		}
		block_infos = (pup_block_info*)&table_buffer[32 * block_count];
	}

	block_buffer = memalign(0x4000, block_size);

	fseek(state.input_file,
		state.input_base_offset + segment->offset, SEEK_SET);
	fseek(state.output_file,
		state.output_base_offset + segment->offset, SEEK_SET);

	////printfsocket("  Decrypting %d blocks...\n", block_count);
	klog(" Decrypting %d blocks...\n", block_count);

	size_t remaining_size = segment->compressed_size;
	int last_index = block_count - 1;
	for (int i = 0; i < block_count; i++)
	{
		//////printfsocket("  Decrypting block %d/%d...\n", i, block_count);
		klog("Decrypting block %d / %d...\n", i, block_count);

		size_t read_size;

		if (is_compressed == 1)
		{
			pup_block_info* block_info = &block_infos[i];
			uint32_t unpadded_size = (block_info->size & ~0xFu) -
				(block_info->size & 0xFu);

			read_size = block_size;
			if (unpadded_size != block_size)
			{
				read_size = block_info->size;
				if (i != last_index || tail_size != block_info->size)
				{
					read_size &= ~0xFu;
				}
			}

			if (block_info->offset != 0)
			{
				off_t block_offset = segment->offset + block_info->offset;
				fseek(state.input_file,
					state.input_base_offset + block_offset, SEEK_SET);
				fseek(state.output_file,
					state.output_base_offset + block_offset, SEEK_SET);
			}
		}
		else
		{
			read_size = remaining_size;
			if (block_size < read_size)
			{
				read_size = block_size;
			}
		}

		read = fread(block_buffer, read_size, 1, state.input_file);
		if (read != 1)
		{
			goto end;
		}

		result = pupup_decrypt_segment_block(state.device_fd,
			index, i, block_buffer, read_size,
			table_buffer, table_length);
		if (result < 0)
		{
			goto end;
		}

		fwrite(block_buffer, read_size, 1, state.output_file);

		remaining_size -= read_size;
	}

end:
	if (block_buffer != NULL)
	{
		free(block_buffer);
	}

	if (table_buffer != NULL)
	{
		free(table_buffer);
	}

	return result;
}

int find_table_segment(int index, pup_segment* segments, int segment_count,
	int* table_index)
{
	if (((index | 0x100) & 0xF00) == 0xF00)
	{
		////printfsocket("Can't do table for segment #%d\n", index);
		*table_index = -1;
		return -1;
	}

	for (int i = 0; i < segment_count; i++)
	{
		if (segments[i].flags & 1)
		{
			uint32_t id = segments[i].flags >> 20;
			if (id == index)
			{
				*table_index = i;
				return 0;
			}
		}
	}

	return -2;
}

int decrypt_pup_data(const decrypt_state state)
{
	int result;
	size_t read;
	uint8_t* header_data = NULL;
	klog("32121)\n");

	fseek(state.input_file, state.input_base_offset, SEEK_SET);

	klog("32121)\n");

	pup_file_header file_header;
	klog("32121)\n");
	read = fread(&file_header, sizeof(file_header), 1, state.input_file);
	klog("32121)\n");
	if (read != 1)
	{
		klog("Failed to read file header! (%u)\n", read);
		////printfsocket("Failed to read file header! (%u)\n", read);
		goto end;
	}
	klog("32121)\n");
	int header_size = file_header.unknown_0C + file_header.unknown_0E;
	klog("32121)\n");
	header_data = memalign(0x4000, header_size);
	klog("3215555555521)\n");
	memcpy(header_data, &file_header, sizeof(file_header));
	klog("3215555555521)\n");
	read = fread(&header_data[sizeof(file_header)],
		header_size - sizeof(file_header), 1, state.input_file);
	klog("3215555555521)\n");
	if (read != 1)
	{
		////printfsocket("Failed to read header! (%u)\n", read);
		klog("Failed to read header! (%u)\n", read);
		goto end;
	}
	klog("3215555555521)\n");
	if ((file_header.flags & 1) == 0)
	{
		////printfsocket("Decrypting header...\n");
		klog("Decrypting header...\n");
		result = pupup_decrypt_header(state.device_fd, header_data, header_size, 0);//state.pup_type);
		klog("2222ader...\n");
		if (result != 0)
		{
			////printfsocket("Failed to decrypt header! %d\n", errno);
			klog("Failed to decrypt header!\n");
			goto end;
		}
	}
	else
	{
		////printfsocket("Can't decrypt network pup!\n");
		klog("Can't decrypt network pup!\n");
		goto end;
	}

	pup_header* header = (pup_header*)&header_data[0];
	pup_segment* segments = (pup_segment*)&header_data[0x20];
	klog("reeeeeeeeeee)\n");
	klog("ggggggggggggggggggggg)\n");
	fseek(state.output_file, state.output_base_offset, SEEK_SET);
	klog("ggggggggggggggggggggg)\n");
	fwrite(header_data, header_size, 1, state.output_file);
	klog("ggggggggggggggggggggg)\n");

	////printfsocket("Verifying segments...\n");
	klog("Verifying segments...\n");
	result = verify_segments(state, segments, header->segment_count);
	klog("ggggggggggggggggggggg)\n");
	if (result < 0)
	{
		////printfsocket("Failed to verify segments!\n");
		klog("Failed to verify segments!\n");
	}

	/*
	for (int i = 0; i < header->segment_count; i++)
	{
	pup_segment* segment = &segments[i];
	////printfsocket("%4d i=%4u b=%u c=%u t=%u r=%05X\n",
	i, segment->flags >> 20,
	(segment->flags & 0x800) != 0,
	(segment->flags & 0x8) != 0,
	(segment->flags & 0x1) != 0,
	segment->flags & 0xFF7F6);
	}
	*/

#define O_RDWR 0x0002 

	////printfsocket("Decrypting %d segments...\n", header->segment_count);
	klog("Decrypting %d segments...\n", header->segment_count);
	for (int i = 0; i < header->segment_count; i++)
	{
		pup_segment* segment = &segments[i];

		uint32_t special = segment->flags & 0xF0000000;
		if (special == 0xE0000000)
		{
			////printfsocket("Skipping additional signature segment #%d!\n", i);
			klog("Skipping additional signature segment #%d!\n", i);
			continue;
		}
		else if (special == 0xF0000000)
		{
			////printfsocket("Skipping watermark segment #%d!\n", i);
			klog("Skipping watermark segment #%d!\n", i);
			continue;
		}


		if ((segment->flags & 0x800) != 0)
		{
			int table_index;
			result = find_table_segment(i, segments, header->segment_count,
				&table_index);
			if (result < 0)
			{
				////printfsocket("Failed to find table for segment #%d!\n", i);
				continue;
			}

			decrypt_segment_blocks(state, i, segment,
				table_index, &segments[table_index]);
		}
		else
		{
			decrypt_segment(state, i, segment);
		}
	}

end:
	if (header_data != NULL)
	{
		free(header_data);
	}

	return 0;
}

int get_pup_type(const char* name)
{
	if (strcmp(name, "PS4UPDATE1.PUP") == 0 ||
		strcmp(name, "PS4UPDATE2.PUP") == 0)
	{
		return 1;
	}

	if (strcmp(name, "PS4UPDATE3.PUP") == 0 ||
		strcmp(name, "PS4UPDATE4.PUP") == 0)
	{
		return 0;
	}

	return -1;
}

void decrypt_pup(const char* name, FILE* input, off_t baseOffset, int fd)
{
	FILE* output = NULL;

	char path[260];
	sprintf(path, "/mnt/usb0/%s.dec", name);
	klog("Creating %s...\n", path);

	////printfsocket("Creating %s...\n", path);

	output = fopen(path, "wb");
	if (output == NULL)
	{
		////printfsocket("Failed to open %s!\n", path);
		goto end;
	}

	int type = get_pup_type(name);
	if (type < 0)
	{
		////printfsocket("Don't know the type for %s!\n", path);
		goto end;
	}

	decrypt_state state;
	state.input_file = input;
	state.input_base_offset = baseOffset;
	state.output_file = output;
	state.output_base_offset = 0;
	state.device_fd = fd;
	state.pup_type = type;
	decrypt_pup_data(state);

end:
	if (output != NULL)
	{
		fclose(output);
	}
}

//typedef struct FILE FILE;

typedef struct _bls_entry
{
	uint32_t block_offset;
	uint32_t size;
	uint8_t reserved[8];
	char name[32];
}
bls_entry;
CHECK_SIZE(bls_entry, 48);

typedef struct _bls_header
{
	uint32_t magic;
	uint32_t version;
	uint32_t flags;
	uint32_t file_count;
	uint32_t block_count;
	uint8_t reserved[12];
}
bls_header;
CHECK_SIZE(bls_header, 32);



void decrypt_pups()
{
	const char* path = "/mnt/usb0/PS4UPDATE.PUP";

	int read;
	int fd = -1;
	FILE* input = NULL;
	bls_entry* entries = NULL;

	fd = open("/dev/pup_update0", O_RDWR, 0);
	if (fd < 0)
	{
		////printfsocket("Failed to open /dev/pup_update0!\n");
		goto end;
	}

	////printfsocket("Opening %s...\n", path);
	klog("Opening %s...\n", path);
	input = fopen(path, "rb");
	if (input == NULL)
	{
		////printfsocket("Failed to open %s!\n", path);
		klog("Failed to open %s!\n", path);
		goto end;
	}

	bls_header header;
	klog("eeeewe!\n");
	read = fread(&header, sizeof(header), 1, input);
	klog("eeeee!\n");
	if (read != 1)
	{
		klog("Failed to read BLS header!\n");
		////printfsocket("Failed to read BLS header!\n");
		goto end;
	}

	entries = (bls_entry*)malloc(sizeof(bls_entry) * header.file_count);
	read = fread(entries, sizeof(bls_entry), header.file_count, input);
	if (read != header.file_count)
	{
		klog("Failed to read BLS entries!\n");
		////printfsocket("Failed to read BLS entries!\n");
		goto end;
	}

	for (int i = 0; i < header.file_count; i++)
	{
		decrypt_pup(entries[i].name, input, entries[i].block_offset * 512, fd);
	}

end:
	if (entries != NULL)
	{
		free(entries);
	}

	if (input != NULL)
	{
		fclose(input);
	}

	if (fd >= 0)
	{
		close(fd);
	}
}

int install_payload455(struct thread *td, void *payload, size_t psize) {

		void *kbase = &((uint8_t*)__readmsr(0xC0000082))[-KERN_455_XFAST_SYSCALL]; //0x30B7D0
		int(*printfkernel)(const char *fmt, ...) = (void *)(kbase + KERN_455_PRINTF);

	vm_offset_t(*kmem_alloc)(vm_map_t map, vm_size_t size) = (void *)(kbase + __kmem_alloc455);
	vm_map_t kernel_map = *(vm_map_t *)(kbase + __kernel_map455);

	size_t msize = 0;
	if (elf_mapped_size(payload, &msize)) {
		printfkernel("[jkpatch] install_payload: elf_mapped_size failed!\n");
		return 1;
	}

	int s = (msize + 0x3FFFull) & ~0x3FFFull;


	void *payloadbase = (void *)kmem_alloc(kernel_map, s);
	if (!payloadbase) {
		printfkernel("kmem_alloc failed!\n");
		// need to set protection back to VM_PROT_DEFAULT...
		return 1;
	}


	// load the elf
	int r = 0;
	int(*payload_entry)(void *p);

	if ((r = load_elf(payload, psize, payloadbase, msize, (void **)&payload_entry))) {
		printfkernel("load_elf failed (r: %i)!\n", r);
		return 1;
	}

	// call entry
	if (payload_entry(NULL)) {
		return 1;
	}

	printfkernel("[jkpatch] + [Syscall 9] loaded at 0x%llX\n", payloadbase);

	return 0;
}

#define ver 0


void *fw_ver(struct kpayload_args* args) {


	void* kbase = 0;
	uint8_t* kernel_ptr;
	void** got_prison0;
	void** got_rootvnode;

	int(*copyout)(const void *kaddr, void *uaddr, size_t len);

	uint64_t fw_version = 0x999;

	if (!memcmp((char*)(&((uint8_t*)__readmsr(0xC0000082))[-KERN_505_XFAST_SYSCALL]), (char[4]) { 0x7F, 0x45, 0x4C, 0x46 }, 4)) {

		kbase = &((uint8_t*)__readmsr(0xC0000082))[-KERN_505_XFAST_SYSCALL];
		copyout = (void *)(kbase + KERN_505_COPYOUT);
		fw_version = 0x505;

	}

	else if (!memcmp((char*)(&((uint8_t*)__readmsr(0xC0000082))[-KERN_455_XFAST_SYSCALL]), (char[4]) { 0x7F, 0x45, 0x4C, 0x46 }, 4)) {

		kbase = &((uint8_t*)__readmsr(0xC0000082))[-KERN_455_XFAST_SYSCALL];


		copyout = (void *)(kbase + KERN_455_COPYOUT);

		fw_version = 0x455;
	}

	else if (!memcmp((char*)(&((uint8_t*)__readmsr(0xC0000082))[-KERN_455_XFAST_SYSCALL]), (char[4]) { 0x7F, 0x45, 0x4C, 0x46 }, 4)) {

		kbase = &((uint8_t*)__readmsr(0xC0000082))[-KERN_455_XFAST_SYSCALL];

		fw_version = 0x455;

	}
	else if (!memcmp((char*)(&((uint8_t*)__readmsr(0xC0000082))[-KERN_405_XFAST_SYSCALL]), (char[4]) { 0x7F, 0x45, 0x4C, 0x46 }, 4)) {
		fw_version = 0x405;

	}
	else return -1;


	uint64_t uaddr = args->payload_info->uaddr;
	copyout(&fw_version, uaddr, 5);

	return 0;
}


void kernel_free_contig(void *addr, size_t size)
{
	if (!addr)
		return;
	kern.kmem_free(*kern.kernel_map, (vm_offset_t)addr, size);
}

int kernel_hook_install(void *target, void *hook)
{
	uintptr_t t = (uintptr_t)target; // addr to redirect to
	uintptr_t h = (uintptr_t)hook; // place to write the thunk

	if (!hook || !target) {
		return 0;
	}

	kern.printf("kernel_hook_install(%p, %p)\n", target, hook);

	if (!(t & (1L << 63))) {
		kern.printf("\n===================== WARNING =====================\n");
		kern.printf("hook target function address: %p\n", target);
		kern.printf("It looks like we're running from userland memory.\n");
		kern.printf("Please run this code from a kernel memory mapping.\n\n");
		return 0;
	}
	s64 displacement = t - (h + 5);

	kern.sched_pin();
	cpu_disable_wp();
	if (displacement < -0x80000000 || displacement > 0x7fffffff) {
		kern.printf("  Using 64bit absolute jump\n");
		struct __attribute__((packed)) jmp_t {
			u8 op[2];
			s32 zero;
			void *target;
		} jmp = {
			.op = { 0xff, 0x25 },
			.zero = 0,
			.target = target,
		};
		ASSERT_STRSIZE(struct jmp_t, 14);
		memcpy(hook, &jmp, sizeof(jmp));
	}
	else {
		kern.printf("  Using 32bit relative jump\n");
		struct __attribute__((packed)) jmp_t {
			u8 op[1];
			s32 imm;
		} jmp = {
			.op = { 0xe9 },
			.imm = displacement,
		};
		ASSERT_STRSIZE(struct jmp_t, 5);
		memcpy(hook, &jmp, sizeof(jmp));
	}
	wbinvd();
	cpu_enable_wp();
	kern.sched_unpin();

	return 1;
}

static inline void *mmemset(void *b, int c, size_t len)
{
	size_t i;

	for (i = 0; i < len; i++)
		((unsigned char *)b)[i] = c;

	return b;
}

#define PAGE_SIZEs 0x4000


void kernel_remap(void *start, void *end, int perm)
{
	void* kbase = &((uint8_t*)__readmsr(0xC0000082))[-KERN_505_XFAST_SYSCALL];
	int(*printfkernel)(const char *fmt, ...) = (void *)(kbase + 0x436040);
	void(*pmap_protect)(pmap_t pmap, uint64_t sva, uint64_t eva, u8 pr) = (void *)(kbase + 0x2E3090);

#define rrr(name, offset) name = (void *)(kbase + offset)
	rrr(kern.kernel_pmap_store, kern_off_kernel_pmap_store);


	uint64_t s = ((uint64_t)start) & ~(uint64_t)(PAGE_SIZEs - 1);
	uint64_t e = ((uint64_t)end + PAGE_SIZEs - 1) & ~(uint64_t)(PAGE_SIZEs - 1);

	printfkernel("pmap_protect(pmap, %p, %p, %d)\n", (void*)s, (void*)e, perm);
	pmap_protect(kern.kernel_pmap_store, s, e, perm);
}


void *jkpatch(struct thread *td, struct jkuap *uap) {


	struct ucred* cred;
	struct filedesc* fd;

	void* kbase = 0;
	uint8_t* kernel_ptr;
	void** got_prison0;
	void** got_rootvnode;


	fd = td->td_proc->p_fd;
	cred = td->td_proc->p_ucred;

	uint64_t fw_version = 0x999;

	if (!memcmp((char*)(&((uint8_t*)__readmsr(0xC0000082))[-KERN_505_XFAST_SYSCALL]), (char[4]) { 0x7F, 0x45, 0x4C, 0x46 }, 4)) {

		kbase = &((uint8_t*)__readmsr(0xC0000082))[-KERN_505_XFAST_SYSCALL];


		fw_version = 0x505;

	}

	else if (!memcmp((char*)(&((uint8_t*)__readmsr(0xC0000082))[-KERN_455_XFAST_SYSCALL]), (char[4]) { 0x7F, 0x45, 0x4C, 0x46 }, 4)) {

		kbase = &((uint8_t*)__readmsr(0xC0000082))[-KERN_455_XFAST_SYSCALL];

		fw_version = 0x455;
	}

	else if (!memcmp((char*)(&((uint8_t*)__readmsr(0xC0000082))[-KERN_455_XFAST_SYSCALL]), (char[4]) { 0x7F, 0x45, 0x4C, 0x46 }, 4)) {

		kbase = &((uint8_t*)__readmsr(0xC0000082))[-KERN_455_XFAST_SYSCALL];

		fw_version = 0x455;

	}
	else if (!memcmp((char*)(&((uint8_t*)__readmsr(0xC0000082))[-KERN_405_XFAST_SYSCALL]), (char[4]) { 0x7F, 0x45, 0x4C, 0x46 }, 4)) {
		fw_version = 0x405;

	}
	else return -1;

	if (fw_version == 0x505) {

		int(*printfkernel)(const char *fmt, ...) = (void *)(kbase + 0x436040);
		printfkernel("FW Version 5.05 Detected\n");//kern.ld 
	}

	else if (fw_version == 0x405) {

		int(*printfkernel)(const char *fmt, ...) = (void *)(kbase + KERN_405_PRINTF);
		printfkernel("FW Version 4.05 Detected\n");

	}
	else if (fw_version == 0x455) {

		int(*printfkernel)(const char *fmt, ...) = (void *)(kbase + KERN_455_PRINTF);
		printfkernel("FW Version 4.55 Detected\n");

	}
	else if (fw_version == 0x501) {

		int(*printfkernel)(const char *fmt, ...) = (void *)(kbase + KERN_501_PRINTF);
		printfkernel("FW Version 5.05 Detected\n");
	}
	else return -1;


	if (fw_version == 0x405) {

		// Kernel pointers resolving

		kernel_ptr = (uint8_t*)kbase;
		got_prison0 = (void**)&kernel_ptr[KERN_405_PRISON_0];
		got_rootvnode = (void**)&kernel_ptr[KERN_405_ROOTVNODE];


	}
	else if (fw_version == 0x455) {

		// Kernel pointers resolving

		kernel_ptr = (uint8_t*)kbase;
		got_prison0 = (void**)&kernel_ptr[KERN_455_PRISON_0];
		got_rootvnode = (void**)&kernel_ptr[KERN_455_ROOTVNODE];

	}
	else if (fw_version == 0x501) {

		// Kernel pointers resolving

		kernel_ptr = (uint8_t*)kbase;
		got_prison0 = (void**)&kernel_ptr[KERN_501_PRISON_0];
		got_rootvnode = (void**)&kernel_ptr[KERN_501_ROOTVNODE];

	}
	else if (fw_version == 0x505) {

		kernel_ptr = (uint8_t*)kbase;
		got_prison0 = (void**)&kernel_ptr[KERN_505_PRISON_0];
		got_rootvnode = (void**)&kernel_ptr[KERN_505_ROOTVNODE];

	}
	else return -1;

	cred->cr_uid = 0;
	cred->cr_ruid = 0;
	cred->cr_rgid = 0;
	cred->cr_groups[0] = 0;
	cred->cr_prison = *got_prison0;
	fd->fd_rdir = fd->fd_jdir = *got_rootvnode;

	// Escalate ucred privs, needed for userland access to the filesystem e.g mounting & decrypting files

	void *td_ucred = *(void **)(((char *)td) + 304); // p_ucred == td_ucred

	uint64_t *sonyCred = (uint64_t *)(((char *)td_ucred) + 96);
	*sonyCred = 0xffffffffffffffff;

	// sceSblACMgrGetDeviceAccessType
	*(uint64_t *)(td_ucred + 0x60) = 0xFFFFFFFFFFFFFFFF;
	*(uint64_t *)(td_ucred + 0x58) = 0x3801000000000013;
	*(uint64_t *)(td_ucred + 0x68) = 0xFFFFFFFFFFFFFFFF;

	uint64_t *sceProcessAuthorityId = (uint64_t *)(((char *)td_ucred) + 88);
	*sceProcessAuthorityId = 0x3800000000000010; // SceShellcore paid
												 // sceSblACMgrHasSceProcessCapability

	uint64_t *sceProcCap = (uint64_t *)(((char *)td_ucred) + 104);
	*sceProcCap = 0xffffffffffffffff; // Max capability

	if (fw_version == 0x505) {

		// Kernel pointers resolving

		kernel_ptr = (uint8_t*)kbase;
		got_prison0 = (void**)&kernel_ptr[KERN_505_PRISON_0];
		got_rootvnode = (void**)&kernel_ptr[KERN_505_ROOTVNODE];

		int(*printfkernel)(const char *fmt, ...) = (void *)(kbase + 0x436040);


#define r(name, offset) name = (void *)(kbase + offset)
		r(k_malloc, __malloc505);
		r(k_free, __free505);
		r(k_memcpy, __memcpy505);
		r(k_memset, __memset505);
		r(k_memcmp, __memcmp505);
		r(k_strlen, __strlen505);


		cpu_disable_wp();
										   // patch vm_map_protect check
		memcpy((void *)(kbase + 0x1A3C08), "\x90\x90\x90\x90\x90\x90", 6);

		// Disable ptrace check

		kernel_ptr[0x30D9AA] = 0xEB;

		// Disable process aslr
		*(uint16_t*)&kernel_ptr[0x194875] = 0x9090;

		// Allow sys_dynlib_dlsym in all processes.
		*(uint16_t *)(kbase + 0x237F3B) = 0x01C1;
		//*(uint16_t *)(kbase + 0x237F3B) = 0x101C;

		// Don't restrict dynlib information.
		*(uint64_t *)(kbase + 0x2B2620) = 0x9090909090C3C031;

		// Allow usage of mangled symbols in dynlib_do_dlsym().
		*(uint16_t *)(kbase + 0x2AFB47) = 0x9090;
		*(uint16_t *)(kbase + 0x2AFB47 + 2) = 0x9090;
		*(uint16_t *)(kbase + 0x2AFB47 + 4) = 0x9090;

		*(uint32_t *)(kbase + 0x19ECEB0) = 0;

		*(uint8_t*)(kbase + 0x117B0) = 0xB0;
		*(uint8_t*)(kbase + 0x117B1) = 0x01;
		*(uint8_t*)(kbase + 0x117B2) = 0xC3;

		*(uint8_t*)(kbase + 0x117C0) = 0xB0;
		*(uint8_t*)(kbase + 0x117C1) = 0x01;
		*(uint8_t*)(kbase + 0x117C2) = 0xC3;

		*(uint8_t*)(kbase + 0x13F03F) = 0x31;
		*(uint8_t*)(kbase + 0x13F040) = 0xC0;
		*(uint8_t*)(kbase + 0x13F041) = 0x90;
		*(uint8_t*)(kbase + 0x13F042) = 0x90;
		*(uint8_t*)(kbase + 0x13F043) = 0x90;

		*(uint8_t *)(kbase + 0xFCD48) = 7; // VM_PROT_ALL;
		*(uint8_t *)(kbase + 0xFCD56) = 7; // VM_PROT_ALL;

		cpu_enable_wp();


		if (!uap->payload) {
			printfkernel("data is NULL!\n");
			return 1;
		}

		// install wizardry
		if (install_payload505(td, uap->payload, uap->psize)) {
			printfkernel("install_payload failed!\n");
			return 1;
		}

		printfkernel("[jkpatch] all done on 505\n");

	}
	else if (fw_version == 0x455) {

		kernel_ptr = (uint8_t*)kbase;
		got_prison0 = (void**)&kernel_ptr[KERN_455_PRISON_0];
		got_rootvnode = (void**)&kernel_ptr[KERN_455_ROOTVNODE];


		int(*copyout)(const void *kaddr, void *uaddr, size_t len);

		copyout = (void *)(kbase + KERN_455_COPYOUT);

#define r(name, offset) name = (void *)(kbase + offset)
		r(k_malloc, __malloc455);
		r(k_free, __free455);
		r(k_memcpy, __memcpy455);
		r(k_memset, __memset455);
		r(k_memcmp, __memcmp455);
		r(k_strlen, __strlen455);


		int(*printfkernel)(const char *fmt, ...) = (void *)(kbase + 0x17F30);

		cpu_disable_wp();

		*(uint8_t *)(kbase + 0x16ED8C) = 7; // VM_PROT_ALL;
		*(uint8_t *)(kbase + 0x16EDA2) = 7; // VM_PROT_ALL;
		*(uint8_t*)(kbase + 0x143BF2) = 0x90; //0x0F
		*(uint8_t*)(kbase + 0x143BF3) = 0xE9; //0x84
		*(uint8_t*)(kbase + 0x143E0E) = 0x90; //0x74
		*(uint8_t*)(kbase + 0x143E0F) = 0x90; //0x0C

		cpu_enable_wp();

		//int(*printfkernel)(const char *fmt, ...) = (void *)(kbase + 0x436040);

		if (!uap->payload) {
			printfkernel("data is NULL!\n");
			return 1;
		}

		// install wizardry
		if (install_payload455(td, uap->payload, uap->psize)) {
			printfkernel("install_payload failed!\n");
			return 1;
		}


		printfkernel("[jkpatch] all done on 455\n");

	}

	return 0;

}

int install_payload505(struct thread *td, void *payload, size_t psize) {

	void* kbase = 0;
	uint8_t* kernel_ptr;

	uint64_t fw_version = 0x999;

		kbase = &((uint8_t*)__readmsr(0xC0000082))[-KERN_505_XFAST_SYSCALL];
		int(*printfkernel)(const char *fmt, ...) = (void *)(kbase + 0x436040);
		fw_version = 0x505;

	vm_offset_t(*kmem_alloc)(vm_map_t map, vm_size_t size) = (void *)(kbase + __kmem_alloc505);
	vm_map_t kernel_map = *(vm_map_t *)(kbase + __kernel_map505);

	size_t msize = 0;
	if (elf_mapped_size(payload, &msize)) {
		printfkernel("[jkpatch] install_payload: elf_mapped_size failed!\n");
		return 1;
	}

	int s = (msize + 0x3FFFull) & ~0x3FFFull;


	void *payloadbase = (void *)kmem_alloc(kernel_map, s);
	if (!payloadbase) {
		printfkernel("kmem_alloc failed!\n");
		// need to set protection back to VM_PROT_DEFAULT...
		return 1;
	}


	// load the elf
	int r = 0;
	int(*payload_entry)(void *p);

	if ((r = load_elf(payload, psize, payloadbase, msize, (void **)&payload_entry))) {
		printfkernel("load_elf failed (r: %i)!\n", r);
		return 1;
	}



	// call entry
	if (payload_entry(NULL)) {
		return 1;
	}

	printfkernel("[jkpatch] + [Syscall 9] loaded at 0x%llX\n", payloadbase);

	return 0;
}

int jkpatch1()
{

	uint64_t fw_version = get_fw_version();

		if (fw_version == 0x505)
		{
			syscall(11, jkpatch, kpayload505, kpayload505_size);
		}

		else if (fw_version == 0x455)
		{
			syscall(11, jkpatch, kpayload455, kpayload455_size);
		}
		else return -1;

		klog("FW_VER is :0x%02X\n", fw_version);

		return 0;
}

int syscall9elf()
{

	uint64_t fw_version = get_fw_version();

	if (fw_version == 0x505)
	{
		syscall(11, jkpatch, syscall9505, syscall9505_size);
	}

	else if (fw_version == 0x455)
	{
		syscall(11, jkpatch, syscall9455, syscall9455_size);
	}
	else return -1;

	klog("FW_VER is :0x%02X\n", fw_version);

	return 0;
}

int dec_pups()
{

	decrypt_pups();
	return 0;
}




/*void kernel_syscall_install(int num, void *call, int narg)
{


	void* kbase = 0;
	uint8_t* kernel_ptr;

	uint64_t fw_version = 0x999;

	if (!memcmp((char*)(&((uint8_t*)__readmsr(0xC0000082))[-KERN_505_XFAST_SYSCALL]), (char[4]) { 0x7F, 0x45, 0x4C, 0x46 }, 4)) {

		kbase = &((uint8_t*)__readmsr(0xC0000082))[-KERN_505_XFAST_SYSCALL];
		fw_version = 0x505;

	}

	else if (!memcmp((char*)(&((uint8_t*)__readmsr(0xC0000082))[-KERN_455_XFAST_SYSCALL]), (char[4]) { 0x7F, 0x45, 0x4C, 0x46 }, 4)) {

		kbase = &((uint8_t*)__readmsr(0xC0000082))[-KERN_455_XFAST_SYSCALL];

		fw_version = 0x455;
	}

	else if (!memcmp((char*)(&((uint8_t*)__readmsr(0xC0000082))[-KERN_455_XFAST_SYSCALL]), (char[4]) { 0x7F, 0x45, 0x4C, 0x46 }, 4)) {

		kbase = &((uint8_t*)__readmsr(0xC0000082))[-KERN_455_XFAST_SYSCALL];

		fw_version = 0x455;

	}

	else if (fw_version == 0x455) {

		// Kernel pointers resolving

		kernel_ptr = (uint8_t*)kbase;



	}
	else if (fw_version == 0x505) {

		kernel_ptr = (uint8_t*)kbase;

	}

	int(*k_gg);

#define r(name, offset) name = (void *)(kbase + offset)
	r(k_malloc, __malloc505);
	r(k_free, __free505);
	r(k_memcpy, __memcpy505);
	r(k_memset, __memset505);
	r(k_memcmp, __memcmp505);
	r(k_gg, 0x0107c610);
	r(k_strlen, __strlen505);

	struct sysent_t *sy = k_gg[num];

	//sched_pin();
	cpu_disable_wp();

	k_memset(sy, 0, sizeof(*sy));
	sy->sy_narg = narg;
	sy->sy_call = call;
	sy->sy_thrcnt = 1;

	cpu_enable_wp();
	//sched_unpin();
}*/

struct {
	int handle;
	int handle__pad;
	char* symbol;
	char* lib;
	unsigned int flags;
	void** addr;
} dlsym;

#include "sparse.h"

typedef uint16_t au_event_t;

typedef int sy_call_t(struct thread*, void* uap);

typedef void(*systrace_args_func_t)(int, void*, uint64_t*, int*);

#define SIZEOF_SYSENT 0x30



#define SYS_UNJAIL 9

#define MAX_SYSCALLS   15

static inline int set_syscall_handler(int n, void* handler, int nargs) {
	struct sysent_t* ent;
	struct sysent_t *k_sysent;

	void* kbase = &((uint8_t*)__readmsr(0xC0000082))[-KERN_505_XFAST_SYSCALL];

#define r(name, offset) name = (void *)(kbase + offset)

		int(*printfkernel)(const char *fmt, ...) = (void *)(kbase + KERN_505_PRINTF);

		r(k_sysent, kern_off_sysent);


	

	void* (*kmemset)(void *s, int c, size_t n) = (void *)(kbase + 0x003205C0);

	if (n > MAX_SYSCALLS)
		return 0;
	cpu_disable_wp();
	//kernel_resolve("sysent");
	//kmemset(k_sysent, 0, sizeof(*k_sysent));
	ent = k_sysent + n;
	ent->sy_narg = nargs;
	ent->sy_call = (sy_call_t*)handler;
	cpu_enable_wp();


	return 0;
}

#define kdlsym_addr_kernel_map	

#define kern_off_pml4pml4i505 0x22CB560 // Pending verification.
#define kern_off_dmpml4i505 0x22CB564
#define kern_off_dmpdpi505 0x22CB568

void kernel_syscall_installs(int num, void *call, int narg)
{

	void* kbase = &((uint8_t*)__readmsr(0xC0000082))[-KERN_505_XFAST_SYSCALL];
	int(*printfkernel)(const char *fmt, ...) = (void *)(kbase + 0x436040);
	void(*pmap_protect)(pmap_t pmap, uint64_t sva, uint64_t eva, u8 pr) = (void *)(kbase + 0x2E3090);

#define rrr(name, offset) name = (void *)(kbase + offset)
	rrr(kern.sysent, kern_off_sysent);
	rrr(kern.sched_pin, kern_off_sched_pin);
	rrr(kern.sched_unpin, kern_off_sched_unpin);
	struct sysent_t *sy = &kern.sysent[num];

	kern.sched_pin();
	cpu_disable_wp();

	memset(sy, 0, sizeof(*sy));
	sy->sy_narg = narg;
	sy->sy_call = call;
	sy->sy_thrcnt = 1;
	kern.sched_unpin();
}

//extern u8 _start[], _end[];

static int patch_pmap_check(void)
{
	u8 *p;

	void* kbase = &((uint8_t*)__readmsr(0xC0000082))[-KERN_505_XFAST_SYSCALL];
	int(*printfkernel)(const char *fmt, ...) = (void *)(kbase + 0x436040);
	void(*pmap_protect)(pmap_t pmap, uint64_t sva, uint64_t eva, u8 pr) = (void *)(kbase + 0x2E3090);

#define rrr(name, offset) name = (void *)(kbase + offset)
	rrr(pmap_protect, kern_off_pmap_protect);

	for (p = (u8*)pmap_protect;
		p < ((u8*)pmap_protect + 0x500); p++) {
		if (!memcmp(p, "\xB8\x06\x00\x00\x00\xC4", 6)) {
			p[1] = 0;
			printfkernel("pmap_protect patch successful (found at %p)\n", p);
			return 1;
		}
	}
	printfkernel("pmap_protect patch failed!\n");
	return 0;
}


int kernel_inits()
{

	void *kbase = 0;
	uint8_t* kernel_ptr;
	typedef unsigned int km_flag_t;

	uint64_t fw_version = 0x999;

	if (!memcmp((char*)(&((uint8_t*)__readmsr(0xC0000082))[-KERN_505_XFAST_SYSCALL]), (char[4]) { 0x7F, 0x45, 0x4C, 0x46 }, 4)) {

		kbase = &((uint8_t*)__readmsr(0xC0000082))[-KERN_505_XFAST_SYSCALL];

		fw_version = 0x505;

	}

	else if (!memcmp((char*)(&((uint8_t*)__readmsr(0xC0000082))[-KERN_455_XFAST_SYSCALL]), (char[4]) { 0x7F, 0x45, 0x4C, 0x46 }, 4)) {

		kbase = &((uint8_t*)__readmsr(0xC0000082))[-KERN_455_XFAST_SYSCALL];

		fw_version = 0x455;
	}

	else if (!memcmp((char*)(&((uint8_t*)__readmsr(0xC0000082))[-KERN_455_XFAST_SYSCALL]), (char[4]) { 0x7F, 0x45, 0x4C, 0x46 }, 4)) {

		kbase = &((uint8_t*)__readmsr(0xC0000082))[-KERN_405_XFAST_SYSCALL];

		int(*printfkernel)(const char *fmt, ...) = (void *)(kbase + KERN_455_PRINTF);

		fw_version = 0x455;

	}
	else if (!memcmp((char*)(&((uint8_t*)__readmsr(0xC0000082))[-KERN_405_XFAST_SYSCALL]), (char[4]) { 0x7F, 0x45, 0x4C, 0x46 }, 4)) {
		fw_version = 0x405;

	}
	else return -1;

	if (fw_version == 0x505) {

		int(*printfkernel)(const char *fmt, ...) = (void *)(kbase + 0x436040);
		printfkernel("FW Version 5.05 Detected\n");
	}

	else if (fw_version == 0x405) {

		int(*printfkernel)(const char *fmt, ...) = (void *)(kbase + KERN_405_PRINTF);
		printfkernel("FW Version 4.05 Detected\n");

	}
	else if (fw_version == 0x455) {

		int(*printfkernel)(const char *fmt, ...) = (void *)(kbase + KERN_455_PRINTF);
		printfkernel("FW Version 4.55 Detected\n");

	}
	else if (fw_version == 0x501) {

		int(*printfkernel)(const char *fmt, ...) = (void *)(kbase + KERN_501_PRINTF);
		printfkernel("FW Version 5.05 Detected\n");
	}
	else return -1;

	/////////////////////////////////////
	uint64_t DMPML4I = *(u32 *)(kbase + kern_off_dmpml4i505);
	uint64_t DMPDPI = *(u32 *)(kbase + kern_off_dmpdpi505);

	kern.dmap_base = KVADDR(DMPML4I, DMPDPI, 0, 0);


#define rrr(name, offset) name = (void *)(kbase + offset)
	rrr(kern.sched_pin, kern_off_sched_pin);
	rrr(kern.sched_unpin, kern_off_sched_unpin);


	// We may not be mapped writable yet, so to be able to write to globals
	// we need WP disabled.
	uint64_t flags = intr_disable();
	cpu_disable_wp();

	// Pin ourselves as soon as possible. This is expected to be released by the caller.
	//void(*sched_pin)(void) = (void *)(kbase + 0x31ff40);
	kern.sched_pin();

	// kernel_remap may need interrupts, but may not write to globals!
	enable_interrupts();
	//kernel_remap(_start, _end, 7);
	patch_pmap_check();
	disable_interrupts();
	////////////

	// Writing to globals is now safe.

	if (fw_version == 0x505) {

		int(*printfkernel)(const char *fmt, ...) = (void *)(kbase + 0x436040);
		printfkernel("Direct map base = %llx\n", kern.dmap_base);
		printfkernel("Testing global variable access (write protection)...\n");
		_global_test = 1;
		printfkernel("OK.\n");

		printfkernel("Kernel interface initialized\n");
	}

	else if (fw_version == 0x405) {

		int(*printfkernel)(const char *fmt, ...) = (void *)(kbase + KERN_405_PRINTF);
		printfkernel("FW Version 4.05 Detected\n");

	}
	else if (fw_version == 0x455) {

		int(*printfkernel)(const char *fmt, ...) = (void *)(kbase + KERN_455_PRINTF);
		printfkernel("FW Version 4.55 Detected\n");

	}
	else if (fw_version == 0x501) {

		int(*printfkernel)(const char *fmt, ...) = (void *)(kbase + KERN_501_PRINTF);
		printfkernel("FW Version 5.05 Detected\n");
	}
	else return -1;


	return 0;
}

void* rwx_kalloc(int size) {
	uint8_t* ptrKernel = (uint8_t *)(__readmsr(0xC0000082) - KERN_XFAST_SYSCALL);

	int fsize = (size + 0x3FFFull) & ~0x3FFFull;

	vm_offset_t(*kmem_alloc)(vm_map_t map, vm_size_t size) = (void *)&ptrKernel[KERN_KMEM_ALLOC];
	vm_map_t kernel_map = *(vm_map_t *)(void *)&ptrKernel[KERN_KERNEL_MAP];

	return (void*)kmem_alloc(kernel_map, fsize);
}

static int k_copyins(const void *uaddr, void *kaddr, size_t len)
{
	void *kbase = &((uint8_t*)__readmsr(0xC0000082))[-KERN_505_XFAST_SYSCALL];

	void* (*kmemcpy)(void *destination, const void * source, size_t num) = (void *)(kbase + 0x1EA530);

	if (!uaddr || !kaddr)
		return EFAULT;
	kmemcpy(kaddr, uaddr, len);
	return 0;
}

#define	M_WAITOK 0x0002
#define	M_ZERO   0x0100

#define	VM_MEMATTR_DEFAULT		0x06

typedef uint64_t vm_paddr_t;
typedef uint64_t vm_offset_t;
typedef uint64_t vm_size_t;
typedef void * vm_map_t;
typedef char vm_memattr_t;
typedef void * pmap_t;

void *kernel_alloc_contig(size_t size)
{

	uint8_t* kbase = (uint8_t *)(__readmsr(0xC0000082) - KERN_XFAST_SYSCALL);


#define rrr(name, offset) name = (void *)(kbase + offset)
	rrr(kern.kmem_alloc_contig, kern_off_kmem_alloc_contig);
	rrr(kern.kernel_map, kern_off_kernel_map);
	rrr(kern.printf, kern_off_printf);
	rrr(kern.kernel_pmap_store, kern_off_kernel_pmap_store);
	rrr(kern.pmap_extract, kern_off_pmap_extract);


	// use kmem_alloc_contig instead of contigalloc to avoid messing with a malloc_type...
	vm_offset_t ret = kern.kmem_alloc_contig(
		*kern.kernel_map, size, M_ZERO | M_WAITOK, (vm_paddr_t)0,
		~(vm_paddr_t)0, 1, 0, VM_MEMATTR_DEFAULT);

	if (!ret) {
		kern.printf("Failed to allocate %zud bytes\n", size);
		return NULL;
	}
	return (void *)PA_TO_DM(kern.pmap_extract(kern.kernel_pmap_store, ret));
}


int rrrr()
{

	//kernel_inits();

	void *kbase = &((uint8_t*)__readmsr(0xC0000082))[-KERN_505_XFAST_SYSCALL];

	int(*printfkernel)(const char *fmt, ...) = (void *)(kbase + KERN_505_PRINTF);

	//5.05
	int(*k_copyin)(const void *uaddr, void *kaddr, size_t len) = (void *)(kbase + 0x001EA710);//0x1ea710

	void *(*k_malloc)(uint64_t size, void *area, uint64_t flags) = (void *)(kbase + 0x10E250);//0x10E250 //0x0010E250
	vm_offset_t(*kmem_alloc)(vm_map_t map, vm_size_t size) = (void *)(kbase + 0x000FCC80);
	void* (*kmemcpy)(void *destination, const void * source, size_t num) = (void *)(kbase + 0x1EA530);
	void* (*kmemset)(void *s, int c, size_t n) = (void *)(kbase + 0x003205C0);

	cpu_disable_wp();

	kmemcpy((void *)(kbase + 0x1A3C08), "\x90\x90\x90\x90\x90\x90", 6);

	vm_offset_t(*kmem_allocs)(vm_map_t map, vm_size_t size) = (void *)(kbase + __kmem_alloc505);
	vm_map_t kernel_map = *(vm_map_t *)(kbase + __kernel_map505);

	*(uint8_t *)(kbase + 0x7673E0) = 0xC3;

	*(uint8_t *)(kbase + 0xFCD48) = 7; // VM_PROT_ALL;
	*(uint8_t *)(kbase + 0xFCD56) = 7; // VM_PROT_ALL;

	//kernel_remap(_start, _end, 7);

	void *buf = (void*)kernel_alloc_contig(0x4000);
	if (!buf)
	{
		printfkernel("failed :(");
	}

	printfkernel("addr: %p", buf);

	k_copyins(sys_unjail, buf, 0x4000);

	kernel_syscall_installs(9, buf, 0);
	return 0;
}



int call_me()
{
	//uint8_t* bufz;
	void *kbase = 0;
	uint8_t* kernel_ptr;
	typedef unsigned int km_flag_t;

	uint64_t fw_version = 0x999;

	if (!memcmp((char*)(&((uint8_t*)__readmsr(0xC0000082))[-KERN_505_XFAST_SYSCALL]), (char[4]) { 0x7F, 0x45, 0x4C, 0x46 }, 4)) {

		kbase = &((uint8_t*)__readmsr(0xC0000082))[-KERN_505_XFAST_SYSCALL];

		fw_version = 0x505;

	}

	else if (!memcmp((char*)(&((uint8_t*)__readmsr(0xC0000082))[-KERN_455_XFAST_SYSCALL]), (char[4]) { 0x7F, 0x45, 0x4C, 0x46 }, 4)) {

		kbase = &((uint8_t*)__readmsr(0xC0000082))[-KERN_455_XFAST_SYSCALL];

		fw_version = 0x455;
	}

	else if (!memcmp((char*)(&((uint8_t*)__readmsr(0xC0000082))[-KERN_455_XFAST_SYSCALL]), (char[4]) { 0x7F, 0x45, 0x4C, 0x46 }, 4)) {

		kbase = &((uint8_t*)__readmsr(0xC0000082))[-KERN_405_XFAST_SYSCALL];

		int(*printfkernel)(const char *fmt, ...) = (void *)(kbase + KERN_455_PRINTF);

		fw_version = 0x455;

	}
	else if (!memcmp((char*)(&((uint8_t*)__readmsr(0xC0000082))[-KERN_405_XFAST_SYSCALL]), (char[4]) { 0x7F, 0x45, 0x4C, 0x46 }, 4)) {
		fw_version = 0x405;

	}
	else return -1;


	// potentially needed to write early_printf
	uint64_t flags = intr_disable();
	cpu_disable_wp();


	if (fw_version == 0x505)
	{


		kbase = &((uint8_t*)__readmsr(0xC0000082))[-KERN_505_XFAST_SYSCALL];
		kernel_ptr = (uint8_t*)kbase;

		int(*printfkernel)(const char *fmt, ...) = (void *)(kbase + KERN_505_PRINTF);
		printfkernel("Syscall Install Started\n");

		//5.05
		int(*k_copyin)(const void *uaddr, void *kaddr, size_t len) = (void *)(kbase + 0x001EA710);//0x1ea710

		void *(*k_malloc)(uint64_t size, void *area, uint64_t flags) = (void *)(kbase + 0x10E250);//0x10E250 //0x0010E250
		vm_offset_t(*kmem_alloc)(vm_map_t map, vm_size_t size) = (void *)(kbase + 0x000FCC80);
		void* (*kmemcpy)(void *destination, const void * source, size_t num) = (void *)(kbase + 0x1EA530);
		void* (*kmemset)(void *s, int c, size_t n) = (void *)(kbase + 0x003205C0);


		kmemcpy((void *)(kbase + 0x1A3C08), "\x90\x90\x90\x90\x90\x90", 6);



		printfkernel("next\n");
		//void *addr = k_malloc(0x1000, 0, 0);//0xFCC80

		vm_offset_t(*kmem_allocs)(vm_map_t map, vm_size_t size) = (void *)(kbase + __kmem_alloc505);
		vm_map_t kernel_map = *(vm_map_t *)(kbase + __kernel_map505);

		int s = (0x1000 + 0x3FFFull) & ~0x3FFFull;
		*(uint8_t *)(kbase + 0x7673E0) = 0xC3;

		*(uint8_t *)(kbase + 0xFCD48) = 7; // VM_PROT_ALL;
		*(uint8_t *)(kbase + 0xFCD56) = 7; // VM_PROT_ALL;

		printfkernel("neqxt\n");
		void *bufz = (void*)rwx_kalloc(0x2000);
		//void *addr = k_malloc(0x1000, 0, 0);
		if (!bufz) {
			printfkernel(" mem alloc failed! \n");
			return -1;
		}

		printfkernel("rrrr\n");


		printfkernel("addr = %p\n", bufz);

		int copyResult = kmemcpy(bufz, sys_unjail, 0x2000);
		if (copyResult != 0)
		{
			printfkernel("kmemcpy is fucked up trying copyin\n");
			int copyin = k_copyin(sys_unjail,bufz, 0x2000);

			if (copyin = 0)
			{

				printfkernel("Copyin Worked\n");

			}

			if (copyin != 0)
			{

				printfkernel("copyin is fucked up, Noping \n");
				__asm__("nop");

			}

			
		}


		int buffers = bufz;
		if (buffers = 0)
		{
			printfkernel("Buffer is NULL\n");
			__asm("nop");
		}

		printfkernel("Installing sys_unjail to system call #%d\n", SYS_KEXEC);
		//kernel_syscall_install(SYS_KEXEC, sys_unjail, SYS_KEXEC_NARGS);
		set_syscall_handler(9, sys_unjail, 0);
		printfkernel("sys_unjail successful\n\n");

	}

	else if (fw_version == 0x455)
	{
		kbase = &((uint8_t*)__readmsr(0xC0000082))[-KERN_455_XFAST_SYSCALL];
		int(*printfkernel)(const char *fmt, ...) = (void *)(kbase + KERN_455_PRINTF);

		//4.55
		int(*k_copyin)(const void *uaddr, void *kaddr, size_t len) = (void *)(kbase + 0x0014A890);
		printfkernel("Syscall Install Started\n");

		void *(*k_malloc)(unsigned long size, void *type, int flags) = (void *)(kbase + 0x3F7750);


		void *addr = k_malloc(0x1000, 0, 0);
		k_copyin(&sys_unjail, addr, 0x1000);


	}
	else return -1;

	//set_syscall_handler(SYS_UNJAIL, &bufz, 8);

	return 0;
}




int Syscall_Thread()
{
//return jkpatch2();
}


int install_sys()
{

	/*ScePthread m_thread;
	ScePthreadAttr threadAttr;
	scePthreadAttrInit(&threadAttr);

	scePthreadCreate(&m_thread, &threadAttr, Syscall_Thread, NULL , "Syscall_9_Thread");

	scePthreadJoin(m_thread, NULL);

	scePthreadAttrDestroy(&threadAttr);*/



	//syscall(11, call_me);
	jkpatch1();
	//syscall(11, sys_unjail1);


	return 0;
}


#include "defines.h"
#include "debug.h"

#define PS4_UPDATE_FULL_PATH "/update/PS4UPDATE.PUP"
#define PS4_UPDATE_TEMP_PATH "/update/PS4UPDATE.PUP.net.temp"

#define	KERN_XFAST_SYSCALL	0x1C0		// 5.05
#define KERN_PRISON_0		0x10986A0
#define KERN_ROOTVNODE		0x22C1A70

#define KERN_PMAP_PROTECT	0x2E3090
#define KERN_PMAP_PROTECT_P	0x2E30D4
#define KERN_PMAP_STORE		0x22CB570

#define DT_HASH_SEGMENT		0xB5EF30

extern char HENPatches[];
unsigned HENPatches_size;

struct payload_infos
{
	uint8_t* buffer;
	size_t size;
};

struct payload_headers
{
	uint64_t signature;
	size_t entrypoint_offset;
};

struct install_payload_argss
{
	void* syscall_handler;
	struct payload_infos* payload_infos;
};

int install_payload(struct thread *td, struct install_payload_argss* args)
{
	struct ucred* cred;
	struct filedesc* fd;

	fd = td->td_proc->p_fd;
	cred = td->td_proc->p_ucred;

	uint8_t* kernel_base = (uint8_t*)(__readmsr(0xC0000082) - KERN_XFAST_SYSCALL);
	uint8_t* kernel_ptr = (uint8_t*)kernel_base;
	void** got_prison0 = (void**)&kernel_ptr[KERN_PRISON_0];
	void** got_rootvnode = (void**)&kernel_ptr[KERN_ROOTVNODE];

#define r(name, offset) name = (void *)(kernel_base + offset)
	r(k_malloc, __malloc505);
	r(k_free, __free505);
	r(k_memcpy, __memcpy505);
	r(k_memset, __memset505);

	void(*pmap_protect)(void * pmap, uint64_t sva, uint64_t eva, uint8_t pr) = (void *)(kernel_base + KERN_PMAP_PROTECT);
	void *kernel_pmap_store = (void *)(kernel_base + KERN_PMAP_STORE);

	uint8_t* payload_data = args->payload_infos->buffer;
	size_t payload_size = args->payload_infos->size;
	struct payload_headers* payload_header = (struct payload_headers*)payload_data;
	uint8_t* payload_buffers = (uint8_t*)&kernel_base[DT_HASH_SEGMENT];

	if (!payload_data ||
		payload_size < sizeof(payload_header) ||
		payload_header->signature != 0x5041594C4F414458ull)
	{
		return -1;
	}

	cred->cr_uid = 0;
	cred->cr_ruid = 0;
	cred->cr_rgid = 0;
	cred->cr_groups[0] = 0;

	cred->cr_prison = *got_prison0;
	fd->fd_rdir = fd->fd_jdir = *got_rootvnode;

	// escalate ucred privs, needed for access to the filesystem ie* mounting & decrypting files
	void *td_ucred = *(void **)(((char *)td) + 304); // p_ucred == td_ucred

													 // sceSblACMgrIsSystemUcred
	uint64_t *sonyCred = (uint64_t *)(((char *)td_ucred) + 96);
	*sonyCred = 0xffffffffffffffff;

	// sceSblACMgrGetDeviceAccessType
	uint64_t *sceProcType = (uint64_t *)(((char *)td_ucred) + 88);
	*sceProcType = 0x3801000000000013; // Max access

									   // sceSblACMgrHasSceProcessCapability
	uint64_t *sceProcCap = (uint64_t *)(((char *)td_ucred) + 104);
	*sceProcCap = 0xffffffffffffffff; // Sce Process

									  // Disable write protection
	cpu_disable_wp();


	// install kpayload
	k_memset(payload_buffers, 0, PAGE_SIZE);
	k_memcpy(payload_buffers, payload_data, payload_size);

	uint64_t sss = ((uint64_t)payload_buffers) & ~(uint64_t)(PAGE_SIZE - 1);
	uint64_t eee = ((uint64_t)payload_buffers + payload_size + PAGE_SIZE - 1) & ~(uint64_t)(PAGE_SIZE - 1);
	kernel_base[KERN_PMAP_PROTECT_P] = 0xEB;
	pmap_protect(kernel_pmap_store, sss, eee, 7);
	kernel_base[KERN_PMAP_PROTECT_P] = 0x75;

	// Restore write protection
	cpu_disable_wp();

	int(*payload_entrypoint)();
	*((void**)&payload_entrypoint) =
		(void*)(&payload_buffers[payload_header->entrypoint_offset]);

	return payload_entrypoint();
}


int HENPatch()
{

	struct payload_infos payload_infos;
	payload_infos.buffer = (uint8_t *)HENPatches;
	payload_infos.size = (size_t)HENPatches_size;

	 kexecsx(&install_payload, &payload_infos);

	return 0;
}


int buzzer1beep()
{
	char mode = 6;
	int fd = open("/dev/icc_indicator", 777, SCE_KERNEL_O_RDONLY);
	if (!fd)
	{
		klog("FD Failed");
	}

	int io = ioctlss(fd, 0x80019501, &mode);
	klog("ioctl:%i\n", io);

	/*Modes
	0 (nothing ? )
	1 (single beep)
	2 (short beeps)
	3(long beep)
	4(longs beeps)
	5(short beep, long beep)
	6(never stops beeping)
	7 (? Stopped testing)*/
}

int fantest1()
{
	char mode = 6;
	int fd = open("/dev/icc_fan", 777, SCE_KERNEL_O_RDONLY);
	if (!fd)
	{
		klog("FD Failed");
	}

	int io = ioctlss(fd, 0xC01C8F08, 0);
	klog("ioctl:%i\n", io);

	/*Modes
	0 (nothing ? )
	1 (single beep)
	2 (short beeps)
	3(long beep)
	4(longs beeps)
	5(short beep, long beep)
	6(never stops beeping)
	7 (? Stopped testing)*/
}

int fantest2()
{
	char mode = 1;
	int fd = open("/dev/icc_fan", 777, SCE_KERNEL_O_RDONLY);
	if (!fd)
	{
		klog("FD Failed");
	}

	int io = ioctlss(fd, 0xC0148F02, &mode);
	klog("ioctl:%i\n", io);

	/*Modes
	0 (nothing ? )
	1 (single beep)
	2 (short beeps)
	3(long beep)
	4(longs beeps)
	5(short beep, long beep)
	6(never stops beeping)
	7 (? Stopped testing)*/
}

int PS4LEDTEST()
{
	char mode = 6;
	int fd = open("/dev/icc_indicator", 777, SCE_KERNEL_O_RDONLY);
	if (!fd)
	{
		klog("FD Failed");
	}

	//Blue LED 0x2000950A
	int io = ioctlss(fd, 0x2000950C, 0x0);
	klog("ioctl:%i\n", io);

	/*Modes
	0 (nothing ? )
	1 (single beep)
	2 (short beeps)
	3(long beep)
	4(longs beeps)
	5(short beep, long beep)
	6(never stops beeping)
	7 (? Stopped testing)*/
}



int HENorNah()
{
	uint64_t fw_version = get_fw_version();

	if (fw_version == 0x505)
	{
		klog("/*\n");
		klog("*Compatible FW Detected :0x%02X\n", fw_version);
		klog("*\n");
		klog("*Running Setup\n");
		klog("*/\n");
		HENPatch();
		klog("Applied FSelf Spawning Patches\n");
	}

	else if (fw_version == 0x455)
	{
		klog("/*\n");
		klog("*InCompatible FW Detected :0x%02X\n", fw_version);
		klog("*\n");
		klog("*Setup Failed\n");
		klog("*/\n");
	}
	else return -1;

	klog("FW_VER is :0x%02X\n", fw_version);

	return 0;
}

int elfloader()
{

	return 0;
}

int tryweb()
{
	initWebServer();
	klog("webserver init\n");
	//addCall("/test", test_call);
	set404error("<h1>Holy sh*t !</h1><p>i doesn't find %s on this server</p>");
	klog("404 set\n");

	launchWebServer();
	klog("webserver launched\n");
	return 0;
}

int remoteplaypatch()
{

	uint64_t fw_version = get_fw_version();

	int moduleId = -1;
	sys_dynlib_load_prx("libSceSysUtil.sprx", &moduleId);


	// This header doesn't work in > 5.00
	int(*sceSysUtilSendSystemNotificationWithText)(int messageType, char* message) = NULL;

	sys_dynlib_dlsym(moduleId, "sceSysUtilSendSystemNotificationWithText", &sceSysUtilSendSystemNotificationWithText);


	if (fw_version == 0x505)
	{

			//syscall(11, jkpatch, remoteplay505, remoteplay505_size);
		buzzer1beep();


	}
	else
	{
		not505();
	}


	return 0;
}


int psxloader()
{
	/*int fd = open("/data/orbislink/", O_RDONLY, 777);
	if (!fd)
	{
		mkdir("/data/orbislink/", 777);
	}
	else if (fd)
	{
		rmdir("/data/orbislink/");
		mkdir("/data/orbislink/", 777);
	}*/

	decrypt_and_dump_self("/mnt/sandbox/NPXX33392_000/app0/Media/Elf/homebrew.elf", "/data/orbislink/homebrew.elf");
}