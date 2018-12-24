#define _WANT_UCRED
#define _XOPEN_SOURCE 700
#define __BSD_VISIBLE 1
#define X86_CR0_WP (1 << 16)

#include "unjail.h"
#include "x86-64.h"
#include <stdio.h>
#include "magics.h"
#include "lv2.h"
#include "elf64.h"
#include "elf_common.h"
#include "Modded_SDK\libPS4\include\ps4.h"

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

#define TRUE 1
#define FALSE 0

typedef struct {
	int index;
	uint64_t fileoff;
	size_t bufsz;
	size_t filesz;
} SegmentBufInfo;


void hexdump(uint8_t *raw, size_t size) {
	for (int i = 1; i <= size; i += 1) {
		//printf("%02X ", raw[i - 1]);
		if (i % 16 == 0) {
			//printf("\n");
		}
	}
}


void print_phdr(Elf64_Phdr *phdr) {
	//printf("=================================\n");
	//printf("     p_type %08x\n", phdr->p_type);
	//printf("     p_flags %08x\n", phdr->p_flags);
	//printf("     p_offset %016llx\n", phdr->p_offset);
	//printf("     p_vaddr %016llx\n", phdr->p_vaddr);
	//printf("     p_paddr %016llx\n", phdr->p_paddr);
	//printf("     p_filesz %016llx\n", phdr->p_filesz);
	//printf("     p_memsz %016llx\n", phdr->p_memsz);
	//printf("     p_align %016llx\n", phdr->p_align);
}


void dumpfile(char *name, uint8_t *raw, size_t size) {
	FILE *fd = fopen(name, "wb");
	if (fd != NULL) {
		fwrite(raw, 1, size, fd);
		fclose(fd);
	}
	else {
		//printf("dump err.\n");
	}
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
		//printf("mmap segment [%d] err(%d) : %s\n", index, errno, strerror(errno));
		return FALSE;
	}
}



int is_segment_in_other_segment(Elf64_Phdr *phdr, int index, Elf64_Phdr *phdrs, int num) {
	for (int i = 0; i < num; i += 1) {
		Elf64_Phdr *p = &phdrs[i];
		if (i != index) {
			if (p->p_filesz > 0) {
				// //printf("offset : %016x,  toffset : %016x\n", phdr->p_offset, p->p_offset);
				// //printf("offset : %016x,  toffset + size : %016x\n", phdr->p_offset, p->p_offset + p->p_filesz);
				if ((phdr->p_offset >= p->p_offset) && ((phdr->p_offset + phdr->p_filesz) <= (p->p_offset + p->p_filesz))) {
					return TRUE;
				}
			}
		}
	}
	return FALSE;
}


SegmentBufInfo *parse_phdr(Elf64_Phdr *phdrs, int num, int *segBufNum) {
	//printf("segment num : %d\n", num);
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

				// //printf("seg buf info %d -->\n", segindex);
				// //printf("    index : %d\n    bufsz : 0x%016llX\n", info->index, info->bufsz);
				// //printf("    filesz : 0x%016llX\n    fileoff : 0x%016llX\n", info->filesz, info->fileoff);
			}
		}
	}
	*segBufNum = segindex;
	return infos;
}


void do_dump(char *saveFile, int fd, SegmentBufInfo *segBufs, int segBufNum, Elf64_Ehdr *ehdr) {
	FILE *sf = fopen(saveFile, "wb");
	if (sf != NULL) {
		size_t elfsz = 0x40 + ehdr->e_phnum * sizeof(Elf64_Phdr);
		//printf("elf header + phdr size : 0x%08X\n", elfsz);
		fwrite(ehdr, elfsz, 1, sf);

		for (int i = 0; i < segBufNum; i += 1) {
			//printf("sbuf index : %d, offset : 0x%016x, bufsz : 0x%016x, filesz : 0x%016x\n", segBufs[i].index, segBufs[i].fileoff, segBufs[i].bufsz, segBufs[i].filesz);
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
		//printf("fopen %s err : %s\n", saveFile, strerror(errno));
	}
}


void decrypt_and_dump_self(char *selfFile, char *saveFile) {
	int fd = open(selfFile, O_RDONLY, NULL);
	if (fd != -1) {
		void *addr = mmap(0, 0x4000, PROT_READ, MAP_PRIVATE, fd, 0);
		if (addr != MAP_FAILED) {
			//printf("mmap %s : %p\n", selfFile, addr);

			uint16_t snum = *(uint16_t*)((uint8_t*)addr + 0x18);
			Elf64_Ehdr *ehdr = (Elf64_Ehdr *)((uint8_t*)addr + 0x20 + snum * 0x20);
			//printf("ehdr : %p\n", ehdr);

			Elf64_Phdr *phdrs = (Elf64_Phdr *)((uint8_t *)ehdr + 0x40);
			//printf("phdrs : %p\n", phdrs);

			int segBufNum = 0;
			SegmentBufInfo *segBufs = parse_phdr(phdrs, ehdr->e_phnum, &segBufNum);
			do_dump(saveFile, fd, segBufs, segBufNum, ehdr);
			//printf("dump completed\n");

			free(segBufs);
			munmap(addr, 0x4000);
		}
		else {
			//printf("mmap file %s err : %s\n", selfFile, strerror(errno));
		}
	}
	else {
		//printf("open %s err : %s\n", selfFile, strerror(errno));
	}
}
