
#include "c:\Program Files (x86)\SCE\ORBIS SDKs\4.500\target\include\sys\_types\_int64_t.h"
#include "h.h"
#include "C:\Program Files (x86)\SCE\ORBIS SDKs\4.500\target\include\sys/ioccom.h"
#include <stdio.h>
#include <stdlib.h>

#include <system_service.h>
#include <orbis2d.h>
#include <orbisPad.h>
#include <orbisAudio.h>
#include <orbisKeyboard.h>
#include <modplayer.h>
#include <ps4link.h>
#include <debugnet.h>
#include <orbissys.h>
#include <pl_ini.h>
#include <string.h>

#include <elfloader.h>

#include <ps4/error.h>
#include <kernel.h>

int64_t sys_dynlib_load_prx(char* prxPath, int* moduleID)
{
	return (int64_t)syscall4(594, prxPath, 0, moduleID, 0);
}

int open(const char *path, int flags, int mode)
{
	return syscall(5, path, flags, mode);
}




int close(int fd)
{
	return syscall(6, fd);
}

ssize_t write(int fd, const void *buf, size_t count)
{
	return syscall(4, fd, buf, count);
}

off_t lseek(int fd, off_t offset, int origin)
{
	return syscall(478, fd, offset, origin);
}


ssize_t read(int fd, void *buf, size_t nbyte)
{
	return syscall(3, fd, buf, nbyte);
}

int ioctls(int fd, unsigned long com, void *data)
{
	return syscalls(54, fd, com, data);
}

int64_t sys_dynlib_unload_prx(int64_t prxID)
{
	return (int64_t)syscall1(595, (void*)prxID);
}


#define TRUE 1
#define FALSE 0

typedef struct {
	int index;
	uint64_t fileoff;
	size_t bufsz;
	size_t filesz;
	int enc;
} SegmentBufInfo;

void print_phdr(Elf64_Phdr *phdr) {
	debugNetPrintf(DEBUG, "=================================\n");
	debugNetPrintf(DEBUG, "     p_type %08x\n", phdr->p_type);
	debugNetPrintf(DEBUG, "     p_flags %08x\n", phdr->p_flags);
	debugNetPrintf(DEBUG, "     p_offset %016llx\n", phdr->p_offset);
	debugNetPrintf(DEBUG, "     p_vaddr %016llx\n", phdr->p_vaddr);
	debugNetPrintf(DEBUG, "     p_paddr %016llx\n", phdr->p_paddr);
	debugNetPrintf(DEBUG, "     p_filesz %016llx\n", phdr->p_filesz);
	debugNetPrintf(DEBUG, "     p_memsz %016llx\n", phdr->p_memsz);
	debugNetPrintf(DEBUG, "     p_align %016llx\n", phdr->p_align);
}

#define SELF_MAGIC	0x1D3D154F
#define ELF_MAGIC	0x464C457F

int is_self(const char *fn)
{
	struct stat st;
	int res = 0;
	int fd = sceKernelOpen(fn, O_RDONLY, 0);
	if (fd != -1) {
		stat(fn, &st);
		void *addr = mmap(0, 0x4000, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
		if (addr != MAP_FAILED) {
			debugNetPrintf(DEBUG, "mmap %s : %p\n", fn, addr);
			if (st.st_size >= 4)
			{
				uint32_t selfMagic = *(uint32_t*)((uint8_t*)addr + 0x00);
				if (selfMagic == SELF_MAGIC)
				{
					uint16_t snum = *(uint16_t*)((uint8_t*)addr + 0x18);
					if (st.st_size >= (0x20 + snum * 0x20 + 4))
					{
						uint32_t elfMagic = *(uint32_t*)((uint8_t*)addr + 0x20 + snum * 0x20);
						if ((selfMagic == SELF_MAGIC) && (elfMagic == ELF_MAGIC))
							res = 1;
					}
				}
			}
			sceKernelMunmap(addr, 0x4000);
		}
		else {
		}
		sceKernelClose(fd);
	}
	else {
	}

	return res;
}

#define DECRYPT_SIZE 0x10000

bool read_decrypt_segment(int fd, uint64_t index, uint64_t offset, size_t size, uint8_t *out)
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
			sceKernelMunmap(addr, bytes);
		}
		else
		{
			return FALSE;
		}
		outPtr += bytes;
		outSize -= bytes;
		realOffset += bytes;
	}
	return TRUE;
}

int is_segment_in_other_segment(Elf64_Phdr *phdr, int index, Elf64_Phdr *phdrs, int num) {
	for (int i = 0; i < num; i += 1) {
		Elf64_Phdr *p = &phdrs[i];
		if (i != index) {
			if (p->p_filesz > 0) {
				debugNetPrintf(DEBUG, "offset : %016x,  toffset : %016x\n", phdr->p_offset, p->p_offset);
				debugNetPrintf(DEBUG, "offset : %016x,  toffset + size : %016x\n", phdr->p_offset, p->p_offset + p->p_filesz);
				if ((phdr->p_offset >= p->p_offset) && ((phdr->p_offset + phdr->p_filesz) <= (p->p_offset + p->p_filesz))) {
					return TRUE;
				}
			}
		}
	}
	return FALSE;
}

SegmentBufInfo *parse_phdr(Elf64_Phdr *phdrs, int num, int *segBufNum) {
	debugNetPrintf(DEBUG, "segment num : %d\n", num);
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

				debugNetPrintf(DEBUG, "seg buf info %d -->\n", segindex);
				debugNetPrintf(DEBUG, "    index : %d\n    bufsz : 0x%016llX\n", info->index, info->bufsz);
				debugNetPrintf(DEBUG, "    filesz : 0x%016llX\n    fileoff : 0x%016llX\n", info->filesz, info->fileoff);
			}
		}
	}
	*segBufNum = segindex;
	return infos;
}

void do_dump(char *saveFile, int fd, SegmentBufInfo *segBufs, int segBufNum, Elf64_Ehdr *ehdr) {
	int sf = sceKernelOpen(saveFile, O_WRONLY | O_CREAT | O_TRUNC, 0777);
	if (sf != -1) {
		size_t elfsz = 0x40 + ehdr->e_phnum * sizeof(Elf64_Phdr);
		debugNetPrintf(DEBUG, "elf header + phdr size : 0x%08X\n", elfsz);
		sceKernelWrite(sf, ehdr, elfsz);

		for (int i = 0; i < segBufNum; i += 1) {
			debugNetPrintf(DEBUG, "sbuf index : %d, offset : 0x%016x, bufsz : 0x%016x, filesz : 0x%016x, enc : %d\n", segBufs[i].index, segBufs[i].fileoff, segBufs[i].bufsz, segBufs[i].filesz, segBufs[i].enc);
			uint8_t *buf = (uint8_t*)malloc(segBufs[i].bufsz);
			memset(buf, 0, segBufs[i].bufsz);
			if (segBufs[i].enc)
			{
				if (read_decrypt_segment(fd, segBufs[i].index, 0, segBufs[i].filesz, buf)) {
					sceKernelLseek(sf, segBufs[i].fileoff, SEEK_SET);
					sceKernelWrite(sf, buf, segBufs[i].bufsz);
				}
			}
			else
			{
				sceKernelLseek(fd, -segBufs[i].filesz, SEEK_END);
				sceKernelRead(fd, buf, segBufs[i].filesz);
				sceKernelLseek(sf, segBufs[i].fileoff, SEEK_SET);
				sceKernelWrite(sf, buf, segBufs[i].filesz);
			}
			free(buf);
		}
		sceKernelClose(sf);
	}
	else {
	}
}

void decrypt_and_dump_self(char *selfFile, char *saveFile) {
	int fd = open(selfFile, O_RDONLY, 0);
	if (fd != -1) {
		void *addr = mmap(0, 0x4000, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
		if (addr != MAP_FAILED) {
			debugNetPrintf(DEBUG, "mmap %s : %p\n", selfFile, addr);

			uint16_t snum = *(uint16_t*)((uint8_t*)addr + 0x18);
			Elf64_Ehdr *ehdr = (Elf64_Ehdr *)((uint8_t*)addr + 0x20 + snum * 0x20);
			debugNetPrintf(DEBUG, "ehdr : %p\n", ehdr);

			// shdr fix
			ehdr->e_shoff = ehdr->e_shentsize = ehdr->e_shnum = ehdr->e_shstrndx = 0;

			Elf64_Phdr *phdrs = (Elf64_Phdr *)((uint8_t *)ehdr + 0x40);
			debugNetPrintf(DEBUG, "phdrs : %p\n", phdrs);

			int segBufNum = 0;
			SegmentBufInfo *segBufs = parse_phdr(phdrs, ehdr->e_phnum, &segBufNum);
			do_dump(saveFile, fd, segBufs, segBufNum, ehdr);
			debugNetPrintf(DEBUG, "dump completed\n");

			free(segBufs);
			sceKernelMunmap(addr, 0x4000);
		}
		else {
		}
		sceKernelClose(fd);
	}
	else {
	}
}

int64_t sys_dynlib_dlsym(int64_t moduleHandle, const char* functionName, void *destFuncOffset)
{
	return (int64_t)syscall3(591, (void*)moduleHandle, (void*)functionName, destFuncOffset);
}

int loadnote()
{
	int moduleId = -1;
	sys_dynlib_load_prx("libSceSysUtil.sprx", &moduleId);


	// This header doesn't work in > 5.00
	int(*sceSysUtilSendSystemNotificationWithText)(int messageType, char* message) = 0;

	sys_dynlib_dlsym(moduleId, "sceSysUtilSendSystemNotificationWithText", &sceSysUtilSendSystemNotificationWithText);

	char* initMessage = "***Demo ONLY****\n\n ELF Loading\n\n 1 Beep Sent";
	sceSysUtilSendSystemNotificationWithText(222, initMessage);
}

int failednote()
{
	int moduleId = -1;
	sys_dynlib_load_prx("libSceSysUtil.sprx", &moduleId);


	// This header doesn't work in > 5.00
	int(*sceSysUtilSendSystemNotificationWithText)(int messageType, char* message) = 0;

	sys_dynlib_dlsym(moduleId, "sceSysUtilSendSystemNotificationWithText", &sceSysUtilSendSystemNotificationWithText);

	char* initMessage = "Loading has Failed, maybe you forgot the ELF???";
	sceSysUtilSendSystemNotificationWithText(222, initMessage);
}


/////////////////////////////////////////////////////////////////////


int buzzer1beep()
{
	char mode = 1;
	int fd = sceKernelOpen("/dev/icc_indicator", 777, 0x0000);
	if (!fd)
	{
		printf("WTF");
	}

	ioctls(fd, 0x80019501, &mode);
}

typedef struct OrbisGlobalConf
{
	Orbis2dConfig *conf;
	OrbisPadConfig *confPad;
	OrbisAudioConfig *confAudio;
	OrbisKeyboardConfig *confKeyboard;
	ps4LinkConfiguration *confLink;
	int orbisLinkFlag;
}OrbisGlobalConf;

OrbisGlobalConf globalConf;
//IV0002-NPXS29040_00-ELFLOADER0000000
//IV0002-NPXS29041_00-MSXORBIS00000000
#define SCE_LIBC_HEAP_SIZE_EXTENDED_ALLOC_NO_LIMIT (0xffffffffffffffffUL)
//size_t sceLibcHeapSize = 256 * 1024 * 1024;
size_t sceLibcHeapSize = SCE_LIBC_HEAP_SIZE_EXTENDED_ALLOC_NO_LIMIT;
unsigned int sceLibcHeapExtendedAlloc = 1;




typedef struct Ps4MemoryProtected
{
	void *writable;
	void *executable;
	size_t size;
}Ps4MemoryProtected;
int ps4MemoryProtectedCreate(Ps4MemoryProtected **memory, size_t size)
{
	int executableHandle, writableHandle;
	Ps4MemoryProtected *m;
	long pageSize = 0x4000;//sysconf(_SC_PAGESIZE);

	if (memory == NULL)
		return PS4_ERROR_ARGUMENT_PRIMARY_MISSING;

	if (size == 0)
		return PS4_ERROR_ARGUMENT_SIZE_NULL;

	m = (Ps4MemoryProtected *)malloc(sizeof(Ps4MemoryProtected));
	if (m == NULL)
		return PS4_ERROR_OUT_OF_MEMORY;

	m->size = (size / pageSize + 1) * pageSize; // align to pageSize


	m->executable = mmap(NULL, m->size, 7, 0x1000, -1, 0);
	if (m->executable == MAP_FAILED)
		goto e1;
	m->writable = m->executable;
	if (m->writable == MAP_FAILED)
		goto e1;
	*memory = m;
	return PS4_OK;

e1:
	free(m);

	return PS4_ERROR_OUT_OF_MEMORY; // make error codes proper errnos ... everywhere ... meh
}

int ps4MemoryProtectedDestroy(Ps4MemoryProtected *memory)
{
	int r = 0;
	if (memory == NULL)
		return -1;
	r |= munmap(memory->writable, memory->size);
	r |= munmap(memory->executable, memory->size);
	free(memory);
	return r;
}

int ps4MemoryProtectedGetWritableAddress(Ps4MemoryProtected *memory, void **address)
{
	if (memory == NULL)
		return PS4_ERROR_ARGUMENT_PRIMARY_MISSING;
	if (address == NULL)
		return PS4_ERROR_ARGUMENT_OUT_MISSING;
	*address = memory->writable;
	return PS4_OK;
}

int ps4MemoryProtectedGetExecutableAddress(Ps4MemoryProtected *memory, void **address)
{
	if (memory == NULL)
		return PS4_ERROR_ARGUMENT_PRIMARY_MISSING;
	if (address == NULL)
		return PS4_ERROR_ARGUMENT_OUT_MISSING;
	*address = memory->executable;
	return PS4_OK;
}

int ps4MemoryProtectedGetSize(Ps4MemoryProtected *memory, size_t *size)
{
	if (memory == NULL)
		return PS4_ERROR_ARGUMENT_PRIMARY_MISSING;
	if (size == NULL)
		return PS4_ERROR_ARGUMENT_OUT_MISSING;
	*size = memory->size;
	return PS4_OK;
}

void orbisMemorySet(void *p, unsigned char value, int size)
{

	unsigned char *buf = (unsigned char *)p;
	//for(i=0;i<size;i++)
	//{
	//	buf[i]=value;
	//}
	debugNetPrintf(3, "[ELFLOADER] orbisMemorySet before memset\n");
	memset(buf, value, size);
	debugNetPrintf(3, "[ELFLOADER] orbisMemorySet after memset\n");


}
void orbisMemoryCopy(void *to, void *from, size_t size)
{


	debugNetPrintf(DEBUG, "[ELFLOADER] orbisMemoryCopy before memcpy\n");

	memcpy(to, from, size);
	debugNetPrintf(DEBUG, "[ELFLOADER] orbisMemoryCopy after memcpy\n");

}

/* Defines */

#define elfRelocationSymbol __ELFN(R_SYM)
#define elfRelocationType __ELFN(R_TYPE)
#define elfRelocationInfo __ELFN(R_INFO)

#define elfSymbolBind __ELFN(ST_BIND)
#define elfSymbolType __ELFN(ST_TYPE)
#define elfSymbolInfo __ELFN(ST_INFO)

#define elfIsElf(e) IS_ELF(*elfHeader(e)) // FIXME: Null deref

#define elfClass(e) (e == NULL ? 0 : e->data[4])
#define elfEncoding(e) (e == NULL ? 0 : e->data[5])
#define elfVersion(e) (e == NULL ? 0 : e->data[6])
#define elfABI(e) (e == NULL ? 0 : e->data[7])

/* Constants */

enum { ELF_MAXIMAL_STRING_LENGTH = 4096 };

/* Type */

typedef struct Elf // FIXME: We could cache a lot of offsets here to inc. performance
{
	uint8_t *data;
	size_t size; // FIXME: Do more checks on size
}
Elf;

size_t elfGetSize(Elf *elf)
{
	return elf->size;
}

uint8_t *elfGetData(Elf *elf)
{
	return elf->data;
}

/* --- elf header --- */

ElfHeader *elfHeader(Elf *elf)
{
	if (!elf)
		return NULL;
	return (ElfHeader *)elf->data;
}

uint64_t elfEntry(Elf *elf)
{
	if (!elf)
		return 0;
	ElfHeader *h = elfHeader(elf);
	if (!h)
		return 0;
	return h->e_entry;
}

uint64_t elfLargestAlignment(Elf *elf) //ignore ...
{
	uint16_t index = 0;
	uint64_t alignment = 0;

	while (1)
	{
		ElfSegment *h = elfSegment(elf, &index, ELF_SEGMENT_ATTRIBUTE_TYPE, PT_LOAD);
		if (!h)
			break;

		// FIXME: Tired of bogus 2MB alignment -> ignore
		if (alignment < h->p_align && h->p_align < 0x200000)
			alignment = h->p_align;
		++index;
	}
	return alignment;
}

size_t elfMemorySize(Elf *elf)
{
	ElfSection *sections;
	ElfSegment *segments;

	uint16_t size;
	uint16_t length;
	uint16_t index;

	size_t memorySize = 0;

	if (!elf)
		return 0;

	segments = elfSegments(elf, &size, &length);
	if (segments)
	{
		for (index = 0; index < length; ++index)
		{
			ElfSegment *s = (ElfSegment *)((uint8_t *)segments + index * size);
			if (memorySize < s->p_paddr + s->p_memsz)
				memorySize = s->p_paddr + s->p_memsz;
		}
	}
	else
	{
		length = 0;
		sections = elfSections(elf, &size, &length);
		if (!sections)
			return 0;
		for (index = 0; index < length; ++index)
		{
			ElfSection *s = (ElfSection *)((uint8_t *)sections + index * size);
			if (memorySize < s->sh_addr + s->sh_size)
				memorySize = s->sh_addr + s->sh_size;
		}
	}

	return memorySize;
}

/* --- elf section header --- */

char *elfSectionStrings(Elf *elf, uint64_t *size)
{
	ElfHeader *h;
	uint16_t i;
	ElfSection *s;
	h = elfHeader(elf);
	i = h->e_shstrndx;
	s = elfSection(elf, &i, ELF_SECTION_ATTRIBUTE_NONE, 0);
	if (size)
		*size = s->sh_size;
	return (char *)elf->data + s->sh_offset;
}

uint64_t elfSectionAttribute(ElfSection *elfSection, ElfSectionAttribute attribute)
{
	switch (attribute)
	{
	case ELF_SECTION_ATTRIBUTE_NAME:
		return elfSection->sh_name;
	case ELF_SECTION_ATTRIBUTE_TYPE:
		return elfSection->sh_type;
	case ELF_SECTION_ATTRIBUTE_FLAGS:
		return elfSection->sh_flags;
	case ELF_SECTION_ATTRIBUTE_ADDRESS:
		return elfSection->sh_addr;
	case ELF_SECTION_ATTRIBUTE_OFFSET:
		return elfSection->sh_offset;
	case ELF_SECTION_ATTRIBUTE_SIZE:
		return elfSection->sh_size;
	case ELF_SECTION_ATTRIBUTE_LINK:
		return elfSection->sh_link;
	case ELF_SECTION_ATTRIBUTE_INFO:
		return elfSection->sh_info;
	case ELF_SECTION_ATTRIBUTE_MEMORY_ALIGNMENT:
		return elfSection->sh_addralign;
	case ELF_SECTION_ATTRIBUTE_ENTRY_SIZE:
		return elfSection->sh_entsize;
	default:
		break;
	}
	return 0;
}

ElfSection *elfSections(Elf *elf, uint16_t *size, uint16_t *length)
{
	ElfHeader *h;

	if (!elf)
		return NULL;

	h = elfHeader(elf);

	if (h->e_shoff == 0)
		return NULL;

	if (size != NULL)
		*size = h->e_shentsize;
	if (length != NULL)
		*length = h->e_shnum;

	return (ElfSection *)(elf->data + h->e_shoff);
}

ElfSection *elfSection(Elf *elf, uint16_t *index, ElfSectionAttribute attribute, uint64_t value)
{
	uint16_t size;
	uint16_t length;
	ElfSection *h, *t;
	uint16_t i = 0;

	if (!index)
		index = &i;

	h = elfSections(elf, &size, &length);

	if (!h)
		return NULL;

	for (; *index < length; ++(*index))
	{
		t = (ElfSection *)((uint8_t *)h + *index * size);
		if (attribute == ELF_SECTION_ATTRIBUTE_NONE || elfSectionAttribute(t, attribute) == value)
			return t;
	}

	return NULL;
}

ElfSection *elfSectionByName(Elf *elf, char *name)
{
	uint64_t size;
	char *mem = elfSectionStrings(elf, &size);

	uint32_t offset = elfStringToOffset(mem, size, name);
	ElfSection *sh = elfSection(elf, NULL, ELF_SECTION_ATTRIBUTE_NAME, offset);

	return sh;
}

/* --- elf segment header --- */

uint64_t elfSegmentAttribute(ElfSegment *elfSegment, ElfSegmentAttribute attribute)
{
	switch (attribute)
	{
	case ELF_SEGMENT_ATTRIBUTE_TYPE:
		return elfSegment->p_type;
	case ELF_SEGMENT_ATTRIBUTE_FLAGS:
		return elfSegment->p_flags;
	case ELF_SEGMENT_ATTRIBUTE_OFFSET:
		return elfSegment->p_offset;
	case ELF_SEGMENT_ATTRIBUTE_VIRTUAL_ADDRESS:
		return elfSegment->p_vaddr;
	case ELF_SEGMENT_ATTRIBUTE_PHYSICAL_ADDRESS:
		return elfSegment->p_paddr;
	case ELF_SEGMENT_ATTRIBUTE_FILE_SIZE:
		return elfSegment->p_filesz;
	case ELF_SEGMENT_ATTRIBUTE_MEMORY_SIZE:
		return elfSegment->p_memsz;
	case ELF_SEGMENT_ATTRIBUTE_ALIGNMENT:
		return elfSegment->p_align;
	default:
		break;
	}
	return 0;
}

ElfSegment *elfSegments(Elf *elf, uint16_t *size, uint16_t *length)
{
	ElfHeader *h;

	if (!elf)
		return NULL;

	h = elfHeader(elf);

	if (h->e_phoff == 0)
		return NULL;

	if (size != NULL)
		*size = h->e_phentsize;
	if (length != NULL)
		*length = h->e_phnum;

	return (ElfSegment *)(elf->data + h->e_phoff);
}

ElfSegment *elfSegment(Elf *elf, uint16_t *index, ElfSegmentAttribute attribute, uint64_t value)
{
	uint16_t size;
	uint16_t length;
	ElfSegment *h, *t;
	uint16_t i = 0;

	if (!index)
		index = &i;

	h = elfSegments(elf, &size, &length);

	if (!h)
		return NULL;

	for (; *index < length; ++(*index))
	{
		t = (ElfSegment *)((uint8_t *)h + *index * size);
		if (attribute == ELF_SEGMENT_ATTRIBUTE_NONE || elfSegmentAttribute(t, attribute) == value)
			return t;
	}

	return NULL;
}

/* --- elf dynamic section --- */

uint64_t elfDynamicAttribute(ElfDynamic *elfDynamic, ElfDynamicAttribute attribute)
{
	switch (attribute)
	{
	case ELF_DYNAMIC_ATTRIBUTE_TAG:
		return elfDynamic->d_tag;
	case ELF_DYNAMIC_ATTRIBUTE_VALUE:
		return elfDynamic->d_un.d_val;
	case ELF_DYNAMIC_ATTRIBUTE_POINTER:
		return elfDynamic->d_un.d_ptr;
	default:
		break;
	}
	return 0;
}

uint16_t elfDynamicsLength(ElfDynamic *dyn)
{
	uint16_t i = 0;
	if (dyn != NULL)
		for (; dyn->d_tag != DT_NULL; ++dyn)
			++i;
	return i;
}

ElfDynamic *elfDynamics(Elf *elf, uint16_t *size, uint16_t *length)
{
	ElfSection *h;
	ElfSegment *h2;

	if (!elf)
		return NULL;

	if ((h = elfSection(elf, NULL, ELF_SECTION_ATTRIBUTE_TYPE, SHT_DYNAMIC)))
	{
		if (size != NULL)
			*size = h->sh_entsize;
		if (length != NULL)
			*length = h->sh_size / h->sh_entsize;

		return (ElfDynamic *)(elf->data + h->sh_offset);
	}
	else if ((h2 = elfSegment(elf, NULL, ELF_SEGMENT_ATTRIBUTE_TYPE, PT_DYNAMIC)))
	{
		if (size != NULL)
			*size = sizeof(ElfDynamic);
		if (length != NULL) //h2->p_filesz / sizeof(ElfDynamic);
			*length = elfDynamicsLength((ElfDynamic *)(elf->data + h2->p_offset));

		return (ElfDynamic *)(elf->data + h2->p_offset);
	}

	return NULL;
}

ElfDynamic *elfDynamic(Elf *elf, uint16_t *index, ElfDynamicAttribute attribute, uint64_t value)
{
	uint16_t size;
	uint16_t length;
	ElfDynamic *h, *t;
	uint16_t i = 0;

	if (!index)
		index = &i;

	h = elfDynamics(elf, &size, &length);

	if (!h)
		return NULL;

	for (; *index < length; ++(*index))
	{
		t = (ElfDynamic *)((uint8_t *)h + *index * size);
		if (attribute == ELF_DYNAMIC_ATTRIBUTE_NONE || elfDynamicAttribute(t, attribute) == value)
			return t;
	}

	return NULL;
}

ElfDynamic *elfLoadedDynamics(Elf *elf, uint16_t *size, uint16_t *length)
{
	//ElfSection *h;
	ElfSegment *h2;

	if (!elf)
		return NULL;

	if ((h2 = elfSegment(elf, NULL, ELF_SEGMENT_ATTRIBUTE_TYPE, PT_DYNAMIC)))
	{
		if (size != NULL)
			*size = sizeof(ElfDynamic);
		if (length != NULL)
			*length = elfDynamicsLength((ElfDynamic *)h2->p_vaddr);

		return (ElfDynamic *)h2->p_vaddr;
	}

	return NULL;
}

ElfDynamic *elfLoadedDynamic(Elf *elf, uint16_t *index, ElfDynamicAttribute attribute, uint64_t value)
{
	uint16_t size;
	uint16_t length;
	ElfDynamic *h, *t;
	uint16_t i = 0;

	if (!index)
		index = &i;

	h = elfLoadedDynamics(elf, &size, &length);

	if (!h)
		return NULL;

	for (; *index < length; ++(*index))
	{
		t = (ElfDynamic *)((uint8_t *)h + *index * size);
		if (attribute == ELF_DYNAMIC_ATTRIBUTE_NONE || elfDynamicAttribute(t, attribute) == value)
			return t;
	}

	return NULL;
}

/* --- elf string tables --- */

char *elfStringFromIndex(char *mem, uint64_t size, uint32_t index)
{
	uint64_t i, j = 0;

	if (!mem)
		return NULL;

	if (index == 0)
		return mem;

	for (i = 0; i < size - 1; ++i)
		if (mem[i] == '\0' && ++j == index)
			return mem + i + 1;

	return NULL;
}

char *elfStringFromOffset(char *mem, uint64_t size, uint32_t offset)
{
	if (!mem || offset >= size)
		return NULL;

	return mem + offset;
}

uint32_t elfStringToOffset(char *mem, uint64_t size, char *str)
{
	uint64_t i, j;

	if (!str)
		return 0;

	for (i = 0; i < size; ++i)
	{
		for (j = 0; j < ELF_MAXIMAL_STRING_LENGTH && mem[i + j] == str[j]; ++j)
			if (str[j] == '\0')
				return i;
	}

	return 0;
}

uint32_t elfStringToIndex(char *mem, uint64_t size, char *str)
{
	uint64_t index, i, j;

	if (!str)
		return 0;

	index = 0;
	for (i = 0; i < size; ++i)
	{
		for (j = 0; j < ELF_MAXIMAL_STRING_LENGTH && mem[i + j] == str[j]; ++j)
			if (str[j] == '\0')
				return index;

		if (mem[i] == '\0')
			index++;
	}

	return 0;
}

/* --- elf relocations --- */

uint64_t elfAddendRelocationAttribute(ElfAddendRelocation *elfAddendRelocation, ElfAddendRelocationAttribute attribute)
{
	switch (attribute)
	{
	case ELF_ADDEND_RELOCATION_ATTRIBUTE_INFO:
		return elfAddendRelocation->r_info;
	case ELF_ADDEND_RELOCATION_ATTRIBUTE_OFFSET:
		return elfAddendRelocation->r_offset;
	case ELF_ADDEND_RELOCATION_ATTRIBUTE_ADDEND:
		return elfAddendRelocation->r_addend;
	default:
		break;
	}
	return 0;
}

ElfAddendRelocation *elfAddendRelocations(Elf *elf, char *name, uint16_t *size, uint16_t *length)
{
	ElfSection *h;

	h = elfSectionByName(elf, name);

	if (!h || h->sh_type != SHT_RELA)
		return NULL;

	if (size != NULL)
		*size = h->sh_entsize;
	if (length != NULL)
		*length = h->sh_size / h->sh_entsize;

	return (ElfAddendRelocation *)(elf->data + h->sh_offset);
}

// FIXME this is not performant, better to pass in the base ElfAddendRelocation *, size and length
/*
ElfAddendRelocation *elfAddendRelocation(Elf *elf, char *name, uint16_t *index, ElfAddendRelocationAttribute attribute, uint64_t value)
{
uint16_t size;
uint16_t length;
ElfAddendRelocation *h, *t;
uint16_t i = 0;
if(!index)
index = &i;
h = elfAddendRelocations(elf, name, &size, &length);
if(!h)
return NULL;
for(; *index < length; ++(*index))
{
t = (ElfAddendRelocation *)((uint8_t *)h + *index * size);
if(attribute == ElfAddendRelocationAttributeNone || elfAddendRelocationAttribute(t, attribute) == value)
return t;
}
return NULL;
}
*/

/* --- elf symbols --- */

uint64_t elfSymbolAttribute(ElfSymbol *elfSymbol, ElfSymbolAttribute attribute)
{
	switch (attribute)
	{
	case ELF_SYMBOL_ATTRIBUTE_NAME:
		return elfSymbol->st_name;
	case ELF_SYMBOL_ATTRIBUTE_INFO:
		return elfSymbol->st_info;
	case ELF_SYMBOL_ATTRIBUTE_UNUSED:
		return elfSymbol->st_other;
	case ELF_SYMBOL_ATTRIBUTE_SECTION_INDEX:
		return elfSymbol->st_shndx;
	case ELF_SYMBOL_ATTRIBUTE_VALUE:
		return elfSymbol->st_value;
	case ELF_SYMBOL_ATTRIBUTE_SIZE:
		return elfSymbol->st_size;
	default:
		break;
	}
	return 0;
}

ElfSymbol *elfSymbols(Elf *elf, char *name, uint16_t *size, uint16_t *length)
{
	ElfSection *h;

	h = elfSectionByName(elf, name);

	if (!h || (h->sh_type != SHT_SYMTAB && h->sh_type != SHT_DYNSYM))
		return NULL;

	if (size != NULL)
		*size = h->sh_entsize;
	if (length != NULL)
		*length = h->sh_size / h->sh_entsize;

	return (ElfSymbol *)(elf->data + h->sh_offset);
}

/*
ElfSymbol *elfSymbol(Elf *elf, char *name, uint16_t *index, ElfSymbolAttribute attribute, uint64_t value)
{
uint16_t size;
uint16_t length;
ElfSymbol *h, *t;
uint16_t i = 0;
if(!index)
index = &i;
h = elfSymbols(elf, name, &size, &length);
if(!h)
return NULL;
for(; *index < length; ++(*index))
{
t = (ElfSymbol *)((uint8_t *)h + *index * size);
if(attribute == ElfSymbolAttributeNone || elfSymbolAttribute(t, attribute) == value)
return t;
}
return NULL;
}*/

/* actions */

Elf *elfCreate(void *data, size_t size)
{
	Elf *elf, t;

	if (data == NULL)
		return NULL;

	t.data = data;
	t.size = size;

	if (!elfIsElf(&t))
		return NULL;

	elf = malloc(sizeof(Elf));
	if (elf == NULL)
	{
		debugNetPrintf(DEBUG, "[ELFLOADER] elfCreate error malloc return null\n");
		return NULL;
	}
	elf->data = (uint8_t *)data;
	elf->size = size;

	return elf;
}

Elf *elfCreateLocal(void *elfl, void *data, size_t size)
{
	Elf *elf, t;

	if (elfl == NULL || data == NULL)
		return NULL;

	t.data = data;
	t.size = size;

	if (!elfIsElf(&t))
		return NULL;

	elf = (Elf *)elfl;
	elf->data = (uint8_t *)data;
	elf->size = size;

	return elf;
}

Elf *elfCreateLocalUnchecked(void *elfl, void *data, size_t size)
{
	Elf *elf;

	if (elfl == NULL || data == NULL)
		return NULL;

	elf = (Elf *)elfl;
	elf->data = (uint8_t *)data;
	elf->size = size;

	return elf;
}

void *elfDestroy(Elf *elf)
{
	void *data;

	if (elf == NULL)
		return NULL;

	if (elf->data != NULL)
	{
		//debugNetPrintf(3,"data %x\n",elf->data);

		//data = elf->data;
		munmap(elf->data, elf->size);
		//free(elf->data);
	}

	return elf;
}

void elfDestroyAndFree(Elf *elf)
{
	void *d;

	if (elf == NULL)
		return;
	//debugNetPrintf(3,"elf %x\n",elf);
	d = elfDestroy(elf);
	//debugNetPrintf(3,"d %x\n",d);

	if (d)
		free(d);
}

/* ---  --- */

int elfLoaderIsLoadable(Elf *elf)
{
	ElfHeader *h;

	if (!elfIsElf(elf))
		return 0;

	h = elfHeader(elf);

	return elfClass(elf) == ELFCLASS64 &&
		elfEncoding(elf) == ELFDATA2LSB &&
		elfVersion(elf) == EV_CURRENT &&
		(elfABI(elf) == ELFOSABI_SYSV || elfABI(elf) == ELFOSABI_FREEBSD) &&
		h->e_type == ET_DYN &&
		h->e_phoff != 0 &&
		h->e_shoff != 0 &&
		h->e_machine == EM_X86_64 &&
		h->e_version == EV_CURRENT;
}

int elfLoaderInstantiate(Elf *elf, void *memory)
{
	ElfSection *sections;
	ElfSegment *segments;

	uint16_t size;
	uint16_t length;
	uint16_t index;

	if (elf == NULL)
		return ELF_LOADER_RETURN_ELF_NULL;
	if (memory == NULL)
		return ELF_LOADER_RETURN_NO_WRITABLE_MEMORY;

	segments = elfSegments(elf, &size, &length);
	if (segments)
	{
		debugNetPrintf(DEBUG, "[ELFLOADER] elfLoaderInstantiate in segments length=%d\n", length);

		for (index = 0; index < length; ++index)
		{
			ElfSegment *s = (ElfSegment *)((uint8_t *)segments + index * size);
			if (s->p_filesz)
			{
				debugNetPrintf(DEBUG, "[ELFLOADER] elfLoaderInstantiate before elfLoaderInstantiate memcpy %p %p %d\n", (char *)memory + s->p_paddr, elf->data + s->p_offset, s->p_filesz);

				orbisMemoryCopy((char *)memory + s->p_paddr, elf->data + s->p_offset, s->p_filesz);
				debugNetPrintf(DEBUG, "[ELFLOADER] elfLoaderInstantiate after elfLoaderInstantiate memcpy\n");

			}
			if (s->p_memsz - s->p_filesz)
			{	//memset((char *)memory + s->p_paddr + s->p_filesz, 0, s->p_memsz - s->p_filesz);
				debugNetPrintf(DEBUG, "[ELFLOADER] elfLoaderInstantiate before elfLoaderInstantiate orbisMemorySet\n");

				orbisMemorySet((char *)memory + s->p_paddr + s->p_filesz, 0, s->p_memsz - s->p_filesz);
				debugNetPrintf(DEBUG, "[ELFLOADER] elfLoaderInstantiate after elfLoaderInstantiate orbisMemorySet\n");

			}
		}
	}
	else
	{
		length = 0;
		sections = elfSections(elf, &size, &length);
		if (!sections)
			return 0;
		for (index = 0; index < length; ++index)
		{
			ElfSection *s = (ElfSection *)((uint8_t *)sections + index * size);
			if (!(s->sh_flags & SHF_ALLOC))
				continue;
			if (s->sh_size)
			{
				orbisMemoryCopy((char *)memory + s->sh_addr, elf->data + s->sh_offset, s->sh_size);
				debugNetPrintf(DEBUG, "[ELFLOADER] elfLoaderInstantiate  after elfLoaderInstantiate second memcpy\n");

			}
		}
	}

	return ELF_LOADER_RETURN_OK;
}

int elfLoaderRelativeAddressIsExecutable(Elf *elf, int64_t address)
{
	ElfSection *sections;
	ElfSegment *segments;

	uint16_t size;
	uint16_t length;
	uint16_t index;

	if (elf == NULL)
		return 0;

	segments = elfSegments(elf, &size, &length);
	if (segments)
	{
		for (index = 0; index < length; ++index)
		{
			ElfSegment *s = (ElfSegment *)((uint8_t *)segments + index * size);
			if (address >= s->p_paddr && address <= s->p_paddr + s->p_memsz)
				return s->p_flags & PF_X;
		}
	}
	else
	{
		length = 0;
		sections = elfSections(elf, &size, &length);
		if (!sections)
			return ELF_LOADER_RETURN_NO_SECTIONS_OR_SEGMENTS;
		for (index = 0; index < length; ++index)
		{
			ElfSection *s = (ElfSection *)((uint8_t *)sections + index * size);
			if (address >= s->sh_addr && address <= s->sh_addr + s->sh_size)
				return s->sh_flags & SHF_EXECINSTR;
		}
	}

	return 1; // FIXME: Recheck
}

// FIXME: Implement ps4 aware relocation for functions using dlsym
int elfLoaderRelocate(Elf *elf, void *writable, void *executable)
{
	int i, j;

	uint16_t relocationSize = 0;
	uint16_t relocationsLength = 0;
	ElfAddendRelocation *relocations;

	uint16_t dynamicSymbolSize = 0;
	uint16_t dynamicSymbolsLength = 0;
	ElfSymbol *dynamicSymbols;

	char *r1 = ".rela.dyn";
	char *r2 = ".rela.plt";
	char *rel[2] = { r1, r2 };

	if (elf == NULL)
		return ELF_LOADER_RETURN_ELF_NULL;
	if (writable == NULL)
		return ELF_LOADER_RETURN_NO_WRITABLE_MEMORY;
	if (executable == NULL)
		return ELF_LOADER_RETURN_NO_EXECUTABLE_MEMORY;

	dynamicSymbols = elfSymbols(elf, ".dynsym", &dynamicSymbolSize, &dynamicSymbolsLength);
	//symbols = elfSymbols(elf, ".symtab", &symbolSize, &symbolsLength);

	for (j = 0; j < sizeof(rel) / sizeof(rel[0]); ++j)
	{
		relocationsLength = 0;
		relocations = elfAddendRelocations(elf, rel[j], &relocationSize, &relocationsLength);

		for (i = 0; i < relocationsLength; ++i)
		{
			ElfSymbol *symbol;
			ElfAddendRelocation *relocation = (ElfAddendRelocation *)(((uint8_t *)relocations) + relocationSize * i);
			uint16_t relocationType = (uint16_t)elfRelocationType(relocation->r_info);
			uint16_t relocationSymbol = (uint16_t)elfRelocationSymbol(relocation->r_info);
			uint8_t **offset = (uint8_t **)((uint8_t *)writable + relocation->r_offset);
			int64_t value = 0;

			switch (relocationType)
			{
			case R_X86_64_RELATIVE:
				value = relocation->r_addend;
				break;
			case R_X86_64_64:
				symbol = (ElfSymbol *)(((uint8_t *)dynamicSymbols) + dynamicSymbolSize * relocationSymbol);
				value = symbol->st_value + relocation->r_addend;
				break;
			case R_X86_64_JMP_SLOT:
			case R_X86_64_GLOB_DAT:
				symbol = (ElfSymbol *)(((uint8_t *)dynamicSymbols) + dynamicSymbolSize * relocationSymbol);
				value = symbol->st_value;
				break;
			default:
				return ELF_LOADER_RETURN_UNKNOWN_RELOCATION;
			}

			if (elfLoaderRelativeAddressIsExecutable(elf, value))
				*offset = (uint8_t *)executable + value;
			else
				*offset = (uint8_t *)writable + value;
		}
	}

	return ELF_LOADER_RETURN_OK;
}

int elfLoaderLoad(Elf *elf, void *writable, void *executable)
{
	int r = ELF_LOADER_RETURN_OK;

	if (elf == NULL)
		return ELF_LOADER_RETURN_ELF_NULL;
	if (writable == NULL)
		return ELF_LOADER_RETURN_NO_WRITABLE_MEMORY;
	if (executable == NULL)
		return ELF_LOADER_RETURN_NO_EXECUTABLE_MEMORY;

	if (!elfLoaderIsLoadable(elf))
		return ELF_LOADER_RETURN_IS_NOT_LOADABLE;

	if ((r = elfLoaderInstantiate(elf, writable)) != ELF_LOADER_RETURN_OK)
	{
		debugNetPrintf(DEBUG, "[ELFLOADER] elfLoaderLoad  after elfLoaderInstantiate error return=%d\n", r);

		return r;
	}
	debugNetPrintf(DEBUG, "[ELFLOADER] elfLoaderLoad  after elfLoaderInstantiate return=%d\n", r);
	r = elfLoaderRelocate(elf, writable, executable);
	debugNetPrintf(DEBUG, "[ELFLOADER] elfLoaderLoad after elfLoaderRelocate return=%d\n", r);


	return r;
}

extern ps4LinkConfiguration *configuration;
typedef int(*ElfMain)(int argc, char **argv);
typedef void(*ElfProcessMain)(void *arg);

typedef void(*ElfProcessExit)(int ret);
typedef void(*ElfProcessFree)(void *m, void *t);


typedef struct ElfRunUserArgument
{
	ElfMain main;
	Ps4MemoryProtected *memory;
}
ElfRunUserArgument;

void *orbisUserMain(void *arg)
{
	ElfRunUserArgument *argument = (ElfRunUserArgument *)arg;
	globalConf.confLink = configuration;
	//ps4LinkConfiguration *shared_conf=configuration;
	char pointer_conf[256];
	sprintf(pointer_conf, "%p", &globalConf);
	debugNetPrintf(DEBUG, "[ELFLOADER] orbisUserMain Configuration pointer %p, pointer_conf string %s\n", &globalConf, pointer_conf);
	char *elfName = "elf";
	char *elfArgv[3] = { elfName, pointer_conf, NULL };
	int elfArgc = 2;

	int r;

	if (argument == NULL)
		return NULL;

	r = argument->main(elfArgc, elfArgv);
	ps4MemoryProtectedDestroy(argument->memory);
	//ps4MemoryDestroy(argument->memory);
	free(argument);
	debugNetPrintf(DEBUG, "[ELFLOADER] orbisUserMain return (user): %i\n", r);

	return NULL;
}

int orbisUserRun(Elf *elf)
{
	//pthread_t thread;
	ScePthread thread;
	int ret;
	ElfRunUserArgument *argument;
	void *writable, *executable;
	int r;

	if (elf == NULL)
		return -1;
	debugNetPrintf(DEBUG, "[ELFLOADER] orbisUserRun malloc for argument\n");

	argument = (ElfRunUserArgument *)malloc(sizeof(ElfRunUserArgument));
	if (argument == NULL)
	{
		elfDestroyAndFree(elf);
		debugNetPrintf(DEBUG, "[ELFLOADER] orbisUserRun argument is NULL\n");
		return -1;
	}
	debugNetPrintf(DEBUG, "[ELFLOADER] orbisUserRun after malloc for argument\n");

	if (ps4MemoryProtectedCreate(&argument->memory, elfMemorySize(elf)) != 0)
		//if(ps4MemoryCreate(&argument->memory, elfMemorySize(elf)) != PS4_OK)
	{
		free(argument);
		elfDestroyAndFree(elf);
		debugNetPrintf(DEBUG, "[ELFLOADER] orbisUserRun after elfDestroyAndFree\n");

		return -1;
	}
	debugNetPrintf(DEBUG, "[ELFLOADER] orbisUserRun after ps4MemoryProtectedCreate\n");

	argument->main = NULL;
	ps4MemoryProtectedGetWritableAddress(argument->memory, &writable);
	debugNetPrintf(DEBUG, "[ELFLOADER] orbisUserRun after ps4MemoryProtectedGetWritableAddress writable=%p\n", writable);

	ps4MemoryProtectedGetExecutableAddress(argument->memory, &executable);
	debugNetPrintf(DEBUG, "[ELFLOADER] orbisUserRun after ps4MemoryProtectedGetExecutableAddress executable=%p\n", executable);

	r = elfLoaderLoad(elf, writable, executable);
	//r = elfLoaderLoad(elf, ps4MemoryGetAddress(argument->memory), ps4MemoryGetAddress(argument->memory));
	debugNetPrintf(DEBUG, "[ELFLOADER] orbisUserRun after elfLoaderLoad return r=%d readable=%p executable=%p\n", r, writable, executable);

	if (r == ELF_LOADER_RETURN_OK)
	{
		argument->main = (ElfMain)((uint8_t *)executable + elfEntry(elf));
		debugNetPrintf(DEBUG, "[ELFLOADER] orbisUserRun after set argument->main %p \n", argument->main);

	}
	//elfDestroyAndFree(elf); // we don't need the "file" anymore but if i leave this line i got a memory crash 
	debugNetPrintf(DEBUG, "[ELFLOADER] orbisUserRun after elfDestroyAndFree \n");

	if (argument->main != NULL)
	{	//pthread_create(&thread, NULL, elfLoaderUserMain, argument);
		ret = scePthreadCreate(&thread, NULL, orbisUserMain, argument, "elf_user_thid");
		if (ret == 0)
		{
			debugNetPrintf(DEBUG, "[ELFLOADER] New user elf thread UID: 0x%08X\n", thread);
		}
		else
		{
			debugNetPrintf(DEBUG, "[ELFLOADER] New user elf thread could not create error: 0x%08X\n", ret);
			scePthreadCancel(thread);
			//ps4LinkFinish();
			return PS4_NOT_OK;
		}
	}
	else
	{
		ps4MemoryProtectedDestroy(argument->memory);
		free(argument);
		debugNetPrintf(DEBUG, "[ELFLOADER]orbisUserRun argument->main is released\n");
		return -1;
	}
	return PS4_OK;
}

Elf * orbisReadElfFromHost(char *path)
{
	int fd; //descriptor to manage file from host0
	int filesize;//variable to control file size 
	uint8_t *buf = NULL;//buffer for read from host0 file
	Elf *elf;//elf to create from buf 

			 //we sceKernelOpen file in read only from host0 ps4sh include the full path with host0:/.......
	fd = sceKernelOpen(path, O_RDONLY, 0);

	//If we can't sceKernelOpen file from host0 print  the error and return
	if (fd<0)
	{
		debugNetPrintf(DEBUG, "[ELFLOADER] sceKernelOpen returned error sceKernelOpening file %d\n", fd);
		return NULL;
	}
	//Seek to final to get file size
	filesize = sceKernelLseek(fd, 0, SEEK_END);
	//If we get an error print it and return
	if (filesize<0)
	{
		debugNetPrintf(DEBUG, "[ELFLOADER] sceKernelLseek returned error %d\n", fd);
		sceKernelClose(fd);
		return NULL;
	}
	//Seek back to start
	sceKernelLseek(fd, 0, SEEK_SET);
	//Reserve  memory for read buffer
	//buf=malloc(filesize);
	//char buf[filesize];
	debugNetPrintf(DEBUG, "[ELFLOADER] before orbisSysMmap\n");
	buzzer1beep();
	loadnote();

	buf = mmap(NULL, filesize, 0x01 | 0x02, 0x1000 | 0x0002, -1, 0);

	if (buf == MAP_FAILED)
	{
		debugNetPrintf(DEBUG, "[ELFLOADER] mmap returned error tryng one more time\n");

		buf = mmap(NULL, filesize, 0x01 | 0x02, 0x1000 | 0x0002, -1, 0);
		if (buf == MAP_FAILED)
		{
			debugNetPrintf(DEBUG, "[ELFLOADER] mmap returned error again\n");
			sceKernelClose(fd);
			return NULL;
		}
	}
	//Read filsesize bytes to buf
	int numread = sceKernelRead(fd, buf, filesize);
	//if we don't get filesize bytes we are in trouble
	if (numread != filesize)
	{
		sleep(1);
		debugNetPrintf(DEBUG, "[ELFLOADER] sceKernelRead returned error %d\n", numread);
		sleep(1);
		sceKernelClose(fd);
		return NULL;
	}
	//Close file
	sceKernelClose(fd);
	//create elf from elfloader code from hitodama :P
	elf = elfCreate((void*)buf, filesize);
	//check is it is loadable
	if (!elfLoaderIsLoadable(elf))
	{
		debugNetPrintf(DEBUG, "[ELFLOADER] elf %s is not loadable\n", path);
		//free(buf);
		elfDestroy(elf);
		elf = NULL;
	}
	return elf;
}
void orbisExecUserElf()
{


	Elf *elf = NULL;
	debugNetPrintf(DEBUG, "[ELFLOADER] orbisExecUserElf called\n");
	elf = orbisReadElfFromHost("/data/orbislink/homebrew.elf"); ///mnt/sandbox/pfsmnt/NPXX33392-app0/Media/Elf/homebrew.elf
	if (elf == NULL)
	{
		debugNetPrintf(DEBUG, "[ELFLOADER] orbisExecUserElf we can't create elf\n");
		failednote();
		return;
	}
	debugNetPrintf(DEBUG, "[ELFLOADER] orbisExecUserElf ready to run elf\n");
	orbisUserRun(elf);
	return;
}


void finishOrbisLinkApp()
{
	orbisAudioFinish();
	orbisKeyboardFinish();
	orbisPadFinish();
	orbis2dFinish();
	ps4LinkFinish();
}
int initOrbisLinkApp()
{
	int ret;
	int jailbreak_out = -1;
	//jailbreak_out=orbisSysJailBreak();

	pl_ini_file init;
	int fds = sceKernelOpen("/mnt/usb0/config.ini", SCE_KERNEL_O_RDONLY, 0);
		if (!fds)
		{
			pl_ini_load(&init, "/app0/Media/config.ini");
		}
		else if (fds)
		{
			pl_ini_load(&init, "/mnt/usb0/config.ini");
		}
	char serverIp[16];
	pl_ini_get_string(&init, "ps4link", "serverIp", "192.168.1.3", serverIp, 16);


	int requestPort = pl_ini_get_int(&init, "ps4link", "requestPort", 18193);
	int debugPort = pl_ini_get_int(&init, "ps4link", "debugPort", 18194);
	int commandPort = pl_ini_get_int(&init, "ps4link", "commandPort", 18194);
	int level = pl_ini_get_int(&init, "ps4link", "level", 3);



	globalConf.orbisLinkFlag = 0;
	ret = ps4LinkInit(serverIp, requestPort, debugPort, commandPort, level);
	if (!ret)
	{
		ps4LinkFinish();
		return ret;
	}
	while (!ps4LinkRequestsIsConnected())
	{
		debugNetPrintf(DEBUG, "[Its me Mario]");


		debugNetPrintf(DEBUG, "[ELFLOADER] Initialized and connected from pc/mac ready to receive commands\n");
		int padEnabled = pl_ini_get_int(&init, "orbisPad", "enabled", 1);
		int o2dEnabled = pl_ini_get_int(&init, "orbis2d", "enabled", 1);
		int audioEnabled = pl_ini_get_int(&init, "orbisAudio", "enabled", 1);
		int fmsxEnabled = pl_ini_get_int(&init, "fmsx", "enabled", 0);
		int audioSamples = pl_ini_get_int(&init, "orbisAudio", "samples", 1024);
		int audioFrequency = pl_ini_get_int(&init, "orbisAudio", "frequency", 48000);
		int audioFormat = pl_ini_get_int(&init, "orbisAudio", "format", ORBISAUDIO_FORMAT_S16_STEREO);

		if (fmsxEnabled == 1)
		{
			audioEnabled = 1;
			audioSamples = 500;
			audioFrequency = 48000;
			audioFormat = ORBISAUDIO_FORMAT_S16_MONO;
		}
		int keyboardEnabled = pl_ini_get_int(&init, "orbisKeyboard", "enabled", 1);


		if (padEnabled == 1)
		{
			ret = orbisPadInit();
		}
		else
		{
			ret = -1;
		}
		if (ret == 1)
		{

			globalConf.confPad = orbisPadGetConf();
			if (o2dEnabled == 1)
			{
				ret = orbis2dInit();
				debugNetPrintf(DEBUG, "[ELFLOADER] orbis2dInit return %x \n", ret);
			}
			else
			{
				ret = -2;
			}
			if (ret == 1)
			{
				globalConf.conf = orbis2dGetConf();
				if (audioEnabled == 1)
				{
					ret = orbisAudioInit();
				}
				else
				{
					ret = -3;
				}
				if (ret == 1)
				{
					//ret=orbisAudioInitChannel(ORBISAUDIO_CHANNEL_MAIN,1024,48000,ORBISAUDIO_FORMAT_S16_STEREO);
					ret = orbisAudioInitChannel(ORBISAUDIO_CHANNEL_MAIN, audioSamples, audioFrequency, audioFormat);

					sleep(1);
					debugNetPrintf(DEBUG, "[ELFLOADER] orbisAudioInitChannel return %x \n", ret);
					sleep(1);
					globalConf.confAudio = orbisAudioGetConf();

					if (keyboardEnabled == 1)
					{
						//ret=orbisKeyboardInit();
						//debugNetPrintf(DEBUG,"orbisKeyboardInit %d\n",ret);
						//if(ret==1)
						//{
						//	globalConf.confKeyboard=OrbisKeyboardGetConf();
						//sleep(1);
						//	ret=orbisKeyboardOpen();
						//	debugNetPrintf(DEBUG,"orbisKeyboardOpen %d\n",ret);
						ret = 0;
						//}
					}

				}
			}
		}
		return ret;


	}
	//debugNetPrintf(DEBUG,"[ELFLOADER] orbisSysJailBreak returned %d\n",jailbreak_out);

	//hide orbislink splash
	//sceSystemServiceHideSplashScreen();





}

int ioctlss(int fd, unsigned long com, void *data)
{
	return syscalls(54, fd, com, data);
}

/*
typedef struct {
	int index;
	uint64_t fileoff;
	size_t bufsz;
	size_t filesz;
	int enc;
} SegmentBufInfo;

int is_segment_in_other_segment(Elf64_Phdr *phdr, int index, Elf64_Phdr *phdrs, int num) {
	for (int i = 0; i < num; i += 1) {
		Elf64_Phdr *p = &phdrs[i];
		if (i != index) {
			if (p->p_filesz > 0) {
				////debugNetPrintf(DEBUG,"offset : %016x,  toffset : %016x\n", phdr->p_offset, p->p_offset);
				debugNetPrintf(DEBUG, "offset : %016x,  toffset : %016x\n", phdr->p_offset, p->p_offset);
				////debugNetPrintf(DEBUG,"offset : %016x,  toffset + size : %016x\n", phdr->p_offset, p->p_offset + p->p_filesz);
				debugNetPrintf(DEBUG, "offset : %016x,  toffset + size : %016x\n", phdr->p_offset, p->p_offset + p->p_filesz);
				if ((phdr->p_offset >= p->p_offset) && ((phdr->p_offset + phdr->p_filesz) <= (p->p_offset + p->p_filesz))) {
					return -1;
				}
			}
		}
	}
	return 0;
}

SegmentBufInfo *parse_phdr(Elf64_Phdr *phdrs, int num, int *segBufNum) {
	////debugNetPrintf(DEBUG,"segment num : %d\n", num);
	SegmentBufInfo *infos = (SegmentBufInfo *)malloc(sizeof(SegmentBufInfo) * num);
	int segindex = 0;
	for (int i = 0; i < num; i += 1) {
		Elf64_Phdr *phdr = &phdrs[i];
		//print_phdr(phdr);

		if (phdr->p_filesz > 0) {
			if ((!is_segment_in_other_segment(phdr, i, phdrs, num)) || (phdr->p_type == 0x6fffff01)) {
				SegmentBufInfo *info = &infos[segindex];
				segindex += 1;
				info->index = i;
				info->bufsz = (phdr->p_filesz + (phdr->p_align - 1)) & (~(phdr->p_align - 1));
				info->filesz = phdr->p_filesz;
				info->fileoff = phdr->p_offset;
				info->enc = (phdr->p_type != 0x6fffff01) ? 0 : 1;
				debugNetPrintf(DEBUG, "seg buf info %d -->\n", segindex);
				////debugNetPrintf(DEBUG,"seg buf info %d -->\n", segindex);
				debugNetPrintf(DEBUG, "    index : %d\n    bufsz : 0x%016llX\n", info->index, info->bufsz);
				////debugNetPrintf(DEBUG,"    index : %d\n    bufsz : 0x%016llX\n", info->index, info->bufsz);
				debugNetPrintf(DEBUG, "    filesz : 0x%016llX\n    fileoff : 0x%016llX\n", info->filesz, info->fileoff);
				////debugNetPrintf(DEBUG,"    filesz : 0x%016llX\n    fileoff : 0x%016llX\n", info->filesz, info->fileoff);
			}
		}
	}
	*segBufNum = segindex;
	return infos;
}

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
			debugNetPrintf(DEBUG, "MAP_FAILED");
			memcpy(outPtr, addr, bytes);
			munmap(addr, bytes);
		}
		else
		{
			////debugNetPrintf(DEBUG,"mmap segment [%d] err(%d) : %s\n", index, errno, strerror(errno));
			debugNetPrintf(DEBUG, "error 2");
			return -1;
		}
		outPtr += bytes;
		outSize -= bytes;
		realOffset += bytes;
	}
	return 0;
}

void do_dump(char *saveFile, int fd, SegmentBufInfo *segBufs, int segBufNum, Elf64_Ehdr *ehdr) {
	int sf = sceKernelOpen(saveFile, O_WRONLY | O_CREAT | O_TRUNC, 0777);
	debugNetPrintf(DEBUG, "sf: x%", sf);
	if (sf != -1) {
		size_t elfsz = 0x40 + ehdr->e_phnum * sizeof(Elf64_Phdr);
		////debugNetPrintf(DEBUG,"elf header + phdr size : 0x%08X\n", elfsz);
		debugNetPrintf(DEBUG, "elf header + phdr size : 0x%08X\n", elfsz);
		sceKernelWrite(sf, ehdr, elfsz);

		for (int i = 0; i < segBufNum; i += 1) {
			////debugNetPrintf(DEBUG,"sbuf index : %d, offset : 0x%016x, bufsz : 0x%016x, filesz : 0x%016x, enc : %d\n", segBufs[i].index, segBufs[i].fileoff, segBufs[i].bufsz, segBufs[i].filesz, segBufs[i].enc);
			debugNetPrintf(DEBUG, "sbuf index : %d, offset : 0x%016x, bufsz : 0x%016x, filesz : 0x%016x, enc : %d\n", segBufs[i].index, segBufs[i].fileoff, segBufs[i].bufsz, segBufs[i].filesz, segBufs[i].enc);
			uint8_t *buf = (uint8_t*)malloc(segBufs[i].bufsz);
			memset(buf, 0, segBufs[i].bufsz);
			if (segBufs[i].enc)
			{
				if (read_decrypt_segment(fd, segBufs[i].index, 0, segBufs[i].filesz, buf)) {
					sceKernelLseek(sf, segBufs[i].fileoff, SEEK_SET);
					sceKernelWrite(sf, buf, segBufs[i].bufsz);
				}
			}
			else
			{
				sceKernelLseek(fd, -segBufs[i].filesz, SEEK_END);
				sceKernelRead(fd, buf, segBufs[i].filesz);
				sceKernelLseek(sf, segBufs[i].fileoff, SEEK_SET);
				sceKernelWrite(sf, buf, segBufs[i].filesz);
			}
			free(buf);
		}
		sceKernelClose(sf);
	}
	else {
		debugNetPrintf(DEBUG, "error f12");
		////debugNetPrintf(DEBUG,"sceKernelOpen %s err : %s\n", saveFile, strerror(errno));
	}
}

void decrypt_and_dump_selfs(char selfFile, char saveFile) {
	int fd = sceKernelOpen(selfFile, O_RDONLY, 0);
	if (fd != -1) {
		void *addr = mmap(0, 0x4000, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
		if (addr != MAP_FAILED) {
			////debugNetPrintf(DEBUG,"mmap %s : %p\n", selfFile, addr);

			uint16_t snum = *(uint16_t*)((uint8_t*)addr + 0x18);
			Elf64_Ehdr *ehdr = (Elf64_Ehdr *)((uint8_t*)addr + 0x20 + snum * 0x20);
			////debugNetPrintf(DEBUG,"ehdr : %p\n", ehdr);

			// shdr fix
			ehdr->e_shoff = ehdr->e_shentsize = ehdr->e_shnum = ehdr->e_shstrndx = 0;

			Elf64_Phdr *phdrs = (Elf64_Phdr *)((uint8_t *)ehdr + 0x40);
			////debugNetPrintf(DEBUG,"phdrs : %p\n", phdrs);

			int segBufNum = 0;
			SegmentBufInfo *segBufs = parse_phdr(phdrs, ehdr->e_phnum, &segBufNum);
			do_dump(saveFile, fd, segBufs, segBufNum, ehdr);
			////debugNetPrintf(DEBUG,"dump completed\n");

			free(segBufs);
			sceKernelMunmap(addr, 0x4000);
		}
		else {
			////debugNetPrintf(DEBUG,"mmap file %s err : %s\n", selfFile, strerror(errno));
		}
		sceKernelClose(fd);

	}
	else {
		////debugNetPrintf(DEBUG,"sceKernelOpen %s err : %s\n", selfFile, strerror(errno));
	}
}


void copyFile(char *sourcefile, char* destfile)
{
	int src = sceKernelOpen(sourcefile, O_RDONLY, 0);
	if (src != -1)
	{
		int out = sceKernelOpen(destfile, O_WRONLY | O_CREAT | O_TRUNC, 0777);
		if (out != -1)
		{
			size_t bytes;
			char *buffer = malloc(65536);
			if (buffer != NULL)
			{
				while (0 < (bytes = sceKernelRead(src, buffer, 65536)))
					sceKernelWrite(out, buffer, bytes);
				free(buffer);
			}
			sceKernelClose(out);
		}
		else {
		}
		sceKernelClose(src);
	}
	else {
	}
}

void decrypt_and_dump_self(char *selfFile, char *saveFile) {
	int fd = sceKernelOpen(selfFile, O_RDONLY, 0);
	if (fd != -1) {
		void *addr = mmap(0, 0x4000, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
		if (addr != MAP_FAILED) {
			////debugNetPrintf(DEBUG,"mmap %s : %p\n", selfFile, addr);
			debugNetPrintf(DEBUG, "mmap %s : %p\n", selfFile, addr);

			uint16_t snum = *(uint16_t*)((uint8_t*)addr + 0x18);
			Elf64_Ehdr *ehdr = (Elf64_Ehdr *)((uint8_t*)addr + 0x20 + snum * 0x20);
			////debugNetPrintf(DEBUG,"ehdr : %p\n", ehdr);
			debugNetPrintf(DEBUG, "ehdr : %p\n", ehdr);

			// shdr fix
			ehdr->e_shoff = ehdr->e_shentsize = ehdr->e_shnum = ehdr->e_shstrndx = 0;

			Elf64_Phdr *phdrs = (Elf64_Phdr *)((uint8_t *)ehdr + 0x40);
			////debugNetPrintf(DEBUG,"phdrs : %p\n", phdrs);
			debugNetPrintf(DEBUG, "phdrs : %p\n", phdrs);

			int segBufNum = 0;
			SegmentBufInfo *segBufs = parse_phdr(phdrs, ehdr->e_phnum, &segBufNum);
			debugNetPrintf(DEBUG, "Before Do_Dump");
			do_dump(saveFile, fd, segBufs, segBufNum, ehdr);
			////debugNetPrintf(DEBUG,"mmap %s : %p\n", selfFile, addr);
			debugNetPrintf(DEBUG, "dump done");

			free(segBufs);
			munmap(addr, 0x4000);
		}
		else {
			////debugNetPrintf(DEBUG,"mmap file %s err : %s\n", selfFile, strerror(errno));
		}
		sceKernelClose(fd);

	}
	else {
		////debugNetPrintf(DEBUG,"sceKernelOpen %s err : %s\n", selfFile, strerror(errno));
	}
}*/

void copyFile(char *sourcefile, char* destfile)
{
	int src = sceKernelOpen(sourcefile, O_RDONLY, 0);
	if (src != -1)
	{
		int out = sceKernelOpen(destfile, O_WRONLY | O_CREAT | O_TRUNC, 0777);
		if (out != -1)
		{
			size_t bytes;
			char *buffer = malloc(65536);
			if (buffer != NULL)
			{
				while (0 < (bytes = sceKernelRead(src, buffer, 65536)))
					sceKernelWrite(out, buffer, bytes);
				free(buffer);
			}
			sceKernelClose(out);
		}
		else {
		}
		sceKernelClose(src);
	}
	else {
	}
}

int hiii()
{
	copyFile("/mnt/sandbox/pfsmnt/NPXX33392-app0/Media/Elf/homebrew.elf", "/data/orbislink/homebrew_encrypted.elf");
	decrypt_and_dump_self("/data/orbislink/homebrew_encrypted.elf", "/update/homebrew.elf");
}


int psxdevloader()
{
	int ret = initOrbisLinkApp();
	if (ret >= 0)
	{
		debugNetPrintf(DEBUG, "[ELFLOADER] Loading Homebrew.elf from PS4\n");
		
		syscall(9);
		/*int fd = sceKernelOpen("/data/orbislink/", O_RDONLY, 777);
		if (fd>0)
		{
			sceKernelMkdir("/data/orbislink/", 0777);
		}
		else if (fd<0)
		{
			sceKernelRmdir("/data/orbislink/");
			sceKernelMkdir("/data/orbislink/", 0777);
		}
		debugNetPrintf(DEBUG, "[ELFLOADER] Copying homebrew.elf\n");
//

		debugNetPrintf(DEBUG, "[ELFLOADER] Copied homebrew.elf\n");*/


		copyFile("/mnt/sandbox/pfsmnt/NPXX33392-app0/Media/Elf/homebrew.elf", "/data/orbislink/homebrew_encrypted.elf");
		decrypt_and_dump_self("/data/orbislink/homebrew_encrypted.elf", "/update/homebrew.elf");

		orbisExecUserElf();

		while (!globalConf.orbisLinkFlag)
		{

		}
	}
	else
	{
		debugNetPrintf(DEBUG, "[ELFLOADER]something wrong happen initOrbisLinkApp return 0x%8x %d \n", ret, ret);
		debugNetPrintf(DEBUG, "[ELFLOADER]Exiting\n");

	}
	finishOrbisLinkApp();

	printf("app done");

	exit(0);

	return 0;
}
////////////////////////////////////////////////////////