

#define X86_CR0_WP (1 << 16)

#define kdlsym_addr_memset  0x003205C0

#define kdlsym_addr_icc_nvs_read 0x00395830
#define kdlsym_addr_sceSblGetEAPInternalPartitionKey 0x006256E0
#define PRX_IMPORT extern "C" __declspec (dllimport)

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
#include "stdlib.h"
#include "string.h"
#include "_pthread.h"
#include "c:\Program Files (x86)\SCE\ORBIS SDKs\4.500\target\include\time.h"
#include "elf64.h"
#include "sys/dirent.h"
#include "netinet/in.h"
#include "netinet/tcp.h"
#include "sys/socket.h"
#include "stdbool.h"
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

#define MAP_POPULATE    0x8000



int getdents(int fd, char *buf, size_t count) 
{
	return syscall(272, fd, buf, count); 
}

typedef uint8_t  u8;
typedef uint32_t u32;
typedef uint64_t u64;

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

//
#define KERN_474_PRISON_0		0x01042AB0
#define KERN_474_ROOTVNODE		0x021B89E0
//

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

int opens(const char *path, int flags, int mode)
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


int stat(const char *path, struct stat *sb)
{
	return syscall(188, path, sb);
}

#define printf_notification(...) \
	do { \
		char message[256]; \
		snprintf(message, sizeof(message), ##__VA_ARGS__); \
		sceSysUtilSendSystemNotificationWithText(222, message); \
	} while (0)


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

int jailbreak(uint64_t fw_version) {
	struct kpayload_jailbreak_info kpayload_jailbreak_info;
	kpayload_jailbreak_info.fw_version = fw_version;
	kexec(&kpayload_jailbreak, &kpayload_jailbreak_info);
	return 0;
}

uint64_t get_kbase(uint64_t fw_version) {
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
#define	KERN_474_XFAST_SYSCALL		0x30B7D0	// #3
#define	KERN_455_XFAST_SYSCALL		0x3095D0	// #2
#define	KERN_501_XFAST_SYSCALL		0x1C0		// #1
#define	KERN_505_XFAST_SYSCALL		0x1C0		// #1
#define KERN_405_PRISON_0		0xF26010
#define KERN_455_PRISON_0		0x10399B0
//
#define KERN_474_PRISON_0		0x01042AB0
#define KERN_474_ROOTVNODE		0x021B89E0
//
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
		//printfsocket("%02X ", raw[i - 1]);
		if (i % 16 == 0) {
			//printfsocket("\n");
		}
	}
}



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

	dfd = opens(path, O_RDONLY, 0);
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
				pd = opens(tmp_path, O_RDONLY, 0);
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

	if ((fd = opens(path, O_RDONLY, 0)) >= 0) {

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
		//decrypt_and_dump_self(dest_path, "/user/temp.self");
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

	if ((fd = opens(path, mode, 0777)) >= 0) {

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
	/*else if (*__error == 66) { /* ENOTEMPTY */
		//client_send_ctrl_msg(client, "550 Directory is not empty." FTPS4_EOL);
	//}
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

		/* If there's an opens data connection, abort it */
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

	/* If there's an opens data connection, close it */
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


static void cmd_RETR_func(ftps4_client_info_t *client)
{
	char dest_path[PATH_MAX];
	gen_ftp_fullpath(client, dest_path, sizeof(dest_path));

	send_file(client, dest_path);

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
	add_command(RETR);
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
	int src = opens(sourcefile, O_RDONLY, 0);
	if (src != -1)
	{
		int out = opens(destfile, O_WRONLY | O_CREAT | O_TRUNC, 0777);
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


int sample1note()
{

	int moduleId = -1;
	sys_dynlib_load_prx("libSceSysUtil.sprx", &moduleId);


	// This header doesn't work in > 5.00
	int(*sceSysUtilSendSystemNotificationWithText)(int messageType, char* message) = NULL;

	sys_dynlib_dlsym(moduleId, "sceSysUtilSendSystemNotificationWithText", &sceSysUtilSendSystemNotificationWithText);

	char* initMessage = "***Sample 1****\n\n Triangle/Decrypt Selected...";
	sceSysUtilSendSystemNotificationWithText(222, initMessage);

	sys_dynlib_unload_prx(moduleId);


	return 0;
}

void *patches_only() {

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


	}
	else if (fw_version == 0x455) {


	}
	else if (fw_version == 0x501) {

	}
	else if (fw_version == 0x505) {

		// Kernel pointers resolving

	}
	else return -1;

	if (fw_version == 0x505) {


		cpu_disable_wp();

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


	}

	return 0;

}




int sample2note()
{

	int moduleId = -1;
	sys_dynlib_load_prx("libSceSysUtil.sprx", &moduleId);

	patches_only();

	// This header doesn't work in > 5.00
	int(*sceSysUtilSendSystemNotificationWithText)(int messageType, char* message) = NULL;

	sys_dynlib_dlsym(moduleId, "sceSysUtilSendSystemNotificationWithText", &sceSysUtilSendSystemNotificationWithText);

	char* initMessage = "uhhhh this is embarrsing ....\n\n This is the secret game backup project however its not done";
	sceSysUtilSendSystemNotificationWithText(222, initMessage);

	sys_dynlib_unload_prx(moduleId);


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

	else if (!memcmp((char*)(&((uint8_t*)__readmsr(0xC0000082))[-KERN_474_XFAST_SYSCALL]), (char[4]) { 0x7F, 0x45, 0x4C, 0x46 }, 4)) {

		kbase = &((uint8_t*)__readmsr(0xC0000082))[-KERN_474_XFAST_SYSCALL];

		fw_version = 0x474;

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

	else if (fw_version == 0x474) {

		int(*printfkernel)(const char *fmt, ...) = (void *)(kbase + KERN_405_PRINTF);
		printfkernel("FW Version 4.74 Detected\n");

	}
	else if (fw_version == 0x455) {

		int(*printfkernel)(const char *fmt, ...) = (void *)(kbase + KERN_455_PRINTF);
		printfkernel("FW Version 4.55 Detected\n");

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

	else if (fw_version == 0x474) {

		// Kernel pointers resolving

		kernel_ptr = (uint8_t*)kbase;
		got_prison0 = (void**)&kernel_ptr[KERN_474_PRISON_0];
		got_rootvnode = (void**)&kernel_ptr[KERN_474_ROOTVNODE];

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

		// Kernel pointers resolving

		kernel_ptr = (uint8_t*)kbase;
		got_prison0 = (void**)&kernel_ptr[KERN_505_PRISON_0];
		got_rootvnode = (void**)&kernel_ptr[KERN_505_ROOTVNODE];

		cpu_disable_wp();

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

		cpu_disable_wp();


		*(uint8_t*)(kbase + 0x143BF2) = 0x90; //0x0F
		*(uint8_t*)(kbase + 0x143BF3) = 0xE9; //0x84
		*(uint8_t*)(kbase + 0x143E0E) = 0x90; //0x74
		*(uint8_t*)(kbase + 0x143E0F) = 0x90; //0x0C

		cpu_enable_wp();

	}
	else if (fw_version == 0x474) {

		kernel_ptr = (uint8_t*)kbase;
		uint8_t *kmem;

	//.......

		cpu_disable_wp();


		uint8_t* map_self_patch1 = &kernel_ptr[0x169820];
		uint8_t* map_self_patch2 = &kernel_ptr[0x169810];
		uint8_t* map_self_patch3 = &kernel_ptr[0x143277];

		// sceSblACMgrIsAllowedToMmapSelf result
		kmem = (uint8_t*)map_self_patch1;
		kmem[0] = 0xB8;
		kmem[1] = 0x01;
		kmem[2] = 0x00;
		kmem[3] = 0x00;
		kmem[4] = 0x00;
		kmem[5] = 0xC3;

		// sceSblACMgrHasMmapSelfCapability result
		kmem = (uint8_t*)map_self_patch2;
		kmem[0] = 0xB8;
		kmem[1] = 0x01;
		kmem[2] = 0x00;
		kmem[3] = 0x00;
		kmem[4] = 0x00;
		kmem[5] = 0xC3;

		// sceSblAuthMgrIsLoadable bypass
		kmem = (uint8_t*)map_self_patch3;
		kmem[0] = 0x31;
		kmem[1] = 0xC0;
		kmem[2] = 0x90;
		kmem[3] = 0x90;
		kmem[4] = 0x90;


//................................

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
		*(uint32_t *)(kbase + 0x14A63F0) = 0x6000001;

		cpu_enable_wp();
	}

	else if (fw_version == 0x405) {


		cpu_disable_wp();
		// spoofer
		*(uint32_t *)(kbase + 0x1344618) = 0x6000001;

		cpu_enable_wp();
	}

	else if (fw_version == 0x455) {

		cpu_disable_wp();
		// spoofer
		*(uint32_t *)(kbase + 0x144B600) = 0x6000001;

		cpu_enable_wp();
	}

	else if (fw_version == 0x501) {

		cpu_disable_wp();
		// spoofer
		*(uint32_t *)(kbase + 0x14A63F0) = 0x6000001;

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

////decrypt_and_dump_self("/system/vsh/SceShellCore.elf", "/mnt/usb0/");

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

	char* initMessage = "Spoofed to 6.00";
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

	//decrypt_and_dump_self("/system/vsh/SceShellCore.elf", "/mnt/usb0/SceShellCore.elf");

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



	// opens file for writing 
	f = fopen("/mnt/usb0/idps_test.txt", "a+");
	if (!f) {
		char* initMessage2 = "failed";
		sceSysUtilSendSystemNotificationWithText(222, initMessage2);
	}

	fprintf(f, "---------------- trying to opens PATH: \"%s\" ", path);


	// it didn't write, it won't append? .........
	fprintf(f, "-----------------TEST444--------------------------");
	fflush(f);

	char subpath[1024];
	//DIR* dir = opendir(path);


	int dir = opens(path, O_DIRECTORY | O_RDONLY, 0777); // octal no  x
	if (dir == -1) {
		fprintf(f," Error: bsd opens()\n");
		fflush(f);// h
		fclose(f);
		return; // haha
	}

	fprintf(f,"\nLS \"%s\"\n{\n", path);
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
				//decrypt_and_dump_self(subpath, dumppath);

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
	mount_large_fs("/dev/da0x0.crypt", "/preinst", "exfatfs", "511", MNT_UPDATE);


	char* initMessage2 = "⚠ Mounted RW\n ALL System folders are now writable ";
	sceSysUtilSendSystemNotificationWithText(222, initMessage2);

	return 0;
}



void custom_dumpshell(ftps4_client_info_t *client)
{

	ftps4_ext_client_send_ctrl_msg(client, "ShellCore has been Successfully Dumped." FTPS4_EOL);
	return;
}



int off_mount_rw()
{

	int moduleId = -1;
	sys_dynlib_load_prx("libSceSysUtil.sprx", &moduleId);

	// This header doesn't work in > 5.00
	int(*sceSysUtilSendSystemNotificationWithText)(int messageType, char* message) = NULL;

	sys_dynlib_dlsym(moduleId, "sceSysUtilSendSystemNotificationWithText", &sceSysUtilSendSystemNotificationWithText);


	char* initMessage23 = "2222";
	sceSysUtilSendSystemNotificationWithText(222, initMessage23);

	mount_large_fs("/dev/da0x1.crypt", "/preinst2", "exfatfs", "511", MNT_RDONLY);
	mount_large_fs("/dev/da0x4.crypt", "/system", "exfatfs", "511", MNT_RDONLY);
	mount_large_fs("/dev/da0x5.crypt", "/system_ex", "exfatfs", "511", MNT_RDONLY);
	mount_large_fs("/dev/da0x0.crypt", "/preinst", "exfatfs", "511", MNT_RDONLY);

	char* initMessages2 = "sssss";
	sceSysUtilSendSystemNotificationWithText(222, initMessages2);


	char* initMessage2 = "R/W Off\n Your Safe";
	sceSysUtilSendSystemNotificationWithText(222, initMessage2);

	return 0;
}

#define FTP_PORT 21

void klog(const char *format, ...)	// didn't notice before, the addrs aren't aligned and deff not correct
{
	char *buff[1024];
	memset(buff, 0, 1024);

	va_list args;
	va_start(args, format);
	vsprintf(buff, format, args);
	va_end(args);



	int fd = opens("/dev/klog", O_WRONLY, 0600);             // O_DIRECT | opens the device with read/write access
	if (fd < 0) {
		perror("Failed to opens the device...");		// idk if we have perror, doesn't matter we'll find out 
		return;
	}

	char *t = buff;
	while (0 != *t) write(fd, t++, 1);
	close(fd);

	///* WTF/>
	fd = opens("/dev/ttyu0", O_WRONLY, 0600);             // O_DIRECT | opens the device with read/write access
	if (fd < 0) {
		perror("Failed to opens the device...");		// idk if we have perror, doesn't matter we'll find out 
		return;
	}

	t = buff;
	while (0 != *t) write(fd, t++, 1);
	close(fd);
	//*/
}

extern u8 _start[], _end[];
#define PAGE_SIZEs 0x4000

int FTPAddr(void *start, void *end, int perm)
{
	void* kbase = 0;
	uint8_t* kernel_ptr;


	if (!memcmp((char*)(&((uint8_t*)__readmsr(0xC0000082))[-KERN_505_XFAST_SYSCALL]), (char[4]) { 0x7F, 0x45, 0x4C, 0x46 }, 4)) {

		kbase = &((uint8_t*)__readmsr(0xC0000082))[-KERN_505_XFAST_SYSCALL];
		int(*printfkernel)(const char *fmt, ...) = (void *)(kbase + KERN_505_PRINTF);
		u64 s = ((u64)start) & ~(u64)(PAGE_SIZEs - 1);
		u64 e = ((u64)end + PAGE_SIZEs - 1) & ~(u64)(PAGE_SIZEs - 1);
		printfkernel("FTP Started on Addr /5.05/ ( %p, %p, %d)\n", (void*)s, (void*)e, perm);
		return 0;
	}

	else if (!memcmp((char*)(&((uint8_t*)__readmsr(0xC0000082))[-KERN_455_XFAST_SYSCALL]), (char[4]) { 0x7F, 0x45, 0x4C, 0x46 }, 4)) {

		kbase = &((uint8_t*)__readmsr(0xC0000082))[-KERN_455_XFAST_SYSCALL];
		int(*printfkernel)(const char *fmt, ...) = (void *)(kbase + KERN_455_PRINTF);
		u64 s = ((u64)start) & ~(u64)(PAGE_SIZEs - 1);
		u64 e = ((u64)end + PAGE_SIZEs - 1) & ~(u64)(PAGE_SIZEs - 1);
		printfkernel("FTP Started on Addr /4.55/ ( %p, %p, %d)\n", (void*)s, (void*)e, perm);
		return 0;
	}
	else return -1;

	return 0;



}

// show me where you want it to load usb, like where does the prx export begin? yea it is setup for net now, can't really do both on same call 

#define SERVER_TCP_PORT (1480)

int FTPAddrs()
{
	FTPAddr(_start, _end, 7);

	return 0;

}

int FTPStart()
{

		char ip_address[SCE_NET_CTL_IPV4_ADDR_STR_LEN];
		char msg[64];

		get_ip_address(ip_address);

		ftps4_init(ip_address, FTP_PORT);

		syscall(11, FTPAddrs);
return 0;
}


int dump_all()
{
	int moduleId = -1;
	sys_dynlib_load_prx("libSceSysUtil.sprx", &moduleId);

	// This header doesn't work in > 5.00
	int(*sceSysUtilSendSystemNotificationWithText)(int messageType, char* message) = NULL;

	sys_dynlib_dlsym(moduleId, "sceSysUtilSendSystemNotificationWithText", &sceSysUtilSendSystemNotificationWithText);

	char* initMessage2 = "System Dump Start, May take a while";
	sceSysUtilSendSystemNotificationWithText(222, initMessage2);

#if 1



#else

	//decrypt_and_dump_self("/system_ex/app/NPXS20001/eboot.bin", "/mnt/usb0/system/NPXS20001-eboot.bin");
	//decrypt_and_dump_self("/system_ex/app/NPXS20103/eboot.bin", "/mnt/usb0/system/NPXS20103-eboot.bin");
	//decrypt_and_dump_self("/system_ex/app/NPXS20113/eboot.bin", "/mnt/usb0/system/NPXS20113-eboot.bin");
	//decrypt_and_dump_self("/system_ex/app/NPXS20114/eboot.bin", "/mnt/usb0/system/NPXS20114-eboot.bin");
	//decrypt_and_dump_self("/system_ex/app/NPXS20118/eboot.bin", "/mnt/usb0/system/NPXS20118-eboot.bin");
	//decrypt_and_dump_self("/system_ex/app/NPXS20120/eboot.bin", "/mnt/usb0/system/NPXS20120-eboot.bin");
	//decrypt_and_dump_self("/system/vsh/app/NPXS20119/eboot.bin", "/mnt/usb0/system/NPXS20119-eboot.bin");
	//decrypt_and_dump_self("/system/vsh/app/NPXS21000/eboot.bin", "/mnt/usb0/system/NPXS21000-eboot.bin");
	//decrypt_and_dump_self("/system/vsh/app/NPXS21001/eboot.bin", "/mnt/usb0/system/NPXS21001-eboot.bin");
	//decrypt_and_dump_self("/system/vsh/app/NPXS21002/eboot.bin", "/mnt/usb0/system/NPXS21002-eboot.bin");
	//decrypt_and_dump_self("/system/vsh/app/NPXS21003/eboot.bin", "/mnt/usb0/system/NPXS21003-eboot.bin");
	//decrypt_and_dump_self("/system/vsh/app/NPXS21004/eboot.bin", "/mnt/usb0/system/NPXS21004-eboot.bin");
	//decrypt_and_dump_self("/system/vsh/app/NPXS21005/eboot.bin", "/mnt/usb0/system/NPXS21005-eboot.bin");
	//decrypt_and_dump_self("/system/vsh/app/NPXS21006/eboot.bin", "/mnt/usb0/system/NPXS21006-eboot.bin");
	//decrypt_and_dump_self("/system/vsh/app/NPXS21007/eboot.bin", "/mnt/usb0/system/NPXS21007-eboot.bin");
	//decrypt_and_dump_self("/system/vsh/app/NPXS21010/eboot.bin", "/mnt/usb0/system/NPXS21010-eboot.bin");
	//decrypt_and_dump_self("/system/vsh/app/NPXS21012/eboot.bin", "/mnt/usb0/system/NPXS21012-eboot.bin");
	//decrypt_and_dump_self("/system/vsh/app/NPXS21016/eboot.bin", "/mnt/usb0/system/NPXS21016-eboot.bin");
	//decrypt_and_dump_self("/system/vsh/app/NPXS21019/eboot.bin", "/mnt/usb0/system/NPXS21019-eboot.bin");
	//decrypt_and_dump_self("/system/vsh/app/NPXS22010/eboot.bin", "/mnt/usb0/system/NPXS22010-eboot.bin");
	//decrypt_and_dump_self("/system/vsh/sce_video_service/eboot.bin", "/mnt/usb0/vsh/sce_video_service.bin");
	//decrypt_and_dump_self("/system_ex/app/NPXS20001/psm/Application/platform.dll.sprx", "/mnt/usb0/system/platform.dll.sprx");
	//decrypt_and_dump_self("/system_ex/app/NPXS20001/psm/Application/Sce.Vsh.AppContentUtilWrapper.dll.sprx", "/mnt/usb0/system/Sce.Vsh.AppContentUtilWrapper.dll.sprx");
	//decrypt_and_dump_self("/system_ex/app/NPXS20001/psm/Application/Sce.Vsh.EventApp.dll.sprx", "/mnt/usb0/system/Sce.Vsh.EventApp.dll.sprx");
	//decrypt_and_dump_self("/system_ex/app/NPXS20001/psm/Application/Sce.Vsh.GameCustomData.dll.sprx", "/mnt/usb0/system/Sce.Vsh.GameCustomData.dll.sprx");
	//decrypt_and_dump_self("/system_ex/app/NPXS20001/psm/Application/Sce.Vsh.GriefReport.dll.sprx", "/mnt/usb0/system/Sce.Vsh.GriefReport.dll.sprx");
	//decrypt_and_dump_self("/system_ex/app/NPXS20001/psm/Application/Sce.Vsh.Messages.dll.sprx", "/mnt/usb0/system/Sce.Vsh.Messages.dll.sprx");
	//decrypt_and_dump_self("/system_ex/app/NPXS20001/psm/Application/Sce.Vsh.Np.AppLaunchLink.dll.sprx", "/mnt/usb0/system/Sce.Vsh.Np.AppLaunchLink.dll.sprx");
	//decrypt_and_dump_self("/system_ex/app/NPXS20001/psm/Application/Sce.Vsh.Orbis.BgftAccessor.dll.sprx", "/mnt/usb0/system/Sce.Vsh.Orbis.BgftAccessor.dll.sprx");
	//decrypt_and_dump_self("/system_ex/app/NPXS20001/psm/Application/Sce.Vsh.Orbis.CdlgServerNpCommerce.dll.sprx", "/mnt/usb0/system/Sce.Vsh.Orbis.CdlgServerNpCommerce.dll.sprx");
	////decrypt_and_dump_self("/system_ex/app/NPXS20001/psm/Application/Sce.Vsh.SessionInvitation.dll.sprx", "/mnt/usb0/system/Sce.Vsh.SessionInvitation.dll.sprx");
	//decrypt_and_dump_self("/system_ex/app/NPXS20001/psm/Application/Sce.Vsh.Sticker.dll.sprx", "/mnt/usb0/system/Sce.Vsh.Sticker.dll.sprx");
	//decrypt_and_dump_self("/system_ex/app/NPXS20001/psm/Application/Sce.Vsh.VideoRecordingWrapper.dll.sprx", "/mnt/usb0/system/Sce.Vsh.VideoRecordingWrapper.dll.sprx");
	//decrypt_and_dump_self("/system_ex/app/NPXS20103/psm/Application/Sce.Vsh.VideoEdit.Wrapper.dll.sprx", "/mnt/usb0/system/Sce.Vsh.VideoEdit.Wrapper.dll.sprx");
	////decrypt_and_dump_self("/system_ex/app/NPXS20113/psm/Application/Sce.Vsh.DiscPlayer.dll.sprx", "/mnt/usb0/system/Sce.Vsh.DiscPlayer.dll.sprx");
	//decrypt_and_dump_self("/system_ex/app/NPXS20114/psm/Application/Sce.CloudClient.App.Platform.dll.sprx", "/mnt/usb0/system/Sce.CloudClient.App.Platform.dll.sprx");
	//decrypt_and_dump_self("/system_ex/app/NPXS20118/psm/Application/Sce.Vsh.RemotePlay.dll.sprx", "/mnt/usb0/system/Sce.Vsh.RemotePlay.dll.sprx");
	//decrypt_and_dump_self("/system_ex/app/NPXS20120/psm/Application/ClassLibrary1.dll.sprx", "/mnt/usb0/system/ClassLibrary1.dll.sprx");
	////decrypt_and_dump_self("/system_ex/app/NPXS20120/psm/Application/Sce.Vsh.MarlinDownloaderWrapper.dll.sprx", "/mnt/usb0/system/Sce.Vsh.MarlinDownloaderWrapper.dll.sprx");
	//decrypt_and_dump_self("/system/common/lib/I18N.CJK.dll.sprx", "/mnt/usb0/system/I18N.CJK.dll.sprx");
	//decrypt_and_dump_self("/system/common/lib/I18N.dll.sprx", "/mnt/usb0/system/I18N.dll.sprx");
	//decrypt_and_dump_self("/system/common/lib/mscorlib.dll.sprx", "/mnt/usb0/system/mscorlib.dll.sprx");
	//decrypt_and_dump_self("/system/common/lib/Sce.PlayStation.Core.dll.sprx", "/mnt/usb0/system/Sce.PlayStation.Core.dll.sprx");
	//decrypt_and_dump_self("/system/common/lib/Sce.PlayStation.HighLevel.UI2.dll.sprx", "/mnt/usb0/system/Sce.PlayStation.HighLevel.UI2.dll.sprx");
	//decrypt_and_dump_self("/system/common/lib/Sce.PlayStation.HighLevel.UI2Platform.dll.sprx", "/mnt/usb0/system/Sce.PlayStation.HighLevel.UI2Platform.dll.sprx");
	//decrypt_and_dump_self("/system/common/lib/Sce.PlayStation.Ime.dll.sprx", "/mnt/usb0/system/Sce.PlayStation.Ime.dll.sprx");
	//decrypt_and_dump_self("/system/common/lib/Sce.PlayStation.Orbis.dll.sprx", "/mnt/usb0/system/Sce.PlayStation.Orbis.dll.sprx");
	//decrypt_and_dump_self("/system/common/lib/Sce.PlayStation.Orbis.Speech.dll.sprx", "/mnt/usb0/system/Sce.PlayStation.Orbis.Speech.dll.sprx");
	//decrypt_and_dump_self("/system/common/lib/Sce.Vsh.Accessor.Db.Notify.dll.sprx", "/mnt/usb0/system/Sce.Vsh.Accessor.Db.Notify.dll.sprx");
	//decrypt_and_dump_self("/system/common/lib/Sce.Vsh.Accessor.Db.dll.sprx", "/mnt/usb0/system/Sce.Vsh.Accessor.Db.dll.sprx");
	//decrypt_and_dump_self("/system/common/lib/Sce.Vsh.Accessor.dll.sprx", "/mnt/usb0/system/Sce.Vsh.Accessor.dll.sprx");
	//decrypt_and_dump_self("/system/common/lib/Sce.Vsh.AppDbWrapper.dll.sprx", "/mnt/usb0/system/Sce.Vsh.AppDbWrapper.dll.sprx");
	//decrypt_and_dump_self("/system/common/lib/Sce.Vsh.AppInstUtilWrapper.dll.sprx", "/mnt/usb0/system/Sce.Vsh.AppInstUtilWrapper.dll.sprx");
	//decrypt_and_dump_self("/system/common/lib/Sce.Vsh.AutoMounterWrapper.dll.sprx", "/mnt/usb0/system/Sce.Vsh.AutoMounterWrapper.dll.sprx");
	//decrypt_and_dump_self("/system/common/lib/Sce.Vsh.BackupRestoreUtil.dll.sprx", "/mnt/usb0/system/Sce.Vsh.BackupRestoreUtil.dll.sprx");
	//decrypt_and_dump_self("/system/common/lib/Sce.Vsh.DataTransfer.dll.sprx", "/mnt/usb0/system/Sce.Vsh.DataTransfer.dll.sprx");
	//decrypt_and_dump_self("/system/common/lib/Sce.Vsh.Db.Shared.dll.sprx", "/mnt/usb0/system/Sce.Vsh.Db.Shared.dll.sprx");
	//decrypt_and_dump_self("/system/common/lib/Sce.Vsh.DbPreparationWrapper.dll.sprx", "/mnt/usb0/system/Sce.Vsh.DbPreparationWrapper.dll.sprx");
	//decrypt_and_dump_self("/system/common/lib/Sce.Vsh.DbRecoveryUtilityWrapper.dll.sprx", "/mnt/usb0/system/Sce.Vsh.DbRecoveryUtilityWrapper.dll.sprx");
	//decrypt_and_dump_self("/system/common/lib/Sce.Vsh.ErrorDialogUtilWrapper.dll.sprx", "/mnt/usb0/system/Sce.Vsh.ErrorDialogUtilWrapper.dll.sprx");
	//decrypt_and_dump_self("/system/common/lib/Sce.Vsh.EventServiceWrapper.dll.sprx", "/mnt/usb0/system/Sce.Vsh.EventServiceWrapper.dll.sprx");
	//decrypt_and_dump_self("/system/common/lib/Sce.Vsh.FileSelector.dll.sprx", "/mnt/usb0/system/Sce.Vsh.FileSelector.dll.sprx");
	//decrypt_and_dump_self("/system/common/lib/Sce.Vsh.Friend.dll.sprx", "/mnt/usb0/system/Sce.Vsh.Friend.dll.sprx");
	//decrypt_and_dump_self("/system/common/lib/Sce.Vsh.GameListRetrieverWrapper.dll.sprx", "/mnt/usb0/system/Sce.Vsh.GameListRetrieverWrapper.dll.sprx");
	//decrypt_and_dump_self("/system/common/lib/Sce.Vsh.Gls.GlsSharedMediaView.dll.sprx", "/mnt/usb0/system/Sce.Vsh.Gls.GlsSharedMediaView.dll.sprx");
	//decrypt_and_dump_self("/system/common/lib/Sce.Vsh.Gls.NativeCall.dll.sprx", "/mnt/usb0/system/Sce.Vsh.Gls.NativeCall.dll.sprx");
	//decrypt_and_dump_self("/system/common/lib/Sce.Vsh.GriefReportStorage.dll.sprx", "/mnt/usb0/system/Sce.Vsh.GriefReportStorage.dll.sprx");
	//decrypt_and_dump_self("/system/common/lib/Sce.Vsh.JsExtension.dll.sprx", "/mnt/usb0/system/Sce.Vsh.JsExtension.dll.sprx");
	//decrypt_and_dump_self("/system/common/lib/Sce.Vsh.KernelSysWrapper.dll.sprx", "/mnt/usb0/system/Sce.Vsh.KernelSysWrapper.dll.sprx");
	//decrypt_and_dump_self("/system/common/lib/Sce.Vsh.Lx.dll.sprx", "/mnt/usb0/system/Sce.Vsh.Lx.dll.sprx");
	//decrypt_and_dump_self("/system/common/lib/Sce.Vsh.MarlinDownloaderWrapper.dll.sprx", "/mnt/usb0/system/Sce.Vsh.MarlinDownloaderWrapper.dll.sprx");
	////decrypt_and_dump_self("/system/common/lib/Sce.Vsh.Messages.BgAccessLib.dll.sprx", "/mnt/usb0/system/Sce.Vsh.Messages.BgAccessLib.dll.sprx");
	//decrypt_and_dump_self("/system/common/lib/Sce.Vsh.Messages.DbAccessLib.dll.sprx", "/mnt/usb0/system/Sce.Vsh.Messages.DbAccessLib.dll.sprx");
	////decrypt_and_dump_self("/system/common/lib/Sce.Vsh.Messages.StorageAccessLib.dll.sprx", "/mnt/usb0/system/Sce.Vsh.Messages.StorageAccessLib.dll.sprx");
	//decrypt_and_dump_self("/system/common/lib/Sce.Vsh.MimeType.dll.sprx", "/mnt/usb0/system/Sce.Vsh.MimeType.dll.sprx");
	////decrypt_and_dump_self("/system/common/lib/Sce.Vsh.MorpheusUpdWrapper.dll.sprx", "/mnt/usb0/system/Sce.Vsh.MorpheusUpdWrapper.dll.sprx");
	//decrypt_and_dump_self("/system/common/lib/Sce.Vsh.MyGameList.dll.sprx", "/mnt/usb0/system/Sce.Vsh.MyGameList.dll.sprx");
	//decrypt_and_dump_self("/system/common/lib/Sce.Vsh.Np.AppInfo.dll.sprx", "/mnt/usb0/system/Sce.Vsh.Np.AppInfo.dll.sprx");
	//decrypt_and_dump_self("/system/common/lib/Sce.Vsh.Np.Asm.dll.sprx", "/mnt/usb0/system/Sce.Vsh.Np.Asm.dll.sprx");
	//decrypt_and_dump_self("/system/common/lib/Sce.Vsh.Np.Common.dll.sprx", "/mnt/usb0/system/Sce.Vsh.Np.Common.dll.sprx");
	//decrypt_and_dump_self("/system/common/lib/Sce.Vsh.Np.IdMapper.dll.sprx", "/mnt/usb0/system/Sce.Vsh.Np.IdMapper.dll.sprx");
	//decrypt_and_dump_self("/system/common/lib/Sce.Vsh.Np.Manager.dll.sprx", "/mnt/usb0/system/Sce.Vsh.Np.Manager.dll.sprx");
	//decrypt_and_dump_self("/system/common/lib/Sce.Vsh.Np.RifManager.dll.sprx", "/mnt/usb0/system/Sce.Vsh.Np.RifManager.dll.sprx");
	//decrypt_and_dump_self("/system/common/lib/Sce.Vsh.Np.ServiceChecker.dll.sprx", "/mnt/usb0/system/Sce.Vsh.Np.ServiceChecker.dll.sprx");
	//decrypt_and_dump_self("/system/common/lib/Sce.Vsh.Np.ServiceChecker2.dll.sprx", "/mnt/usb0/system/Sce.Vsh.Np.ServiceChecker2.dll.sprx");
	//decrypt_and_dump_self("/system/common/lib/Sce.Vsh.Np.Sns.dll.sprx", "/mnt/usb0/system/Sce.Vsh.Np.Sns.dll.sprx");
	//decrypt_and_dump_self("/system/common/lib/Sce.Vsh.Np.Tmdb.dll.sprx", "/mnt/usb0/system/Sce.Vsh.Np.Tmdb.dll.sprx");
	//decrypt_and_dump_self("/system/common/lib/Sce.Vsh.Np.Trophy.dll.sprx", "/mnt/usb0/system/Sce.Vsh.Np.Trophy.dll.sprx");
	//decrypt_and_dump_self("/system/common/lib/Sce.Vsh.Np.Webapi.dll.sprx", "/mnt/usb0/system/Sce.Vsh.Np.Webapi.dll.sprx");
	//decrypt_and_dump_self("/system/common/lib/Sce.Vsh.Orbis.AbstractStorage.dll.sprx", "/mnt/usb0/system/Sce.Vsh.Orbis.AbstractStorage.dll.sprx");
	//decrypt_and_dump_self("/system/common/lib/Sce.Vsh.Orbis.Bgft.dll.sprx", "/mnt/usb0/system/Sce.Vsh.Orbis.Bgft.dll.sprx");
	//decrypt_and_dump_self("/system/common/lib/Sce.Vsh.Orbis.ContentManager.dll.sprx", "/mnt/usb0/system/Sce.Vsh.Orbis.ContentManager.dll.sprx");
	//decrypt_and_dump_self("/system/common/lib/Sce.Vsh.PartyCommon.dll.sprx", "/mnt/usb0/system/Sce.Vsh.PartyCommon.dll.sprx");
	//decrypt_and_dump_self("/system/common/lib/Sce.Vsh.Passcode.dll.sprx", "/mnt/usb0/system/Sce.Vsh.Passcode.dll.sprx");
	//decrypt_and_dump_self("/system/common/lib/Sce.Vsh.PatchCheckerClientWrapper.dll.sprx", "/mnt/usb0/system/Sce.Vsh.PatchCheckerClientWrapper.dll.sprx");
	//decrypt_and_dump_self("/system/common/lib/Sce.Vsh.ProfileCache.dll.sprx", "/mnt/usb0/system/Sce.Vsh.ProfileCache.dll.sprx");
	//decrypt_and_dump_self("/system/common/lib/Sce.Vsh.PsnMessageUtil.dll.sprx", "/mnt/usb0/system/Sce.Vsh.PsnMessageUtil.dll.sprx");
	//decrypt_and_dump_self("/system/common/lib/Sce.Vsh.PsnUtil.dll.sprx", "/mnt/usb0/system/Sce.Vsh.PsnUtil.dll.sprx");
	//decrypt_and_dump_self("/system/common/lib/Sce.Vsh.Registry.dll.sprx", "/mnt/usb0/system/Sce.Vsh.Registry.dll.sprx");
	//decrypt_and_dump_self("/system/common/lib/Sce.Vsh.RequestShareScreen.dll.sprx", "/mnt/usb0/system/Sce.Vsh.RequestShareScreen.dll.sprx");
	//decrypt_and_dump_self("/system/common/lib/Sce.Vsh.RequestShareStorageWrapper.dll.sprx", "/mnt/usb0/system/Sce.Vsh.RequestShareStorageWrapper.dll.sprx");
	//decrypt_and_dump_self("/system/common/lib/Sce.Vsh.dll.sprx", "/mnt/usb0/system/Sce.Vsh.dll.sprx");
	//decrypt_and_dump_self("/system/common/lib/Sce.Vsh.SessionInvitation.dll.sprx", "/mnt/usb0/system/Sce.Vsh.SessionInvitation.dll.sprx");
	//decrypt_and_dump_self("/system/common/lib/Sce.Vsh.ShareServerPostWrapper.dll.sprx", "/mnt/usb0/system/Sce.Vsh.ShareServerPostWrapper.dll.sprx");
	//decrypt_and_dump_self("/system/common/lib/Sce.Vsh.ShellCoreUtilWrapper.dll.sprx", "/mnt/usb0/system/Sce.Vsh.ShellCoreUtilWrapper.dll.sprx");
	//decrypt_and_dump_self("/system/common/lib/Sce.Vsh.SQLite.dll.sprx", "/mnt/usb0/system/Sce.Vsh.SQLite.dll.sprx");
	//decrypt_and_dump_self("/system/common/lib/Sce.Vsh.Sticker.StickerLibAccessor.dll.sprx", "/mnt/usb0/system/Sce.Vsh.Sticker.StickerLibAccessor.dll.sprx");
	//decrypt_and_dump_self("/system/common/lib/Sce.Vsh.SyscallWrapper.dll.sprx", "/mnt/usb0/system/Sce.Vsh.SyscallWrapper.dll.sprx");
	//decrypt_and_dump_self("/system/common/lib/Sce.Vsh.SysfileUtilWrapper.dll.sprx", "/mnt/usb0/system/Sce.Vsh.SysfileUtilWrapper.dll.sprx");
	//decrypt_and_dump_self("/system/common/lib/Sce.Vsh.SystemLoggerWrapper.dll.sprx", "/mnt/usb0/system/Sce.Vsh.SystemLoggerWrapper.dll.sprx");
	//decrypt_and_dump_self("/system/common/lib/Sce.Vsh.SysUtilWrapper.dll.sprx", "/mnt/usb0/system/Sce.Vsh.SysUtilWrapper.dll.sprx");
	//decrypt_and_dump_self("/system/common/lib/Sce.Vsh.Theme.dll.sprx", "/mnt/usb0/system/Sce.Vsh.Theme.dll.sprx");
	//decrypt_and_dump_self("/system/common/lib/Sce.Vsh.UpdateServiceWrapper.dll.sprx", "/mnt/usb0/system/Sce.Vsh.UpdateServiceWrapper.dll.sprx");
	//decrypt_and_dump_self("/system/common/lib/Sce.Vsh.UsbStorageScene.dll.sprx", "/mnt/usb0/system/Sce.Vsh.UsbStorageScene.dll.sprx");
	//decrypt_and_dump_self("/system/common/lib/Sce.Vsh.UserServiceWrapper.dll.sprx", "/mnt/usb0/system/Sce.Vsh.UserServiceWrapper.dll.sprx");
	//decrypt_and_dump_self("/system/common/lib/Sce.Vsh.VideoServiceWrapper.dll.sprx", "/mnt/usb0/system/Sce.Vsh.VideoServiceWrapper.dll.sprx");
	//decrypt_and_dump_self("/system/common/lib/Sce.Vsh.VoiceMsg.VoiceMsgWrapper.dll.sprx", "/mnt/usb0/system/Sce.Vsh.VoiceMsg.VoiceMsgWrapper.dll.sprx");
	//decrypt_and_dump_self("/system/common/lib/Sce.Vsh.VrEnvironment.dll.sprx", "/mnt/usb0/system/Sce.Vsh.VrEnvironment.dll.sprx");
	//decrypt_and_dump_self("/system/common/lib/Sce.Vsh.WebBrowser.dll.sprx", "/mnt/usb0/system/Sce.Vsh.WebBrowser.dll.sprx");
	//decrypt_and_dump_self("/system/common/lib/Sce.Vsh.Webbrowser.XdbWrapper.dll.sprx", "/mnt/usb0/system/Sce.Vsh.Webbrowser.XdbWrapper.dll.sprx");
	//decrypt_and_dump_self("/system/common/lib/Sce.Vsh.Webbrowser.XutilWrapper.dll.sprx", "/mnt/usb0/system/Sce.Vsh.Webbrowser.XutilWrapper.dll.sprx");
	//decrypt_and_dump_self("/system/common/lib/Sce.Vsh.WebViewDialog.dll.sprx", "/mnt/usb0/system/Sce.Vsh.WebViewDialog.dll.sprx");
	//decrypt_and_dump_self("/system/common/lib/System.Core.dll.sprx", "/mnt/usb0/system/System.Core.dll.sprx");
	////decrypt_and_dump_self("/system/common/lib/System.Json.dll.sprx", "/mnt/usb0/system/System.Json.dll.sprx");
	//decrypt_and_dump_self("/system/common/lib/System.Runtime.Serialization.dll.sprx", "/mnt/usb0/system/System.Runtime.Serialization.dll.sprx");
	//decrypt_and_dump_self("/system/common/lib/System.dll.sprx", "/mnt/usb0/system/System.dll.sprx");
	//decrypt_and_dump_self("/system/common/lib/System.ServiceModel.dll.sprx", "/mnt/usb0/system/System.ServiceModel.dll.sprx");
	//decrypt_and_dump_self("/system/common/lib/System.ServiceModel.Web.dll.sprx", "/mnt/usb0/system/System.ServiceModel.Web.dll.sprx");
	//decrypt_and_dump_self("/system/common/lib/System.ServiceModel.Internals.dll.sprx", "/mnt/usb0/system/System.ServiceModel.Internals.dll.sprx");
	//decrypt_and_dump_self("/system/common/lib/System.Web.Services.dll.sprx", "/mnt/usb0/system/System.Web.Services.dll.sprx");
	//decrypt_and_dump_self("/system/common/lib/System.Xml.Linq.dll.sprx", "/mnt/usb0/system/System.Xml.Linq.dll.sprx");
	//decrypt_and_dump_self("/system/common/lib/System.Xml.dll.sprx", "/mnt/usb0/system/System.Xml.dll.sprx");
	char* initMessageq = "qqqqqqqqqqqqqqSystem Dump Start, May take a while";
	sceSysUtilSendSystemNotificationWithText(222, initMessageq);
	dump1();
	dump2();
	dump3();
#endif
	char* initMessage = "ALL System File Dumped\n Saved to /sytem/ on USB0\n Keep this Safe!";
	sceSysUtilSendSystemNotificationWithText(222, initMessage);


	return 0;
}

int dump3()

{
	int moduleId = -1;
	sys_dynlib_load_prx("libSceSysUtil.sprx", &moduleId);

	// This header doesn't work in > 5.00
	int(*sceSysUtilSendSystemNotificationWithText)(int messageType, char* message) = NULL;

	sys_dynlib_dlsym(moduleId, "sceSysUtilSendSystemNotificationWithText", &sceSysUtilSendSystemNotificationWithText);

	char* initMessage2 = "3";
	sceSysUtilSendSystemNotificationWithText(222, initMessage2);

	//decrypt_and_dump_self("/system/vsh/app/NPXS22010/psm/Application/Sce.Cdlg.Platform.dll.sprx", "/mnt/usb0/system/Sce.Cdlg.Platform.dll.sprx");
	//decrypt_and_dump_self("/system/vsh/app/NPXS22010/psm/Application/Sce.Vsh.ShellUIUtilWrapper.dll.sprx", "/mnt/usb0/Sce.Vsh.ShellUIUtilWrapper.dll.sprx");
	//decrypt_and_dump_self("/system/vsh/sce_video_service/psm/Application/Sce.Vsh.VideoFramework.Platform.dll.sprx", "/mnt/usb0/system/Sce.Vsh.VideoFramework.Platform.dll.sprx");
	//decrypt_and_dump_self("/system_ex/app/NPXS20001/psm/Application/app.exe.sprx", "/mnt/usb0/system/NPXS20001-app.exe.sprx");
	//decrypt_and_dump_self("/system_ex/app/NPXS20103/psm/Application/app.exe.sprx", "/mnt/usb0/system/NPXS20103-app.exe.sprx");
	//decrypt_and_dump_self("/system_ex/app/NPXS20113/psm/Application/app.exe.sprx", "/mnt/usb0/system/NPXS20113-app.exe.sprx");
	//decrypt_and_dump_self("/system_ex/app/NPXS20114/psm/Application/app.exe.sprx", "/mnt/usb0/system/NPXS20114-app.exe.sprx");
	//decrypt_and_dump_self("/system_ex/app/NPXS20118/psm/Application/app.exe.sprx", "/mnt/usb0/system/NPXS20118-app.exe.sprx");
	//decrypt_and_dump_self("/system_ex/app/NPXS20120/psm/Application/app.exe.sprx", "/mnt/usb0/system/NPXS20120-app.exe.sprx");
	//decrypt_and_dump_self("/system/vsh/app/NPXS22010/psm/Application/app.exe.sprx", "/mnt/usb0/system/NPXS22010-app.exe.sprx");
	//decrypt_and_dump_self("/system/vsh/sce_video_service/psm/Application/app.exe.sprx", "/mnt/usb0/system/sce_video_service-app.exe.sprx");
	//decrypt_and_dump_self("/system_ex/app/NPXS20120/avbaseMiniApp.self", "/mnt/usb0/system/NPXS20120-avbaseMiniApp.self");
	//decrypt_and_dump_self("/system/common/lib/orbis-jsc-compiler.self", "/mnt/usb0/system/orbis-jsc-compiler.self");
	//decrypt_and_dump_self("/system/common/lib/ScePlayReady.self", "/mnt/usb0/system/ScePlayReady.self");
	//decrypt_and_dump_self("/system/common/lib/SecureUIProcess.self", "/mnt/usb0/system/SecureUIProcess.self");
	//decrypt_and_dump_self("/system/common/lib/SecureWebProcess.self", "/mnt/usb0/system/SecureWebProcess.self");
	//decrypt_and_dump_self("/system/common/lib/swagner.self", "/mnt/usb0/system/swagner.self");
	//decrypt_and_dump_self("/system/common/lib/swreset.self", "/mnt/usb0/system/swreset.self");
	//decrypt_and_dump_self("/system/common/lib/UIProcess.self", "/mnt/usb0/system/UIProcess.self");
	//decrypt_and_dump_self("/system/common/lib/webapp.self", "/mnt/usb0/system/webapp.self");
	//decrypt_and_dump_self("/system/common/lib/WebBrowserUIProcess.self", "/mnt/usb0/system/WebBrowserUIProcess.self");
	//decrypt_and_dump_self("/system/common/lib/WebProcess.self", "/mnt/usb0/system/WebProcess.self");
	//decrypt_and_dump_self("/system/common/lib/WebProcessHeapLimited.self", "/mnt/usb0/system/WebProcessHeapLimited.self");
	//decrypt_and_dump_self("/system/common/lib/WebProcessHTMLTile.self", "/mnt/usb0/system/WebProcessHTMLTile.self");
	//decrypt_and_dump_self("/system/common/lib/WebProcessWebApp.self", "/mnt/usb0/system/WebProcessWebApp.self");
	//decrypt_and_dump_self("/system/vsh/app/NPXS21007/BgmPlayerCore.self", "/mnt/usb0/system/NPXS21007-BgmPlayerCore.self");
	//decrypt_and_dump_self("/system/vsh/app/NPXS21007/BgmPlayerCore2.self", "/mnt/usb0/system/NPXS21007-BgmPlayerCore2.self");
	//decrypt_and_dump_self("/system_ex/app/NPXS20113/bdj.elf", "/mnt/usb0/system/NPXS20113-bdj.elf");
	//decrypt_and_dump_self("/system_ex/app/NPXS20113/BdmvPlayerCore.elf", "/mnt/usb0/system/NPXS20113-BdmvPlayerCore.elf");
	//decrypt_and_dump_self("/system_ex/app/NPXS20113/BdvdPlayerCore.elf", "/mnt/usb0/system/NPXS20113-BdvdPlayerCore.elf");
	//decrypt_and_dump_self("/system_ex/app/NPXS20113/bdjstack/bin/JavaJitCompiler.elf", "/mnt/usb0/system/NPXS20113-bdjstack-JavaJitCompiler.elf");
	//decrypt_and_dump_self("/system/common/lib/custom_video_core.elf", "/mnt/usb0/system/custom_video_core.elf");
	////decrypt_and_dump_self("/system/common/lib/MonoCompiler.elf", "/mnt/usb0/system/MonoCompiler.elf");
	//decrypt_and_dump_self("/system/sys/coredump.elf", "/mnt/usb0/system/coredump.elf");
	//decrypt_and_dump_self("/system/sys/fs_cleaner.elf", "/mnt/usb0/system/fs_cleaner.elf");
	//decrypt_and_dump_self("/system/sys/GnmCompositor.elf", "/mnt/usb0/system/GnmCompositor.elf");
	//decrypt_and_dump_self("/system/sys/gpudump.elf", "/mnt/usb0/system/gpudump.elf");
	//decrypt_and_dump_self("/system/sys/orbis_audiod.elf", "/mnt/usb0/system/orbis_audiod.elf");
	//decrypt_and_dump_self("/system/sys/orbis_setip.elf", "/mnt/usb0/system/orbis_setip.elf");
	//decrypt_and_dump_self("/system/sys/SceSysCore.elf", "/mnt/usb0/system/SceSysCore.elf");
	//decrypt_and_dump_self("/system/sys/SceVdecProxy.elf", "/mnt/usb0/system/SceVdecProxy.elf");
	//decrypt_and_dump_self("/system/sys/SceVencProxy.elf", "/mnt/usb0/system/SceVencProxy.elf");
	//decrypt_and_dump_self("/system/vsh/SceShellCore.elf", "/mnt/usb0/vsh/SceShellCore.elf");
	//decrypt_and_dump_self("/system/vsh/app/NPXS21004/avbase.elf", "/mnt/usb0/system/NPXS21004-avbase.elf");
	//decrypt_and_dump_self("/system/vsh/app/NPXS21004/becore.elf", "/mnt/usb0/system/NPXS21004-becore.elf");
	//decrypt_and_dump_self("/system_ex/app/NPXS20113/libAacs.sprx", "/mnt/usb0/system/NPXS20113-libAacs.sprx");
	//decrypt_and_dump_self("/system_ex/app/NPXS20113/libBdplus.sprx", "/mnt/usb0/system/NPXS20113-libBdplus.sprx");
	//decrypt_and_dump_self("/system_ex/app/NPXS20113/libCprm.sprx", "/mnt/usb0/system/NPXS20113-libCprm.sprx");
	//decrypt_and_dump_self("/system_ex/app/NPXS20113/libCss.sprx", "/mnt/usb0/system/NPXS20113-libCss.sprx");
	//decrypt_and_dump_self("/system/common/lib/libc.sprx", "/mnt/usb0/system/libc.sprx");
	//decrypt_and_dump_self("/system/common/lib/libkernel.sprx", "/mnt/usb0/system/libkernel.sprx");
	//decrypt_and_dump_self("/system/common/lib/libkernel_sys.sprx", "/mnt/usb0/system/libkernel_sys.sprx");
	//decrypt_and_dump_self("/system/common/lib/libkernel_web.sprx", "/mnt/usb0/system/libkernel_web.sprx");
	//decrypt_and_dump_self("/system/common/lib/libSceAbstractDailymotion.sprx", "/mnt/usb0/system/libSceAbstractDailymotion.sprx");
	//decrypt_and_dump_self("/system/common/lib/libSceAbstractFacebook.sprx", "/mnt/usb0/system/libSceAbstractFacebook.sprx");
	//decrypt_and_dump_self("/system/common/lib/libSceAbstractLocal.sprx", "/mnt/usb0/system/libSceAbstractLocal.sprx");
	//decrypt_and_dump_self("/system/common/lib/libSceAbstractStorage.sprx", "/mnt/usb0/system/libSceAbstractStorage.sprx");
	//decrypt_and_dump_self("/system/common/lib/libSceAbstractTwitter.sprx", "/mnt/usb0/system/libSceAbstractTwitter.sprx");
	//decrypt_and_dump_self("/system/common/lib/libSceAbstractYoutube.sprx", "/mnt/usb0/system/libSceAbstractYoutube.sprx");
	//decrypt_and_dump_self("/system/common/lib/libSceAjm.sprx", "/mnt/usb0/system/libSceAjm.sprx");
	//decrypt_and_dump_self("/system/common/lib/libSceAppContent.sprx", "/mnt/usb0/system/libSceAppContent.sprx");
	//decrypt_and_dump_self("/system/common/lib/libSceAppInstUtil.sprx", "/mnt/usb0/system/libSceAppInstUtil.sprx");
	//decrypt_and_dump_self("/system/common/lib/libSceAt9Enc.sprx", "/mnt/usb0/system/libSceAt9Enc.sprx");
	//decrypt_and_dump_self("/system/common/lib/libSceAudio3d.sprx", "/mnt/usb0/system/libSceAudio3d.sprx");
	//decrypt_and_dump_self("/system/common/lib/libSceAudiodec.sprx", "/mnt/usb0/system/libSceAudiodec.sprx");
	//decrypt_and_dump_self("/system/common/lib/libSceAudiodecCpu.sprx", "/mnt/usb0/system/libSceAudiodecCpu.sprx");
	//decrypt_and_dump_self("/system/common/lib/libSceAudiodecCpuDdp.sprx", "/mnt/usb0/system/libSceAudiodecCpuDdp.sprx");
	//decrypt_and_dump_self("/system/common/lib/libSceAudiodecCpuDtsHdLbr.sprx", "/mnt/usb0/system/libSceAudiodecCpuDtsHdLbr.sprx");
	//decrypt_and_dump_self("/system/common/lib/libSceAudiodecCpuHevag.sprx", "/mnt/usb0/system/libSceAudiodecCpuHevag.sprx");
	//decrypt_and_dump_self("/system/common/lib/libSceAudiodecCpuM4aac.sprx", "/mnt/usb0/system/libSceAudiodecCpuM4aac.sprx");
	//decrypt_and_dump_self("/system/common/lib/libSceAudioIn.sprx", "/mnt/usb0/system/libSceAudioIn.sprx");
	//decrypt_and_dump_self("/system/common/lib/libSceAudioOut.sprx", "/mnt/usb0/system/libSceAudioOut.sprx");
	//decrypt_and_dump_self("/system/common/lib/libSceAutoMounterClient.sprx", "/mnt/usb0/system/libSceAutoMounterClient.sprx");
	//decrypt_and_dump_self("/system/common/lib/libSceAvcap.sprx", "/mnt/usb0/system/libSceAvcap.sprx");
	//decrypt_and_dump_self("/system/common/lib/libSceAvPlayer.sprx", "/mnt/usb0/system/libSceAvPlayer.sprx");
	//decrypt_and_dump_self("/system/common/lib/libSceAvPlayerStreaming.sprx", "/mnt/usb0/system/libSceAvPlayerStreaming.sprx");

	return 0;
}
int FTPS()
{
	ftps4_fini();

	int moduleId = -1;
	sys_dynlib_load_prx("libSceSysUtil.sprx", &moduleId);

	// This header doesn't work in > 5.00
	int(*sceSysUtilSendSystemNotificationWithText)(int messageType, char* message) = NULL;

	sys_dynlib_dlsym(moduleId, "sceSysUtilSendSystemNotificationWithText", &sceSysUtilSendSystemNotificationWithText);

	char* initMessage2 = "Button Combo Activated FTP has Stopped";
	sceSysUtilSendSystemNotificationWithText(222, initMessage2);

	return 0;

}
int dump2()
{

	int moduleId = -1;
	sys_dynlib_load_prx("libSceSysUtil.sprx", &moduleId);

	// This header doesn't work in > 5.00
	int(*sceSysUtilSendSystemNotificationWithText)(int messageType, char* message) = NULL;

	sys_dynlib_dlsym(moduleId, "sceSysUtilSendSystemNotificationWithText", &sceSysUtilSendSystemNotificationWithText);

	char* initMessage2 = "2";
	sceSysUtilSendSystemNotificationWithText(222, initMessage2);

	//decrypt_and_dump_self("/system/priv/lib/libmdbg_syscore.sprx", "/mnt/usb0/system/libmdbg_syscore.sprx");
	//decrypt_and_dump_self("/system/priv/lib/libSceAc3Enc.sprx", "/mnt/usb0/system/libSceAc3Enc.sprx");
	//decrypt_and_dump_self("/system/priv/lib/libSceAudiodecCpuDts.sprx", "/mnt/usb0/system/libSceAudiodecCpuDts.sprx");
	//decrypt_and_dump_self("/system/priv/lib/libSceAudiodecCpuDtsHdMa.sprx", "/mnt/usb0/system/libSceAudiodecCpuDtsHdMa.sprx");
	//decrypt_and_dump_self("/system/priv/lib/libSceAudiodecCpuLpcm.sprx", "/mnt/usb0/system/libSceAudiodecCpuLpcm.sprx");
	//decrypt_and_dump_self("/system/priv/lib/libSceAudiodReport.sprx", "/mnt/usb0/system/libSceAudiodReport.sprx");
	//decrypt_and_dump_self("/system/priv/lib/libSceComposite.sprx", "/mnt/usb0/system/libSceComposite.sprx");
	//decrypt_and_dump_self("/system/priv/lib/libSceDipsw.sprx", "/mnt/usb0/system/libSceDipsw.sprx");
	//decrypt_and_dump_self("/system/priv/lib/libSceDiscMapForVsh.sprx", "/mnt/usb0/system/libSceDiscMapForVsh.sprx");
	//decrypt_and_dump_self("/system/priv/lib/libSceDseehx.sprx", "/mnt/usb0/system/libSceDseehx.sprx");
	//decrypt_and_dump_self("/system/priv/lib/libSceDtsEnc.sprx", "/mnt/usb0/system/libSceDtsEnc.sprx");
	//decrypt_and_dump_self("/system/priv/lib/libSceGnmDriver_sys.sprx", "/mnt/usb0/system/libSceGnmDriver_sys.sprx");
	//decrypt_and_dump_self("/system/priv/lib/libSceLoginMgrServer.sprx", "/mnt/usb0/system/libSceLoginMgrServer.sprx");
	//decrypt_and_dump_self("/system/priv/lib/libSceMarlin.sprx", "/mnt/usb0/system/libSceMarlin.sprx");
	//decrypt_and_dump_self("/system/priv/lib/libSceOpusCeltEnc.sprx", "/mnt/usb0/system/libSceOpusCeltEnc.sprx");
	//decrypt_and_dump_self("/system/priv/lib/libSceS3da.sprx", "/mnt/usb0/system/libSceS3da.sprx");
	//decrypt_and_dump_self("/system/priv/lib/libSceSdma.sprx", "/mnt/usb0/system/libSceSdma.sprx");
	//decrypt_and_dump_self("/system/priv/lib/libSceSrcUtl.sprx", "/mnt/usb0/system/libSceSrcUtl.sprx");
	//decrypt_and_dump_self("/system/priv/lib/libSceSulphaDrv.sprx", "/mnt/usb0/system/libSceSulphaDrv.sprx");
	//decrypt_and_dump_self("/system/priv/lib/libSceVencCore.sprx", "/mnt/usb0/system/libSceVencCore.sprx");
	//decrypt_and_dump_self("/system/priv/lib/libSceVencCoreForNeo.sprx", "/mnt/usb0/system/libSceVencCoreForNeo.sprx");
	//decrypt_and_dump_self("/system/priv/lib/libSceVisionManager.sprx", "/mnt/usb0/system/libSceVisionManager.sprx");
	//decrypt_and_dump_self("/system/priv/lib/libSceVorbisDec.sprx", "/mnt/usb0/system/libSceVorbisDec.sprx");
	//decrypt_and_dump_self("/system/vsh/app/NPXS22010/libSceCdlg_aot.sprx", "/mnt/usb0/system/NPXS22010-libSceCdlg_aot.sprx");
	return 0;
}


int dump1()
{

	int moduleId = -1;
	sys_dynlib_load_prx("libSceSysUtil.sprx", &moduleId);

	// This header doesn't work in > 5.00
	int(*sceSysUtilSendSystemNotificationWithText)(int messageType, char* message) = NULL;

	sys_dynlib_dlsym(moduleId, "sceSysUtilSendSystemNotificationWithText", &sceSysUtilSendSystemNotificationWithText);

	char* initMessage2 = "1";
	sceSysUtilSendSystemNotificationWithText(222, initMessage2);

	//decrypt_and_dump_self("/system/common/lib/libSceAvSetting.sprx", "/mnt/usb0/system/libSceAvSetting.sprx");
	//decrypt_and_dump_self("/system/common/lib/libSceBackupRestoreUtil.sprx", "/mnt/usb0/system/libSceBackupRestoreUtil.sprx");
	//decrypt_and_dump_self("/system/common/lib/libSceBeisobmf.sprx", "/mnt/usb0/system/libSceBeisobmf.sprx");
	//decrypt_and_dump_self("/system/common/lib/libSceBemp2sys.sprx", "/mnt/usb0/system/libSceBemp2sys.sprx");
	//decrypt_and_dump_self("/system/common/lib/libSceBgft.sprx", "/mnt/usb0/system/libSceBgft.sprx");
	//decrypt_and_dump_self("/system/common/lib/libSceBluetoothHid.sprx", "/mnt/usb0/system/libSceBluetoothHid.sprx");
	//decrypt_and_dump_self("/system/common/lib/libSceCamera.sprx", "/mnt/usb0/system/libSceCamera.sprx");
	//decrypt_and_dump_self("/system/common/lib/libSceCdlgUtilServer.sprx", "/mnt/usb0/system/libSceCdlgUtilServer.sprx");
	//decrypt_and_dump_self("/system/common/lib/libSceClSysCallWrapper.sprx", "/mnt/usb0/system/libSceClSysCallWrapper.sprx");
	//decrypt_and_dump_self("/system/common/lib/libSceCommonDialog.sprx", "/mnt/usb0/system/libSceCommonDialog.sprx");
	//decrypt_and_dump_self("/system/common/lib/libSceCompanionHttpd.sprx", "/mnt/usb0/system/libSceCompanionHttpd.sprx");
	//decrypt_and_dump_self("/system/common/lib/libSceCompanionUtil.sprx", "/mnt/usb0/system/libSceCompanionUtil.sprx");
	//decrypt_and_dump_self("/system/common/lib/libSceCompositeExt.sprx", "/mnt/usb0/system/libSceCompositeExt.sprx");
	//decrypt_and_dump_self("/system/common/lib/libSceContentDelete.sprx", "/mnt/usb0/system/libSceContentDelete.sprx");
	//decrypt_and_dump_self("/system/common/lib/libSceContentExport.sprx", "/mnt/usb0/system/libSceContentExport.sprx");
	//decrypt_and_dump_self("/system/common/lib/libSceContentSearch.sprx", "/mnt/usb0/system/libSceContentSearch.sprx");
	//decrypt_and_dump_self("/system/common/lib/libSceConvertKeycode.sprx", "/mnt/usb0/system/libSceConvertKeycode.sprx");
	////decrypt_and_dump_self("/system/common/lib/libSceCoreIPC.sprx", "/mnt/usb0/system/libSceCoreIPC.sprx");
	//decrypt_and_dump_self("/system/common/lib/libSceCustomMusicCore.sprx", "/mnt/usb0/system/libSceCustomMusicCore.sprx");
	//decrypt_and_dump_self("/system/common/lib/libSceCustomMusicService.sprx", "/mnt/usb0/system/libSceCustomMusicService.sprx");
	//decrypt_and_dump_self("/system/common/lib/libSceDataTransfer.sprx", "/mnt/usb0/system/libSceDataTransfer.sprx");
	//decrypt_and_dump_self("/system/common/lib/libSceDepth.sprx", "/mnt/usb0/system/libSceDepth.sprx");
	//decrypt_and_dump_self("/system/common/lib/libSceDiscMap.sprx", "/mnt/usb0/system/libSceDiscMap.sprx");
	//decrypt_and_dump_self("/system/common/lib/libSceDtcpIp.sprx", "/mnt/usb0/system/libSceDtcpIp.sprx");
	//decrypt_and_dump_self("/system/common/lib/libSceEditMp4.sprx", "/mnt/usb0/system/libSceEditMp4.sprx");
	//decrypt_and_dump_self("/system/common/lib/libSceErrorDialog.sprx", "/mnt/usb0/system/libSceErrorDialog.sprx");
	//decrypt_and_dump_self("/system/common/lib/libSceFiber.sprx", "/mnt/usb0/system/libSceFiber.sprx");
	//decrypt_and_dump_self("/system/common/lib/libSceFios2.sprx", "/mnt/usb0/system/libSceFios2.sprx");

	return 0;
}


int eapkey()
{
	int moduleId = -1;
	sys_dynlib_load_prx("libSceSysUtil.sprx", &moduleId);

	// This header doesn't work in > 5.00
	int(*sceSysUtilSendSystemNotificationWithText)(int messageType, char* message) = NULL;

	sys_dynlib_dlsym(moduleId, "sceSysUtilSendSystemNotificationWithText", &sceSysUtilSendSystemNotificationWithText);


	uint64_t* dump = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	uint64_t filedump = mmap(NULL, KERN_DUMPSIZE, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);

	// patch some things in the kernel (sandbox, prison, debug settings etc..)

	struct payload_info payload_info;

	payload_info.uaddr = dump;

	kexec(&kpayloads, &payload_info);

	uint64_t kbase;
	memcpy(&kbase, dump, 8);


	uint64_t pos = 0;
	struct payload_info_dumper payload_info_dumper;

	struct EAP_PartKey_t *pkey = (struct EAP_PartKey_t *)(filedump + 0x20);

	payload_info_dumper.kaddr = kbase + 0x2790C90;
	payload_info_dumper.uaddr = filedump;

	// call our copyout wrapper and send the userland buffer over socket
	kexec(&kdump, &payload_info_dumper);

	//decrypt_and_dump_self("/system/vsh/SceShellCore.elf", "/mnt/usb0/shell.elf");
#define EAPKEY_FILEPATH "/mnt/usb0/eap_key.bin"

	int fd = opens(EAPKEY_FILEPATH, O_WRONLY | O_CREAT | O_TRUNC, 0777);

	if (fd > 0)
	{
		write(fd, filedump, 0x20); // Write the userland buffer to USB

		char* initMessage8w8 = ("EAP Key (HEX) \n\nDumped and Written to USB0\n Keep this Safe!");
		sceSysUtilSendSystemNotificationWithText(222, initMessage8w8);
		close(fd);
	}
	else {
		char* initMessage88 = ("Cant make File");
		sceSysUtilSendSystemNotificationWithText(222, initMessage88);
	}
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
	int fd = opens(KERN_FILEPATH, O_WRONLY | O_CREAT | O_TRUNC, 0777);

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

	int fd = opens("/mnt/usb0/file.bin", 0, 0);
	void* executable = mmap(NULL, st.st_size, PROT_READ | PROT_EXEC, MAP_PRIVATE | MAP_POPULATE, fd, 0);
	close(fd);

	int(*payloadEntry)(void) = (void*)executable;
	payloadEntry();

	return 0;
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

	int fd = opens("/mnt/usb0/file.bin", 0, 0);


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

int elfloadernote()
{

	int moduleId = -1;
	sys_dynlib_load_prx("libSceSysUtil.sprx", &moduleId);


	// This header doesn't work in > 5.00
	int(*sceSysUtilSendSystemNotificationWithText)(int messageType, char* message) = NULL;

	sys_dynlib_dlsym(moduleId, "sceSysUtilSendSystemNotificationWithText", &sceSysUtilSendSystemNotificationWithText);

	char* initMessage = "ELF Loader Loaded\n If you want to cancel close the App\n Listening on Port: 1480";
	sceSysUtilSendSystemNotificationWithText(222, initMessage);


	return 0;
}


int not505()
{

	int moduleId = -1;
	sys_dynlib_load_prx("libSceSysUtil.sprx", &moduleId);


	// This header doesn't work in > 5.00
	int(*sceSysUtilSendSystemNotificationWithText)(int messageType, char* message) = NULL;

	sys_dynlib_dlsym(moduleId, "sceSysUtilSendSystemNotificationWithText", &sceSysUtilSendSystemNotificationWithText);

	char* initMessage = "This Firmware is NOT Supported, Only 5.05 is Supported!";
	sceSysUtilSendSystemNotificationWithText(222, initMessage);

	return 0;
}


int loadElfFileelf()
{
	int ret = 0;
	//	struct stat sb;
	uint64_t fw_version = get_fw_version();

	if (fw_version == 0x505)
	{

		ret = sceSystemServiceLoadExec("/data/self/load.elf", NULL); // &args);
		printf("is a .elf\n Executing");
		if (ret) {
			printf("sceSystemServiceLoadExec failed: %d\n", ret);
			return -1;
		}
	}
	else
	{
		not505();
	}


	return 0;
}



int loadElfFilebin()
{
	uint64_t fw_version = get_fw_version();

	if (fw_version == 0x505)
	{
		int ret = 0;
		//	struct stat sb;

		ret = sceSystemServiceLoadExec("/data/self/load.bin", NULL); // &args);
		printf("is a .bin\n");
		printf("Executing....\n");
		printf("Executing....\n");
		printf("Executing....\n");
		printf("Executing....\n");
		printf("Executing....\n");
		if (ret) {
			printf("sceSystemServiceLoadExec failed: %d\n", ret);
			return -1;
		}
	}
	else
	{
		not505();
	}


	return 0;
}


int pkgdl()
{
	char ip_address[SCE_NET_CTL_IPV4_ADDR_STR_LEN];

	uint64_t fw_version = get_fw_version();

	int moduleId = -1;
	sys_dynlib_load_prx("libSceSysUtil.sprx", &moduleId);


	// This header doesn't work in > 5.00
	int(*sceSysUtilSendSystemNotificationWithText)(int messageType, char* message) = NULL;

	sys_dynlib_dlsym(moduleId, "sceSysUtilSendSystemNotificationWithText", &sceSysUtilSendSystemNotificationWithText);


	if (fw_version == 0x505)
	{
		int ret = 0;
		//	struct stat sb;
		klog("PKG Install Service Started\n");
		klog("Executing....\n");
		klog("Executing....\n");

		char buffers[10024];

		char* message = "PKG install Service Started";

		sceSysUtilSendSystemNotificationWithText(222, message);

		ret = sceSystemServiceLoadExec("/data/self/pkginstall.self", NULL); // &args);

		if (ret) {
			klog("sceSystemServiceLoadExec failed: %d\n", ret);
			return -1;
		}

	}
	else
	{
		not505();
	}


	return 0;
}

int ElfFileselfz()
{
	uint64_t fw_version = get_fw_version();

	if (fw_version == 0x505)
	{
		int ret = 0;
		//	struct stat sb;

		ret = sceSystemServiceLoadExec("/data/self/load.self", NULL); // &args);
		printf("is a .self\n Executing\n");
		printf("Executing....\n");
		printf("Executing....\n");
		printf("Executing....\n");
		printf("Executing....\n");
		printf("Executing....\n");

		if (ret) {
			printf("sceSystemServiceLoadExec failed: %d\n", ret);
			return -1;
		}
	}
	else
	{
		not505();
	}


	return 0;
}


int loadElfFileselfz()
{
	uint64_t fw_version = get_fw_version();

	if (fw_version == 0x505)
	{
		int ret = 0;
		//	struct stat sb;

		ret = sceSystemServiceLoadExec("/data/self/load.self", NULL); // &args);
		printf("is a .elf\n Executing");
		printf("Executing....\n");
		printf("Executing....\n");
		printf("Executing....\n");
		printf("Executing....\n");
		printf("Executing....\n");
		if (ret) {
			printf("sceSystemServiceLoadExec failed: %d\n", ret);
			return -1;
		}
	}

	else
	{
		not505();
	}

	return 0;
}


int cantfindelfs()
{

	int moduleId = -1;
	sys_dynlib_load_prx("libSceSysUtil.sprx", &moduleId);


	// This header doesn't work in > 5.00
	int(*sceSysUtilSendSystemNotificationWithText)(int messageType, char* message) = NULL;

	sys_dynlib_dlsym(moduleId, "sceSysUtilSendSystemNotificationWithText", &sceSysUtilSendSystemNotificationWithText);

	char* initMessage = "Could Not Find load.self, elf or .bin\n\n Please check your filename on your USB";
	sceSysUtilSendSystemNotificationWithText(222, initMessage);

	return 0;
}
