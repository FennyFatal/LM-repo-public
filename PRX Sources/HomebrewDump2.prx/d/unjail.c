

#define X86_CR0_WP (1 << 16)


#include "unjail.h"
#include "x86-64.h"
#include "stdio.h"
#include "magics.h"
#include "remount.h"
#include "dump.h"
#include "lv2.h"
#include "definess.h"
//#include <C:\Users\sethk\Desktop\oni-framework-master\include\oni/config.h>
//#include <C:\Users\sethk\Desktop\oni-framework-master\include\oni/messaging/message.h>
//#include <C:\Users\sethk\Desktop\oni-framework-master\include\oni/messaging/messagemanager.h>
//#include <C:\Users\sethk\Desktop\oni-framework-master\include\oni/utils/kdlsym.h>
//#include <C:\Users\sethk\Desktop\oni-framework-master\include\oni/utils/logger.h>
//#include <C:\Users\sethk\Desktop\oni-framework-master\include\oni/utils/memory/allocator.h>
//#include <C:\Users\sethk\Desktop\oni-framework-master\include\oni/utils/sys_wrappers.h>
//#include <C:\Users\sethk\Desktop\oni-framework-master\include\oni/utils/cpu.h>
//#include <sys/ioctl.h>
#include "elf64.h"
#include "elf_common.h"
#include "Modded_SDK\libPS4\include\ps4.h"
#define devclass_get_devices 0x312660
#define devclass_find 0x312020

struct kpayload_get_fw_version_info
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

};


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
#define KERN_FILEPATH "/mnt/usb0/kernel.bin"		// file path if debug socket isnt defined

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


//int64_t AvailableSpace{
	//get; 
//}



static void build_iovec(struct iovec** iov, int* iovlen, const char* name, const void* val, size_t len) {
	int i;

	int moduleId = -1;
	sys_dynlib_load_prx("libSceSysUtil.sprx", &moduleId);

	// This header doesn't work in > 5.00
	int(*sceSysUtilSendSystemNotificationWithText)(int messageType, char* message) = NULL;

	sys_dynlib_dlsym(moduleId, "sceSysUtilSendSystemNotificationWithText", &sceSysUtilSendSystemNotificationWithText);
	/////////////////////////////////////////////////////////////////////////////////
	char* initMessage111 = "122222222222221111";
	sceSysUtilSendSystemNotificationWithText(222, initMessage111);
	//////////////////////////////////////////////////////////////////////////////////
	if (*iovlen < 0)
		return;
	//////////////////////////////////////////////////////////////////////////////////////
	char* initMessage11w1 = "wwwwwwwww";
	sceSysUtilSendSystemNotificationWithText(222, initMessage11w1);
	///////////////////////////////////////////////////////////////////////////////////////
	i = *iovlen;
	*iov = reallocf(*iov, sizeof **iov * (i + 2));
	if (*iov == NULL) {
		*iovlen = -1;
		return;
	}
	///////////////////////////////////////////////////////////////////////////////////////////
	char* initMessage11ww1 = "wjjjjjwww";
	sceSysUtilSendSystemNotificationWithText(222, initMessage11ww1);
	/////////////////////////////////////////////////////////////////////////////////////////////
	(*iov)[i].iov_base = strdup(name);
	(*iov)[i].iov_len = strlen(name) + 1;
	++i;
	/////////////////////////////////////////////////////////////////////////////////////////////
	char* initMessage11w21 = "w444444";
	sceSysUtilSendSystemNotificationWithText(222, initMessage11w21);
    /////////////////////////////////////////////////////////////////////////////////////////////
	(*iov)[i].iov_base = (void*)val;
	if (len == (size_t)-1) {
		if (val != NULL)
			len = strlen(val) + 1;
		else
			len = 0;
	}
	/////////////////////////////////////////////////////////////////////////////////////////////////
	char* initMessage11w221 = "qqqqq44444qqqq";
	sceSysUtilSendSystemNotificationWithText(222, initMessage11w21);

	(*iov)[i].iov_len = (int)len;

	*iovlen = ++i;
}

static int mount_large_fs(const char* device, const char* mountpoint, const char* fstype, const char* mode, unsigned int flags) {

	int moduleId = -1;
	sys_dynlib_load_prx("libSceSysUtil.sprx", &moduleId);

	// This header doesn't work in > 5.00
	int(*sceSysUtilSendSystemNotificationWithText)(int messageType, char* message) = NULL;

	sys_dynlib_dlsym(moduleId, "sceSysUtilSendSystemNotificationWithText", &sceSysUtilSendSystemNotificationWithText);

	char* initMessage111 = "1111111111";
	sceSysUtilSendSystemNotificationWithText(222, initMessage111);

	struct iovec* iov = NULL;
	int iovlen = 0;

	build_iovec(&iov, &iovlen, "fstype", fstype, -1);
	char* initMessage11222 = "2222222";
	sceSysUtilSendSystemNotificationWithText(222, initMessage11222);
	build_iovec(&iov, &iovlen, "fspath", mountpoint, -1);
	char* initMessage111333 = "333333333";
	sceSysUtilSendSystemNotificationWithText(222, initMessage111333);
	build_iovec(&iov, &iovlen, "from", device, -1);
	char* initMessage11144 = "44444444444";
	sceSysUtilSendSystemNotificationWithText(222, initMessage11144);
	build_iovec(&iov, &iovlen, "large", "yes", -1);
	char* initMessage1116666 = "6666666666";
	sceSysUtilSendSystemNotificationWithText(222, initMessage1116666);
	build_iovec(&iov, &iovlen, "timezone", "static", -1);
	char* initMessage11177 = "777777777";
	sceSysUtilSendSystemNotificationWithText(222, initMessage11177);
	build_iovec(&iov, &iovlen, "async", "", -1);
	build_iovec(&iov, &iovlen, "ignoreacl", "", -1);

	if (mode) {
		build_iovec(&iov, &iovlen, "dirmask", mode, -1);
		build_iovec(&iov, &iovlen, "mask", mode, -1);
	}
	char* initMessage111rr = "rrrrrrrrr";
	sceSysUtilSendSystemNotificationWithText(222, initMessage111rr);
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
		else if (!memcmp((char*)(kbase + KERN_501_PRINTF), (char[12]) { 0x55, 0x48, 0x89, 0xE5, 0x53, 0x48, 0x83, 0xEC, 0x58, 0x48, 0x8D, 0x1D }, 12)) {
			fw_version = 0x501;
			copyout = (void *)(kbase + KERN_501_COPYOUT);
		}

	
	else if (!memcmp((char*)(&((uint8_t*)__readmsr(0xC0000082))[-KERN_455_XFAST_SYSCALL]), (char[4]) { 0x7F, 0x45, 0x4C, 0x46 }, 4)) {
		kbase = &((uint8_t*)__readmsr(0xC0000082))[-KERN_455_XFAST_SYSCALL];
		// (!memcmp((char*)(kbase + KERN_455_PRINTF), (char[12]) { 0x55, 0x48, 0x89, 0xE5, 0x53, 0x48, 0x83, 0xEC, 0x58, 0x48, 0x8D, 0x1D }, 12)) {

			fw_version = 0x455;
			copyout = (void *)(kbase + KERN_455_COPYOUT);
		}
	
	else if (!memcmp((char*)(&((uint8_t*)__readmsr(0xC0000082))[-KERN_405_XFAST_SYSCALL]), (char[4]) { 0x7F, 0x45, 0x4C, 0x46 }, 4)) {
		kbase = &((uint8_t*)__readmsr(0xC0000082))[-KERN_405_XFAST_SYSCALL];
		// (!memcmp((char*)(kbase + KERN_405_PRINTF), (char[12]) { 0x55, 0x48, 0x89, 0xE5, 0x53, 0x48, 0x83, 0xEC, 0x58, 0x48, 0x8D, 0x1D }, 12)) {
		fw_version = 0x405;
			copyout = (void *)(kbase + KERN_405_COPYOUT);
		}
	
	else return -1;



	// Put the fw version in userland so we can use it later

	uint64_t uaddr = args->kpayload_get_fw_version_info->uaddr;
	copyout(&fw_version, (uint64_t*)uaddr, 8);
	return 0;

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
	else if (fw_version == 0x501) {

		// Kernel base resolving
		kbase = &((uint8_t*)__readmsr(0xC0000082))[-KERN_501_XFAST_SYSCALL];
		// Kernel functions resolving
		copyout = (void *)(kbase + KERN_501_COPYOUT);

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

int kdump(struct thread *td, struct kdump_args* args) {

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
		copyout = (void *)(kbase + KERN_405_COPYOUT);

	}
	else return -1;

	if (fw_version == 0x505) {

		int(*printfkernel)(const char *fmt, ...) = (void *)(kbase + 0x436040);
		printfkernel("FW 5.05 Looping\n");
	}

	else if (fw_version == 0x405) {

		int(*printfkernel)(const char *fmt, ...) = (void *)(kbase + KERN_405_PRINTF);
		printfkernel("FW 4.05 Looping\n\n");

	}
	else if (fw_version == 0x455) {

		int(*printfkernel)(const char *fmt, ...) = (void *)(kbase + KERN_455_PRINTF);
		printfkernel("FW 4.55 Looping\n\n");

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
		void(*bzero)(void *b, size_t len) = (void *)(kbase + 0x286c30);

	}
	else if (fw_version == 0x455) {

		// Kernel pointers resolving

		kernel_ptr = (uint8_t*)kbase;
		got_prison0 = (void**)&kernel_ptr[KERN_455_PRISON_0];
		got_rootvnode = (void**)&kernel_ptr[KERN_455_ROOTVNODE];
		void(*bzero)(void *b, size_t len) = (void *)(kbase + 0x14A610);

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
		void(*bzero)(void *b, size_t len) = (void *)(kbase + KERN_BZERO);

	}
	else return -1;


	// pull in our arguments
	uint64_t kaddr = args->payload_info_dumper->kaddr;
	uint64_t uaddr = args->payload_info_dumper->uaddr;

	// run copyout into userland memory for the kaddr we specify
	int cpRet = copyout(kaddr, uaddr, PAGE_SIZE);

	// if mapping doesnt exist zero out that mem
	if (cpRet == -1) {
		//printfkernel("bzero at 0x%016llx\n", kaddr);
		bzero(uaddr, PAGE_SIZE);
		return cpRet;
	}

	return cpRet;
}

//#define RESOLVE(module, name) getFunctionAddressByName(module, #name, &name)

//double(*ceil)(double x);
int(*sceSysUtilSendSystemNotificationWithText)(int messageType, char* message);

void sysNotify5(char* msg) {
	sceSysUtilSendSystemNotificationWithText(222, msg);
}

//int getFunctionAddressByName(int loadedModuleID, char *name, void *destination);

//int(*sceSysUtilSendSystemNotificationWithText)(int messageType, char* message);

void initSysUtilw(void) {
	int sysUtilHandle = sceKernelLoadStartModule("libSceSysUtil.sprx", 0, NULL, 0, 0, 0);

	RESOLVE(sysUtilHandle, sceSysUtilSendSystemNotificationWithText); //, (void **)&sceSysUtilSendSystemNotificationWithText);
}

void initSysUtiljw(void) {
	int sysUtilHandle = sceKernelLoadStartModule("libSceSysUtil.sprx", 0, NULL, 0, 0, 0);

	RESOLVE(sysUtilHandle, sceSysUtilSendSystemNotificationWithText); //, (void **)&sceSysUtilSendSystemNotificationWithText);
}

extern char kpayload[];
unsigned kpayload_size;


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
	uint8_t* kernel_ptr;
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

	else if (fw_version == 0x501) {

		cpu_disable_wp();

		cpu_enable_wp();
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
		*(uint32_t *)(kbase + 0x144B600) = 0x5050001;

		cpu_enable_wp();
	}

	else if(fw_version == 0x501) {

		cpu_disable_wp();
		// spoofer
		*(uint32_t *)(kbase + 0x14A63F0) = 0x5050001;

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
	remount_root_partition();

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
	}

	else if (!memcmp((char*)(&((uint8_t*)__readmsr(0xC0000082))[-KERN_455_XFAST_SYSCALL]), (char[4]) { 0x7F, 0x45, 0x4C, 0x46 }, 4)) {

		kbase = &((uint8_t*)__readmsr(0xC0000082))[-KERN_455_XFAST_SYSCALL];

		fw_version = 0x455;

	}


	else if (!memcmp((char*)(&((uint8_t*)__readmsr(0xC0000082))[-KERN_405_XFAST_SYSCALL]), (char[4]) { 0x7F, 0x45, 0x4C, 0x46 }, 4)) {
		fw_version = 0x405;
		copyout = (void *)(kbase + KERN_405_COPYOUT);

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
		copyout = (void *)(kbase + KERN_455_COPYOUT);

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

int kdumper() {


	int moduleId = -1;
	sys_dynlib_load_prx("libSceSysUtil.sprx", &moduleId);

	// This header doesn't work in > 5.00
	int(*sceSysUtilSendSystemNotificationWithText)(int messageType, char* message) = NULL;

	sys_dynlib_dlsym(moduleId, "sceSysUtilSendSystemNotificationWithText", &sceSysUtilSendSystemNotificationWithText);

	char* initMessage = "Start -- App will Unfreeze once Done";
	sceSysUtilSendSystemNotificationWithText(222, initMessage);

	uint64_t* dump = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	uint64_t filedump = mmap(NULL, KERN_DUMPSIZE, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);

	// patch some things in the kernel (sandbox, prison, debug settings etc..)

	struct payload_info payload_info;

	payload_info.uaddr = dump;

	kexec(&kpayloads, &payload_info);
	// retreive the kernel base copied into userland memory and set it
	//char* initMessage2 = ("kbase Gotten");
	//sceSysUtilSendSystemNotificationWithText(222, initMessage2);

	uint64_t kbase;
	//int(*printfkernel)(const char *fmt, ...) = (void *)(kbase + KERN_PRINTF);
	//printfkernel("memcpy");
	//char* initMessage3 = ("Memcpy start");
	//sceSysUtilSendSystemNotificationWithText(222, initMessage3);
	memcpy(&kbase, dump, 8);
	//char* initMessage4 = ("memcopy done");
	//sceSysUtilSendSystemNotificationWithText(222, initMessage4);
	//printfkernel("memcpy done");

	////printfsocket("kernBase is:0x%016llx\n", kbase);
	////printfsocket("dump is:0x%016llx\n", dump);

	// loop on our kdump payload 

	//printfkernel("3333");
	//char* initMessage5 = ("Payload start");
	//sceSysUtilSendSystemNotificationWithText(222, initMessage5);

	uint64_t pos = 0;
	struct payload_info_dumper payload_info_dumper;

	//char* initMessage6 = ("Payload done");
	//sceSysUtilSendSystemNotificationWithText(222, initMessage6);

	//printfkernel("3333444");

	//notify("Starting Kernel Dump...");
	//printfkernel("555555");
	// loop enough to dump up until gpu used memory
	char* initMessage7 = ("Dump Started");
	sceSysUtilSendSystemNotificationWithText(222, initMessage7);

	for (int i = 0; i < KERN_DUMPITER; i++) {

		payload_info_dumper.kaddr = kbase + pos;
		payload_info_dumper.uaddr = filedump + pos;

		// call our copyout wrapper and send the userland buffer over socket
		kexec(&kdump, &payload_info_dumper);

		pos = pos + PAGE_SIZE;
	}
	//char* initMessage8 = ("555555");
	//sceSysUtilSendSystemNotificationWithText(222, initMessage8);

	//printfkernel("6666666");

	//sceKernelSleep(5);

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
	//char* initMessage88 = ("777777");
	//sceSysUtilSendSystemNotificationWithText(222, initMessage88);

	munmap(dump, PAGE_SIZE);
	munmap(filedump, KERN_DUMPSIZE);

	//char* initMessage88e = ("9999999");
	//sceSysUtilSendSystemNotificationWithText(222, initMessage88e);

	return 0;
}

char mount_from_path[PATH_MAX]; /* Yes, global. Lazy */ /* As long it works, who cares ? */

int MTRW()
{

	//uint64_t fw_version = get_fw_version();



	//uint64_t fw_version = get_fw_version();

	int moduleId = -1;
	sys_dynlib_load_prx("libSceSysUtil.sprx", &moduleId);

	// This header doesn't work in > 5.00
	int(*sceSysUtilSendSystemNotificationWithText)(int messageType, char* message) = NULL;

	sys_dynlib_dlsym(moduleId, "sceSysUtilSendSystemNotificationWithText", &sceSysUtilSendSystemNotificationWithText);

	char* initMessage = "Parent Controls removed";
	sceSysUtilSendSystemNotificationWithText(222, initMessage);

	sys_dynlib_unload_prx(moduleId);

	/*int moduleId = -1;
	sys_dynlib_load_prx("libSceSysUtil.sprx", &moduleId);

	// This header doesn't work in > 5.00
	int(*sceSysUtilSendSystemNotificationWithText)(int messageType, char* message) = NULL;

	sys_dynlib_dlsym(moduleId, "sceSysUtilSendSystemNotificationWithText", &sceSysUtilSendSystemNotificationWithText);

	char* initMessage = "not frozen";
	sceSysUtilSendSystemNotificationWithText(222, initMessage);*/




	//char path_to[PATH_MAX];
	//struct iovec iov[8];
	//char msg[512];
	//char errmsg[255];
	//int result;

	//int moduleId = -1;
	//sys_dynlib_load_prx("system\common\lib\libkernel_sys.sprx", &moduleId);

	// This header doesn't work in > 5.00
	//int(*sceKernelGetIdPs)(void* ret);

	//sys_dynlib_dlsym(moduleId, "sceKernelGetIdPs", &sceKernelGetIdPs);

	//char buffer[500];
	//char idps[32];
	//memset(idps, 0, 32);
	//sceKernelGetIdPs(idps);
	//sprintf(buffer, "Address: %p\n", sceKernelGetIdPs);

	//sflashdumpnote();





	/* Just in case */
	//unmounts(path_to, 0);

	/*char* initMessage111 = "qqqqqqqqq";
	sceSysUtilSendSystemNotificationWithText(222, initMessage111);

	iov[0].iov_base = (void *)"fstype";
	iov[0].iov_len = sizeof("fstype");
	char* initMessage1121 = "qqq22222qqqq";
	sceSysUtilSendSystemNotificationWithText(222, initMessage1121);
	iov[1].iov_base = (void *)"nullfs";
	iov[1].iov_len = sizeof("nullfs");
	char* initMessage11f21 = "qq2fffffqqq";
	sceSysUtilSendSystemNotificationWithText(222, initMessage11f21);
	iov[2].iov_base = (void *)"fspath";
	iov[2].iov_len = sizeof("fspath");
	char* initMessage112ss1 = "ssssssssssss";
	sceSysUtilSendSystemNotificationWithText(222, initMessage112ss1);
	iov[3].iov_base = path_to;
	iov[3].iov_len = strlen(path_to) + 1;
	char* initMessage13121 = "q333333qqqq";
	sceSysUtilSendSystemNotificationWithText(222, initMessage13121);
	iov[4].iov_base = (void *)"target";
	iov[4].iov_len = sizeof("target");
	char* initMessage131221 = "6666663qqqq";
	sceSysUtilSendSystemNotificationWithText(222, initMessage131221);
	//iov[5].iov_base = mount_from_path;
	//iov[5].iov_len = strlen(mount_from_path) + 1;
	//char* initMessage138121 = "q3888888qq";
	//sceSysUtilSendSystemNotificationWithText(222, initMessage138121);
	iov[6].iov_base = (void *)"errmsg";
	iov[6].iov_len = sizeof("errmsg");
	char* initMessage131721 = "q37777qqqq";
	sceSysUtilSendSystemNotificationWithText(222, initMessage131721);
	iov[7].iov_base = errmsg;
	iov[7].iov_len = sizeof(errmsg);
	char* initMessage13e121 = "q33eeeee3qqqq";
	sceSysUtilSendSystemNotificationWithText(222, initMessage13e121);
	result = nmounts(iov, 8, 0);
	if (result < 0) {
		char* initMessage13e121 = "failed";
		sceSysUtilSendSystemNotificationWithText(222, initMessage13e121);
		return 0;
	}
}

int MTRW()
{
	int moduleId = -1;
	sys_dynlib_load_prx("libSceSysUtil.sprx", &moduleId);

	// This header doesn't work in > 5.00
	int(*sceSysUtilSendSystemNotificationWithText)(int messageType, char* message) = NULL;

	sys_dynlib_dlsym(moduleId, "sceSysUtilSendSystemNotificationWithText", &sceSysUtilSendSystemNotificationWithText);

	char* initMessage111 = "Start";
	sceSysUtilSendSystemNotificationWithText(222, initMessage111);
///////////////////////////////////////////////////////////////////////////////////////////////////////////
	if (mount_large_fs("/dev/da0x0.crypt", "/preinst", "exfatfs", "511", MNT_UPDATE) < 0) goto fail;
	//////////////////////////////////////////////////////////////////////////////////////////////////
	char* initMessage11133 = "33333331";
	sceSysUtilSendSystemNotificationWithText(222, initMessage11133);
	////////////////////////////////////////////////////////////////////////////////////////////////////
	if (mount_large_fs("/dev/da0x1.crypt", "/preinst2", "exfatfs", "511", MNT_UPDATE) < 0) goto fail;
	///////////////////////////////////////////////////////////////////////////////////////////////////////
	char* initMessage11155 = "55555565555555";
	sceSysUtilSendSystemNotificationWithText(222, initMessage11155);
	//////////////////////////////////////////////////////////////////////////////////////////////////////////////
	if (mount_large_fs("/dev/da0x4.crypt", "/system", "exfatfs", "511", MNT_UPDATE) < 0) goto fail;
	if (mount_large_fs("/dev/da0x5.crypt", "/system_ex", "exfatfs", "511", MNT_UPDATE) < 0) goto fail;

	return 0;

fail:
	notifye("sss");*/
}



//int dumper()
//int dumperdev()
//{
//}