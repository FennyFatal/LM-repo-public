
// change the version
#define KERN_VER 505

// comment to use usb method!
//#define DEBUG_SOCKET

// comment if you dont want ps4 to turn off after completing kdump
//#define SHUTDOWN_ON_FINISH

// multi version support
#if KERN_VER == 405

	#define	KERN_PRINTF		0x00347580
	#define	KERN_BASE_PTR		0x0030EB30
	#define	KERN_COPYOUT		0x00286d70
	#define	KERN_BZERO		0x00286c30
	#define	KERN_PRISON0		0x00F26010
	#define	KERN_ROOTVNODE		0x0206D250
	#define	KERN_UART_ENABLE	0x0186b0a0

	#define KERN_DUMPSIZE 		108806144	// can change if you want but may crash if you hit critical code in gpu memory

#elif KERN_VER == 455

	#define	KERN_BASE_PTR 		0x03095d0
	#define	KERN_PRINTF 		0x0017F30
	#define	KERN_COPYOUT 		0x014A7B0
	#define	KERN_BZERO 		0x014A610
	#define	KERN_PRISON0 		0x10399B0
	#define	KERN_ROOTVNODE 		0x21AFA30
	#define	KERN_UART_ENABLE 	0x1997BC8

	#define KERN_DUMPSIZE 		100663296	// can change if you want but may crash if you hit critical code in gpu memory

#elif KERN_VER == 505

	#define	KERN_PRINTF		0x0436040
	#define	KERN_BASE_PTR 		0x00001C0
	#define	KERN_COPYOUT		0x01ea630
	#define	KERN_BZERO		0x01ea510 
	#define	KERN_PRISON0 		0x10986A0
	#define	KERN_ROOTVNODE 		0x22C1A70
	#define	KERN_UART_ENABLE 		0	// mira takes care of this

	#define KERN_DUMPSIZE 		108806144	// can change if you want but may crash if you hit critical code in gpu memory

#else // crash your shit lol

	#define	KERN_PRINTF 			0
	#define	KERN_BASE_PTR			0
	#define	KERN_COPYOUT			0
	#define	KERN_BZERO			0
	#define	KERN_COPYIN			0
	#define	KERN_PRISON0			0
	#define	KERN_ROOTVNODE			0
	#define	KERN_UART_ENABLE		0

	#define KERN_DUMPSIZE 			0	

#endif





#define PAGE_SIZE 16348
#define KERN_DUMPITER KERN_DUMPSIZE / PAGE_SIZE 	// can only dump a page at at time so we need to iterate
#define KERN_FILEPATH "/mnt/usb0/kdump.bin"		// file path if debug socket isnt defined

#define IP(a, b, c, d) (((a) << 0) + ((b) << 8) + ((c) << 16) + ((d) << 24))

#define	CTL_KERN	1				/* "high kernel": proc, limits */
#define	KERN_PROC	14				/* struct: process entries */
#define	KERN_PROC_VMMAP	32				/* VM map entries for process */
#define	KERN_PROC_PID	1				/* by process id */


struct payload_info
{
	uint64_t uaddr;
};

struct payload_info_dumper
{
	uint64_t fw_version;
	uint64_t uaddr;
	uint64_t kaddr;
};

struct kdump_args
{
	void* syscall_handler;
	struct payload_info_dumper* payload_info_dumper;
	struct kpayload_get_fw_version_info* kpayload_get_fw_version_info;
};

struct kpayload_args
{
	void* syscall_handler;
	struct payload_info* payload_info;
};

