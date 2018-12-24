/* golden */
/* 1/2/2018 */

// inspired by fail0verflow, of course
// 5.05

// ref 0xFFFFFFFF87464000

#define __Xfast_syscall505							0x1C0
#define __copyin505								0x1EA710 
#define __copyout505								0x1EA630
#define __printf505								0x436040 
#define __malloc505								0x10E250
#define __free505									0x10E460 
#define __memcpy505								0x1EA530
#define __memset505								0x3205C0
#define __memcmp505								0x50AC0
#define __kmem_alloc505							0xFCC80
#define __strlen505                                0x3B71A0

#define __disable_console_output505                0x19ECEB0
#define __M_TEMP505					        	0x14B4110
#define __kernel_map505                            0x1AC60E0
#define __prison0505                               0x10986A0
#define __rootvnode 505                            0x22C1A70
