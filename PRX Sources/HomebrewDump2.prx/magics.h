

#pragma once

//#include "fw.h"


#define __Xfast_syscall                                 0x00001C0
#define __prison0                                       0x10986a0
#define __rootvnode                                     0x22C1A70
#define __pml4pml4i                                     0x22CB560 // Pending verification
#define __dmpml4i                                       0x22CB564
#define __dmpdpi                                        0x22CB568
#define __printf                                        0x0436040
#define __copyin                                        0x01EA710
#define __copyout                                       0x01EA630
#define __copyinstr                                     0x01EAB40
#define __kmem_alloc_contig                             0x00F1C90
#define __kmem_free                                     0x00FCE50
#define __pmap_extract                                  0x02E0570
#define __pmap_protect                                  0x02E3090
#define __sched_pin                                     0x031FF40
#define __sched_unpin                                   0x031FF50
#define __smp_rendezvous                                0x01B85B0
#define __smp_no_rendevous_barrier                      0x01B8366
#define __icc_query_nowait                              0x0044020
#define __kernel_map                                    0x1AC60E0
#define __sysent                                        0x107C610
#define __kernel_pmap_store                             0x22CB570
#define __Starsha_UcodeInfo                             0
#define __gpu_devid_is_9924                             0x4DE010
#define __gc_get_fw_info                                0x4D37A0
#define	__UART_ENABLE 	                                0		// offset is 0 due to mira have uart auto enabled in autorun patches.
