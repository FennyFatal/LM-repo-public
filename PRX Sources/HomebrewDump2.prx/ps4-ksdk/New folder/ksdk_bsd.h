/**
* (c) 2017-2018 Alexandro Sanchez Bach.
* Released under MIT license. Read LICENSE for more details.
*/

#define KSDK_BSD_H
/*
/* constants */
/*
#define DT_DIR      0x0004
#define DT_REG      0x0008

#define M_NOWAIT    0x0001
#define M_WAITOK    0x0002
#define M_ZERO      0x0100


#define	VM_PROT_NONE		0x00
#define VM_PROT_READ		0x01
#define VM_PROT_WRITE		0x02
#define VM_PROT_EXECUTE		0x04
#define VM_PROT_DEFAULT		(VM_PROT_READ | VM_PROT_WRITE)
#define VM_PROT_ALL			(VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE)
#define VM_PROT_NO_CHANGE	0x08
#define VM_PROT_COPY		0x10
#define VM_PROT_WANTS_COPY	0x10

#define PROT_READ			VM_PROT_READ
#define PROT_WRITE			VM_PROT_WRITE
#define PROT_EXEC			VM_PROT_EXECUTE
#define PROT_NONE			VM_PROT_NONE

#define	TRACEBUF	struct qm_trace trace;

#define	TAILQ_FIRST(head) ((head)->tqh_first)
#define	TAILQ_NEXT(elm, field) ((elm)->field.tqe_next)

#define	TAILQ_HEAD(name, type)									\
struct name {													\
	struct type *tqh_first;										\
	struct type **tqh_last;										\
	TRACEBUF													\
}

#define	TAILQ_ENTRY(type)											\
struct {															\
	struct type *tqe_next;											\
	struct type **tqe_prev;											\
	TRACEBUF														\
}

#define	LIST_ENTRY(type)											\
struct {															\
	struct type *le_next;											\
	struct type **le_prev;											\
}

#define	TAILQ_FOREACH(var, head, field)				\
	for ((var) = TAILQ_FIRST((head));				\
	    (var);										\
(var) = TAILQ_NEXT((var), field))

struct qm_trace {
	char * lastfile;
	int lastline;
	char * prevfile;
	int prevline;
};

struct trapframe {
	uint64_t tf_rdi;	// 0x00
	uint64_t tf_rsi;	// 0x08
	uint64_t tf_rdx;	// 0x10
	uint64_t tf_rcx;	// 0x18
	uint64_t tf_r8;		// 0x20
	uint64_t tf_r9;		// 0x28
	uint64_t tf_rax;	// 0x30
	uint64_t tf_rbx;	// 0x38
	uint64_t tf_rbp;	// 0x40
	uint64_t tf_r10;	// 0x48
	uint64_t tf_r11;	// 0x50
	uint64_t tf_r12;	// 0x58
	uint64_t tf_r13;	// 0x60
	uint64_t tf_r14;	// 0x68
	uint64_t tf_r15;	// 0x70
	uint32_t tf_trapno;	// 0x78
	uint16_t tf_fs;		// 0x7C
	uint16_t tf_gs;		// 0x7E
	uint64_t tf_addr;	// 0x80
	uint32_t tf_flags;	// 0x88
	uint16_t tf_es;		// 0x8C
	uint16_t tf_ds;		// 0x8E
	uint64_t tf_err;	// 0x90
	uint64_t tf_rip;	// 0x98
	uint64_t tf_cs;		// 0xA0
	uint64_t tf_rflags;	// 0xA8
	uint64_t tf_rsp;	// 0xB0
	uint64_t tf_ss;		// 0xB8
};

struct reg {
	uint64_t r_r15;
	uint64_t r_r14;
	uint64_t r_r13;
	uint64_t r_r12;
	uint64_t r_r11;
	uint64_t r_r10;
	uint64_t r_r9;
	uint64_t r_r8;
	uint64_t r_rdi;
	uint64_t r_rsi;
	uint64_t r_rbp;
	uint64_t r_rbx;
	uint64_t r_rdx;
	uint64_t r_rcx;
	uint64_t r_rax;
	uint32_t r_trapno;
	uint16_t r_fs; // 0x7C
	uint16_t r_gs; // 0x7E
	uint32_t r_err;
	uint16_t r_es;
	uint16_t r_ds;
	uint64_t r_rip;
	uint64_t r_cs;
	uint64_t r_rflags;
	uint64_t r_rsp;
	uint64_t r_ss;
};



struct lock_object {
	const char* lo_name;
	uint32_t lo_flags;
	uint32_t lo_data;
	void* lo_witness;
};

struct mtx {
	struct lock_object lock_object;
	volatile void* mtx_lock;
};

struct sx {
	struct lock_object lock_object;
	volatile uintptr_t sx_lock;
};*/


