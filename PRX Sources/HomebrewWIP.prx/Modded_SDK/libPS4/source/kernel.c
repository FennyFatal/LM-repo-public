
#include "module.h"
#include "syscall.h"
#include "kernel.h"

int libKernelHandle;

int (*sysctlbyname)(char *name, char *oldval, __size_t *oldlen, char *newval, __size_t newlen);

int(*setregid)(int rgid, int egid);

SYSCALL(kill, 37);
SYSCALL(ioctl, 54);

SYSCALL(kexec, 11);

void initKernel(void) {


}


