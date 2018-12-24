#include "module.h"
#include "syscall.h"

#include "kernel.h"

int libKernelHandle;

int (*sysctl)(int *name, unsigned int namelen, char *oldval, size_t *oldlen, char *newval, size_t newlen);
int (*sysctlbyname)(char *name, char *oldval, size_t *oldlen, char *newval, size_t newlen);
int (*sysarch)(int type, void *arg);
int (*execve)(char *path, char *argv[], char *envp[]);

void *(*pthread_self)();
int (*pthread_setaffinity_np)(void *one, long unsigned int two, void *three);


int (*getuid)();
int (*getgid)();
int (*getpid)();

int (*setuid)(int uid);
int (*setgid)(int gid);
int (*setreuid)(int ruid, int euid);
int (*setregid)(int rgid, int egid);

SYSCALL(kill, 37);
SYSCALL(ioctl, 54);

SYSCALL(kexec, 11);

void initKernel(void) {

	//...
}
