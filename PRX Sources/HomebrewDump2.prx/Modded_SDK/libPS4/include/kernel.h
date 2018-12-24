#pragma once

#include "types.h"

//typedef struct timeval SceKernelTimeval;

extern int libKernelHandle;

extern int **__stack_chk_guard;
extern void (*__stack_chk_fail)(void);



extern int (*setuid)(int uid);
extern int (*setreuid)(int ruid, int euid);
extern int (*setregid)(int rgid, int egid);

int kill(int pid, int signum);

void initKernel(void);

int kexec(void* func, void* user_arg);
