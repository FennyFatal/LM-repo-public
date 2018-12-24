#pragma once

#include "_types.h"


extern int libKernelHandle;

extern int **__stack_chk_guard;
extern void (*__stack_chk_fail)(void);
//extern int *(*__error)();
#define errno (* __error())

int kill(int pid, int signum);

void initKernel(void);

int kexec(void* func, void* user_arg);
