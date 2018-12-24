#include "kernel.h"
#include "module.h"

#include "pthread.h"

int (*scePthreadCreate)(ScePthread *thread, const ScePthreadAttr *attr, void *(*entry) (void *), void *arg, const char *name);
void (*scePthreadExit)(void *value);
int (*scePthreadDetach)(ScePthread thread);
int (*scePthreadJoin)(ScePthread thread, void **value_ptr);
void (*scePthreadYield)(void);
ScePthread (*scePthreadSelf)(void);
int (*scePthreadCancel)(ScePthread thread);

int (*scePthreadMutexInit)(ScePthreadMutex *mutex, const ScePthreadMutexattr *attr, const char *name);
int (*scePthreadMutexDestroy)(ScePthreadMutex *mutex);
int (*scePthreadMutexLock)(ScePthreadMutex *mutex);
int (*scePthreadMutexTrylock)(ScePthreadMutex *mutex);
int (*scePthreadMutexTimedlock)(ScePthreadMutex *mutex, SceKernelUseconds usec);
int (*scePthreadMutexUnlock)(ScePthreadMutex *mutex);

void Pthread(void) {
int moduleIds = 1;

sys_dynlib_load_prx("libkernel.sprx", &moduleIds);

sys_dynlib_dlsym(moduleIds, "scePthreadCreate", &scePthreadCreate);
sys_dynlib_dlsym(moduleIds, "scePthreadExit", &scePthreadExit);
sys_dynlib_dlsym(moduleIds, "scePthreadDetach", &scePthreadDetach);
sys_dynlib_dlsym(moduleIds, "scePthreadJoin", &scePthreadJoin);
sys_dynlib_dlsym(moduleIds, "scePthreadYield", &scePthreadYield);
sys_dynlib_dlsym(moduleIds, "scePthreadSelf", &scePthreadSelf);
sys_dynlib_dlsym(moduleIds, "scePthreadCancel", &scePthreadCancel);
sys_dynlib_dlsym(moduleIds, "scePthreadMutexInit", &scePthreadMutexInit);
sys_dynlib_dlsym(moduleIds, "scePthreadMutexDestroy", &scePthreadMutexDestroy);
sys_dynlib_dlsym(moduleIds, "scePthreadMutexLock", &scePthreadMutexLock);
sys_dynlib_dlsym(moduleIds, "scePthreadMutexTrylock", &scePthreadMutexTrylock);
sys_dynlib_dlsym(moduleIds, "scePthreadMutexTimedlock", &scePthreadMutexTimedlock);
sys_dynlib_dlsym(moduleIds, "scePthreadMutexUnlock", &scePthreadMutexUnlock);
}
