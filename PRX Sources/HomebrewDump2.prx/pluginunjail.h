#pragma once
#include "Modded_SDK\libPS4\include\types.h"

class Sys {
private:
	//private for me

public:
	static int opens(const char *path, int flags, int mode);
	static int kexec(void* func, void *user_arg);
	static int getuid();
	static int getpid();
	static int getlogin();
	static int shutdown();
	static int sandboxpath();
	static int development_mode();
	static int cpu_usage();
	static int sdk_compiled_version();
	static ssize_t read(int fd, void *buf, size_t nbyte);
	static ssize_t write(int fd, const void *buf, size_t count);
	//static int opens(const char *path, int flags, int mode);
	static int close(int fd);
	//static long waitpid(pid_t pid, int *stat_address, int options);
	static int create(const char *pathname, int mode);
	static int link(const char *oldname, const char *newname);
	static int unlink(const char *pathname);
	//static int kexec(void* func, void *user_arg);
	static off_t lseek(int fd, off_t offset, int origin);
	//static int getpid(void);
	static int mount(const char *type, const char *dir, int flags, void *data);
	static int unmount(const char *dir, int flags);
	//static int getuid(void);
	static int kill(int pid, int signum);
	static int ioctl(int fd, unsigned long com, void *data);
	static int msync(void *addr, size_t len, int flags);
	static int munmap(void *addr, size_t len);
	static int mprotect(void *addr, size_t len, int prot);
	static int fchown(int fd, int uid, int gid);
	static int nmount(struct iovec *iov, uint32_t niov, int flags);
	static int fchmod(int fd, int mode);
	static int rename(const char *oldpath, const char *newpath);
	static int mkdir(const char *pathname, mode_t mode);
	static int rmdir(const char *path);
	static int stat(const char *path, struct stat *sb);
	static int fstat(int fd, struct stat *sb);
	static int mlock(void *addr, size_t len);
	static int munlock(void *addr, size_t len);
	static int getdents(int fd, char *buf, size_t count);
	static void *mmap(void *addr, size_t len, int prot, int flags, int fd, off_t offset);
	static int registryCommand(int command);
	static int createEventFlag(const char *name);
	static int destroyEventFlag(int eventFlag);
	static int getMemoryInfo(void *address, struct memoryRegionInfo *destination);
	static int mutexInit(const char *name, unsigned int attributes);
	static int mutexDestroy(int mutex);
	static int getOtherMemoryInfo(void *address, int nextMatchIfUnmapped, struct otherMemoryRegionInfo *destination);
	static int unknownResourceCreate(const char *name);
	static int unknownResourceDestroy(int unknownResource);
	static int getFunctionAddressByName(int loadedModuleID, char *name, void *destination);
	static int getLoadedModules(int *destination, int max, int *count);
	//static int getModuleInfo(int loadedModuleID, ModuleInfo *destination);
	static int loadModule(const char *name, int *idDestination);
	static int unloadModule(int id);
	static int getSandboxDirectory(char *destination, int *length);
};
