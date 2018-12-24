#pragma once

#include "types.h"

//enum {
	//SEEK_SET,
	//SEEK_CUR,
	//SEEK_END
//};

#define O_RDONLY  0x0000
#define O_WRONLY  0x0001
#define O_RDWR    0x0002
#define O_ACCMODE 0x0003

#define	O_NONBLOCK 0x0004		/* no delay */
#define	O_APPEND   0x0008		/* set append mode */
#define	O_CREAT    0x0200		/* create if nonexistent */
#define	O_TRUNC    0x0400		/* truncate to zero length */
#define	O_EXCL     0x0800		/* error if already exists */

#define S_ISDIR(m)  (((m) & 0170000) == 0040000)
#define S_ISCHR(m)  (((m) & 0170000) == 0020000)
#define S_ISBLK(m)  (((m) & 0170000) == 0060000)
#define S_ISREG(m)  (((m) & 0170000) == 0100000)
#define S_ISFIFO(m) (((m) & 0170000) == 0010000)
#define S_ISLNK(m)  (((m) & 0170000) == 0120000)
#define S_ISSOCK(m) (((m) & 0170000) == 0140000)
#define S_ISWHT(m)  (((m) & 0170000) == 0160000)


ssize_t read(int fd, void *buf, size_t nbyte);
ssize_t write(int fd, const void *buf, size_t count);
int opens(const char *path, int flags, int mode);
int close(int fd);
int unlink(const char *pathname);
int readlink(const char *path,	char *buf, int bufsiz);
int mount(const char *type, const char	*dir, int flags, void *data);
int unmount(const char *dir, int flags);
int fchown(int fd, int uid, int gid);
//int rename(const char *oldpath, const char *newpath);
int mkdir(const char *pathname, mode_t mode);
int rmdir(const char *path);
//off_t lseek(int fildes, off_t offset, int whence);

int getSandboxDirectory(char *destination, int *length);
