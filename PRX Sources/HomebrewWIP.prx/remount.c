#include "Modded_SDK\libPS4\include\ps4.h"
//#include "C:\Users\sethk\Desktop\ps4-payload-sdk-master\libPS4\include\file.h"
#include "remount.h"
//#include <sys/types.h>

typedef	unsigned int	u_int;
int nmount(struct iovec *iov, u_int niov, int flags);

void build_iovec(struct iovec** iov, int* iovlen, const char* name, const void* val, size_t len) {
    int i;

    if (*iovlen < 0)
        return;

    i = *iovlen;
    *iov = realloc(*iov, sizeof **iov * (i + 2));
    if (*iov == NULL) {
        *iovlen = -1;
        return;
    }

    (*iov)[i].iov_base = strdup(name);
    (*iov)[i].iov_len = strlen(name) + 1;
    ++i;

    (*iov)[i].iov_base = (void*)val;
    if (len == (size_t)-1) {
        if (val != NULL)
            len = strlen(val) + 1;
        else
            len = 0;
    }
    (*iov)[i].iov_len = (int)len;

    *iovlen = ++i;
}

int mount_large_fs(const char* device, const char* mountpoint, const char* fstype, const char* mode, unsigned int flags) {
    struct iovec* iov = NULL;
    int iovlen = 0;
    int ret;

    build_iovec(&iov, &iovlen, "fstype", fstype, -1);
    build_iovec(&iov, &iovlen, "fspath", mountpoint, -1);
    build_iovec(&iov, &iovlen, "from", device, -1);
    build_iovec(&iov, &iovlen, "large", "yes", -1);
    build_iovec(&iov, &iovlen, "timezone", "static", -1);
    build_iovec(&iov, &iovlen, "async", "", -1);
    build_iovec(&iov, &iovlen, "ignoreacl", "", -1);

    if (mode) {
        build_iovec(&iov, &iovlen, "dirmask", mode, -1);
        build_iovec(&iov, &iovlen, "mask", mode, -1);
    }

    ret = nmount(iov, iovlen, flags);
    if (ret < 0) {
        goto error;
    } else {
    }

    error:
    return ret;
}

// Hello :) You come here often?
int remount_root_partition() {
    int ret;
	ret = mount_large_fs("/dev/da0x1.crypt", "/preinst2", "exfatfs", "511", MNT_UPDATE);
	ret = mount_large_fs("/dev/da0x4.crypt", "/system", "exfatfs", "511", MNT_UPDATE);
	ret = mount_large_fs("/dev/da0x9.crypt", "/system_data", "exfatfs", "511", MNT_UPDATE);
	ret = mount_large_fs("/dev/md0", "/", "exfatfs", "511", MNT_UPDATE);
	ret = mount_large_fs("/dev/md0.crypt", "/", "exfatfs", "511", MNT_UPDATE);
	ret = mount_large_fs("/dev/da0x0.crypt", "/preinst", "exfatfs", "511", MNT_UPDATE);
    if (ret) {
    }

    return ret;
}

int remount_system_partition() {
    int ret;

    ret = mount_large_fs("/dev/da0x5.crypt", "/system_ex", "exfatfs", "511", MNT_UPDATE);
    if (ret) {
    }

    return ret;
}

