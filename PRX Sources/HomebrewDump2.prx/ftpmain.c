/*
 * Copyright (c) 2015 Sergi Granell (xerpi)
 */
#include "ps4.h"
#include "defines.h"
#include "debug.h"
#include "ftps4.h"
#include "dump.h"

int run;

static void build_iovec(struct iovec** iov, int* iovlen, const char* name, const void* val, size_t len) {
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

static int mount_large_fs(const char* device, const char* mountpoint, const char* fstype, const char* mode, unsigned int flags) {
	struct iovec* iov = NULL;
	int iovlen = 0;

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

	return nmount(iov, iovlen, flags);
}

void custom_MTRW(ftps4_client_info_t *client)
{
	if (mount_large_fs("/dev/da0x0.crypt", "/preinst",   "exfatfs", "511", MNT_UPDATE) < 0) goto fail;
	if (mount_large_fs("/dev/da0x1.crypt", "/preinst2",  "exfatfs", "511", MNT_UPDATE) < 0) goto fail;
	if (mount_large_fs("/dev/da0x4.crypt", "/system",    "exfatfs", "511", MNT_UPDATE) < 0) goto fail;
	if (mount_large_fs("/dev/da0x5.crypt", "/system_ex", "exfatfs", "511", MNT_UPDATE) < 0) goto fail;

	ftps4_ext_client_send_ctrl_msg(client, "200 Mount success." FTPS4_EOL);
	return;

fail:
	ftps4_ext_client_send_ctrl_msg(client, "550 Could not mount!" FTPS4_EOL);
}

void custom_SHUTDOWN(ftps4_client_info_t *client) {
	ftps4_ext_client_send_ctrl_msg(client, "200 Shutting down..." FTPS4_EOL);
	run = 0;
}

int get_ip_address(char *ip_address)
{
	int ret;
	SceNetCtlInfo info;

	ret = sceNetCtlInit();
	if (ret < 0)
		goto error;

	ret = sceNetCtlGetInfo(SCE_NET_CTL_INFO_IP_ADDRESS, &info);
	if (ret < 0)
		goto error;

	memcpy(ip_address, info.ip_address, sizeof(info.ip_address));

	sceNetCtlTerm();

	return ret;

error:
	ip_address = NULL;
	return -1;
}

int _main(struct thread *td)
{
	char ip_address[SCE_NET_CTL_IPV4_ADDR_STR_LEN];
	char msg[64];

	run = 1;

	// Init and resolve libraries
	initKernel();
	initLibc();
	initNetwork();
	initPthread();

#ifdef DEBUG_SOCKET
	initDebugSocket();
#endif

	// patch some things in the kernel (sandbox, prison, debug settings etc..)
	//syscall(11,kpayload,td);

	//initSysUtil();
	//notify("Welcome to FTPS4 v"VERSION);

	//int ret = get_ip_address(ip_address);
	//if (ret < 0)
	//{
		//notify("Unable to get IP address");
		//goto error;
	//}

	ftps4_init(ip_address, FTP_PORT);
	ftps4_ext_add_command("SHUTDOWN", custom_SHUTDOWN);
	ftps4_ext_add_command("MTRW", custom_MTRW);

	//sprintf(msg, "PS4 listening on\nIP %s Port %i", ip_address, FTP_PORT);
	//notify(msg);

	while (run) {
		sceKernelUsleep(5 * 1000);
	}

	ftps4_fini();

error:
	//notify("Bye!");

#ifdef DEBUG_SOCKET
	closeDebugSocket();
#endif
	return 0;
}
