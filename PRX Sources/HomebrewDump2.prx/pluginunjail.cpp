#include "pluginunjail.h"

extern "C" {
#include "unjail.h"
}

//#include "C:\Users\sethk\Desktop\ps4-ftp-vtx-master\include\elf64.h"
//#include "C:\Users\sethk\Desktop\ps4-ftp-vtx-master\include\elf_common.h"
#include "Modded_SDK\libPS4\include\ps4.h"

#include "dump.h"
#include "remount.h"

extern int(*sceKernelLoadStartModule)(const char *name, size_t argc, const void *argv, unsigned int flags, int, int);

int(*sceSysUtilSendSystemNotificationWithText)(int messageType, char* message);

void sysNotify2(char* msg) {
	sceSysUtilSendSystemNotificationWithText(222, msg);
}

int FreeUnjail(void)
{
	struct thread td;
	return Sys::kexec((void *)&unjail505, &td);

}

int mmaps(void)
{
	struct thread td;
	return Sys::kexec((void *)&mmapp, &td);

}
int Spoofdevkitl(void)
{
	struct thread td;
	return Sys::kexec((void *)&spoofdevkit, &td);

}
int Spooftestkitl(void)
{
	struct thread td;
	return Sys::kexec((void *)&spooftestkit, &td);

}
int Spoofretaill(void)
{
	struct thread td;
	return Sys::kexec((void *)&spoofretail, &td);

}

int Spooftwol(void)
{
	struct thread td;
	return Sys::kexec((void *)&spooftwo, &td);

}
int Spooftherel(void)
{
	struct thread td;
	return Sys::kexec((void *)&spoofthere, &td);

}
int Debugonl(void)
{
	struct thread td;
	return Sys::kexec((void *)&debugon, &td);

}

int Uartoffl(void)
{
	struct thread td;
	return Sys::kexec((void *)&uartoff, &td);

}

int Uartonl(void)
{
	struct thread td;
	return Sys::kexec((void *)&uarton, &td);

}

int Debugoffl(void)
{
	struct thread td;
	return Sys::kexec((void *)&debugoff, &td);

}

int Testl(void)
{
	struct thread td;
	return Sys::kexec((void *)&testmenu, &td);

}

int notess(void)
{
	return note();
}

int messages(void)
{
	//int sysUtil = sceKernelLoadStartModule("/system/common/lib/libSceSysUtil.sprx", 0, NULL, 0, 0, 0);
	//RESOLVE(sysUtil, sceSysUtilSendSystemNotificationWithText);

	//initSysUtil();
	//sysNotify2("Testkit Spoofed/n Homebrew W.I.P");
}

int shutdownl(void)
{
	return Sys::shutdown();

}

const char* GetString()
{
	return "Hello";
}
