
#include <kernel.h>
#include "syscall.h"
#define PRX_EXPORT extern "C" __declspec (dllexport)
#define PRX_IMPORT extern "C" __declspec (dllimport)

#include "pluginunjail.h"

extern "C" {
#include "unjail.h"
}

#include <assert.h>
#include "dump.h"
#include "remount.h"
#define Assert assert



/*extern "C" {
	int module_start(size_t args, const void *argp)
	{
		return FTPStart();
	}

	int module_stop(size_t args, const void *argp)
	{
		return 0;

	}
}*/

PRX_EXPORT int GetInteger()
{
	return 6;
}

PRX_EXPORT const char* GetString()
{
	return "Hello";
}

PRX_EXPORT int AddTwoIntegers(int i1, int i2)
{
	return i1 + i2;
}

PRX_EXPORT float AddTwoFloats(float f1, float f2)
{
	return f1 + f2;
}

PRX_EXPORT int GetPid(void)
{
	return Sys::getpid();

}

PRX_EXPORT int shutdown(void)
{
	return Sys::shutdown();

}

PRX_EXPORT int Spoofdevkitl(void)
{
	struct thread td;
	return Sys::kexec((void *)&spoofdevkit, &td);


}

PRX_EXPORT int Spooftestkitl(void)
{
	struct thread td;
	return Sys::kexec((void *)&spooftestkit, &td);

}

PRX_EXPORT int Unjail505(void)
{
	struct thread td;
	return Sys::kexec((void *)&unjail505, &td);

}


PRX_EXPORT int Testl(void)
{
	struct thread td;
	return Sys::kexec((void *)&testmenu, &td);

}

PRX_EXPORT int mmaps(void)
{
	struct thread td;
	return Sys::kexec((void *)&mmapp, &td);

}

PRX_EXPORT int shutdowns(void)
{
	struct thread td;
	return Sys::kexec((void *)&shutdowne, &td);

}

PRX_EXPORT int Spoofretaill(void)
{
	struct thread td;
	return Sys::kexec((void *)&spoofretail, &td);

}

PRX_EXPORT int webtry(void)
{
	return syscall(2);
}

PRX_EXPORT int pkgdlmode(void)
{

	return pkgdl();

}

PRX_EXPORT int Spoofonel(void)
{
	struct thread td;
	return Sys::kexec((void *)&spoofone, &td);

}

PRX_EXPORT int Spooftwol(void)
{
	struct thread td;
	return Sys::kexec((void *)&spooftwo, &td);

}

PRX_EXPORT int Spooftherel(void)
{
	struct thread td;
	return Sys::kexec((void *)&spoofthere, &td);

}

PRX_EXPORT int Debugonl(void)
{
	struct thread td;
	return Sys::kexec((void *)&debugon, &td);

}

PRX_EXPORT int Uartoffl(void)
{
	struct thread td;
	return Sys::kexec((void *)&uartoff, &td);

}

PRX_EXPORT int Unjail455(void)
{
	struct thread td;
	return Sys::kexec((void *)&unjail455, &td);

}



PRX_EXPORT int Uartonl(void)
{
	struct thread td;
	return Sys::kexec((void *)&uarton, &td);

}

PRX_EXPORT int shutdownl(void)
{
	return Sys::shutdown();

}


PRX_EXPORT int Debugoffl(void)
{
	struct thread td;
	return Sys::kexec((void *)&debugoff, &td);

}

PRX_EXPORT int recoveryl(void)
{
	struct thread td;
	return Sys::kexec((void *)&recovery, &td);

}

PRX_EXPORT int parentconrtoll(void)
{
	struct thread td;
	return Sys::kexec((void *)&parentcontrol, &td);

}

PRX_EXPORT int Killproccess(void)
{

	int kills();
}


PRX_EXPORT int FTP()
{
	return FTPStart();
}

PRX_EXPORT int GetUid(void)
{
	return Sys::getuid();

}

PRX_EXPORT int installnotes(void)
{
	return installnote();

}


PRX_EXPORT int uninstallnotes(void)
{
	return uninstallnote();

}

PRX_EXPORT int GetLogin(void)
{
	return Sys::getlogin();

}

PRX_EXPORT int messages(void)
{
	//return syscall(11, remount_root_partition);
}

PRX_EXPORT int notess(void)
{
	return note();
}


struct ReturnedStructure
{
	int number;
	const char* text;
};

PRX_EXPORT bool ReturnAStructure(ReturnedStructure* data)
{
	static char sText[] = "Hello";
	data->number = 23;
	data->text = sText;

	return true;
}

PRX_EXPORT int Sboxpath(void)
{
	return Sys::sandboxpath();

}
PRX_EXPORT int dev_mode(void)
{
	return Sys::development_mode();

}
PRX_EXPORT int CPU_usage(void)
{
	return Sys::cpu_usage();

}
PRX_EXPORT int SDK_Ver(void)
{
	return Sys::sdk_compiled_version();

}

PRX_EXPORT int Spoofretaillnote(void)
{
	return spoofretailnote();

}

PRX_EXPORT int parentcontrolnotel(void)
{
	return parentcontrolnote();

}

PRX_EXPORT int NoUSBs(void)
{
	return nousbnote();

}


PRX_EXPORT int Spooftestkitlnote(void)
{
	return spooftestkitnote();

}

PRX_EXPORT int Spoofdevkitlnote(void)
{
	return spoofdevkitnote();

}

PRX_EXPORT int Spoofonelnote(void)
{
	return spoofonenote();

}


PRX_EXPORT int jks(void)
{

	jk();

}

PRX_EXPORT int loadpls(void)
{
	return 0;

}

PRX_EXPORT int Kdumper(void)
{
	return kdumper();

}

PRX_EXPORT int Spooftwolnote(void)
{
	return spooftwonote();

}

PRX_EXPORT int Eapkeys(void)
{
	return eapkey();

}

PRX_EXPORT int Wipenote(void)
{
	return wipenote();

}

PRX_EXPORT int Spooftherelnote(void)
{
	return spooftherenote();

}

PRX_EXPORT int Debugonlnote(void)
{
	return debugonnote();

}

PRX_EXPORT int backuplnote(void)
{
	return backupnote();

}

PRX_EXPORT int restorelnote(void)
{
	return restorednote();

}

PRX_EXPORT int dumpall(void)
{

	return dump_all();

}

PRX_EXPORT int Mount_RW(void)
{

	return mount_rw();

}

PRX_EXPORT int Off_Mount_RW(void)
{

	return off_mount_rw();

}

PRX_EXPORT int dumpanddecryptnote(void)
{
	return dumped_and_decrypted_note();

}

PRX_EXPORT int dumpshellcore(void)
{
	return dump_shellcore();

}

PRX_EXPORT int Uartofflnote(void)
{
	return uartoffnote();

}

PRX_EXPORT int Uartonlnote(void)
{
	return uartonnote();

}

PRX_EXPORT int connectionfailednote(void)
{
	return connectionfaild();

}
PRX_EXPORT int bugreportnote(void)
{
	return bugreport();

}

PRX_EXPORT int Dumpsflash(void)
{
	return dumpsflash();

}

PRX_EXPORT int rebootl(void)
{
	return reboot();

}

PRX_EXPORT int dumpss(void)
{
	return dumps();
}

PRX_EXPORT int sflashdumpnotes(void)
{
	return sflashdumpnote();
}

PRX_EXPORT int sample11note(void)
{
	return sample1note();
}


PRX_EXPORT int sample22note(void)
{
	return sample2note();
}

PRX_EXPORT int ELFLoader(void)
{
	return loadElfFileselfz(); // wtf?
}

PRX_EXPORT int ELFLoaderELF(void)
{
	return loadElfFileelf(); // wtf?
}

PRX_EXPORT int ELFLoaderBIN(void)
{
	return loadElfFilebin(); // wtf?
}

PRX_EXPORT int NOELFS(void)
{
	return cantfindelfs();
		// wtf?
}

//int Sys::sandboxpath() { return syscall(600); }
//int Sys::development_mode() { return syscall(606); }
//int Sys::cpu_usage() { return syscall(627); }
//int Sys::sdk_compiled_version() { return syscall(647); }
