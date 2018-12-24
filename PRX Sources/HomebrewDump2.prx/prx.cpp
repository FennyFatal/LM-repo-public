
#include <kernel.h>
#include "syscall.h"
#define PRX_EXPORT extern "C" __declspec (dllexport)

#include "pluginunjail.h"

extern "C" {
#include "unjail.h"
#include "elfloader/jailbreak.h"
}

#include <kernel.h>
#include <assert.h>

#include <assert.h>
#include "c:\Program Files (x86)\SCE\ORBIS SDKs\4.500\target\include\sys\_types\_int32_t.h"
#include "c:\Program Files (x86)\SCE\ORBIS SDKs\4.500\target\include\scetypes.h"
#include "dump.h"
#include "remount.h"
#include "c:\Program Files (x86)\SCE\ORBIS SDKs\4.500\target\include\stdio.h"
#define Assert assert
bool			s_progressSetMsg = false;



int module_start(size_t args, const void *argp)
{
	syscall(9);
	psxloader();
}

int module_stop(size_t args, const void *argp)
{
	return 0;

}


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


PRX_EXPORT int install_syscall(void)
{
	return 0;

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


PRX_EXPORT void decrypts(char selfFile, char saveFile)
{
	return decrypt_and_dump_selfs(selfFile, saveFile);

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

PRX_EXPORT int GetUid(void)
{
	return Sys::getuid();

}

PRX_EXPORT int installnotes(void)
{
	return installnote();

}

PRX_EXPORT int dumpall(void)
{

	return dump_all();

}


PRX_EXPORT int dumppart(int partNo)
{
	return dump_part((uint64_t)partNo);
}



PRX_EXPORT int dumpanddecryptnote(void)
{
	return dumped_and_decrypted_note();

}

PRX_EXPORT int Eap455s(void)
{
	return eap455();

}

PRX_EXPORT int decrypttemps(void)
{
	return decrypttemp();

}

PRX_EXPORT int dumpshellcore(void)
{
	return dump_shellcore();

}

PRX_EXPORT int loadump(void)
{
	return 0;

}

PRX_EXPORT int decrypttemps22(void)
{
	return decrypttempfs();

}

PRX_EXPORT int copyfilez(char* src, char* des)
{
	copyFile(src, des);
	return 0;

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
	buzzer1beep();
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

PRX_EXPORT int JKpatch(void)
{
	HENorNah();
	return jkpatch1();
}

PRX_EXPORT int loadrip(void)
{
	return 0;

}


PRX_EXPORT int Kdumper(void)
{
	kdumper();
	return 0;

}

PRX_EXPORT int Spooftwolnote(void)
{
	return spooftwonote();

}

PRX_EXPORT int Eapkeys(void)
{
	//const char kk[] = { 'A','a','B','b','\xAA','\xBB','z','x','c', 'A','a','B','b','\xAA','\xBB','z','x','c', '\x0','\x0' };
	//klog("********************************************\n\n \t TEST TEST TEST etc \n\n ((((((((((((((((((((((((((((");

	eapkey();
	//dump_part(14);	// is /dev/sde25 right?, PS4 doesnt do sda it does it like a USB ... sec
	// these are from linux then:
		// raw part copy to /dev/da1s* for usb 
		// da0x[1-9] , 5b, 6x[0-2], 1[2-5] 
	//klog("********************************************\n\n \t TEST TEST TEST etc \n\n ((((((((((((((((((((((((((((");

	return 0;

}

PRX_EXPORT int Wipenote(void)
{
	return wipenote();
}

PRX_EXPORT int Linuxs(void)
{
	return linux();
}

PRX_EXPORT int Spooftherelnote(void)
{
	return spooftherenote();

}


PRX_EXPORT int backuplnote(void)
{
	return backupnote();

}

PRX_EXPORT int ALN(void)
{
	return autoloadnote();

}
//syscall9elf

PRX_EXPORT int syscall9wojk(void)
{
	HENorNah();
	return syscall9elf();

}

PRX_EXPORT int DALN(void)
{
	return disbaledautoloadnote();

}

PRX_EXPORT int restorelnote(void)
{
	return restorednote();

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

PRX_EXPORT int ELFLoader(void)
{
	return ElfFileselfz(); // wtf?
}

PRX_EXPORT int ELFLoaderELF(void)
{
	return loadElfFileelf(); // wtf?
}

PRX_EXPORT int ELFLoaderBIN(void)
{
	return loadElfFilebin(); // wtf?
}

PRX_EXPORT int pkgdlmode(void)
{
	return pkgdl(); // wtf?
}

PRX_EXPORT int NOELFS(void)
{
	return cantfindelfs();
	// wtf?
}// remoteplaypatch

PRX_EXPORT int Decrypt_PUP(void)
{
	return  0; //syscall(9);//dec_pups();
}

PRX_EXPORT int playpatch(void)
{
	return remoteplaypatch();
}

PRX_EXPORT int syscall9(void)
{
	//return install_sys();
	return Unjail505();//syscall(9);

}

PRX_EXPORT int fantest1s(void)
{
	//return install_sys();
	return 0;//syscall(9);

}

PRX_EXPORT int fantest2s(void)
{
	//return install_sys();
	return fantest2();//syscall(9);

}

PRX_EXPORT int ps4ledt(void)
{
	//return install_sys();
	return PS4LEDTEST();//syscall(9);

}



//int Sys::sandboxpath() { return syscall(600); }
//int Sys::development_mode() { return syscall(606); }
//int Sys::cpu_usage() { return syscall(627); }
//int Sys::sdk_compiled_version() { return syscall(647); }
