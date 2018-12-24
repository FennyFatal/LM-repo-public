

#pragma once
#include <types.h>
#include "lv2.h"
#include "remount.h"

//struct kpayload_args { uint64_t user_arg; };

//struct kdump_args { uint64_t argArrayPtr; };

void *unjail505(struct thread *td);
void *unjail455(struct thread *td);
void *spoofdevkit(struct thread *td);
void *spooftestkit(struct thread *td);
void *spoofretail(struct thread *td);
void *spoofone(struct thread *td);
void *spooftwo(struct thread *td);
void *spoofthere(struct thread *td);
void *debugon(struct thread *td);
void *testmenu(struct thread *td);
void *mmapp(struct thread *td);
void *debugoff(struct thread *td);
void *uarton(struct thread *td);
void *uartoff(struct thread *td);
void *shutdowne(struct thread *td);
int buzzer1beep();
int decrypttemp();
int decrypttempfs();
void copyFile(char *sourcefile, char* destfile);
int disbaledautoloadnote();
int syscall9elf();
int HENorNah();
int elfloader();
int autoloadnote();
int dumpnote();
void *parentcontrol(struct thread *td);
int kdumper();
int bugreport();
int connectionfaild();
int nousbnote();
int kills();
int installnote();
int uninstallnote();
//int amain(struct thread *td);
int spoofdevkitnote();
int dumpsflash();
int sflashdumpnote();
int parentcontrolnote();
int spooftestkitnote();
int spoofretailnote();
int spoofonenote();
int spooftwonote();
int spooftherenote();
int debugonnote();
//int debugoffnote();
int wipenote();
int jk();
int uartonnote();
int uartoffnote();
int backupnote();
int restorednote();
int reboot();
int dumps();
void *recovery(struct thread *td);
int note();
int eapkey();
//void mmappw();
int dumped_and_decrypted_note();
int dump_shellcore();
int dump_all();
int dump_part(uint64_t partNo);
int test33();
int jkpatch1();
int dec_pups();
int install_sys();
void klog(const char *format, ...);
void logprintf(const char *format, ...);
void decrypt_and_dump_self(char *selfFile, char *saveFile);
void decrypt_and_dump_selfs(char selfFile, char saveFile);
int linux();
int eap455();
int tryweb();
int ElfFileselfz(); // wtf?
int loadElfFileelf();
int pkgdl();
int remoteplaypatch();
int psxloader();
int loadElfFilebin(); // wtf?
int cantfindelfs();
int PS4LEDTEST();
int fantest2();
int fantest1();


