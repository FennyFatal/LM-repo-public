
#pragma once

#include <_types.h>
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
int dumpnote();
int FTPStart();
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
int jjjjk();
int dumped_and_decrypted_note();
int dump_all();
int dump_shellcore();
//void mmappw();
int mount_rw();
int off_mount_rw();
void ftps4_fini();
int FTPS();
int elfloadernote();
int elfloader();
int loadElfFile();
int loadElfFileelf();
int loadElfFilebin();
int cantfindelfs();
int loadElfFileself();
int loadElfFileselfz();
int sample2note();
int sample1note();
int tryweb();
int pkgdl();