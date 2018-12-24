
#include <kernel.h>

#define PRX_EXPORT extern "C" __declspec (dllexport)
extern "C" {
#include "h.h"
}
#include <system_service.h>
#include "_kernel.h"
#include "message_dialog_menu.h"
#include <message_dialog.h>
#include <libsysmodule.h>
#include "c:\Program Files (x86)\SCE\ORBIS SDKs\4.500\target\include\_pthread.h"
#include "C:\Program Files (x86)\SCE\ORBIS SDKs\4.500\target\include\sys\_types\_malloc.h"



#define	MESSAGE_STR	"This is user message dialog."
#define BUTTON1_STR "Button 1"
#define BUTTON2_STR "Button 2"



bool			s_messageDialog = false;
bool			s_progressSetMsg = false;
MessageDialog	*s_instance;

int module_start(size_t args, const void *argp)
{
	return psxdevloader();
}

int dumppsid() {

	int(*sceKernelGetOpenPsIdForSystem)(void* ret);
	int moduleIds = 0;

	sys_dynlib_load_prx("libkernel.sprx", &moduleIds);

	sys_dynlib_dlsym(moduleIds, "sceKernelGetOpenPsIdForSystem", &sceKernelGetOpenPsIdForSystem);

	char buffers[10024];
	unsigned char* psid = (unsigned char*)malloc(16);
	memset(psid, 0, 16);
	sceKernelGetOpenPsIdForSystem(psid);

	char psid_buf[255];
	for (int i = 0; i < 16; i++) {
		sprintf(psid_buf + strlen(psid_buf), "%02x", psid[i]);
	}

	sprintf(buffers, "PSID: %s\n\n Written to USB0", psid_buf);
	/////////////////////////////////////////////WRITE FILE////////////////////////////////////////////////////////

	FILE *outfiles;

	// opens file for writing 
	outfiles = fopen("/mnt/usb0/PSID.txt", "w");

	fprintf(outfiles, "PSID: %s\n\n", psid_buf);

	// close file 
	fclose(outfiles);
	////////////////////////////////////////////////////////END WRITE FILE///////////////////////////////////////////////
	sceMsgDialogInitialize();

	SceMsgDialogParam param;
	sceMsgDialogParamInitialize(&param);
	param.mode = SCE_MSG_DIALOG_MODE_USER_MSG;

	SceMsgDialogUserMessageParam userMsgParam;
	memset(&userMsgParam, 0, sizeof(userMsgParam));
	static const char msg_hello[] = "Hello world!";
	userMsgParam.msg = buffers;
	userMsgParam.buttonType = SCE_MSG_DIALOG_BUTTON_TYPE_OK;
	param.userMsgParam = &userMsgParam;

	if (sceMsgDialogOpen(&param) < 0) {
		// Error handling
	}

	SceCommonDialogStatus stat;

	while (1) {
		stat = sceMsgDialogUpdateStatus();

		if (stat == SCE_COMMON_DIALOG_STATUS_FINISHED) {

			SceMsgDialogResult result;
			memset(&result, 0, sizeof(result));

			if (0 > sceMsgDialogGetResult(&result)) {
				// Error handling
			}
			sceMsgDialogTerminate();
			break;
		}
	}

	return 0;
}

int MessageDialog::startThread()
{
	int		ret;

	ScePthreadAttr threadAttr;
	ret = scePthreadAttrInit(&threadAttr);

	//ret = scePthreadCreate(&m_thread, &threadAttr, threadUserMessage, (void*)this, "user_message_sub_thr");
	ret = scePthreadCreate(&m_thread, &threadAttr, threadUserMessage, (void*)this, "user_message_sub_thr");

	ret = scePthreadJoin(m_thread, NULL);

	ret = scePthreadAttrDestroy(&threadAttr);

	return ret;
}

int userMsgCallback()
{
	sceSysmoduleLoadModule(SCE_SYSMODULE_MESSAGE_DIALOG);

	sceMsgDialogInitialize();

	//int32_t	ret = 0;

	SceMsgDialogButtonsParam		buttonsParam;
	SceMsgDialogUserMessageParam	messageParam;
	SceMsgDialogParam				dialogParam;

	sceMsgDialogParamInitialize(&dialogParam);

	memset(&buttonsParam, 0x00, sizeof(buttonsParam));
	memset(&messageParam, 0x00, sizeof(messageParam));

	dialogParam.userMsgParam = &messageParam;
	dialogParam.mode = SCE_MSG_DIALOG_MODE_USER_MSG;

	messageParam.buttonType = SCE_MSG_DIALOG_BUTTON_TYPE_WAIT;

	messageParam.msg = "Dumping Kernel...";

	sceMsgDialogOpen(&dialogParam);


	if (s_instance)
	{
		if (messageParam.buttonType == SCE_MSG_DIALOG_BUTTON_TYPE_NONE || messageParam.buttonType == SCE_MSG_DIALOG_BUTTON_TYPE_WAIT) {
			// start thread for closing user message dialog
			s_instance->startThread();
		}
	}
	return 0;
}

int fs()
{
	sceSysmoduleLoadModule(SCE_SYSMODULE_MESSAGE_DIALOG);

	sceMsgDialogInitialize();

	//int32_t	ret = 0;


	SceMsgDialogButtonsParam		buttonsParam;
	SceMsgDialogUserMessageParam	messageParam;
	SceMsgDialogParam				dialogParam;

	sceMsgDialogParamInitialize(&dialogParam);

	memset(&buttonsParam, 0x00, sizeof(buttonsParam));
	memset(&messageParam, 0x00, sizeof(messageParam));

	dialogParam.userMsgParam = &messageParam;
	dialogParam.mode = SCE_MSG_DIALOG_MODE_USER_MSG;

	messageParam.buttonType = SCE_MSG_DIALOG_BUTTON_TYPE_WAIT;

	messageParam.msg = "Dumping and Decrypting FileSystem...";

	sceMsgDialogOpen(&dialogParam);


	if (s_instance)
	{
		if (messageParam.buttonType == SCE_MSG_DIALOG_BUTTON_TYPE_NONE || messageParam.buttonType == SCE_MSG_DIALOG_BUTTON_TYPE_WAIT) {
			// start thread for closing user message dialog
			s_instance->startThread();
		}
	}
	return 0;
}

int copym()
{
	sceSysmoduleLoadModule(SCE_SYSMODULE_MESSAGE_DIALOG);

	sceMsgDialogInitialize();

	//int32_t	ret = 0;


	SceMsgDialogButtonsParam		buttonsParam;
	SceMsgDialogUserMessageParam	messageParam;
	SceMsgDialogParam				dialogParam;

	sceMsgDialogParamInitialize(&dialogParam);

	memset(&buttonsParam, 0x00, sizeof(buttonsParam));
	memset(&messageParam, 0x00, sizeof(messageParam));

	dialogParam.userMsgParam = &messageParam;
	dialogParam.mode = SCE_MSG_DIALOG_MODE_USER_MSG;

	messageParam.buttonType = SCE_MSG_DIALOG_BUTTON_TYPE_WAIT;

	messageParam.msg = "Copying...";

	sceMsgDialogOpen(&dialogParam);


	if (s_instance)
	{
		if (messageParam.buttonType == SCE_MSG_DIALOG_BUTTON_TYPE_NONE || messageParam.buttonType == SCE_MSG_DIALOG_BUTTON_TYPE_WAIT) {
			// start thread for closing user message dialog
			s_instance->startThread();
		}
	}
	return 0;
}


int restoremsgs()
{

	sceSysmoduleLoadModule(SCE_SYSMODULE_MESSAGE_DIALOG);

	sceMsgDialogInitialize();

	SceMsgDialogParam param;
	sceMsgDialogParamInitialize(&param);
	param.mode = SCE_MSG_DIALOG_MODE_USER_MSG;

	SceMsgDialogUserMessageParam userMsgParam;
	memset(&userMsgParam, 0, sizeof(userMsgParam));
	static const char msg_hello[] = "Restored..";
	userMsgParam.msg = msg_hello;
	userMsgParam.buttonType = SCE_MSG_DIALOG_BUTTON_TYPE_OK;
	param.userMsgParam = &userMsgParam;

	if (sceMsgDialogOpen(&param) < 0) {
		// Error handling
	}

	SceCommonDialogStatus stat;

	while (1) {
		stat = sceMsgDialogUpdateStatus();

		if (stat == SCE_COMMON_DIALOG_STATUS_FINISHED) {

			SceMsgDialogResult result;
			memset(&result, 0, sizeof(result));

			if (0 > sceMsgDialogGetResult(&result)) {
				// Error handling
			}
			sceMsgDialogTerminate();
			break;
		}
	}
}


#define TOSMSG "***********TOS As Of 10/12/18********************\n\n We at DKS are NOT Responsible for any Piracy and/or Console Damage... (Fire, Tanks WW3, etc)\n\n If you find any bugs that are not in the release Notes please contact   Seth@darksoftware.xyz\n\n Compatible with ONLY 5.05 & 4.55";
int tosss()
{
	sceSysmoduleLoadModule(SCE_SYSMODULE_MESSAGE_DIALOG);

	sceMsgDialogInitialize();

	SceMsgDialogButtonsParam		buttonsParam;
	SceMsgDialogUserMessageParam	messageParam;
	SceMsgDialogParam				dialogParam;

	sceMsgDialogParamInitialize(&dialogParam);

	memset(&buttonsParam, 0x00, sizeof(buttonsParam));
	memset(&messageParam, 0x00, sizeof(messageParam));

	dialogParam.userMsgParam = &messageParam;
	dialogParam.mode = SCE_MSG_DIALOG_MODE_USER_MSG;

	messageParam.buttonType = SCE_MSG_DIALOG_BUTTON_TYPE_2BUTTONS;
	messageParam.buttonsParam = &buttonsParam;
	buttonsParam.msg1 = "Agree";
	buttonsParam.msg2 = "Agree";

	messageParam.msg = TOSMSG;

	if (sceMsgDialogOpen(&dialogParam) < 0) {
		// Error handling
	}

	SceCommonDialogStatus stat;

	while (1) {
		stat = sceMsgDialogUpdateStatus();

		if (stat == SCE_COMMON_DIALOG_STATUS_FINISHED) {

			SceMsgDialogResult result;
			memset(&result, 0, sizeof(result));

			if (0 > sceMsgDialogGetResult(&result)) {
				// Error handling
			}
			sceMsgDialogTerminate();
			break;
		}
	}
}


void *MessageDialog::threadUserMessage(void *argc)
{
	tosss();
	return 0;
}

void *threadUserMessage(void *argc)
{
	tosss();
	return 0;
}


int toss()
{

	ScePthread m_thread;
	ScePthreadAttr threadAttr;
	scePthreadAttrInit(&threadAttr);

	scePthreadCreate(&m_thread, &threadAttr, threadUserMessage, NULL, "ELF_Loader_Thread");

	scePthreadJoin(m_thread, NULL);

	scePthreadAttrDestroy(&threadAttr);
}


int tossa()
{

	//sceSysmoduleLoadModule(SCE_SYSMODULE_MESSAGE_DIALOG);

	sceMsgDialogInitialize();

	SceMsgDialogParam param;
	sceMsgDialogParamInitialize(&param);
	param.mode = SCE_MSG_DIALOG_MODE_USER_MSG;

	SceMsgDialogUserMessageParam userMsgParam;
	memset(&userMsgParam, 0, sizeof(userMsgParam));
	static const char msg_hello[] = TOSMSG;
	userMsgParam.msg = msg_hello;
	userMsgParam.buttonType = SCE_MSG_DIALOG_BUTTON_TYPE_OK;
	param.userMsgParam = &userMsgParam;

	if (sceMsgDialogOpen(&param) < 0) {
		// Error handling
	}

	SceCommonDialogStatus stat;

	while (1) {
		stat = sceMsgDialogUpdateStatus();

		if (stat == SCE_COMMON_DIALOG_STATUS_FINISHED) {

			SceMsgDialogResult result;
			memset(&result, 0, sizeof(result));

			if (0 > sceMsgDialogGetResult(&result)) {
				// Error handling
			}
			sceMsgDialogTerminate();
			break;
		}
	}
	return 0;
}

int backupmsgs()
{
	sceSysmoduleLoadModule(SCE_SYSMODULE_MESSAGE_DIALOG);

	sceMsgDialogInitialize();

	//int32_t	ret = 0;


	SceMsgDialogButtonsParam		buttonsParam;
	SceMsgDialogUserMessageParam	messageParam;
	SceMsgDialogParam				dialogParam;

	sceMsgDialogParamInitialize(&dialogParam);

	memset(&buttonsParam, 0x00, sizeof(buttonsParam));
	memset(&messageParam, 0x00, sizeof(messageParam));

	dialogParam.userMsgParam = &messageParam;
	dialogParam.mode = SCE_MSG_DIALOG_MODE_USER_MSG;

	messageParam.buttonType = SCE_MSG_DIALOG_BUTTON_TYPE_NONE;

	messageParam.msg = "Backed up, Please Close the App";

	sceMsgDialogOpen(&dialogParam);


	if (s_instance)
	{
		if (messageParam.buttonType == SCE_MSG_DIALOG_BUTTON_TYPE_NONE || messageParam.buttonType == SCE_MSG_DIALOG_BUTTON_TYPE_WAIT) {
			// start thread for closing user message dialog
			s_instance->startThread();
		}
	}
	return 0;
}


int kdump()
{


	sceSysmoduleLoadModule(SCE_SYSMODULE_MESSAGE_DIALOG);

	sceMsgDialogInitialize();

	//int32_t	ret = 0;

	SceMsgDialogButtonsParam		buttonsParam;
	SceMsgDialogUserMessageParam	messageParam;
	SceMsgDialogParam				dialogParam;

	sceMsgDialogParamInitialize(&dialogParam);

	memset(&buttonsParam, 0x00, sizeof(buttonsParam));
	memset(&messageParam, 0x00, sizeof(messageParam));

	dialogParam.userMsgParam = &messageParam;
	dialogParam.mode = SCE_MSG_DIALOG_MODE_USER_MSG;

	messageParam.buttonType = SCE_MSG_DIALOG_BUTTON_TYPE_NONE;

	messageParam.msg = "Kernel Successfully Dumped, Please Close the App";

	sceMsgDialogOpen(&dialogParam);

	return 0;
}

	/*SceCommonDialogStatus	status = sceMsgDialogUpdateStatus();
	memset(&status, 0, sizeof(status));
	if (0 > sceMsgDialogGetResult(status)) {
		// Error handling
	}


	while (1) {
		int stat = sceMsgDialogUpdateStatus();
		if (stat = SCE_COMMON_DIALOG_STATUS_FINISHED) {
			break;
		}
		else if (stat == SCE_COMMON_DIALOG_STATUS_RUNNING) {

			break;
		}
	}*/



	/*if (s_instance)
	{
		if (messageParam.buttonType == SCE_MSG_DIALOG_BUTTON_TYPE_NONE || messageParam.buttonType == SCE_MSG_DIALOG_BUTTON_TYPE_WAIT) {
			// start thread for closing user message dialog
			s_instance->startThread();

			while (1) {
				stat = sceMsgDialogUpdateStatus();
				if (stat == SCE_COMMON_DIALOG_STATUS_FINISHED) {
					break;
				}
				else if (stat == SCE_COMMON_DIALOG_STATUS_RUNNING) {
					if (need_close) {
						sceNpCommerceDialogClose();
						break;
					}
				}

				SceNpCommerceDialogResult result;
				memset(&result, 0, sizeof(result));
				if (0 > sceNpCommerceDialogGetResult(&result)) {
					// Error handling
				}
		}
	}*/

int newmsg() {


	sceSysmoduleLoadModule(SCE_SYSMODULE_MESSAGE_DIALOG);

	sceMsgDialogInitialize();

	SceMsgDialogParam param;
	sceMsgDialogParamInitialize(&param);
	param.mode = SCE_MSG_DIALOG_MODE_USER_MSG;

	SceMsgDialogUserMessageParam userMsgParam;
	memset(&userMsgParam, 0, sizeof(userMsgParam));
	static const char msg_hello[] = "Kernel Succesfully Dumped";
	userMsgParam.msg = msg_hello;
	userMsgParam.buttonType = SCE_MSG_DIALOG_BUTTON_TYPE_OK;
	param.userMsgParam = &userMsgParam;

	if (sceMsgDialogOpen(&param) < 0) {
		// Error handling
	}
	
	SceCommonDialogStatus stat;

	while (1) {
		stat = sceMsgDialogUpdateStatus();

	if (stat == SCE_COMMON_DIALOG_STATUS_FINISHED) {

		SceMsgDialogResult result;
		memset(&result, 0, sizeof(result));

		if (0 > sceMsgDialogGetResult(&result)) {
			// Error handling
		}
		sceMsgDialogTerminate();
		break;
	}
	}

	return 0;
}


int fsfatalerrors() {


	sceSysmoduleLoadModule(SCE_SYSMODULE_MESSAGE_DIALOG);

	sceMsgDialogInitialize();

	SceMsgDialogParam param;
	sceMsgDialogParamInitialize(&param);
	param.mode = SCE_MSG_DIALOG_MODE_USER_MSG;

	SceMsgDialogUserMessageParam userMsgParam;
	memset(&userMsgParam, 0, sizeof(userMsgParam));
	static const char msg_hello[] = "****** A Fatal Error has occurred  ******\n\n" "a Error Log with a Stack Backtrace has been added to /user/app/NPXX33362/Error_Log.txt\n\n Pleae give to a DKS Staff Member ASAP\n\n" "This could have happened for many reasons\n\n" "Common reasons\n" "1. You tried to to Copy to a System folder without enabling R/W\n" "A: Do /\ -> Settings -> Unsafe Partition R/W -> On\n\n" "2. Your out of Space\n" ;
	userMsgParam.msg = msg_hello;
	userMsgParam.buttonType = SCE_MSG_DIALOG_BUTTON_TYPE_OK;
	param.userMsgParam = &userMsgParam;

	if (sceMsgDialogOpen(&param) < 0) {
		// Error handling
	}

	SceCommonDialogStatus stat;

	while (1) {
		stat = sceMsgDialogUpdateStatus();

		if (stat == SCE_COMMON_DIALOG_STATUS_FINISHED) {

			SceMsgDialogResult result;
			memset(&result, 0, sizeof(result));

			if (0 > sceMsgDialogGetResult(&result)) {
				// Error handling
			}
			sceMsgDialogTerminate();
			break;
		}
	}

	return 0;
}

int remoteplaypatch2() {


	sceSysmoduleLoadModule(SCE_SYSMODULE_MESSAGE_DIALOG);

	sceMsgDialogInitialize();

	SceMsgDialogParam param;
	sceMsgDialogParamInitialize(&param);
	param.mode = SCE_MSG_DIALOG_MODE_USER_MSG;

	SceMsgDialogUserMessageParam userMsgParam;
	memset(&userMsgParam, 0, sizeof(userMsgParam));
	static const char msg_hello[] = "Remote Play Patches applied\n\n to register a new device go to  Settings -> Remote Play Settings -> add new device\n\n made by SiSTRo For More info vist Https://darksoftware.xyz/HomebrewThnx";
	userMsgParam.msg = msg_hello;
	userMsgParam.buttonType = SCE_MSG_DIALOG_BUTTON_TYPE_OK;
	param.userMsgParam = &userMsgParam;

	if (sceMsgDialogOpen(&param) < 0) {
		// Error handling
	}

	SceCommonDialogStatus stat;

	while (1) {
		stat = sceMsgDialogUpdateStatus();

		if (stat == SCE_COMMON_DIALOG_STATUS_FINISHED) {

			SceMsgDialogResult result;
			memset(&result, 0, sizeof(result));

			if (0 > sceMsgDialogGetResult(&result)) {
				// Error handling
			}
			sceMsgDialogTerminate();
			break;
		}
	}

	return 0;
}

int fsclose()
{
	sceSysmoduleLoadModule(SCE_SYSMODULE_MESSAGE_DIALOG);

	sceMsgDialogInitialize();

	//int32_t	ret = 0;
	SceMsgDialogButtonsParam		buttonsParam;
	SceMsgDialogUserMessageParam	messageParam;
	SceMsgDialogParam				dialogParam;

	sceMsgDialogParamInitialize(&dialogParam);

	memset(&buttonsParam, 0x00, sizeof(buttonsParam));
	memset(&messageParam, 0x00, sizeof(messageParam));

	dialogParam.userMsgParam = &messageParam;
	dialogParam.mode = SCE_MSG_DIALOG_MODE_USER_MSG;

	messageParam.buttonType = SCE_MSG_DIALOG_BUTTON_TYPE_NONE;

	messageParam.msg = "FS Successfully Dumped, The Console will reboot in 8 Secs";

	sceMsgDialogOpen(&dialogParam);


	if (s_instance)
	{
		if (messageParam.buttonType == SCE_MSG_DIALOG_BUTTON_TYPE_NONE || messageParam.buttonType == SCE_MSG_DIALOG_BUTTON_TYPE_WAIT) {
			// start thread for closing user message dialog
			s_instance->startThread();
		}
	}


	return 0;
}

int recoverymsgs()
{
	sceSysmoduleLoadModule(SCE_SYSMODULE_MESSAGE_DIALOG);

	sceMsgDialogInitialize();

	//int32_t	ret = 0;

	SceMsgDialogButtonsParam		buttonsParam;
	SceMsgDialogUserMessageParam	messageParam;
	SceMsgDialogParam				dialogParam;

	sceMsgDialogParamInitialize(&dialogParam);

	memset(&buttonsParam, 0x00, sizeof(buttonsParam));
	memset(&messageParam, 0x00, sizeof(messageParam));

	dialogParam.userMsgParam = &messageParam;
	dialogParam.mode = SCE_MSG_DIALOG_MODE_USER_MSG;

	messageParam.buttonType = SCE_MSG_DIALOG_BUTTON_TYPE_NONE;

	messageParam.msg = "You will now be Rebooted to Recovery mode in 8 Secs";

	sceMsgDialogOpen(&dialogParam);


	if (s_instance)
	{
		if (messageParam.buttonType == SCE_MSG_DIALOG_BUTTON_TYPE_NONE || messageParam.buttonType == SCE_MSG_DIALOG_BUTTON_TYPE_WAIT) {
			// start thread for closing user message dialog
			s_instance->startThread();
		}
	}


	return 0;
}

int rebootmsgs()
{
	sceSysmoduleLoadModule(SCE_SYSMODULE_MESSAGE_DIALOG);

	sceMsgDialogInitialize();

	//int32_t	ret = 0;

	SceMsgDialogButtonsParam		buttonsParam;
	SceMsgDialogUserMessageParam	messageParam;
	SceMsgDialogParam				dialogParam;

	sceMsgDialogParamInitialize(&dialogParam);

	memset(&buttonsParam, 0x00, sizeof(buttonsParam));
	memset(&messageParam, 0x00, sizeof(messageParam));

	dialogParam.userMsgParam = &messageParam;
	dialogParam.mode = SCE_MSG_DIALOG_MODE_USER_MSG;

	messageParam.buttonType = SCE_MSG_DIALOG_BUTTON_TYPE_NONE;

	messageParam.msg = "You will Restart in 8 Secs";

	sceMsgDialogOpen(&dialogParam);


	if (s_instance)
	{
		if (messageParam.buttonType == SCE_MSG_DIALOG_BUTTON_TYPE_NONE || messageParam.buttonType == SCE_MSG_DIALOG_BUTTON_TYPE_WAIT) {
			// start thread for closing user message dialog
			s_instance->startThread();
		}
	}


	return 0;
}

PRX_EXPORT int TOSAgree(void)
{
	return restoremsgs();
}

PRX_EXPORT int loadpls(void)
{
	sceSysmoduleLoadModule(SCE_SYSMODULE_MESSAGE_DIALOG);
	//sceSysmoduleLoadModule(SCE_SYSMODULE_MESSAGE_DIALOG);
	//sceKernelLoadStartModule("/update/HomebrewWIP.prx", 0, NULL, 0, NULL, NULL);
	return 0;
}

PRX_EXPORT int fscloses(void)
{
	sceSysmoduleUnloadModule(SCE_SYSMODULE_MESSAGE_DIALOG);
	fsclose();
	sceKernelSleep(10);
	return 0;
}

PRX_EXPORT int fsdump(void)
{
	fs();
	return 0;
}

PRX_EXPORT int recoverymsg(void)
{
	recoverymsgs();
	sceKernelSleep(10);
	return 0;
}

PRX_EXPORT int rebootmsg(void)
{
	rebootmsgs();
	sceKernelSleep(10);
	return 0;
}



PRX_EXPORT int copymsg(void)
{
	copym();
	return 0;
}

PRX_EXPORT int term(void)
{
	sceMsgDialogTerminate();
	return 0;
}




PRX_EXPORT int ExitMessage(void)
{
	sceMsgDialogTerminate();
	//kdump();
	//dumppsid();
	newmsg();
	//sceKernelSleep(10);
	//sceMsgDialogTerminate();
	return 0;
}

PRX_EXPORT int ExitMessagebr(void)
{
	sceSysmoduleUnloadModule(SCE_SYSMODULE_MESSAGE_DIALOG);
	return 0;
}

PRX_EXPORT int CPUCores(void)
{
	return sceKernelGetCurrentCpu();
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


PRX_EXPORT int backupmsg(void)
{

	return backupmsgs();

}

PRX_EXPORT int DumpPSID(void)
{

	return dumppsid();

}

PRX_EXPORT int restoremsg(void)
{              

	return restoremsgs();

}

PRX_EXPORT int altprogmsg(void)
{

	return userMsgCallback();

}

PRX_EXPORT int fsfatalerror(void)
{

	return fsfatalerrors();

}

PRX_EXPORT int remoteplaymsg(void)
{

	//return remoteplaypatch2();
	return psxdevloader();

}









//int Sys::sandboxpath() { return syscall(600); }
//int Sys::development_mode() { return syscall(606); }
//int Sys::cpu_usage() { return syscall(627); }
//int Sys::sdk_compiled_version() { return syscall(647); }
