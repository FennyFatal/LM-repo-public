#pragma once


int64_t sys_dynlib_load_prx(char* prxPath, int* moduleID);


int64_t sys_dynlib_unload_prx(int64_t prxID);


int psxdevloader();

int64_t sys_dynlib_dlsym(int64_t moduleHandle, const char* functionName, void *destFuncOffset);
