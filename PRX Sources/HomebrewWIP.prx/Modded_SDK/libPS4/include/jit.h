#pragma once


void initJIT(void);

void allocateJIT(size_t size, void **executableAddress, void **writableAddress);
