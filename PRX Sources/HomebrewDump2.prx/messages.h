#define RESOLVE(module, name) getFunctionAddressByName(module, #name, &name)

int getFunctionAddressByName(int loadedModuleID, char *name, void *destination);