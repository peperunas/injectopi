#include "utils.h"

IMAGE_OPTIONAL_HEADER32 GetOptHdr(unsigned char *read_proc) {
	IMAGE_DOS_HEADER *idh = NULL;
	IMAGE_NT_HEADERS *inh = NULL;

	idh = (IMAGE_DOS_HEADER *)read_proc;
	inh = (IMAGE_NT_HEADERS *)((BYTE *)read_proc + idh->e_lfanew);
	return inh->OptionalHeader;
}