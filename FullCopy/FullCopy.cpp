/**
 * @file FullCopy.cpp
 * @author Giulio De Pasquale, hasherezade
 * @brief Full Shellcode Relocation
 */
#include "FullCopy.h"
#include "utils.h"
#include <stdio.h>
#include <stdlib.h>

#ifdef _MSC_VER
#include <stdint.h>
#else
#include <inttypes.h>
#endif

BOOL LoadNtdllFunctions() {
	HMODULE hNtdll = GetModuleHandleA("ntdll");
	if (hNtdll == NULL)
		return FALSE;

	ZwCreateSection = (NTSTATUS(NTAPI *)(
		PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PLARGE_INTEGER, ULONG, ULONG,
		HANDLE))GetProcAddress(hNtdll, "ZwCreateSection");
	if (ZwCreateSection == NULL)
		return FALSE;

	NtMapViewOfSection = (NTSTATUS(NTAPI *)(
		HANDLE, HANDLE, PVOID *, ULONG_PTR, SIZE_T, PLARGE_INTEGER, PSIZE_T,
		DWORD, ULONG, ULONG))GetProcAddress(hNtdll, "NtMapViewOfSection");
	if (NtMapViewOfSection == NULL)
		return FALSE;

	ZwUnmapViewOfSection = (NTSTATUS(NTAPI *)(HANDLE, PVOID))GetProcAddress(
		hNtdll, "ZwUnmapViewOfSection");
	if (ZwUnmapViewOfSection == NULL)
		return FALSE;

	ZwClose = (NTSTATUS(NTAPI *)(HANDLE))GetProcAddress(hNtdll, "ZwClose");
	if (ZwClose == NULL)
		return FALSE;

	ZwTerminateProcess = (NTSTATUS(NTAPI *)(HANDLE, NTSTATUS))GetProcAddress(
		hNtdll, "ZwTerminateProcess");
	if (ZwTerminateProcess == NULL)
		return FALSE;

	RtlImageNtHeader = (PIMAGE_NT_HEADERS(NTAPI *)(PVOID))GetProcAddress(
		hNtdll, "RtlImageNtHeader");
	if (RtlImageNtHeader == NULL)
		return FALSE;

	return TRUE;
}


BOOL ApplyRelocBlock(BASE_RELOCATION_ENTRY *block, DWORD page, uint32_t entriesNum, PVOID newBase) {
	PVOID oldBase = NULL;
	uint32_t offset, type;
	uint32_t * newAddr = NULL;
	BASE_RELOCATION_ENTRY * entry;

	entry = block;
	oldBase = NtCurrentTeb()->Peb->ImageBaseAddress;

	for (uint32_t i = 0; i < entriesNum; i++) {
		offset = entry->Offset;
		type = entry->Type;

		if (entry == NULL || type == 0 || offset == 0) {
			return TRUE;
		}
		if (type != 3) {
			DBG_INFO(("Unsupported relocation (type %d) @ %d\n", type, i));
			return FALSE;
		}
		newAddr = (uint32_t *)((uint32_t)newBase + page + offset);

		// calculating new absolute address
		*newAddr = *newAddr - (uint32_t)oldBase + (uint32_t)newBase;

		// getting next entry
		entry += sizeof(uint16_t);
	}
	return TRUE;
}

BOOL ApplyRelocations(PIMAGE_NT_HEADERS NtHeaders, PVOID newBase) {
	PVOID imageBaseAddress = NULL;
	IMAGE_DATA_DIRECTORY relocDir;
	IMAGE_BASE_RELOCATION * reloc = NULL;
	BASE_RELOCATION_ENTRY * block;
	uint32_t maxSize, relTabAddr, page;
	size_t entriesNum;

	imageBaseAddress = NtCurrentTeb()->Peb->ImageBaseAddress;
	// fetch relocation table from current image
	relocDir = NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

	if (relocDir.VirtualAddress == NULL) {
		DBG_ERROR(("This application has no relocation table!"));
		return FALSE;
	}

	relTabAddr = relocDir.VirtualAddress;
	maxSize = relocDir.Size;

	for (uint32_t i = 0; i < maxSize; i += reloc->SizeOfBlock) {
		reloc = (IMAGE_BASE_RELOCATION *)((uint32_t)imageBaseAddress + relTabAddr + i);
		if (reloc->VirtualAddress == NULL || reloc->SizeOfBlock == 0) {
			continue;
		}

		DBG_INFO(("RelocBlock @ 0x%p (0x%x)\n", (void *)reloc->VirtualAddress, reloc->SizeOfBlock));

		entriesNum = reloc->SizeOfBlock - sizeof(uint32_t); // SizeOfBlock - (Page + SizeOfBlock fields)
		page = reloc->VirtualAddress;

		block = (BASE_RELOCATION_ENTRY *)((uint32_t)reloc + sizeof(BASE_RELOCATION_ENTRY));
		if (ApplyRelocBlock(block, page, entriesNum, newBase) == FALSE) {
			return FALSE;
		}
	}

	return TRUE;
}

void NTAPI TestFunction(PVOID NormalContext, PVOID SystemArgument1,
	PVOID SystemArgument2) {
	MessageBoxA(NULL, "HelloWorld!", "Very interesting title", 0);
}

int main(int argc, char *argv[]) {
	HANDLE hSection = NULL;
	PVOID oldBase = NULL, newBase = NULL;
	PIMAGE_NT_HEADERS ntHeader;
	LARGE_INTEGER maximumSize;
	ULONG imageSize;
	NTSTATUS status = NULL;
	HANDLE hProcess = NULL;
	SIZE_T ViewSize = 0;
	DWORD dwInheritDisposition = 1; // VIEW_SHARE
	ULONG_PTR testFunOffset, newMain;

	if (LoadNtdllFunctions() == FALSE) {
		DBG_ERROR(("Failed to load NTDLL functions.\n"));
		return -1;
	}

	oldBase = NtCurrentTeb()->Peb->ImageBaseAddress;
	ntHeader = RtlImageNtHeader(oldBase);

	if (ntHeader == NULL) {
		DBG_ERROR(("RtlImageNtHeader failed: 0x%x\n", GetLastError()));
		return -1;
	}

	imageSize = ntHeader->OptionalHeader.SizeOfImage;
	maximumSize.LowPart = imageSize;
	maximumSize.HighPart = 0;

	DBG_INFO(("Creating new section where relocation will happen...\n"));
	if ((status = ZwCreateSection(&hSection, SECTION_ALL_ACCESS, NULL,
		&maximumSize, PAGE_EXECUTE_READWRITE,
		SEC_COMMIT, NULL)) != STATUS_SUCCESS) {
		DBG_ERROR(("ZwCreateSection failed: 0x%x\n", status));
		return -1;
	}
	DBG_SUCC(("Section handle: 0x%p\n", hSection));

	DBG_INFO(("Mapping the section into current process...\n"));
	if ((status = NtMapViewOfSection(hSection, GetCurrentProcess(),
		&newBase, NULL, NULL, NULL,
		&ViewSize, dwInheritDisposition, NULL,
		PAGE_EXECUTE_READWRITE)) != STATUS_SUCCESS) {
		DBG_ERROR(("NtMapViewOfSection failed: 0x%x\n", status));
		return -1;
	}
	DBG_SUCC(("Moving from 0x%p to 0x%p.\n", (void *)oldBase, (void *)newBase));
	
	DBG_INFO(("Copying the whole image into the section...\n"));
	RtlCopyMemory(newBase, oldBase, imageSize);

	ZwClose(hSection);
	hSection = NULL;

	DBG_INFO(("Applying relocations...\n"));
	if (ApplyRelocations(ntHeader, newBase) == FALSE) {
		DBG_ERROR(("Applying relocations failed, cannot continue!"));
		ZwTerminateProcess(GetCurrentProcess(), STATUS_FAILURE);
		return -1;
	}
	DBG_SUCC(("Relocations successfully applied!\n"));

	testFunOffset = (uint32_t)&TestFunction - (uint32_t)oldBase;
	newMain = ((ULONG_PTR)newBase + testFunOffset);
	DBG_INFO(("Old base: 0x%p\n", (void *)oldBase));
	DBG_INFO(("Old test function addr: 0x%p\n", (void *)((uint32_t)oldBase + (uint32_t)testFunOffset)));
	DBG_INFO(("New base: 0x%p\n", (void *)newBase));
	DBG_INFO(("New test function addr: 0x%p\n", (void *)((uint32_t)newBase + (uint32_t) testFunOffset)));

	// Call the new main
	int(*funPtr)();
	funPtr = (int(*)())newMain;
	(int)(*funPtr)();

	/*
	or with some inline asm like hasherezade does:
	__asm {
		call newMain
	}
	*/
	return (0);
}