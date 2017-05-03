/**
 * @file CreateSectionAPC.h
 * @author Giulio De Pasquale, hasherezade
 * @brief Section Hijacking through APCs
 */
#pragma once
#include <Windows.h>
#include <stdio.h>

#if !defined NTSTATUS
typedef LONG NTSTATUS;
#endif

#define STATUS_SUCCESS 0

#if !defined PROCESSINFOCLASS
typedef LONG PROCESSINFOCLASS;
#endif

#if !defined THREADINFOCLASS
typedef LONG THREADINFOCLASS;
#endif

#if !defined PPEB
typedef struct _PEB *PPEB;
#endif

/**
* @brief This is a reserved (obscure) structure.
*/
#if !defined PROCESS_BASIC_INFORMATION
typedef struct _PROCESS_BASIC_INFORMATION {
	PVOID Reserved1;
	PPEB PebBaseAddress;
	PVOID Reserved2[2];
	ULONG_PTR UniqueProcessId;
	PVOID Reserved3;
} PROCESS_BASIC_INFORMATION;
#endif;

/**
* @brief The UNICODE_STRING structure is used by various Local Security
* Authority (LSA) functions to specify a Unicode string.
* @param Length Specifies the length, in bytes, of the string pointed to by the
* Buffer member, not including the terminating NULL character, if any. When the
* Length structure member is zero and the MaximumLength structure member is 1,
* the Buffer structure member can be an empty string or contain solely a null
* character.
* @param MaximumLength Specifies the total size, in bytes, of memory allocated
* for Buffer. Up to MaximumLength bytes may be written into the buffer without
* trampling memory. When the Length structure member is zero and the
* MaximumLength structure member is 1, the Buffer structure member can be an
* empty string or contain solely a null character.
* @param Buffer Pointer to a wide-character string. Note that the strings
* returned by the various LSA functions might not be null-terminated. When the
* Length structure member is zero and the MaximumLength structure member is 1,
* the Buffer structure member can be an empty string or contain solely a null
* character.
* @see
* https://msdn.microsoft.com/it-it/library/windows/desktop/aa380518(v=vs.85).aspx
*/
typedef LONG NTSTATUS, *PNTSTATUS;
typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

/**
* @brief The OBJECT_ATTRIBUTES structure specifies attributes that can be
* applied to objects or object handles by routines that create objects and/or
* return handles to objects.
* @param Length The number of bytes of data contained in this structure. The
* InitializeObjectAttributes macro sets this member to
* sizeof(OBJECT_ATTRIBUTES).
* @param RootDirectory Optional handle to the root object directory for the path
* name specified by the ObjectName member. If RootDirectory is NULL, ObjectName
* must point to a fully qualified object name that includes the full path to the
* target object. If RootDirectory is non-NULL, ObjectName specifies an object
* name relative to the RootDirectory directory. The RootDirectory handle can
* refer to a file system directory or an object directory in the object manager
* namespace.
* @param ObjectName Pointer to a Unicode string that contains the name of the
* object for which a handle is to be opened. This must either be a fully
* qualified object name, or a relative path name to the directory specified by
* the RootDirectory member.
* @param Attributes Bitmask of flags that specify object handle attributes. This
* member can contain one or more of the flags in the following table.
* @param SecurityDescriptor Specifies a security descriptor
* (SECURITY_DESCRIPTOR) for the object when the object is created. If this
* member is NULL, the object will receive default security settings.
* @param SecurityQualityOfService Optional quality of service to be applied to
* the object when it is created. Used to indicate the security impersonation
* level and context tracking mode (dynamic or static). Currently, the
* InitializeObjectAttributes macro sets this member to NULL.
* @see
* https://msdn.microsoft.com/en-us/library/windows/hardware/ff557749(v=vs.85).aspx
*/
typedef struct _OBJECT_ATTRIBUTES {
	ULONG Length;
	HANDLE RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG Attributes;
	PVOID SecurityDescriptor;
	PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

/**
* @brief Function pointer to ZwQueryInformationProcess
* @see
* https://msdn.microsoft.com/it-it/library/windows/desktop/ms684280(v=vs.85).aspx
*/
typedef NTSTATUS(WINAPI *PFN_ZWQUERYINFORMATIONPROCESS)(HANDLE,
	PROCESSINFOCLASS, PVOID,
	ULONG, PULONG);

/**
* @brief Retrieves information about the specified process.
* @param ProcessHandle A handle to the process for which information is to be
* retrieved.
* @param ProcessInformationClass The type of process information to be
* retrieved.
* @param ProcessInformation  A pointer to a buffer supplied by the calling
* application into which the function writes the requested information.
* @param ProcessInformationLength The size of the buffer pointed to by the
* ProcessInformation parameter, in bytes.
* @param ReturnLength A pointer to a variable in which the function returns the
* size of the requested information. If the function was successful, this is the
* size of the information written to the buffer pointed to by the
* ProcessInformation parameter, but if the buffer was too small, this is the
* minimum size of buffer needed to receive the information successfully.
* @return The function returns an NTSTATUS success or error code.
* @see
* https://msdn.microsoft.com/it-it/library/windows/desktop/ms684280(v=vs.85).aspx
*/
NTSTATUS(NTAPI *ZwQueryInformationProcess)
(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass,
	PVOID ProcessInformation, ULONG ProcessInformationLength,
	PULONG ReturnLength OPTIONAL);

/**
* @brief The ZwCreateSection routine creates a section object.
* @param SectionHandle Pointer to a HANDLE variable that receives a handle to
* the section object.
* @param DesiredAccess Specifies an ACCESS_MASK value that determines the
* requested access to the object.
* @param ObjectAttributes  Pointer to an OBJECT_ATTRIBUTES structure that
* specifies the object name and other attributes. Use InitializeObjectAttributes
* to initialize this structure. If the caller is not running in a system thread
* context, it must set the OBJ_KERNEL_HANDLE attribute when it calls
* InitializeObjectAttributes.
* @param MaximumSize Specifies the maximum size, in bytes, of the section.
* ZwCreateSection rounds this value up to the nearest multiple of PAGE_SIZE. If
* the section is backed by the paging file, MaximumSize specifies the actual
* size of the section. If the section is backed by an ordinary file, MaximumSize
* specifies the maximum size that the file can be extended or mapped to.
* @param SectionPageProtection Specifies the protection to place on each page in
* the section. Use one of the following four values: PAGE_READONLY,
* PAGE_READWRITE, PAGE_EXECUTE, or PAGE_WRITECOPY. For a description of these
* values, see CreateFileMapping.
* @param AllocationAttributes Specifies a bitmask of SEC_XXX flags that
* determines the allocation attributes of the section. For a description of
* these flags, see CreateFileMapping.
* @param FileHandle Optionally specifies a handle for an open file object. If
* the value of FileHandle is NULL, the section is backed by the paging file.
* Otherwise, the section is backed by the specified file.
* @return ZwCreateSection returns STATUS_SUCCESS on success, or the appropriate
* NTSTATUS error code on failure.
* @see
* https://msdn.microsoft.com/en-us/library/windows/hardware/ff566428(v=vs.85).aspx
*/
NTSTATUS(NTAPI *ZwCreateSection)
(_Out_ PHANDLE SectionHandle, _In_ ACCESS_MASK DesiredAccess,
	_In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
	_In_opt_ PLARGE_INTEGER MaximumSize, _In_ ULONG SectionPageProtection,
	_In_ ULONG AllocationAttributes, _In_opt_ HANDLE FileHandle);

/**
* @brief The NtMapViewOfSection routine maps a view of a section into the
virtual address space of a subject process.
* @param SectionHandle Handle to a section object. This handle is created by a
successful call to ZwCreateSection or ZwOpenSection.
* @param ProcessHandle Handle to the object that represents the process that the
view should be mapped into. Use the ZwCurrentProcess macro to specify the
current process. The handle must have been opened with PROCESS_VM_OPERATION
access (described in the Microsoft Windows SDK documentation).
* @param BaseAddress Pointer to a variable that receives the base address of the
view. If the value of this parameter is not NULL, the view is allocated starting
at the specified virtual address rounded down to the next 64-kilobyte address
boundary.
* @param ZeroBits  Specifies the number of high-order address bits that must be
zero in the base address of the section view. The value of this parameter must
be less than 21 and is used only if BaseAddress is NULL—in other words, when the
caller allows the system to determine where to allocate the view.
* @param CommitSize Specifies the size, in bytes, of the initially committed
region of the view. CommitSize is meaningful only for page-file backed sections
and is rounded up to the nearest multiple of PAGE_SIZE. (For sections that map
files, both the data and the image are committed at section-creation time.)
* @param SectionOffset A pointer to a variable that receives the offset, in
bytes, from the beginning of the section to the view. If this pointer is not
NULL, the offset is rounded down to the next allocation-granularity size
boundary.
* @param ViewSize
A pointer to a SIZE_T variable. If the initial value of this variable is zero,
ZwMapViewOfSection maps a view of the section that starts at SectionOffset and
continues to the end of the section. Otherwise, the initial value specifies the
view's size, in bytes. ZwMapViewOfSection always rounds this value up to the
nearest multiple of PAGE_SIZE before mapping the view.
On return, the value receives the actual size, in bytes, of the view.
* @param InheritDisposition Specifies how the view is to be shared with child
processes.
* @param AllocationType Specifies a set of flags that describes the type of
allocation to be performed for the specified region of pages. The valid flags
are MEM_LARGE_PAGES, MEM_RESERVE, and MEM_TOP_DOWN. Although MEM_COMMIT is not
allowed, it is implied unless MEM_RESERVE is specified. For more information
about the MEM_XXX flags, see the description of the VirtualAlloc routine.
* @param Win32Protect Specifies the type of protection for the region of
initially committed pages. Device and intermediate drivers should set this value
to PAGE_READWRITE.
* @return NtMapViewOfSection returns an NTSTATUS value.
* @see
https://msdn.microsoft.com/en-us/library/windows/hardware/ff556551(v=vs.85).aspx
* @see
https://msdn.microsoft.com/en-us/library/windows/hardware/ff566481(v=vs.85).aspx
*/
NTSTATUS(NTAPI *NtMapViewOfSection)
(_In_ HANDLE SectionHandle, _In_ HANDLE ProcessHandle,
	_Inout_ PVOID *BaseAddress, _In_ ULONG_PTR ZeroBits, _In_ SIZE_T CommitSize,
	_Inout_opt_ PLARGE_INTEGER SectionOffset, _Inout_ PSIZE_T ViewSize,
	_In_ DWORD InheritDisposition, _In_ ULONG AllocationType,
	_In_ ULONG Win32Protect);

/**
* @brief The ZwCreateThreadEx routine creates a new thread.
* @see
* https://ntquery.wordpress.com/2014/03/29/anti-debug-ntcreatethreadex/#more-11
*/
NTSTATUS(NTAPI *ZwCreateThreadEx)
(_Out_ PHANDLE ThreadHandle, _In_ ACCESS_MASK DesiredAccess,
	_In_opt_ POBJECT_ATTRIBUTES ObjectAttributes, _In_ HANDLE ProcessHandle,
	_In_ PVOID StartRoutine, _In_opt_ PVOID Argument, _In_ ULONG CreateFlags,
	_In_opt_ ULONG_PTR ZeroBits, _In_opt_ SIZE_T StackSize,
	_In_opt_ SIZE_T MaximumStackSize, _In_opt_ PVOID AttributeList);

/**
* @brief The ZwUnmapViewOfSection routine unmaps a view of a section from the
* virtual address space of a subject process.
* @param ProcessHandle Handle to a process object that was previously passed to
* ZwMapViewOfSection.
* @param BaseAddress Pointer to the base virtual address of the view to unmap.
* This value can be any virtual address within the view.
* @return ZwUnmapViewOfSection returns an NTSTATUS value.
* @see
* https://msdn.microsoft.com/it-it/library/windows/hardware/ff567119(v=vs.85).aspx
*/
NTSTATUS(NTAPI *ZwUnmapViewOfSection)
(_In_ HANDLE ProcessHandle, _In_opt_ PVOID BaseAddress);

/**
* @brief The ZwClose routine closes an object handle.
* @param Handle Handle to an object of any type.
* @return ZwClose returns STATUS_SUCCESS on success, or the appropriate NTSTATUS
* error code on failure. In particular, it returns STATUS_INVALID_HANDLE if
* Handle is not a valid handle, or STATUS_HANDLE_NOT_CLOSABLE if the calling
* thread does not have permission to close the handle.
* @see
* https://msdn.microsoft.com/en-us/library/windows/hardware/ff566417(v=vs.85).aspx
*/
NTSTATUS(NTAPI *ZwClose)(_In_ HANDLE Handle);

/**
* @brief The ZwTerminateProcess routine terminates a process and all of its
* threads.
* @param ProcessHandle A handle to the process object that represents the
* process to be terminated.
* @param An NTSTATUS value that the operating system uses as the final status
* for the process and each of its threads.
* @return ZwTerminateProcess returns STATUS_SUCCESS if the operation succeeds.
* @see
* https://msdn.microsoft.com/it-it/library/windows/hardware/ff567115(v=vs.85).aspx
*/
NTSTATUS(NTAPI *ZwTerminateProcess)
(_In_opt_ HANDLE ProcessHandle, _In_ NTSTATUS ExitStatus);

NTSTATUS(NTAPI *NtQueueApcThread)
(_In_ HANDLE ThreadHandle, _In_ PVOID ApcRoutine,
	_In_ PVOID ApcRoutineContext OPTIONAL, _In_ PVOID ApcStatusBlock OPTIONAL,
	_In_ ULONG ApcReserved OPTIONAL);

/**
* @brief The ZwSetInformationThread routine sets the priority of a thread.
* @param ThreadHandle Handle to the thread object. To create a new thread and
* get a handle to it, call PsCreateSystemThread. To specify the current thread,
* use the ZwCurrentThread macro.
* @param ThreadInformationClass One of the system-defined values in the
* THREADINFOCLASS enumeration (see ntddk.h), ThreadPriority, ThreadBasePriority,
* or ThreadPagePriority.
* @param ThreadInformation Pointer to a variable that specifies the information
* to set.
* @param ThreadInformationLength The size, in bytes, of ThreadInformation.
* @return ZwSetInformationThread returns STATUS_SUCCESS on success, or the
* appropriate NTSTATUS error code on failure. Possible error codes include
* STATUS_INFO_LENGTH_MISMATCH or STATUS_INVALID_PARAMETER.
* @see
* https://msdn.microsoft.com/en-us/library/windows/hardware/ff567101(v=vs.85).aspx
*/
NTSTATUS(NTAPI *ZwSetInformationThread)
(_In_ HANDLE ThreadHandle, _In_ THREADINFOCLASS ThreadInformationClass,
	_In_ PVOID ThreadInformation, _In_ ULONG ThreadInformationLength);

/*
* kernel32.dll API
*/
BOOL(WINAPI *CreateProcessInternalW)
(HANDLE hToken, LPCWSTR lpApplicationName, LPWSTR lpCommandLine,
	LPSECURITY_ATTRIBUTES lpProcessAttributes,
	LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles,
	DWORD dwCreationFlags, LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory,
	LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation,
	PHANDLE hNewToken);

/**
* @brief This is the shellcode which will be executed as Entry Point.
*
* It searches for the API "Fatal Application Exit" in the Export Table of kernel32 and then executes it.
* @see https://en.wikipedia.org/wiki/Shellcode
* @see SHELLCODE.md in the root of the project
*/
unsigned char shellcode[] =
"\x31\xD2\xB2\x30\x64\x8B\x12\x8B\x52\x0C\x8B\x52\x1C\x8B\x42\x08\x8B\x72\x20\x8B"
"\x12\x80\x7E\x0C\x33\x75\xF2\x89\xC7\x03\x78\x3C\x8B\x57\x78\x01\xC2\x8B\x7A\x20"
"\x01\xC7\x31\xED\x8B\x34\xAF\x01\xC6\x45\x81\x3E\x46\x61\x74\x61\x75\xF2\x81\x7E"
"\x08\x45\x78\x69\x74\x75\xE9\x8B\x7A\x24\x01\xC7\x66\x8B\x2C\x6F\x8B\x7A\x1C\x01"
"\xC7\x8B\x7C\xAF\xFC\x01\xC7\x68\x6C\x64\x21\x01\x68\x6F\x57\x6F\x72\x68\x48\x65"
"\x6C\x6C\x89\xE1\xFE\x49\x0B\x31\xC0\x51\x50\xFF\xD7";