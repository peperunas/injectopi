/**
 * @file CreatePatched.h
 * @author Giulio De Pasquale, hasherezade
 * @brief Entrypoint Patching
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

typedef LONG NTSTATUS, *PNTSTATUS;

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
NTSTATUS(__stdcall *ZwQueryInformationProcess)
(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass,
 PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength);

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