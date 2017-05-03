/**
 * @file FullCopy.h
 * @author Giulio De Pasquale, hasherezade
 * @brief Full Shellcode Relocation
 */
#pragma once
#include <stdio.h>
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#if !NTSTATUS
typedef LONG NTSTATUS;
#endif

#define STATUS_SUCCESS 0
#define STATUS_FAILURE (-1)
#define NtCurrentProcess() ((HANDLE)-1)

typedef struct _CLIENT_ID {
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

typedef LONG NTSTATUS, *PNTSTATUS;
typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _PEB_LDR_DATA {
	ULONG Length;
	BOOLEAN Initialized;
	PVOID SsHandle;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _PEB {
	BYTE Reserved1[2];        /*  00 */
	BYTE BeingDebugged;       /*  02 */
	BYTE Reserved2[5];        /*  03 */
	HMODULE ImageBaseAddress; /*  08 */
	PPEB_LDR_DATA LdrData;    /*  0c */
	DWORD ProcessParameters;  /*  10 */
	PVOID __pad_14;           /*  14 */
	HANDLE ProcessHeap;       /*  18 */
	BYTE __pad_1c[36];        /*  1c */
	DWORD TlsBitmap;          /*  40 */
	ULONG TlsBitmapBits[2];   /*  44 */
	BYTE __pad_4c[24];        /*  4c */
	ULONG NumberOfProcessors; /*  64 */
	BYTE __pad_68[128];       /*  68 */
	PVOID Reserved3[59];      /*  e8 */
	ULONG SessionId;          /* 1d4 */
} PEB, *PPEB;

typedef struct _TEB {
	NT_TIB Tib;                         /* 000 */
	PVOID EnvironmentPointer;           /* 01c */
	CLIENT_ID ClientId;                 /* 020 */
	PVOID ActiveRpcHandle;              /* 028 */
	PVOID ThreadLocalStoragePointer;    /* 02c */
	PPEB Peb;                           /* 030 */
	ULONG LastErrorValue;               /* 034 */
	BYTE __pad038[140];                 /* 038 */
	ULONG CurrentLocale;                /* 0c4 */
	BYTE __pad0c8[1752];                /* 0c8 */
	PVOID Reserved2[278];               /* 7a0 */
	UNICODE_STRING StaticUnicodeString; /* bf8 used by advapi32 */
	WCHAR StaticUnicodeBuffer[261];     /* c00 used by advapi32 */
	PVOID DeallocationStack;            /* e0c */
	PVOID TlsSlots[64];                 /* e10 */
	LIST_ENTRY TlsLinks;                /* f10 */
	PVOID Reserved4[26];                /* f18 */
	PVOID ReservedForOle;               /* f80 Windows 2000 only */
	PVOID Reserved5[4];                 /* f84 */
	PVOID TlsExpansionSlots;            /* f94 */
} TEB, *PTEB;

typedef void(*PKNORMAL_ROUTINE)(void *NormalContext, void *SystemArgument1,
	void *SystemArgument2);

typedef struct {
	int info;
	PKNORMAL_ROUTINE fun;
} *PIO_STATUS_BLOCK;

// Make sure we print the __stdcall properly
typedef void(__stdcall *PIO_APC_ROUTINE)(void *ApcContext,
	PIO_STATUS_BLOCK IoStatusBlock,
	long Reserved);

#if !defined PROCESSINFOCLASS
typedef LONG PROCESSINFOCLASS;
#endif

#if !defined THREADINFOCLASS
typedef LONG THREADINFOCLASS;
#endif

#if !defined PPEB
typedef struct _PEB *PPEB;
#endif

#if !defined PROCESS_BASIC_INFORMATION
typedef struct _PROCESS_BASIC_INFORMATION {
	PVOID Reserved1;
	PPEB PebBaseAddress;
	PVOID Reserved2[2];
	ULONG_PTR UniqueProcessId;
	PVOID Reserved3;
} PROCESS_BASIC_INFORMATION;
#endif;

typedef struct _OBJECT_ATTRIBUTES {
	ULONG Length;
	HANDLE RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG Attributes;
	PVOID SecurityDescriptor;
	PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

NTSTATUS(NTAPI *ZwCreateSection)
(__out PHANDLE SectionHandle, __in ACCESS_MASK DesiredAccess,
	__in POBJECT_ATTRIBUTES ObjectAttributes, __in PLARGE_INTEGER MaximumSize,
	__in ULONG SectionPageProtection, __in ULONG AllocationAttributes,
	__in HANDLE FileHandle);

NTSTATUS(NTAPI *NtMapViewOfSection)
(__in HANDLE SectionHandle, __in HANDLE ProcessHandle,
	__inout PVOID *BaseAddress, __in ULONG_PTR ZeroBits, __in SIZE_T CommitSize,
	__inout PLARGE_INTEGER SectionOffset, __inout PSIZE_T ViewSize,
	__in DWORD InheritDisposition, __in ULONG AllocationType,
	__in ULONG Win32Protect);

NTSTATUS(NTAPI *ZwUnmapViewOfSection)
(__in HANDLE ProcessHandle, __in PVOID BaseAddress);

NTSTATUS(NTAPI *ZwClose)(__in HANDLE Handle);

NTSTATUS(NTAPI *ZwTerminateProcess)
(__in HANDLE ProcessHandle, __in NTSTATUS ExitStatus);

PIMAGE_NT_HEADERS(NTAPI *RtlImageNtHeader)(__in PVOID ModuleAddress);