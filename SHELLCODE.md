# Introduction
This shellcode was originally written by [Giuseppe D'Amore][Giuseppe D'Amore] and I have edited it to print out "`HelloWorld!`".

It searches for the API [`Fatal Application Exit`][Fatal Application Exit] in the *Export Table* of `kernel32` and then executes it.

## Windbg
In order to carve more information about the following structures (often opaque and not well documented), I suggest you to use [Windbg][Windbg] from the Windows SDK. Its [`dt`][dt] feature will be used throughout the following explanation.

## x86 Crash Course

It is recommended to know the basics of the x86 assembly language to fully enjoy this write-up.
This [document][x86] may come in handy.

# Disassembly
```assembly
0:  31 d2                   xor    edx,edx
2:  b2 30                   mov    dl,0x30
4:  64 8b 12                mov    edx,DWORD PTR fs:[edx]
7:  8b 52 0c                mov    edx,DWORD PTR [edx+0xc]
a:  8b 52 1c                mov    edx,DWORD PTR [edx+0x1c] 
d:  8b 42 08                mov    eax,DWORD PTR [edx+0x8]
10: 8b 72 20                mov    esi,DWORD PTR [edx+0x20] 
13: 8b 12                   mov    edx,DWORD PTR [edx]
15: 80 7e 0c 33             cmp    BYTE PTR [esi+0xc],0x33
19: 75 f2                   jne    0xd
1b: 89 c7                   mov    edi,eax
1d: 03 78 3c                add    edi,DWORD PTR [eax+0x3c]
20: 8b 57 78                mov    edx,DWORD PTR [edi+0x78]
23: 01 c2                   add    edx,eax
25: 8b 7a 20                mov    edi,DWORD PTR [edx+0x20]
28: 01 c7                   add    edi,eax
2a: 31 ed                   xor    ebp,ebp
2c: 8b 34 af                mov    esi,DWORD PTR [edi+ebp*4]
2f: 01 c6                   add    esi,eax
31: 45                      inc    ebp
32: 81 3e 46 61 74 61       cmp    DWORD PTR [esi],0x61746146
38: 75 f2                   jne    0x2c
3a: 81 7e 08 45 78 69 74    cmp    DWORD PTR [esi+0x8],0x74697845
41: 75 e9                   jne    0x2c
43: 8b 7a 24                mov    edi,DWORD PTR [edx+0x24]
46: 01 c7                   add    edi,eax
48: 66 8b 2c 6f             mov    bp,WORD PTR [edi+ebp*2]
4c: 8b 7a 1c                mov    edi,DWORD PTR [edx+0x1c]
4f: 01 c7                   add    edi,eax
51: 8b 7c af fc             mov    edi,DWORD PTR [edi+ebp*4-0x4]
55: 01 c7                   add    edi,eax
57: 68 6c 64 21 01          push   0x121646c
5c: 68 6f 57 6f 72          push   0x726f576f
61: 68 48 65 6c 6c          push   0x6c6c6548
66: 89 e1                   mov    ecx,esp
68: fe 49 0b                dec    BYTE PTR [ecx+0xb]
6b: 31 c0                   xor    eax,eax
6d: 51                      push   ecx
6e: 50                      push   eax
6f: ff d7                   call   edi
```
# Explanation
Shellcodes need to be as small as possible and they subsequently resort to neat techniques to obtain system information.

Spawning the message box through the `Fatal Application Exit` WINAPI means that some steps have to be accomplished first:

1. Get the `kernel32.dll` address since `Fatal Application Exit` is exported by this DLL 
2. Get the position of `Fatal Application Exit` in the Export Table
3. Get the address of `Fatal Application Exit`
4. Call `Fatal Application Exit`

The first thing the shellcode does is to save `fs:[0x30]` into `edx`.

```assembly
 0:  31 d2                   xor    edx,edx
 2:  b2 30                   mov    dl,0x30
 4:  64 8b 12                mov    edx,DWORD PTR fs:[edx] ; edx points to PEB
``` 
This is because in the `FS` segment, under the Windows OS, reside several [thread specific information][TEB]: specifically, the structure which holds everything together is called `TEB (Thread Environment Block)`.

## TEB

```
0:000> dt ntdll!_TEB
   +0x000 NtTib            : _NT_TIB
   +0x01c EnvironmentPointer : Ptr32 Void
   +0x020 ClientId         : _CLIENT_ID
   +0x028 ActiveRpcHandle  : Ptr32 Void
   +0x02c ThreadLocalStoragePointer : Ptr32 Void
   +0x030 ProcessEnvironmentBlock : Ptr32 _PEB
   +0x034 LastErrorValue   : Uint4B
   +0x038 CountOfOwnedCriticalSections : Uint4B
   +0x03c CsrClientThread  : Ptr32 Void
[snip...]
```
It is easily observable the `TEB` contains lots of information about the running thread and it may also be useful to accomplish something else: the `TEB` comes in handy when it is needed to retrieve details of the current process without having to resort to any WINAPI.

Moving on, what is there at offset `0x30` of the `TEB`?

## PEB

```
0:000> dt ntdll!_PEB
   +0x000 InheritedAddressSpace : UChar
   +0x001 ReadImageFileExecOptions : UChar
   +0x002 BeingDebugged    : UChar
   +0x003 BitField         : UChar
   +0x003 ImageUsesLargePages : Pos 0, 1 Bit
   +0x003 IsProtectedProcess : Pos 1, 1 Bit
   +0x003 IsImageDynamicallyRelocated : Pos 2, 1 Bit
   +0x003 SkipPatchingUser32Forwarders : Pos 3, 1 Bit
   +0x003 IsPackagedProcess : Pos 4, 1 Bit
   +0x003 IsAppContainer   : Pos 5, 1 Bit
   +0x003 IsProtectedProcessLight : Pos 6, 1 Bit
   +0x003 SpareBits        : Pos 7, 1 Bit
   +0x004 Mutant           : Ptr32 Void
   +0x008 ImageBaseAddress : Ptr32 Void
   +0x00c Ldr              : Ptr32 _PEB_LDR_DATA
   +0x010 ProcessParameters : Ptr32 _RTL_USER_PROCESS_PARAMETERS
   +0x014 SubSystemData    : Ptr32 Void
   +0x018 ProcessHeap      : Ptr32 Void
   +0x01c FastPebLock      : Ptr32 _RTL_CRITICAL_SECTION
   +0x020 AtlThunkSListPtr : Ptr32 Void
[snip...]
```

It is a pointer to the `PEB` structure, another fundamental data structure. From [**scape's**][skape] paper:

> The PEB structure holds information about the process’
> heaps, binary image information, and, most importantly, three linked lists regarding
> loaded modules that have been mapped into process space.

Again, just like the `TEB`, the `PEB` holds several nice pointers: for example, the `ImageBaseAddress` at offset `0x8` and the `Ldr` at offset `0xc`. The latter is used by the shellcode to access the `_PEB_LDR_DATA` structure:

```assembly
7:  8b 52 0c                mov    edx,DWORD PTR [edx+0xc] ; edx points to Ldr
```

This is how it is composed:

```
0:000> dt ntdll!_PEB_LDR_DATA
   +0x000 Length           : Uint4B
   +0x004 Initialized      : UChar
   +0x008 SsHandle         : Ptr32 Void
   +0x00c InLoadOrderModuleList : _LIST_ENTRY
   +0x014 InMemoryOrderModuleList : _LIST_ENTRY
   +0x01c InInitializationOrderModuleList : _LIST_ENTRY
   +0x024 EntryInProgress  : Ptr32 Void
   +0x028 ShutdownInProgress : UChar
   +0x02c ShutdownThreadId : Ptr32 Void

```

There are [**three doubly-linked lists (LIST_ENTRY)**][LIST_ENTRY] which represent every module, such as a library, loaded by the process in that very moment.
* `InLoadOrderModuleList`: built following the order in which the modules are loaded
* `InMemoryOrderModuleList`:  built following the order in which the modules are present in memory
* `InInitializationOrderModuleList`: built following the order in which the modules are initialized



## Searching for  `kernel32.dll`

Here the shellcode accesses to the head of the `InInitializationOrderModuleList` which points to a `LDR_DATA_TABLE_ENTRY` according to the [MSDN][LDR_DATA_TABLE_ENTRY].

It has to be noted that there is a [**one to one correspondence**][CONTAINING_MACRO] between the `_LIST_ENTRY` fields of the two structures: the `InInitializationOrderModuleList` points to the `InInitializationOrderLinks` entry of the `_LDR_DATA_TABLE_ENTRY` structure at offset 0.

![CONTAINING_RECORD]

```
0:000> dt ntdll!_LDR_DATA_TABLE_ENTRY
   +0x000 InLoadOrderLinks : _LIST_ENTRY
   +0x008 InMemoryOrderLinks : _LIST_ENTRY
   +0x010 InInitializationOrderLinks : _LIST_ENTRY
   +0x010 InProgressLinks  : _LIST_ENTRY
   +0x018 DllBase          : Ptr32 Void
   +0x01c EntryPoint       : Ptr32 Void
   +0x020 SizeOfImage      : Uint4B
   +0x024 FullDllName      : _UNICODE_STRING
   +0x02c BaseDllName      : _UNICODE_STRING
   +0x034 FlagGroup        : [4] UChar
   +0x034 Flags            : Uint4B
   +0x034 PackagedBinary   : Pos 0, 1 Bit
   +0x034 MarkedForRemoval : Pos 1, 1 Bit
   +0x034 ImageDll         : Pos 2, 1 Bit
   +0x034 LoadNotificationsSent : Pos 3, 1 Bit
   +0x034 TelemetryEntryProcessed : Pos 4, 1 Bit
   +0x034 ProcessStaticImport : Pos 5, 1 Bit
   +0x034 InLegacyLists    : Pos 6, 1 Bit
   +0x034 InIndexes        : Pos 7, 1 Bit
   +0x034 ShimDll          : Pos 8, 1 Bit
   +0x034 InExceptionTable : Pos 9, 1 Bit
   +0x034 ReservedFlags1   : Pos 10, 2 Bits
[snip...]
```

The next thing the shellcode does is to iterate over the list in order to check every module's `BaseDllName` buffer:
```assembly
  a:  8b 52 1c                mov    edx,DWORD PTR [edx+0x1c] ; Load InInitializationOrderModuleList next object
->d:  8b 42 08                mov    eax,DWORD PTR [edx+0x8]  ; eax = DllBase
| 10: 8b 72 20                mov    esi,DWORD PTR [edx+0x20] ; esi = BaseDllName.Buffer
| 13: 8b 12                   mov    edx,DWORD PTR [edx]      ; edx points to the next object
| 15: 80 7e 0c 33             cmp    BYTE PTR [esi+0xc],0x33  ; FullDllName.Buffer[0xC] == "3"
|-19: 75 f2                   jne    0xd
```

`edx` is used as buffer to hold the current list position, `eax` holds the `.dll` address base which will be loaded later and `esi` points to the start of the name of the `.dll`. Note that the `_UNICODE_STRING` type is not directly a buffer:

```
0:000> dt ntdll!_UNICODE_STRING
   +0x000 Length           : Uint2B
   +0x002 MaximumLength    : Uint2B
   +0x004 Buffer           : Ptr32 Uint2B
```

When a `"3"` is found at position `0xC` or `12` it means the base address of `kernel32.dll` has been successfully recovered. A little thing has to be noted here, though: the character `"3"` is not located at position `6` because the string is stored in memory with spaces between each letter.
```
0|1|2|3|4|5|6|7|8|9|a|b|c|d|e|f|.|.|.|.|.|.|.|
k| |e| |r| |n| |e| |l| |3| |2| |.| |d| |l| |l|
```

## The Export Directory Table

In the next paragraph, [this image][WM PESTRUCT] will significantly help to keep the orientation in `kernel32.dll`. It is also suggested to read the official [Microsoft PE and COFF objects specification document][MS PECOFF]. 

The interesting offsets to keep an eye on are the following:
* `0x3c` : PE Header
* `0x78` : Relative Virtual Address (RVA) of the Export Directory Table

The **Export Directory Table** plays a central role in determining the `Fatal Application Exit` address. From Microsoft's specification document it is described that:
> The export symbol information begins with the export directory table, which describes the remainder of the export symbol information. The export directory table contains address information that is used to resolve imports to the entry points within this image.

The [*Export Directory Table* composition][ORCE POSTER] is as follows:
```
typedef struct _IMAGE_EXPORT_DIRECTORY {
    DWORD Characteristics;       // 0x0
    DWORD TimeDateStamp;         // 0x4
    WORD MajorVersion;           // 0x8
    WORD MinorVersion;           // 0xA
    DWORD Name;                  // 0xC
    DWORD Base;                  // 0x10
    DWORD NumberOfFunctions;     // 0x14
    DWORD NumberOfNames;         // 0x18
    DWORD AddressOfFunctions;    // 0x1C - Export Address Table
    DWORD AddressOfNames;        // 0x20
    DWORD AddressOfNameOrdinals; // 0x24
}
```

In the *Export Directory Table*, located at offset `0x78` from the start of the `.dll`, there is the **Export Address Table** which, from the specification document:
> contains the address of exported entry points and exported data and absolutes. An ordinal number is used as an index into the export address table.

The ordinal of `Fatal Application Exit` is calculated by finding the offset of the `WINAPI` name in the `AddressOfNames` array of the *Export Directory Table*. Once the ordinal is found, it will be used to retrieve the entrypoint of `Fatal Application Exit` by reading the corresponding entry in the `AddressOfFunctions` array which represents the **Export Address Table**. 

Let's recap the steps:
1. Access the Export **Directory** Table
2. Calculate the ordinal of `Fatal Application Exit`
3. Access the Export **Address** Table with the newfound ordinal
4. Call `Fatal Application Exit`

Steps 1 and 2 are executed below:
```assembly
                                                                      ; eax = Kernel32 base address
    1b: 89 c7                   mov    edi,eax                        ; edi = Kernel32 base address
    1d: 03 78 3c                add    edi,DWORD PTR [eax+0x3c]       ; Moving edi forward to the start of the PE Header
    20: 8b 57 78                mov    edx,DWORD PTR [edi+0x78]       ; edx = rva of the Export Directory
    23: 01 c2                   add    edx,eax                        ; edx = absolute address of the Export Directory
    25: 8b 7a 20                mov    edi,DWORD PTR [edx+0x20]       ; edi = rva of names array
    28: 01 c7                   add    edi,eax                        ; edi = absolute address of names' array
    2a: 31 ed                   xor    ebp,ebp                        ; ebp = index of Fatal Application Exit
  ->2c: 8b 34 af                mov    esi,DWORD PTR [edi+ebp*4]      ;
  | 2f: 01 c6                   add    esi,eax                        ;
  | 31: 45                      inc    ebp                            ; i++
  | 32: 81 3e 46 61 74 61       cmp    DWORD PTR [esi],0x61746146     ; Fata
  |-38: 75 f2                   jne    0x2c
  | 3a: 81 7e 08 45 78 69 74    cmp    DWORD PTR [esi+0x8],0x74697845 ; Exit
  |-41: 75 e9                   jne    0x2c
```

## Showing the message box

Now that the ordinal for `FatalAppExit` is known, it is used to retrieve the absolute address of the `WINAPI` which can be found at position `#ordinal` in the `AddressOfFunctions` in the *Export Table*.

As final step, the `HelloWorld!` message is pushed onto the stack and `FatalAppExit` called!

```assembly
                                                                  ; edx = absolute address of the Export Directory
                                                                  ; ebp = index of 
43: 8b 7a 24                mov    edi,DWORD PTR [edx+0x24]       ; edi = rva of ordinals' array
46: 01 c7                   add    edi,eax                        ; edi = absolute address of ordinals' array
48: 66 8b 2c 6f             mov    bp,WORD PTR [edi+ebp*2]        ; bp = ordinal of Fatal Application Exit 
4c: 8b 7a 1c                mov    edi,DWORD PTR [edx+0x1c]       ; edi = rva of functions' addresses array
4f: 01 c7                   add    edi,eax                        ; edi = absolute address of functions' addresses array
51: 8b 7c af fc             mov    edi,DWORD PTR [edi+ebp*4-0x4]  ; edi = rva of Fatal Application Exit
55: 01 c7                   add    edi,eax                        ; edi = absolute value of Fatal Application Exit
57: 68 6c 64 21 01          push   0x121646c                      ; 
5c: 68 6f 57 6f 72          push   0x726f576f                     ; HelloWorld!
61: 68 48 65 6c 6c          push   0x6c6c6548                     ; 
66: 89 e1                   mov    ecx,esp                        ; ecx points to our message
68: fe 49 0b                dec    BYTE PTR [ecx+0xb]             ; making last char == 0x00
6b: 31 c0                   xor    eax,eax                        ; 
6d: 51                      push   ecx                            ; pushing lpMessageText
6e: 50                      push   eax                            ; pushing uAction
6f: ff d7                   call   edi                            ; WIN!
```

[Giuseppe D'Amore]: http://it.linkedin.com/pub/giuseppe-d-amore/69/37/66b
[Windbg]: https://msdn.microsoft.com/en-us/library/windows/hardware/ff551063(v=vs.85).aspx
[dt]: https://msdn.microsoft.com/en-us/library/windows/hardware/ff542772(v=vs.85).aspx
[x86]: resources/x86-crash-course.pdf
[TEB]: https://en.wikipedia.org/wiki/Win32_Thread_Information_Block
[skape]: http://www.hick.org/code/skape/papers/win32-shellcode.pdf
[LIST_ENTRY]: https://msdn.microsoft.com/en-us/library/windows/hardware/ff554296(v=vs.85).aspx
[LDR_DATA_TABLE_ENTRY]: https://msdn.microsoft.com/en-us/library/windows/desktop/aa813708%28v=vs.85%29.aspx
[CONTAINING_MACRO]: https://msdn.microsoft.com/en-us/library/windows/hardware/ff542043(v=vs.85).aspx
[CONTAINING_RECORD]: resources/CONTAINING_RECORD.png?raw=true
[WM PESTRUCT]: https://upload.wikimedia.org/wikipedia/commons/7/70/Portable_Executable_32_bit_Structure_in_SVG.svg
[MS PECOFF]: http://download.microsoft.com/download/9/c/5/9c5b2167-8017-4bae-9fde-d599bac8184a/pecoff_v83.docx
[ORCE POSTER]: http://www.openrce.org/reference_library/files/reference/PE%20Format.pdf

[Fatal Application Exit]: https://msdn.microsoft.com/en-us/library/windows/desktop/ms679336(v=vs.85).aspx