# Overview

This method moves the whole application into another section and then proceed to apply any relocation in the *Relocation Table*.

This technique illustrates how to relocate an entire PE and how to run it using a different base address. As seen in the previous examples, copying its own code into another section and then proceeding to call the returned address will not be enough this time. This happens because the application is supposed to be loaded at a specified address and some of its code is **position-dependent** and it will not work if moved somewhere else.

Once the relocation has been realized, a test function, which pops a message box, will be manually called through its relocated address to prove the technique was successful.

# Creating a new section and moving the image in it

The current base address is retrieved through the [TEB (Thread Environment Block) structure][TEB] which contains several information about the current thread. ([source](FullCopy.cpp#L150))
```c
oldBase = NtCurrentTeb()->Peb->ImageBaseAddress;
```

The first step is to create a new section in the executable in order to relocate into it later. This is accomplished with [`ZwCreateSection()`][ZwCreateSection]. ([source](FullCopy.cpp#L163-L168))
```c
if ((status = ZwCreateSection(&hSection, SECTION_ALL_ACCESS, NULL,
  &maximumSize, PAGE_EXECUTE_READWRITE,
  SEC_COMMIT, NULL)) != STATUS_SUCCESS) {
  DBG_ERROR(("ZwCreateSection failed: 0x%x\n", status));
  return -1;
}v
```
There are several important variables being passed to [`ZwCreateSection()`][ZwCreateSection]: `&hSection`, `SECTION_ALL_ACCESS` and `PAGE_EXECUTE_READWRITE`.

* `hSection` is the section handle: it will represent our new section.

* `SECTION_ALL_ACCESS` is a bitwise flag which basically grants every permission to the section.

* `PAGE_EXECUTE_READWRITE` makes the section's memory page readable, writeable and **executable**.

The next step is to invoke [`NtMapViewOfSection()`][NtMapViewOfSection] which maps a view, a whole or partial mapping of a section object, in the virtual address space of a process. This is necessary because the section created above is not bound to any memory address of the current process and, therefore, is not possible to write into it.([source](FullCopy.cpp#L172-L178))

![MapSection]

```c
if ((status = NtMapViewOfSection(hSection, GetCurrentProcess(),
  &newBase, NULL, NULL, NULL,
  &ViewSize, dwInheritDisposition, NULL,
  PAGE_EXECUTE_READWRITE)) != STATUS_SUCCESS) {
  DBG_ERROR(("NtMapViewOfSection failed: 0x%x\n", status));
  return -1;
}
```

Now it is possible to write the whole executable into the newly created section. Basically, the image is "duplicated" into itself. ([source](FullCopy.cpp#L182))
```c
RtlCopyMemory(newBase, oldBase, imageSize);
```

# The relocation table

From the official [Microsoft PE and COFF objects specification document][MS PECOFF]:
> The base relocation table contains entries for all base relocations in the image. The Base Relocation Table field in the optional header data directories gives the number of bytes in the base relocation table. [...snip ...] The base relocation table is divided into blocks. Each block represents the base relocations for a 4K page. 

The relocation table is needed to edit every address and code that is not position independent in the binary. By moving the image into the section, the original base address of the executable will not correspond anymore. Therefore, calling the entrypoint of the moved image will result in a crash sooner or later! 

This happens because the **new** base address has to be set to the section's base. This is just one of the several addresses that need to be changed in the relocated image.

![RELOC_BLOCK]

# Relocating the binary

The relocation happens in two functions: [`ApplyRelocations()`][ApplyRelocations] and [`ApplyRelocBlock`][ApplyRelocBlock].

## `ApplyRelocations()`

This function cycles through every relocation block and calls `ApplyRelocBlocks()` to apply the transformations defined in them. The relocation table is accessed through the `NtHeaders` passed as arguments by calling `RtlImageNtHeader()`: it is placed at the fixed offset `IMAGE_DIRECTORY_ENTRY_BASERELOC` in the Data Directory array in the Optional Header ([scheme][ORCE POSTER]). ([source](FullCopy.cpp#L98))
```c
relocDir = NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
```
The main loop cycles through every relocation entry in the relocation table: ([source](FullCopy.cpp#L108-123))
```c
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
```
This is the structure that it is used to represent each **relocation entry**:
```c
typedef struct _IMAGE_BASE_RELOCATION {
  DWORD   VirtualAddress;
  DWORD   SizeOfBlock;
} IMAGE_BASE_RELOCATION, *PIMAGE_BASE_RELOCATION;
```
A relocation entry may have multiple **relocation blocks** and they are placed immediately after every **relocation entry**. The `Offset` in each block refers to the parent `VirtualAddress` and they have multiple `Type` values (they can be found in the [PE specification][MS PECOFF], section 6). A block is represented as bitfields:
```c
typedef struct _BASE_RELOCATION_ENTRY {
    WORD Offset : 12;
    WORD Type: 4;
} BASE_RELOCATION_ENTRY;
```

Each **entry starting address** is calculated from the image base address (the section one in this case), the relocation table address and an offset updated every time an entry is elaborated. The **number of relocations** for each entry is calculated by removing the fields `Page` and `SizeOfBlock` from the `SizeOfBlock` itself.
```c
reloc = (IMAGE_BASE_RELOCATION *)((uint32_t)imageBaseAddress + relTabAddr + i);
entriesNum = reloc->SizeOfBlock - sizeof(uint32_t);
```

## `ApplyRelocBlocks()`

This function **processes** every relocation defined in a block. It is important to remember that every relocation is referred to RVAs (relative virtual addresses) so, before applying an entry, it is needed to calculate the **absolute** address the relocation will affect. ([source](FullCopy.cpp#L77))
```c
newAddr = (uint32_t *)((uint32_t)newBase + page + offset);
```
Then it is simply a matter of a few calculations and the relocation is done. ([source](FullCopy.cpp#L80))
```c
*newAddr = *newAddr - (uint32_t)oldBase + (uint32_t)newBase;
```

# Running the test function

The final step is to call the relocated test function. A few calculations to get the final absolute address... ([source](FullCopy.cpp#L195-L196))
```c
testFunOffset = (uint32_t)&TestFunction - (uint32_t)oldBase;
newMain = ((ULONG_PTR)newBase + testFunOffset);
```
and it is done! ([source](FullCopy.cpp#L203-L212))
```c
int(*funPtr)();
funPtr = (int(*)())newMain;
(int)(*funPtr)();

/*
or with some inline asm like hasherezade does:
__asm {
  call newMain
}
*/
```
# Resources

* [Source](FullCopy.cpp)
* [Header](FullCopy.h)

[RELOC_BLOCK]: ../resources/RELOC_BLOCK.png?raw=true "Relocation Table Structure"
[MS PECOFF]: http://download.microsoft.com/download/9/c/5/9c5b2167-8017-4bae-9fde-d599bac8184a/pecoff_v83.docx
[ORCE POSTER]: http://www.openrce.org/reference_library/files/reference/PE%20Format.pdf
[TEB]: https://en.wikipedia.org/wiki/Win32_Thread_Information_Block
[MapSection]: ../resources/MapSection.png?raw=true

[ApplyRelocations]: FullCopy.cpp#L88-L126
[ApplyRelocBlock]: FullCopy.cpp#L56-L86

[ZwCreateSection]: https://msdn.microsoft.com/en-us/library/windows/hardware/ff566428(v=vs.85).aspx
[NtMapViewOfSection]: https://msdn.microsoft.com/en-us/library/windows/hardware/ff556551(v=vs.85).aspx