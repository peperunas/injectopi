# What is this?
Injectopi is a set of tutorials that I've decided to write down in order to learn about various injection techniques in the Windows' environment. The idea came to my mind when I noticed these awesome [sources by Hasherezade][Hasherezade demo].

# Why "Injectopi"?
Here is what I thought:
> "Is there anything better than a mighty animal with multiple arms swinging poisonous pointy weapons?"

# Getting Started
This tutorial shows how you can create a program that, when run, will inject code into an existing process.
We will show multiple techniques of increasing complexity discovered by security researchers and malware coders.
It has to be noted that these list is **not** complete as it only shows the main techniques!

# Techniques overview
| Name | Description  | Main WINAPI |
|------------------|------------------------------------------------------------------------------------------|-------------|
| CreatePatched | Spawns a benign process with its Entrypoint patched with a shellcode | [`CreateProcess`][CreateProcess], [`VirtualProtectEx`][VirtualProtectEx], [`ReadProcessMemory`][ReadProcessMemory] | 
| CreateSection | Creates a new executable section, containing a shellcode, in an existing process | [`CreateProcess`][CreateProcess], [`ZwCreateSection`][ZwCreateSection], [`NtMapViewOfSection`][NtMapViewOfSection], `ZwCreateThreadEx` | 
| CreateSectionAPC | Same as CreateSection: this time asynchronous procedure calls will be used.  | [`CreateProcess`][CreateProcess], [`ZwCreateSection`][ZwCreateSection], [`NtMapViewOfSection`][NtMapViewOfSection], `NtQueueApcThread` | 
| FullCopy | Allocates an executable memory region in an existing process and copies itself in that region  | [`ZwCreateSection`][ZwCreateSection], [`NtMapViewOfSection`][NtMapViewOfSection] | 

# Requisites
If you want to compile each binary it is suggested to use:
 
* Visual Studio 2017 (Community will suffice)
* Windows 7+

# Building
Just open `Injectopi.sln` with Visual Studio!

## Visual Studio 2017
Make sure to have the `Desktop C++ x86 and x64` components enabled with your Visual Studio installation!

You should be ready to go!

# What are you running with that shellcode?
I have commented what the shellcode does in the file [`SHELLCODE.md`](SHELLCODE.md).

# Further reading
Here below you can find a list of interesting articles / websites / papers which I found useful while writing down Injectopi!

## ReactOS
From their website:
> Imagine running your favorite Windows applications and drivers in an open-source environment you can trust. That's ReactOS. Not just an Open but also a Free operating system.

ReactOS is an awesome project which aims at open-sourcing the Windows OS by reverse engineering it. 
The documentation you find on their website is pure gold.

* [Take me there!][ReactOS]

## Windows shellcoding
**skape's "Understanding Windows Shellcode" paper** is a great resource that will surely help you understand how Windows' internals work and how to use them to write shellcode.

***The shellcode I use in these examples uses some techniques shown in the paper!***

* [I can't wait to read it!][skape]
# Contributions

Any contribution is **very** welcome! Feel free to open issues and pull requests!

# Credits

This project idea was born thanks to [Hasherezade][Hasherezade]'s demo repository and the constant support of my instructor [Federico Maggi](mailto:federico@maggi.cc).

Special thanks to my friends [Francesco][Francesco] and [Giancarlo][Giancarlo] that helped me review everything!


# License
```
Copyright 2017 Giulio De Pasquale

Permission is hereby granted, free of charge, to any person obtaining a copy of this 
software and associated documentation files (the "Software"), to deal in the Software 
without restriction, including without limitation the rights to use, copy, modify, merge, 
publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons 
to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or 
substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, 
INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR 
PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE 
FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR 
OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER 
DEALINGS IN THE SOFTWARE.
```
[Hasherezade]: https://github.com/hasherezade
[Hasherezade demo]: https://github.com/hasherezade/demos
[ReactOS]: https://doxygen.reactos.org/index.html
[skape]: http://www.hick.org/code/skape/papers/win32-shellcode.pdf
[Francesco]: https://github.com/francescorinaldi
[Giancarlo]: https://github.com/giancarlocolaci

[CreateProcess]: https://msdn.microsoft.com/en-us/library/windows/desktop/ms682425(v=vs.85).aspx
[ReadProcessMemory]: https://msdn.microsoft.com/en-us/library/windows/desktop/ms680553(v=vs.85).aspx
[VirtualProtectEx]: https://msdn.microsoft.com/en-us/library/windows/desktop/aa366899(v=vs.85).aspx
[ZwCreateSection]: https://msdn.microsoft.com/en-us/library/windows/hardware/ff566428(v=vs.85).aspx
[NtMapViewOfSection]: https://msdn.microsoft.com/en-us/library/windows/hardware/ff556551(v=vs.85).aspx