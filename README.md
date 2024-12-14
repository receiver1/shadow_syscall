# shadow syscalls

Easy to use syscall/import executor wrapper. Syscall is based on shellcode. Function names passed in arguments are hashed at compile-time.
Supports x86 architecture, but on x86 `.shadowsyscall()` is inaccessible.

The repository provides a convenient high-level wrapper over low-level operations, range-based enumerators for modules and their exports. Includes all `GetModuleHandle`, `GetProcAddress` implementations in a much nicer wrapper without leaving any strings in binary.
Allows calling undocumented DLL functions. Has a built-in forwarded import resolver (HeapAlloc, etc.)

### Supported platforms
CLANG, GCC, MSVC. Library requires cpp20.

> [!WARNING]
> This is currently in early stages of development and is not recommended for use. Examples of usage will appear here later.

## 🚀 Features

- Caching each call (it is possible to disable caching)
- Enumerate every DLL loaded to current process
- Compute checksum of the DLL section (any) in runtime
- Find exactly known DLL loaded to current process
- Enumerate EAT of module
- Resolve PE-headers and directories of module
- Compile-time string hasher
- Hash seed is pseudo-randomized, based on header file location
- Syscall executor
- Overriding syscall SSN parser
- Execute any export at runtime
- Doesn't leave any imports in the executable
- CPU instruction-set support checker & cache parser

## 📜 What is a syscall in Windows?
![syscalls](https://github.com/user-attachments/assets/1719c073-669b-4e6b-b2ec-23850ba91dbc)

## Thanks to
invers1on :heart:

https://github.com/can1357/linux-pe
