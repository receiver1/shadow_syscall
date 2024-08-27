# shadow syscalls

Easy to use syscall/lazy import wrapper. Syscall is based on shellcode. Function names are hashed, library doesn't leave any strings or imports.
Supports x86 architecture, but on x86 `.shadowsyscall()` is inaccessible.

Allows calling undocumented DLL functions. Allows to call forwarded imports (HeapAlloc, etc.)

### Supported platforms
CLANG, GCC, MSVC. Library requires cpp20

### Quick example
```cpp
// Execute syscall
shadowsyscall<NTSTATUS>( "NtTerminateProcess", reinterpret_cast< HANDLE >( -1 ), -6932 );

// Execute any export at runtime
shadowcall<int>( "MessageBoxA", nullptr, "string 1", "string 2", MB_OK );
```

> [!IMPORTANT]\
> Make sure you load the dll module that contains the export you want to call. For example - to call MessageBoxA, you need to load "user32.dll" into the current process.

Shellcode uses ```NtAllocateVirtualMemory | NtFreeVirtualMemory```, functions to allocate/free memory.

## Detailed example
```cpp
int main()
{
    shadowcall<int>( "LoadLibraryA", "user32.dll" );

    // Enumerate every module loaded to current process
    for ( const auto& module : shadow::c_modules_range{} )
        std::wcout << module->name.to_wstring() << "\n";

    // Find exactly known module loaded to current process
    // "ntdll.dll" doesn't leave string in executable, it
    // being hashed on compile-time with consteval guarantee
    auto module = shadow::c_module{ "ntdll.dll" };
    auto exports = shadow::c_exports{ module };

    // Enumerate EAT of `module`
    for ( const auto& [export_name, export_address] : exports )
        std::cout << export_name << " : " << export_address << "\n";

    std::string_view target_export_name = "RtlTimeToTimeFields";

    // Find export in EAT with user-defined predicate
    auto it = exports.find_if( [target_export_name]( const auto& pair ) -> bool {
        const auto& [name, address] = pair;
        return name == target_export_name;
    } );

    if ( it != exports.end() ) {
        const auto& [name, address] = *it;
        std::cout << "Target export found: " << name << " : " << address << '\n';
    }
    else {
        std::cout << "Failed to find target export.\n";
    }

    // Enumerate sections of `module`
    for ( const auto& section : module.image()->get_nt_headers()->sections() )
        std::cout << section.name.to_string() << '\n';

    // Execute any export at runtime
    shadowcall<int>( "MessageBoxA", nullptr, "string 1", "string 2", MB_OK );

    shadowcall<int>( { "MessageBoxA", "user32.dll" }, nullptr, "string 1", "string 2", MB_OK );

    // We need to call actually `MessageBoxA`, but not just MessageBox,
    // because the MessageBox is just a #define from WinAPI
    // the actual export is MessageBoxA / MessageBoxW.
    // MessageBoxA( nullptr, "string 1", "string 2", MB_OK );

    HANDLE process = reinterpret_cast< HANDLE >( -1 );

    auto start_routine = []( void* ) -> DWORD {
        std::cout << "thread started!\n";
        return 0;
    };

    auto status = shadowsyscall<NTSTATUS>(
        "NtCreateThreadEx",
        &process,
        THREAD_ALL_ACCESS,
        NULL,
        process,
        static_cast< LPTHREAD_START_ROUTINE >( start_routine ),
        0,
        FALSE,
        NULL, // from v1.1 nullptr can be replaced with `0`
        NULL,
        NULL,
        0
    );

    std::cout << "NtCreateThreadEx call status: 0x" << std::hex << status << '\n';

    // Find an export address
    auto export_address = shadow::c_export{ "NtTerminateProcess" };

    std::cout << "NtTerminateProcess address: 0x" << std::hex << export_address << "\n";
    std::cout << "NtTerminateProcess address: " << export_address.to_pointer() << "\n";

    shadowsyscall<NTSTATUS>( "NtTerminateProcess", reinterpret_cast< HANDLE >( -1 ), -6932 );

    return 0;
}
```

## 🚀 Features

- Caching each call.
- Exception-safe code.
- Enumerate every module loaded to current process.
- Find exactly known module loaded to current process.
- Enumerate EAT of module.
- Resolve PE-headers and directories of module.
- Compile-time hashing export.
- Hash seed is pseudo-randomized, based on header file location
- Execute syscall.
- Execute any export at runtime.
- Doesn't leave any imports in the executable.
- Find an export address

## 📜 What's a syscall?
![syscall_architecture](https://github.com/annihilatorq/shadow_syscall/assets/143023834/63f46089-a590-4c6b-aa60-447b536ece34)

# 🧪 Assembly output (MSVC, x64)

## IDA64 Pseudocode - shadowcall
```c
struct _PEB *sub_1400012D0()
{
  struct _PEB *result; // rax
  PVOID *v1; // rsi
  PVOID *v2; // rbx
  __int64 (__fastcall *v3)(_QWORD, const char *, const char *, _QWORD, _QWORD); // rdi
  char *v4; // rcx
  __int64 v5; // rdx
  __int128 v6; // [rsp+20h] [rbp-48h] BYREF
  __m128i v7[2]; // [rsp+30h] [rbp-38h] BYREF
  __int64 (__fastcall *v8)(_QWORD, const char *, const char *, _QWORD, _QWORD); // [rsp+50h] [rbp-18h]

  result = NtCurrentPeb();
  v1 = &result->Ldr->Reserved2[1];
  v2 = *(PVOID **)*v1;
  v3 = 0i64;
  if ( v2 != v1 )
  {
    while ( 1 )
    {
      v6 = 0i64;
      v4 = (char *)v2[6];
      v6 = (unsigned __int64)v4;
      v5 = *(_QWORD *)&v4[*((unsigned int *)v4 + 15) + 136];
      if ( HIDWORD(v5) )
        *((_QWORD *)&v6 + 1) = &v4[(unsigned int)v5];
      v7[0] = 0i64;
      v7[1] = 0i64;
      v8 = 0i64;
      sub_140001000((__int64 *)&v6, v7, -1722595609);
      result = (struct _PEB *)*((_QWORD *)&v6 + 1);
      if ( v7[0].m128i_i64[1] != *(_DWORD *)(*((_QWORD *)&v6 + 1) + 24i64) )
        break;
      v2 = (PVOID *)*v2;
      if ( v2 == v1 )
        goto LABEL_8;
    }
    v3 = v8;
  }
LABEL_8:
  if ( v3 )
    result = (struct _PEB *)v3(0i64, "string 1", "string 2", 0i64, v6);
  return result;
}


__m128i *__fastcall sub_140001000(__int64 *a1, __m128i *a2, int a3)
{
  _QWORD *v5; // r9
  unsigned __int64 v6; // r11
  __int64 v7; // rcx
  __int64 v8; // r10
  __m128i v9; // xmm0
  _DWORD *v10; // r14
  __int64 v11; // rsi
  __m128i v12; // xmm1
  __int64 v13; // rax
  __int64 v14; // r10
  __int64 v15; // r11
  __int64 v16; // rcx
  __int64 v17; // rcx
  unsigned __int64 v18; // r11
  int v19; // ebx
  unsigned __int64 v20; // xmm0_8
  char v21; // r9
  char v22; // cl
  int v23; // edx
  int v24; // ecx
  int v25; // er9
  __int64 v26; // r11
  __int64 v27; // rcx
  __int64 v28; // rcx
  __m128i v30; // [rsp+0h] [rbp-78h]
  __m128i v31; // [rsp+0h] [rbp-78h]
  __m128i v32; // [rsp+10h] [rbp-68h]
  __m128i v33; // [rsp+10h] [rbp-68h]
  __m128i v34; // [rsp+20h] [rbp-58h]
  __int64 v35; // [rsp+40h] [rbp-38h]

  if ( a3 )
  {
    v10 = (_DWORD *)a1[1];
    v11 = 0i64;
    v34 = (__m128i)(unsigned __int64)a1;
    v12 = 0i64;
    v13 = 0i64;
    v35 = 0i64;
    v14 = -1i64;
    if ( v10[6] )
    {
      v15 = *a1;
      v13 = -1i64;
      v16 = *a1 + *(unsigned int *)((unsigned int)v10[8] + *a1);
      v31.m128i_i64[0] = v16;
      do
        ++v13;
      while ( *(_BYTE *)(v16 + v13) );
      v31.m128i_i64[1] = v13;
      v12 = v31;
      v35 = v15
          + *(unsigned int *)(v15 + (unsigned int)v10[7] + 4i64 * *(unsigned __int16 *)((unsigned int)v10[9] + v15));
    }
    v17 = (unsigned int)v10[6];
    while ( v11 != v17 )
    {
      v18 = 0i64;
      v19 = 42700073;
      if ( v13 )
      {
        v20 = _mm_srli_si128(v12, 8).m128i_u64[0];
        do
        {
          v21 = *(_BYTE *)(v12.m128i_i64[0] + v18);
          v22 = v21 + 32;
          if ( (unsigned __int8)(v21 - 65) > 0x19u )
            v22 = *(_BYTE *)(v12.m128i_i64[0] + v18);
          v23 = v22;
          v24 = 143730706 * (v22 + (_DWORD)v18);
          v25 = v23 * (v18 - 830768914) - 830768915 * v19 - 830914342 * v18 + 3675271;
          ++v18;
          v19 += v24 ^ v25;
        }
        while ( v18 < v20 );
      }
      if ( a3 == v19 )
      {
        *a2 = v34;
        a2[1] = v12;
        a2[2].m128i_i64[0] = v35;
        return a2;
      }
      v26 = *a1;
      v13 = -1i64;
      do
        ++v13;
      while ( *(_BYTE *)(*a1 + *(unsigned int *)(*a1 + (unsigned int)v10[8] + 4 * v11) + v13) );
      v32.m128i_i64[1] = v13;
      v32.m128i_i64[0] = *a1 + *(unsigned int *)(*a1 + (unsigned int)v10[8] + 4 * v11);
      v12 = v32;
      v27 = *(unsigned int *)(v26
                            + (unsigned int)v10[7]
                            + 4i64 * *(unsigned __int16 *)(v26 + (unsigned int)v10[9] + 2 * v11++));
      v35 = v26 + v27;
      v17 = (unsigned int)v10[6];
      v34.m128i_i64[1] = v11;
    }
    a2->m128i_i64[0] = (__int64)a1;
    a2->m128i_i64[1] = v17;
    a2[1].m128i_i64[0] = 0i64;
    a2[1].m128i_i64[1] = 0i64;
    a2[2].m128i_i64[0] = 0i64;
    v5 = (_QWORD *)a2->m128i_i64[0];
    v6 = a2->m128i_u64[1];
    v28 = *(_QWORD *)(a2->m128i_i64[0] + 8);
    if ( v6 < *(unsigned int *)(v28 + 24) )
    {
      do
        ++v14;
      while ( *(_BYTE *)(*v5 + *(unsigned int *)(*v5 + *(unsigned int *)(v28 + 32) + 4 * v6) + v14) );
      v33.m128i_i64[1] = v14;
      v33.m128i_i64[0] = *v5 + *(unsigned int *)(*v5 + *(unsigned int *)(v28 + 32) + 4 * v6);
      v9 = v33;
      goto LABEL_25;
    }
  }
  else
  {
    a2->m128i_i64[1] = *(unsigned int *)(a1[1] + 24);
    a2->m128i_i64[0] = (__int64)a1;
    a2[1] = 0ui64;
    a2[2].m128i_i64[0] = 0i64;
    v5 = (_QWORD *)a2->m128i_i64[0];
    v6 = a2->m128i_u64[1];
    v7 = *(_QWORD *)(a2->m128i_i64[0] + 8);
    if ( v6 < *(unsigned int *)(v7 + 24) )
    {
      v8 = -1i64;
      do
        ++v8;
      while ( *(_BYTE *)(*v5 + *(unsigned int *)(*v5 + *(unsigned int *)(v7 + 32) + 4 * v6) + v8) );
      v30.m128i_i64[1] = v8;
      v30.m128i_i64[0] = *v5 + *(unsigned int *)(*v5 + *(unsigned int *)(v7 + 32) + 4 * v6);
      v9 = v30;
LABEL_25:
      a2[1] = v9;
      a2[2].m128i_i64[0] = *v5
                         + *(unsigned int *)(*v5
                                           + *(unsigned int *)(v5[1] + 28i64)
                                           + 4i64
                                           * *(unsigned __int16 *)(*v5 + *(unsigned int *)(v5[1] + 36i64) + 2 * v6));
      return a2;
    }
  }
  return a2;
}
```

## IDA64 Pseudocode - shadowsyscall
```c
__int64 sub_1400013C0()
{
  void (__fastcall *v0)(__int64, __int64); // rdi
  __int64 (__fastcall *v1)(__int64, __int64 *, _QWORD, __int64 *, int, int); // rbx
  int v2; // eax
  __int64 v3; // rdx
  __int64 v5; // [rsp+30h] [rbp-40h] BYREF
  int v6; // [rsp+38h] [rbp-38h]
  char v7[12]; // [rsp+3Ch] [rbp-34h] BYREF
  __int64 v8; // [rsp+48h] [rbp-28h]
  _BYTE v9[13]; // [rsp+50h] [rbp-20h]
  char v10; // [rsp+5Dh] [rbp-13h]
  __int16 v11; // [rsp+5Eh] [rbp-12h]
  __int64 v12; // [rsp+60h] [rbp-10h] BYREF

  v0 = 0i64;
  *(_DWORD *)v7 = 0;
  *(_DWORD *)v9 = -896972544;
  v11 = 0;
  v6 = -1400949656;
  *(_QWORD *)&v7[4] = 0i64;
  *(_WORD *)&v9[4] = -14520;
  v9[6] = -64;
  *(_WORD *)&v9[11] = 1295;
  v10 = -61;
  v1 = (__int64 (__fastcall *)(__int64, __int64 *, _QWORD, __int64 *, int, int))sub_1400012C0(0xDAB74943);// find NtAllocateVirtualMemory
  qword_140005670 = (__int64)v1;
  qword_140005668 = sub_1400012C0(0x4344A267u); // find NtFreeVirtualMemory
  *(_QWORD *)v7 = *(unsigned int *)(sub_1400012C0(0xAC7F3468) + 4);// find NtTerminateProcess, extract syscall index
  *(_DWORD *)&v9[7] = *(_DWORD *)v7;
  v5 = 0i64;
  v12 = 13i64;
  v2 = v1(-1i64, &v5, 0i64, &v12, 12288, 64);
  v3 = 0i64;
  if ( v2 >= 0 )
    v3 = v5;
  v8 = v3;
  if ( v3 )
  {
    *(_QWORD *)v3 = *(_QWORD *)&v9[1];
    *(_DWORD *)(v3 + 8) = *(_DWORD *)&v9[9];
    *(_BYTE *)(v3 + 12) = -61;
    v0 = (void (__fastcall *)(__int64, __int64))v3;
    *(_QWORD *)&v7[4] = v3;
  }
  v0(-1i64, 777i64);
  return sub_140001500(&v7[4]);
}
```

## Thanks to
invers1on :heart:

https://github.com/can1357/linux-pe
