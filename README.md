# shadow syscalls

Easy to use syscall/import executor wrapper. Syscall is based on shellcode. Function names passed in arguments are hashed at compile-time.
Supports x86 architecture, but on x86 `.shadowsyscall()` is inaccessible.

The repository provides a convenient high-level wrapper over low-level operations, range-based enumerators for modules and their exports. Includes all `GetModuleHandle`, `GetProcAddress` implementations in a much nicer wrapper without leaving any strings in binary.
Allows calling undocumented DLL functions. Has a built-in import resolver (for HeapAlloc, etc.)

### Supported platforms
CLANG, GCC, MSVC. Library requires cpp20.

### Quick example
```cpp
// Execute "NtTerminateProcess" syscall
shadowsyscall<NTSTATUS>( "NtTerminateProcess", reinterpret_cast< HANDLE >( -1 ), -6932 );

// Since version 1.2, the return type may not be specified
shadowsyscall( "NtTerminateProcess", reinterpret_cast< HANDLE >( -1 ), -6932 );

// Execute any export at runtime
// Since version 1.2, the return type may not be specified
shadowcall<int>( "MessageBoxA", nullptr, "string 1", "string 2", MB_OK );
```

> [!IMPORTANT]\
> Make sure you load the dll module that contains the export you want to call. For example - to call MessageBoxA, you need to load "user32.dll" into the current process.

Shellcode uses allocator based on `NtAllocateVirtualMemory` & `NtFreeVirtualMemory`

## Detailed executors example
```cpp
// If “set_custom_ssn_parser” was called, the handling
// of the syscall index falls entirely on the user.
//
// This function is gonna be called once if caching is enabled.
// If not, function will be called on every syscall
std::optional<uint32_t> custom_ssn_parser( shadow::syscaller<NTSTATUS>& instance, shadow::address_t export_address ) {
    if ( !export_address ) {
        instance.set_last_error( shadow::errc::ssn_not_found );
        return std::nullopt;
    }
    return *export_address.ptr<std::uint32_t>( 4 );
}

// Pass the function name as a string, it will be converted
// into a number at the compile-time by the hash64_t ctor
void execute_syscall_with_custom_ssn( shadow::hash64_t function_name ) {
    shadow::syscaller<NTSTATUS> sc{ function_name };
    sc.set_custom_ssn_parser( custom_ssn_parser );

    auto current_process = reinterpret_cast<void*>( -1 );
    std::uint32_t debug_port{ 0 };
    auto [status, err] = sc( current_process, 7, &debug_port, sizeof( uint64_t ), nullptr );
    if ( err )
        std::cerr << "Syscall error occured: " << *err << '\n';

    std::cout << "NtQueryInformationProcess status: " << status << ", debug port is: " << debug_port << "\n";
}

int main() {
    execute_syscall_with_custom_ssn( "NtQueryInformationProcess" );

    // Return type may not be specified since v1.2
    shadowcall( "LoadLibraryA", "user32.dll" );

    // When we know where to look for a specified
    // export it is better to specify it right away,
    // it will speed up the search.
    shadowcall( { "MessageBoxA", "user32.dll" }, nullptr, "string 1", "string 2", MB_OK );

    // Execute any export at runtime. Since we have ct constructor -
    // every string will be converted to uint64_t during compilation time
    auto message_box = shadowcall<int>( "MessageBoxA", nullptr, "string 3", "string 4", MB_OK );

    // "message_box" variable is treated same as "int"
    auto function_result = message_box;
    std::wcout << "Result: " << function_result << ", DLL that contains MessageBoxA is: " << message_box.export_location().filepath() << '\n';

    auto process = reinterpret_cast<HANDLE>( -1 );
    const auto current_process = reinterpret_cast<HANDLE>( -1 );
    auto start_routine = []( void* ) -> DWORD {
        std::cout << "\nthread started!\n";
        return 0;
    };

    // 1 variant - handle error by return value
    // Return type may not be specified since v1.2
    auto [status, error] = shadowsyscall( "NtCreateThreadEx", &process, THREAD_ALL_ACCESS, NULL, current_process,
                                          static_cast<LPTHREAD_START_ROUTINE>( start_routine ), 0, FALSE, NULL, NULL, NULL, 0 );

    if ( error )
        std::cout << "NtCreateThreadEx error occured: " << *error << "\n";
    else
        std::cout << "NtCreateThreadEx call status: 0x" << std::hex << status << '\n';

    // 2 variant - when error handling is not required, get a plain return value
    auto simple_status = shadowsyscall( "NtTerminateProcess", reinterpret_cast<HANDLE>( -1 ), -6932 );

    return 0;
}
```

## Detailed module & shared-data parser example
```cpp
int main() {
    // Enumerate every dll loaded to current process
    for ( const auto& dll : shadow::dlls() )
        std::wcout << dll.filepath() << " : " << dll.native_handle() << "\n";

    std::cout.put( '\n' );

    // Find exactly known dll loaded to current process
    // "ntdll.dll" doesn't leave string in executable, it
    // being hashed on compile-time with consteval guarantee
    // The implementation doesn't care about the “.dll” suffix.
    auto ntdll = shadow::dll( "ntdll" /* after compilation it will become 384989384324938 */ );

    std::wcout << "Current .exe filepath: " << shadow::current_module().filepath() << "\n\n"; // Contains same methods as "ntdll"

    std::cout << ntdll.base_address().ptr() << '\n';                         // .base_address() returns address_t
    std::cout << ntdll.native_handle() << '\n';                              // .native_handle() returns void*
    std::cout << ntdll.entry_point() << '\n';                                // .entry_point() returns address_t, if presented
    std::wcout << ntdll.name() << '\n';                                      // .name() returns std::wstrview, "NTDLL.DLL"
    std::wcout << ntdll.filepath() << '\n';                                  // .filepath() returns std::wstrview, "C:\WINDOWS\SYSTEM32\NTDLL.DLL"
    std::cout << ntdll.image()->get_nt_headers()->signature << '\n';         // returns uint32_t, NT magic value
    std::cout << ntdll.image()->get_optional_header()->size_image << "\n\n"; // returns uint32_t, loaded NTDLL image size

    std::cout << "5 exports of ntdll.dll:\n";
    for ( const auto& [name, address] : ntdll.exports() | std::views::take( 5 ) )
        std::cout << name << " : " << address.raw() << '\n';

    std::cout.put( '\n' );

    auto it = ntdll.exports().find_if( []( auto export_data ) -> bool {
        const auto& [name, address] = export_data;
        constexpr auto compiletime_hash = shadow::hash64_t{ "NtQuerySystemInformation" }; // after compilation it will become 384989384324938
        const auto runtime_hash = shadow::hash64_t{}( name );                             // accepts any range that have access by index
        return compiletime_hash == runtime_hash;
    } );

    const auto& [name, address] = *it;
    std::cout << "Found target export:\n" << name << " : " << address << "\n\n";

    // "location" returns a DLL struct that contains this export
    std::wcout << "DLL that contains Sleep export is: " << shadow::dll_export( "Sleep" ).location().name() << "\n\n";

    // shared_data parses KUSER_SHARED_DATA
    // The class is a high-level wrapper for parsing,
    // which will save you from direct work with raw addresses

    auto shared = shadow::shared_data();

    std::cout << shared.safe_boot_enabled() << '\n';
    std::cout << shared.boot_id() << '\n';
    std::cout << shared.physical_pages_num() << '\n';
    std::cout << shared.kernel_debugger_present() << '\n';
    std::wcout << shared.system_root() << '\n';

    std::cout << shared.system().is_windows_11() << '\n';
    std::cout << shared.system().is_windows_10() << '\n';
    std::cout << shared.system().is_windows_7() << '\n';
    std::cout << shared.system().build_number() << '\n';
    std::cout << shared.system().formatted() << '\n';

    std::cout << shared.unix_epoch_timestamp().utc().time_since_epoch() << '\n';
    std::cout << shared.unix_epoch_timestamp().utc().format_iso8601() << '\n';
    std::cout << shared.unix_epoch_timestamp().local().time_since_epoch() << '\n';
    std::cout << shared.unix_epoch_timestamp().local().format_iso8601() << '\n';
    std::cout << shared.timezone_offset<std::chrono::seconds>() << "\n\n";

    // Iterators are compatible with the ranges library
    static_assert( std::bidirectional_iterator<shadow::detail::export_enumerator::iterator> );
    static_assert( std::bidirectional_iterator<shadow::detail::module_enumerator::iterator> );

    return 0;
}
```

## 🚀 Features

- Caching each call
- Exception-safe code
- Enumerate every DLL loaded to current process
- Find exactly known module loaded to current process
- Enumerate EAT of module
- Resolve PE-headers and directories of module
- Compile-time string hasher
- Hash seed is pseudo-randomized, based on header file location
- Syscall executor
- Overriding syscall SSN parser
- Execute any export at runtime
- Doesn't leave any imports in the executable

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
