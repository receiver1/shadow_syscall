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

## 📜 What is a syscall in Windows?
![syscalls](https://github.com/user-attachments/assets/1719c073-669b-4e6b-b2ec-23850ba91dbc)

## Thanks to
invers1on :heart:

https://github.com/can1357/linux-pe
