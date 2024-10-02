// [FAQ / Examples] here: https://github.com/annihilatorq/shadow_syscall

// Creator Discord - @ntraiseharderror,
// Telegram - https://t.me/annihilatorq,
// Github - https://github.com/annihilatorq

// Credits to https://github.com/can1357/linux-pe for the very pretty structs
// Special thanks to @inversion

#ifndef SHADOWSYSCALL_HPP
#define SHADOWSYSCALL_HPP

#ifndef SHADOWSYSCALLS_DISABLE_CACHING
    #include <mutex>
    #include <shared_mutex>
    #include <unordered_map>
#endif

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <intrin.h>
#include <iostream>
#include <numeric>
#include <optional>
#include <ranges>
#include <span>
#include <string>
#include <string_view>
#include <variant>

namespace shadow {

    [[maybe_unused]] constexpr auto bitness = std::numeric_limits<uintptr_t>::digits;
    [[maybe_unused]] constexpr auto is_x64 = bitness == 64;
    [[maybe_unused]] constexpr auto is_x32 = bitness == 32;

    class address_t {
    public:
        template <typename Ty>
        struct is_fundamental_or_pointer : std::bool_constant<std::is_pointer_v<Ty> || std::is_fundamental_v<Ty>> { };

        using underlying_t = std::uintptr_t;

        constexpr address_t() = default;
        constexpr address_t( underlying_t address ) noexcept: m_address( address ) { }

        template <typename Ty>
            requires( std::is_pointer_v<Ty> )
        constexpr address_t( Ty address ) noexcept: m_address( reinterpret_cast<underlying_t>( address ) ) { }

        address_t( const address_t& instance ) = default;
        address_t( address_t&& instance ) = default;
        address_t& operator=( const address_t& instance ) = default;
        address_t& operator=( address_t&& instance ) = default;
        ~address_t() = default;

        template <typename Ty = void, typename PointerTy = std::add_pointer_t<Ty>>
        [[nodiscard]] constexpr PointerTy ptr( std::ptrdiff_t offset = 0 ) const noexcept {
            return this->offset( offset ).as<PointerTy>();
        }

        [[nodiscard]] constexpr underlying_t raw() const noexcept {
            return m_address;
        }

        template <typename Ty = address_t>
        [[nodiscard]] constexpr Ty offset( std::ptrdiff_t offset = 0 ) const noexcept {
            if constexpr ( std::is_pointer_v<Ty> )
                return m_address == 0u ? nullptr : reinterpret_cast<Ty>( m_address + offset );
            else
                return m_address == 0u ? static_cast<Ty>( *this ) : Ty{ m_address + offset };
        }

        template <typename Ty>
        [[nodiscard]] constexpr Ty as() const noexcept {
            if constexpr ( std::is_pointer_v<Ty> )
                return reinterpret_cast<Ty>( m_address );
            else
                return static_cast<Ty>( m_address );
        }

        template <typename Ty, typename... Args>
            requires( std::conjunction_v<is_fundamental_or_pointer<Args>...> )
        [[nodiscard]] Ty execute( Args... args ) const noexcept {
            if ( m_address == 0 )
                return Ty{};

            return reinterpret_cast<Ty ( * )( Args... )>( m_address )( args... );
        }

        constexpr explicit operator std::uintptr_t() const noexcept {
            return m_address;
        }

        constexpr explicit operator bool() const noexcept {
            return static_cast<bool>( m_address );
        }

        constexpr auto operator<=>( const address_t& ) const = default;

        friend std::ostream& operator<<( std::ostream& os, const address_t& address ) {
            return os << address.ptr();
        }

    private:
        underlying_t m_address{ 0 };
    };

    namespace win {
        static constexpr std::uint32_t NUM_DATA_DIRECTORIES = 16;
        static constexpr std::uint32_t img_npos = 0xFFFFFFFF;

        union version_t {
            uint16_t identifier;
            struct {
                uint8_t major;
                uint8_t minor;
            };
        };

        union ex_version_t {
            uint32_t identifier;
            struct {
                uint16_t major;
                uint16_t minor;
            };
        };

        struct section_string_t {
            char short_name[8];

            [[nodiscard]] auto view() const noexcept {
                return std::string_view{ short_name };
            }

            explicit operator std::string_view() const noexcept {
                return view();
            }

            [[nodiscard]] auto operator[]( size_t n ) const noexcept {
                return view()[n];
            }

            auto operator==( const section_string_t& other ) const {
                return view().compare( other.view() ) == 0;
            }
        };

        struct unicode_string {
            using char_t = wchar_t;
            using pointer_t = char_t*;

        public:
            constexpr unicode_string() = default;
            constexpr unicode_string( const std::uint16_t length, const std::uint16_t max_length, pointer_t buffer ) noexcept
                : m_length( length ), m_max_length( max_length ), m_buffer( buffer ) { }

            unicode_string( const unicode_string& instance ) = default;
            unicode_string( unicode_string&& instance ) = default;
            unicode_string& operator=( const unicode_string& instance ) = default;
            unicode_string& operator=( unicode_string&& instance ) = default;
            ~unicode_string() = default;

            template <typename Ty>
                requires( std::is_constructible_v<Ty, pointer_t> )
            [[nodiscard]] auto as() const noexcept( std::is_nothrow_constructible_v<Ty, pointer_t> ) {
                return Ty{ m_buffer };
            }

            [[nodiscard]] auto to_path( std::filesystem::path::format fmt = std::filesystem::path::auto_format ) const {
                return std::filesystem::path{ m_buffer, fmt };
            }

            [[nodiscard]] auto view() const noexcept {
                return std::wstring_view{ m_buffer };
            }

            [[nodiscard]] auto string() const {
                // \note: Since std::codecvt & std::wstring_convert is
                // deprecated in cpp17 and will be deleted in
                // cpp26, we use the std::filesystem::path
                // as a string converter, although it will
                // require more memory, we will be sure
                // that the conversion will be correct.
                // We will not use wcstombs_s because of the
                // dependency on the current locale.

                const auto src = view();
                const auto is_non_ascii = contains_non_ascii( src );
                if ( is_non_ascii ) {
                    // Use std::filesystem::path as string converter
                    return to_path().string();
                } else {
                    // Otherwise, return string_view converted to std::string
                    return std::string( src.begin(), src.end() );
                }
            }

            [[nodiscard]] auto data() const noexcept {
                return m_buffer;
            }

            [[nodiscard]] auto size() const noexcept {
                return m_length;
            }

        private:
            [[nodiscard]] bool contains_non_ascii( const std::wstring_view str ) const noexcept {
                return std::ranges::any_of( str, []( wchar_t ch ) {
                    return ch > 127; // characters out of ASCII range
                } );
            }

            std::uint16_t m_length{ 0 };
            std::uint16_t m_max_length{ 0 };
            pointer_t     m_buffer{ nullptr };
        };

        struct list_entry {
            list_entry* flink;
            list_entry* blink;
        };

        enum directory_id : std::uint8_t {
            directory_entry_export = 0,          // Export Directory
            directory_entry_import = 1,          // Import Directory
            directory_entry_resource = 2,        // Resource Directory
            directory_entry_exception = 3,       // Exception Directory
            directory_entry_security = 4,        // Security Directory
            directory_entry_basereloc = 5,       // Base Relocation Table
            directory_entry_debug = 6,           // Debug Directory
            directory_entry_copyright = 7,       // (X86 usage)
            directory_entry_architecture = 7,    // Architecture Specific Data
            directory_entry_globalptr = 8,       // RVA of GP
            directory_entry_tls = 9,             // TLS Directory
            directory_entry_load_config = 10,    // Load Configuration Directory
            directory_entry_bound_import = 11,   // Bound Import Directory in headers
            directory_entry_iat = 12,            // Import Address Table
            directory_entry_delay_import = 13,   // Delay Load Import Descriptors
            directory_entry_com_descriptor = 14, // COM Runtime descriptor
            directory_reserved0 = 15,            // -
        };

        struct data_directory_t {
            std::uint32_t      rva;
            std::uint32_t      size;
            [[nodiscard]] bool present() const noexcept {
                return size > 0;
            }
        };

        struct raw_data_directory_t {
            uint32_t           ptr_raw_data;
            uint32_t           size;
            [[nodiscard]] bool present() const noexcept {
                return size > 0;
            }
        };

        struct data_directories_x64_t {
            union {
                struct {
                    data_directory_t     export_directory;
                    data_directory_t     import_directory;
                    data_directory_t     resource_directory;
                    data_directory_t     exception_directory;
                    raw_data_directory_t security_directory; // File offset instead of RVA!
                    data_directory_t     basereloc_directory;
                    data_directory_t     debug_directory;
                    data_directory_t     architecture_directory;
                    data_directory_t     globalptr_directory;
                    data_directory_t     tls_directory;
                    data_directory_t     load_config_directory;
                    data_directory_t     bound_import_directory;
                    data_directory_t     iat_directory;
                    data_directory_t     delay_import_directory;
                    data_directory_t     com_descriptor_directory;
                    data_directory_t     _reserved0;
                };
                data_directory_t entries[NUM_DATA_DIRECTORIES];
            };
        };

        struct data_directories_x86_t {
            union {
                struct {
                    data_directory_t     export_directory;
                    data_directory_t     import_directory;
                    data_directory_t     resource_directory;
                    data_directory_t     exception_directory;
                    raw_data_directory_t security_directory; // File offset instead of RVA!
                    data_directory_t     basereloc_directory;
                    data_directory_t     debug_directory;
                    data_directory_t     copyright_directory;
                    data_directory_t     globalptr_directory;
                    data_directory_t     tls_directory;
                    data_directory_t     load_config_directory;
                    data_directory_t     bound_import_directory;
                    data_directory_t     iat_directory;
                    data_directory_t     delay_import_directory;
                    data_directory_t     com_descriptor_directory;
                    data_directory_t     _reserved0;
                };
                data_directory_t entries[NUM_DATA_DIRECTORIES];
            };
        };

        struct export_directory_t {
            uint32_t  characteristics;
            uint32_t  timedate_stamp;
            version_t version;
            uint32_t  name;
            uint32_t  base;
            uint32_t  num_functions;
            uint32_t  num_names;
            uint32_t  rva_functions;
            uint32_t  rva_names;
            uint32_t  rva_name_ordinals;

            [[nodiscard]] auto rva_table( std::uintptr_t base_address ) const {
                return reinterpret_cast<std::uint32_t*>( base_address + rva_functions );
            }

            [[nodiscard]] auto ordinal_table( std::uintptr_t base_address ) const {
                return reinterpret_cast<std::uint16_t*>( base_address + rva_name_ordinals );
            }
        };

        enum class subsystem_id : uint16_t {
            unknown = 0x0000,        // Unknown subsystem.
            native = 0x0001,         // Image doesn't require a subsystem.
            windows_gui = 0x0002,    // Image runs in the Windows GUI subsystem.
            windows_cui = 0x0003,    // Image runs in the Windows character subsystem
            os2_cui = 0x0005,        // image runs in the OS/2 character subsystem.
            posix_cui = 0x0007,      // image runs in the Posix character subsystem.
            native_windows = 0x0008, // image is a native Win9x driver.
            windows_ce_gui = 0x0009, // Image runs in the Windows CE subsystem.
            efi_application = 0x000A,
            efi_boot_service_driver = 0x000B,
            efi_runtime_driver = 0x000C,
            efi_rom = 0x000D,
            xbox = 0x000E,
            windows_boot_application = 0x0010,
            xbox_code_catalog = 0x0011,
        };

        struct loader_table_entry {
            list_entry     in_load_order_links;
            list_entry     in_memory_order_links;
            std::nullptr_t reserved[2];
            address_t      base_address;
            address_t      entry_point;
            std::nullptr_t reserved2;
            unicode_string path;
            unicode_string name;
            std::nullptr_t reserved3[3];
            union {
                std::uint32_t  check_sum;
                std::nullptr_t reserved4;
            };
            std::uint32_t time_date_stamp;
        };

        struct module_loader_data {
            std::uint32_t length;
            std::uint8_t  initialized;
            void*         ss_handle;
            list_entry    in_load_order_module_list;
            list_entry    in_memory_order_module_list;
            list_entry    in_initialization_order_module_list;
        };

        struct PEB {
            uint8_t             reserved1[2];
            uint8_t             being_debugged;
            uint8_t             reserved2[1];
            std::nullptr_t      reserved3[2];
            module_loader_data* ldr_data;

            static auto address() noexcept {
#if defined( _M_X64 )
                return reinterpret_cast<const PEB*>( __readgsqword( 0x60 ) );
#elif defined( _M_IX86 )
                return reinterpret_cast<const PEB*>( __readfsdword( 0x30 ) );
#else
    #error Unsupported platform.
#endif
            }

            static auto loader_data() noexcept {
                return reinterpret_cast<module_loader_data*>( address()->ldr_data );
            }
        };

        struct section_header_t {
            section_string_t name;
            union {
                uint32_t physical_address;
                uint32_t virtual_size;
            };
            uint32_t virtual_address;

            uint32_t size_raw_data;
            uint32_t ptr_raw_data;

            uint32_t ptr_relocs;
            uint32_t ptr_line_numbers;
            uint16_t num_relocs;
            uint16_t num_line_numbers;

            uint32_t characteristics_flags;
        };

        struct file_header_t {
            std::uint16_t machine;
            std::uint16_t num_sections;
            std::uint32_t timedate_stamp;
            std::uint32_t ptr_symbols;
            std::uint32_t num_symbols;
            std::uint16_t size_optional_header;
            std::uint16_t characteristics;
        };

        struct optional_header_x64_t {
            // Standard fields.
            uint16_t               magic;
            version_t              linker_version;
            uint32_t               size_code;
            uint32_t               size_init_data;
            uint32_t               size_uninit_data;
            uint32_t               entry_point;
            uint32_t               base_of_code;
            uint64_t               image_base;
            uint32_t               section_alignment;
            uint32_t               file_alignment;
            ex_version_t           os_version;
            ex_version_t           img_version;
            ex_version_t           subsystem_version;
            uint32_t               win32_version_value;
            uint32_t               size_image;
            uint32_t               size_headers;
            uint32_t               checksum;
            subsystem_id           subsystem;
            uint16_t               characteristics;
            uint64_t               size_stack_reserve;
            uint64_t               size_stack_commit;
            uint64_t               size_heap_reserve;
            uint64_t               size_heap_commit;
            uint32_t               ldr_flags;
            uint32_t               num_data_directories;
            data_directories_x64_t data_directories;
        };

        struct optional_header_x86_t {
            // Standard fields.
            uint16_t               magic;
            version_t              linker_version;
            uint32_t               size_code;
            uint32_t               size_init_data;
            uint32_t               size_uninit_data;
            uint32_t               entry_point;
            uint32_t               base_of_code;
            uint32_t               base_of_data;
            uint32_t               image_base;
            uint32_t               section_alignment;
            uint32_t               file_alignment;
            ex_version_t           os_version;
            ex_version_t           img_version;
            ex_version_t           subsystem_version;
            uint32_t               win32_version_value;
            uint32_t               size_image;
            uint32_t               size_headers;
            uint32_t               checksum;
            subsystem_id           subsystem;
            uint16_t               characteristics;
            uint32_t               size_stack_reserve;
            uint32_t               size_stack_commit;
            uint32_t               size_heap_reserve;
            uint32_t               size_heap_commit;
            uint32_t               ldr_flags;
            uint32_t               num_data_directories;
            data_directories_x86_t data_directories;

            inline bool has_directory( const data_directory_t* dir ) const {
                return &data_directories.entries[num_data_directories] < dir && dir->present();
            }

            inline bool has_directory( directory_id id ) const {
                return has_directory( &data_directories.entries[id] );
            }
        };

        using optional_header_t = std::conditional_t<is_x64, optional_header_x64_t, optional_header_x86_t>;

        struct nt_headers_t {
            uint32_t          signature;
            file_header_t     file_header;
            optional_header_t optional_header;

            // Section getters
            inline section_header_t* get_sections() {
                return ( section_header_t* )( ( uint8_t* )&optional_header + file_header.size_optional_header );
            }
            inline section_header_t* get_section( size_t n ) {
                return n >= file_header.num_sections ? nullptr : get_sections() + n;
            }
            inline const section_header_t* get_sections() const {
                return const_cast<nt_headers_t*>( this )->get_sections();
            }
            inline const section_header_t* get_section( size_t n ) const {
                return const_cast<nt_headers_t*>( this )->get_section( n );
            }

            // Section iterator
            template <typename T>
            struct proxy {
                T*       base;
                uint16_t count;
                T*       begin() const {
                    return base;
                }
                T* end() const {
                    return base + count;
                }
            };
            inline proxy<section_header_t> sections() {
                return { get_sections(), file_header.num_sections };
            }
            inline proxy<const section_header_t> sections() const {
                return { get_sections(), file_header.num_sections };
            }
        };

        struct dos_header_t {
            uint16_t e_magic;
            uint16_t e_cblp;
            uint16_t e_cp;
            uint16_t e_crlc;
            uint16_t e_cparhdr;
            uint16_t e_minalloc;
            uint16_t e_maxalloc;
            uint16_t e_ss;
            uint16_t e_sp;
            uint16_t e_csum;
            uint16_t e_ip;
            uint16_t e_cs;
            uint16_t e_lfarlc;
            uint16_t e_ovno;
            uint16_t e_res[4];
            uint16_t e_oemid;
            uint16_t e_oeminfo;
            uint16_t e_res2[10];
            uint32_t e_lfanew;

            inline file_header_t* get_file_header() {
                return &get_nt_headers()->file_header;
            }
            inline const file_header_t* get_file_header() const {
                return &get_nt_headers()->file_header;
            }
            inline nt_headers_t* get_nt_headers() {
                return ( nt_headers_t* )( ( uint8_t* )this + e_lfanew );
            }
            inline const nt_headers_t* get_nt_headers() const {
                return const_cast<dos_header_t*>( this )->get_nt_headers();
            }
        };

        struct image_t {
            dos_header_t dos_header;

            // Basic getters.
            inline dos_header_t* get_dos_headers() {
                return &dos_header;
            }
            inline const dos_header_t* get_dos_headers() const {
                return &dos_header;
            }
            inline file_header_t* get_file_header() {
                return dos_header.get_file_header();
            }
            inline const file_header_t* get_file_header() const {
                return dos_header.get_file_header();
            }
            inline nt_headers_t* get_nt_headers() {
                return dos_header.get_nt_headers();
            }
            inline const nt_headers_t* get_nt_headers() const {
                return dos_header.get_nt_headers();
            }
            inline optional_header_t* get_optional_header() {
                return &get_nt_headers()->optional_header;
            }
            inline const optional_header_t* get_optional_header() const {
                return &get_nt_headers()->optional_header;
            }

            inline data_directory_t* get_directory( directory_id id ) {
                auto nt_hdrs = get_nt_headers();
                if ( nt_hdrs->optional_header.num_data_directories <= id )
                    return nullptr;
                data_directory_t* dir = &nt_hdrs->optional_header.data_directories.entries[id];
                return dir->present() ? dir : nullptr;
            }

            inline const data_directory_t* get_directory( directory_id id ) const {
                return const_cast<image_t*>( this )->get_directory( id );
            }

            template <typename T = uint8_t>
            inline T* rva_to_ptr( uint32_t rva, size_t length = 1 ) {
                // Find the section, try mapping to header if none found.
                auto scn = rva_to_section( rva );
                if ( !scn ) {
                    uint32_t rva_hdr_end = get_nt_headers()->optional_header.size_headers;
                    if ( rva < rva_hdr_end && ( rva + length ) <= rva_hdr_end )
                        return ( T* )( ( uint8_t* )&dos_header + rva );
                    return nullptr;
                }

                // Apply the boundary check.
                size_t offset = rva - scn->virtual_address;
                if ( ( offset + length ) > scn->size_raw_data )
                    return nullptr;

                // Return the final pointer.
                return ( T* )( ( uint8_t* )&dos_header + scn->ptr_raw_data + offset );
            }

            inline section_header_t* rva_to_section( uint32_t rva ) {
                auto nt_hdrs = get_nt_headers();
                for ( size_t i = 0; i != nt_hdrs->file_header.num_sections; i++ ) {
                    auto section = nt_hdrs->get_section( i );
                    if ( section->virtual_address <= rva && rva < ( section->virtual_address + section->virtual_size ) )
                        return section;
                }
                return nullptr;
            }

            template <typename T = uint8_t>
            inline const T* rva_to_ptr( uint32_t rva, size_t length = 1 ) const {
                return const_cast<image_t*>( this )->template rva_to_ptr<const T>( rva, length );
            }
            inline uint32_t rva_to_fo( uint32_t rva, size_t length = 1 ) const {
                return ptr_to_raw( rva_to_ptr( rva, length ) );
            }
            inline uint32_t ptr_to_raw( const void* ptr ) const {
                return ptr ? uint32_t( uintptr_t( ptr ) - uintptr_t( &dos_header ) ) : img_npos;
            }
        };

        inline auto image_from_base( address_t base ) {
            return base.ptr<image_t>();
        }

        inline auto image_from_base( loader_table_entry* module ) {
            return image_from_base( module->base_address.as<address_t>() );
        }

        template <typename T, typename FieldT>
        constexpr T* containing_record( FieldT* address, FieldT T::*field ) {
            auto offset = reinterpret_cast<std::uintptr_t>( &( reinterpret_cast<T*>( 0 )->*field ) );
            return reinterpret_cast<T*>( reinterpret_cast<std::uintptr_t>( address ) - offset );
        }

        struct kernel_system_time {
            uint32_t low_part;
            int32_t  high1_time;
            int32_t  high2_time;
        };

        enum nt_product_type {
            win_nt = 1,
            lan_man_nt = 2,
            server = 3
        };

        enum alternative_arch_type {
            standart_design,
            nec98x86,
            end_alternatives
        };

        struct xstate_feature {
            uint32_t offset;
            uint32_t size;
        };

        struct xstate_configuration {
            // Mask of all enabled features
            uint64_t enabled_features;
            // Mask of volatile enabled features
            uint64_t enabled_volatile_features;
            // Total size of the save area for user states
            uint32_t size;
            // Control Flags
            union {
                uint32_t control_flags;
                struct {
                    uint32_t optimized_save:1;
                    uint32_t compaction_enabled:1;
                    uint32_t extended_feature_disable:1;
                };
            };
            // List of features
            xstate_feature features[64];
            // Mask of all supervisor features
            uint64_t enabled_supervisor_features;
            // Mask of features that require start address to be 64 byte aligned
            uint64_t aligned_features;
            // Total size of the save area for user and supervisor states
            uint32_t all_features_size;
            // List which holds size of each user and supervisor state supported by CPU
            uint32_t all_features[64];
            // Mask of all supervisor features that are exposed to user-mode
            uint64_t enabled_user_visible_supervisor_features;
            // Mask of features that can be disabled via XFD
            uint64_t extended_feature_disable_features;
            // Total size of the save area for non-large user and supervisor states
            uint32_t all_non_large_feature_size;
            uint32_t spare;
        };

        union win32_large_integer {
            struct {
                uint32_t low_part;
                int32_t  high_part;
            };
            struct {
                uint32_t low_part;
                int32_t  high_part;
            } u;
            uint64_t quad_part;
        };

        struct kernel_user_shared_data {
            uint32_t              tick_count_low_deprecated;
            uint32_t              tick_count_multiplier;
            kernel_system_time    interrupt_time;
            kernel_system_time    system_time;
            kernel_system_time    time_zone_bias;
            uint16_t              image_number_low;
            uint16_t              image_number_high;
            wchar_t               nt_system_root[260];
            uint32_t              max_stack_trace_depth;
            uint32_t              crypto_exponent;
            uint32_t              time_zone_id;
            uint32_t              large_page_minimum;
            uint32_t              ait_sampling_value;
            uint32_t              app_compat_flag;
            uint64_t              random_seed_version;
            uint32_t              global_validation_runlevel;
            int32_t               time_zone_bias_stamp;
            uint32_t              nt_build_number;
            nt_product_type       nt_product_type;
            bool                  product_type_is_valid;
            bool                  reserved0[1];
            uint16_t              native_processor_architecture;
            uint32_t              nt_major_version;
            uint32_t              nt_minor_version;
            bool                  processor_features[64];
            uint32_t              reserved1;
            uint32_t              reserved3;
            uint32_t              time_slip;
            alternative_arch_type alternative_arch;
            uint32_t              boot_id;
            win32_large_integer   system_expiration_date;
            uint32_t              suite_mask;
            bool                  kernel_debugger_enabled;
            union {
                uint8_t mitigation_policies;
                struct {
                    uint8_t nx_support_policy:2;
                    uint8_t seh_validation_policy:2;
                    uint8_t cur_dir_devices_skipped_for_dlls:2;
                    uint8_t reserved:2;
                };
            };
            uint16_t cycles_per_yield;
            uint32_t active_console_id;
            uint32_t dismount_count;
            uint32_t com_plus_package;
            uint32_t last_system_rit_event_tick_count;
            uint32_t number_of_physical_pages;
            bool     safe_boot_mode;
            union {
                uint8_t virtualization_flags;
                struct {
                    uint8_t arch_started_in_el2:1;
                    uint8_t qc_sl_is_supported:1;
                };
            };
            uint8_t reserved12[2];
            union {
                uint32_t shared_data_flags;
                struct {
                    uint32_t dbg_error_port_present:1;
                    uint32_t dbg_elevation_enabled:1;
                    uint32_t dbg_virt_enabled:1;
                    uint32_t dbg_installer_detect_enabled:1;
                    uint32_t dbg_lkg_enabled:1;
                    uint32_t dbg_dyn_processor_enabled:1;
                    uint32_t dbg_console_broker_enabled:1;
                    uint32_t dbg_secure_boot_enabled:1;
                    uint32_t dbg_multi_session_sku:1;
                    uint32_t dbg_multi_users_in_session_sku:1;
                    uint32_t dbg_state_separation_enabled:1;
                    uint32_t spare_bits:21;
                };
            };
            uint32_t data_flags_pad[1];
            uint64_t test_ret_instruction;
            int64_t  qpc_frequency;
            uint32_t system_call;
            uint32_t reserved2;
            uint64_t full_number_of_physical_pages;
            uint64_t system_call_pad[1];
            union {
                kernel_system_time tick_count;
                uint64_t           tick_count_quad;
                struct {
                    uint32_t reserved_tick_count_overlay[3];
                    uint32_t tick_count_pad[1];
                };
            };
            uint32_t cookie;
            uint32_t cookie_pad[1];
            int64_t  console_session_foreground_process_id;
            uint64_t time_update_lock;
            uint64_t baseline_system_time_qpc;
            uint64_t baseline_interrupt_time_qpc;
            uint64_t qpc_system_time_increment;
            uint64_t qpc_interrupt_time_increment;
            uint8_t  qpc_system_time_increment_shift;
            uint8_t  qpc_interrupt_time_increment_shift;
            uint16_t unparked_processor_count;
            uint32_t enclave_feature_mask[4];
            uint32_t telemetry_coverage_round;
            uint16_t user_mode_global_logger[16];
            uint32_t image_file_execution_options;
            uint32_t lang_generation_count;
            uint64_t reserved4;
            uint64_t interrupt_time_bias;
            uint64_t qpc_bias;
            uint32_t active_processor_count;
            uint8_t  active_group_count;
            uint8_t  reserved9;
            union {
                uint16_t qpc_data;
                struct {
                    uint8_t qpc_bypass_enabled;
                    uint8_t qpc_reserved;
                };
            };
            win32_large_integer  time_zone_bias_effective_start;
            win32_large_integer  time_zone_bias_effective_end;
            xstate_configuration xstate;
            kernel_system_time   feature_configuration_change_stamp;
            uint32_t             spare;
            uint64_t             user_pointer_auth_mask;
            xstate_configuration xstate_arm64;
            uint32_t             reserved10[210];
        };

    } // namespace win

    namespace detail {

        template <typename Ret, typename... Args>
        class stack_function;

        template <typename Ret, typename... Args>
        class stack_function<Ret( Args... )> {
        public:
            using function_ptr_t = Ret ( * )( void*, Args&&... );
            using destructor_ptr_t = void ( * )( void* );

            stack_function() = default;

            template <typename F, typename DecayedF = std::decay_t<F>>
                requires( std::is_invocable_r_v<Ret, F, Args...> )
            stack_function( F&& func ) {
                static_assert( sizeof( DecayedF ) <= sizeof( m_storage ), "Function object too large" );

                // Here we use "placement new" for SBO, which does
                // not result in any additional memory allocation
                // https://en.cppreference.com/w/cpp/language/new#Placement_new
                new ( &m_storage ) DecayedF( std::forward<F>( func ) );

                m_invoker = []( void* ptr, Args&&... args ) -> Ret {
                    return ( *reinterpret_cast<DecayedF*>( ptr ) )( std::forward<Args>( args )... );
                };

                if constexpr ( std::is_destructible_v<DecayedF> ) {
                    m_destroyer = []( void* ptr ) {
                        std::destroy_at( reinterpret_cast<std::decay_t<F>*>( ptr ) );
                    };
                }
            }

            ~stack_function() {
                if ( m_destroyer ) {
                    m_destroyer( &m_storage );
                }
            }

            void swap( stack_function& other ) noexcept {
                if ( m_destroyer )
                    m_destroyer( &m_storage );
                if ( other.m_destroyer )
                    other.m_destroyer( &other.m_storage );

                std::swap( m_storage, other.m_storage );
                std::swap( m_invoker, other.m_invoker );
                std::swap( m_destroyer, other.m_destroyer );
            }

            Ret operator()( Args... args ) {
                if ( !m_invoker )
                    throw std::bad_function_call();
                return m_invoker( &m_storage, std::forward<Args>( args )... );
            }

        private:
            alignas( void* ) std::byte m_storage[32];
            function_ptr_t   m_invoker{ nullptr };
            destructor_ptr_t m_destroyer{ nullptr };
        };

        template <std::integral Ty>
        consteval Ty generate_compilation_seed() {
            Ty hash = __cplusplus;

            // \note: @annihilatorq Fix note since 27.08.2024:
            // We cannot use __TIME__ or alternatives here since
            // such macros represent the build time of a translation
            // unit, not the build time of the entire project.
            for ( auto c : __FILE__ )
                hash ^= static_cast<Ty>( c ) * 0x1928231;

            return hash;
        }

        template <typename Ty>
        concept ArrayLike = requires( Ty t ) {
            { t.size() } -> std::convertible_to<std::size_t>;         // Size methods required
            { t[0] } -> std::convertible_to<typename Ty::value_type>; // Should be accessable by index
        };

        // basic_hash class provides compile-time and runtime hash
        // computation. Uses FNV-1a hashing algorithm.
        // Case-insensitive by default.
        template <std::integral ValTy>
        class basic_hash {
        public:
            using underlying_t = ValTy;
            static constexpr bool  case_sensitive = false;
            static constexpr ValTy FNV_prime = ( sizeof( ValTy ) == 4 ) ? 16777619u : 1099511628211ull;

        public:
            constexpr basic_hash( ValTy hash ): m_value( hash ) { }
            constexpr basic_hash() = default;
            constexpr ~basic_hash() = default;

            // The compile-time constructor, consteval gives an
            // absolute guarantee that the hash of the string
            // will be computed at compile time, so the output
            // of any string will be a number.
            template <typename CharT, std::size_t N>
            consteval basic_hash( const CharT ( &string )[N] ) {
                constexpr auto string_length = N - 1;
                for ( auto i = 0; i < string_length; i++ )
                    m_value += fnv1a_append_bytes<>( m_value, string[i] );
            }

        public:
            // Method for calculating hash at runtime. Accepts
            // any object with range properties.
            template <ArrayLike Ty>
            [[nodiscard]] ValTy operator()( const Ty& object ) {
                ValTy local_value = m_value;
                for ( auto i = 0; i < object.size(); i++ )
                    local_value += fnv1a_append_bytes<>( local_value, object[i] );
                return local_value;
            }

            // \return Hash-value copy as an integral
            [[nodiscard]] constexpr ValTy raw() const {
                return m_value;
            }

            [[nodiscard]] constexpr explicit operator ValTy() const {
                return m_value;
            }

            constexpr auto operator<=>( const basic_hash& ) const = default;

            friend std::ostream& operator<<( std::ostream& os, const basic_hash& hash ) {
                return os << hash.m_value;
            }

        private:
            template <typename CharTy>
            [[nodiscard]] constexpr ValTy fnv1a_append_bytes( ValTy value, const CharTy byte ) const noexcept {
                const auto lowercase_byte = case_sensitive ? byte : to_lower( byte );
                value ^= static_cast<ValTy>( lowercase_byte );
                value *= FNV_prime;
                return value;
            }

            template <typename CharTy>
            [[nodiscard]] constexpr CharTy to_lower( CharTy c ) const {
                return ( ( c >= 'A' && c <= 'Z' ) ? ( c + 32 ) : c );
            }

        private:
            ValTy m_value{ generate_compilation_seed<ValTy>() };
        };

        using hash32_t = detail::basic_hash<uint32_t>;
        using hash64_t = detail::basic_hash<uint64_t>;

        // \note: Some useful benchmarks to understand the
        // difference in the bytewise vs collection rate
        // using SSE intrinsics, benched using 2MB span:
        // [MSVC]
        // BM_SumBytesBasic     792456 ns       802176 ns
        // BM_SumBytesSSE        85171 ns        85794 ns
        // [CLANG]
        // BM_SumBytesBasic     381638 ns       383650 ns
        // BM_SumBytesSSE        98902 ns        97656 ns

        template <std::integral Ty = std::size_t>
        class memory_checksum {
            using vector128_t = __m128i;

        public:
            [[nodiscard]] Ty compute( const std::span<const char> data ) const {
                const auto  size = data.size();
                auto        sum = _mm_setzero_si128();
                std::size_t pos = 0;

                // The main feature of vectorized byte collection is
                // that we do not iterate each byte separately, but
                // load 16 bytes in one iteration, respectively, the
                // number of iterations is reduced by 16 times.

                for ( ; pos + 16 <= size; pos += 16 )
                    process_block( data, pos, sum );

                // Just sum up all 16-bit words from the "sum"
                Ty total_sum = sum_16bit_words( sum );

                // If the sum of bytes is not a multiple of 16, there
                // will be a "tail" of remaining bytes, collect them.
                total_sum += append_tail( data, pos );

                return total_sum * 58998238934ull;
            }

        private:
            void process_block( const std::span<const char> data, std::size_t pos, vector128_t& sum ) const {
                // Load 16 bytes in one-go
                auto block = _mm_loadu_si128( reinterpret_cast<const vector128_t*>( &data[pos] ) );

                // We will not use '_mm_cvtepi8_epi16' in order
                // not to switch from SSE2 to SSE 4.1
                auto low_eight_bytes = _mm_unpacklo_epi8( block, _mm_setzero_si128() );
                auto high_eight_bytes = _mm_unpackhi_epi8( block, _mm_setzero_si128() );

                sum = _mm_add_epi16( sum, low_eight_bytes );
                sum = _mm_add_epi16( sum, high_eight_bytes );
            }

            Ty sum_16bit_words( const vector128_t& sum ) const {
                alignas( 16 ) int16_t temp[8];
                _mm_storeu_si128( reinterpret_cast<vector128_t*>( temp ), sum );

                return std::accumulate( std::begin( temp ), std::end( temp ), Ty{ 0 } );
            }

            Ty append_tail( const std::span<const char> data, std::size_t pos ) const {
                return std::reduce( data.begin() + pos, data.end(), 0ull, []( Ty acc, char byte ) {
                    return acc + static_cast<unsigned char>( byte );
                } );
            }
        };

        class export_enumerator {
        public:
            explicit export_enumerator( address_t base ) noexcept: m_module_base( base ), m_export_table( get_export_directory( base ) ) { }

            [[nodiscard]] std::size_t size() const noexcept {
                return m_export_table->num_names;
            }

            [[nodiscard]] const win::export_directory_t* table() const noexcept {
                return m_export_table;
            }

            [[nodiscard]] std::string_view name( std::size_t index ) const noexcept {
                const auto rva_names = std::span{ m_module_base.offset<const std::uint32_t*>( m_export_table->rva_names ), m_export_table->num_names };
                return { m_module_base.offset<const char*>( rva_names[index] ) };
            }

            [[nodiscard]] address_t address( std::size_t index ) const noexcept {
                const auto rva_table = m_export_table->rva_table( m_module_base.raw() );
                const auto ordinal_table = m_export_table->ordinal_table( m_module_base.raw() );
                const auto ordinal = ordinal_table[index];
                const auto rva_function = rva_table[ordinal];
                return m_module_base.offset( rva_function );
            }

            [[nodiscard]] bool is_export_forwarded( address_t export_address ) const noexcept {
                const auto image = win::image_from_base( m_module_base.raw() );
                const auto export_data_dir = image->get_optional_header()->data_directories.export_directory;
                const auto export_table_start = m_module_base.offset( export_data_dir.rva );
                const auto export_table_end = export_table_start.offset( export_data_dir.size );
                return ( export_address >= export_table_start ) && ( export_address < export_table_end );
            }

            class iterator {
            public:
                using iterator_category = std::bidirectional_iterator_tag;
                using value_type = std::pair<std::string_view, address_t>;
                using difference_type = std::ptrdiff_t;
                using pointer = value_type*;
                using reference = value_type&;

                iterator(): m_exports( nullptr ), m_index( 0 ), m_value( {} ) {};
                ~iterator() = default;
                iterator( const iterator& ) = default;
                iterator( iterator&& ) = default;
                iterator& operator=( iterator&& ) = default;

                iterator( const export_enumerator* exports, std::size_t index ) noexcept: m_exports( exports ), m_index( index ), m_value() {
                    on_update();
                }

                reference operator*() const noexcept {
                    return m_value;
                }

                pointer operator->() const noexcept {
                    return &m_value;
                }

                iterator& operator=( const iterator& other ) noexcept {
                    if ( this != &other ) {
                        m_index = other.m_index;
                        m_value = other.m_value;
                    }
                    return *this;
                }

                iterator& operator++() noexcept {
                    if ( m_index < m_exports->size() ) {
                        ++m_index;

                        if ( m_index < m_exports->size() )
                            on_update();
                        else
                            reset_value();
                    } else {
                        reset_value();
                    }
                    return *this;
                }

                iterator operator++( int ) noexcept {
                    iterator temp = *this;
                    ++( *this );
                    return temp;
                }

                iterator& operator--() noexcept {
                    if ( m_index > 0 ) {
                        --m_index;
                        on_update();
                    }
                    return *this;
                }

                iterator operator--( int ) noexcept {
                    iterator temp = *this;
                    --( *this );
                    return temp;
                }

                bool operator==( const iterator& other ) const noexcept {
                    return m_index == other.m_index && m_exports == other.m_exports;
                }

                bool operator!=( const iterator& other ) const noexcept {
                    return !( *this == other );
                }

            private:
                void on_update() noexcept {
                    if ( m_index < m_exports->size() )
                        m_value = value_type{ m_exports->name( m_index ), m_exports->address( m_index ) };
                }

                void reset_value() noexcept {
                    m_value = value_type{ "", 0 };
                }

                const export_enumerator* m_exports;
                std::size_t              m_index;
                mutable value_type       m_value;
            };

            // Make sure the iterator is compatible with std::ranges
            static_assert( std::bidirectional_iterator<iterator> );

            iterator begin() const noexcept {
                return iterator( this, 0 );
            }

            iterator end() const noexcept {
                return iterator( this, size() );
            }

            // \brief Finds an export in the specified module.
            // \param export_name The name of the export to find.
            // \return Iterator pointing to [name, address] if export is found, or .end() if export is not found.
            [[nodiscard]] iterator find( hash64_t export_name ) const noexcept {
                if ( export_name == 0 )
                    return end();

                auto it = std::ranges::find_if( *this, [export_name]( const auto& pair ) -> bool {
                    const auto& [name, address] = pair;
                    return export_name == hash64_t{}( name );
                } );

                return it;
            }

            // \brief Find an export with user-defined predicate
            // \param predicate User-defined predicate
            // \return Iterator pointing to [name, address] if export is found, .end() if export is not found.
            [[nodiscard]] iterator find_if( std::predicate<iterator::value_type> auto predicate ) {
                return std::ranges::find_if( *this, predicate );
            }

        private:
            win::export_directory_t* get_export_directory( address_t base_address ) const noexcept {
                const auto image = win::image_from_base( base_address.raw() );
                const auto export_data_dir = image->get_optional_header()->data_directories.export_directory;
                return m_module_base.offset<win::export_directory_t*>( export_data_dir.rva );
            }

            address_t                m_module_base;
            win::export_directory_t* m_export_table{ nullptr };
        };

        class dynamic_link_library {
        public:
            constexpr dynamic_link_library() noexcept = default;
            dynamic_link_library( hash64_t module_name ): m_data( find( module_name ).raw() ) { }
            dynamic_link_library( win::loader_table_entry* module_data ): m_data( module_data ) { }

            dynamic_link_library( const dynamic_link_library& instance ) = default;
            dynamic_link_library( dynamic_link_library&& instance ) = default;
            dynamic_link_library& operator=( const dynamic_link_library& instance ) = default;
            dynamic_link_library& operator=( dynamic_link_library&& instance ) = default;
            ~dynamic_link_library() = default;

            // \return loader_table_entry* - Raw pointer to Win32
            // loader data about the current module
            [[nodiscard]] win::loader_table_entry* raw() const noexcept {
                return m_data;
            }

            // \return image_t - Displaying an image in process
            // memory using the image_t structure from "linuxpe"
            [[nodiscard]] auto image() const noexcept {
                return win::image_from_base( m_data );
            }

            // \return address_t - Base address of current DLL
            [[nodiscard]] auto base_address() const noexcept {
                return m_data->base_address;
            }

            // \return void* - Pointer on base address of current
            // DLL, same as GetModuleHandle() in Win32 API
            [[nodiscard]] auto native_handle() const noexcept {
                return base_address().ptr();
            }

            // \return Address of entrypoint
            [[nodiscard]] auto entry_point() const noexcept {
                return m_data->entry_point;
            }

            // \return Name of current DLL as std::wstring_view
            [[nodiscard]] auto name() const noexcept {
                return m_data == nullptr ? win::unicode_string{} : m_data->name;
            }

            // \return Filepath to current DLL as std::wstring_view
            [[nodiscard]] auto filepath() const noexcept {
                return m_data == nullptr ? win::unicode_string{} : m_data->path;
            }

            // \return Exports range-enumerator of current DLL
            [[nodiscard]] auto exports() const noexcept {
                return export_enumerator{ m_data->base_address };
            }

            template <std::integral Ty = std::size_t>
            [[nodiscard]] auto section_checksum( hash32_t section_name = ".text" ) const {
                const auto module_base = base_address();
                const auto sections = image()->get_nt_headers()->sections();
                auto       section = std::find_if( sections.begin(), sections.end(), [=]( const win::section_header_t& section ) {
                    return section_name == hash32_t{}( section.name.view() );
                } );

                const auto section_content = std::span{ module_base.ptr<char>( section->virtual_address ), section->virtual_size };
                return memory_checksum<Ty>{}.compute( section_content );
            }

        private:
            dynamic_link_library find( hash64_t module_name ) const;

            bool is_module_hash_valid( hash64_t module_hash, std::wstring_view module_name ) const {
                // Try to compare hash of full module name
                const auto full_name_hash = hash64_t{}( module_name );

                // Try to compare hash of trimmed module name (.dll)
                const auto trimmed_name = module_name.substr( 0, module_name.size() - 4 );
                const auto trimmed_name_hash = hash64_t{}( trimmed_name );

                // Verify both hashes
                return full_name_hash == module_hash || trimmed_name_hash == module_hash;
            }

            win::loader_table_entry* m_data{ nullptr };
        };

        class module_enumerator {
        public:
            module_enumerator( bool skip_current_module = false ) {
                auto entry = &win::PEB::loader_data()->in_load_order_module_list;
                m_begin = ( skip_current_module ? entry->flink->flink : entry->flink );
                m_end = entry;
            }

            class iterator {
            public:
                using iterator_category = std::bidirectional_iterator_tag;
                using value_type = dynamic_link_library;
                using difference_type = std::ptrdiff_t;
                using pointer = value_type*;
                using reference = value_type&;

                iterator() noexcept( std::is_nothrow_default_constructible_v<value_type> ): m_entry( nullptr ), m_value( {} ) { }
                ~iterator() = default;
                iterator( const iterator& ) = default;
                iterator( iterator&& ) = default;
                iterator& operator=( iterator&& ) = default;
                iterator( win::list_entry* entry ): m_entry( entry ) {
                    on_update();
                }

                pointer operator->() const noexcept {
                    return &m_value;
                }

                iterator& operator=( const iterator& other ) noexcept {
                    if ( this != &other ) {
                        m_entry = other.m_entry;
                        on_update();
                    }
                    return *this;
                }

                iterator& operator++() noexcept {
                    m_entry = m_entry->flink;
                    on_update();
                    return *this;
                }

                iterator operator++( int ) noexcept {
                    iterator temp = *this;
                    ++( *this );
                    return temp;
                }

                iterator& operator--() noexcept {
                    m_entry = m_entry->blink;
                    on_update();
                    return *this;
                }

                iterator operator--( int ) noexcept {
                    iterator temp = *this;
                    --( *this );
                    return temp;
                }

                bool operator==( const iterator& other ) const noexcept {
                    return m_entry == other.m_entry;
                }

                bool operator!=( const iterator& other ) const noexcept {
                    return !( *this == other );
                }

                reference operator*() const noexcept {
                    return m_value;
                }

            private:
                void on_update() const noexcept {
                    auto table_entry = win::containing_record( m_entry, &win::loader_table_entry::in_load_order_links );
                    m_value = dynamic_link_library{ table_entry };
                }

                win::list_entry*   m_entry;
                mutable value_type m_value;
            };

            // Make sure the iterator is compatible with std::ranges
            static_assert( std::bidirectional_iterator<iterator> );

            iterator begin() const noexcept {
                return iterator( m_begin );
            }

            iterator end() const noexcept {
                return iterator( m_end );
            }

            // \brief Find an export with user-defined predicate
            // \param predicate User-defined predicate
            // \return Iterator pointing to [name, address] if
            // export is found, .end() if export is not found.
            [[nodiscard]] iterator find_if( std::predicate<iterator::value_type> auto predicate ) const noexcept {
                return std::ranges::find_if( *this, predicate );
            }

        private:
            win::list_entry* m_begin{ nullptr };
            win::list_entry* m_end{ nullptr };
        };

        class dll_export {
        public:
            dll_export() = default;
            dll_export( hash64_t export_name, hash64_t module_hash = 0 ) noexcept: m_address( 0 ), m_dll() {
                const auto [address, location] = find_export_address( export_name, module_hash );
                m_address = address;
                m_dll = location;
            }

            dll_export( const dll_export& instance ) = default;
            dll_export( dll_export&& instance ) = default;
            dll_export& operator=( const dll_export& instance ) = default;
            dll_export& operator=( dll_export&& instance ) = default;
            ~dll_export() = default;

            [[nodiscard]] address_t address() const noexcept {
                return m_address;
            }

            [[nodiscard]] dynamic_link_library location() const noexcept {
                return m_dll;
            }

            bool operator==( address_t other ) const noexcept {
                return m_address == other;
            }

        private:
            struct export_with_location {
                address_t                    address{ 0 };
                detail::dynamic_link_library location{};
            };

            export_with_location find_export_address( hash64_t export_name, hash64_t module_hash = 0 ) const noexcept {
                if ( export_name == 0 )
                    return { 0, {} };

                constexpr bool skip_current_module = true;
                const auto     loaded_modules = module_enumerator{ skip_current_module };

                for ( const auto& module : loaded_modules ) {
                    if ( module_hash != 0 && is_module_hash_invalid( module_hash, module.name().view() ) )
                        continue;

                    export_enumerator exports{ module.base_address() };

                    auto export_it = exports.find_if( [export_name]( const auto& pair ) -> bool {
                        const auto& [name, address] = pair;
                        return export_name == hash64_t{}( name );
                    } );

                    if ( export_it == exports.end() )
                        continue;

                    const auto& [_, address] = *export_it;
                    if ( exports.is_export_forwarded( address ) )
                        return handle_forwarded_export( address );

                    return { address, module };
                }

                return { 0, {} };
            }

            bool is_module_hash_invalid( hash64_t module_hash, std::wstring_view module_name ) const {
                // Try to compare hash of full module name
                auto full_name_hash = hash64_t{}( module_name );

                // Try to compare hash of trimmed module name (.dll)
                auto trimmed_name = module_name.substr( 0, module_name.size() - 4 );
                auto trimmed_name_hash = hash64_t{}( trimmed_name );

                // Verify both hashes
                return full_name_hash != module_hash && trimmed_name_hash != module_hash;
            }

            export_with_location handle_forwarded_export( address_t address ) const {
                // In a forwarded export, the address is a string containing
                // information about the actual export and its location
                // They are always presented as "module_name.export_name"
                auto forwarded_export_name = address.ptr<const char>();

                // Split forwarded export to module name and real export name
                auto [module_name, real_export_name] = split_forwarded_export_name( forwarded_export_name, '.' );

                // Perform call with the name of the real export, with a pre-known module
                return find_export_address( hash64_t{}( real_export_name ), hash64_t{}( module_name ) );
            }

            std::pair<std::string_view, std::string_view> split_forwarded_export_name( std::string_view view, char delimiter ) const noexcept {
                auto pos = view.find( delimiter );
                if ( pos != std::string_view::npos ) {
                    auto first_part = view.substr( 0, pos );
                    auto second_part = view.substr( pos + 1 );
                    return { first_part, second_part };
                }
                return { view, {} };
            }

            address_t                    m_address{ 0 };
            detail::dynamic_link_library m_dll{};
        };

        inline dynamic_link_library dynamic_link_library::find( hash64_t module_name ) const {
            module_enumerator modules{};
            auto              it = modules.find_if( [=, this]( const dynamic_link_library& dll ) -> bool {
                return !dll.name().view().empty() && is_module_hash_valid( module_name, dll.name().view() );
            } );
            return it != modules.end() ? *it : dynamic_link_library{};
        }

        class operation_system {
        public:
            constexpr operation_system( std::uint32_t major, std::uint32_t minor, std::uint32_t build_num ) noexcept
                : m_major_version( major ), m_minor_version( minor ), m_build_number( build_num ) { }

            [[nodiscard]] bool is_windows_11() const {
                return m_major_version == 10 && m_build_number >= 22000;
            }

            [[nodiscard]] bool is_windows_10() const {
                return m_major_version == 10 && m_build_number < 22000;
            }

            [[nodiscard]] bool is_windows_8_1() const {
                return verify_version_mask( 6, 3 );
            }

            [[nodiscard]] bool is_windows_8() const {
                return verify_version_mask( 6, 2 );
            }

            [[nodiscard]] bool is_windows_7() const {
                return verify_version_mask( 6, 1 );
            }

            [[nodiscard]] bool is_windows_xp() const {
                return verify_version_mask( 6, 0 );
            }

            [[nodiscard]] bool is_windows_vista() const {
                return verify_version_mask( 5, 1 );
            }

            [[nodiscard]] uint32_t major_version() const {
                return m_major_version;
            }

            [[nodiscard]] uint32_t minor_version() const {
                return m_minor_version;
            }

            [[nodiscard]] uint32_t build_number() const {
                return m_build_number;
            }

            [[nodiscard]] std::string formatted() const {
                return std::format( "Windows {}.{} (Build {})", m_major_version, m_minor_version, m_build_number );
            }

        private:
            bool verify_version_mask( std::uint32_t major, std::uint32_t minor ) const {
                return m_major_version == major && m_minor_version == minor;
            }

            std::uint32_t m_major_version, m_minor_version, m_build_number;
        };

        class time_formatter {
        public:
            constexpr time_formatter( std::uint64_t unix_timestamp ) noexcept: m_unix_seconds( unix_timestamp ) { }

            // \return European format: "dd.mm.yyyy hh:mm"
            [[nodiscard]] std::string format_european() const {
                auto [year, month, day, hours, minutes, _] = break_down_unix_time( m_unix_seconds );
                return std::format( "{:02}.{:02}.{} {:02}:{:02}", day, month, year, hours, minutes );
            }

            // \return American format: "mm/dd/yyyy hh:mm"
            [[nodiscard]] std::string format_american() const {
                auto [year, month, day, hours, minutes, _] = break_down_unix_time( m_unix_seconds );
                return std::format( "{:02}/{:02}/{} {:02}:{:02}", month, day, year, hours, minutes );
            }

            // \return ISO 8601 format: "yyyy-mm-ddThh:mm:ss"
            [[nodiscard]] std::string format_iso8601() const {
                auto [year, month, day, hours, minutes, seconds] = break_down_unix_time( m_unix_seconds );
                return std::format( "{}-{:02}-{:02}T{:02}:{:02}:{:02}", year, month, day, hours, minutes, seconds );
            }

            // \return Raw unix timestamp as integral
            [[nodiscard]] std::uint64_t time_since_epoch() const noexcept {
                return m_unix_seconds;
            }

            operator std::uint64_t() const noexcept {
                return m_unix_seconds;
            }

        private:
            struct timestamp {
                int32_t  year;
                uint32_t month;
                uint32_t day;
                int32_t  hours;
                int32_t  minutes;
                int32_t  seconds;
            };

            timestamp break_down_unix_time( std::uint64_t unix_timestamp ) const {
                auto time_point = std::chrono::system_clock::time_point( std::chrono::seconds( unix_timestamp ) );

                auto days = std::chrono::floor<std::chrono::days>( time_point );
                auto time_since_midnight = std::chrono::duration_cast<std::chrono::seconds>( time_point - days );

                std::chrono::year_month_day ymd{ days };
                timestamp                   stamp{ .year = static_cast<int32_t>( ymd.year() ),
                                                   .month = static_cast<uint32_t>( ymd.month() ),
                                                   .day = static_cast<uint32_t>( ymd.day() ),
                                                   .hours = static_cast<int32_t>( std::chrono::duration_cast<std::chrono::hours>( time_since_midnight ).count() ),
                                                   .minutes = static_cast<int32_t>( std::chrono::duration_cast<std::chrono::minutes>( time_since_midnight ).count() % 60 ),
                                                   .seconds = static_cast<int32_t>( time_since_midnight.count() % 60 ) };

                return stamp;
            }

            std::uint64_t m_unix_seconds;
        };

        class zoned_time {
        public:
            constexpr zoned_time( std::uint64_t unix_timestamp, std::int64_t timezone_offset ) noexcept
                : m_unix_seconds( unix_timestamp ), m_timezone_offset( timezone_offset ) { }

            [[nodiscard]] time_formatter utc() const noexcept {
                return time_formatter{ m_unix_seconds };
            }

            [[nodiscard]] time_formatter local() const noexcept {
                return time_formatter{ m_unix_seconds + m_timezone_offset };
            }

            operator std::uint64_t() const noexcept {
                return m_unix_seconds;
            }

        private:
            std::uint64_t m_unix_seconds;
            std::int64_t  m_timezone_offset;
        };

        template <typename T> concept ChronoDuration = std::is_base_of_v<std::chrono::duration<typename T::rep, typename T::period>, T>;

        // shared_data parses kernel_user_shared_data filled
        // by the operating system when the process starts.
        // The structure contains a lot of useful information
        // about the operating system. The class is a high-level
        // wrapper for parsing, which will save you from direct
        // work with raw addresses and can greatly simplify
        // your coding process.
        class shared_data {
        public:
            // The read-only user-mode address for the shared data
            // is 0x7ffe0000, both in 32-bit and 64-bit Windows.
            static constexpr shadow::address_t memory_location{ 0x7ffe0000 };

            // The difference in epochs depicted in seconds between
            // "January 1st, 1601" and "January 1st, 1970".
            static constexpr std::chrono::seconds epoch_difference{ 0x2b6109100 };

            // Windows time is always represented as 100-nanosecond
            // interval. Define a type to easily convert through.
            using hundred_ns_interval = std::chrono::duration<int64_t, std::ratio<1, 10000000>>;

        public:
            constexpr shared_data(): m_data( memory_location.ptr<win::kernel_user_shared_data>() ) { }

            [[nodiscard]] auto* raw() const noexcept {
                return m_data;
            }

            [[nodiscard]] bool kernel_debugger_present() const noexcept {
                return m_data->kernel_debugger_enabled;
            }

            [[nodiscard]] bool safe_boot_enabled() const noexcept {
                return m_data->safe_boot_mode;
            }

            [[nodiscard]] std::uint32_t boot_id() const noexcept {
                return m_data->boot_id;
            }

            [[nodiscard]] std::uint32_t physical_pages_num() const noexcept {
                return m_data->number_of_physical_pages;
            }

            [[nodiscard]] std::wstring_view system_root() const noexcept( std::is_nothrow_constructible_v<std::wstring_view> ) {
                return std::wstring_view{ m_data->nt_system_root };
            }

            [[nodiscard]] std::uint32_t timezone_id() const noexcept {
                return m_data->time_zone_id;
            }

            template <ChronoDuration Ty>
            [[nodiscard]] Ty timezone_offset() const noexcept( std::is_nothrow_constructible_v<Ty> ) {
                std::chrono::seconds seconds{ parse_time_zone_bias() };
                return std::chrono::duration_cast<Ty>( seconds );
            }

            [[nodiscard]] operation_system system() const {
                const auto major = m_data->nt_major_version;
                const auto minor = m_data->nt_minor_version;
                const auto build_num = m_data->nt_build_number;
                return operation_system{ major, minor, build_num };
            }

            // \return 100-ns interval. Timestamp starting
            // from Windows epoch, "January 1st, 1601"
            [[nodiscard]] std::uint64_t windows_epoch_timestamp() const {
                const auto system_time = m_data->system_time;
                const auto windows_time_100ns = static_cast<uint64_t>( system_time.high1_time ) << 32 | system_time.low_part;
                return windows_time_100ns;
            }

            // \return Seconds. Timestamp starting from
            // Unix epoch, "January 1st, 1970"
            [[nodiscard]] zoned_time unix_epoch_timestamp() const {
                // Windows time is measured in 100-nanosecond intervals.
                // Convert 100-ns intervals to seconds, formula is:
                // 1 second = 10,000,000 100-ns intervals
                const auto windows_time_100ns = windows_epoch_timestamp();
                const auto windows_time_seconds = std::chrono::duration_cast<std::chrono::seconds>( hundred_ns_interval( windows_time_100ns ) );
                return zoned_time{ static_cast<uint64_t>( ( windows_time_seconds - epoch_difference ).count() ), parse_time_zone_bias() };
            }

        private:
            int64_t parse_time_zone_bias() const {
                const auto bias = m_data->time_zone_bias;
                // Build 64-bit value from low_part and high1_time
                const auto bias_100ns = ( static_cast<int64_t>( bias.high1_time ) << 32 ) | bias.low_part;

                // The time offset is measured from local time to UTC,
                // in 100-ns intervals. Convert 100-ns intervals to
                // seconds (1 second = 10,000,000 100-ns intervals)
                const auto bias_seconds = std::chrono::duration_cast<std::chrono::seconds>( hundred_ns_interval( bias_100ns ) );

                // Offset from local time to UTC: if the offset is
                // positive, it means UTC is ahead, so the result
                // should be made negative.
                return -bias_seconds.count();
            }

            win::kernel_user_shared_data* m_data;
        };

#ifndef SHADOWSYSCALLS_DISABLE_CACHING

        template <typename Ty, typename Kty>
        class memory_cache {
        public:
            using value_t = Ty;
            using key_t = Kty;

        public:
            value_t operator[]( key_t export_hash ) {
                std::shared_lock lock( m_cache_mutex );
                auto             it = m_cache_map.find( export_hash );
                return it == m_cache_map.end() ? value_t{} : it->second;
            }

            void try_emplace( key_t export_hash, value_t address ) {
                std::lock_guard lock( m_cache_mutex );
                m_cache_map.try_emplace( export_hash, address );
            }

            bool exists( key_t export_hash ) {
                std::shared_lock lock( m_cache_mutex );
                return m_cache_map.find( export_hash ) != m_cache_map.end();
            }

        private:
            // Making sure that's every `cache_map` call is safe.
            mutable std::shared_mutex          m_cache_mutex{};
            std::unordered_map<key_t, value_t> m_cache_map{};
        };

        static inline memory_cache<std::uint32_t, hash64_t::underlying_t>      ssn_cache;
        static inline memory_cache<detail::dll_export, hash64_t::underlying_t> address_cache;

#endif

        template <typename Ty>
        auto convert_nulls_to_nullptrs( Ty arg ) {
            // All credits to @Debounce, huge thanks to him/her!
            //
            // Since arguments after the fourth are written on the stack,
            // the compiler will fill the lower 32 bits from int with null,
            // and the upper 32 bits will remain undefined.
            //
            // Because the syscall handler expects a (void*)-sized pointer
            // there, this address will be garbage for it, hence AV.
            // If the argument went 1/2/3/4, the compiler would generate a
            // write to ecx/edx/r8d/r9d, by x64 convention, writing to the
            // lower half of a 64 - bit register zeroes the upper part too
            // ( i.e.ecx = 0 = > rcx = 0 ), so this problem should only exist
            // on x64 for arguments after the fourth.
            // The solution would be on templates to loop through all
            // arguments and manually cast them to size_t size.

            constexpr auto is_signed_integral = std::signed_integral<Ty>;
            constexpr auto is_unsigned_integral = std::unsigned_integral<Ty>;

            using unsigned_integral_type = std::conditional_t<is_unsigned_integral, std::uintptr_t, Ty>;
            using tag_type = std::conditional_t<is_signed_integral, std::intptr_t, unsigned_integral_type>;

            return static_cast<tag_type>( arg );
        }

    } // namespace detail

    using hash32_t = detail::basic_hash<uint32_t>;
    using hash64_t = detail::basic_hash<uint64_t>;

    // Used in `shadowcall` to create a pairing
    // with simple syntax, e.g.{ "name", "name" }
    struct hashpair {
        consteval hashpair( hash64_t first_, hash64_t second_ ): first( first_ ), second( second_ ) { }

        hash64_t first;
        hash64_t second;
    };

    inline auto dll( hash64_t name ) {
        return detail::dynamic_link_library{ name };
    }

    inline auto current_module() {
        constexpr auto skip_current_module = false;
        return *( detail::module_enumerator{ skip_current_module }.begin() );
    }

    inline auto dll_export( hash64_t export_name, hash64_t module_name = 0 ) {
        return detail::dll_export{ export_name, module_name };
    }

    inline auto dlls() {
        constexpr auto skip_current_module = true;
        return detail::module_enumerator{ skip_current_module };
    }

    inline auto dll_exports( hash64_t module_name ) {
        return detail::export_enumerator{ dll( module_name ).base_address() };
    }

    inline auto shared_data() {
        return detail::shared_data{};
    }

    /* General utilities that could theoretically be useful outside the header */

    // nt_memory_allocator allocates memory based on "Nt" memory
    // functions located at "ntdll.dll".
    template <typename Ty>
    class nt_memory_allocator {
    public:
        using value_type = Ty;

        nt_memory_allocator() noexcept = default;

        template <typename U>
        constexpr nt_memory_allocator( const nt_memory_allocator<U>& ) noexcept { }

        [[nodiscard]] Ty* allocate( std::size_t n ) const {
            std::size_t size = n * sizeof( Ty );
            void*       ptr = nt_virtual_alloc( nullptr, size, memory_commit | memory_reserve, page_rwx );
            if ( !ptr )
                throw std::bad_alloc();
            return static_cast<Ty*>( ptr );
        }

        template <typename PtrTy>
        void deallocate( PtrTy p, std::size_t n ) noexcept {
            std::size_t size = n * sizeof( Ty );
            nt_virtual_free( static_cast<void*>( p ), size, memory_release );
        }

    private:
        using NTSTATUS = std::int32_t;

        void* nt_virtual_alloc( void* address, std::uint64_t allocation_size, std::uint32_t allocation_t, std::uint32_t protect ) const {
            void*            current_process{ reinterpret_cast<void*>( -1 ) };
            void*            base_address = address;
            std::uint64_t    region_size = allocation_size;
            static address_t allocation_procedure{ dll_export( "NtAllocateVirtualMemory", "ntdll.dll" ).address() };

            auto result = allocation_procedure.execute<NTSTATUS>( current_process, &base_address, 0ull, &region_size, allocation_t & 0xFFFFFFC0, protect );
            return result >= 0 ? base_address : nullptr;
        }

        bool nt_virtual_free( void* address, std::uint64_t allocation_size, std::uint32_t flags ) const {
            NTSTATUS         result{ 0 };
            auto             region_size{ allocation_size };
            void*            base_address = address;
            void*            current_process{ reinterpret_cast<void*>( -1 ) };
            static address_t free_procedure{ dll_export( "NtFreeVirtualMemory", "ntdll.dll" ).address() };

            if ( ( flags & 0xFFFF3FFC ) != 0 || ( flags & 0x8003 ) == 0x8000 && allocation_size )
                result = -0x3FFFFFF3;

            result = free_procedure.execute<NTSTATUS>( current_process, &base_address, &region_size, flags );
            if ( result == -0x3FFFFFBB )
                result = free_procedure.execute<NTSTATUS>( current_process, &base_address, &region_size, flags );

            return result >= 0;
        }

        static constexpr auto memory_commit{ 0x1000 };
        static constexpr auto memory_reserve{ 0x2000 };
        static constexpr auto memory_release{ 0x8000 };
        static constexpr auto page_rwx{ 0x40 };
    };

    template <std::uint32_t shell_size>
    class shellcode {
    public:
        template <class... Args>
            requires( ( std::is_convertible_v<Args, std::uint8_t> && ... ) && shell_size != 0 )
        shellcode( Args&&... list ) noexcept: m_shellcode{ static_cast<std::uint8_t>( std::forward<Args&&>( list ) )... } { }

        ~shellcode() {
            if ( m_memory == nullptr ) {
                return;
            }

            m_allocator.deallocate( m_memory, shell_size );
            m_memory = nullptr;
        }

        void setup() {
            m_memory = m_allocator.allocate( shell_size );
            if ( m_memory != nullptr ) {
                memcpy( m_memory, m_shellcode.data(), shell_size );
                m_shellcode_fn = m_memory;
            }
        }

        template <std::integral Ty = std::uint8_t>
        [[nodiscard]] constexpr Ty read( std::size_t index ) const noexcept {
            return m_shellcode[index];
        }

        template <std::integral Ty>
        constexpr void write( std::size_t index, Ty value ) noexcept {
            *reinterpret_cast<Ty*>( &m_shellcode[index] ) = value;
        }

        template <typename Ty, typename... Args>
            requires( std::is_default_constructible_v<Ty> )
        [[nodiscard]] Ty execute( Args&&... args ) const noexcept {
            if ( !m_shellcode_fn ) {
                return Ty{};
            }
            return reinterpret_cast<Ty( __stdcall* )( Args... )>( m_shellcode_fn )( args... );
        }

        template <typename Ty = void, typename PointerTy = std::add_pointer_t<Ty>>
        [[nodiscard]] constexpr PointerTy ptr() const noexcept {
            return static_cast<PointerTy>( m_shellcode_fn );
        }

    private:
        void*                                m_shellcode_fn = nullptr;
        void*                                m_memory = nullptr;
        nt_memory_allocator<std::uint8_t>    m_allocator;
        std::array<std::uint8_t, shell_size> m_shellcode;
    };

    // Names for generic error codes
    enum errc : std::uint32_t {
        none = 0,        // No error occured
        ssn_not_found,   // System Service Number can't be found
        export_not_found // Such export doesn't exist
    };

    template <typename Ty, typename ErrTy>
        requires( std::is_enum_v<ErrTy> )
    struct call_result_t {
        Ty                   value;
        std::optional<ErrTy> error;

        operator Ty() {
            return value;
        }
    };

    template <typename Ty>
    class syscaller {
    public:
        // Parser needs to return std::optional<uint32_t> and accept (syscaller&, address_t)
        using ssn_parser_t = detail::stack_function<std::optional<uint32_t>( syscaller&, address_t )>;
        using is_return_type_ntstatus = std::is_same<std::remove_cv_t<Ty>, long>;

        static_assert( std::is_fundamental_v<Ty>, "Nt/Zw functions cannot return the type you specified."
                                                  "Type should be fundamental" );

    public:
        constexpr syscaller( hash64_t syscall_name ) noexcept
            : m_name_hash( syscall_name ), m_service_number( 0 ), m_last_error( std::nullopt ),
              m_ssn_parser( [this]( [[maybe_unused]] syscaller& instance, address_t address ) {
                  return this->default_ssn_parser( address );
              } ) { }

        template <typename... Args>
            requires( shadow::is_x64 )
        call_result_t<Ty, shadow::errc> operator()( Args&&... args ) noexcept {
            auto parse_result = resolve_service_number();
            if ( !parse_result || m_last_error ) {
                // Return -1 if type is NTSTATUS (call failed),
                // otherwise return default-constructible (0)
                return is_return_type_ntstatus::value ? call_result_t{ Ty{ -1 }, get_last_error() } : call_result_t{ Ty{}, get_last_error() };
            } else {
                m_service_number = *parse_result;
            }
            setup_shellcode();
            return { m_shellcode.execute<Ty>( shadow::detail::convert_nulls_to_nullptrs( args )... ), get_last_error() };
        }

        void set_custom_ssn_parser( ssn_parser_t parser ) {
            m_ssn_parser.swap( parser );
        }

        void set_last_error( errc error ) noexcept {
            m_last_error.emplace( error );
        }

        std::optional<errc> get_last_error() const noexcept {
            return m_last_error;
        }

    private:
        void setup_shellcode() noexcept {
            m_shellcode.write<std::uint32_t>( 6, m_service_number );
            m_shellcode.setup();
        }

        std::optional<uint32_t> resolve_service_number() {
#ifndef SHADOWSYSCALLS_DISABLE_CACHING
            auto cached_ssn = detail::ssn_cache[m_name_hash];
            if ( cached_ssn != 0 )
                return cached_ssn;
#endif
            auto mod_export = dll_export( m_name_hash );
            if ( mod_export == 0 ) {
                set_last_error( errc::export_not_found );
                return std::nullopt;
            }

            auto parsed_ssn = m_ssn_parser( *this, mod_export.address() );
#ifndef SHADOWSYSCALLS_DISABLE_CACHING
            if ( parsed_ssn )
                detail::ssn_cache.try_emplace( m_name_hash, *parsed_ssn );
#endif
            return parsed_ssn;
        }

        // Syscall ID is at an offset of 4 bytes from the specified address.
        // \note Not considering the situation when EDR hook is installed
        // Learn more here: https://github.com/annihilatorq/shadow_syscall/issues/1
        std::uint32_t default_ssn_parser( address_t export_address ) {
            auto address = export_address.ptr<std::uint8_t>();
            for ( auto i = 0; i < 24; ++i ) {
                if ( address[i] == 0x4c && address[i + 1] == 0x8b && address[i + 2] == 0xd1 && address[i + 3] == 0xb8 && address[i + 6] == 0x00 &&
                     address[i + 7] == 0x00 ) {
                    return *reinterpret_cast<std::uint32_t*>( &address[i + 4] );
                }
            }
            set_last_error( errc::ssn_not_found );
            return 0;
        }

    private:
        hash64_t::underlying_t m_name_hash;
        std::uint32_t          m_service_number;
        std::optional<errc>    m_last_error;
        ssn_parser_t           m_ssn_parser;

        shellcode<13> m_shellcode = {
            0x49, 0x89, 0xCA,                         // mov r10, rcx
            0x48, 0xC7, 0xC0, 0x3F, 0x10, 0x00, 0x00, // mov rax, ssn
            0x0F, 0x05,                               // syscall
            0xC3                                      // ret
        };
    };

    template <typename Ty>
    class importer {
    public:
        static_assert( std::is_default_constructible_v<Ty>, "Return type must be default-constructible" );

    public:
        explicit importer( hash64_t import_name, hash64_t module_name = 0 ): m_export( get_export( import_name, module_name ) ) { }

        template <typename... Args>
        Ty operator()( Args&&... args ) noexcept {
            return m_call_result = m_export.address().execute<Ty>( shadow::detail::convert_nulls_to_nullptrs( args )... );
        }

        [[nodiscard]] auto export_location() const noexcept {
            return m_export.location();
        }

        operator Ty() const {
            return m_call_result;
        }

    private:
        detail::dll_export get_export( hash64_t export_name, hash64_t module_name ) {
#ifndef SHADOWSYSCALLS_DISABLE_CACHING
            detail::dll_export module = detail::address_cache[export_name.raw()];
            if ( module == 0 ) {
                module = dll_export( export_name, module_name );
                detail::address_cache.try_emplace( export_name.raw(), module );
            }

            return module;
#else
            return dll_export( export_name );
#endif
        }

        Ty                 m_call_result{};
        detail::dll_export m_export{ 0 };
    };
} // namespace shadow

template <>
struct std::hash<shadow::address_t> {
    size_t operator()( const shadow::address_t& instance ) const noexcept {
        return std::hash<shadow::address_t::underlying_t>()( instance.raw() );
    }
};

template <>
struct std::hash<shadow::hash32_t> {
    size_t operator()( const shadow::hash32_t& instance ) const noexcept {
        return std::hash<shadow::hash32_t::underlying_t>()( instance.raw() );
    }
};

template <>
struct std::hash<shadow::hash64_t> {
    size_t operator()( const shadow::hash64_t& instance ) const noexcept {
        return std::hash<shadow::hash64_t::underlying_t>()( instance.raw() );
    }
};

template <typename Ty = long, class... Args>
    requires( shadow::is_x64 )
inline shadow::call_result_t<Ty, shadow::errc> shadowsyscall( shadow::hash64_t syscall_name, Args&&... args ) {
    shadow::syscaller<std::remove_cv_t<Ty>> sc{ syscall_name };
    auto                                    result = sc( shadow::detail::convert_nulls_to_nullptrs( args )... );
    return shadow::call_result_t{ result, sc.get_last_error() };
}

template <typename Ty = std::monostate, class... Args>
inline shadow::importer<Ty> shadowcall( shadow::hash64_t export_name, Args&&... args ) {
    shadow::importer<Ty> importer{ export_name };
    importer( std::forward<Args>( args )... );
    return importer;
}

template <typename Ty = std::monostate, class... Args>
inline shadow::importer<Ty> shadowcall( shadow::hashpair export_and_module_names, Args&&... args ) {
    const auto& [export_name, module_name] = export_and_module_names;
    shadow::importer<Ty> importer{ export_name, module_name };
    importer( std::forward<Args>( args )... );
    return importer;
}

#endif
