#ifndef SHADOW_HARDWARE_PROCESSOR_HPP
#define SHADOW_HARDWARE_PROCESSOR_HPP

#include <array>
#include <bitset>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "hash.hpp"
#include "memory_converter.hpp"

namespace shadow {
    class hardware_processor {
        class caches_info;

    public:
        hardware_processor() noexcept {
            parse_cpu_fields();
        }

        [[nodiscard]] bool is_intel() const noexcept {
            return m_is_intel;
        }
        [[nodiscard]] bool is_amd() const noexcept {
            return m_is_amd;
        }

        // \return caches returns CPU caches information
        // (only works for Intel so far)
        [[nodiscard]] std::optional<caches_info> caches() const noexcept {
            if ( is_intel() ) {
                return caches_info{};
            } else {
                // Not really sure about processors other than Intel.
                // Any good PR with a solution is greatly appreciated
                return std::nullopt;
            }
        }

        // \return returns processor vendor name
        [[nodiscard]] std::string vendor() const noexcept {
            return m_vendor;
        }

        // \return returns cpu full name
        [[nodiscard]] std::string brand() const noexcept {
            return m_brand;
        }

        // \return returns true if SSE (Streaming SIMD Extensions) is supported
        [[nodiscard]] bool supports_sse() const noexcept {
            return m_standard_features_edx[25];
        }

        // \return returns true if SSE2 is supported by the CPU
        [[nodiscard]] bool supports_sse2() const noexcept {
            return m_standard_features_edx[26];
        }

        // \return returns true if SSE3 is supported by the CPU
        [[nodiscard]] bool supports_sse3() const noexcept {
            return m_standard_features_ecx[0];
        }

        // \return returns true if SSSE3 is supported by the CPU
        [[nodiscard]] bool supports_ssse3() const noexcept {
            return m_standard_features_ecx[9];
        }

        // \return returns true if SSE4.1 is supported by the CPU
        [[nodiscard]] bool supports_sse4_1() const noexcept {
            return m_standard_features_ecx[19];
        }

        // \return returns true if SSE4.2 is supported by the CPU
        [[nodiscard]] bool supports_sse4_2() const noexcept {
            return m_standard_features_ecx[20];
        }

        // AVX Instruction Set
        // \return returns true if AVX (Advanced Vector Extensions) is supported
        [[nodiscard]] bool supports_avx() const noexcept {
            return m_standard_features_ecx[28];
        }

        // \return returns true if AVX2 is supported by the CPU
        [[nodiscard]] bool supports_avx2() const noexcept {
            return m_extended_features_ebx[5];
        }

        // \return returns true if AVX-512 Foundation is supported
        [[nodiscard]] bool supports_avx512f() const noexcept {
            return m_extended_features_ebx[16];
        }

        // \return returns true if AVX-512 Prefetch is supported
        [[nodiscard]] bool supports_avx512pf() const noexcept {
            return m_extended_features_ebx[26];
        }

        // \return returns true if AVX-512 Exponential and Reciprocal is supported
        [[nodiscard]] bool supports_avx512er() const noexcept {
            return m_extended_features_ebx[27];
        }

        // \return returns true if AVX-512 Conflict Detection is supported
        [[nodiscard]] bool supports_avx512cd() const noexcept {
            return m_extended_features_ebx[28];
        }

        // AMD-Specific Extensions
        // \return returns true if SSE4a is supported on AMD CPUs
        [[nodiscard]] bool supports_sse4a() const noexcept {
            return m_is_amd && m_amd_extended_features_ecx[6];
        }

        // \return returns true if LAHF/SAHF is supported in 64-bit mode
        [[nodiscard]] bool supports_lahf() const noexcept {
            return m_amd_extended_features_ecx[0];
        }

        // \return returns true if ABM (Advanced Bit Manipulation) is supported on AMD
        // CPUs
        [[nodiscard]] bool supports_abm() const noexcept {
            return m_is_amd && m_amd_extended_features_ecx[5];
        }

        // \return returns true if XOP (Extended Operations) is supported on AMD CPUs
        [[nodiscard]] bool supports_xop() const noexcept {
            return m_is_amd && m_amd_extended_features_ecx[11];
        }

        // \return returns true if TBM (Trailing Bit Manipulation) is supported on AMD
        // CPUs
        [[nodiscard]] bool supports_tbm() const noexcept {
            return m_is_amd && m_amd_extended_features_ecx[21];
        }

        // \return returns true if MMX extensions are supported on AMD CPUs
        [[nodiscard]] bool supports_mmxext() const noexcept {
            return m_is_amd && m_amd_extended_features_edx[22];
        }

        // Other Instruction Set Extensions
        // \return returns true if PCLMULQDQ (Carry-Less Multiplication) is supported
        [[nodiscard]] bool supports_pclmulqdq() const noexcept {
            return m_standard_features_ecx[1];
        }

        // \return returns true if MONITOR/MWAIT instructions are supported
        [[nodiscard]] bool supports_monitor() const noexcept {
            return m_standard_features_ecx[3];
        }

        // \return returns true if FMA (Fused Multiply-Add) is supported
        [[nodiscard]] bool supports_fma() const noexcept {
            return m_standard_features_ecx[12];
        }

        // \return returns true if CMPXCHG16B is supported by the CPU
        [[nodiscard]] bool supports_cmpxchg16b() const noexcept {
            return m_standard_features_ecx[13];
        }

        // \return returns true if MOVBE (Move with Byte Swap) is supported
        [[nodiscard]] bool supports_movbe() const noexcept {
            return m_standard_features_ecx[22];
        }

        // \return returns true if POPCNT (Population Count) instruction is supported
        [[nodiscard]] bool supports_popcnt() const noexcept {
            return m_standard_features_ecx[23];
        }

        // \return returns true if AES-NI (Advanced Encryption Standard) is supported
        [[nodiscard]] bool supports_aes() const noexcept {
            return m_standard_features_ecx[25];
        }

        // \return returns true if XSAVE/XRSTOR instructions are supported
        [[nodiscard]] bool supports_xsave() const noexcept {
            return m_standard_features_ecx[26];
        }

        // \return returns true if OSXSAVE (Operating System XSave) is supported
        [[nodiscard]] bool supports_osxsave() const noexcept {
            return m_standard_features_ecx[27];
        }

        // \return returns true if RDRAND (Hardware Random Number Generator) is
        // supported
        [[nodiscard]] bool supports_rdrand() const noexcept {
            return m_standard_features_ecx[30];
        }

        // \return returns true if F16C (16-bit Floating-Point Conversion) is
        // supported
        [[nodiscard]] bool supports_f16c() const noexcept {
            return m_standard_features_ecx[29];
        }

        // Miscellaneous Features
        // \return returns true if MSR (Model-Specific Registers) are supported
        [[nodiscard]] bool supports_msr() const noexcept {
            return m_standard_features_edx[5];
        }

        // \return returns true if CMPXCHG8 instruction is supported
        [[nodiscard]] bool supports_cx8() const noexcept {
            return m_standard_features_edx[8];
        }

        // \return returns true if SYSENTER/SYSEXIT instructions are supported
        [[nodiscard]] bool supports_sep() const noexcept {
            return m_standard_features_edx[11];
        }

        // \return returns true if CMOV (Conditional Move) is supported
        [[nodiscard]] bool supports_cmov() const noexcept {
            return m_standard_features_edx[15];
        }

        // \return returns true if CLFLUSH (Cache Line Flush) instruction is supported
        [[nodiscard]] bool supports_clflush() const noexcept {
            return m_standard_features_edx[19];
        }

        // \return returns true if MMX (MultiMedia Extensions) is supported
        [[nodiscard]] bool supports_mmx() const noexcept {
            return m_standard_features_edx[23];
        }

        // \return returns true if FXSAVE/FXRSTOR instructions are supported
        [[nodiscard]] bool supports_fxsr() const noexcept {
            return m_standard_features_edx[24];
        }

        // Extended Features
        // \return returns true if FSGSBASE instructions are supported
        [[nodiscard]] bool supports_fsgsbase() const noexcept {
            return m_extended_features_ebx[0];
        }

        // \return returns true if BMI1 (Bit Manipulation Instructions Set 1) is
        // supported
        [[nodiscard]] bool supports_bmi1() const noexcept {
            return m_extended_features_ebx[3];
        }

        // \return returns true if HLE (Hardware Lock Elision) is supported on Intel
        // CPUs
        [[nodiscard]] bool supports_hle() const noexcept {
            return m_is_intel && m_extended_features_ebx[4];
        }

        // \return returns true if BMI2 (Bit Manipulation Instructions Set 2) is
        // supported
        [[nodiscard]] bool supports_bmi2() const noexcept {
            return m_extended_features_ebx[8];
        }

        // \return returns true if Enhanced REP MOVSB/STOSB is supported
        [[nodiscard]] bool supports_erms() const noexcept {
            return m_extended_features_ebx[9];
        }

        // \return returns true if INVPCID (Invalidate Process-Context Identifier) is
        // supported
        [[nodiscard]] bool supports_invpcid() const noexcept {
            return m_extended_features_ebx[10];
        }

        // \return returns true if RTM (Restricted Transactional Memory) is supported
        // on Intel CPUs
        [[nodiscard]] bool supports_rtm() const noexcept {
            return m_is_intel && m_extended_features_ebx[11];
        }

        // \return returns true if RDSEED (Random Seed) instruction is supported
        [[nodiscard]] bool supports_rdseed() const noexcept {
            return m_extended_features_ebx[18];
        }

        // \return returns true if ADX (Multi-Precision Add-Carry Instruction
        // Extensions) is supported
        [[nodiscard]] bool supports_adx() const noexcept {
            return m_extended_features_ebx[19];
        }

        // \return returns true if SHA (Secure Hash Algorithm) instructions are
        // supported
        [[nodiscard]] bool supports_sha() const noexcept {
            return m_extended_features_ebx[29];
        }

        // \return returns true if PREFETCHWT1 instruction is supported
        [[nodiscard]] bool supports_prefetchwt1() const noexcept {
            return m_extended_features_ecx[0];
        }

        // AMD and Intel-Specific Features
        // \return returns true if SYSCALL/SYSRET instructions are supported on Intel
        // CPUs
        [[nodiscard]] bool supports_syscall() const noexcept {
            return m_is_intel && m_amd_extended_features_edx[11];
        }

        // \return returns true if LZCNT (Leading Zero Count) is supported on Intel
        // CPUs
        [[nodiscard]] bool supports_lzcnt() const noexcept {
            return m_is_intel && m_amd_extended_features_ecx[5];
        }

        // \return returns true if RDTSCP (Read Time-Stamp Counter) instruction is
        // supported on Intel CPUs
        [[nodiscard]] bool supports_rdtscp() const noexcept {
            return m_is_intel && m_amd_extended_features_edx[27];
        }

        // clang-format on

    private:
        constexpr static auto cpuid_base = 0x80000000;

        class caches_info {
        public:
            caches_info() noexcept {
                parse_cache_info();
            }

            [[nodiscard]] auto l1_size() const noexcept {
                return memory_converter{ m_cache_sizes[0] };
            }

            [[nodiscard]] auto l2_size() const noexcept {
                return memory_converter{ m_cache_sizes[1] };
            }

            [[nodiscard]] auto l3_size() const noexcept {
                return memory_converter{ m_cache_sizes[2] };
            }

            [[nodiscard]] auto total_size() const noexcept {
                return memory_converter{ l1_size() + l2_size() + l3_size() };
            }

        private:
            void parse_cache_info() noexcept {
                std::array<std::int32_t, 4> cpu_info{};

                // CPUID for cache hierarchy (EAX=4)
                for ( int i = 0;; ++i ) {
                    __cpuidex( cpu_info.data(), 4, i );

                    // Check cache type (bits [3:0] of EAX) - 0 means no more caches
                    std::int32_t cache_type = cpu_info[0] & 0xF;
                    if ( cache_type == 0 )
                        break; // No more caches

                    // Extract cache level (bits [7:5] of EAX)
                    std::int32_t cache_level = ( cpu_info[0] >> 5 ) & 0x7;
                    std::int32_t cache_size = ( ( cpu_info[1] >> 22 ) + 1 ) *   // Number of sets
                                              ( ( cpu_info[1] & 0xFFF ) + 1 ) * // Line size (in bytes)
                                              ( ( cpu_info[2] & 0x3FF ) + 1 ) * // Associativity (ways of set associativity)
                                              ( cpu_info[3] + 1 );              // Number of partitions

                    // Adjust cache_level (1-3) to array index (0-2)
                    m_cache_sizes[cache_level - 1] = cache_size;
                }
            }

            std::array<std::int32_t, 3> m_cache_sizes;
        };

        // https://en.wikipedia.org/wiki/CPUID
        void parse_cpu_fields() noexcept {
            std::array<int, 4> cpu_info{};

            // Get highest standard CPUID function ID
            __cpuid( cpu_info.data(), 0 );
            m_max_standard_id = cpu_info[0];

            // Query and store information for all standard CPUID functions
            for ( std::int32_t i = 0; i <= m_max_standard_id; ++i ) {
                __cpuidex( cpu_info.data(), i, 0 );
                m_standard_data.push_back( cpu_info );
            }

            m_vendor = extract_cpu_vendor();

            // Read standard feature flags from function
            // 0x00000001 (ECX and EDX registers)
            if ( m_max_standard_id >= 1 ) {
                m_standard_features_ecx = m_standard_data[1][2]; // ECX features
                m_standard_features_edx = m_standard_data[1][3]; // EDX features
            }

            // Read extended feature flags from function
            // 0x00000007 (EBX and ECX registers)
            if ( m_max_standard_id >= 7 ) {
                m_extended_features_ebx = m_standard_data[7][1]; // EBX features
                m_extended_features_ecx = m_standard_data[7][2]; // ECX features
            }

            // To determine the highest supported extended CPUID
            // function, call CPUID with EAX = 0x80000000
            __cpuid( cpu_info.data(), cpuid_base );
            m_max_extended_id = cpu_info[0];

            // Gather information for all extended CPUID
            // functions starting from 0x80000000
            for ( std::int32_t i = cpuid_base; i <= m_max_extended_id; ++i ) {
                __cpuidex( cpu_info.data(), i, 0 );
                m_extended_data.push_back( cpu_info );
            }

            // Read extended feature flags (ECX and EDX)
            // from function 0x80000001
            if ( m_max_extended_id >= cpuid_base + 1 ) {
                m_amd_extended_features_ecx = m_extended_data[1][2]; // ECX features
                m_amd_extended_features_edx = m_extended_data[1][3]; // EDX features
            }

            // Extract the processor brand string from
            // functions 0x80000002 to 0x80000004
            if ( m_max_extended_id >= cpuid_base + 4 ) {
                m_brand = extract_cpu_brand();
            }
        }

        std::string extract_cpu_vendor() noexcept {
            using namespace shadow::literals;

            std::array<char, 12> vendor_bytes{};
            std::array<int, 3> vendor_ids = { m_standard_data[0][1], m_standard_data[0][3], m_standard_data[0][2] };
            memcpy( vendor_bytes.data(), vendor_ids.data(), sizeof( vendor_ids ) );

            const std::string vendor_str( vendor_bytes.data(), vendor_bytes.size() );
            const auto hashed_str = hash64_t{}( vendor_str );

            // Intel || Intel (rare)
            if ( hashed_str == "GenuineIntel"_h64 || hashed_str == "GenuineIotel"_h64 ) {
                m_is_intel = true;
            }
            // AMD || Early samples of AMD K5 processor
            else if ( hashed_str == "AuthenticAMD"_h64 || hashed_str == "AMD ISBETTER"_h64 ) {
                m_is_amd = true;
            }

            return vendor_str;
        }

        std::string extract_cpu_brand() const noexcept {
            std::array<char, 48> vendor_bytes{};
            memcpy( vendor_bytes.data(), m_extended_data[2].data(), sizeof( m_extended_data[2] ) );
            memcpy( vendor_bytes.data() + 16, m_extended_data[3].data(), sizeof( m_extended_data[3] ) );
            memcpy( vendor_bytes.data() + 32, m_extended_data[4].data(), sizeof( m_extended_data[4] ) );
            return std::string( vendor_bytes.begin(), vendor_bytes.end() );
        }

        std::int32_t m_max_standard_id{ 0 };
        std::int32_t m_max_extended_id{ 0 };
        std::string m_vendor;
        std::string m_brand;
        bool m_is_intel{ false };
        bool m_is_amd{ false };
        std::bitset<32> m_standard_features_ecx;
        std::bitset<32> m_standard_features_edx;
        std::bitset<32> m_extended_features_ebx;
        std::bitset<32> m_extended_features_ecx;
        std::bitset<32> m_amd_extended_features_ecx;
        std::bitset<32> m_amd_extended_features_edx;
        std::vector<std::array<int, 4>> m_standard_data;
        std::vector<std::array<int, 4>> m_extended_data;
    };
} // namespace shadow

#endif // SHADOW_HARDWARE_PROCESSOR_HPP
