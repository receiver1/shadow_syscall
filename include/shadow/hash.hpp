#ifndef SHADOW_HASH_HPP
#define SHADOW_HASH_HPP

#include <cstdint>
#include <ostream>

namespace shadow {
    namespace detail {
        template <std::integral Ty>
        consteval Ty generate_compilation_seed() {
            Ty hash = __cplusplus;

            // \note: Fix note since 27.08.2024:
            // We cannot use __TIME__ or alternatives here since
            // such macros represent the build time of a translation
            // unit, not the build time of the entire project.
            for ( auto c : __FILE__ )
                hash ^= static_cast<Ty>( c ) * 0x1928231;

            return hash;
        }

        template <typename Ty>
        concept ArrayLike = requires( Ty t ) {
            { t.size() } -> std::convertible_to<std::size_t>; // Size methods required
            {
                t[0]
            } -> std::convertible_to<typename Ty::value_type>; // Should be accessable by
                                                               // index
        };

        // basic_hash class provides compile-time and runtime hash
        // computation. Uses FNV-1a hashing algorithm.
        // Case-insensitive by default.
        template <std::integral ValTy>
        class basic_hash {
        public:
            using underlying_t = ValTy;
            constexpr static bool case_sensitive = false;
            constexpr static ValTy FNV_prime = ( sizeof( ValTy ) == 4 ) ? 16777619u : 1099511628211ull;

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

            consteval basic_hash( const char* string, std::size_t len ) {
                for ( auto i = 0; i < len; i++ )
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
    } // namespace detail

    using hash32_t = detail::basic_hash<uint32_t>;
    using hash64_t = detail::basic_hash<uint64_t>;

    namespace literals {
        consteval hash32_t operator""_h32( const char* str, std::size_t len ) noexcept {
            return hash32_t{ str, len };
        }

        consteval hash64_t operator""_h64( const char* str, std::size_t len ) noexcept {
            return hash64_t{ str, len };
        }
    } // namespace literals
} // namespace shadow

#endif // SHADOW_HASH_HPP
