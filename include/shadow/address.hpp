#ifndef SHADOW_ADDRESS_HPP
#define SHADOW_ADDRESS_HPP

#include <cstdint>
#include <ostream>
#include <type_traits>

namespace shadow {
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
        [[nodiscard]] Ty execute( Args... args ) const noexcept {
            if ( m_address == 0 ) {
                if constexpr ( std::is_pointer_v<Ty> )
                    return nullptr;
                else
                    return Ty{};
            }

            return reinterpret_cast<Ty( __stdcall* )( Args... )>( m_address )( args... );
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
} // namespace shadow

#endif // SHADOW_ADDRESS_HPP
