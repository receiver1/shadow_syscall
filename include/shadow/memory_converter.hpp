#ifndef SHADOW_MEMORY_CONVERTER_HPP
#define SHADOW_MEMORY_CONVERTER_HPP

#include <cmath>
#include <concepts>

namespace shadow {
class memory_converter {
  constexpr static auto conversion_value = 1000.0;

 public:
  template <std::integral Ty>
  explicit memory_converter(Ty bytes) noexcept : m_bytes(bytes) {}

  [[nodiscard]] auto as_bytes() const noexcept { return m_bytes; }

  [[nodiscard]] auto as_kilobytes() const noexcept {
    return static_cast<std::double_t>(m_bytes) / conversion_value;
  }

  [[nodiscard]] auto as_megabytes() const noexcept {
    return static_cast<std::double_t>(m_bytes) /
           (std::pow(conversion_value, 2));
  }

  [[nodiscard]] auto as_gigabytes() const noexcept {
    return static_cast<std::double_t>(m_bytes) /
           (std::pow(conversion_value, 3));
  }

  // Use implicit conversion
  operator std::size_t() const noexcept { return m_bytes; }

 private:
  std::size_t m_bytes;
};
}  // namespace shadow

#endif  // SHADOW_MEMORY_CONVERTER_HPP
