/* Copyright (C) 2026 FixCraft Inc. AGPL-3.0-or-later. */

#include "module_header.hpp"

#include <algorithm>

namespace ito::module {
namespace {

constexpr std::size_t kFingerprintStart = kModuleHeaderPrefix.size();
constexpr std::size_t kFingerprintEnd = kFingerprintStart + kFingerprintDigits;
constexpr std::size_t kServiceStart = kFingerprintEnd + 1U;

int hex_value(std::byte byte) noexcept {
    const auto value = std::to_integer<unsigned char>(byte);
    if (value >= '0' && value <= '9') return value - '0';
    if (value >= 'a' && value <= 'f') return value - 'a' + 10;
    return -1;
}

// The bytes a canonical service name may contain. Segment rules are checked
// once the name is complete.
bool service_byte(unsigned char value) noexcept {
    return (value >= 'a' && value <= 'z') || (value >= '0' && value <= '9') ||
           value == '.' || value == '-' || value == '_';
}

}  // namespace

bool valid_service_name(std::string_view name) noexcept {
    if (name.empty() || name.size() > kMaxServiceBytes) return false;
    if (name == "yume" || name.starts_with("yume.")) return false;
    bool at_segment_start = true;
    bool previous_is_alphanumeric = false;
    for (const char character : name) {
        const auto byte = static_cast<unsigned char>(character);
        const bool alphanumeric =
            (byte >= 'a' && byte <= 'z') || (byte >= '0' && byte <= '9');
        if (alphanumeric) {
            at_segment_start = false;
            previous_is_alphanumeric = true;
        } else if (byte == '.') {
            if (at_segment_start || !previous_is_alphanumeric) return false;
            at_segment_start = true;
            previous_is_alphanumeric = false;
        } else if (byte == '-' || byte == '_') {
            if (at_segment_start) return false;
            previous_is_alphanumeric = false;
        } else {
            return false;
        }
    }
    return !at_segment_start && previous_is_alphanumeric;
}

HeaderParse parse_module_header(std::span<const std::byte> input,
                                std::string_view service) noexcept {
    const std::size_t available = std::min(input.size(), kMaxHeaderBytes);
    for (std::size_t index = 0U; index < available; ++index) {
        const auto byte = input[index];
        if (index < kFingerprintStart) {
            if (std::to_integer<char>(byte) != kModuleHeaderPrefix[index])
                return {HeaderStatus::Malformed, 0U, {}};
        } else if (index < kFingerprintEnd) {
            if (hex_value(byte) < 0) return {HeaderStatus::Malformed, 0U, {}};
        } else if (index == kFingerprintEnd) {
            if (std::to_integer<char>(byte) != ' ')
                return {HeaderStatus::Malformed, 0U, {}};
        } else if (std::to_integer<char>(byte) == '\n') {
            const std::string_view named(
                reinterpret_cast<const char*>(input.data()) + kServiceStart,
                index - kServiceStart);
            if (!valid_service_name(named))
                return {HeaderStatus::Malformed, 0U, {}};
            if (named != service) return {HeaderStatus::OtherService, 0U, {}};
            HeaderParse parsed{HeaderStatus::Accepted, index + 1U, {}};
            for (std::size_t digit = 0U; digit < parsed.principal.size();
                 ++digit) {
                const auto high =
                    hex_value(input[kFingerprintStart + 2U * digit]);
                const auto low =
                    hex_value(input[kFingerprintStart + 2U * digit + 1U]);
                parsed.principal[digit] =
                    static_cast<std::uint8_t>((high << 4) | low);
            }
            return parsed;
        } else if (index - kServiceStart >= kMaxServiceBytes ||
                   !service_byte(std::to_integer<unsigned char>(byte))) {
            return {HeaderStatus::Malformed, 0U, {}};
        }
    }
    return {HeaderStatus::Incomplete, 0U, {}};
}

}  // namespace ito::module
