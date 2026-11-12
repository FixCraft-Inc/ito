/* Copyright (C) 2026 FixCraft Inc. AGPL-3.0-or-later. */

// The line yumed writes before each stream it hands to a module, and the
// service-name grammar inside it. Parsing is pure, bounded and allocation
// free. A parse reports how many bytes it consumed and never looks past them,
// so stream bytes that follow the header in the same read stay with the
// caller.

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

namespace ito::module {

// The client's composite key fingerprint, as yumed authenticated it.
using Principal = std::array<std::uint8_t, 32>;

inline constexpr std::string_view kModuleHeaderPrefix = "yume-module 1 ";
inline constexpr std::size_t kFingerprintDigits = 64U;
inline constexpr std::size_t kMaxServiceBytes = 64U;
inline constexpr std::size_t kMaxHeaderBytes = kModuleHeaderPrefix.size() +
                                               kFingerprintDigits + 1U +
                                               kMaxServiceBytes + 1U;
static_assert(kMaxHeaderBytes == 144U);

// YUME's canonical service-name grammar, narrowed to Ito's 64 bytes, without
// the names YUME reserves for itself. YUME's src/common/service_name.hpp
// owns the grammar. A module cannot include that private header, so
// module_test.cpp carries vectors for this copy.
[[nodiscard]] bool valid_service_name(std::string_view name) noexcept;

enum class HeaderStatus {
    Incomplete,
    Accepted,
    Malformed,
    OtherService,
};

struct HeaderParse final {
    HeaderStatus status{HeaderStatus::Incomplete};
    // Bytes of the header line, newline included, when Accepted.
    std::size_t consumed{0U};
    // The fingerprint's 32 bytes, when Accepted.
    Principal principal{};
};

// Parses "yume-module 1 <64 lowercase hex> <service>\n" from the start of
// input. Rejects the first byte no canonical header can contain at that
// position. The service name's segment rules are checked at its newline,
// which comes within 144 bytes. OtherService is a well-formed header naming
// a service other than `service`.
[[nodiscard]] HeaderParse parse_module_header(
    std::span<const std::byte> input, std::string_view service) noexcept;

}  // namespace ito::module
