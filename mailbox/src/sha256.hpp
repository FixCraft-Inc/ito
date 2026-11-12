/* Copyright (C) 2026 FixCraft Inc. AGPL-3.0-or-later. */

// SHA-256 (FIPS 180-4), for the one hash the mailbox computes: an inbox's
// address from its secret. The service links only the C++ standard library,
// so it carries this small implementation. sha256_test.cpp checks it against
// the FIPS 180-4 examples and against addresses computed independently.
// Every operation is the same for every input of a given length, so the time
// it takes reveals nothing about the secret.

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

namespace ito::mailbox {

using Digest = std::array<std::uint8_t, 32>;

class Sha256 final {
public:
    Sha256() noexcept;
    ~Sha256();

    Sha256(const Sha256&) = delete;
    Sha256& operator=(const Sha256&) = delete;

    void update(std::span<const std::byte> bytes) noexcept;
    // Pads and returns the digest. The object holds nothing afterwards and
    // must not be updated again.
    [[nodiscard]] Digest finish() noexcept;

private:
    void compress(const std::byte* block) noexcept;
    void wipe() noexcept;

    std::array<std::uint32_t, 8> state_;
    std::array<std::byte, 64> block_{};
    std::size_t buffered_{0U};
    std::uint64_t length_{0U};
};

using Secret = std::array<std::uint8_t, 32>;
using Address = std::array<std::uint8_t, 32>;

// SHA-256 over ASCII "ito/mailbox-address/1", one zero byte and the secret.
[[nodiscard]] Address inbox_address(const Secret& secret) noexcept;

}  // namespace ito::mailbox
