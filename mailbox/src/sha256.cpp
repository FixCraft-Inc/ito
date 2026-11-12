/* Copyright (C) 2026 FixCraft Inc. AGPL-3.0-or-later. */

#include "sha256.hpp"

#include <algorithm>
#include <bit>
#include <cstring>
#include <string_view>

namespace ito::mailbox {
namespace {

constexpr std::array<std::uint32_t, 64> kRoundConstants{
    0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U, 0x3956c25bU,
    0x59f111f1U, 0x923f82a4U, 0xab1c5ed5U, 0xd807aa98U, 0x12835b01U,
    0x243185beU, 0x550c7dc3U, 0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U,
    0xc19bf174U, 0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU,
    0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU, 0x983e5152U,
    0xa831c66dU, 0xb00327c8U, 0xbf597fc7U, 0xc6e00bf3U, 0xd5a79147U,
    0x06ca6351U, 0x14292967U, 0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU,
    0x53380d13U, 0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U,
    0xa2bfe8a1U, 0xa81a664bU, 0xc24b8b70U, 0xc76c51a3U, 0xd192e819U,
    0xd6990624U, 0xf40e3585U, 0x106aa070U, 0x19a4c116U, 0x1e376c08U,
    0x2748774cU, 0x34b0bcb5U, 0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU,
    0x682e6ff3U, 0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U,
    0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U};

constexpr std::array<std::uint32_t, 8> kInitialState{
    0x6a09e667U, 0xbb67ae85U, 0x3c6ef372U, 0xa54ff53aU,
    0x510e527fU, 0x9b05688cU, 0x1f83d9abU, 0x5be0cd19U};

constexpr std::string_view kAddressLabel = "ito/mailbox-address/1";

std::uint32_t load_be32(const std::byte* bytes) noexcept {
    return (std::to_integer<std::uint32_t>(bytes[0]) << 24U) |
           (std::to_integer<std::uint32_t>(bytes[1]) << 16U) |
           (std::to_integer<std::uint32_t>(bytes[2]) << 8U) |
           std::to_integer<std::uint32_t>(bytes[3]);
}

}  // namespace

Sha256::Sha256() noexcept : state_(kInitialState) {}

Sha256::~Sha256() {
    wipe();
}

void Sha256::wipe() noexcept {
    ::explicit_bzero(state_.data(), sizeof state_);
    ::explicit_bzero(block_.data(), block_.size());
    buffered_ = 0U;
    length_ = 0U;
}

void Sha256::compress(const std::byte* block) noexcept {
    std::array<std::uint32_t, 64> schedule;
    for (std::size_t index = 0U; index < 16U; ++index)
        schedule[index] = load_be32(block + 4U * index);
    for (std::size_t index = 16U; index < 64U; ++index) {
        const std::uint32_t early = schedule[index - 15U];
        const std::uint32_t late = schedule[index - 2U];
        const std::uint32_t sigma0 =
            std::rotr(early, 7) ^ std::rotr(early, 18) ^ (early >> 3U);
        const std::uint32_t sigma1 =
            std::rotr(late, 17) ^ std::rotr(late, 19) ^ (late >> 10U);
        schedule[index] =
            schedule[index - 16U] + sigma0 + schedule[index - 7U] + sigma1;
    }
    std::uint32_t a = state_[0], b = state_[1], c = state_[2], d = state_[3];
    std::uint32_t e = state_[4], f = state_[5], g = state_[6], h = state_[7];
    for (std::size_t index = 0U; index < 64U; ++index) {
        const std::uint32_t sum1 =
            std::rotr(e, 6) ^ std::rotr(e, 11) ^ std::rotr(e, 25);
        const std::uint32_t choice = (e & f) ^ (~e & g);
        const std::uint32_t first =
            h + sum1 + choice + kRoundConstants[index] + schedule[index];
        const std::uint32_t sum0 =
            std::rotr(a, 2) ^ std::rotr(a, 13) ^ std::rotr(a, 22);
        const std::uint32_t majority = (a & b) ^ (a & c) ^ (b & c);
        const std::uint32_t second = sum0 + majority;
        h = g;
        g = f;
        f = e;
        e = d + first;
        d = c;
        c = b;
        b = a;
        a = first + second;
    }
    state_[0] += a;
    state_[1] += b;
    state_[2] += c;
    state_[3] += d;
    state_[4] += e;
    state_[5] += f;
    state_[6] += g;
    state_[7] += h;
    ::explicit_bzero(schedule.data(), sizeof schedule);
}

void Sha256::update(std::span<const std::byte> bytes) noexcept {
    length_ += bytes.size();
    while (!bytes.empty()) {
        const std::size_t take =
            std::min(bytes.size(), block_.size() - buffered_);
        std::memcpy(block_.data() + buffered_, bytes.data(), take);
        buffered_ += take;
        bytes = bytes.subspan(take);
        if (buffered_ == block_.size()) {
            compress(block_.data());
            buffered_ = 0U;
        }
    }
}

Digest Sha256::finish() noexcept {
    const std::uint64_t bits = length_ * 8U;
    block_[buffered_++] = std::byte{0x80};
    if (buffered_ > block_.size() - 8U) {
        std::fill(block_.begin() + static_cast<std::ptrdiff_t>(buffered_),
                  block_.end(), std::byte{0});
        compress(block_.data());
        buffered_ = 0U;
    }
    std::fill(block_.begin() + static_cast<std::ptrdiff_t>(buffered_),
              block_.end() - 8, std::byte{0});
    for (std::size_t index = 0U; index < 8U; ++index)
        block_[block_.size() - 1U - index] =
            static_cast<std::byte>(bits >> (8U * index));
    compress(block_.data());
    Digest digest;
    for (std::size_t word = 0U; word < state_.size(); ++word)
        for (std::size_t index = 0U; index < 4U; ++index)
            digest[4U * word + index] =
                static_cast<std::uint8_t>(state_[word] >> (24U - 8U * index));
    wipe();
    return digest;
}

Address inbox_address(const Secret& secret) noexcept {
    Sha256 hash;
    hash.update(std::as_bytes(std::span(kAddressLabel)));
    const std::byte separator{0};
    hash.update(std::span(&separator, 1U));
    hash.update(std::as_bytes(std::span(secret)));
    return hash.finish();
}

}  // namespace ito::mailbox
