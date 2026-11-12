/* Copyright (C) 2026 FixCraft Inc. AGPL-3.0-or-later. */

// SHA-256 against the FIPS 180-4 examples, against digests Python's hashlib
// computed for lengths around the padding boundaries, and the inbox address
// vectors of docs/MAILBOX.md.

#include "sha256.hpp"

#include <cstdio>
#include <string>
#include <string_view>
#include <vector>

#include "check.hpp"

namespace {

using namespace ito::mailbox;

std::string hex(const Digest& digest) {
    static constexpr char kDigits[] = "0123456789abcdef";
    std::string out;
    for (const auto byte : digest) {
        out += kDigits[byte >> 4U];
        out += kDigits[byte & 0x0fU];
    }
    return out;
}

std::string digest_of(std::string_view text) {
    Sha256 hash;
    hash.update(std::as_bytes(std::span(text)));
    return hex(hash.finish());
}

void test_fips_examples() {
    CHECK(digest_of("") ==
          "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    CHECK(digest_of("abc") ==
          "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    CHECK(
        digest_of("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq") ==
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
    CHECK(
        digest_of("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn"
                  "hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu") ==
        "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1");
    // One million 'a', fed in uneven pieces.
    const std::string piece(997U, 'a');
    Sha256 hash;
    std::size_t fed = 0U;
    while (fed < 1'000'000U) {
        const std::size_t take = std::min(piece.size(), 1'000'000U - fed);
        hash.update(std::as_bytes(std::span(piece.data(), take)));
        fed += take;
    }
    CHECK(hex(hash.finish()) ==
          "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
}

void test_padding_boundaries() {
    const std::vector<std::pair<std::size_t, std::string_view>> expected{
        {55U,
         "e7313d333c272e639f790978283f9eb392e843d0f29b7016828bb1daa4aac70b"},
        {56U,
         "4324d65f3c103567f5589c710bc08f8523f929a9272e3af36fc968e52abc6c27"},
        {63U,
         "81c80242132f230c3bd41b3e63bbcff16107339549214a99614ff26664625055"},
        {64U,
         "39e3d7b6b5d075d37d053ad89b24b41bef4f3c29760c84447cab3f3be1882241"},
        {65U,
         "aacca6ff74fdbb296d165a45cecfa04e5127bc008770fbbdd48006f2d2fae95e"},
        {119U,
         "9ce7368e4daf32341631b492e80359dc9f594b48453cd0dd5bf0b19279cc177e"},
        {120U,
         "7836b787757e95e58b3ca5aec90b1b004e8deba1e50e9675af9cabf1a13a04b5"}};
    for (const auto& [length, digest] : expected) {
        std::vector<std::byte> data;
        for (std::size_t index = 0U; index < length; ++index)
            data.push_back(static_cast<std::byte>((index * 7U + 3U) & 0xffU));
        Sha256 whole;
        whole.update(data);
        CHECK(hex(whole.finish()) == digest);
        // Byte by byte gives the same digest.
        Sha256 split;
        for (const auto byte : data) split.update(std::span(&byte, 1U));
        CHECK(hex(split.finish()) == digest);
    }
}

void test_inbox_addresses() {
    Secret counting{};
    for (std::size_t index = 0U; index < counting.size(); ++index)
        counting[index] = static_cast<std::uint8_t>(index);
    CHECK(hex(inbox_address(counting)) ==
          "9bedd192749f88c8b5eae4e9e6d52b83139294a47ba374bb032cc12906c1af00");
    Secret ones{};
    ones.fill(0xffU);
    CHECK(hex(inbox_address(ones)) ==
          "849294bd70e8b7e1a3975968916f2b4afb25f0f1666eaca6004c5af8a526af09");
}

}  // namespace

int main() {
    test_fips_examples();
    test_padding_boundaries();
    test_inbox_addresses();
    std::puts("sha256: all checks passed");
    return 0;
}
