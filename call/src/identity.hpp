/* Copyright (C) 2026 FixCraft Inc. AGPL-3.0-or-later. */

// Identity 2 of docs/MESSAGE_SECURITY.md: an Ed25519 key and an ML-DSA-87
// key that always sign together, the fingerprint that names both, and the
// safety code two people compare. The private seeds stay in the store, which
// passes them in only for the duration of one signature.

#pragma once

#include <array>
#include <span>
#include <string_view>

#include "bytes.hpp"
#include "crypto.hpp"

namespace ito::call {

// The public half of an identity 2.
struct Identity2 final {
    Key ed25519{};
    MlDsaPublicKey ml_dsa{};

    [[nodiscard]] bool operator==(const Identity2&) const = default;
};

using CompositeSignature = std::array<Byte, kCompositeSignatureBytes>;
using SafetyCode = std::array<char, kSafetyCodeDigits>;

inline constexpr std::string_view kFingerprint2Domain{
    "ito/contact-identity/2\0", 23U};
inline constexpr std::string_view kSafetyCodeDomain{"ito/safety-code/1\0", 18U};

// SHA-256 of "ito/contact-identity/2", zero, the Ed25519 key, the ML-DSA key.
[[nodiscard]] Hash fingerprint2(const CryptoContext& crypto,
                                const Identity2& identity);

// Both halves sign one message: the label (which ends in its zero byte), the
// signer's fingerprint, then the body parts in order. Naming the fingerprint
// binds each half to the other, so neither can be cut out and reused.
[[nodiscard]] CompositeSignature sign_composite(const CryptoContext& crypto,
                                                const Seed& ed25519_seed,
                                                const Secret32& ml_dsa_seed,
                                                const Hash& signer,
                                                std::string_view label,
                                                std::span<const ByteView> body);
// Valid only when both halves verify for the signer's two keys.
[[nodiscard]] Verification verify_composite(
    const CryptoContext& crypto, const Identity2& signer,
    std::string_view label, std::span<const ByteView> body,
    const CompositeSignature& signature);

// SHA-256 of "ito/safety-code/1", zero and both fingerprints in ascending
// byte order, read as a big-endian number and written as its lowest 60
// decimal digits. The order makes it the same on both phones.
[[nodiscard]] SafetyCode safety_code(const CryptoContext& crypto,
                                     const Hash& first, const Hash& second);
// True when compared holds exactly the 60 digits, ignoring spaces and
// hyphens. Any other character, or a prefix, is false.
[[nodiscard]] bool safety_code_matches(std::string_view compared,
                                       const SafetyCode& expected) noexcept;

// The lowest digits.size() decimal digits of a big-endian number, most
// significant first and zero padded.
void decimal_digits(ByteView number, std::span<char> digits) noexcept;

}  // namespace ito::call
