/* Copyright (C) 2026 FixCraft Inc. AGPL-3.0-or-later. */

#include "identity.hpp"

#include <algorithm>
#include <vector>

namespace ito::call {
namespace {

[[nodiscard]] SecretBytes composite_message(const Hash& signer,
                                            std::string_view label,
                                            std::span<const ByteView> body) {
    std::size_t size = label.size() + signer.size();
    for (const ByteView part : body) size += part.size();
    // The body can hold secrets, such as a pairing code's record.
    SecretBytes message;
    message.reserve(size);
    message.append(as_bytes(label));
    message.append(signer);
    for (const ByteView part : body) message.append(part);
    return message;
}

[[nodiscard]] bool key_less(const Hash& a, const Hash& b) noexcept {
    return std::lexicographical_compare(a.begin(), a.end(), b.begin(), b.end());
}

}  // namespace

Hash fingerprint2(const CryptoContext& crypto, const Identity2& identity) {
    const std::array<ByteView, 3> parts{as_bytes(kFingerprint2Domain),
                                        identity.ed25519, identity.ml_dsa};
    return crypto.sha256(parts);
}

CompositeSignature sign_composite(const CryptoContext& crypto,
                                  const Seed& ed25519_seed,
                                  const Secret32& ml_dsa_seed,
                                  const Hash& signer, std::string_view label,
                                  std::span<const ByteView> body) {
    const SecretBytes message = composite_message(signer, label, body);
    CompositeSignature signature{};
    const Signature classical = crypto.sign(ed25519_seed, message.view());
    std::copy(classical.begin(), classical.end(), signature.begin());
    crypto.ml_dsa_sign(
        ml_dsa_seed, message.view(),
        std::span<Byte, kMlDsaSignatureBytes>(
            signature.data() + kSignatureBytes, kMlDsaSignatureBytes));
    return signature;
}

Verification verify_composite(const CryptoContext& crypto,
                              const Identity2& signer, std::string_view label,
                              std::span<const ByteView> body,
                              const CompositeSignature& signature) {
    const SecretBytes message =
        composite_message(fingerprint2(crypto, signer), label, body);
    Signature classical{};
    std::copy_n(signature.begin(), classical.size(), classical.begin());
    if (crypto.verify(signer.ed25519, message.view(), classical) !=
        Verification::Valid) {
        return Verification::Invalid;
    }
    return crypto.ml_dsa_verify(
        signer.ml_dsa, message.view(),
        std::span<const Byte, kMlDsaSignatureBytes>(
            signature.data() + kSignatureBytes, kMlDsaSignatureBytes));
}

void decimal_digits(ByteView number, std::span<char> digits) noexcept {
    // Schoolbook division by ten, once per digit, least significant first.
    // The quotient replaces the number in a bounded local copy.
    std::array<Byte, kHashBytes> value{};
    const std::size_t size = std::min(number.size(), value.size());
    std::copy(number.end() - static_cast<std::ptrdiff_t>(size), number.end(),
              value.end() - static_cast<std::ptrdiff_t>(size));
    for (std::size_t index = digits.size(); index > 0U; --index) {
        unsigned remainder = 0U;
        for (Byte& byte : value) {
            const unsigned current = (remainder << 8U) | byte;
            byte = static_cast<Byte>(current / 10U);
            remainder = current % 10U;
        }
        digits[index - 1U] = static_cast<char>('0' + remainder);
    }
    wipe(value.data(), value.size());
}

SafetyCode safety_code(const CryptoContext& crypto, const Hash& first,
                       const Hash& second) {
    const bool ordered = !key_less(second, first);
    const Hash& low = ordered ? first : second;
    const Hash& high = ordered ? second : first;
    const std::array<ByteView, 3> parts{as_bytes(kSafetyCodeDomain), low, high};
    const Hash digest = crypto.sha256(parts);
    SafetyCode code{};
    decimal_digits(digest, code);
    return code;
}

bool safety_code_matches(std::string_view compared,
                         const SafetyCode& expected) noexcept {
    SafetyCode normalized{};
    std::size_t count = 0U;
    for (const char character : compared) {
        if (character == ' ' || character == '-') continue;
        if (character < '0' || character > '9' || count == normalized.size()) {
            return false;
        }
        normalized[count++] = character;
    }
    if (count != normalized.size()) return false;
    unsigned difference = 0U;
    for (std::size_t index = 0U; index < normalized.size(); ++index) {
        difference |=
            static_cast<unsigned>(normalized[index] ^ expected[index]);
    }
    return difference == 0U;
}

}  // namespace ito::call
