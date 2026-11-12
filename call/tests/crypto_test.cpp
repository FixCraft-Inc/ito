/* Copyright (C) 2026 FixCraft Inc. AGPL-3.0-or-later. */

// Known answers for the primitives the core fetches from its private
// library context, as I3's component evaluation checked them, and the
// identity 2 and pairing primitives: ML-DSA-87, X25519, ML-KEM-1024,
// HKDF-SHA-384 and AES-256-GCM.

#include <algorithm>
#include <array>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include <openssl/err.h>

#include "check.hpp"
#include "crypto.hpp"

using namespace ito::call;

namespace {

template <std::size_t Size>
std::array<Byte, Size> hex_array(const std::string& text) {
    const std::vector<unsigned char> bytes = testing::from_hex(text);
    CHECK(bytes.size() == Size);
    std::array<Byte, Size> result{};
    std::copy(bytes.begin(), bytes.end(), result.begin());
    return result;
}

template <std::size_t Size>
void fill_secret(SecretArray<Size>& secret, const std::string& text) {
    secret.assign(std::span<const Byte, Size>(hex_array<Size>(text)));
}

void test_ml_dsa(const CryptoContext& crypto) {
    Secret32 seed;
    crypto.random(std::span<Byte>(seed.data(), seed.size()));
    const MlDsaPublicKey key = crypto.ml_dsa_public_key(seed);
    // The seed alone fixes the key.
    CHECK(crypto.ml_dsa_public_key(seed) == key);
    std::array<Byte, kMlDsaSignatureBytes> signature{};
    crypto.ml_dsa_sign(seed, as_bytes("ito"), signature);
    CHECK(crypto.ml_dsa_verify(key, as_bytes("ito"), signature) ==
          Verification::Valid);
    CHECK(crypto.ml_dsa_verify(key, as_bytes("itO"), signature) ==
          Verification::Invalid);
    std::array<Byte, kMlDsaSignatureBytes> changed = signature;
    changed[100] ^= 1U;
    CHECK(crypto.ml_dsa_verify(key, as_bytes("ito"), changed) ==
          Verification::Invalid);
    Secret32 other;
    crypto.random(std::span<Byte>(other.data(), other.size()));
    CHECK(crypto.ml_dsa_verify(crypto.ml_dsa_public_key(other), as_bytes("ito"),
                               signature) == Verification::Invalid);
    // A stale diagnostic cannot turn a mismatch into a dependency failure.
    ERR_raise(ERR_LIB_EVP, ERR_R_MALLOC_FAILURE);
    CHECK(crypto.ml_dsa_verify(key, as_bytes("ito"), changed) ==
          Verification::Invalid);
    CHECK(ERR_peek_error() == 0);
}

void test_x25519(const CryptoContext& crypto) {
    // RFC 7748 section 6.1.
    Secret32 alice;
    Secret32 bob;
    fill_secret(
        alice,
        "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
    fill_secret(
        bob,
        "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
    const Key alice_public = hex_array<32>(
        "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
    const Key bob_public = hex_array<32>(
        "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
    const Key expected = hex_array<32>(
        "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
    CHECK(crypto.x25519_public_key(alice) == alice_public);
    CHECK(crypto.x25519_public_key(bob) == bob_public);
    Secret32 shared;
    CHECK(crypto.x25519_agree(alice, bob_public, shared));
    CHECK(constant_time_equal(shared.view(), expected));
    CHECK(crypto.x25519_agree(bob, alice_public, shared));
    CHECK(constant_time_equal(shared.view(), expected));
    // A small-order peer key gives the all-zero secret, which is refused.
    const Key zero{};
    CHECK(!crypto.x25519_agree(alice, zero, shared));
    Key one{};
    one[0] = 1U;
    CHECK(!crypto.x25519_agree(alice, one, shared));
    CHECK(ERR_peek_error() == 0);
}

void test_ml_kem(const CryptoContext& crypto) {
    MlKemSeed seed;
    crypto.random(std::span<Byte>(seed.data(), seed.size()));
    const MlKemPublicKey key = crypto.ml_kem_public_key(seed);
    CHECK(crypto.ml_kem_public_key(seed) == key);
    MlKemCiphertext ciphertext{};
    Secret32 sent;
    CHECK(crypto.ml_kem_encapsulate(key, ciphertext, sent));
    Secret32 received;
    crypto.ml_kem_decapsulate(seed, ciphertext, received);
    CHECK(constant_time_equal(sent.view(), received.view()));
    // Implicit rejection: another ciphertext yields another secret.
    ciphertext[0] ^= 1U;
    crypto.ml_kem_decapsulate(seed, ciphertext, received);
    CHECK(!constant_time_equal(sent.view(), received.view()));
    // FIPS 203's input check refuses coefficients of q or more.
    MlKemPublicKey invalid = key;
    std::fill(invalid.begin(), invalid.begin() + 384, Byte{0xFF});
    CHECK(!crypto.ml_kem_encapsulate(invalid, ciphertext, sent));
    CHECK(ERR_peek_error() == 0);
}

void test_hkdf_and_aead(const CryptoContext& crypto) {
    // Computed independently with Python's hmac from RFC 5869.
    Prk prk;
    crypto.hkdf_extract(as_bytes("salt"), as_bytes("input key"), prk);
    CHECK(prk.view().size() == 48U);
    const std::vector<unsigned char> expected_prk = testing::from_hex(
        "2c5080a063e4dba8f0a20cf69e347da6a846f45a85c66efca99004c7cd130737"
        "ca12afead87f8437d26fe99a477e5c4a");
    CHECK(std::equal(prk.data(), prk.data() + prk.size(), expected_prk.begin(),
                     expected_prk.end()));
    const std::array<ByteView, 2> info{as_bytes("in"), as_bytes("fo")};
    std::array<Byte, 60> expanded{};
    crypto.hkdf_expand(prk.view(), info, expanded);
    CHECK(expanded ==
          (hex_array<60>(
              "9f809df68d64486734c41903f99e5d2b2e72d6a535d590344a0404c7"
              "ad6ae8dda9fd6f6354ec3a6a101e4bf96de9fdcdba40de9dc2a0532c"
              "2316482b")));

    std::array<Byte, 32> key{};
    for (std::size_t index = 0U; index < key.size(); ++index) {
        key[index] = static_cast<Byte>(index);
    }
    Nonce nonce{};
    for (std::size_t index = 0U; index < nonce.size(); ++index) {
        nonce[index] = static_cast<Byte>(index);
    }
    constexpr std::string_view plain = "plain text";
    std::array<Byte, plain.size() + kAeadTagBytes> sealed{};
    crypto.seal(key, nonce, as_bytes("aad"), as_bytes(plain), sealed);
    CHECK(sealed ==
          (hex_array<26>(
              "376eb772abc5b67ef535519ee121298002ed4e265959884c0456")));
    std::array<Byte, plain.size()> opened{};
    CHECK(crypto.open(key, nonce, as_bytes("aad"), sealed, opened));
    CHECK(std::equal(opened.begin(), opened.end(), plain.begin(), plain.end(),
                     [](Byte a, char b) { return a == static_cast<Byte>(b); }));
    // A changed tag, ciphertext or associated data is refused, and nothing
    // of the plaintext is left behind.
    for (const std::size_t position : {0U, 25U}) {
        std::array<Byte, sealed.size()> changed = sealed;
        changed[position] ^= 1U;
        CHECK(!crypto.open(key, nonce, as_bytes("aad"), changed, opened));
        CHECK(std::all_of(opened.begin(), opened.end(),
                          [](Byte byte) { return byte == 0U; }));
    }
    CHECK(!crypto.open(key, nonce, as_bytes("aaD"), sealed, opened));
    CHECK(ERR_peek_error() == 0);
}

}  // namespace

int main() {
    const CryptoContext crypto;

    constexpr std::string_view abc = "abc";
    const std::array<ByteView, 1> message{as_bytes(abc)};
    const Hash expected_abc{0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
                            0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
                            0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
                            0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad};
    CHECK(crypto.sha256(message) == expected_abc);
    // Split input hashes the same.
    const std::array<ByteView, 3> parts{as_bytes("a"), as_bytes(""),
                                        as_bytes("bc")};
    CHECK(crypto.sha256(parts) == expected_abc);

    // RFC 8032 section 7.1, TEST 1 (empty message).
    Seed seed;
    seed.assign(std::array<Byte, 32>{
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a,
        0xf4, 0x92, 0xec, 0x2c, 0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32,
        0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60});
    const Key expected_public{0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7,
                              0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
                              0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25,
                              0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a};
    const Signature expected_signature{
        0xe5, 0x56, 0x43, 0x00, 0xc3, 0x60, 0xac, 0x72, 0x90, 0x86, 0xe2,
        0xcc, 0x80, 0x6e, 0x82, 0x8a, 0x84, 0x87, 0x7f, 0x1e, 0xb8, 0xe5,
        0xd9, 0x74, 0xd8, 0x73, 0xe0, 0x65, 0x22, 0x49, 0x01, 0x55, 0x5f,
        0xb8, 0x82, 0x15, 0x90, 0xa3, 0x3b, 0xac, 0xc6, 0x1e, 0x39, 0x70,
        0x1c, 0xf9, 0xb4, 0x6b, 0xd2, 0x5b, 0xf5, 0xf0, 0x59, 0x5b, 0xbe,
        0x24, 0x65, 0x51, 0x41, 0x43, 0x8e, 0x7a, 0x10, 0x0b};
    CHECK(crypto.public_key(seed) == expected_public);
    CHECK(crypto.sign(seed, {}) == expected_signature);
    CHECK(crypto.verify(expected_public, {}, expected_signature) ==
          Verification::Valid);
    Signature changed = expected_signature;
    changed[10] ^= 1U;
    CHECK(crypto.verify(expected_public, {}, changed) == Verification::Invalid);
    CHECK(crypto.verify(expected_public, as_bytes("x"), expected_signature) ==
          Verification::Invalid);
    // A public key that is not a curve point is refused, not an error.
    Key invalid{};
    invalid.fill(0xFF);
    CHECK(crypto.verify(invalid, {}, expected_signature) ==
          Verification::Invalid);

    // A different operation's diagnostics cannot change peer verification.
    ERR_raise(ERR_LIB_EVP, ERR_R_MALLOC_FAILURE);
    CHECK(crypto.verify(expected_public, {}, expected_signature) ==
          Verification::Valid);
    CHECK(ERR_peek_error() == 0);
    ERR_raise(ERR_LIB_EVP, ERR_R_MALLOC_FAILURE);
    CHECK(crypto.verify(expected_public, {}, changed) == Verification::Invalid);
    CHECK(ERR_peek_error() == 0);
    ERR_raise(ERR_LIB_EVP, ERR_R_MALLOC_FAILURE);
    CHECK(crypto.verify(expected_public, as_bytes("x"), expected_signature) ==
          Verification::Invalid);
    CHECK(ERR_peek_error() == 0);
    ERR_raise(ERR_LIB_EVP, ERR_R_MALLOC_FAILURE);
    CHECK(crypto.verify(invalid, {}, expected_signature) ==
          Verification::Invalid);
    CHECK(ERR_peek_error() == 0);

    // Fresh identities differ and sign verifiably.
    Seed first;
    Seed second;
    Key first_public{};
    Key second_public{};
    crypto.generate_identity(first, first_public);
    crypto.generate_identity(second, second_public);
    CHECK(first_public != second_public);
    const Signature signed_first = crypto.sign(first, as_bytes("ito"));
    CHECK(crypto.verify(first_public, as_bytes("ito"), signed_first) ==
          Verification::Valid);
    CHECK(crypto.verify(second_public, as_bytes("ito"), signed_first) ==
          Verification::Invalid);

    test_ml_dsa(crypto);
    test_x25519(crypto);
    test_ml_kem(crypto);
    test_hkdf_and_aead(crypto);
    return 0;
}
