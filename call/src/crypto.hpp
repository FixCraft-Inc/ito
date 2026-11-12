/* Copyright (C) 2026 FixCraft Inc. AGPL-3.0-or-later. */

// The core's only cryptographic owner outside TLS. One private OpenSSL
// library context with its default provider, explicitly loaded, serves every
// fetch with "provider=default". There is no fallback to OpenSSL's global
// context or another provider. The context outlives every key and operation
// the core creates.

#pragma once

#include <openssl/types.h>

#include <cstddef>
#include <memory>
#include <span>

#include "bytes.hpp"

namespace ito::call {

inline constexpr const char* kProviderProperty = "provider=default";

enum class Verification { Valid, Invalid };

template <class T, auto Free>
struct OpenSslDeleter final {
    void operator()(T* value) const noexcept {
        if (value != nullptr) (void)Free(value);
    }
};

template <class T, auto Free>
using OpenSslOwned = std::unique_ptr<T, OpenSslDeleter<T, Free>>;

class CryptoContext final {
public:
    // Throws CryptoFailure when the context or provider cannot be created.
    CryptoContext();
    CryptoContext(const CryptoContext&) = delete;
    CryptoContext& operator=(const CryptoContext&) = delete;
    ~CryptoContext();

    [[nodiscard]] OSSL_LIB_CTX* library() const noexcept { return library_; }

    // Fills output from the context's DRBG. Throws CryptoFailure.
    void random(std::span<Byte> output) const;
    [[nodiscard]] Hash sha256(std::span<const ByteView> parts) const;

    // A new random Ed25519 seed and its public key.
    void generate_identity(Seed& seed, Key& public_key) const;
    [[nodiscard]] Key public_key(const Seed& seed) const;
    [[nodiscard]] Signature sign(const Seed& seed, ByteView message) const;
    [[nodiscard]] Verification verify(const Key& public_key, ByteView message,
                                      const Signature& signature) const;

    // ML-DSA-87 from its 32-byte FIPS 204 seed. Signing is hedged (OpenSSL's
    // default) and uses the empty context string. Any 2592 bytes decode as a
    // public key, so a failed import is the dependency's.
    [[nodiscard]] MlDsaPublicKey ml_dsa_public_key(const Secret32& seed) const;
    void ml_dsa_sign(const Secret32& seed, ByteView message,
                     std::span<Byte, kMlDsaSignatureBytes> signature) const;
    [[nodiscard]] Verification ml_dsa_verify(
        const MlDsaPublicKey& public_key, ByteView message,
        std::span<const Byte, kMlDsaSignatureBytes> signature) const;

    // X25519 with a raw 32-byte private key. agree returns false for a peer
    // key that OpenSSL refuses or that gives the all-zero shared secret.
    [[nodiscard]] Key x25519_public_key(const Secret32& private_key) const;
    [[nodiscard]] bool x25519_agree(const Secret32& private_key,
                                    const Key& peer, Secret32& shared) const;

    // ML-KEM-1024 from its 64-byte FIPS 203 seed (d || z). encapsulate
    // returns false for an encapsulation key that fails FIPS 203's input
    // check. Decapsulation rejects implicitly: a wrong ciphertext yields an
    // unrelated secret, which the AEAD built on it then refuses.
    [[nodiscard]] MlKemPublicKey ml_kem_public_key(const MlKemSeed& seed) const;
    [[nodiscard]] bool ml_kem_encapsulate(const MlKemPublicKey& public_key,
                                          MlKemCiphertext& ciphertext,
                                          Secret32& shared) const;
    void ml_kem_decapsulate(const MlKemSeed& seed,
                            const MlKemCiphertext& ciphertext,
                            Secret32& shared) const;

    // HKDF with SHA-384 (RFC 5869). The info parts are concatenated.
    void hkdf_extract(ByteView salt, ByteView input, Prk& prk) const;
    void hkdf_expand(ByteView prk, std::span<const ByteView> info,
                     std::span<Byte> output) const;

    // AES-256-GCM with a 16-byte tag appended. sealed is plaintext.size() + 16
    // bytes. open returns false when the tag does not verify, and then
    // leaves plaintext wiped.
    void seal(ByteView key, const Nonce& nonce, ByteView aad,
              ByteView plaintext, std::span<Byte> sealed) const;
    [[nodiscard]] bool open(ByteView key, const Nonce& nonce, ByteView aad,
                            ByteView sealed, std::span<Byte> plaintext) const;

private:
    OSSL_LIB_CTX* library_{nullptr};
    OSSL_PROVIDER* provider_{nullptr};
};

// Thrown when OpenSSL or the random source fails. The C interface maps it to
// ITO_STATUS_DEPENDENCY_FAILURE. Peer input never causes it: verification
// failure is a Verification value.
struct CryptoFailure final {};

}  // namespace ito::call
