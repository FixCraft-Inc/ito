/* Copyright (C) 2026 FixCraft Inc. AGPL-3.0-or-later. */

#include "crypto.hpp"

#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/evperr.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/provider.h>
#include <openssl/rand.h>

#include <algorithm>
#include <array>
#include <limits>
#include <string_view>

namespace ito::call {
namespace {

using Pkey = OpenSslOwned<EVP_PKEY, EVP_PKEY_free>;
using PkeyContext = OpenSslOwned<EVP_PKEY_CTX, EVP_PKEY_CTX_free>;
using DigestContext = OpenSslOwned<EVP_MD_CTX, EVP_MD_CTX_free>;
using DigestAlgorithm = OpenSslOwned<EVP_MD, EVP_MD_free>;
using Kdf = OpenSslOwned<EVP_KDF, EVP_KDF_free>;
using KdfContext = OpenSslOwned<EVP_KDF_CTX, EVP_KDF_CTX_free>;
using Cipher = OpenSslOwned<EVP_CIPHER, EVP_CIPHER_free>;
using CipherContext = OpenSslOwned<EVP_CIPHER_CTX, EVP_CIPHER_CTX_free>;

constexpr const char* kMlDsa87 = "ML-DSA-87";
constexpr const char* kMlKem1024 = "ML-KEM-1024";
constexpr const char* kX25519 = "X25519";

void require(bool condition) {
    if (!condition) throw CryptoFailure{};
}

[[nodiscard]] unsigned char* mutable_bytes(const Byte* bytes) noexcept {
    // OSSL_PARAM takes non-const pointers for input it only reads.
    return const_cast<unsigned char*>(bytes);
}

// A key from a FIPS 203 or 204 seed. OpenSSL derives the rest of the private
// key and wipes its copies when the key object is freed.
[[nodiscard]] Pkey key_from_seed(OSSL_LIB_CTX* library, const char* algorithm,
                                 const Byte* seed, std::size_t size) {
    PkeyContext context(
        EVP_PKEY_CTX_new_from_name(library, algorithm, kProviderProperty));
    require(context != nullptr && EVP_PKEY_fromdata_init(context.get()) == 1);
    std::array<OSSL_PARAM, 2> parameters{
        OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_ML_DSA_SEED,
                                          mutable_bytes(seed), size),
        OSSL_PARAM_construct_end()};
    static_assert(std::string_view(OSSL_PKEY_PARAM_ML_DSA_SEED) ==
                  OSSL_PKEY_PARAM_ML_KEM_SEED);
    EVP_PKEY* raw = nullptr;
    require(EVP_PKEY_fromdata(context.get(), &raw, EVP_PKEY_KEYPAIR,
                              parameters.data()) == 1 &&
            raw != nullptr);
    return Pkey(raw);
}

// An encoded public key of a provider algorithm. Returns null when OpenSSL
// refuses it, which for ML-KEM is FIPS 203's encapsulation key check.
[[nodiscard]] Pkey public_from_bytes(OSSL_LIB_CTX* library,
                                     const char* algorithm, ByteView bytes) {
    PkeyContext context(
        EVP_PKEY_CTX_new_from_name(library, algorithm, kProviderProperty));
    require(context != nullptr && EVP_PKEY_fromdata_init(context.get()) == 1);
    std::array<OSSL_PARAM, 2> parameters{
        OSSL_PARAM_construct_octet_string(
            OSSL_PKEY_PARAM_PUB_KEY, mutable_bytes(bytes.data()), bytes.size()),
        OSSL_PARAM_construct_end()};
    EVP_PKEY* raw = nullptr;
    if (EVP_PKEY_fromdata(context.get(), &raw, EVP_PKEY_PUBLIC_KEY,
                          parameters.data()) != 1) {
        ERR_clear_error();
        return Pkey(nullptr);
    }
    return Pkey(raw);
}

template <std::size_t Size>
[[nodiscard]] std::array<Byte, Size> encoded_public(const EVP_PKEY* key) {
    std::array<Byte, Size> result{};
    std::size_t size = 0U;
    require(EVP_PKEY_get_octet_string_param(key, OSSL_PKEY_PARAM_PUB_KEY,
                                            result.data(), result.size(),
                                            &size) == 1 &&
            size == result.size());
    return result;
}

// One-shot signing with a key OpenSSL signs messages with directly.
void sign_message(OSSL_LIB_CTX* library, EVP_PKEY* key, ByteView message,
                  std::span<Byte> signature) {
    DigestContext context(EVP_MD_CTX_new());
    require(context != nullptr);
    require(EVP_DigestSignInit_ex(context.get(), nullptr, nullptr, library,
                                  kProviderProperty, key, nullptr) == 1);
    std::size_t size = signature.size();
    require(EVP_DigestSign(context.get(), signature.data(), &size,
                           message.data(), message.size()) == 1 &&
            size == signature.size());
}

// Verification that tells a mismatch from a dependency failure. It isolates
// and drains the thread's OpenSSL error queue, so an earlier operation's
// diagnostics cannot change the result.
[[nodiscard]] Verification verify_message(OSSL_LIB_CTX* library, EVP_PKEY* key,
                                          ByteView message,
                                          ByteView signature) {
    DigestContext context(EVP_MD_CTX_new());
    require(context != nullptr);
    require(EVP_DigestVerifyInit_ex(context.get(), nullptr, nullptr, library,
                                    kProviderProperty, key, nullptr) == 1);
    ERR_clear_error();
    const int verified =
        EVP_DigestVerify(context.get(), signature.data(), signature.size(),
                         message.data(), message.size());
    bool dependency_error = false;
    while (const unsigned long error = ERR_get_error()) {
        // EVP adds this generic diagnostic even for an ordinary bad signature.
        // Other diagnostics include allocation failures that the provider
        // returns as zero, the same result as a signature mismatch.
        dependency_error |=
            ERR_GET_LIB(error) != ERR_LIB_EVP ||
            ERR_GET_REASON(error) != EVP_R_PROVIDER_SIGNATURE_FAILURE;
    }
    require(verified >= 0 && (verified == 1 || !dependency_error));
    return verified == 1 ? Verification::Valid : Verification::Invalid;
}

// A signing key exists only for the duration of one signature. OpenSSL wipes
// the private key it copied when the key object is freed.
[[nodiscard]] Pkey private_key(OSSL_LIB_CTX* library, const Seed& seed) {
    Pkey key(EVP_PKEY_new_raw_private_key_ex(
        library, "ED25519", kProviderProperty, seed.data(), seed.size()));
    require(key != nullptr);
    return key;
}

[[nodiscard]] Key raw_public_key(const EVP_PKEY* key) {
    Key result{};
    std::size_t size = result.size();
    require(EVP_PKEY_get_raw_public_key(key, result.data(), &size) == 1 &&
            size == result.size());
    return result;
}

}  // namespace

CryptoContext::CryptoContext() {
    library_ = OSSL_LIB_CTX_new();
    if (library_ == nullptr) throw CryptoFailure{};
    provider_ = OSSL_PROVIDER_load(library_, "default");
    if (provider_ == nullptr) {
        OSSL_LIB_CTX_free(library_);
        throw CryptoFailure{};
    }
}

CryptoContext::~CryptoContext() {
    // The provider unloads before its private library context is freed.
    (void)OSSL_PROVIDER_unload(provider_);
    OSSL_LIB_CTX_free(library_);
}

void CryptoContext::random(std::span<Byte> output) const {
    require(RAND_bytes_ex(library_, output.data(), output.size(), 256U) == 1);
}

Hash CryptoContext::sha256(std::span<const ByteView> parts) const {
    DigestAlgorithm algorithm(
        EVP_MD_fetch(library_, "SHA256", kProviderProperty));
    DigestContext context(EVP_MD_CTX_new());
    require(algorithm != nullptr && context != nullptr);
    require(EVP_DigestInit_ex2(context.get(), algorithm.get(), nullptr) == 1);
    for (const ByteView part : parts) {
        require(EVP_DigestUpdate(context.get(), part.data(), part.size()) == 1);
    }
    Hash result{};
    unsigned int size = 0U;
    require(EVP_DigestFinal_ex(context.get(), result.data(), &size) == 1 &&
            size == result.size());
    return result;
}

void CryptoContext::generate_identity(Seed& seed, Key& public_key) const {
    random(std::span<Byte>(seed.data(), seed.size()));
    public_key = this->public_key(seed);
}

Key CryptoContext::public_key(const Seed& seed) const {
    return raw_public_key(private_key(library_, seed).get());
}

Signature CryptoContext::sign(const Seed& seed, ByteView message) const {
    const Pkey key = private_key(library_, seed);
    Signature result{};
    sign_message(library_, key.get(), message, result);
    return result;
}

Verification CryptoContext::verify(const Key& public_key, ByteView message,
                                   const Signature& signature) const {
    Pkey key(
        EVP_PKEY_new_raw_public_key_ex(library_, "ED25519", kProviderProperty,
                                       public_key.data(), public_key.size()));
    // Any 32 bytes import as an Ed25519 public key, so a failure here is the
    // dependency's, such as an allocation, not the peer's.
    require(key != nullptr);
    return verify_message(library_, key.get(), message, signature);
}

MlDsaPublicKey CryptoContext::ml_dsa_public_key(const Secret32& seed) const {
    const Pkey key =
        key_from_seed(library_, kMlDsa87, seed.data(), seed.size());
    return encoded_public<kMlDsaPublicKeyBytes>(key.get());
}

void CryptoContext::ml_dsa_sign(
    const Secret32& seed, ByteView message,
    std::span<Byte, kMlDsaSignatureBytes> signature) const {
    const Pkey key =
        key_from_seed(library_, kMlDsa87, seed.data(), seed.size());
    sign_message(library_, key.get(), message, signature);
}

Verification CryptoContext::ml_dsa_verify(
    const MlDsaPublicKey& public_key, ByteView message,
    std::span<const Byte, kMlDsaSignatureBytes> signature) const {
    const Pkey key = public_from_bytes(library_, kMlDsa87, public_key);
    require(key != nullptr);
    return verify_message(library_, key.get(), message, signature);
}

Key CryptoContext::x25519_public_key(const Secret32& private_key) const {
    const Pkey key(EVP_PKEY_new_raw_private_key_ex(
        library_, kX25519, kProviderProperty, private_key.data(),
        private_key.size()));
    require(key != nullptr);
    return raw_public_key(key.get());
}

bool CryptoContext::x25519_agree(const Secret32& private_key, const Key& peer,
                                 Secret32& shared) const {
    const Pkey own(EVP_PKEY_new_raw_private_key_ex(
        library_, kX25519, kProviderProperty, private_key.data(),
        private_key.size()));
    // Any 32 bytes import as an X25519 public key.
    const Pkey other(EVP_PKEY_new_raw_public_key_ex(
        library_, kX25519, kProviderProperty, peer.data(), peer.size()));
    require(own != nullptr && other != nullptr);
    const PkeyContext context(
        EVP_PKEY_CTX_new_from_pkey(library_, own.get(), kProviderProperty));
    require(context != nullptr && EVP_PKEY_derive_init(context.get()) == 1);
    if (EVP_PKEY_derive_set_peer(context.get(), other.get()) != 1) {
        ERR_clear_error();
        return false;
    }
    std::size_t size = shared.size();
    // OpenSSL refuses the all-zero result of a small-order peer key. The
    // check below holds whichever way a release reports it.
    if (EVP_PKEY_derive(context.get(), shared.data(), &size) != 1) {
        ERR_clear_error();
        wipe(shared.data(), shared.size());
        return false;
    }
    require(size == shared.size());
    const Secret32 zero;
    if (constant_time_equal(shared.view(), zero.view())) {
        wipe(shared.data(), shared.size());
        return false;
    }
    return true;
}

MlKemPublicKey CryptoContext::ml_kem_public_key(const MlKemSeed& seed) const {
    const Pkey key =
        key_from_seed(library_, kMlKem1024, seed.data(), seed.size());
    return encoded_public<kMlKemPublicKeyBytes>(key.get());
}

bool CryptoContext::ml_kem_encapsulate(const MlKemPublicKey& public_key,
                                       MlKemCiphertext& ciphertext,
                                       Secret32& shared) const {
    const Pkey key = public_from_bytes(library_, kMlKem1024, public_key);
    if (key == nullptr) return false;
    const PkeyContext context(
        EVP_PKEY_CTX_new_from_pkey(library_, key.get(), kProviderProperty));
    require(context != nullptr &&
            EVP_PKEY_encapsulate_init(context.get(), nullptr) == 1);
    std::size_t ciphertext_size = ciphertext.size();
    std::size_t shared_size = shared.size();
    require(
        EVP_PKEY_encapsulate(context.get(), ciphertext.data(), &ciphertext_size,
                             shared.data(), &shared_size) == 1 &&
        ciphertext_size == ciphertext.size() && shared_size == shared.size());
    return true;
}

void CryptoContext::ml_kem_decapsulate(const MlKemSeed& seed,
                                       const MlKemCiphertext& ciphertext,
                                       Secret32& shared) const {
    const Pkey key =
        key_from_seed(library_, kMlKem1024, seed.data(), seed.size());
    const PkeyContext context(
        EVP_PKEY_CTX_new_from_pkey(library_, key.get(), kProviderProperty));
    require(context != nullptr &&
            EVP_PKEY_decapsulate_init(context.get(), nullptr) == 1);
    std::size_t size = shared.size();
    require(EVP_PKEY_decapsulate(context.get(), shared.data(), &size,
                                 ciphertext.data(), ciphertext.size()) == 1 &&
            size == shared.size());
}

void CryptoContext::hkdf_extract(ByteView salt, ByteView input,
                                 Prk& prk) const {
    const Kdf kdf(EVP_KDF_fetch(library_, "HKDF", kProviderProperty));
    require(kdf != nullptr);
    const KdfContext context(EVP_KDF_CTX_new(kdf.get()));
    require(context != nullptr);
    int mode = EVP_KDF_HKDF_MODE_EXTRACT_ONLY;
    char digest[] = "SHA384";
    char properties[] = "provider=default";
    std::array<OSSL_PARAM, 6> parameters{
        OSSL_PARAM_construct_int(OSSL_KDF_PARAM_MODE, &mode),
        OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, digest, 0U),
        OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_PROPERTIES, properties,
                                         0U),
        OSSL_PARAM_construct_octet_string(
            OSSL_KDF_PARAM_SALT, mutable_bytes(salt.data()), salt.size()),
        OSSL_PARAM_construct_octet_string(
            OSSL_KDF_PARAM_KEY, mutable_bytes(input.data()), input.size()),
        OSSL_PARAM_construct_end()};
    require(EVP_KDF_derive(context.get(), prk.data(), prk.size(),
                           parameters.data()) == 1);
}

void CryptoContext::hkdf_expand(ByteView prk, std::span<const ByteView> info,
                                std::span<Byte> output) const {
    // RFC 5869 caps the output at 255 hash blocks.
    require(!output.empty() && output.size() <= 255U * kHkdfPrkBytes);
    SecretBytes joined;
    std::size_t info_size = 0U;
    for (const ByteView part : info) info_size += part.size();
    joined.reserve(info_size);
    for (const ByteView part : info) joined.append(part);
    const Kdf kdf(EVP_KDF_fetch(library_, "HKDF", kProviderProperty));
    require(kdf != nullptr);
    const KdfContext context(EVP_KDF_CTX_new(kdf.get()));
    require(context != nullptr);
    int mode = EVP_KDF_HKDF_MODE_EXPAND_ONLY;
    char digest[] = "SHA384";
    char properties[] = "provider=default";
    std::array<OSSL_PARAM, 6> parameters{
        OSSL_PARAM_construct_int(OSSL_KDF_PARAM_MODE, &mode),
        OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, digest, 0U),
        OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_PROPERTIES, properties,
                                         0U),
        OSSL_PARAM_construct_octet_string(
            OSSL_KDF_PARAM_KEY, mutable_bytes(prk.data()), prk.size()),
        OSSL_PARAM_construct_octet_string(
            OSSL_KDF_PARAM_INFO, mutable_bytes(joined.data()), joined.size()),
        OSSL_PARAM_construct_end()};
    require(EVP_KDF_derive(context.get(), output.data(), output.size(),
                           parameters.data()) == 1);
}

void CryptoContext::seal(ByteView key, const Nonce& nonce, ByteView aad,
                         ByteView plaintext, std::span<Byte> sealed) const {
    require(key.size() == kAeadKeyBytes &&
            sealed.size() == plaintext.size() + kAeadTagBytes &&
            plaintext.size() <=
                static_cast<std::size_t>(std::numeric_limits<int>::max()) &&
            aad.size() <=
                static_cast<std::size_t>(std::numeric_limits<int>::max()));
    const Cipher cipher(
        EVP_CIPHER_fetch(library_, "AES-256-GCM", kProviderProperty));
    const CipherContext context(EVP_CIPHER_CTX_new());
    require(cipher != nullptr && context != nullptr);
    require(EVP_EncryptInit_ex2(context.get(), cipher.get(), key.data(),
                                nonce.data(), nullptr) == 1);
    int written = 0;
    if (!aad.empty()) {
        require(EVP_EncryptUpdate(context.get(), nullptr, &written, aad.data(),
                                  static_cast<int>(aad.size())) == 1);
    }
    require(EVP_EncryptUpdate(context.get(), sealed.data(), &written,
                              plaintext.data(),
                              static_cast<int>(plaintext.size())) == 1 &&
            static_cast<std::size_t>(written) == plaintext.size());
    int final_size = 0;
    require(EVP_EncryptFinal_ex(context.get(), sealed.data() + written,
                                &final_size) == 1 &&
            final_size == 0);
    require(EVP_CIPHER_CTX_ctrl(context.get(), EVP_CTRL_GCM_GET_TAG,
                                static_cast<int>(kAeadTagBytes),
                                sealed.data() + plaintext.size()) == 1);
}

bool CryptoContext::open(ByteView key, const Nonce& nonce, ByteView aad,
                         ByteView sealed, std::span<Byte> plaintext) const {
    require(key.size() == kAeadKeyBytes && sealed.size() >= kAeadTagBytes &&
            plaintext.size() == sealed.size() - kAeadTagBytes &&
            plaintext.size() <=
                static_cast<std::size_t>(std::numeric_limits<int>::max()) &&
            aad.size() <=
                static_cast<std::size_t>(std::numeric_limits<int>::max()));
    const Cipher cipher(
        EVP_CIPHER_fetch(library_, "AES-256-GCM", kProviderProperty));
    const CipherContext context(EVP_CIPHER_CTX_new());
    require(cipher != nullptr && context != nullptr);
    require(EVP_DecryptInit_ex2(context.get(), cipher.get(), key.data(),
                                nonce.data(), nullptr) == 1);
    int written = 0;
    if (!aad.empty()) {
        require(EVP_DecryptUpdate(context.get(), nullptr, &written, aad.data(),
                                  static_cast<int>(aad.size())) == 1);
    }
    require(EVP_DecryptUpdate(context.get(), plaintext.data(), &written,
                              sealed.data(),
                              static_cast<int>(plaintext.size())) == 1 &&
            static_cast<std::size_t>(written) == plaintext.size());
    // OpenSSL reads the expected tag through a non-const pointer.
    std::array<Byte, kAeadTagBytes> tag{};
    std::copy_n(sealed.data() + plaintext.size(), tag.size(), tag.begin());
    require(EVP_CIPHER_CTX_ctrl(context.get(), EVP_CTRL_GCM_SET_TAG,
                                static_cast<int>(tag.size()), tag.data()) == 1);
    int final_size = 0;
    // GCM's final step only compares tags, so a zero result is a mismatch
    // and never an allocation failure.
    if (EVP_DecryptFinal_ex(context.get(), plaintext.data() + written,
                            &final_size) != 1) {
        ERR_clear_error();
        wipe(plaintext.data(), plaintext.size());
        return false;
    }
    return true;
}

}  // namespace ito::call
