/* Copyright (C) 2026 FixCraft Inc. AGPL-3.0-or-later. */

#include "pairing.hpp"

#include <algorithm>
#include <limits>

namespace ito::call {
namespace {

constexpr std::string_view kBase64Url =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

// The plaintext of each sealed item fills it to one of the mailbox's sizes.
constexpr std::size_t kHelloSaltBytes = 32U;
constexpr std::size_t kHelloPlaintextBytes =
    kLargeItemBytes - kHelloSaltBytes - kAeadTagBytes;
constexpr std::size_t kReplyPublicBytes = kKeyBytes + kMlKemCiphertextBytes;
constexpr std::size_t kReplyPlaintextBytes =
    kLargeItemBytes - kReplyPublicBytes - kAeadTagBytes;
constexpr std::size_t kConfirmPlaintextBytes = kSmallItemBytes - kAeadTagBytes;
constexpr std::size_t kAeadKeyNonceBytes = kAeadKeyBytes + kAeadNonceBytes;

// Hello body: both identity keys, share, KEM key, server fingerprint, u8
// service length and service, inbox, u8 name length and name.
constexpr std::size_t kMaxHelloBodyBytes =
    kKeyBytes + kMlDsaPublicKeyBytes + kKeyBytes + kMlKemPublicKeyBytes +
    kKeyBytes + 1U + kMaxServiceBytes + kHashBytes + 1U + kMaxNameBytes;
static_assert(kMaxHelloBodyBytes + kCompositeSignatureBytes <=
              kHelloPlaintextBytes);
// Reply body: both identity keys, ratchet key, inbox, u8 name length, name.
constexpr std::size_t kMaxReplyBodyBytes = kKeyBytes + kMlDsaPublicKeyBytes +
                                           kKeyBytes + kHashBytes + 1U +
                                           kMaxNameBytes;
static_assert(kMaxReplyBodyBytes + kCompositeSignatureBytes <=
              kReplyPlaintextBytes);

[[nodiscard]] int base64url_value(char character) noexcept {
    const std::size_t index = kBase64Url.find(character);
    return index == std::string_view::npos ? -1 : static_cast<int>(index);
}

void append_base64url(ByteView bytes, SecretBytes& out) {
    std::array<Byte, 1> character{};
    std::uint32_t accumulator = 0U;
    int bits = 0;
    for (const Byte byte : bytes) {
        accumulator = (accumulator << 8U) | byte;
        bits += 8;
        while (bits >= 6) {
            bits -= 6;
            character[0] =
                static_cast<Byte>(kBase64Url[(accumulator >> bits) & 0x3FU]);
            out.append(character);
        }
    }
    if (bits > 0) {
        character[0] =
            static_cast<Byte>(kBase64Url[(accumulator << (6 - bits)) & 0x3FU]);
        out.append(character);
    }
    accumulator = 0U;
}

// Unpadded base64url whose unused trailing bits are zero, the one canonical
// form. A length that leaves a lone character is never canonical.
[[nodiscard]] bool parse_base64url(std::string_view text, SecretBytes& out) {
    if (text.size() % 4U == 1U) return false;
    out.reserve(text.size() * 3U / 4U);
    std::array<Byte, 1> byte{};
    std::uint32_t accumulator = 0U;
    int bits = 0;
    for (const char character : text) {
        const int value = base64url_value(character);
        if (value < 0) return false;
        accumulator =
            ((accumulator << 6U) | static_cast<std::uint32_t>(value)) & 0xFFFFU;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            byte[0] = static_cast<Byte>(accumulator >> bits);
            out.append(byte);
        }
    }
    const bool canonical =
        (accumulator & ((1U << static_cast<unsigned>(bits)) - 1U)) == 0U;
    accumulator = 0U;
    byte[0] = 0U;
    return canonical;
}

[[nodiscard]] std::vector<Byte> encode_hello_body(const HelloBody& body) {
    std::vector<Byte> out;
    out.reserve(kMaxHelloBodyBytes);
    Writer write(out);
    write.bytes(body.sender.ed25519);
    write.bytes(body.sender.ml_dsa);
    write.bytes(body.share);
    write.bytes(body.kem);
    write_authority(write, body.mailbox);
    write.bytes(body.inbox);
    write_name(write, body.name);
    return out;
}

[[nodiscard]] std::vector<Byte> encode_reply_body(const ReplyBody& body) {
    std::vector<Byte> out;
    out.reserve(kMaxReplyBodyBytes);
    Writer write(out);
    write.bytes(body.sender.ed25519);
    write.bytes(body.sender.ml_dsa);
    write.bytes(body.ratchet);
    write.bytes(body.inbox);
    write_name(write, body.name);
    return out;
}

// The rest of a plaintext after its signature is padding and must be zero,
// so each item has exactly one valid plaintext.
[[nodiscard]] bool zero_padding(Reader& in) {
    ByteView rest;
    if (!in.take(in.remaining(), rest)) return false;
    return std::all_of(rest.begin(), rest.end(),
                       [](Byte byte) { return byte == 0U; });
}

// An AEAD key and nonce from one HKDF expansion.
struct KeyNonce final {
    SecretArray<kAeadKeyBytes> key;
    Nonce nonce{};
};

[[nodiscard]] KeyNonce expand_key_nonce(const CryptoContext& crypto,
                                        ByteView prk,
                                        std::span<const ByteView> info) {
    SecretArray<kAeadKeyNonceBytes> material;
    crypto.hkdf_expand(prk, info,
                       std::span<Byte>(material.data(), material.size()));
    KeyNonce result;
    result.key.assign(material.view().first<kAeadKeyBytes>());
    std::copy_n(material.data() + kAeadKeyBytes, kAeadNonceBytes,
                result.nonce.begin());
    return result;
}

[[nodiscard]] KeyNonce hello_key(const CryptoContext& crypto,
                                 const PairingCode& code, ByteView salt) {
    Prk prk;
    crypto.hkdf_extract(salt, code.secret.view(), prk);
    const std::array<ByteView, 2> info{as_bytes(kPairHelloKeyLabel), code.id};
    return expand_key_nonce(crypto, prk.view(), info);
}

// The extract every post-root value expands from: salt the transcript hash,
// input the root key.
[[nodiscard]] Prk root_prk(const CryptoContext& crypto, const Secret32& root,
                           const Hash& transcript) {
    Prk prk;
    crypto.hkdf_extract(transcript, root.view(), prk);
    return prk;
}

void derive_pairing_prk(const CryptoContext& crypto, const PairingCode& code,
                        const Secret32& exchanged, const Secret32& encapsulated,
                        Prk& prk) {
    SecretArray<2U * kSharedSecretBytes> input;
    std::copy_n(exchanged.data(), kSharedSecretBytes, input.data());
    std::copy_n(encapsulated.data(), kSharedSecretBytes,
                input.data() + kSharedSecretBytes);
    crypto.hkdf_extract(code.secret.view(),
                        ByteView(input.data(), input.size()), prk);
}

[[nodiscard]] KeyNonce reply_key(const CryptoContext& crypto, const Prk& prk,
                                 const Hash& hello_transcript) {
    const std::array<ByteView, 2> info{as_bytes(kPairReplyKeyLabel),
                                       hello_transcript};
    return expand_key_nonce(crypto, prk.view(), info);
}

[[nodiscard]] Hash reply_transcript(const CryptoContext& crypto,
                                    const Hash& hello_transcript,
                                    const Key& share,
                                    const MlKemCiphertext& ciphertext,
                                    ByteView body,
                                    const CompositeSignature& signature) {
    const std::array<ByteView, 6> parts{as_bytes(kPairTranscriptLabel),
                                        hello_transcript,
                                        share,
                                        ciphertext,
                                        body,
                                        signature};
    return crypto.sha256(parts);
}

void derive_root(const CryptoContext& crypto, const Prk& prk,
                 const Hash& transcript, Secret32& root) {
    const std::array<ByteView, 2> info{as_bytes(kPairRootLabel), transcript};
    crypto.hkdf_expand(prk.view(), info,
                       std::span<Byte>(root.data(), root.size()));
}

}  // namespace

void write_authority(Writer& write, const Authority& authority) {
    write.bytes(authority.server_fingerprint);
    write.u8(static_cast<std::uint8_t>(authority.service.size()));
    write.text(authority.service);
}

bool read_authority(Reader& in, Authority& authority) {
    std::uint8_t size = 0U;
    ByteView service;
    if (!in.fixed(authority.server_fingerprint) || !in.u8(size) ||
        !in.take(size, service)) {
        return false;
    }
    authority.service.assign(reinterpret_cast<const char*>(service.data()),
                             service.size());
    return valid_service_name(authority.service);
}

void write_name(Writer& write, const std::string& name) {
    write.u8(static_cast<std::uint8_t>(name.size()));
    write.text(name);
}

bool read_name(Reader& in, std::string& name) {
    std::uint8_t size = 0U;
    ByteView bytes;
    if (!in.u8(size) || !in.take(size, bytes)) return false;
    name.assign(reinterpret_cast<const char*>(bytes.data()), bytes.size());
    return valid_contact_name(name);
}

void PairingCode::copy_from(const PairingCode& other) {
    kind = other.kind;
    id = other.id;
    secret.assign(other.secret.view());
    owner = other.owner;
    mailbox = other.mailbox;
    inbox = other.inbox;
    expires_at = other.expires_at;
}

void ScanSecrets::copy_from(const ScanSecrets& other) {
    share.assign(other.share.view());
    kem.assign(other.kem.view());
    inbox.assign(other.inbox.view());
}

void write_code_record(Writer& write, const PairingCode& code) {
    write.u8(static_cast<std::uint8_t>(code.kind));
    write.bytes(code.id);
    write.bytes(code.secret.view());
    write.bytes(code.owner);
    write_authority(write, code.mailbox);
    write.bytes(code.inbox);
    write.u64(code.expires_at);
}

bool read_code_record(Reader& in, PairingCode& code) {
    std::uint8_t kind = 0U;
    if (!in.u8(kind) ||
        kind < static_cast<std::uint8_t>(PairingKind::InPerson) ||
        kind > static_cast<std::uint8_t>(PairingKind::Link) ||
        !in.fixed(code.id) || !in.secret(code.secret) ||
        !in.fixed(code.owner) || !read_authority(in, code.mailbox) ||
        !in.fixed(code.inbox) || !in.u64(code.expires_at)) {
        return false;
    }
    code.kind = static_cast<PairingKind>(kind);
    // Zero is no time, and the largest value is the store's clock sentinel.
    return code.expires_at != 0U &&
           code.expires_at != std::numeric_limits<std::uint64_t>::max();
}

SecretBytes encode_code_record(const PairingCode& code) {
    std::vector<Byte> out;
    const WipeOnExit wiped(out);
    out.reserve(kMaxCodeRecordBytes);
    Writer write(out);
    write_code_record(write, code);
    return SecretBytes(out);
}

CodecStatus parse_code_record(ByteView record, PairingCode& code) {
    if (record.size() > kMaxCodeRecordBytes) return CodecStatus::Malformed;
    Reader in(record);
    return read_code_record(in, code) && in.at_end() ? CodecStatus::Ok
                                                     : CodecStatus::Malformed;
}

SecretBytes format_pairing_code(const PairingCode& code) {
    const SecretBytes record = encode_code_record(code);
    SecretBytes text;
    text.reserve(kMaxPairingCodeChars);
    text.append(as_bytes(kPairingCodePrefix));
    text.append(as_bytes(kPairingCodeVersion));
    append_base64url(record.view(), text);
    return text;
}

CodecStatus parse_pairing_code(std::string_view text, PairingCode& code) {
    if (text.size() > kMaxPairingCodeChars + 16U ||
        !text.starts_with(kPairingCodePrefix)) {
        return CodecStatus::Malformed;
    }
    text.remove_prefix(kPairingCodePrefix.size());
    if (!text.starts_with(kPairingCodeVersion)) {
        // A different decimal version is well formed but unsupported.
        const std::size_t colon = text.find(':');
        const bool numeric =
            colon != std::string_view::npos && colon > 0U &&
            std::all_of(text.begin(), text.begin() + colon,
                        [](char c) { return c >= '0' && c <= '9'; });
        return numeric ? CodecStatus::Unsupported : CodecStatus::Malformed;
    }
    text.remove_prefix(kPairingCodeVersion.size());
    if (text.size() > kMaxPairingCodeChars) return CodecStatus::Malformed;
    SecretBytes record;
    if (!parse_base64url(text, record)) return CodecStatus::Malformed;
    return parse_code_record(record.view(), code);
}

Hash mailbox_address(const CryptoContext& crypto,
                     const Secret32& inbox_secret) {
    const std::array<ByteView, 2> parts{as_bytes(kMailboxAddressDomain),
                                        inbox_secret.view()};
    return crypto.sha256(parts);
}

BuiltHello build_hello(const CryptoContext& crypto, const Signer& signer,
                       const PairingCode& code, const HelloBody& body) {
    const SecretBytes record = encode_code_record(code);
    const std::vector<Byte> body_bytes = encode_hello_body(body);
    const std::array<ByteView, 2> signed_parts{record.view(), body_bytes};
    const CompositeSignature signature =
        sign_composite(crypto, signer.ed25519, signer.ml_dsa,
                       signer.fingerprint, kPairHelloLabel, signed_parts);

    std::vector<Byte> plaintext;
    const WipeOnExit wiped(plaintext);
    plaintext.reserve(kHelloPlaintextBytes);
    Writer write(plaintext);
    write.bytes(body_bytes);
    write.bytes(signature);
    plaintext.resize(kHelloPlaintextBytes, 0U);

    BuiltHello result;
    result.item.resize(kLargeItemBytes);
    const std::span<Byte> salt(result.item.data(), kHelloSaltBytes);
    crypto.random(salt);
    const KeyNonce key = hello_key(crypto, code, salt);
    crypto.seal(key.key.view(), key.nonce, salt, plaintext,
                std::span<Byte>(result.item).subspan(kHelloSaltBytes));

    const std::array<ByteView, 4> transcript{
        as_bytes(kPairHelloTranscriptLabel), record.view(), body_bytes,
        signature};
    result.transcript = crypto.sha256(transcript);
    return result;
}

Status open_hello(const CryptoContext& crypto, const PairingCode& code,
                  ByteView item, ReceivedHello& out) {
    if (item.size() != kLargeItemBytes) return Status::Malformed;
    const ByteView salt = item.first(kHelloSaltBytes);
    const KeyNonce key = hello_key(crypto, code, salt);
    std::vector<Byte> buffer(kHelloPlaintextBytes);
    const WipeOnExit wiped(buffer);
    if (!crypto.open(key.key.view(), key.nonce, salt,
                     item.subspan(kHelloSaltBytes), buffer)) {
        return Status::AuthenticationFailed;
    }
    Reader in(buffer);
    HelloBody& body = out.body;
    if (!in.fixed(body.sender.ed25519) || !in.fixed(body.sender.ml_dsa) ||
        !in.fixed(body.share) || !in.fixed(body.kem) ||
        !read_authority(in, body.mailbox) || !in.fixed(body.inbox) ||
        !read_name(in, body.name)) {
        return Status::Malformed;
    }
    const std::size_t body_size = in.consumed();
    if (!in.fixed(out.signature) || !zero_padding(in)) return Status::Malformed;
    out.body_bytes.assign(
        buffer.begin(),
        buffer.begin() + static_cast<std::ptrdiff_t>(body_size));
    return Status::Ok;
}

Verification verify_hello(const CryptoContext& crypto, const PairingCode& code,
                          const ReceivedHello& hello) {
    const SecretBytes record = encode_code_record(code);
    const std::array<ByteView, 2> signed_parts{record.view(), hello.body_bytes};
    return verify_composite(crypto, hello.body.sender, kPairHelloLabel,
                            signed_parts, hello.signature);
}

Hash hello_transcript(const CryptoContext& crypto, const PairingCode& code,
                      const ReceivedHello& hello) {
    const SecretBytes record = encode_code_record(code);
    const std::array<ByteView, 4> parts{as_bytes(kPairHelloTranscriptLabel),
                                        record.view(), hello.body_bytes,
                                        hello.signature};
    return crypto.sha256(parts);
}

Status build_reply(const CryptoContext& crypto, const Signer& signer,
                   const PairingCode& code, const Hash& hello_transcript,
                   const HelloBody& hello, const ReplyBody& body,
                   BuiltReply& out) {
    Secret32 share_private;
    crypto.random(std::span<Byte>(share_private.data(), share_private.size()));
    const Key share = crypto.x25519_public_key(share_private);
    Secret32 exchanged;
    if (!crypto.x25519_agree(share_private, hello.share, exchanged)) {
        return Status::Malformed;
    }
    MlKemCiphertext ciphertext{};
    Secret32 encapsulated;
    if (!crypto.ml_kem_encapsulate(hello.kem, ciphertext, encapsulated)) {
        return Status::Malformed;
    }
    Prk prk;
    derive_pairing_prk(crypto, code, exchanged, encapsulated, prk);

    const std::vector<Byte> body_bytes = encode_reply_body(body);
    const std::array<ByteView, 4> signed_parts{hello_transcript, share,
                                               ciphertext, body_bytes};
    const CompositeSignature signature =
        sign_composite(crypto, signer.ed25519, signer.ml_dsa,
                       signer.fingerprint, kPairReplyLabel, signed_parts);

    std::vector<Byte> plaintext;
    const WipeOnExit wiped(plaintext);
    plaintext.reserve(kReplyPlaintextBytes);
    Writer write(plaintext);
    write.bytes(body_bytes);
    write.bytes(signature);
    plaintext.resize(kReplyPlaintextBytes, 0U);

    out.item.assign(kLargeItemBytes, 0U);
    std::copy(share.begin(), share.end(), out.item.begin());
    std::copy(ciphertext.begin(), ciphertext.end(),
              out.item.begin() + static_cast<std::ptrdiff_t>(kKeyBytes));
    const KeyNonce key = reply_key(crypto, prk, hello_transcript);
    crypto.seal(key.key.view(), key.nonce,
                ByteView(out.item.data(), kReplyPublicBytes), plaintext,
                std::span<Byte>(out.item).subspan(kReplyPublicBytes));

    out.transcript = reply_transcript(crypto, hello_transcript, share,
                                      ciphertext, body_bytes, signature);
    derive_root(crypto, prk, out.transcript, out.root);
    return Status::Ok;
}

Status open_reply(const CryptoContext& crypto, const PairingCode& code,
                  const ScanSecrets& secrets, const Hash& hello_transcript,
                  ByteView item, ReceivedReply& out) {
    if (item.size() != kLargeItemBytes) return Status::Malformed;
    std::copy_n(item.begin(), kKeyBytes, out.share.begin());
    std::copy_n(item.begin() + static_cast<std::ptrdiff_t>(kKeyBytes),
                kMlKemCiphertextBytes, out.ciphertext.begin());
    Secret32 exchanged;
    // A share that gives no shared secret cannot be from the owner, whose
    // share is a fresh key: the item is refused like any other forgery.
    if (!crypto.x25519_agree(secrets.share, out.share, exchanged)) {
        return Status::AuthenticationFailed;
    }
    Secret32 encapsulated;
    crypto.ml_kem_decapsulate(secrets.kem, out.ciphertext, encapsulated);
    derive_pairing_prk(crypto, code, exchanged, encapsulated, out.prk);

    std::vector<Byte> buffer(kReplyPlaintextBytes);
    const WipeOnExit wiped(buffer);
    const KeyNonce key = reply_key(crypto, out.prk, hello_transcript);
    if (!crypto.open(key.key.view(), key.nonce, item.first(kReplyPublicBytes),
                     item.subspan(kReplyPublicBytes), buffer)) {
        return Status::AuthenticationFailed;
    }
    Reader in(buffer);
    ReplyBody& body = out.body;
    if (!in.fixed(body.sender.ed25519) || !in.fixed(body.sender.ml_dsa) ||
        !in.fixed(body.ratchet) || !in.fixed(body.inbox) ||
        !read_name(in, body.name)) {
        return Status::Malformed;
    }
    const std::size_t body_size = in.consumed();
    if (!in.fixed(out.signature) || !zero_padding(in)) return Status::Malformed;
    out.body_bytes.assign(
        buffer.begin(),
        buffer.begin() + static_cast<std::ptrdiff_t>(body_size));
    return Status::Ok;
}

Verification verify_reply(const CryptoContext& crypto, const PairingCode& code,
                          const Hash& hello_transcript,
                          const ReceivedReply& reply) {
    if (fingerprint2(crypto, reply.body.sender) != code.owner) {
        return Verification::Invalid;
    }
    const std::array<ByteView, 4> signed_parts{
        hello_transcript, reply.share, reply.ciphertext, reply.body_bytes};
    return verify_composite(crypto, reply.body.sender, kPairReplyLabel,
                            signed_parts, reply.signature);
}

void finish_reply(const CryptoContext& crypto, const Hash& hello_transcript,
                  const ReceivedReply& reply, Hash& transcript,
                  Secret32& root) {
    transcript =
        reply_transcript(crypto, hello_transcript, reply.share,
                         reply.ciphertext, reply.body_bytes, reply.signature);
    derive_root(crypto, reply.prk, transcript, root);
}

ShortCode short_code(const CryptoContext& crypto, const Secret32& root,
                     const Hash& transcript) {
    const Prk prk = root_prk(crypto, root, transcript);
    const std::array<ByteView, 1> info{as_bytes(kPairShortCodeLabel)};
    std::array<Byte, 8> number{};
    crypto.hkdf_expand(prk.view(), info, number);
    ShortCode code{};
    decimal_digits(number, code);
    wipe(number.data(), number.size());
    return code;
}

std::vector<Byte> seal_confirm(const CryptoContext& crypto,
                               const Secret32& root, const Hash& transcript,
                               const Key& ratchet) {
    const Prk prk = root_prk(crypto, root, transcript);
    const std::array<ByteView, 1> info{as_bytes(kPairConfirmLabel)};
    const KeyNonce key = expand_key_nonce(crypto, prk.view(), info);
    std::array<Byte, kConfirmPlaintextBytes> plaintext{};
    std::copy(transcript.begin(), transcript.end(), plaintext.begin());
    std::copy(ratchet.begin(), ratchet.end(),
              plaintext.begin() + static_cast<std::ptrdiff_t>(kHashBytes));
    std::vector<Byte> item(kSmallItemBytes);
    crypto.seal(key.key.view(), key.nonce, {}, plaintext, item);
    return item;
}

Status open_confirm(const CryptoContext& crypto, const Secret32& root,
                    const Hash& transcript, ByteView item, Key& ratchet) {
    if (item.size() != kSmallItemBytes) return Status::AuthenticationFailed;
    const Prk prk = root_prk(crypto, root, transcript);
    const std::array<ByteView, 1> info{as_bytes(kPairConfirmLabel)};
    const KeyNonce key = expand_key_nonce(crypto, prk.view(), info);
    std::array<Byte, kConfirmPlaintextBytes> plaintext{};
    if (!crypto.open(key.key.view(), key.nonce, {}, item, plaintext)) {
        return Status::AuthenticationFailed;
    }
    Reader in(plaintext);
    Hash echoed{};
    if (!in.fixed(echoed) || !in.fixed(ratchet) || !zero_padding(in) ||
        !constant_time_equal(echoed, transcript)) {
        return Status::AuthenticationFailed;
    }
    return Status::Ok;
}

}  // namespace ito::call
