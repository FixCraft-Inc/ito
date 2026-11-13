/* Copyright (C) 2026 FixCraft Inc. AGPL-3.0-or-later. */

// Pairing 1 of docs/MESSAGE_SECURITY.md: the pairing code, the hello, reply
// and confirm items, and the key schedule that turns one meeting into a
// shared root key. These functions encode, seal, open and verify. They keep
// no state and apply no trust policy: the store decides which code is open,
// who may pair and what is saved.
//
// Roles: the owner shows the code, the scanner reads it. The scanner sends
// the hello to the code's pairing inbox, the owner answers with the reply,
// and the scanner's confirm proves to the owner that both hold the root.

#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "bytes.hpp"
#include "codec.hpp"
#include "crypto.hpp"
#include "identity.hpp"
#include "status.hpp"

namespace ito::call {

enum class PairingKind : std::uint8_t { InPerson = 1, Link = 2 };
// Which side of a pairing this installation was.
enum class PairingRole : std::uint8_t { Owner = 1, Scanner = 2 };

inline constexpr std::string_view kPairingCodePrefix = "ito-pair:";
inline constexpr std::string_view kPairingCodeVersion = "1:";

// Labels. Each ends in its zero byte.
inline constexpr std::string_view kMailboxAddressDomain{
    "ito/mailbox-address/1\0", 22U};
inline constexpr std::string_view kPairHelloKeyLabel{"ito/pair/1 hello key\0",
                                                     21U};
inline constexpr std::string_view kPairHelloLabel{"ito/pair/1 hello\0", 17U};
inline constexpr std::string_view kPairHelloTranscriptLabel{
    "ito/pair/1 hello transcript\0", 28U};
inline constexpr std::string_view kPairReplyKeyLabel{"ito/pair/1 reply key\0",
                                                     21U};
inline constexpr std::string_view kPairReplyLabel{"ito/pair/1 reply\0", 17U};
inline constexpr std::string_view kPairTranscriptLabel{
    "ito/pair/1 transcript\0", 22U};
inline constexpr std::string_view kPairRootLabel{"ito/pair/1 root\0", 16U};
inline constexpr std::string_view kPairShortCodeLabel{"ito/pair/1 short-code\0",
                                                      22U};
inline constexpr std::string_view kPairConfirmLabel{"ito/pair/1 confirm\0",
                                                    19U};

// What a pairing code carries. The secret makes it a credential: whoever
// holds the code can write the one hello the owner accepts.
struct PairingCode final {
    PairingKind kind{PairingKind::InPerson};
    PairingId id{};
    Secret32 secret;
    Hash owner{};  // the owner's fingerprint 2
    Authority mailbox;
    Hash inbox{};  // the pairing inbox's address
    std::uint64_t expires_at{0U};

    void copy_from(const PairingCode& other);
};

// Kind, ID, secret, owner, server fingerprint, u8 service length and the
// service, inbox, expiry.
inline constexpr std::size_t kCodeRecordFixedBytes =
    1U + kPairingIdBytes + 32U + kHashBytes + kKeyBytes + 1U + kHashBytes + 8U;
static_assert(kCodeRecordFixedBytes == 154U);
inline constexpr std::size_t kMaxCodeRecordBytes =
    kCodeRecordFixedBytes + kMaxServiceBytes;
// The prefix, the version and unpadded base64url of the longest record.
inline constexpr std::size_t kMaxPairingCodeChars =
    kPairingCodePrefix.size() + kPairingCodeVersion.size() +
    (kMaxCodeRecordBytes * 4U + 2U) / 3U;
static_assert(kMaxPairingCodeChars == 302U);

// Field codecs the identity snapshot shares: an authority as server
// fingerprint, u8 service length and service; a name as u8 length and UTF-8;
// the code record as below. Readers check every value they read.
void write_authority(Writer& write, const Authority& authority);
[[nodiscard]] bool read_authority(Reader& in, Authority& authority);
void write_name(Writer& write, const std::string& name);
[[nodiscard]] bool read_name(Reader& in, std::string& name);
void write_code_record(Writer& write, const PairingCode& code);
[[nodiscard]] bool read_code_record(Reader& in, PairingCode& code);

[[nodiscard]] SecretBytes encode_code_record(const PairingCode& code);
[[nodiscard]] CodecStatus parse_code_record(ByteView record, PairingCode& code);
// The code as text, "ito-pair:1:" and unpadded base64url of the record. It
// holds the pairing secret.
[[nodiscard]] SecretBytes format_pairing_code(const PairingCode& code);
// Refuses noncanonical base64url, other versions (Unsupported) and any
// record that is not exactly canonical.
[[nodiscard]] CodecStatus parse_pairing_code(std::string_view text,
                                             PairingCode& code);

// SHA-256 of "ito/mailbox-address/1", zero and the inbox secret.
[[nodiscard]] Hash mailbox_address(const CryptoContext& crypto,
                                   const Secret32& inbox_secret);

// The scanner's hello. inbox is the scanner's inbox for the owner.
struct HelloBody final {
    Identity2 sender;
    Key share{};
    MlKemPublicKey kem{};
    Authority mailbox;
    Hash inbox{};
    std::string name;
};

// The owner's reply. inbox is the owner's inbox for the scanner, and
// ratchet the owner's first ratchet public key.
struct ReplyBody final {
    Identity2 sender;
    Key ratchet{};
    Hash inbox{};
    std::string name;
};

// The scanner's private values for one hello, kept until the reply.
struct ScanSecrets final {
    Secret32 share;
    MlKemSeed kem;
    Secret32 inbox;

    void copy_from(const ScanSecrets& other);
};

// The private keys of identity 2, borrowed for one signature.
struct Signer final {
    const Seed& ed25519;
    const Secret32& ml_dsa;
    const Hash& fingerprint;
};

// The scanner seals a hello to the code's pairing inbox. transcript is the
// hello transcript hash, which the reply's keys and signature build on.
struct BuiltHello final {
    std::vector<Byte> item;
    Hash transcript{};
};
[[nodiscard]] BuiltHello build_hello(const CryptoContext& crypto,
                                     const Signer& signer,
                                     const PairingCode& code,
                                     const HelloBody& body);

// The owner opens a hello: decryption and structure only. AuthenticationFailed
// when it does not decrypt under the code, Malformed when what decrypts is
// not one canonical hello. The signature is checked separately, after the
// store's cheaper policy checks.
struct ReceivedHello final {
    HelloBody body;
    CompositeSignature signature{};
    std::vector<Byte> body_bytes;
};
[[nodiscard]] Status open_hello(const CryptoContext& crypto,
                                const PairingCode& code, ByteView item,
                                ReceivedHello& out);
[[nodiscard]] Verification verify_hello(const CryptoContext& crypto,
                                        const PairingCode& code,
                                        const ReceivedHello& hello);
[[nodiscard]] Hash hello_transcript(const CryptoContext& crypto,
                                    const PairingCode& code,
                                    const ReceivedHello& hello);

// The owner answers a verified hello. The ratchet key and the owner's inbox
// are generated by the caller and passed in. Malformed when the scanner's
// X25519 share or ML-KEM key cannot be used.
struct BuiltReply final {
    std::vector<Byte> item;
    Secret32 root;
    Hash transcript{};
};
[[nodiscard]] Status build_reply(const CryptoContext& crypto,
                                 const Signer& signer, const PairingCode& code,
                                 const Hash& hello_transcript,
                                 const HelloBody& hello, const ReplyBody& body,
                                 BuiltReply& out);

// The scanner opens the reply with its saved secrets. AuthenticationFailed
// when it does not decrypt, Malformed when its content is not canonical.
struct ReceivedReply final {
    ReplyBody body;
    CompositeSignature signature{};
    std::vector<Byte> body_bytes;
    Key share{};
    MlKemCiphertext ciphertext{};
    Prk prk;
};
[[nodiscard]] Status open_reply(const CryptoContext& crypto,
                                const PairingCode& code,
                                const ScanSecrets& secrets,
                                const Hash& hello_transcript, ByteView item,
                                ReceivedReply& out);
// The reply must come from the identity whose fingerprint the code named.
[[nodiscard]] Verification verify_reply(const CryptoContext& crypto,
                                        const PairingCode& code,
                                        const Hash& hello_transcript,
                                        const ReceivedReply& reply);
// The transcript hash and root key both sides now share.
void finish_reply(const CryptoContext& crypto, const Hash& hello_transcript,
                  const ReceivedReply& reply, Hash& transcript, Secret32& root);

using ShortCode = std::array<char, kShortCodeDigits>;
// Six digits both screens show after an in-person pairing.
[[nodiscard]] ShortCode short_code(const CryptoContext& crypto,
                                   const Secret32& root,
                                   const Hash& transcript);

// The scanner's confirm: the transcript hash and its first ratchet public
// key, sealed under a key only the two phones can derive. It is the same
// bytes each time it is built, so a resend is safe.
[[nodiscard]] std::vector<Byte> seal_confirm(const CryptoContext& crypto,
                                             const Secret32& root,
                                             const Hash& transcript,
                                             const Key& ratchet);
// AuthenticationFailed unless it is exactly the confirm for this root and
// transcript.
[[nodiscard]] Status open_confirm(const CryptoContext& crypto,
                                  const Secret32& root, const Hash& transcript,
                                  ByteView item, Key& ratchet);

}  // namespace ito::call
