/* Copyright (C) 2026 FixCraft Inc. AGPL-3.0-or-later. */

// The message ratchet of docs/MESSAGE_SECURITY.md: the Double Ratchet with
// X25519 at each turn and an ML-KEM-1024 secret mixed into a root step at
// most 20 root steps or 24 hours apart. These functions seal and open one
// ratchet message against a state value. They keep no other state, perform
// no I/O and apply no trust policy: the session decides who may send, saves
// each new state and hands out items only after that.
//
// The caller passes a copy of its state. A refused message leaves that copy
// in an unspecified state, so the session discards it and keeps its own.

#pragma once

#include <array>
#include <cstdint>
#include <string_view>
#include <vector>

#include "bytes.hpp"
#include "crypto.hpp"
#include "pairing.hpp"
#include "status.hpp"

namespace ito::call {

// Labels. Each ends in its zero byte.
inline constexpr std::string_view kRatchetRootLabel{"ito/ratchet/1 root\0",
                                                    19U};
inline constexpr std::string_view kMessageKeyLabel{"ito/message/1 key\0", 18U};
inline constexpr std::string_view kMessageDataLabel{"ito/message/1\0", 14U};

inline constexpr std::uint8_t kMessageVersion = 1U;
inline constexpr std::uint8_t kHeaderAdvertises = 1U;
inline constexpr std::uint8_t kHeaderAnswers = 2U;

// Version, flags, ratchet key, previous chain length, message number, salt.
inline constexpr std::size_t kHeaderFixedBytes =
    1U + 1U + kKeyBytes + 4U + 4U + kMessageSaltBytes;
inline constexpr std::size_t kHeaderKemBytes = 4U + kMlKemPublicKeyBytes;
static_assert(kMlKemPublicKeyBytes == kMlKemCiphertextBytes);
inline constexpr std::size_t kMaxHeaderBytes =
    kHeaderFixedBytes + 2U * kHeaderKemBytes;

using ChainKey = SecretArray<kChainKeyBytes>;
using MessageKey = SecretArray<kChainKeyBytes>;
using Salt = std::array<Byte, kMessageSaltBytes>;

// What a session starts from: the pairing's root key and transcript, this
// side's first ratchet key and the contact's, which pairing exchanged.
struct SessionSeed final {
    PairingRole role{PairingRole::Owner};
    Secret32 root;
    Hash transcript{};
    Secret32 own_ratchet;
    Key peer_ratchet{};
    std::uint64_t paired_at{0U};
};

// A message key kept for a message that has not arrived yet.
struct SkippedKey final {
    Key ratchet{};
    std::uint32_t number{0U};
    MessageKey key;
    std::uint64_t stored_at{0U};

    void copy_from(const SkippedKey& other);
};

struct RatchetState final {
    Secret32 root;
    // The session's clock in Unix seconds. It never moves back.
    std::uint64_t time{0U};
    // The last root step that mixed an ML-KEM secret, or the pairing.
    std::uint64_t quantum_time{0U};
    std::uint32_t quantum_steps{0U};
    // This side's current ratchet key and the contact's.
    Secret32 own_ratchet;
    Key peer_ratchet{};

    // The sending chain. Without one, the next message starts a chain, and
    // last_length is the length of the chain before it.
    bool sending{false};
    ChainKey send_key;
    std::uint32_t send_next{0U};
    std::uint32_t send_previous{0U};
    std::uint32_t last_length{0U};
    // An ML-KEM ciphertext the sending chain answers, in all its headers.
    bool send_answers{false};
    std::uint32_t send_answer_id{0U};
    MlKemCiphertext send_ciphertext{};

    // The chain of the contact's current ratchet key.
    bool receiving{false};
    ChainKey receive_key;
    std::uint32_t receive_next{0U};
    // The chain before it, kept to recognize a repeated delivery.
    bool has_previous{false};
    Key previous_ratchet{};
    std::uint32_t previous_next{0U};

    // This side's advertised ML-KEM key, until a chain answers it. IDs count
    // up from 1, and own_kem_id is the last one used.
    std::uint32_t own_kem_id{0U};
    bool own_kem{false};
    MlKemSeed own_kem_seed;
    // The contact's newest advertised key that no chain of ours answered.
    std::uint32_t answered_id{0U};
    bool peer_kem{false};
    std::uint32_t peer_kem_id{0U};
    MlKemPublicKey peer_kem_key{};

    // Ascending by ratchet key, then number.
    std::vector<SkippedKey> skipped;

    void copy_from(const RatchetState& other);
};

// The randomness one sealed message may use. The session draws it. Tests
// pass fixed values to reproduce the contract's vectors.
struct MessageRandom final {
    Salt salt{};
    // A new sending chain's ratchet key, used when this message starts one.
    Secret32 ratchet;
    // A new ML-KEM key, used when this message must advertise one.
    MlKemSeed kem;
};

// Sender first, then recipient, in every message's associated data.
struct Fingerprints final {
    Hash own{};
    Hash peer{};
};

// Builds the first state from the pairing. Malformed when the contact's
// first ratchet key gives no X25519 secret.
[[nodiscard]] Status start_ratchet(const CryptoContext& crypto,
                                   const SessionSeed& seed, RatchetState& out);

// Moves the session's clock forward to now and forgets skipped keys older
// than their lifetime. A clock that moved back changes nothing.
void advance_time(RatchetState& state, std::uint64_t now);

// Seals one envelope's bytes as the next message. Capacity when the
// sending chain is full.
[[nodiscard]] Status seal_message(const CryptoContext& crypto,
                                  RatchetState& state,
                                  const Fingerprints& fingerprints,
                                  ByteView envelope,
                                  const MessageRandom& random,
                                  std::vector<Byte>& item);

// Opens one item into its plaintext (the envelope and its zero padding).
// Malformed for a size or header outside the grammar, Unsupported for
// another version, AlreadySpent for a message key already used,
// AuthenticationFailed when it does not decrypt, Capacity when it would skip
// more keys than the bounds allow.
[[nodiscard]] Status open_message(const CryptoContext& crypto,
                                  RatchetState& state,
                                  const Fingerprints& fingerprints,
                                  ByteView item, SecretBytes& plaintext);

// The smallest mailbox item size that holds a message, or 0 when none does.
[[nodiscard]] std::size_t item_size_for(std::size_t header,
                                        std::size_t envelope) noexcept;

}  // namespace ito::call
