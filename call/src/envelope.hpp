/* Copyright (C) 2026 FixCraft Inc. AGPL-3.0-or-later. */

// The envelope each ratchet message carries (docs/MESSAGE_SECURITY.md,
// "Messages inside the ratchet"): a kind, a message ID, the sender's time, a
// Resent flag and a payload whose grammar the kind fixes. These functions
// encode and check bytes only. The session decides what a kind does.

#pragma once

#include <array>
#include <cstdint>
#include <span>

#include "bytes.hpp"
#include "status.hpp"

namespace ito::call {

enum class MessageKind : std::uint8_t {
    Text = 1,
    Receipt = 2,
    Check = 3,
    Missing = 4,
    Ring = 5,
    RingEnd = 6,
    Inbox = 7,
    Profile = 8,
    Timer = 9,
};

// Ring end names the invitation ID (32 bytes), then one reason byte.
enum class RingEndReason : std::uint8_t {
    Canceled = 1,
    Declined = 2,
    Busy = 3,
    Missed = 4
};

enum class ReceiptKind : std::uint8_t { Delivered = 1, Read = 2 };
enum class TimerSetting : std::uint8_t {
    Off = 0,
    Day = 1,
    Week = 2,
    Month = 3
};

using MessageId = std::array<Byte, kMessageIdBytes>;

// Kind, ID, sent milliseconds, flags and payload length.
inline constexpr std::size_t kEnvelopeFixedBytes =
    1U + kMessageIdBytes + 8U + 1U + 2U;
inline constexpr std::size_t kMaxEnvelopeBytes =
    kEnvelopeFixedBytes + kMaxTextBytes;
inline constexpr std::uint8_t kEnvelopeResent = 1U;

// The payload holds a person's text, so it wipes itself.
struct Envelope final {
    MessageKind kind{MessageKind::Text};
    MessageId id{};
    std::uint64_t sent_ms{0U};
    bool resent{false};
    SecretBytes payload;

    void copy_from(const Envelope& other);
};

// Text, Profile and Timer wait in the outbox until a receipt names them.
// Receipts, checks and missing lists are rebuilt when needed instead.
[[nodiscard]] bool kept_until_delivered(MessageKind kind) noexcept;

// Ok when the payload is canonical for a kind this core implements, Malformed
// when it is not, Unsupported for a reserved or unknown kind.
[[nodiscard]] Status check_payload(MessageKind kind, ByteView payload);
// The same, plus the Resent flag only on kinds that are resent.
[[nodiscard]] Status check_envelope(const Envelope& envelope);

[[nodiscard]] std::size_t envelope_size(const Envelope& envelope) noexcept;
void write_envelope(Writer& write, const Envelope& envelope);
// Reads one envelope from the start of a decrypted plaintext and requires
// every byte after it to be zero, so each plaintext has one valid form.
[[nodiscard]] Status read_envelope(ByteView plaintext, Envelope& out);

// A Receipt, Check or Missing payload: 1 to 64 distinct IDs, which the core
// writes in ascending order so each list has one encoding. A receipt puts
// its kind first. InvalidArgument for an empty, long or repeating list.
[[nodiscard]] Status encode_ids(MessageKind kind, ReceiptKind receipt,
                                std::span<const MessageId> ids,
                                SecretBytes& payload);
// The IDs of a payload that check_payload accepted, 16 bytes each.
[[nodiscard]] ByteView payload_ids(MessageKind kind, ByteView payload) noexcept;
[[nodiscard]] MessageId id_at(ByteView ids, std::size_t index) noexcept;

}  // namespace ito::call
