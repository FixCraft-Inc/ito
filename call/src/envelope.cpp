/* Copyright (C) 2026 FixCraft Inc. AGPL-3.0-or-later. */

#include "envelope.hpp"

#include <algorithm>
#include <vector>

#include "codec.hpp"

namespace ito::call {
namespace {

[[nodiscard]] bool id_less(const MessageId& a, const MessageId& b) noexcept {
    return std::lexicographical_compare(a.begin(), a.end(), b.begin(), b.end());
}

// 1 to 64 IDs, strictly ascending.
[[nodiscard]] bool canonical_ids(ByteView ids) noexcept {
    if (ids.empty() || ids.size() % kMessageIdBytes != 0U ||
        ids.size() / kMessageIdBytes > kMaxMessageIds) {
        return false;
    }
    for (std::size_t offset = kMessageIdBytes; offset < ids.size();
         offset += kMessageIdBytes) {
        const ByteView previous =
            ids.subspan(offset - kMessageIdBytes, kMessageIdBytes);
        const ByteView current = ids.subspan(offset, kMessageIdBytes);
        if (!std::lexicographical_compare(previous.begin(), previous.end(),
                                          current.begin(), current.end())) {
            return false;
        }
    }
    return true;
}

[[nodiscard]] bool listed(MessageKind kind) noexcept {
    return kind == MessageKind::Receipt || kind == MessageKind::Check ||
           kind == MessageKind::Missing;
}

}  // namespace

void Envelope::copy_from(const Envelope& other) {
    kind = other.kind;
    id = other.id;
    sent_ms = other.sent_ms;
    resent = other.resent;
    payload.clear();
    payload.append(other.payload.view());
}

bool kept_until_delivered(MessageKind kind) noexcept {
    return kind == MessageKind::Text || kind == MessageKind::Profile ||
           kind == MessageKind::Timer;
}

Status check_payload(MessageKind kind, ByteView payload) {
    switch (kind) {
        case MessageKind::Text:
            return valid_message_text(payload) ? Status::Ok : Status::Malformed;
        case MessageKind::Receipt:
            return payload.size() > 1U &&
                           (payload[0] ==
                                static_cast<Byte>(ReceiptKind::Delivered) ||
                            payload[0] ==
                                static_cast<Byte>(ReceiptKind::Read)) &&
                           canonical_ids(payload.subspan(1U))
                       ? Status::Ok
                       : Status::Malformed;
        case MessageKind::Check:
        case MessageKind::Missing:
            return canonical_ids(payload) ? Status::Ok : Status::Malformed;
        case MessageKind::Profile: {
            const std::string_view name(
                reinterpret_cast<const char*>(payload.data()), payload.size());
            return valid_contact_name(name) ? Status::Ok : Status::Malformed;
        }
        case MessageKind::Timer:
            return payload.size() == 1U &&
                           payload[0] <= static_cast<Byte>(TimerSetting::Month)
                       ? Status::Ok
                       : Status::Malformed;
        case MessageKind::Ring: {
            Invitation invitation;
            const CodecStatus parsed = parse_invitation(payload, invitation);
            if (parsed == CodecStatus::Unsupported) return Status::Unsupported;
            return parsed == CodecStatus::Ok && invitation.version == 2U &&
                           invitation.expires_at > invitation.issued_at &&
                           invitation.expires_at - invitation.issued_at <=
                               kRingRoomSeconds &&
                           invitation.invitation_id != invitation.room_id &&
                           invitation.initiator != invitation.responder
                       ? Status::Ok
                       : Status::Malformed;
        }
        case MessageKind::RingEnd:
            return payload.size() == kIdBytes + 1U &&
                           payload.back() >=
                               static_cast<Byte>(RingEndReason::Canceled) &&
                           payload.back() <=
                               static_cast<Byte>(RingEndReason::Missed)
                       ? Status::Ok
                       : Status::Malformed;
        case MessageKind::Inbox:
            return Status::Unsupported;
    }
    return Status::Unsupported;
}

Status check_envelope(const Envelope& envelope) {
    const Status payload =
        check_payload(envelope.kind, envelope.payload.view());
    if (payload != Status::Ok) return payload;
    return envelope.resent && !kept_until_delivered(envelope.kind)
               ? Status::Malformed
               : Status::Ok;
}

std::size_t envelope_size(const Envelope& envelope) noexcept {
    return kEnvelopeFixedBytes + envelope.payload.size();
}

void write_envelope(Writer& write, const Envelope& envelope) {
    write.u8(static_cast<std::uint8_t>(envelope.kind));
    write.bytes(envelope.id);
    write.u64(envelope.sent_ms);
    write.u8(envelope.resent ? kEnvelopeResent : 0U);
    write.u16(static_cast<std::uint16_t>(envelope.payload.size()));
    write.bytes(envelope.payload.view());
}

Status read_envelope(ByteView plaintext, Envelope& out) {
    Reader in(plaintext);
    std::uint8_t kind = 0U;
    std::uint8_t flags = 0U;
    std::uint16_t size = 0U;
    ByteView payload;
    if (!in.u8(kind) || !in.fixed(out.id) || !in.u64(out.sent_ms) ||
        !in.u8(flags) || (flags & ~kEnvelopeResent) != 0U || !in.u16(size) ||
        size > kMaxTextBytes || !in.take(size, payload)) {
        return Status::Malformed;
    }
    ByteView rest;
    if (!in.take(in.remaining(), rest) ||
        !std::all_of(rest.begin(), rest.end(),
                     [](Byte byte) { return byte == 0U; })) {
        return Status::Malformed;
    }
    // A kind outside the table is a later version's: well formed, but not
    // one this core can act on.
    if (kind < static_cast<std::uint8_t>(MessageKind::Text) ||
        kind > static_cast<std::uint8_t>(MessageKind::Timer)) {
        return Status::Unsupported;
    }
    out.kind = static_cast<MessageKind>(kind);
    out.resent = (flags & kEnvelopeResent) != 0U;
    out.payload.clear();
    out.payload.reserve(payload.size());
    out.payload.append(payload);
    return check_envelope(out);
}

Status encode_ids(MessageKind kind, ReceiptKind receipt,
                  std::span<const MessageId> ids, SecretBytes& payload) {
    if (!listed(kind) || ids.empty() || ids.size() > kMaxMessageIds) {
        return Status::InvalidArgument;
    }
    std::vector<MessageId> sorted(ids.begin(), ids.end());
    std::sort(sorted.begin(), sorted.end(), id_less);
    if (std::adjacent_find(sorted.begin(), sorted.end()) != sorted.end()) {
        return Status::InvalidArgument;
    }
    payload.clear();
    payload.reserve(1U + sorted.size() * kMessageIdBytes);
    if (kind == MessageKind::Receipt) {
        const std::array<Byte, 1> lead{static_cast<Byte>(receipt)};
        payload.append(lead);
    }
    for (const MessageId& id : sorted) payload.append(id);
    return Status::Ok;
}

ByteView payload_ids(MessageKind kind, ByteView payload) noexcept {
    if (kind == MessageKind::Receipt) return payload.subspan(1U);
    return listed(kind) ? payload : ByteView{};
}

MessageId id_at(ByteView ids, std::size_t index) noexcept {
    MessageId id{};
    std::copy_n(
        ids.begin() + static_cast<std::ptrdiff_t>(index * kMessageIdBytes),
        kMessageIdBytes, id.begin());
    return id;
}

}  // namespace ito::call
