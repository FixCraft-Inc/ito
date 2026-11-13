/* Copyright (C) 2026 FixCraft Inc. AGPL-3.0-or-later. */

// One paired contact's message session (docs/MESSAGE_SECURITY.md): the
// ratchet state, the outbox of messages the contact has not confirmed, and
// the exact snapshot that holds both. The platform seals and publishes each
// snapshot as it does the identity snapshot.
//
// Every change follows the store's rule: build a candidate, persist it, and
// only then make it current and hand out what it produced. Receiving adds
// one step before the persist: the platform stores a history message. So a
// crash leaves either nothing changed or a repeat delivery the platform
// recognizes by its message ID.
//
// The store stays the owner of trust, the contact's mailbox and the pairing
// seed. The session reads them at each operation and refuses to act for a
// contact that was blocked or paired again since it was opened.

#pragma once

#include <functional>
#include <memory>
#include <mutex>
#include <string_view>
#include <vector>

#include "envelope.hpp"
#include "invitation.hpp"
#include "ratchet.hpp"
#include "store.hpp"

namespace ito::call {

inline constexpr std::string_view kSessionSnapshotDomain{
    "ito/session-snapshot/1\0", 23U};

// A message the contact has not confirmed. A check is due once the later of
// its sealing and its last check is a hold period old.
struct OutboxEntry final {
    Envelope envelope;
    std::uint64_t sealed_at{0U};
    std::uint64_t checked_at{0U};

    void copy_from(const OutboxEntry& other);
};

struct SessionState final {
    Key contact{};
    // The pairing this session started from. Pairing again makes a new one.
    Hash transcript{};
    RatchetState ratchet;
    std::vector<OutboxEntry> outbox;  // in sealing order

    void copy_from(const SessionState& other);
};

[[nodiscard]] SecretBytes encode_session(const SessionState& state);
// Parses and checks every invariant. Anything else is CorruptState.
[[nodiscard]] Status decode_session(const CryptoContext& crypto,
                                    ByteView snapshot, SessionState& state);
// The largest snapshot the session's bounds allow, counted field by field.
[[nodiscard]] std::size_t max_session_bytes() noexcept;

// The platform's history: makes one received message durable, or
// recognizes its ID as one it already holds or deleted. False when it could
// not, and then the session is not saved.
using Deliver = std::function<bool(const Envelope& envelope)>;

struct OutboxInfo final {
    MessageId id{};
    MessageKind kind{MessageKind::Text};
    std::uint64_t sent_ms{0U};
    std::uint64_t sealed_at{0U};
    std::uint64_t checked_at{0U};
};

class Session final {
public:
    // Opens a contact's session from its snapshot, or starts it from the
    // pairing seed when the snapshot is empty. Starting saves the first
    // snapshot, then the identity snapshot without the seed, and only then
    // returns the session, so a seed is never used twice.
    [[nodiscard]] static Status open(Store& store, const Key& contact,
                                     ByteView snapshot, Persist persist,
                                     std::uint64_t now_ms,
                                     std::unique_ptr<Session>& out);
    Session(const Session&) = delete;
    Session& operator=(const Session&) = delete;
    ~Session();

    // Seals Text, Receipt, Missing, Ring, RingEnd, Profile or Timer. id is the
    // new message ID, out the item and its target.
    [[nodiscard]] Status send(MessageKind kind, ByteView payload,
                              std::uint64_t now_ms, MessageId& id,
                              OutgoingItem& out);
    [[nodiscard]] Status receive(ByteView item, std::uint64_t now_ms,
                                 const Deliver& deliver);
    // Opens only a ring, authenticated by this session. Non-rings return
    // WrongState without consuming a ratchet key. The handle is published
    // only after the session snapshot commits. It is never written to history.
    [[nodiscard]] Status receive_ring(ByteView item, const Authority& authority,
                                      std::uint64_t now_ms, TimePoint observed,
                                      std::unique_ptr<OpenedInvitation>& out);
    // A new copy of an outbox message, with its ID, time and Resent.
    [[nodiscard]] Status resend(const MessageId& id, std::uint64_t now_ms,
                                OutgoingItem& out);
    // One Check listing up to 64 messages that are due one. NotFound when
    // none is.
    [[nodiscard]] Status check(std::uint64_t now_ms, std::uint64_t hold_seconds,
                               OutgoingItem& out);
    [[nodiscard]] std::vector<OutboxInfo> outbox() const;

private:
    Session(Store& store, const Key& contact, Persist persist,
            SessionState&& state);

    [[nodiscard]] Status receive_checked(
        ByteView item, std::uint64_t now_ms,
        const std::function<Status(const Envelope&)>& deliver);
    [[nodiscard]] Status peer(bool verified, MessagePeer& out) const;
    [[nodiscard]] Status seal(SessionState& candidate, const MessagePeer& peer,
                              const Envelope& envelope,
                              OutgoingItem& out) const;
    [[nodiscard]] Status commit(SessionState& candidate);

    Store& store_;
    const Key contact_;
    Persist persist_;
    mutable std::mutex lock_;
    SessionState state_;
    // Set by an ambiguous persist. The platform reopens the session from
    // what storage holds.
    bool latched_{false};
};

}  // namespace ito::call
