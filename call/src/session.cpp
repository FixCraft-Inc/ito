/* Copyright (C) 2026 FixCraft Inc. AGPL-3.0-or-later. */

#include "session.hpp"

#include <algorithm>
#include <type_traits>

namespace ito::call {
namespace {

// Field sizes for the reservation and the measured bound.
constexpr std::size_t kSessionFixedBytes = kSessionSnapshotDomain.size() +
                                           kKeyBytes + kHashBytes + 32U + 8U +
                                           8U + 4U + 32U + kKeyBytes;
// Sending flag, chain key, next and previous numbers, the answer flag, and
// the answered key ID and ciphertext.
constexpr std::size_t kMaxSendingBytes =
    1U + kChainKeyBytes + 4U + 4U + 1U + 4U + kMlKemCiphertextBytes;
constexpr std::size_t kReceivingBytes = 1U + kChainKeyBytes + 4U;
constexpr std::size_t kPreviousBytes = 1U + kKeyBytes + 4U;
constexpr std::size_t kOwnKemBytes = 4U + 1U + kMlKemSeedBytes;
constexpr std::size_t kPeerKemBytes = 4U + 1U + 4U + kMlKemPublicKeyBytes;
constexpr std::size_t kSkippedBytes = kKeyBytes + 4U + kChainKeyBytes + 8U;
constexpr std::size_t kMaxOutboxEntryBytes = kMaxEnvelopeBytes + 8U + 8U;
constexpr std::size_t kMaxSessionBytes =
    kSessionFixedBytes + kMaxSendingBytes + kReceivingBytes + kPreviousBytes +
    kOwnKemBytes + kPeerKemBytes + 2U + kMaxSkippedKeys * kSkippedBytes + 1U +
    kMaxOutbox * kMaxOutboxEntryBytes;
// The bound the identity snapshot's sealed store accepts holds sessions too.
static_assert(kMaxSessionBytes <= kMaxSnapshotBytes);

[[nodiscard]] std::uint64_t seconds_of(std::uint64_t milliseconds) noexcept {
    return milliseconds / 1000U;
}

[[nodiscard]] Status persisted(const Persist& persist, ByteView snapshot) {
    PersistResult result = PersistResult::Ambiguous;
    try {
        result = persist(snapshot);
    } catch (...) {
        // A callback that throws gives no reliable answer.
        result = PersistResult::Ambiguous;
    }
    switch (result) {
        case PersistResult::Committed:
            return Status::Ok;
        case PersistResult::NotCommitted:
            return Status::StorageFailed;
        case PersistResult::Ambiguous:
            return Status::StorageAmbiguous;
    }
    return Status::StorageAmbiguous;
}

void write_ratchet(Writer& write, const RatchetState& state) {
    write.bytes(state.root.view());
    write.u64(state.time);
    write.u64(state.quantum_time);
    write.u32(state.quantum_steps);
    write.bytes(state.own_ratchet.view());
    write.bytes(state.peer_ratchet);
    write.u8(state.sending ? 1U : 0U);
    if (state.sending) {
        write.bytes(state.send_key.view());
        write.u32(state.send_next);
        write.u32(state.send_previous);
        write.u8(state.send_answers ? 1U : 0U);
        if (state.send_answers) {
            write.u32(state.send_answer_id);
            write.bytes(state.send_ciphertext);
        }
    } else {
        write.u32(state.last_length);
    }
    write.u8(state.receiving ? 1U : 0U);
    if (state.receiving) {
        write.bytes(state.receive_key.view());
        write.u32(state.receive_next);
    }
    write.u8(state.has_previous ? 1U : 0U);
    if (state.has_previous) {
        write.bytes(state.previous_ratchet);
        write.u32(state.previous_next);
    }
    write.u32(state.own_kem_id);
    write.u8(state.own_kem ? 1U : 0U);
    if (state.own_kem) write.bytes(state.own_kem_seed.view());
    write.u32(state.answered_id);
    write.u8(state.peer_kem ? 1U : 0U);
    if (state.peer_kem) {
        write.u32(state.peer_kem_id);
        write.bytes(state.peer_kem_key);
    }
    write.u16(static_cast<std::uint16_t>(state.skipped.size()));
    for (const SkippedKey& key : state.skipped) {
        write.bytes(key.ratchet);
        write.u32(key.number);
        write.bytes(key.key.view());
        write.u64(key.stored_at);
    }
}

[[nodiscard]] bool read_flag(Reader& in, bool& flag) noexcept {
    std::uint8_t value = 0U;
    if (!in.u8(value) || value > 1U) return false;
    flag = value == 1U;
    return true;
}

[[nodiscard]] bool read_sending(Reader& in, RatchetState& state) {
    if (!read_flag(in, state.sending)) return false;
    if (!state.sending) {
        return in.u32(state.last_length) &&
               state.last_length <= kMaxChainMessages;
    }
    if (!in.secret(state.send_key) || !in.u32(state.send_next) ||
        state.send_next > kMaxChainMessages || !in.u32(state.send_previous) ||
        state.send_previous > kMaxChainMessages ||
        !read_flag(in, state.send_answers)) {
        return false;
    }
    return !state.send_answers ||
           (in.u32(state.send_answer_id) && state.send_answer_id != 0U &&
            in.fixed(state.send_ciphertext));
}

[[nodiscard]] bool read_receiving(Reader& in, RatchetState& state) {
    if (!read_flag(in, state.receiving)) return false;
    if (state.receiving &&
        (!in.secret(state.receive_key) || !in.u32(state.receive_next) ||
         state.receive_next > kMaxChainMessages)) {
        return false;
    }
    if (!read_flag(in, state.has_previous)) return false;
    return !state.has_previous ||
           (in.fixed(state.previous_ratchet) && in.u32(state.previous_next) &&
            state.previous_next <= kMaxChainMessages);
}

[[nodiscard]] bool read_kem(const CryptoContext& crypto, Reader& in,
                            RatchetState& state) {
    if (!in.u32(state.own_kem_id) || !read_flag(in, state.own_kem) ||
        (state.own_kem &&
         (state.own_kem_id == 0U || !in.secret(state.own_kem_seed)))) {
        return false;
    }
    if (!in.u32(state.answered_id) || !read_flag(in, state.peer_kem)) {
        return false;
    }
    if (state.peer_kem &&
        (!in.u32(state.peer_kem_id) || state.peer_kem_id <= state.answered_id ||
         !in.fixed(state.peer_kem_key) ||
         !crypto.ml_kem_key_usable(state.peer_kem_key))) {
        return false;
    }
    // A chain answers a key the contact advertised, never a newer one.
    return !state.send_answers || state.send_answer_id <= state.answered_id;
}

[[nodiscard]] bool read_skipped(Reader& in, RatchetState& state) {
    std::uint16_t count = 0U;
    if (!in.u16(count) || count > kMaxSkippedKeys) return false;
    state.skipped.clear();
    state.skipped.resize(count);
    for (std::size_t index = 0U; index < count; ++index) {
        SkippedKey& key = state.skipped[index];
        if (!in.fixed(key.ratchet) || !in.u32(key.number) ||
            key.number >= kMaxChainMessages || !in.secret(key.key) ||
            !in.u64(key.stored_at) || key.stored_at > state.time) {
            return false;
        }
        if (index == 0U) continue;
        const SkippedKey& previous = state.skipped[index - 1U];
        const bool ascending =
            previous.ratchet != key.ratchet
                ? std::lexicographical_compare(
                      previous.ratchet.begin(), previous.ratchet.end(),
                      key.ratchet.begin(), key.ratchet.end())
                : previous.number < key.number;
        if (!ascending) return false;
    }
    return true;
}

[[nodiscard]] bool read_ratchet(const CryptoContext& crypto, Reader& in,
                                RatchetState& state) {
    return in.secret(state.root) && in.u64(state.time) &&
           in.u64(state.quantum_time) && state.quantum_time <= state.time &&
           in.u32(state.quantum_steps) && in.secret(state.own_ratchet) &&
           in.fixed(state.peer_ratchet) && read_sending(in, state) &&
           read_receiving(in, state) && read_kem(crypto, in, state) &&
           read_skipped(in, state);
}

void write_outbox(Writer& write, const std::vector<OutboxEntry>& outbox) {
    write.u8(static_cast<std::uint8_t>(outbox.size()));
    for (const OutboxEntry& entry : outbox) {
        write_envelope(write, entry.envelope);
        write.u64(entry.sealed_at);
        write.u64(entry.checked_at);
    }
}

[[nodiscard]] bool read_outbox(Reader& in, std::uint64_t time,
                               std::vector<OutboxEntry>& outbox) {
    std::uint8_t count = 0U;
    if (!in.u8(count) || count > kMaxOutbox) return false;
    outbox.clear();
    outbox.resize(count);
    for (OutboxEntry& entry : outbox) {
        Envelope& envelope = entry.envelope;
        std::uint8_t kind = 0U;
        std::uint8_t flags = 0U;
        std::uint16_t size = 0U;
        ByteView payload;
        if (!in.u8(kind) || !in.fixed(envelope.id) ||
            !in.u64(envelope.sent_ms) || !in.u8(flags) || flags != 0U ||
            !in.u16(size) || !in.take(size, payload) ||
            !in.u64(entry.sealed_at) || entry.sealed_at > time ||
            !in.u64(entry.checked_at) || entry.checked_at > time) {
            return false;
        }
        envelope.kind = static_cast<MessageKind>(kind);
        if (!kept_until_delivered(envelope.kind)) return false;
        envelope.payload.append(payload);
        if (check_envelope(envelope) != Status::Ok) return false;
    }
    for (std::size_t index = 0U; index < outbox.size(); ++index) {
        for (std::size_t other = 0U; other < index; ++other) {
            if (outbox[other].envelope.id == outbox[index].envelope.id) {
                return false;
            }
        }
    }
    return true;
}

}  // namespace

void OutboxEntry::copy_from(const OutboxEntry& other) {
    envelope.copy_from(other.envelope);
    sealed_at = other.sealed_at;
    checked_at = other.checked_at;
}

void SessionState::copy_from(const SessionState& other) {
    contact = other.contact;
    transcript = other.transcript;
    ratchet.copy_from(other.ratchet);
    outbox.clear();
    outbox.resize(other.outbox.size());
    for (std::size_t index = 0U; index < outbox.size(); ++index) {
        outbox[index].copy_from(other.outbox[index]);
    }
}

SecretBytes encode_session(const SessionState& state) {
    std::vector<Byte> out;
    const WipeOnExit wiped(out);
    // The reservation covers the longest encoding of these counts, so the
    // vector never reallocates and leaves a secret in freed memory.
    out.reserve(kSessionFixedBytes + kMaxSendingBytes + kReceivingBytes +
                kPreviousBytes + kOwnKemBytes + kPeerKemBytes + 2U +
                state.ratchet.skipped.size() * kSkippedBytes + 1U +
                state.outbox.size() * kMaxOutboxEntryBytes);
    Writer write(out);
    write.text(kSessionSnapshotDomain);
    write.bytes(state.contact);
    write.bytes(state.transcript);
    write_ratchet(write, state.ratchet);
    write_outbox(write, state.outbox);
    return SecretBytes(out);
}

Status decode_session(const CryptoContext& crypto, ByteView snapshot,
                      SessionState& state) {
    if (snapshot.size() > kMaxSessionBytes) return Status::CorruptState;
    Reader in(snapshot);
    if (!in.literal(as_bytes(kSessionSnapshotDomain)) ||
        !in.fixed(state.contact) || !in.fixed(state.transcript) ||
        !read_ratchet(crypto, in, state.ratchet) ||
        !read_outbox(in, state.ratchet.time, state.outbox) || !in.at_end()) {
        return Status::CorruptState;
    }
    return Status::Ok;
}

std::size_t max_session_bytes() noexcept {
    return kMaxSessionBytes;
}

Session::Session(Store& store, const Key& contact, Persist persist,
                 SessionState&& state)
    : store_(store),
      contact_(contact),
      persist_(std::move(persist)),
      state_(std::move(state)) {
    store_.add_borrower();
}

Session::~Session() {
    store_.unregister_session(contact_);
    store_.remove_borrower();
}

Status Session::open(Store& store, const Key& contact, ByteView snapshot,
                     Persist persist, std::uint64_t now_ms,
                     std::unique_ptr<Session>& out) {
    MessagePeer peer;
    Status status = store.message_peer(contact, peer);
    if (status != Status::Ok) return status;
    if (peer.trust == Trust::Blocked) return Status::Untrusted;
    status = store.register_session(contact);
    if (status != Status::Ok) return status;
    // Releases the registration on every path that returns no session.
    struct Registration final {
        Store& store;
        const Key& contact;
        bool held{true};
        ~Registration() {
            if (held) store.unregister_session(contact);
        }
    } registration{store, contact};

    SessionState state;
    if (snapshot.empty()) {
        // A session whose seed is gone and whose snapshot is lost cannot be
        // rebuilt: rebuilding would reuse message keys.
        if (!peer.seed_held) return Status::CorruptState;
        SessionSeed seed;
        status = store.session_seed(contact, peer.transcript, seed);
        if (status != Status::Ok) return status;
        state.contact = contact;
        state.transcript = peer.transcript;
        status = start_ratchet(store.crypto(), seed, state.ratchet);
        if (status != Status::Ok) return status;
        advance_time(state.ratchet, seconds_of(now_ms));
        const SecretBytes first = encode_session(state);
        status = persisted(persist, first.view());
        if (status != Status::Ok) return status;
    } else {
        status = decode_session(store.crypto(), snapshot, state);
        if (status != Status::Ok) return status;
        if (state.contact != contact) return Status::InvalidArgument;
        // An earlier pairing's session. Pairing again starts a new one.
        if (state.transcript != peer.transcript) return Status::WrongState;
    }
    const Hash transcript = state.transcript;
    // The session exists before the store forgets the seed, so forgetting
    // it is the last step that can fail. Its destructor releases the
    // registration from here on.
    std::unique_ptr<Session> session(
        new Session(store, contact, std::move(persist), std::move(state)));
    registration.held = false;
    // Still held when an earlier open saved the first snapshot and then
    // failed to save the identity snapshot.
    if (peer.seed_held) {
        status = store.consume_session_seed(contact, transcript);
        if (status != Status::Ok) return status;
    }
    out = std::move(session);
    return Status::Ok;
}

Status Session::peer(bool verified, MessagePeer& out) const {
    const Status status = store_.message_peer(contact_, out);
    if (status != Status::Ok) return status;
    if (out.transcript != state_.transcript) return Status::WrongState;
    if (out.trust == Trust::Blocked) return Status::Untrusted;
    if (verified && out.trust != Trust::Verified) return Status::Untrusted;
    return Status::Ok;
}

Status Session::seal(SessionState& candidate, const MessagePeer& peer,
                     const Envelope& envelope, OutgoingItem& out) const {
    std::vector<Byte> bytes;
    const WipeOnExit wiped(bytes);
    bytes.reserve(envelope_size(envelope));
    Writer write(bytes);
    write_envelope(write, envelope);
    const CryptoContext& crypto = store_.crypto();
    MessageRandom random;
    crypto.random(random.salt);
    crypto.random(
        std::span<Byte>(random.ratchet.data(), random.ratchet.size()));
    crypto.random(std::span<Byte>(random.kem.data(), random.kem.size()));
    const Fingerprints fingerprints{peer.own_fingerprint,
                                    peer.peer_fingerprint};
    const Status sealed = seal_message(crypto, candidate.ratchet, fingerprints,
                                       bytes, random, out.item);
    if (sealed != Status::Ok) return sealed;
    out.mailbox = peer.send_mailbox;
    out.address = peer.send_address;
    return Status::Ok;
}

Status Session::commit(SessionState& candidate) {
    if (latched_) return Status::StorageAmbiguous;
    const SecretBytes encoded = encode_session(candidate);
    const Status status = persisted(persist_, encoded.view());
    if (status == Status::StorageAmbiguous) latched_ = true;
    if (status != Status::Ok) return status;
    static_assert(std::is_nothrow_move_assignable_v<SessionState>);
    state_ = std::move(candidate);
    return Status::Ok;
}

Status Session::send(MessageKind kind, ByteView payload, std::uint64_t now_ms,
                     MessageId& id, OutgoingItem& out) {
    switch (kind) {
        case MessageKind::Text:
        case MessageKind::Receipt:
        case MessageKind::Missing:
        case MessageKind::Profile:
        case MessageKind::Timer:
            break;
        // The core writes checks itself, from the outbox.
        case MessageKind::Check:
            return Status::InvalidArgument;
        case MessageKind::Ring:
        case MessageKind::RingEnd:
        case MessageKind::Inbox:
            return Status::Unsupported;
    }
    if (check_payload(kind, payload) != Status::Ok) {
        return Status::InvalidArgument;
    }
    std::lock_guard guard(lock_);
    if (latched_) return Status::StorageAmbiguous;
    MessagePeer current;
    const Status allowed = peer(true, current);
    if (allowed != Status::Ok) return allowed;
    SessionState candidate;
    candidate.copy_from(state_);
    advance_time(candidate.ratchet, seconds_of(now_ms));
    const bool kept = kept_until_delivered(kind);
    if (kept && candidate.outbox.size() >= kMaxOutbox) return Status::Capacity;
    OutboxEntry entry;
    Envelope& envelope = entry.envelope;
    envelope.kind = kind;
    store_.crypto().random(envelope.id);
    envelope.sent_ms = now_ms;
    envelope.payload.reserve(payload.size());
    envelope.payload.append(payload);
    OutgoingItem item;
    const Status sealed = seal(candidate, current, envelope, item);
    if (sealed != Status::Ok) return sealed;
    const MessageId sent = envelope.id;
    if (kept) {
        entry.sealed_at = candidate.ratchet.time;
        candidate.outbox.push_back(std::move(entry));
    }
    const Status saved = commit(candidate);
    if (saved != Status::Ok) return saved;
    id = sent;
    out = std::move(item);
    return Status::Ok;
}

Status Session::receive(ByteView item, std::uint64_t now_ms,
                        const Deliver& deliver) {
    std::lock_guard guard(lock_);
    if (latched_) return Status::StorageAmbiguous;
    MessagePeer current;
    const Status allowed = peer(true, current);
    if (allowed != Status::Ok) return allowed;
    SessionState candidate;
    candidate.copy_from(state_);
    advance_time(candidate.ratchet, seconds_of(now_ms));
    const Fingerprints fingerprints{current.own_fingerprint,
                                    current.peer_fingerprint};
    SecretBytes plaintext;
    Status status = open_message(store_.crypto(), candidate.ratchet,
                                 fingerprints, item, plaintext);
    if (status != Status::Ok) return status;
    Envelope envelope;
    status = read_envelope(plaintext.view(), envelope);
    if (status != Status::Ok) return status;
    if (envelope.kind == MessageKind::Receipt) {
        // Delivered and Read both confirm. Unknown IDs change nothing.
        const ByteView ids =
            payload_ids(envelope.kind, envelope.payload.view());
        std::erase_if(candidate.outbox, [&](const OutboxEntry& entry) {
            for (std::size_t index = 0U; index < ids.size() / kMessageIdBytes;
                 ++index) {
                if (id_at(ids, index) == entry.envelope.id) return true;
            }
            return false;
        });
    }
    bool stored = false;
    try {
        stored = deliver(envelope);
    } catch (...) {
        stored = false;
    }
    if (!stored) return Status::StorageFailed;
    return commit(candidate);
}

Status Session::resend(const MessageId& id, std::uint64_t now_ms,
                       OutgoingItem& out) {
    std::lock_guard guard(lock_);
    if (latched_) return Status::StorageAmbiguous;
    MessagePeer current;
    const Status allowed = peer(true, current);
    if (allowed != Status::Ok) return allowed;
    SessionState candidate;
    candidate.copy_from(state_);
    advance_time(candidate.ratchet, seconds_of(now_ms));
    const auto entry = std::find_if(
        candidate.outbox.begin(), candidate.outbox.end(),
        [&](const OutboxEntry& held) { return held.envelope.id == id; });
    if (entry == candidate.outbox.end()) return Status::NotFound;
    Envelope copy;
    copy.copy_from(entry->envelope);
    copy.resent = true;
    OutgoingItem item;
    const Status sealed = seal(candidate, current, copy, item);
    if (sealed != Status::Ok) return sealed;
    const Status saved = commit(candidate);
    if (saved != Status::Ok) return saved;
    out = std::move(item);
    return Status::Ok;
}

Status Session::check(std::uint64_t now_ms, std::uint64_t hold_seconds,
                      OutgoingItem& out) {
    if (hold_seconds == 0U || hold_seconds > kMaxHoldSeconds) {
        return Status::InvalidArgument;
    }
    std::lock_guard guard(lock_);
    if (latched_) return Status::StorageAmbiguous;
    MessagePeer current;
    const Status allowed = peer(true, current);
    if (allowed != Status::Ok) return allowed;
    SessionState candidate;
    candidate.copy_from(state_);
    advance_time(candidate.ratchet, seconds_of(now_ms));
    const std::uint64_t time = candidate.ratchet.time;
    std::vector<MessageId> due;
    due.reserve(kMaxMessageIds);
    for (OutboxEntry& entry : candidate.outbox) {
        if (due.size() == kMaxMessageIds) break;
        if (time - std::max(entry.sealed_at, entry.checked_at) < hold_seconds) {
            continue;
        }
        due.push_back(entry.envelope.id);
        entry.checked_at = time;
    }
    if (due.empty()) return Status::NotFound;
    Envelope check;
    check.kind = MessageKind::Check;
    store_.crypto().random(check.id);
    check.sent_ms = now_ms;
    const Status encoded = encode_ids(
        MessageKind::Check, ReceiptKind::Delivered, due, check.payload);
    if (encoded != Status::Ok) return Status::Internal;
    OutgoingItem item;
    const Status sealed = seal(candidate, current, check, item);
    if (sealed != Status::Ok) return sealed;
    const Status saved = commit(candidate);
    if (saved != Status::Ok) return saved;
    out = std::move(item);
    return Status::Ok;
}

std::vector<OutboxInfo> Session::outbox() const {
    std::lock_guard guard(lock_);
    std::vector<OutboxInfo> result;
    result.reserve(state_.outbox.size());
    for (const OutboxEntry& entry : state_.outbox) {
        result.push_back(OutboxInfo{entry.envelope.id, entry.envelope.kind,
                                    entry.envelope.sent_ms, entry.sealed_at,
                                    entry.checked_at});
    }
    return result;
}

}  // namespace ito::call
