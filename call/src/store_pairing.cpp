/* Copyright (C) 2026 FixCraft Inc. AGPL-3.0-or-later. */

// The store's identity 2 and pairing operations (docs/MESSAGE_SECURITY.md).
// They follow the store's one rule for change: build a candidate, persist
// it, and only then make it current and hand out what it produced. A
// refused item, a refused clock or a failed persist leaves every open code,
// scan and contact as it was.

#include <algorithm>
#include <limits>

#include "store.hpp"

namespace ito::call {
namespace {

[[nodiscard]] bool id_less(const PairingId& a, const PairingId& b) noexcept {
    return std::lexicographical_compare(a.begin(), a.end(), b.begin(), b.end());
}

[[nodiscard]] bool key_less(const Key& a, const Key& b) noexcept {
    return std::lexicographical_compare(a.begin(), a.end(), b.begin(), b.end());
}

[[nodiscard]] std::uint64_t code_lifetime(PairingKind kind) noexcept {
    return kind == PairingKind::InPerson ? kInPersonCodeLifetime
                                         : kLinkCodeLifetime;
}

// now plus a bounded span, refusing the sum that would reach the clock
// sentinel.
[[nodiscard]] bool add_time(std::uint64_t now, std::uint64_t span,
                            std::uint64_t& out) noexcept {
    if (now >= kUncertainClock - span) return false;
    out = now + span;
    return true;
}

// Removes pairings whose deadline has passed. A later call cannot use them.
void prune_pairings(StoreState& state, std::uint64_t now) {
    std::erase_if(state.codes, [&](const OwnedCode& owned) {
        return owned.deadline <= now;
    });
    std::erase_if(state.scans, [&](const PendingScan& scan) {
        return scan.deadline <= now;
    });
}

[[nodiscard]] bool id_in_use(const StoreState& state, const PairingId& id) {
    return std::any_of(
               state.codes.begin(), state.codes.end(),
               [&](const OwnedCode& owned) { return owned.code.id == id; }) ||
           std::any_of(
               state.scans.begin(), state.scans.end(),
               [&](const PendingScan& scan) { return scan.code.id == id; });
}

template <class Record>
[[nodiscard]] std::size_t index_of(const std::vector<Record>& records,
                                   const PairingId& id) {
    for (std::size_t index = 0U; index < records.size(); ++index) {
        if (records[index].code.id == id) return index;
    }
    return records.size();
}

template <class Record>
void insert_by_id(std::vector<Record>& records, Record&& record) {
    const auto position =
        std::lower_bound(records.begin(), records.end(), record.code.id,
                         [](const Record& existing, const PairingId& wanted) {
                             return id_less(existing.code.id, wanted);
                         });
    records.insert(position, std::move(record));
}

// Whether this identity may pair with a peer, checked before its signature
// costs anything: never oneself, never a Blocked key, never a known Ed25519
// key with a different ML-DSA key, and room for a new contact.
[[nodiscard]] Status check_peer(const StoreState& state,
                                const Identity2& peer) {
    if (peer.ed25519 == state.public_key) return Status::Untrusted;
    const Contact* existing = lookup_contact(state, peer.ed25519);
    if (existing == nullptr) {
        return state.contacts.size() < kMaxContacts ? Status::Ok
                                                    : Status::Capacity;
    }
    if (existing->trust == Trust::Blocked) return Status::Untrusted;
    if (existing->paired && existing->paired->ml_dsa != peer.ml_dsa) {
        return Status::Untrusted;
    }
    return Status::Ok;
}

[[nodiscard]] std::optional<ShortCode> in_person_code(
    const CryptoContext& crypto, PairingKind kind,
    const ContactSecrets& secrets) {
    if (kind != PairingKind::InPerson) return std::nullopt;
    return short_code(crypto, secrets.root, secrets.transcript);
}

}  // namespace

Status Store::sign2(std::string_view label, std::span<const ByteView> body,
                    CompositeSignature& signature) const {
    std::lock_guard guard(lock_);
    if (!state_.has_identity2) return Status::WrongState;
    signature = sign_composite(crypto_, state_.seed, state_.ml_dsa_seed,
                               state_.fingerprint2, label, body);
    return Status::Ok;
}

Signer Store::signer() const noexcept {
    return Signer{state_.seed, state_.ml_dsa_seed, state_.fingerprint2};
}

Status Store::admit_pairing_clock(std::uint64_t now, TimePoint observed,
                                  std::uint64_t& admitted) {
    ClockAdmission admission;
    const Status status = admit_clock(now, observed, admission);
    if (status != Status::Ok) return status;
    admitted = now;
    return Status::Ok;
}

Status Store::upgrade_identity() {
    std::lock_guard guard(lock_);
    if (!state_.has_identity) return Status::NotFound;
    if (state_.has_identity2) return Status::WrongState;
    StoreState candidate;
    candidate.copy_from(state_);
    crypto_.random(std::span<Byte>(candidate.ml_dsa_seed.data(),
                                   candidate.ml_dsa_seed.size()));
    candidate.has_identity2 = true;
    candidate.identity2.ed25519 = candidate.public_key;
    candidate.identity2.ml_dsa =
        crypto_.ml_dsa_public_key(candidate.ml_dsa_seed);
    candidate.fingerprint2 = fingerprint2(crypto_, candidate.identity2);
    return commit(candidate);
}

Status Store::identity2(Identity2& identity, Hash& fingerprint) const {
    std::lock_guard guard(lock_);
    if (!state_.has_identity) return Status::NotFound;
    if (!state_.has_identity2) return Status::WrongState;
    identity = state_.identity2;
    fingerprint = state_.fingerprint2;
    return Status::Ok;
}

Status Store::create_code(PairingKind kind, const Authority& mailbox,
                          std::string_view name, std::uint64_t now,
                          TimePoint observed, PairingId& id,
                          SecretBytes& text) {
    if (!valid_service_name(mailbox.service) || !valid_contact_name(name)) {
        return Status::InvalidArgument;
    }
    {
        std::lock_guard guard(lock_);
        if (!state_.has_identity) return Status::NotFound;
        if (!state_.has_identity2) return Status::WrongState;
    }
    std::uint64_t admitted = 0U;
    const Status clock = admit_pairing_clock(now, observed, admitted);
    if (clock != Status::Ok) return clock;
    std::lock_guard guard(lock_);
    StoreState candidate;
    candidate.copy_from(state_);
    prune_pairings(candidate, admitted);
    if (candidate.codes.size() >= kMaxOwnedCodes) return Status::Capacity;
    OwnedCode owned;
    owned.code.kind = kind;
    if (!add_time(admitted, code_lifetime(kind), owned.code.expires_at)) {
        return Status::InvalidArgument;
    }
    crypto_.random(owned.code.id);
    // Sixteen random bytes repeat only by a broken random source.
    if (id_in_use(candidate, owned.code.id)) return Status::Internal;
    crypto_.random(
        std::span<Byte>(owned.code.secret.data(), owned.code.secret.size()));
    crypto_.random(std::span<Byte>(owned.inbox.data(), owned.inbox.size()));
    owned.code.owner = candidate.fingerprint2;
    owned.code.mailbox = mailbox;
    owned.code.inbox = mailbox_address(crypto_, owned.inbox);
    owned.own_name.assign(name);
    owned.state = CodeState::Open;
    owned.deadline = owned.code.expires_at;
    const PairingId created = owned.code.id;
    SecretBytes formatted = format_pairing_code(owned.code);
    insert_by_id(candidate.codes, std::move(owned));
    const Status saved = commit(candidate);
    if (saved != Status::Ok) return saved;
    id = created;
    text = std::move(formatted);
    return Status::Ok;
}

Status Store::code_text(const PairingId& id, SecretBytes& text) const {
    std::lock_guard guard(lock_);
    const std::size_t index = index_of(state_.codes, id);
    if (index == state_.codes.size()) return Status::NotFound;
    if (state_.codes[index].state != CodeState::Open) return Status::WrongState;
    text = format_pairing_code(state_.codes[index].code);
    return Status::Ok;
}

Status Store::scan(std::string_view text, bool scanned,
                   const Authority& own_mailbox, std::string_view name,
                   std::uint64_t now, TimePoint observed, PairingId& id,
                   OutgoingItem& hello) {
    if (!valid_service_name(own_mailbox.service) || !valid_contact_name(name)) {
        return Status::InvalidArgument;
    }
    PendingScan scan;
    switch (parse_pairing_code(text, scan.code)) {
        case CodecStatus::Ok:
            break;
        case CodecStatus::Unsupported:
            return Status::Unsupported;
        case CodecStatus::Malformed:
            return Status::Malformed;
    }
    {
        std::lock_guard guard(lock_);
        if (!state_.has_identity) return Status::NotFound;
        if (!state_.has_identity2) return Status::WrongState;
        if (scan.code.owner == state_.fingerprint2) {
            return Status::InvalidArgument;
        }
    }
    std::uint64_t admitted = 0U;
    const Status clock = admit_pairing_clock(now, observed, admitted);
    if (clock != Status::Ok) return clock;
    if (admitted >= scan.code.expires_at) return Status::Expired;

    std::lock_guard guard(lock_);
    StoreState candidate;
    candidate.copy_from(state_);
    prune_pairings(candidate, admitted);
    if (id_in_use(candidate, scan.code.id)) return Status::AlreadySpent;
    if (candidate.scans.size() >= kMaxPendingScans) return Status::Capacity;
    // A code may claim an expiry far ahead. The scanner keeps its secrets no
    // longer than the code's own kind allows, plus the reply window.
    std::uint64_t latest = 0U;
    if (!add_time(admitted, code_lifetime(scan.code.kind), latest) ||
        !add_time(std::min(latest, scan.code.expires_at), kPairingReplyWindow,
                  scan.deadline)) {
        return Status::InvalidArgument;
    }
    scan.scanned = scanned;
    scan.own_mailbox = own_mailbox;
    crypto_.random(
        std::span<Byte>(scan.secrets.share.data(), scan.secrets.share.size()));
    crypto_.random(
        std::span<Byte>(scan.secrets.kem.data(), scan.secrets.kem.size()));
    crypto_.random(
        std::span<Byte>(scan.secrets.inbox.data(), scan.secrets.inbox.size()));
    HelloBody body;
    body.sender = candidate.identity2;
    body.share = crypto_.x25519_public_key(scan.secrets.share);
    body.kem = crypto_.ml_kem_public_key(scan.secrets.kem);
    body.mailbox = own_mailbox;
    body.inbox = mailbox_address(crypto_, scan.secrets.inbox);
    body.name.assign(name);
    BuiltHello built = build_hello(crypto_, signer(), scan.code, body);
    scan.hello_transcript = built.transcript;

    OutgoingItem item;
    item.mailbox = scan.code.mailbox;
    item.address = scan.code.inbox;
    item.item = std::move(built.item);
    const PairingId scanned_id = scan.code.id;
    insert_by_id(candidate.scans, std::move(scan));
    const Status saved = commit(candidate);
    if (saved != Status::Ok) return saved;
    id = scanned_id;
    hello = std::move(item);
    return Status::Ok;
}

Status Store::receive_pairing(const Hash& address, ByteView item,
                              std::uint64_t now, TimePoint observed,
                              PairingEvent& event,
                              std::optional<OutgoingItem>& out) {
    enum class Target { None, Hello, Confirm, Reply };
    Target target = Target::None;
    PairingId id{};
    {
        // Find what the address belongs to before the clock is admitted, so
        // an item for no pairing changes nothing at all.
        std::lock_guard guard(lock_);
        if (!state_.has_identity2) return Status::NotFound;
        for (const OwnedCode& owned : state_.codes) {
            if (owned.code.inbox == address) {
                // Only the first valid hello opens a code.
                if (owned.state != CodeState::Open) return Status::AlreadySpent;
                target = Target::Hello;
            } else if (owned.state != CodeState::Open &&
                       mailbox_address(crypto_, owned.secrets.receive) ==
                           address) {
                target = Target::Confirm;
            }
            if (target != Target::None) {
                id = owned.code.id;
                break;
            }
        }
        for (const PendingScan& scan : state_.scans) {
            if (target != Target::None) break;
            if (mailbox_address(crypto_, scan.secrets.inbox) == address) {
                target = Target::Reply;
                id = scan.code.id;
            }
        }
        if (target == Target::None) {
            // A confirm sent again after the owner finished is recognized
            // until the contact's message session takes the pairing seed.
            for (const ContactSecrets& secrets : state_.contact_secrets) {
                if (secrets.role != PairingRole::Owner || !secrets.seed_held ||
                    mailbox_address(crypto_, secrets.receive) != address) {
                    continue;
                }
                Key ratchet{};
                if (open_confirm(crypto_, secrets.root, secrets.transcript,
                                 item, ratchet) == Status::Ok &&
                    ratchet == secrets.peer_ratchet) {
                    return Status::AlreadySpent;
                }
                break;
            }
            return Status::NotFound;
        }
    }
    std::uint64_t admitted = 0U;
    const Status clock = admit_pairing_clock(now, observed, admitted);
    if (clock != Status::Ok) return clock;

    std::lock_guard guard(lock_);
    StoreState candidate;
    candidate.copy_from(state_);
    if (target == Target::Reply) {
        const std::size_t index = index_of(candidate.scans, id);
        if (index == candidate.scans.size()) return Status::NotFound;
        if (admitted >= candidate.scans[index].deadline) return Status::Expired;
        prune_pairings(candidate, admitted);
        return receive_reply(candidate, index_of(candidate.scans, id), item,
                             admitted, event, out);
    }
    const std::size_t index = index_of(candidate.codes, id);
    if (index == candidate.codes.size()) return Status::NotFound;
    if (admitted >= candidate.codes[index].deadline) return Status::Expired;
    prune_pairings(candidate, admitted);
    const std::size_t current = index_of(candidate.codes, id);
    if (target == Target::Hello) {
        if (candidate.codes[current].state != CodeState::Open) {
            return Status::AlreadySpent;
        }
        return receive_hello(candidate, current, item, admitted, event, out);
    }
    return receive_confirm(candidate, current, item, admitted, event);
}

Status Store::receive_hello(StoreState& candidate, std::size_t index,
                            ByteView item, std::uint64_t now,
                            PairingEvent& event,
                            std::optional<OutgoingItem>& out) {
    OwnedCode& owned = candidate.codes[index];
    ReceivedHello hello;
    const Status opened = open_hello(crypto_, owned.code, item, hello);
    if (opened != Status::Ok) return opened;
    const Status allowed = check_peer(candidate, hello.body.sender);
    if (allowed != Status::Ok) return allowed;
    if (verify_hello(crypto_, owned.code, hello) != Verification::Valid) {
        return Status::AuthenticationFailed;
    }
    std::uint64_t deadline = 0U;
    if (!add_time(now, kPairingReplyWindow, deadline)) {
        return Status::InvalidArgument;
    }
    ContactSecrets& secrets = owned.secrets;
    secrets.key = hello.body.sender.ed25519;
    secrets.role = PairingRole::Owner;
    crypto_.random(
        std::span<Byte>(secrets.receive.data(), secrets.receive.size()));
    crypto_.random(std::span<Byte>(secrets.own_ratchet.data(),
                                   secrets.own_ratchet.size()));
    ReplyBody reply;
    reply.sender = candidate.identity2;
    reply.ratchet = crypto_.x25519_public_key(secrets.own_ratchet);
    reply.inbox = mailbox_address(crypto_, secrets.receive);
    reply.name = owned.own_name;
    BuiltReply built;
    const Status answered = build_reply(
        crypto_, signer(), owned.code,
        hello_transcript(crypto_, owned.code, hello), hello.body, reply, built);
    if (answered != Status::Ok) return answered;
    secrets.root.assign(built.root.view());
    secrets.transcript = built.transcript;
    owned.state = CodeState::Replied;
    owned.deadline = deadline;
    owned.peer = hello.body.sender;
    owned.peer_mailbox = hello.body.mailbox;
    owned.peer_inbox = hello.body.inbox;
    owned.peer_name = hello.body.name;

    PairingEvent result;
    result.kind = PairingEventKind::Replied;
    result.id = owned.code.id;
    result.role = PairingRole::Owner;
    result.pairing_kind = owned.code.kind;
    result.peer = owned.peer.ed25519;
    result.short_code = in_person_code(crypto_, owned.code.kind, secrets);
    result.peer_name = owned.peer_name;
    OutgoingItem answer;
    answer.mailbox = owned.peer_mailbox;
    answer.address = owned.peer_inbox;
    answer.item = std::move(built.item);
    const Status saved = commit(candidate);
    if (saved != Status::Ok) return saved;
    event = std::move(result);
    out = std::move(answer);
    return Status::Ok;
}

Status Store::receive_confirm(StoreState& candidate, std::size_t index,
                              ByteView item, std::uint64_t now,
                              PairingEvent& event) {
    OwnedCode& owned = candidate.codes[index];
    Key ratchet{};
    const Status opened = open_confirm(crypto_, owned.secrets.root,
                                       owned.secrets.transcript, item, ratchet);
    if (opened != Status::Ok) return opened;
    // The confirm is deterministic, so a second one is a resend.
    if (owned.state == CodeState::Confirmed) return Status::AlreadySpent;
    owned.secrets.peer_ratchet = ratchet;
    PairingEvent result;
    if (owned.code.kind == PairingKind::Link || owned.matched) {
        const Status completed = complete_owned(candidate, index, now, result);
        if (completed != Status::Ok) return completed;
    } else {
        owned.state = CodeState::Confirmed;
        result.kind = PairingEventKind::Confirmed;
        result.id = owned.code.id;
        result.role = PairingRole::Owner;
        result.pairing_kind = owned.code.kind;
        result.peer = owned.peer.ed25519;
        result.short_code =
            in_person_code(crypto_, owned.code.kind, owned.secrets);
        result.peer_name = owned.peer_name;
    }
    const Status saved = commit(candidate);
    if (saved != Status::Ok) return saved;
    event = std::move(result);
    return Status::Ok;
}

Status Store::complete_owned(StoreState& candidate, std::size_t index,
                             std::uint64_t now, PairingEvent& event) {
    OwnedCode& owned = candidate.codes[index];
    // Trust may have changed since the hello, such as a block.
    const Status allowed = check_peer(candidate, owned.peer);
    if (allowed != Status::Ok) return allowed;
    PairedContact paired;
    paired.ml_dsa = owned.peer.ml_dsa;
    paired.send_mailbox = owned.peer_mailbox;
    paired.send_address = owned.peer_inbox;
    paired.receive_mailbox = owned.code.mailbox;
    paired.paired_at = now;
    event.kind = PairingEventKind::Completed;
    event.id = owned.code.id;
    event.role = PairingRole::Owner;
    event.pairing_kind = owned.code.kind;
    event.peer = owned.peer.ed25519;
    event.peer_name = owned.peer_name;
    const bool in_person =
        owned.code.kind == PairingKind::InPerson && owned.matched;
    event.trust =
        save_paired(candidate, owned.peer, owned.peer_name, std::move(paired),
                    std::move(owned.secrets), in_person, now);
    candidate.codes.erase(candidate.codes.begin() +
                          static_cast<std::ptrdiff_t>(index));
    return Status::Ok;
}

Status Store::receive_reply(StoreState& candidate, std::size_t index,
                            ByteView item, std::uint64_t now,
                            PairingEvent& event,
                            std::optional<OutgoingItem>& out) {
    PendingScan& scan = candidate.scans[index];
    ReceivedReply reply;
    const Status opened = open_reply(crypto_, scan.code, scan.secrets,
                                     scan.hello_transcript, item, reply);
    if (opened != Status::Ok) return opened;
    const Status allowed = check_peer(candidate, reply.body.sender);
    if (allowed != Status::Ok) return allowed;
    if (verify_reply(crypto_, scan.code, scan.hello_transcript, reply) !=
        Verification::Valid) {
        return Status::AuthenticationFailed;
    }
    ContactSecrets secrets;
    secrets.key = reply.body.sender.ed25519;
    secrets.role = PairingRole::Scanner;
    secrets.receive.assign(scan.secrets.inbox.view());
    finish_reply(crypto_, scan.hello_transcript, reply, secrets.transcript,
                 secrets.root);
    crypto_.random(std::span<Byte>(secrets.own_ratchet.data(),
                                   secrets.own_ratchet.size()));
    secrets.peer_ratchet = reply.body.ratchet;

    PairedContact paired;
    paired.ml_dsa = reply.body.sender.ml_dsa;
    paired.send_mailbox = scan.code.mailbox;
    paired.send_address = reply.body.inbox;
    paired.receive_mailbox = scan.own_mailbox;
    paired.paired_at = now;

    PairingEvent result;
    result.kind = PairingEventKind::Paired;
    result.id = scan.code.id;
    result.role = PairingRole::Scanner;
    result.pairing_kind = scan.code.kind;
    result.peer = reply.body.sender.ed25519;
    result.short_code = in_person_code(crypto_, scan.code.kind, secrets);
    result.peer_name = reply.body.name;
    OutgoingItem confirm;
    confirm.mailbox = scan.code.mailbox;
    confirm.address = reply.body.inbox;
    confirm.item = seal_confirm(crypto_, secrets.root, secrets.transcript,
                                crypto_.x25519_public_key(secrets.own_ratchet));
    // Only a code read from the owner's own screen verifies the owner.
    const bool in_person =
        scan.code.kind == PairingKind::InPerson && scan.scanned;
    candidate.scans.erase(candidate.scans.begin() +
                          static_cast<std::ptrdiff_t>(index));
    result.trust =
        save_paired(candidate, reply.body.sender, reply.body.name,
                    std::move(paired), std::move(secrets), in_person, now);
    const Status saved = commit(candidate);
    if (saved != Status::Ok) return saved;
    event = std::move(result);
    out = std::move(confirm);
    return Status::Ok;
}

Trust Store::save_paired(StoreState& state, const Identity2& peer,
                         const std::string& name, PairedContact paired,
                         ContactSecrets&& secrets, bool verified_in_person,
                         std::uint64_t now) {
    Contact* contact = find(state, peer.ed25519);
    if (contact == nullptr) {
        Contact added;
        added.key = peer.ed25519;
        added.added_at = now;
        added.name = name;
        const auto position = std::lower_bound(
            state.contacts.begin(), state.contacts.end(), peer.ed25519,
            [](const Contact& existing, const Key& wanted) {
                return key_less(existing.key, wanted);
            });
        contact = &*state.contacts.insert(position, std::move(added));
    }
    // Trust carries over only when the whole identity 2 was verified before.
    // An identity 1 verification never covered the ML-DSA key.
    const bool same_verified = contact->paired &&
                               contact->paired->ml_dsa == peer.ml_dsa &&
                               contact->trust == Trust::Verified;
    if (verified_in_person) {
        contact->trust = Trust::Verified;
        contact->verified_at = now == 0U ? 1U : now;
        paired.verified_by = VerifiedBy::InPerson;
    } else if (same_verified) {
        paired.verified_by = contact->paired->verified_by;
    } else {
        if (contact->trust == Trust::Verified) stop_attempt_for(contact->key);
        contact->trust = Trust::Unverified;
        contact->verified_at = 0U;
        paired.verified_by = VerifiedBy::None;
    }
    contact->paired = std::move(paired);
    const Trust trust = contact->trust;

    auto existing = std::find_if(
        state.contact_secrets.begin(), state.contact_secrets.end(),
        [&](const ContactSecrets& held) { return held.key == peer.ed25519; });
    if (existing != state.contact_secrets.end()) {
        *existing = std::move(secrets);
    } else {
        const auto position = std::lower_bound(
            state.contact_secrets.begin(), state.contact_secrets.end(),
            peer.ed25519, [](const ContactSecrets& held, const Key& wanted) {
                return key_less(held.key, wanted);
            });
        state.contact_secrets.insert(position, std::move(secrets));
    }
    return trust;
}

Status Store::decide_pairing(const PairingId& id, bool matches,
                             std::uint64_t now, TimePoint observed,
                             PairingEvent& event) {
    {
        std::lock_guard guard(lock_);
        const std::size_t index = index_of(state_.codes, id);
        if (index == state_.codes.size()) {
            return index_of(state_.scans, id) == state_.scans.size()
                       ? Status::NotFound
                       : Status::WrongState;
        }
        const OwnedCode& owned = state_.codes[index];
        if (owned.state == CodeState::Open ||
            owned.code.kind != PairingKind::InPerson) {
            return Status::WrongState;
        }
    }
    std::uint64_t admitted = 0U;
    const Status clock = admit_pairing_clock(now, observed, admitted);
    if (clock != Status::Ok) return clock;

    std::lock_guard guard(lock_);
    StoreState candidate;
    candidate.copy_from(state_);
    std::size_t index = index_of(candidate.codes, id);
    if (index == candidate.codes.size()) return Status::NotFound;
    if (admitted >= candidate.codes[index].deadline) return Status::Expired;
    prune_pairings(candidate, admitted);
    index = index_of(candidate.codes, id);
    OwnedCode& owned = candidate.codes[index];
    PairingEvent result;
    result.id = id;
    result.role = PairingRole::Owner;
    result.pairing_kind = owned.code.kind;
    result.peer = owned.peer.ed25519;
    result.peer_name = owned.peer_name;
    if (!matches) {
        result.kind = PairingEventKind::Rejected;
        candidate.codes.erase(candidate.codes.begin() +
                              static_cast<std::ptrdiff_t>(index));
    } else if (owned.state == CodeState::Confirmed) {
        // The match is what makes the contact Verified on completion.
        owned.matched = true;
        const Status completed =
            complete_owned(candidate, index, admitted, result);
        if (completed != Status::Ok) return completed;
    } else {
        owned.matched = true;
        result.kind = PairingEventKind::Matched;
        result.short_code =
            in_person_code(crypto_, owned.code.kind, owned.secrets);
    }
    const Status saved = commit(candidate);
    if (saved != Status::Ok) return saved;
    event = std::move(result);
    return Status::Ok;
}

Status Store::cancel_pairing(const PairingId& id) {
    std::lock_guard guard(lock_);
    StoreState candidate;
    candidate.copy_from(state_);
    const std::size_t code = index_of(candidate.codes, id);
    const std::size_t scan = index_of(candidate.scans, id);
    if (code != candidate.codes.size()) {
        candidate.codes.erase(candidate.codes.begin() +
                              static_cast<std::ptrdiff_t>(code));
    } else if (scan != candidate.scans.size()) {
        candidate.scans.erase(candidate.scans.begin() +
                              static_cast<std::ptrdiff_t>(scan));
    } else {
        return Status::NotFound;
    }
    return commit(candidate);
}

std::vector<PairingInfo> Store::pairings() const {
    std::lock_guard guard(lock_);
    std::vector<PairingInfo> result;
    result.reserve(state_.codes.size() + state_.scans.size());
    for (const OwnedCode& owned : state_.codes) {
        PairingInfo info;
        info.id = owned.code.id;
        info.role = PairingRole::Owner;
        info.kind = owned.code.kind;
        info.state = owned.state;
        info.deadline = owned.deadline;
        info.matched = owned.matched;
        if (owned.state != CodeState::Open) {
            info.peer = owned.peer.ed25519;
            info.short_code =
                in_person_code(crypto_, owned.code.kind, owned.secrets);
            info.peer_name = owned.peer_name;
        }
        result.push_back(std::move(info));
    }
    for (const PendingScan& scan : state_.scans) {
        PairingInfo info;
        info.id = scan.code.id;
        info.role = PairingRole::Scanner;
        info.kind = scan.code.kind;
        info.state = CodeState::Open;
        info.deadline = scan.deadline;
        result.push_back(std::move(info));
    }
    return result;
}

Status Store::confirm_item(const Key& contact, OutgoingItem& out) const {
    std::lock_guard guard(lock_);
    const Contact* found = lookup_contact(state_, contact);
    if (found == nullptr) return Status::NotFound;
    const ContactSecrets* secrets = lookup_secrets(state_, contact);
    if (!found->paired || secrets == nullptr) return Status::WrongState;
    // The owner shows no confirm, and a session that started took the root.
    if (secrets->role != PairingRole::Scanner || !secrets->seed_held) {
        return Status::WrongState;
    }
    out.mailbox = found->paired->send_mailbox;
    out.address = found->paired->send_address;
    out.item = seal_confirm(crypto_, secrets->root, secrets->transcript,
                            crypto_.x25519_public_key(secrets->own_ratchet));
    return Status::Ok;
}

Status Store::paired_contact(const Key& contact, PairedView& out) const {
    std::lock_guard guard(lock_);
    const Contact* found = lookup_contact(state_, contact);
    if (found == nullptr) return Status::NotFound;
    const ContactSecrets* secrets = lookup_secrets(state_, contact);
    if (!found->paired || secrets == nullptr) return Status::WrongState;
    out.paired = *found->paired;
    out.fingerprint =
        fingerprint2(crypto_, Identity2{found->key, found->paired->ml_dsa});
    out.receive_address = mailbox_address(crypto_, secrets->receive);
    out.role = secrets->role;
    return Status::Ok;
}

std::size_t Store::inbox_count() const {
    std::lock_guard guard(lock_);
    std::size_t count = state_.codes.size() + state_.scans.size();
    for (const Contact& contact : state_.contacts) {
        if (contact.paired && contact.trust != Trust::Blocked) ++count;
    }
    return count;
}

Status Store::inbox_at(std::size_t index, Inbox& out) const {
    std::lock_guard guard(lock_);
    if (index < state_.codes.size()) {
        const OwnedCode& owned = state_.codes[index];
        out.mailbox = owned.code.mailbox;
        out.pairing = owned.code.id;
        if (owned.state == CodeState::Open) {
            out.purpose = InboxPurpose::ShownCode;
            out.secret.assign(owned.inbox.view());
        } else {
            out.purpose = InboxPurpose::AwaitingConfirm;
            out.secret.assign(owned.secrets.receive.view());
        }
        out.address = mailbox_address(crypto_, out.secret);
        return Status::Ok;
    }
    index -= state_.codes.size();
    if (index < state_.scans.size()) {
        const PendingScan& scan = state_.scans[index];
        out.purpose = InboxPurpose::AwaitingReply;
        out.mailbox = scan.own_mailbox;
        out.pairing = scan.code.id;
        out.secret.assign(scan.secrets.inbox.view());
        out.address = mailbox_address(crypto_, out.secret);
        return Status::Ok;
    }
    index -= state_.scans.size();
    for (const Contact& contact : state_.contacts) {
        if (!contact.paired || contact.trust == Trust::Blocked) continue;
        if (index-- != 0U) continue;
        const ContactSecrets* secrets = lookup_secrets(state_, contact.key);
        if (secrets == nullptr) return Status::Internal;
        out.purpose = InboxPurpose::ContactInbox;
        out.mailbox = contact.paired->receive_mailbox;
        out.contact = contact.key;
        out.secret.assign(secrets->receive.view());
        out.address = mailbox_address(crypto_, out.secret);
        return Status::Ok;
    }
    return Status::NotFound;
}

Status Store::safety_code(const Key& contact, SafetyCode& code) const {
    std::lock_guard guard(lock_);
    if (!state_.has_identity2) return Status::WrongState;
    const Contact* found = lookup_contact(state_, contact);
    if (found == nullptr) return Status::NotFound;
    if (!found->paired) return Status::WrongState;
    const Identity2 peer{found->key, found->paired->ml_dsa};
    code = ito::call::safety_code(crypto_, state_.fingerprint2,
                                  fingerprint2(crypto_, peer));
    return Status::Ok;
}

Status Store::verify_safety_code(const Key& contact, std::string_view compared,
                                 std::uint64_t now) {
    std::lock_guard guard(lock_);
    if (!state_.has_identity2) return Status::WrongState;
    StoreState candidate;
    candidate.copy_from(state_);
    Contact* found = find(candidate, contact);
    if (found == nullptr) return Status::NotFound;
    if (!found->paired) return Status::WrongState;
    if (found->trust == Trust::Blocked) return Status::Untrusted;
    const Identity2 peer{found->key, found->paired->ml_dsa};
    const SafetyCode expected = ito::call::safety_code(
        crypto_, candidate.fingerprint2, fingerprint2(crypto_, peer));
    if (!safety_code_matches(compared, expected)) {
        return Status::AuthenticationFailed;
    }
    if (found->trust == Trust::Verified) return Status::Ok;
    found->trust = Trust::Verified;
    found->verified_at = now == 0U ? 1U : now;
    found->paired->verified_by = VerifiedBy::Compared;
    return commit(candidate);
}

}  // namespace ito::call
