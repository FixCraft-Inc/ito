/* Copyright (C) 2026 FixCraft Inc. AGPL-3.0-or-later. */

// The store's two snapshot formats. Snapshot 1 holds an identity 1, its
// contacts and spent invitations. Snapshot 2 adds the ML-DSA seed, the paired
// part and session seed of each paired contact, the codes this installation
// shows and the codes it scanned. The encoder writes snapshot 1 until the
// identity is upgraded, so a store that never pairs keeps its old bytes.

#include <algorithm>
#include <limits>

#include "store.hpp"

namespace ito::call {
namespace {

constexpr std::uint8_t kHasReplacedBy = 1U;
constexpr std::uint8_t kHasReplaces = 2U;
constexpr std::uint8_t kPaired = 4U;  // snapshot 2 only

// Field sizes for reservations and the measured bound.
constexpr std::size_t kAuthorityBytes = kKeyBytes + 1U + kMaxServiceBytes;
constexpr std::size_t kNameBytes = 1U + kMaxNameBytes;
// Key, trust, flags, two linked keys, added and verified times, name.
constexpr std::size_t kContactBytes =
    3U * kKeyBytes + 2U + 2U * 8U + kNameBytes;
// ML-DSA key, send authority and address, receive authority, pairing time,
// verification and role bytes, the receive secret, the transcript, the seed
// byte, then while the seed is held the root, own ratchet key and the peer's
// ratchet key.
constexpr std::size_t kPairedBytes = kMlDsaPublicKeyBytes + kAuthorityBytes +
                                     kHashBytes + kAuthorityBytes + 8U + 2U +
                                     2U * 32U + 1U + 3U * 32U;
// ID, hash, expiry and role.
constexpr std::size_t kSpentBytes = 2U * kKeyBytes + 8U + 1U;
// The record, the inbox secret, the owner's offered name, state and
// deadline, then once replied the scanner's keys, mailbox, inbox and name,
// four secrets and the match flag, and once confirmed the scanner's ratchet
// key.
constexpr std::size_t kOwnedCodeBytes =
    kMaxCodeRecordBytes + 32U + kNameBytes + 1U + 8U + kKeyBytes +
    kMlDsaPublicKeyBytes + kAuthorityBytes + kHashBytes + kNameBytes +
    4U * 32U + 1U + kKeyBytes;
// The record, scanned flag, own mailbox, share, KEM seed, inbox secret,
// hello transcript and deadline.
constexpr std::size_t kScanBytes = kMaxCodeRecordBytes + 1U + kAuthorityBytes +
                                   32U + kMlKemSeedBytes + 32U + kHashBytes +
                                   8U;
// Domain, both seeds, the Ed25519 key, identity time, clock, pruned floor,
// and the four counts.
constexpr std::size_t kSnapshot2FixedBytes =
    kSnapshot2Domain.size() + 3U * 32U + 8U + 8U + 8U + 2U + 2U + 1U + 1U;
constexpr std::size_t kMaxSnapshot2Bytes =
    kSnapshot2FixedBytes + kMaxContacts * (kContactBytes + kPairedBytes) +
    kMaxSpentInvitations * kSpentBytes + kMaxOwnedCodes * kOwnedCodeBytes +
    kMaxPendingScans * kScanBytes;
// The bound the platform's sealed store also enforces.
static_assert(kMaxSnapshot2Bytes <= kMaxSnapshotBytes);

[[nodiscard]] bool key_less(const Key& a, const Key& b) noexcept {
    return std::lexicographical_compare(a.begin(), a.end(), b.begin(), b.end());
}

[[nodiscard]] bool valid_trust(std::uint8_t value) noexcept {
    return value >= static_cast<std::uint8_t>(Trust::Unverified) &&
           value <= static_cast<std::uint8_t>(Trust::Blocked);
}

// Cross-record invariants that a sequence of valid mutations preserves.
[[nodiscard]] bool consistent(const StoreState& state) {
    const auto lookup = [&](const Key& key) -> const Contact* {
        const auto found =
            std::lower_bound(state.contacts.begin(), state.contacts.end(), key,
                             [](const Contact& contact, const Key& wanted) {
                                 return key_less(contact.key, wanted);
                             });
        return found != state.contacts.end() && found->key == key ? &*found
                                                                  : nullptr;
    };
    for (const Contact& contact : state.contacts) {
        if (state.has_identity && contact.key == state.public_key) return false;
        if ((contact.trust == Trust::Verified) != (contact.verified_at != 0U) &&
            contact.trust != Trust::Blocked) {
            return false;
        }
        if (contact.replaced_by) {
            const Contact* successor = lookup(*contact.replaced_by);
            if (contact.trust != Trust::Blocked || successor == nullptr ||
                successor->replaces != contact.key) {
                return false;
            }
        }
        if (contact.replaces) {
            const Contact* retired = lookup(*contact.replaces);
            if (retired == nullptr || retired->replaced_by != contact.key) {
                return false;
            }
        }
    }
    return true;
}

// The identity 2 invariants: one secret record per paired contact, in the
// same order, and a verification method exactly when a paired contact is
// Verified.
[[nodiscard]] bool consistent_pairing(const StoreState& state) {
    auto secrets = state.contact_secrets.begin();
    for (const Contact& contact : state.contacts) {
        if (!contact.paired) continue;
        if (secrets == state.contact_secrets.end() ||
            secrets->key != contact.key) {
            return false;
        }
        ++secrets;
        const VerifiedBy method = contact.paired->verified_by;
        if (contact.trust == Trust::Verified && method == VerifiedBy::None) {
            return false;
        }
        if (contact.trust == Trust::Unverified && method != VerifiedBy::None) {
            return false;
        }
    }
    if (secrets != state.contact_secrets.end()) return false;
    // A pairing ID names one pairing across both lists.
    for (const OwnedCode& owned : state.codes) {
        for (const PendingScan& scan : state.scans) {
            if (scan.code.id == owned.code.id) return false;
        }
    }
    return true;
}

template <class Record>
[[nodiscard]] bool ascending_ids(const std::vector<Record>& records) {
    for (std::size_t index = 1U; index < records.size(); ++index) {
        const PairingId& previous = records[index - 1U].code.id;
        const PairingId& current = records[index].code.id;
        if (!std::lexicographical_compare(previous.begin(), previous.end(),
                                          current.begin(), current.end())) {
            return false;
        }
    }
    return true;
}

void write_contact(Writer& write, const Contact& contact, bool version2) {
    write.bytes(contact.key);
    write.u8(static_cast<std::uint8_t>(contact.trust));
    write.u8(
        static_cast<std::uint8_t>((contact.replaced_by ? kHasReplacedBy : 0U) |
                                  (contact.replaces ? kHasReplaces : 0U) |
                                  (version2 && contact.paired ? kPaired : 0U)));
    if (contact.replaced_by) write.bytes(*contact.replaced_by);
    if (contact.replaces) write.bytes(*contact.replaces);
    write.u64(contact.added_at);
    write.u64(contact.verified_at);
    write.u8(static_cast<std::uint8_t>(contact.name.size()));
    write.text(contact.name);
}

// Reads the fields both versions share. flags reports the paired bit, which
// only snapshot 2 allows.
[[nodiscard]] bool read_contact(Reader& in, Contact& contact,
                                std::uint8_t allowed, std::uint8_t& flags) {
    std::uint8_t trust = 0U;
    std::uint8_t name_size = 0U;
    ByteView name;
    if (!in.fixed(contact.key) || !in.u8(trust) || !valid_trust(trust) ||
        !in.u8(flags) || (flags & ~allowed) != 0U) {
        return false;
    }
    contact.trust = static_cast<Trust>(trust);
    if ((flags & kHasReplacedBy) != 0U) {
        Key successor{};
        if (!in.fixed(successor)) return false;
        contact.replaced_by = successor;
    }
    if ((flags & kHasReplaces) != 0U) {
        Key retired{};
        if (!in.fixed(retired)) return false;
        contact.replaces = retired;
    }
    if (!in.u64(contact.added_at) || !in.u64(contact.verified_at) ||
        !in.u8(name_size) || !in.take(name_size, name)) {
        return false;
    }
    contact.name.assign(reinterpret_cast<const char*>(name.data()),
                        name.size());
    return valid_contact_name(contact.name);
}

void write_spent(Writer& write, const SpentInvitation& spent) {
    write.bytes(spent.invitation_id);
    write.bytes(spent.invitation_hash);
    write.u64(spent.expires_at);
    write.u8(static_cast<std::uint8_t>(spent.role));
}

[[nodiscard]] bool read_spent(Reader& in, SpentInvitation& spent) {
    std::uint8_t role = 0U;
    if (!in.fixed(spent.invitation_id) || !in.fixed(spent.invitation_hash) ||
        !in.u64(spent.expires_at) || !in.u8(role) || role < 1U || role > 2U) {
        return false;
    }
    spent.role = static_cast<Role>(role);
    return true;
}

[[nodiscard]] bool read_contacts1(Reader& in, StoreState& state) {
    std::uint16_t count = 0U;
    if (!in.u16(count) || count > kMaxContacts) return false;
    state.contacts.clear();
    state.contacts.reserve(count);
    for (std::uint16_t index = 0U; index < count; ++index) {
        Contact contact;
        std::uint8_t flags = 0U;
        if (!read_contact(in, contact, kHasReplacedBy | kHasReplaces, flags) ||
            (!state.contacts.empty() &&
             !key_less(state.contacts.back().key, contact.key))) {
            return false;
        }
        state.contacts.push_back(std::move(contact));
    }
    return true;
}

[[nodiscard]] bool read_spent_list(Reader& in, StoreState& state) {
    std::uint16_t count = 0U;
    if (!in.u16(count) || count > kMaxSpentInvitations) return false;
    state.spent.clear();
    state.spent.reserve(count);
    for (std::uint16_t index = 0U; index < count; ++index) {
        SpentInvitation spent;
        if (!read_spent(in, spent) ||
            (!state.spent.empty() && !key_less(state.spent.back().invitation_id,
                                               spent.invitation_id))) {
            return false;
        }
        state.spent.push_back(spent);
    }
    return true;
}

SecretBytes encode_snapshot1(const StoreState& state) {
    // The reservation covers the largest encoding, so the vector holding the
    // seed never reallocates and leaves an unwiped copy behind. Fixed part:
    // domain, identity flag, seed, key, three u64 and two u16 counts.
    constexpr std::size_t kFixedBytes =
        kSnapshotDomain.size() + 1U + 2U * kKeyBytes + 3U * 8U + 2U * 2U;
    std::vector<Byte> out;
    const WipeOnExit wiped(out);
    out.reserve(kFixedBytes + state.contacts.size() * kContactBytes +
                state.spent.size() * kSpentBytes);
    Writer write(out);
    write.text(kSnapshotDomain);
    write.u8(state.has_identity ? 1U : 0U);
    if (state.has_identity) {
        write.bytes(state.seed.view());
        write.bytes(state.public_key);
        write.u64(state.identity_created);
    }
    write.u64(state.clock_high_water);
    write.u64(state.pruned_through);
    write.u16(static_cast<std::uint16_t>(state.contacts.size()));
    for (const Contact& contact : state.contacts) {
        write_contact(write, contact, false);
    }
    write.u16(static_cast<std::uint16_t>(state.spent.size()));
    for (const SpentInvitation& spent : state.spent) write_spent(write, spent);
    return SecretBytes(out);
}

// The secrets of a code that a hello opened, before its contact exists.
void write_code_secrets(Writer& write, const ContactSecrets& secrets) {
    write.bytes(secrets.receive.view());
    write.bytes(secrets.root.view());
    write.bytes(secrets.transcript);
    write.bytes(secrets.own_ratchet.view());
}

[[nodiscard]] bool read_code_secrets(Reader& in, ContactSecrets& secrets) {
    return in.secret(secrets.receive) && in.secret(secrets.root) &&
           in.fixed(secrets.transcript) && in.secret(secrets.own_ratchet);
}

SecretBytes encode_snapshot2(const StoreState& state) {
    // As for snapshot 1, the reservation covers the largest encoding of
    // these counts, so the vector never reallocates and strands a secret.
    std::vector<Byte> out;
    const WipeOnExit wiped(out);
    out.reserve(kSnapshot2FixedBytes +
                state.contacts.size() * (kContactBytes + kPairedBytes) +
                state.spent.size() * kSpentBytes +
                state.codes.size() * kOwnedCodeBytes +
                state.scans.size() * kScanBytes);
    Writer write(out);
    write.text(kSnapshot2Domain);
    write.bytes(state.seed.view());
    write.bytes(state.public_key);
    write.u64(state.identity_created);
    write.bytes(state.ml_dsa_seed.view());
    write.u64(state.clock_high_water);
    write.u64(state.pruned_through);
    write.u16(static_cast<std::uint16_t>(state.contacts.size()));
    auto secrets = state.contact_secrets.begin();
    for (const Contact& contact : state.contacts) {
        write_contact(write, contact, true);
        if (!contact.paired) continue;
        const PairedContact& paired = *contact.paired;
        write.bytes(paired.ml_dsa);
        write_authority(write, paired.send_mailbox);
        write.bytes(paired.send_address);
        write_authority(write, paired.receive_mailbox);
        write.u64(paired.paired_at);
        write.u8(static_cast<std::uint8_t>(paired.verified_by));
        write.u8(static_cast<std::uint8_t>(secrets->role));
        write.bytes(secrets->receive.view());
        write.bytes(secrets->transcript);
        write.u8(secrets->seed_held ? 1U : 0U);
        if (secrets->seed_held) {
            write.bytes(secrets->root.view());
            write.bytes(secrets->own_ratchet.view());
            write.bytes(secrets->peer_ratchet);
        }
        ++secrets;
    }
    write.u16(static_cast<std::uint16_t>(state.spent.size()));
    for (const SpentInvitation& spent : state.spent) write_spent(write, spent);
    write.u8(static_cast<std::uint8_t>(state.codes.size()));
    for (const OwnedCode& owned : state.codes) {
        write_code_record(write, owned.code);
        write.bytes(owned.inbox.view());
        write_name(write, owned.own_name);
        write.u8(static_cast<std::uint8_t>(owned.state));
        write.u64(owned.deadline);
        if (owned.state == CodeState::Open) continue;
        write.bytes(owned.peer.ed25519);
        write.bytes(owned.peer.ml_dsa);
        write_authority(write, owned.peer_mailbox);
        write.bytes(owned.peer_inbox);
        write_name(write, owned.peer_name);
        write_code_secrets(write, owned.secrets);
        write.u8(owned.matched ? 1U : 0U);
        if (owned.state == CodeState::Confirmed) {
            write.bytes(owned.secrets.peer_ratchet);
        }
    }
    write.u8(static_cast<std::uint8_t>(state.scans.size()));
    for (const PendingScan& scan : state.scans) {
        write_code_record(write, scan.code);
        write.u8(scan.scanned ? 1U : 0U);
        write_authority(write, scan.own_mailbox);
        write.bytes(scan.secrets.share.view());
        write.bytes(scan.secrets.kem.view());
        write.bytes(scan.secrets.inbox.view());
        write.bytes(scan.hello_transcript);
        write.u64(scan.deadline);
    }
    return SecretBytes(out);
}

[[nodiscard]] Status decode_snapshot1(const CryptoContext& crypto, Reader& in,
                                      StoreState& state) {
    std::uint8_t has_identity = 0U;
    if (!in.literal(as_bytes(kSnapshotDomain)) || !in.u8(has_identity) ||
        has_identity > 1U) {
        return Status::CorruptState;
    }
    state.has_identity = has_identity == 1U;
    if (state.has_identity) {
        if (!in.secret(state.seed) || !in.fixed(state.public_key) ||
            !in.u64(state.identity_created)) {
            return Status::CorruptState;
        }
        if (crypto.public_key(state.seed) != state.public_key) {
            return Status::CorruptState;
        }
    }
    if (!in.u64(state.clock_high_water) || !in.u64(state.pruned_through) ||
        !read_contacts1(in, state) || !read_spent_list(in, state) ||
        !in.at_end() || !consistent(state)) {
        return Status::CorruptState;
    }
    return Status::Ok;
}

[[nodiscard]] bool read_paired(Reader& in, PairedContact& paired,
                               ContactSecrets& secrets) {
    std::uint8_t verified_by = 0U;
    std::uint8_t role = 0U;
    std::uint8_t seed = 0U;
    if (!in.fixed(paired.ml_dsa) || !read_authority(in, paired.send_mailbox) ||
        !in.fixed(paired.send_address) ||
        !read_authority(in, paired.receive_mailbox) ||
        !in.u64(paired.paired_at) || !in.u8(verified_by) ||
        verified_by > static_cast<std::uint8_t>(VerifiedBy::Compared) ||
        !in.u8(role) || role < static_cast<std::uint8_t>(PairingRole::Owner) ||
        role > static_cast<std::uint8_t>(PairingRole::Scanner) ||
        !in.secret(secrets.receive) || !in.fixed(secrets.transcript) ||
        !in.u8(seed) || seed > 1U) {
        return false;
    }
    secrets.seed_held = seed == 1U;
    if (secrets.seed_held &&
        (!in.secret(secrets.root) || !in.secret(secrets.own_ratchet) ||
         !in.fixed(secrets.peer_ratchet))) {
        return false;
    }
    paired.verified_by = static_cast<VerifiedBy>(verified_by);
    secrets.role = static_cast<PairingRole>(role);
    return true;
}

[[nodiscard]] bool read_owned(const CryptoContext& crypto, Reader& in,
                              const StoreState& state, OwnedCode& owned) {
    std::uint8_t code_state = 0U;
    if (!read_code_record(in, owned.code) || !in.secret(owned.inbox) ||
        !read_name(in, owned.own_name) || !in.u8(code_state) ||
        code_state < static_cast<std::uint8_t>(CodeState::Open) ||
        code_state > static_cast<std::uint8_t>(CodeState::Confirmed) ||
        !in.u64(owned.deadline)) {
        return false;
    }
    owned.state = static_cast<CodeState>(code_state);
    if (owned.code.owner != state.fingerprint2 ||
        owned.code.inbox != mailbox_address(crypto, owned.inbox)) {
        return false;
    }
    if (owned.state == CodeState::Open) return true;
    std::uint8_t matched = 0U;
    if (!in.fixed(owned.peer.ed25519) || !in.fixed(owned.peer.ml_dsa) ||
        !read_authority(in, owned.peer_mailbox) ||
        !in.fixed(owned.peer_inbox) || !read_name(in, owned.peer_name) ||
        !read_code_secrets(in, owned.secrets) || !in.u8(matched) ||
        matched > 1U) {
        return false;
    }
    owned.matched = matched == 1U;
    owned.secrets.key = owned.peer.ed25519;
    owned.secrets.role = PairingRole::Owner;
    if (owned.state == CodeState::Confirmed &&
        !in.fixed(owned.secrets.peer_ratchet)) {
        return false;
    }
    // Only an in-person code is compared, and never with oneself.
    return (!owned.matched || owned.code.kind == PairingKind::InPerson) &&
           owned.peer.ed25519 != state.public_key;
}

[[nodiscard]] bool read_scan(Reader& in, const StoreState& state,
                             PendingScan& scan) {
    std::uint8_t scanned = 0U;
    if (!read_code_record(in, scan.code) || !in.u8(scanned) || scanned > 1U ||
        !read_authority(in, scan.own_mailbox) ||
        !in.secret(scan.secrets.share) || !in.secret(scan.secrets.kem) ||
        !in.secret(scan.secrets.inbox) || !in.fixed(scan.hello_transcript) ||
        !in.u64(scan.deadline)) {
        return false;
    }
    scan.scanned = scanned == 1U;
    return scan.code.owner != state.fingerprint2;
}

[[nodiscard]] Status decode_snapshot2(const CryptoContext& crypto, Reader& in,
                                      StoreState& state) {
    if (!in.literal(as_bytes(kSnapshot2Domain)) || !in.secret(state.seed) ||
        !in.fixed(state.public_key) || !in.u64(state.identity_created) ||
        !in.secret(state.ml_dsa_seed)) {
        return Status::CorruptState;
    }
    if (crypto.public_key(state.seed) != state.public_key) {
        return Status::CorruptState;
    }
    state.has_identity = true;
    state.has_identity2 = true;
    state.identity2.ed25519 = state.public_key;
    state.identity2.ml_dsa = crypto.ml_dsa_public_key(state.ml_dsa_seed);
    state.fingerprint2 = fingerprint2(crypto, state.identity2);

    std::uint16_t contact_count = 0U;
    if (!in.u64(state.clock_high_water) || !in.u64(state.pruned_through) ||
        !in.u16(contact_count) || contact_count > kMaxContacts) {
        return Status::CorruptState;
    }
    state.contacts.clear();
    state.contacts.reserve(contact_count);
    state.contact_secrets.clear();
    for (std::uint16_t index = 0U; index < contact_count; ++index) {
        Contact contact;
        std::uint8_t flags = 0U;
        if (!read_contact(in, contact, kHasReplacedBy | kHasReplaces | kPaired,
                          flags) ||
            (!state.contacts.empty() &&
             !key_less(state.contacts.back().key, contact.key))) {
            return Status::CorruptState;
        }
        if ((flags & kPaired) != 0U) {
            PairedContact paired;
            ContactSecrets secrets;
            secrets.key = contact.key;
            if (!read_paired(in, paired, secrets)) return Status::CorruptState;
            contact.paired = std::move(paired);
            state.contact_secrets.push_back(std::move(secrets));
        }
        state.contacts.push_back(std::move(contact));
    }
    std::uint8_t code_count = 0U;
    if (!read_spent_list(in, state) || !in.u8(code_count) ||
        code_count > kMaxOwnedCodes) {
        return Status::CorruptState;
    }
    state.codes.clear();
    state.codes.reserve(code_count);
    for (std::uint8_t index = 0U; index < code_count; ++index) {
        state.codes.emplace_back();
        if (!read_owned(crypto, in, state, state.codes.back())) {
            return Status::CorruptState;
        }
    }
    std::uint8_t scan_count = 0U;
    if (!in.u8(scan_count) || scan_count > kMaxPendingScans) {
        return Status::CorruptState;
    }
    state.scans.clear();
    state.scans.reserve(scan_count);
    for (std::uint8_t index = 0U; index < scan_count; ++index) {
        state.scans.emplace_back();
        if (!read_scan(in, state, state.scans.back())) {
            return Status::CorruptState;
        }
    }
    if (!in.at_end() || !consistent(state) || !consistent_pairing(state) ||
        !ascending_ids(state.codes) || !ascending_ids(state.scans)) {
        return Status::CorruptState;
    }
    return Status::Ok;
}

}  // namespace

SecretBytes encode_snapshot(const StoreState& state) {
    return state.has_identity2 ? encode_snapshot2(state)
                               : encode_snapshot1(state);
}

Status decode_snapshot(const CryptoContext& crypto, ByteView snapshot,
                       StoreState& state) {
    if (snapshot.size() > kMaxSnapshotBytes) return Status::CorruptState;
    Reader in(snapshot);
    const ByteView domain =
        snapshot.first(std::min(snapshot.size(), kSnapshotDomain.size()));
    if (std::equal(domain.begin(), domain.end(),
                   as_bytes(kSnapshot2Domain).begin(),
                   as_bytes(kSnapshot2Domain).end())) {
        return decode_snapshot2(crypto, in, state);
    }
    return decode_snapshot1(crypto, in, state);
}

std::size_t max_snapshot2_bytes() noexcept {
    return kMaxSnapshot2Bytes;
}

}  // namespace ito::call
