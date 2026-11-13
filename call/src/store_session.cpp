/* Copyright (C) 2026 FixCraft Inc. AGPL-3.0-or-later. */

// What the store gives a message session (session.hpp): the contact's trust,
// fingerprints and mailbox at each operation, and the pairing seed exactly
// once. The seed leaves only after the session's first snapshot is saved,
// and the store then forgets it in its own snapshot.

#include <algorithm>

#include "store.hpp"

namespace ito::call {

Status Store::message_peer(const Key& contact, MessagePeer& out) const {
    std::lock_guard guard(lock_);
    const Contact* found = lookup_contact(state_, contact);
    if (found == nullptr) return Status::NotFound;
    const ContactSecrets* secrets = lookup_secrets(state_, contact);
    if (!state_.has_identity2 || !found->paired || secrets == nullptr) {
        return Status::WrongState;
    }
    out.trust = found->trust;
    out.transcript = secrets->transcript;
    out.seed_held = secrets->seed_held;
    out.own_fingerprint = state_.fingerprint2;
    out.peer_fingerprint =
        fingerprint2(crypto_, Identity2{found->key, found->paired->ml_dsa});
    out.send_mailbox = found->paired->send_mailbox;
    out.send_address = found->paired->send_address;
    out.receive_mailbox = found->paired->receive_mailbox;
    return Status::Ok;
}

Status Store::session_seed(const Key& contact, const Hash& transcript,
                           SessionSeed& out) const {
    std::lock_guard guard(lock_);
    const Contact* found = lookup_contact(state_, contact);
    if (found == nullptr) return Status::NotFound;
    const ContactSecrets* secrets = lookup_secrets(state_, contact);
    if (!found->paired || secrets == nullptr) return Status::WrongState;
    if (!secrets->seed_held || secrets->transcript != transcript) {
        return Status::WrongState;
    }
    out.role = secrets->role;
    out.root.assign(secrets->root.view());
    out.transcript = secrets->transcript;
    out.own_ratchet.assign(secrets->own_ratchet.view());
    out.peer_ratchet = secrets->peer_ratchet;
    out.paired_at = found->paired->paired_at;
    return Status::Ok;
}

Status Store::consume_session_seed(const Key& contact, const Hash& transcript) {
    std::lock_guard guard(lock_);
    StoreState candidate;
    candidate.copy_from(state_);
    const auto secrets = std::find_if(
        candidate.contact_secrets.begin(), candidate.contact_secrets.end(),
        [&](const ContactSecrets& held) { return held.key == contact; });
    if (secrets == candidate.contact_secrets.end()) return Status::NotFound;
    if (!secrets->seed_held || secrets->transcript != transcript) {
        return Status::WrongState;
    }
    secrets->seed_held = false;
    wipe(secrets->root.data(), secrets->root.size());
    wipe(secrets->own_ratchet.data(), secrets->own_ratchet.size());
    secrets->peer_ratchet = Key{};
    return commit(candidate);
}

Status Store::register_session(const Key& contact) {
    std::lock_guard guard(lock_);
    if (std::find(sessions_.begin(), sessions_.end(), contact) !=
        sessions_.end()) {
        return Status::Busy;
    }
    if (sessions_.size() >= kMaxContacts) return Status::Capacity;
    sessions_.push_back(contact);
    return Status::Ok;
}

void Store::unregister_session(const Key& contact) noexcept {
    std::lock_guard guard(lock_);
    std::erase(sessions_, contact);
}

}  // namespace ito::call
