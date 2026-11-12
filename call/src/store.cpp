/* Copyright (C) 2026 FixCraft Inc. AGPL-3.0-or-later. */

#include "store.hpp"

#include <algorithm>
#include <limits>

namespace ito::call {
namespace {

[[nodiscard]] bool key_less(const Key& a, const Key& b) noexcept {
    return std::lexicographical_compare(a.begin(), a.end(), b.begin(), b.end());
}

template <class Record>
void copy_records(std::vector<Record>& target,
                  const std::vector<Record>& source) {
    target.clear();
    target.reserve(source.size());
    for (const Record& record : source) {
        target.emplace_back();
        target.back().copy_from(record);
    }
}

}  // namespace

void ContactSecrets::copy_from(const ContactSecrets& other) {
    key = other.key;
    role = other.role;
    receive.assign(other.receive.view());
    root.assign(other.root.view());
    transcript = other.transcript;
    own_ratchet.assign(other.own_ratchet.view());
    peer_ratchet = other.peer_ratchet;
}

void OwnedCode::copy_from(const OwnedCode& other) {
    code.copy_from(other.code);
    inbox.assign(other.inbox.view());
    own_name = other.own_name;
    state = other.state;
    deadline = other.deadline;
    peer = other.peer;
    peer_mailbox = other.peer_mailbox;
    peer_inbox = other.peer_inbox;
    peer_name = other.peer_name;
    secrets.copy_from(other.secrets);
    matched = other.matched;
}

void PendingScan::copy_from(const PendingScan& other) {
    code.copy_from(other.code);
    scanned = other.scanned;
    own_mailbox = other.own_mailbox;
    secrets.copy_from(other.secrets);
    hello_transcript = other.hello_transcript;
    deadline = other.deadline;
}

void StoreState::copy_from(const StoreState& other) {
    has_identity = other.has_identity;
    seed.assign(other.seed.view());
    public_key = other.public_key;
    identity_created = other.identity_created;
    has_identity2 = other.has_identity2;
    ml_dsa_seed.assign(other.ml_dsa_seed.view());
    identity2 = other.identity2;
    fingerprint2 = other.fingerprint2;
    clock_high_water = other.clock_high_water;
    pruned_through = other.pruned_through;
    contacts = other.contacts;
    spent = other.spent;
    copy_records(contact_secrets, other.contact_secrets);
    copy_records(codes, other.codes);
    copy_records(scans, other.scans);
}

void StoreState::take_from(StoreState&& other) noexcept {
    has_identity = other.has_identity;
    seed = std::move(other.seed);
    public_key = other.public_key;
    identity_created = other.identity_created;
    has_identity2 = other.has_identity2;
    ml_dsa_seed = std::move(other.ml_dsa_seed);
    identity2 = other.identity2;
    fingerprint2 = other.fingerprint2;
    clock_high_water = other.clock_high_water;
    pruned_through = other.pruned_through;
    contacts = std::move(other.contacts);
    spent = std::move(other.spent);
    contact_secrets = std::move(other.contact_secrets);
    codes = std::move(other.codes);
    scans = std::move(other.scans);
}

Status ClockAdmission::project(TimePoint now, std::uint64_t& lower,
                               std::uint64_t& upper) const noexcept {
    if (owner_ == nullptr) return Status::InvalidArgument;
    if (now < observed_) return Status::ClockRegressed;
    const auto start = observed_.time_since_epoch().count();
    const auto finish = now.time_since_epoch().count();
    if (start < 0 && finish > std::numeric_limits<Clock::rep>::max() + start) {
        return Status::InvalidArgument;
    }
    const auto elapsed = now - observed_;
    const auto whole = std::chrono::floor<std::chrono::seconds>(elapsed);
    const auto rounded = std::chrono::ceil<std::chrono::seconds>(elapsed);
    const auto seconds = static_cast<std::uint64_t>(rounded.count());
    if (wall_ >= kUncertainClock - seconds) {
        return Status::InvalidArgument;
    }
    lower = wall_ + static_cast<std::uint64_t>(whole.count());
    upper = wall_ + seconds;
    return Status::Ok;
}

Store::Store(const CryptoContext& crypto, Persist persist)
    : crypto_(crypto), persist_(std::move(persist)) {}

Status Store::open(const CryptoContext& crypto, ByteView snapshot,
                   Persist persist, std::unique_ptr<Store>& out) {
    std::unique_ptr<Store> store(new Store(crypto, std::move(persist)));
    if (!snapshot.empty()) {
        const Status decoded = decode_snapshot(crypto, snapshot, store->state_);
        if (decoded != Status::Ok) return decoded;
    }
    out = std::move(store);
    return Status::Ok;
}

Status Store::commit(StoreState& candidate) {
    if (latched_) return Status::StorageAmbiguous;
    // A previous uncertainty checkpoint may have been refused. Every later
    // successful write must retain that observation, including contact edits.
    if (clock_uncertain_) candidate.clock_high_water = kUncertainClock;
    SecretBytes encoded = encode_snapshot(candidate);
    if (encoded.size() > kMaxSnapshotBytes) return Status::Capacity;
    PersistResult result = PersistResult::Ambiguous;
    try {
        result = persist_(encoded.view());
    } catch (...) {
        // A callback that throws gives no reliable answer.
        result = PersistResult::Ambiguous;
    }
    switch (result) {
        case PersistResult::Committed:
            // Memory takes the published candidate in a step that cannot
            // fail, so it always matches what the platform holds.
            state_.take_from(std::move(candidate));
            return Status::Ok;
        case PersistResult::NotCommitted:
            return Status::StorageFailed;
        case PersistResult::Ambiguous:
            latched_ = true;
            return Status::StorageAmbiguous;
    }
    latched_ = true;
    return Status::StorageAmbiguous;
}

Contact* Store::find(StoreState& state, const Key& key) noexcept {
    const auto found =
        std::lower_bound(state.contacts.begin(), state.contacts.end(), key,
                         [](const Contact& contact, const Key& wanted) {
                             return key_less(contact.key, wanted);
                         });
    return found != state.contacts.end() && found->key == key ? &*found
                                                              : nullptr;
}

void Store::stop_attempt_for(const Key& key) noexcept {
    if (attempt_peer_ == key && attempt_stop_ != nullptr) {
        attempt_stop_->store(true, std::memory_order_release);
    }
}

Status Store::create_identity(std::uint64_t now) {
    std::lock_guard guard(lock_);
    if (state_.has_identity) return Status::WrongState;
    StoreState candidate;
    candidate.copy_from(state_);
    candidate.has_identity = true;
    crypto_.generate_identity(candidate.seed, candidate.public_key);
    candidate.identity_created = now;
    // A contact can never share the new key, but check rather than assume.
    if (find(candidate, candidate.public_key) != nullptr) {
        return Status::Internal;
    }
    return commit(candidate);
}

Status Store::identity(Key& key) const {
    std::lock_guard guard(lock_);
    if (!state_.has_identity) return Status::NotFound;
    key = state_.public_key;
    return Status::Ok;
}

Status Store::add_contact(const Key& key, std::string_view name,
                          std::uint64_t now) {
    if (!valid_contact_name(name)) return Status::InvalidArgument;
    std::lock_guard guard(lock_);
    if (state_.has_identity && key == state_.public_key) {
        return Status::InvalidArgument;
    }
    StoreState candidate;
    candidate.copy_from(state_);
    if (find(candidate, key) != nullptr) return Status::WrongState;
    if (candidate.contacts.size() >= kMaxContacts) return Status::Capacity;
    Contact contact;
    contact.key = key;
    contact.added_at = now;
    contact.name.assign(name);
    const auto position =
        std::lower_bound(candidate.contacts.begin(), candidate.contacts.end(),
                         key, [](const Contact& existing, const Key& wanted) {
                             return key_less(existing.key, wanted);
                         });
    candidate.contacts.insert(position, std::move(contact));
    return commit(candidate);
}

Status Store::verify_contact(const Key& key, std::string_view compared,
                             std::uint64_t now) {
    const Hash expected = fingerprint(crypto_, key);
    std::lock_guard guard(lock_);
    StoreState candidate;
    candidate.copy_from(state_);
    Contact* contact = find(candidate, key);
    if (contact == nullptr) return Status::NotFound;
    if (contact->trust == Trust::Blocked) return Status::Untrusted;
    // A paired contact's trust covers its ML-DSA key too, so only the
    // safety code, which names both keys, can verify it.
    if (contact->paired) return Status::WrongState;
    if (!fingerprint_matches(compared, expected)) {
        return Status::AuthenticationFailed;
    }
    if (contact->trust == Trust::Verified) return Status::Ok;
    contact->trust = Trust::Verified;
    contact->verified_at = now == 0U ? 1U : now;
    return commit(candidate);
}

Status Store::block_contact(const Key& key) {
    std::lock_guard guard(lock_);
    StoreState candidate;
    candidate.copy_from(state_);
    Contact* contact = find(candidate, key);
    if (contact == nullptr) return Status::NotFound;
    if (contact->trust == Trust::Blocked) return Status::Ok;
    contact->trust = Trust::Blocked;
    // Stop an attempt even when persistence fails or throws.
    stop_attempt_for(key);
    return commit(candidate);
}

Status Store::rename_contact(const Key& key, std::string_view name) {
    if (!valid_contact_name(name)) return Status::InvalidArgument;
    std::lock_guard guard(lock_);
    StoreState candidate;
    candidate.copy_from(state_);
    Contact* contact = find(candidate, key);
    if (contact == nullptr) return Status::NotFound;
    contact->name.assign(name);
    return commit(candidate);
}

Status Store::replace_contact(const Key& old_key, const Key& new_key,
                              std::uint64_t now) {
    std::lock_guard guard(lock_);
    if (old_key == new_key ||
        (state_.has_identity && new_key == state_.public_key)) {
        return Status::InvalidArgument;
    }
    StoreState candidate;
    candidate.copy_from(state_);
    Contact* retired = find(candidate, old_key);
    if (retired == nullptr) return Status::NotFound;
    if (retired->replaced_by || find(candidate, new_key) != nullptr) {
        return Status::WrongState;
    }
    if (candidate.contacts.size() >= kMaxContacts) return Status::Capacity;
    retired->trust = Trust::Blocked;
    retired->replaced_by = new_key;
    Contact successor;
    successor.key = new_key;
    successor.replaces = old_key;
    successor.added_at = now;
    successor.name = retired->name;
    const auto position = std::lower_bound(
        candidate.contacts.begin(), candidate.contacts.end(), new_key,
        [](const Contact& existing, const Key& wanted) {
            return key_less(existing.key, wanted);
        });
    candidate.contacts.insert(position, std::move(successor));
    // Stop an attempt even when persistence fails or throws.
    stop_attempt_for(old_key);
    return commit(candidate);
}

std::vector<Contact> Store::contacts() const {
    std::lock_guard guard(lock_);
    return state_.contacts;
}

std::size_t Store::contact_count() const {
    std::lock_guard guard(lock_);
    return state_.contacts.size();
}

std::optional<Contact> Store::contact_at(std::size_t index) const {
    std::lock_guard guard(lock_);
    if (index >= state_.contacts.size()) return std::nullopt;
    return state_.contacts[index];
}

std::optional<Contact> Store::find_contact(const Key& key) const {
    std::lock_guard guard(lock_);
    for (const Contact& contact : state_.contacts) {
        if (contact.key == key) return contact;
    }
    return std::nullopt;
}

bool Store::is_verified(const Key& key) const {
    std::lock_guard guard(lock_);
    for (const Contact& contact : state_.contacts) {
        if (contact.key == key) return contact.trust == Trust::Verified;
    }
    return false;
}

Status Store::check_unspent(const Id& invitation_id,
                            std::uint64_t expires_at) const {
    std::lock_guard guard(lock_);
    for (const SpentInvitation& spent : state_.spent) {
        if (spent.invitation_id == invitation_id) return Status::AlreadySpent;
    }
    if (expires_at <= state_.pruned_through) return Status::Expired;
    return Status::Ok;
}

Status Store::refuse_clock_locked() {
    clock_uncertain_ = true;
    if (state_.clock_high_water == kUncertainClock)
        return Status::ClockRegressed;
    StoreState candidate;
    candidate.copy_from(state_);
    candidate.clock_high_water = kUncertainClock;
    const Status saved = commit(candidate);
    return saved == Status::Ok ? Status::ClockRegressed : saved;
}

Status Store::check_clock_locked(std::uint64_t now, TimePoint observed) {
    if (latched_) return Status::StorageAmbiguous;
    if (clock_uncertain_ || state_.clock_high_water == kUncertainClock) {
        return refuse_clock_locked();
    }
    if (now == kUncertainClock) return Status::InvalidArgument;
    if (now < state_.clock_high_water) return refuse_clock_locked();
    if (last_clock_observed_ && observed < *last_clock_observed_) {
        return refuse_clock_locked();
    }
    if (clock_anchor_) {
        std::uint64_t lower = 0U;
        std::uint64_t upper = 0U;
        const Status status = clock_anchor_->project(observed, lower, upper);
        if (status == Status::ClockRegressed) return refuse_clock_locked();
        if (status != Status::Ok) return status;
        if (now < lower) return refuse_clock_locked();
    }
    return Status::Ok;
}

Status Store::check_clock(std::uint64_t now, TimePoint observed) {
    std::lock_guard guard(lock_);
    return check_clock_locked(now, observed);
}

Status Store::admit_clock(std::uint64_t now, TimePoint observed,
                          ClockAdmission& out) {
    std::lock_guard guard(lock_);
    const Status checked = check_clock_locked(now, observed);
    if (checked != Status::Ok) return checked;
    if (now > state_.clock_high_water) {
        StoreState candidate;
        candidate.copy_from(state_);
        candidate.clock_high_water = now;
        const Status saved = commit(candidate);
        if (saved != Status::Ok) return saved;
    }
    ClockAdmission admitted;
    admitted.owner_ = this;
    admitted.wall_ = now;
    admitted.observed_ = observed;
    if (!clock_anchor_) {
        clock_anchor_ = admitted;
    } else {
        std::uint64_t lower = 0U;
        std::uint64_t upper = 0U;
        const Status projected = clock_anchor_->project(observed, lower, upper);
        if (projected != Status::Ok) return projected;
        // Equal integer-second samples must not restart elapsed time and
        // disguise a stopped clock. A forward correction establishes a new
        // anchor only when it exceeds the old projection's rounding interval.
        if (now > upper) clock_anchor_ = admitted;
    }
    last_clock_observed_ = observed;
    out = admitted;
    return Status::Ok;
}

Status Store::project_clock(const ClockAdmission& admission, TimePoint now,
                            std::uint64_t& lower) const {
    if (latched_) return Status::StorageAmbiguous;
    if (clock_uncertain_ || state_.clock_high_water == kUncertainClock) {
        return Status::ClockRegressed;
    }
    if (admission.owner_ != this) return Status::InvalidArgument;
    std::uint64_t upper = 0U;
    return admission.project(now, lower, upper);
}

Status Store::advance_clock(const ClockAdmission& admission, TimePoint now) {
    std::lock_guard guard(lock_);
    std::uint64_t lower = 0U;
    const Status checked = project_clock(admission, now, lower);
    if (checked != Status::Ok) return checked;
    if (lower <= state_.clock_high_water) return Status::Ok;
    StoreState candidate;
    candidate.copy_from(state_);
    candidate.clock_high_water = lower;
    return commit(candidate);
}

Status Store::spend(const SpentInvitation& record,
                    const ClockAdmission& admission, TimePoint observed) {
    std::lock_guard guard(lock_);
    std::uint64_t now = 0U;
    const Status checked = project_clock(admission, observed, now);
    if (checked != Status::Ok) return checked;
    StoreState candidate;
    candidate.copy_from(state_);
    for (const SpentInvitation& spent : candidate.spent) {
        if (spent.invitation_id == record.invitation_id) {
            return Status::AlreadySpent;
        }
    }
    if (record.role == Role::Responder &&
        record.expires_at <= candidate.pruned_through) {
        return Status::Expired;
    }
    // This is an admitted attempt's monotonic lower bound. Another fresh
    // observation may be newer, so it is not a new wall-clock sample.
    if (now >= candidate.clock_high_water) {
        std::erase_if(candidate.spent, [&](const SpentInvitation& spent) {
            const bool expired =
                now >= kSpentRetentionSeconds &&
                spent.expires_at <= now - kSpentRetentionSeconds;
            if (expired && spent.role == Role::Responder) {
                candidate.pruned_through =
                    std::max(candidate.pruned_through, spent.expires_at);
            }
            return expired;
        });
    }
    if (candidate.spent.size() >= kMaxSpentInvitations) {
        return Status::Capacity;
    }
    candidate.clock_high_water = std::max(candidate.clock_high_water, now);
    const auto position = std::lower_bound(
        candidate.spent.begin(), candidate.spent.end(), record.invitation_id,
        [](const SpentInvitation& existing, const Id& wanted) {
            return key_less(existing.invitation_id, wanted);
        });
    candidate.spent.insert(position, record);
    return commit(candidate);
}

Status Store::sign(ByteView message, Signature& signature) const {
    std::lock_guard guard(lock_);
    if (!state_.has_identity) return Status::NotFound;
    signature = crypto_.sign(state_.seed, message);
    return Status::Ok;
}

Status Store::acquire_pending() {
    std::lock_guard guard(lock_);
    if (pending_ >= kMaxPendingInvitations) return Status::Capacity;
    ++pending_;
    return Status::Ok;
}

void Store::release_pending() noexcept {
    std::lock_guard guard(lock_);
    if (pending_ > 0U) --pending_;
}

Status Store::register_attempt(const Key& peer, std::atomic<bool>* stop) {
    std::lock_guard guard(lock_);
    if (attempt_peer_) return Status::Busy;
    attempt_peer_ = peer;
    attempt_stop_ = stop;
    return Status::Ok;
}

void Store::unregister_attempt() noexcept {
    std::lock_guard guard(lock_);
    attempt_peer_.reset();
    attempt_stop_ = nullptr;
}

void Store::add_borrower() noexcept {
    std::lock_guard guard(lock_);
    ++borrowers_;
}

void Store::remove_borrower() noexcept {
    std::lock_guard guard(lock_);
    if (borrowers_ > 0U) --borrowers_;
}

bool Store::borrowed() const noexcept {
    std::lock_guard guard(lock_);
    return borrowers_ != 0U;
}

bool Store::latched() const noexcept {
    std::lock_guard guard(lock_);
    return latched_;
}

}  // namespace ito::call
