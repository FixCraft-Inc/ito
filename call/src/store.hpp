/* Copyright (C) 2026 FixCraft Inc. AGPL-3.0-or-later. */

// The local communication identity, contact trust and spent invitations of
// docs/CALL_SECURITY.md, identity 2 and pairing state of
// docs/MESSAGE_SECURITY.md, and the exact plaintext snapshot that holds them.
// The platform seals and publishes each snapshot. This class decides what
// it contains and applies every policy.
//
// Each mutation builds a candidate state, encodes it, asks the platform to
// persist it, and only then makes it current. A refused persist leaves the
// previous state current. An ambiguous one latches the store: it refuses
// mutation until the platform reopens it from what storage actually holds.
//
// One mutex serializes all access. Persistence runs with it held, so the
// platform callback must not call back into the store.

#pragma once

#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <limits>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "bytes.hpp"
#include "codec.hpp"
#include "crypto.hpp"
#include "identity.hpp"
#include "pairing.hpp"
#include "ratchet.hpp"
#include "status.hpp"

namespace ito::call {

using Clock = std::chrono::steady_clock;
using TimePoint = Clock::time_point;

// No finite-lifetime invitation can use this wall second. In the existing
// snapshot clock field it records detected uncertainty across store reopen.
inline constexpr std::uint64_t kUncertainClock =
    std::numeric_limits<std::uint64_t>::max();

class Store;

// A wall-clock observation admitted by one store. Its monotonic projection
// remains valid for that attempt, without treating a rounded deadline as a
// new wall-clock observation. It cannot be restored from a snapshot.
class ClockAdmission final {
public:
    ClockAdmission() = default;
    [[nodiscard]] Status project(TimePoint now, std::uint64_t& lower,
                                 std::uint64_t& upper) const noexcept;

private:
    friend class Store;
    const Store* owner_{nullptr};
    std::uint64_t wall_{0U};
    TimePoint observed_{};
};

enum class Trust : std::uint8_t { Unverified = 1, Verified = 2, Blocked = 3 };

// How a paired contact's identity 2 was verified, when it is Verified.
// Compared is the full safety code, InPerson the scan with the short code.
enum class VerifiedBy : std::uint8_t { None = 0, InPerson = 1, Compared = 2 };

// The public half of a contact paired with identity 2. send is where the
// contact receives from us, receive where our inbox for the contact lives.
struct PairedContact final {
    MlDsaPublicKey ml_dsa{};
    Authority send_mailbox;
    Hash send_address{};
    Authority receive_mailbox;
    std::uint64_t paired_at{0U};
    VerifiedBy verified_by{VerifiedBy::None};

    [[nodiscard]] bool operator==(const PairedContact&) const = default;
};

// A contact is keyed by its Ed25519 key. An identity 1 contact has no paired
// part and shows "Pair again". Pairing again keeps the record, its name and
// the app's history, and adds the ML-DSA key that the Ed25519 key signed with.
struct Contact final {
    Key key{};
    Trust trust{Trust::Unverified};
    std::optional<Key> replaced_by;
    std::optional<Key> replaces;
    std::uint64_t added_at{0U};
    std::uint64_t verified_at{0U};
    std::string name;
    std::optional<PairedContact> paired;

    [[nodiscard]] bool operator==(const Contact&) const = default;
};

// The secret half of a paired contact: our inbox for it, the pairing's
// transcript, and the seed the message ratchet starts from. The session
// takes the seed once, and the store then forgets the root and the first
// ratchet key, so a stolen store opens no message sealed before.
struct ContactSecrets final {
    Key key{};  // the contact's Ed25519 key
    PairingRole role{PairingRole::Owner};
    Secret32 receive;
    Hash transcript{};
    bool seed_held{true};
    Secret32 root;
    Secret32 own_ratchet;
    Key peer_ratchet{};

    void copy_from(const ContactSecrets& other);
};

enum class CodeState : std::uint8_t { Open = 1, Replied = 2, Confirmed = 3 };

// A pairing code this installation showed. From the first valid hello on it
// holds the scanner's identity and the pairing's keys until the confirm,
// and for an in-person code until the owner says the short codes match.
struct OwnedCode final {
    PairingCode code;
    Secret32 inbox;  // the pairing inbox's secret
    // The name the owner offers in its reply.
    std::string own_name;
    CodeState state{CodeState::Open};
    // Open: the code's expiry. Later: the end of the reply window.
    std::uint64_t deadline{0U};
    Identity2 peer;
    Authority peer_mailbox;
    Hash peer_inbox{};
    std::string peer_name;
    // receive is our inbox for the scanner, given in the reply. peer_ratchet
    // arrives with the confirm.
    ContactSecrets secrets;
    bool matched{false};

    void copy_from(const OwnedCode& other);
};

// A code this installation scanned, waiting for the owner's reply.
struct PendingScan final {
    PairingCode code;
    // Read from the owner's screen rather than received as a link.
    bool scanned{false};
    Authority own_mailbox;
    ScanSecrets secrets;
    Hash hello_transcript{};
    std::uint64_t deadline{0U};

    void copy_from(const PendingScan& other);
};

// A sealed item for the platform to deposit.
struct OutgoingItem final {
    Authority mailbox;
    Hash address{};
    std::vector<Byte> item;
};

enum class PairingEventKind : std::uint8_t {
    // The owner answered a hello. The reply goes to the scanner.
    Replied = 1,
    // The scanner verified the reply and saved the contact. The confirm goes
    // to the owner.
    Paired = 2,
    // The owner holds the confirm and waits for the short-code decision.
    Confirmed = 3,
    // The owner said the codes match, before the confirm arrived.
    Matched = 4,
    // The owner saved the contact.
    Completed = 5,
    // The owner said the codes differ, and the pairing is gone.
    Rejected = 6,
};

struct PairingEvent final {
    PairingEventKind kind{PairingEventKind::Replied};
    PairingId id{};
    PairingRole role{PairingRole::Owner};
    PairingKind pairing_kind{PairingKind::InPerson};
    Key peer{};
    Trust trust{Trust::Unverified};
    // Set after an in-person exchange: Replied, Paired, Confirmed, Matched.
    std::optional<ShortCode> short_code;
    std::string peer_name;
};

// A paired contact's public part with what is derived from its secrets.
struct PairedView final {
    PairedContact paired;
    Hash fingerprint{};
    Hash receive_address{};
    PairingRole role{PairingRole::Owner};
};

// What a message session reads about its contact at each operation.
struct MessagePeer final {
    Trust trust{Trust::Unverified};
    Hash transcript{};
    bool seed_held{false};
    Hash own_fingerprint{};
    Hash peer_fingerprint{};
    Authority send_mailbox;
    Hash send_address{};
    Authority receive_mailbox;
};

// One open pairing, for display.
struct PairingInfo final {
    PairingId id{};
    PairingRole role{PairingRole::Owner};
    PairingKind kind{PairingKind::InPerson};
    // Open while the owner's code waits for a hello. Replied or Confirmed
    // after it. A scanner's pairing is Open until its reply arrives.
    CodeState state{CodeState::Open};
    std::uint64_t deadline{0U};
    bool matched{false};
    std::optional<Key> peer;
    std::optional<ShortCode> short_code;
    std::string peer_name;
};

enum class InboxPurpose : std::uint8_t {
    // A shown code's pairing inbox, open until its first valid hello.
    ShownCode = 1,
    // The inbox a reply named, until the pairing completes.
    AwaitingConfirm = 2,
    // A scanner's inbox for the owner's reply.
    AwaitingReply = 3,
    // A paired contact's inbox. Blocked contacts have none.
    ContactInbox = 4,
};

// An inbox the platform keeps open on its mailbox. The secret opens it.
struct Inbox final {
    InboxPurpose purpose{InboxPurpose::ContactInbox};
    Authority mailbox;
    Hash address{};
    Secret32 secret;
    // The pairing for the first three purposes.
    PairingId pairing{};
    // The contact for ContactInbox.
    Key contact{};
};

struct SpentInvitation final {
    Id invitation_id{};
    // SHA-256 of the complete invitation. Not secret.
    Hash invitation_hash{};
    std::uint64_t expires_at{0U};
    Role role{Role::Initiator};

    [[nodiscard]] bool operator==(const SpentInvitation&) const = default;
};

enum class PersistResult { Committed, NotCommitted, Ambiguous };

// The platform's sealing and atomic publication of one snapshot.
using Persist = std::function<PersistResult(ByteView snapshot)>;

// The contents of one snapshot.
struct StoreState final {
    bool has_identity{false};
    Seed seed;
    Key public_key{};
    std::uint64_t identity_created{0U};
    // Identity 2 adds an ML-DSA-87 seed. Its public key and the fingerprint
    // are derived when the seed is created or read, and are never stored.
    bool has_identity2{false};
    Secret32 ml_dsa_seed;
    Identity2 identity2;
    Hash fingerprint2{};
    // A durable lower bound from admitted wall observations and their
    // monotonic projections, or kUncertainClock after detected rollback.
    // It refuses rollback, never proves current time or safe recovery.
    std::uint64_t clock_high_water{0U};
    // The latest expiry of any pruned received invitation. A received
    // invitation expiring no later than this may be a replay of one whose
    // record is gone, so it is refused.
    std::uint64_t pruned_through{0U};
    std::vector<Contact> contacts;       // ascending by key
    std::vector<SpentInvitation> spent;  // ascending by invitation ID
    // One per paired contact, ascending by key.
    std::vector<ContactSecrets> contact_secrets;
    std::vector<OwnedCode> codes;    // ascending by pairing ID
    std::vector<PendingScan> scans;  // ascending by pairing ID

    StoreState() = default;
    StoreState(const StoreState&) = delete;
    StoreState& operator=(const StoreState&) = delete;
    void copy_from(const StoreState& other);
    // Publishes a committed candidate. It cannot fail.
    void take_from(StoreState&& other) noexcept;
};

// A contact and a paired contact's secrets in a state, or null.
[[nodiscard]] const Contact* lookup_contact(const StoreState& state,
                                            const Key& key) noexcept;
[[nodiscard]] const ContactSecrets* lookup_secrets(const StoreState& state,
                                                   const Key& key) noexcept;

inline constexpr std::string_view kSnapshotDomain{"ito/identity-snapshot/1\0",
                                                  24U};
inline constexpr std::string_view kSnapshot2Domain{"ito/identity-snapshot/2\0",
                                                   24U};

// Snapshot 1 while the identity is version 1, snapshot 2 once it has its
// ML-DSA key. A store that never upgrades keeps writing snapshot 1.
[[nodiscard]] SecretBytes encode_snapshot(const StoreState& state);
// Reads either version. Parses and checks every invariant, including that
// the seed derives the stored public key. Malformed or inconsistent input is
// CorruptState.
[[nodiscard]] Status decode_snapshot(const CryptoContext& crypto,
                                     ByteView snapshot, StoreState& state);
// The largest snapshot 2 the store's bounds allow, counted field by field.
[[nodiscard]] std::size_t max_snapshot2_bytes() noexcept;

class Store final {
public:
    // Opens a snapshot (empty for a new installation). Throws only on
    // allocation or dependency failure.
    [[nodiscard]] static Status open(const CryptoContext& crypto,
                                     ByteView snapshot, Persist persist,
                                     std::unique_ptr<Store>& out);
    Store(const Store&) = delete;
    Store& operator=(const Store&) = delete;

    [[nodiscard]] const CryptoContext& crypto() const noexcept {
        return crypto_;
    }

    [[nodiscard]] Status create_identity(std::uint64_t now);
    [[nodiscard]] Status identity(Key& key) const;

    [[nodiscard]] Status add_contact(const Key& key, std::string_view name,
                                     std::uint64_t now);
    [[nodiscard]] Status verify_contact(const Key& key,
                                        std::string_view compared,
                                        std::uint64_t now);
    [[nodiscard]] Status block_contact(const Key& key);
    [[nodiscard]] Status rename_contact(const Key& key, std::string_view name);
    [[nodiscard]] Status replace_contact(const Key& old_key, const Key& new_key,
                                         std::uint64_t now);
    [[nodiscard]] std::vector<Contact> contacts() const;
    // One contact by its place in key order, without copying the others.
    [[nodiscard]] std::size_t contact_count() const;
    [[nodiscard]] std::optional<Contact> contact_at(std::size_t index) const;
    [[nodiscard]] std::optional<Contact> find_contact(const Key& key) const;
    [[nodiscard]] bool is_verified(const Key& key) const;

    // Checks a fresh platform wall observation against the durable floor and
    // the live monotonic anchor. Refusal checkpoints detected uncertainty.
    // Admission checkpoints the clock separately from identity/trust/replay
    // mutations, before invitation secrets are used.
    [[nodiscard]] Status check_clock(std::uint64_t now, TimePoint observed);
    [[nodiscard]] Status admit_clock(std::uint64_t now, TimePoint observed,
                                     ClockAdmission& out);
    // Advances an already admitted attempt's lower bound. Its upper rounding
    // is for expiry only and must never become a durable clock observation.
    [[nodiscard]] Status advance_clock(const ClockAdmission& admission,
                                       TimePoint now);

    // Checks a received invitation's freshness against the spent records:
    // AlreadySpent for a recorded ID, Expired when its record may have been
    // pruned. Does not mutate.
    [[nodiscard]] Status check_unspent(const Id& invitation_id,
                                       std::uint64_t expires_at) const;
    // Records the invitation as spent before its first JOIN, using a clock
    // admitted by this store. Capacity refuses rather than evicting a record.
    [[nodiscard]] Status spend(const SpentInvitation& record,
                               const ClockAdmission& admission, TimePoint now);

    // Signs with the identity seed, which never leaves the store.
    [[nodiscard]] Status sign(ByteView message, Signature& signature) const;

    // Both signing halves, bound to the store's identity 2 fingerprint.
    [[nodiscard]] Status sign2(std::string_view label,
                               std::span<const ByteView> body,
                               CompositeSignature& signature) const;

    // Identity 2 (docs/MESSAGE_SECURITY.md). upgrade adds the ML-DSA key to
    // an existing identity: NotFound without one, WrongState when done.
    [[nodiscard]] Status upgrade_identity();
    [[nodiscard]] Status identity2(Identity2& identity,
                                   Hash& fingerprint) const;

    // Pairing. Each call that takes now admits the clock first, under the
    // same rule as invitations, and prunes pairings past their deadline.
    // The owner shows a new code, or the text of an open one again.
    [[nodiscard]] Status create_code(PairingKind kind, const Authority& mailbox,
                                     std::string_view name, std::uint64_t now,
                                     TimePoint observed, PairingId& id,
                                     SecretBytes& text);
    [[nodiscard]] Status code_text(const PairingId& id,
                                   SecretBytes& text) const;
    // The scanner reads a code and seals its hello.
    [[nodiscard]] Status scan(std::string_view text, bool scanned,
                              const Authority& own_mailbox,
                              std::string_view name, std::uint64_t now,
                              TimePoint observed, PairingId& id,
                              OutgoingItem& hello);
    // An item that arrived at one of this store's pairing inboxes. out holds
    // the reply or confirm to deposit, if the event has one.
    [[nodiscard]] Status receive_pairing(const Hash& address, ByteView item,
                                         std::uint64_t now, TimePoint observed,
                                         PairingEvent& event,
                                         std::optional<OutgoingItem>& out);
    // The owner's answer to the in-person short-code comparison.
    [[nodiscard]] Status decide_pairing(const PairingId& id, bool matches,
                                        std::uint64_t now, TimePoint observed,
                                        PairingEvent& event);
    [[nodiscard]] Status cancel_pairing(const PairingId& id);
    [[nodiscard]] std::vector<PairingInfo> pairings() const;
    // The scanner's confirm again, for a resend. WrongState once this store
    // was the owner of that pairing.
    [[nodiscard]] Status confirm_item(const Key& contact,
                                      OutgoingItem& out) const;

    // NotFound for an unknown key, WrongState for an identity 1 contact.
    [[nodiscard]] Status paired_contact(const Key& contact,
                                        PairedView& out) const;

    [[nodiscard]] std::size_t inbox_count() const;
    [[nodiscard]] Status inbox_at(std::size_t index, Inbox& out) const;

    // The 60-digit safety code with a paired contact, and verification by
    // comparing it in full.
    [[nodiscard]] Status safety_code(const Key& contact,
                                     SafetyCode& code) const;
    [[nodiscard]] Status verify_safety_code(const Key& contact,
                                            std::string_view compared,
                                            std::uint64_t now);

    // Message sessions (session.hpp). NotFound for an unknown key,
    // WrongState for a contact without identity 2 on both sides.
    [[nodiscard]] Status message_peer(const Key& contact,
                                      MessagePeer& out) const;
    // The seed of the pairing named by transcript. WrongState once a session
    // took it or the contact paired again.
    [[nodiscard]] Status session_seed(const Key& contact,
                                      const Hash& transcript,
                                      SessionSeed& out) const;
    // Forgets that seed, after the session's first snapshot is saved.
    [[nodiscard]] Status consume_session_seed(const Key& contact,
                                              const Hash& transcript);
    // One open session per contact, so two cannot seal with one chain.
    [[nodiscard]] Status register_session(const Key& contact);
    void unregister_session(const Key& contact) noexcept;

    // Pending invitations and attempts share one bound of eight.
    [[nodiscard]] Status acquire_pending();
    void release_pending() noexcept;

    // One active attempt per installation. stop is raised when the attempt's
    // peer key is blocked or replaced while it runs.
    [[nodiscard]] Status register_attempt(const Key& peer,
                                          std::atomic<bool>* stop);
    void unregister_attempt() noexcept;

    // Handles that borrow this store. Destruction is refused while any do.
    void add_borrower() noexcept;
    void remove_borrower() noexcept;
    [[nodiscard]] bool borrowed() const noexcept;

    [[nodiscard]] bool latched() const noexcept;

private:
    Store(const CryptoContext& crypto, Persist persist);

    // Encodes candidate, persists it and makes it current. Called with lock_
    // held.
    [[nodiscard]] Status commit(StoreState& candidate);
    [[nodiscard]] Status check_clock_locked(std::uint64_t now,
                                            TimePoint observed);
    [[nodiscard]] Status refuse_clock_locked();
    [[nodiscard]] Status project_clock(const ClockAdmission& admission,
                                       TimePoint now,
                                       std::uint64_t& lower) const;
    void stop_attempt_for(const Key& key) noexcept;
    [[nodiscard]] Contact* find(StoreState& state, const Key& key) noexcept;
    [[nodiscard]] Signer signer() const noexcept;
    [[nodiscard]] Status admit_pairing_clock(std::uint64_t now,
                                             TimePoint observed,
                                             std::uint64_t& admitted);
    [[nodiscard]] Trust save_paired(StoreState& state, const Identity2& peer,
                                    const std::string& name,
                                    PairedContact paired,
                                    ContactSecrets&& secrets,
                                    bool verified_in_person, std::uint64_t now);
    [[nodiscard]] Status receive_hello(StoreState& candidate, std::size_t index,
                                       ByteView item, std::uint64_t now,
                                       PairingEvent& event,
                                       std::optional<OutgoingItem>& out);
    [[nodiscard]] Status receive_confirm(StoreState& candidate,
                                         std::size_t index, ByteView item,
                                         std::uint64_t now,
                                         PairingEvent& event);
    [[nodiscard]] Status receive_reply(StoreState& candidate, std::size_t index,
                                       ByteView item, std::uint64_t now,
                                       PairingEvent& event,
                                       std::optional<OutgoingItem>& out);
    [[nodiscard]] Status complete_owned(StoreState& candidate,
                                        std::size_t index, std::uint64_t now,
                                        PairingEvent& event);

    const CryptoContext& crypto_;
    Persist persist_;
    mutable std::mutex lock_;
    StoreState state_;
    bool latched_{false};
    // Set before persisting uncertainty can allocate or fail. A refused
    // publication cannot make this live store resume invitation use.
    bool clock_uncertain_{false};
    std::optional<ClockAdmission> clock_anchor_;
    std::optional<TimePoint> last_clock_observed_;
    std::size_t pending_{0U};
    std::size_t borrowers_{0U};
    std::optional<Key> attempt_peer_;
    std::atomic<bool>* attempt_stop_{nullptr};
    // Contacts with an open session. Reserved for every contact, so
    // registering never allocates after the first.
    std::vector<Key> sessions_;
};

}  // namespace ito::call
