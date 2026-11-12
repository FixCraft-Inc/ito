/* Copyright (C) 2026 FixCraft Inc. AGPL-3.0-or-later. */

// The mailbox's policy and its in-memory index: principals with their stream
// counts, registrations and rate windows, inboxes with their items, who is
// subscribed to which inbox, and every expiry. The table performs no I/O and
// reads no clock. It decides what the disk must do and appends those jobs to
// the caller's list in the order they must run. The event loop is its only
// caller and submits the jobs, in that order, to the storage worker.

#pragma once

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <span>
#include <unordered_map>
#include <utility>
#include <vector>

#include "limits.hpp"
#include "module_header.hpp"
#include "storage_worker.hpp"
#include "store.hpp"
#include "wire.hpp"

namespace ito::mailbox {

using Clock = std::chrono::steady_clock;
using TimePoint = Clock::time_point;
using module::Principal;
using Jobs = std::vector<std::unique_ptr<Job>>;

// The two clocks the table works with: steady time for rings, rate windows
// and retention, and the host's wall clock for what the disk records.
struct Now final {
    TimePoint steady{};
    std::int64_t unix_seconds{0};

    // Whole minutes and days since 1970-01-01 00:00 UTC, rounded down.
    [[nodiscard]] std::uint32_t minute() const noexcept;
    [[nodiscard]] std::uint32_t day() const noexcept;
};

// The cryptographic source of item IDs.
class RandomSource {
public:
    virtual ~RandomSource() = default;
    // Fills every byte of out, or returns false. A false return leaves the
    // contents unspecified, and the caller uses nothing from them.
    [[nodiscard]] virtual bool fill(std::span<std::uint8_t> out) noexcept = 0;
};

// The kernel's random source through getrandom(2).
class SystemRandom final : public RandomSource {
public:
    [[nodiscard]] bool fill(std::span<std::uint8_t> out) noexcept override;
};

struct DepositOutcome final {
    Status status{Status::Later};
    ItemId id{};
    std::uint32_t granted_seconds{0U};
    // A message's write job was appended. Its reply waits for the job.
    bool waits_for_write{false};
};

// One item to push to a stream.
struct Delivery final {
    ItemHead head;
    // A message's on-disk name. Unused for a ring.
    MessageName name;
    // A ring's sealed bytes, valid until the table next changes. Null for a
    // message.
    const std::byte* ring_bytes{nullptr};
    std::uint64_t sequence{0U};
};

struct TableCounts final {
    std::size_t streams{0U};
    std::size_t principals{0U};
    std::size_t inboxes{0U};
    std::size_t messages{0U};
    std::size_t rings{0U};
    std::uint64_t store_bytes{0U};
    std::uint64_t ring_bytes{0U};
    std::uint64_t taken{0U};
    std::uint64_t expired_messages{0U};
    std::uint64_t expired_rings{0U};
    std::uint64_t ended_inboxes{0U};
    std::uint64_t lost_messages{0U};
};

class MailboxTable final {
public:
    MailboxTable(const Limits& limits, RandomSource& random);

    MailboxTable(const MailboxTable&) = delete;
    MailboxTable& operator=(const MailboxTable&) = delete;

    // Adds a registration the startup scan found, its messages in deposit
    // order. False, adding nothing, when one of its item IDs is already in
    // the table, which a store this service wrote never holds.
    [[nodiscard]] bool import(LoadedInbox&& inbox);

    // Counts one more stream for principal, creating its entry when absent.
    // False refuses it: the principal holds its stream quota, or the table is
    // full of principals that may not yet be forgotten.
    [[nodiscard]] bool add_stream(StreamId stream, const Principal& principal,
                                  TimePoint now);
    // Ends every subscription of the stream and releases its count.
    void remove_stream(StreamId stream) noexcept;

    // Counts one OPEN or CLOSE, or one DEPOSIT, in the stream principal's
    // rolling window. False, counting nothing, when the window is full.
    [[nodiscard]] bool count_inbox_change(StreamId stream, TimePoint now);
    [[nodiscard]] bool count_deposit(StreamId stream, TimePoint now);

    // OPEN, first half: starts registering each address that has none, when
    // the principal and the service have room. True when the reply must wait
    // for every job appended so far, because a registration this OPEN names
    // is not yet stored.
    [[nodiscard]] bool begin_open(StreamId stream,
                                  std::span<const Address> addresses,
                                  const Now& now, Jobs& work);
    // OPEN, second half: one status per address, renewing, charging and
    // subscribing each open inbox.
    void finish_open(StreamId stream, std::span<const Address> addresses,
                     const Now& now, std::span<Status> statuses, Jobs& work);
    // A creation job finished.
    void inbox_created(const Address& address, std::uint64_t generation,
                       bool stored);

    // CLOSE. True when a close job was appended and the reply waits for it.
    [[nodiscard]] bool close(const Address& address, Jobs& work);

    // DEPOSIT, after the loop counted it. A message's sealed bytes are
    // copied into its write job.
    [[nodiscard]] DepositOutcome deposit(const DepositRequest& request,
                                         const Now& now, Jobs& work);
    // A write job finished. True when the message was stored.
    bool message_written(const Job& job);

    // TAKEN: forgets the named items of inboxes the stream holds open.
    void take(StreamId stream, const TakenRequest& request, Jobs& work);

    // The next item for the stream, round robin across its inboxes, oldest
    // first in each. Moves the stream past it.
    [[nodiscard]] std::optional<Delivery> next_delivery(StreamId stream,
                                                        const Now& now);
    // A message whose file is gone or damaged. Forgets it.
    void drop_message(const Address& address, std::uint64_t sequence,
                      Jobs& work);

    // Removes rings, messages and registrations whose time ended, and
    // forgets principals whose retention ended.
    void expire(const Now& now, Jobs& work);
    // The earliest steady deadline: a ring or a principal's retention.
    [[nodiscard]] std::optional<TimePoint> next_deadline() const noexcept;
    // The earliest wall-clock deadline, in Unix seconds: a message's expiry
    // or a registration's end.
    [[nodiscard]] std::optional<std::int64_t> next_wall_deadline()
        const noexcept;

    // Streams that gained deliveries since the last call.
    void take_woken(std::vector<StreamId>& out);

    [[nodiscard]] TableCounts counts() const noexcept;

private:
    // The newest-last timestamps of one rolling window, at most N of them.
    template <std::size_t N>
    struct Window final {
        std::array<TimePoint, N> times{};
        std::size_t size{0U};

        void prune(TimePoint now, Clock::duration window) noexcept;
        [[nodiscard]] std::optional<TimePoint> newest() const noexcept;
    };

    struct PrincipalState final {
        std::size_t streams{0U};
        // Registrations charged to this principal.
        std::size_t inboxes{0U};
        Window<kMaxDepositsPerWindow> deposits;
        Window<kMaxInboxChangesPerWindow> changes;
        // When this idle principal may be forgotten, while it is queued in
        // idle_.
        std::optional<TimePoint> retained_until;
    };

    struct StoredItem final {
        // A message's place in the store's deposit order.
        std::uint64_t order{0U};
        ItemId id{};
        ItemClass item_class{ItemClass::Message};
        std::uint32_t size{0U};
        std::uint32_t deposit_minute{0U};
        // A message's expiry, in Unix minutes.
        std::uint32_t expiry_minute{0U};
        // A ring's expiry and sealed bytes.
        TimePoint ring_deadline{};
        std::unique_ptr<std::byte[]> ring_bytes;
    };

    struct Inbox final {
        std::uint64_t generation{0U};
        // The creation is stored. Until then deposits find no inbox.
        bool registered{false};
        // The registration ends at 00:00 UTC on this day.
        std::uint32_t day{0U};
        // The day the newest creation or renewal job writes.
        std::uint32_t stored_day{0U};
        std::optional<Principal> charged;
        std::optional<StreamId> subscriber;
        // By sequence, so delivery order is deposit order.
        std::map<std::uint64_t, StoredItem> items;
        std::size_t messages{0U};
        std::size_t rings{0U};
        std::uint64_t sealed_bytes{0U};
        // Messages being written: counted against the inbox's quota.
        std::size_t writing{0U};
        std::uint64_t writing_bytes{0U};
    };

    struct Subscription final {
        // The sequence the next delivery starts from.
        std::uint64_t next{0U};
        // Queued in the stream's due list.
        bool due{false};
    };

    struct StreamState final {
        Principal principal{};
        std::map<Address, Subscription> subscriptions;
        // Inboxes with items this stream has not yet received, round robin.
        std::deque<Address> due;
        bool woken{false};
    };

    struct ItemRef final {
        Address address{};
        std::uint64_t generation{0U};
        // 0 while the message is being written.
        std::uint64_t sequence{0U};
    };

    struct IdHash final {
        std::size_t operator()(const ItemId& id) const noexcept;
    };

    using Principals = std::map<Principal, PrincipalState>;
    using Inboxes = std::map<Address, Inbox>;

    PrincipalState& principal_of(StreamId stream);
    void charge(Inbox& inbox, const Principal& principal);
    void uncharge(Inbox& inbox) noexcept;
    void maybe_idle(Principals::iterator principal) noexcept;
    void forget_principals(TimePoint now, bool full_scan) noexcept;

    void subscribe(StreamId stream, const Address& address, Inbox& inbox);
    void unsubscribe(StreamId stream, const Address& address) noexcept;
    void mark_due(const Address& address, const Inbox& inbox);
    void wake(StreamId stream, StreamState& state);

    void remove_item(Inbox& inbox,
                     std::map<std::uint64_t, StoredItem>::iterator item,
                     const Address& address, Jobs& work);
    void remove_inbox(Inboxes::iterator inbox, Jobs& work);
    [[nodiscard]] std::optional<ItemId> new_item_id() noexcept;

    const Limits limits_;
    RandomSource& random_;
    Principals principals_;
    std::set<std::pair<TimePoint, Principal>> idle_;
    std::map<StreamId, StreamState> streams_;
    Inboxes inboxes_;
    std::unordered_map<ItemId, ItemRef, IdHash> ids_;
    std::set<std::pair<std::uint32_t, ItemId>> message_expiries_;
    std::set<std::pair<TimePoint, ItemId>> ring_expiries_;
    std::set<std::pair<std::uint32_t, Address>> registration_ends_;
    std::vector<StreamId> woken_;
    std::uint64_t next_generation_{1U};
    std::uint64_t next_sequence_{1U};
    // The next message's place in the store's deposit order, above every one
    // on disk.
    std::uint64_t next_order_{1U};
    // Registrations and messages, stored or being written, in whole blocks.
    std::uint64_t store_used_{0U};
    std::uint64_t ring_bytes_{0U};
    std::size_t messages_{0U};
    std::size_t rings_{0U};
    std::uint64_t taken_{0U};
    std::uint64_t expired_messages_{0U};
    std::uint64_t expired_rings_{0U};
    std::uint64_t ended_inboxes_{0U};
    std::uint64_t lost_messages_{0U};
};

}  // namespace ito::mailbox
