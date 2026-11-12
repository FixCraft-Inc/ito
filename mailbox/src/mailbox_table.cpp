/* Copyright (C) 2026 FixCraft Inc. AGPL-3.0-or-later. */

#include "mailbox_table.hpp"

#include <sys/random.h>

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <new>

namespace ito::mailbox {
namespace {

constexpr std::int64_t kSecondsPerDay = 86'400;
// A clash between two random 16-byte IDs is not expected, so a second one
// means the random source is broken.
constexpr int kIdAttempts = 2;

std::unique_ptr<Job> make_job(Job::Kind kind, const Address& address) {
    auto job = std::make_unique<Job>();
    job->kind = kind;
    job->address = address;
    return job;
}

}  // namespace

std::uint32_t Now::minute() const noexcept {
    return static_cast<std::uint32_t>(std::max<std::int64_t>(unix_seconds, 0) /
                                      60);
}

std::uint32_t Now::day() const noexcept {
    return static_cast<std::uint32_t>(std::max<std::int64_t>(unix_seconds, 0) /
                                      kSecondsPerDay);
}

bool SystemRandom::fill(std::span<std::uint8_t> out) noexcept {
    while (!out.empty()) {
        const ssize_t got = ::getrandom(out.data(), out.size(), 0);
        if (got < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        out = out.subspan(static_cast<std::size_t>(got));
    }
    return true;
}

std::size_t MailboxTable::IdHash::operator()(const ItemId& id) const noexcept {
    // IDs come from the random source, so any eight of their bytes are
    // already uniform.
    std::size_t value = 0U;
    std::memcpy(&value, id.data(), sizeof value);
    return value;
}

template <std::size_t N>
void MailboxTable::Window<N>::prune(TimePoint now,
                                    Clock::duration window) noexcept {
    std::size_t kept = 0U;
    for (std::size_t index = 0U; index < size; ++index)
        if (now - times[index] < window) times[kept++] = times[index];
    size = kept;
}

template <std::size_t N>
std::optional<TimePoint> MailboxTable::Window<N>::newest() const noexcept {
    if (size == 0U) return std::nullopt;
    return times[size - 1U];
}

MailboxTable::MailboxTable(const Limits& limits, RandomSource& random)
    : limits_(limits), random_(random) {}

// Principals.

bool MailboxTable::add_stream(StreamId stream, const Principal& principal,
                              TimePoint now) {
    auto found = principals_.find(principal);
    if (found == principals_.end()) {
        if (principals_.size() >= limits_.max_principals)
            forget_principals(now, true);
        if (principals_.size() >= limits_.max_principals) return false;
        found = principals_.emplace(principal, PrincipalState{}).first;
    }
    PrincipalState& state = found->second;
    if (state.streams >= limits_.max_streams_per_principal) return false;
    try {
        streams_.emplace(stream, StreamState{principal, {}, {}, false});
    } catch (...) {
        maybe_idle(found);
        throw;
    }
    if (state.retained_until) {
        idle_.erase({*state.retained_until, principal});
        state.retained_until.reset();
    }
    ++state.streams;
    return true;
}

void MailboxTable::remove_stream(StreamId stream) noexcept {
    const auto found = streams_.find(stream);
    if (found == streams_.end()) return;
    for (const auto& [address, subscription] : found->second.subscriptions) {
        const auto inbox = inboxes_.find(address);
        if (inbox != inboxes_.end() && inbox->second.subscriber == stream)
            inbox->second.subscriber.reset();
    }
    const Principal principal = found->second.principal;
    streams_.erase(found);
    const auto state = principals_.find(principal);
    if (state == principals_.end()) return;
    --state->second.streams;
    maybe_idle(state);
}

MailboxTable::PrincipalState& MailboxTable::principal_of(StreamId stream) {
    return principals_.at(streams_.at(stream).principal);
}

bool MailboxTable::count_inbox_change(StreamId stream, TimePoint now) {
    auto& window = principal_of(stream).changes;
    window.prune(now, limits_.rate_window);
    if (window.size == window.times.size()) return false;
    window.times[window.size++] = now;
    return true;
}

bool MailboxTable::count_deposit(StreamId stream, TimePoint now) {
    auto& window = principal_of(stream).deposits;
    window.prune(now, limits_.rate_window);
    if (window.size == window.times.size()) return false;
    window.times[window.size++] = now;
    return true;
}

void MailboxTable::charge(Inbox& inbox, const Principal& principal) {
    uncharge(inbox);
    auto& state = principals_.at(principal);
    inbox.charged = principal;
    ++state.inboxes;
}

void MailboxTable::uncharge(Inbox& inbox) noexcept {
    if (!inbox.charged) return;
    const auto state = principals_.find(*inbox.charged);
    inbox.charged.reset();
    if (state == principals_.end()) return;
    --state->second.inboxes;
    maybe_idle(state);
}

// A principal with no stream and no registration is kept until its newest
// counted frame leaves the rate window, so a reconnect cannot reset a quota.
void MailboxTable::maybe_idle(Principals::iterator principal) noexcept {
    PrincipalState& state = principal->second;
    if (state.streams != 0U || state.inboxes != 0U || state.retained_until)
        return;
    std::optional<TimePoint> newest = state.deposits.newest();
    if (const auto changed = state.changes.newest())
        newest = newest ? std::max(*newest, *changed) : changed;
    if (!newest) {
        principals_.erase(principal);
        return;
    }
    const TimePoint until = *newest + limits_.rate_window;
    state.retained_until = until;
    try {
        idle_.emplace(until, principal->first);
    } catch (const std::bad_alloc&) {
        // Without its queue entry the principal stays until a full scan
        // finds it, which only lengthens its retention.
    }
}

void MailboxTable::forget_principals(TimePoint now, bool full_scan) noexcept {
    while (!idle_.empty() && idle_.begin()->first <= now) {
        const Principal principal = idle_.begin()->second;
        idle_.erase(idle_.begin());
        const auto found = principals_.find(principal);
        if (found != principals_.end() && found->second.retained_until &&
            *found->second.retained_until <= now)
            principals_.erase(found);
    }
    if (!full_scan) return;
    for (auto found = principals_.begin(); found != principals_.end();) {
        const auto& state = found->second;
        if (state.streams == 0U && state.inboxes == 0U &&
            state.retained_until && *state.retained_until <= now) {
            idle_.erase({*state.retained_until, found->first});
            found = principals_.erase(found);
        } else {
            ++found;
        }
    }
}

// Startup.

bool MailboxTable::import(LoadedInbox&& loaded) {
    // The scan lists files in directory order. Sequences follow deposits.
    std::sort(loaded.messages.begin(), loaded.messages.end(),
              [](const LoadedMessage& left, const LoadedMessage& right) {
                  return left.name.order < right.name.order;
              });
    Inbox inbox;
    inbox.generation = next_generation_++;
    inbox.registered = true;
    inbox.day = loaded.registration_day;
    inbox.stored_day = loaded.registration_day;
    std::vector<const MessageName*> added;
    added.reserve(loaded.messages.size());
    const auto forget_added = [&]() noexcept {
        for (const MessageName* name : added) {
            ids_.erase(name->id);
            message_expiries_.erase({name->expiry_minute, name->id});
        }
    };
    try {
        for (const auto& message : loaded.messages) {
            const std::uint64_t sequence = next_sequence_++;
            if (!ids_.emplace(
                         message.name.id,
                         ItemRef{loaded.address, inbox.generation, sequence})
                     .second) {
                forget_added();
                return false;
            }
            added.push_back(&message.name);
            StoredItem item;
            item.order = message.name.order;
            item.id = message.name.id;
            item.item_class = ItemClass::Message;
            item.size = message.size;
            item.deposit_minute = message.name.deposit_minute;
            item.expiry_minute = message.name.expiry_minute;
            inbox.items.emplace(sequence, std::move(item));
            message_expiries_.emplace(message.name.expiry_minute,
                                      message.name.id);
            ++inbox.messages;
            inbox.sealed_bytes += message.size;
        }
        registration_ends_.emplace(inbox.day, loaded.address);
        inboxes_.emplace(loaded.address, std::move(inbox));
    } catch (...) {
        forget_added();
        throw;
    }
    for (const auto& message : loaded.messages) {
        store_used_ += blocks_for(message.size);
        next_order_ = std::max(next_order_, message.name.order + 1U);
    }
    store_used_ += kBlockBytes;
    messages_ += loaded.messages.size();
    return true;
}

// Opening.

bool MailboxTable::begin_open(StreamId stream,
                              std::span<const Address> addresses,
                              const Now& now, Jobs& work) {
    const Principal principal = streams_.at(stream).principal;
    PrincipalState& state = principals_.at(principal);
    bool waits = false;
    for (const Address& address : addresses) {
        const auto found = inboxes_.find(address);
        if (found != inboxes_.end()) {
            // Another stream's creation is not yet stored.
            if (!found->second.registered) waits = true;
            continue;
        }
        if (state.inboxes >= limits_.max_inboxes_per_principal ||
            inboxes_.size() >= limits_.max_inboxes ||
            store_used_ + kBlockBytes > limits_.store_bytes)
            continue;
        auto job = make_job(Job::Kind::CreateInbox, address);
        job->generation = next_generation_;
        job->day = now.day() + limits_.registration_days;
        work.reserve(work.size() + 1U);
        Inbox inbox;
        inbox.generation = next_generation_;
        inbox.day = job->day;
        inbox.stored_day = job->day;
        const auto created = inboxes_.emplace(address, std::move(inbox)).first;
        ++next_generation_;
        charge(created->second, principal);
        store_used_ += kBlockBytes;
        work.push_back(std::move(job));
        waits = true;
    }
    return waits;
}

void MailboxTable::inbox_created(const Address& address,
                                 std::uint64_t generation, bool stored) {
    const auto found = inboxes_.find(address);
    // A close since then released everything this creation held.
    if (found == inboxes_.end() || found->second.generation != generation)
        return;
    Inbox& inbox = found->second;
    if (stored) {
        registration_ends_.emplace(inbox.day, address);
        inbox.registered = true;
        return;
    }
    uncharge(inbox);
    store_used_ -= kBlockBytes;
    inboxes_.erase(found);
}

void MailboxTable::finish_open(StreamId stream,
                               std::span<const Address> addresses,
                               const Now& now, std::span<Status> statuses,
                               Jobs& work) {
    const Principal principal = streams_.at(stream).principal;
    for (std::size_t index = 0U; index < addresses.size(); ++index) {
        const Address& address = addresses[index];
        const PrincipalState& state = principals_.at(principal);
        const bool at_quota =
            state.inboxes >= limits_.max_inboxes_per_principal;
        const auto found = inboxes_.find(address);
        if (found == inboxes_.end() || !found->second.registered) {
            statuses[index] = at_quota ? Status::NotHere : Status::Later;
            continue;
        }
        Inbox& inbox = found->second;
        if (inbox.charged != principal) {
            if (at_quota) {
                statuses[index] = Status::NotHere;
                continue;
            }
            charge(inbox, principal);
        }
        const std::uint32_t day = now.day() + limits_.registration_days;
        if (day > inbox.day) {
            if (day != inbox.stored_day) {
                auto job = make_job(Job::Kind::RenewRegistration, address);
                job->day = day;
                work.push_back(std::move(job));
                inbox.stored_day = day;
            }
            registration_ends_.erase({inbox.day, address});
            inbox.day = day;
            registration_ends_.emplace(day, address);
        }
        subscribe(stream, address, inbox);
        statuses[index] = Status::Done;
    }
}

void MailboxTable::subscribe(StreamId stream, const Address& address,
                             Inbox& inbox) {
    if (inbox.subscriber && *inbox.subscriber != stream)
        unsubscribe(*inbox.subscriber, address);
    StreamState& state = streams_.at(stream);
    Subscription& subscription = state.subscriptions[address];
    inbox.subscriber = stream;
    // Each OPEN starts the inbox's delivery over from its oldest item.
    subscription.next = 0U;
    if (!inbox.items.empty() && !subscription.due) {
        state.due.push_back(address);
        subscription.due = true;
        wake(stream, state);
    }
}

void MailboxTable::unsubscribe(StreamId stream,
                               const Address& address) noexcept {
    const auto found = streams_.find(stream);
    if (found == streams_.end()) return;
    StreamState& state = found->second;
    const auto subscription = state.subscriptions.find(address);
    if (subscription == state.subscriptions.end()) return;
    if (subscription->second.due) {
        const auto queued =
            std::find(state.due.begin(), state.due.end(), address);
        if (queued != state.due.end()) state.due.erase(queued);
    }
    state.subscriptions.erase(subscription);
}

void MailboxTable::mark_due(const Address& address, const Inbox& inbox) {
    if (!inbox.subscriber) return;
    const StreamId stream = *inbox.subscriber;
    StreamState& state = streams_.at(stream);
    Subscription& subscription = state.subscriptions.at(address);
    if (!subscription.due) {
        state.due.push_back(address);
        subscription.due = true;
    }
    wake(stream, state);
}

void MailboxTable::wake(StreamId stream, StreamState& state) {
    if (state.woken) return;
    woken_.push_back(stream);
    state.woken = true;
}

void MailboxTable::take_woken(std::vector<StreamId>& out) {
    out.clear();
    out.swap(woken_);
    for (const StreamId stream : out) {
        const auto found = streams_.find(stream);
        if (found != streams_.end()) found->second.woken = false;
    }
}

// Closing and removing.

bool MailboxTable::close(const Address& address, Jobs& work) {
    const auto found = inboxes_.find(address);
    if (found == inboxes_.end()) return false;
    work.reserve(work.size() + found->second.items.size() + 1U);
    remove_inbox(found, work);
    return true;
}

void MailboxTable::remove_item(
    Inbox& inbox, std::map<std::uint64_t, StoredItem>::iterator item,
    const Address& address, Jobs& work) {
    StoredItem& stored = item->second;
    std::unique_ptr<Job> job;
    if (stored.item_class == ItemClass::Message) {
        job = make_job(Job::Kind::DeleteMessage, address);
        job->message = {stored.order, stored.id, stored.deposit_minute,
                        stored.expiry_minute};
        work.reserve(work.size() + 1U);
        message_expiries_.erase({stored.expiry_minute, stored.id});
        store_used_ -= blocks_for(stored.size);
        --inbox.messages;
        --messages_;
    } else {
        ring_expiries_.erase({stored.ring_deadline, stored.id});
        ::explicit_bzero(stored.ring_bytes.get(), stored.size);
        ring_bytes_ -= stored.size;
        --inbox.rings;
        --rings_;
    }
    inbox.sealed_bytes -= stored.size;
    ids_.erase(stored.id);
    inbox.items.erase(item);
    if (job) work.push_back(std::move(job));
}

void MailboxTable::remove_inbox(Inboxes::iterator found, Jobs& work) {
    const Address address = found->first;
    Inbox& inbox = found->second;
    auto job = make_job(Job::Kind::CloseInbox, address);
    work.reserve(work.size() + 1U);
    if (inbox.subscriber) unsubscribe(*inbox.subscriber, address);
    uncharge(inbox);
    for (auto& [sequence, item] : inbox.items) {
        if (item.item_class == ItemClass::Message) {
            message_expiries_.erase({item.expiry_minute, item.id});
            store_used_ -= blocks_for(item.size);
            --messages_;
        } else {
            ring_expiries_.erase({item.ring_deadline, item.id});
            ::explicit_bzero(item.ring_bytes.get(), item.size);
            ring_bytes_ -= item.size;
            --rings_;
        }
        ids_.erase(item.id);
    }
    // Messages still being written keep their reservation until their jobs
    // return, and the close job, queued after them, removes their files.
    store_used_ -= kBlockBytes;
    if (inbox.registered) registration_ends_.erase({inbox.day, address});
    inboxes_.erase(found);
    work.push_back(std::move(job));
}

// Depositing.

std::optional<ItemId> MailboxTable::new_item_id() noexcept {
    for (int attempt = 0; attempt < kIdAttempts; ++attempt) {
        ItemId id{};
        if (!random_.fill(id)) return std::nullopt;
        if (!ids_.contains(id)) return id;
    }
    return std::nullopt;
}

DepositOutcome MailboxTable::deposit(const DepositRequest& request,
                                     const Now& now, Jobs& work) {
    const auto found = inboxes_.find(request.address);
    // Unknown, not yet stored, ended and full all answer the same, after the
    // same lookups.
    if (found == inboxes_.end() || !found->second.registered ||
        found->second.day <= now.day())
        return {Status::NotHere, {}, 0U, false};
    Inbox& inbox = found->second;
    const auto size = static_cast<std::uint32_t>(request.sealed.size());
    const bool ring = request.item_class == ItemClass::Ring;
    if (inbox.items.size() + inbox.writing >= limits_.max_items_per_inbox ||
        inbox.sealed_bytes + inbox.writing_bytes + size >
            limits_.max_bytes_per_inbox ||
        (ring && inbox.rings >= limits_.max_rings_per_inbox))
        return {Status::NotHere, {}, 0U, false};
    if (ring ? ring_bytes_ + size > limits_.max_ring_bytes
             : store_used_ + blocks_for(size) > limits_.store_bytes)
        return {Status::Later, {}, 0U, false};
    const auto id = new_item_id();
    if (!id) return {Status::Later, {}, 0U, false};
    const auto cap = static_cast<std::uint32_t>(
        (ring ? limits_.ring_lifetime : limits_.hold_time).count());
    const std::uint32_t granted = std::min(request.lifetime_seconds, cap);

    if (ring) {
        std::unique_ptr<std::byte[]> bytes(new (std::nothrow) std::byte[size]);
        if (!bytes) return {Status::Later, {}, 0U, false};
        std::memcpy(bytes.get(), request.sealed.data(), size);
        const std::uint64_t sequence = next_sequence_;
        StoredItem item;
        item.id = *id;
        item.item_class = ItemClass::Ring;
        item.size = size;
        item.deposit_minute = now.minute();
        item.ring_deadline = now.steady + std::chrono::seconds(granted);
        item.ring_bytes = std::move(bytes);
        const TimePoint deadline = item.ring_deadline;
        ids_.emplace(*id, ItemRef{request.address, inbox.generation, sequence});
        try {
            ring_expiries_.emplace(deadline, *id);
            inbox.items.emplace(sequence, std::move(item));
        } catch (...) {
            ring_expiries_.erase({deadline, *id});
            ids_.erase(*id);
            throw;
        }
        ++next_sequence_;
        ++inbox.rings;
        ++rings_;
        inbox.sealed_bytes += size;
        ring_bytes_ += size;
        mark_due(request.address, inbox);
        return {Status::Done, *id, granted, false};
    }

    auto job = make_job(Job::Kind::WriteMessage, request.address);
    job->generation = inbox.generation;
    job->message.order = next_order_;
    job->message.id = *id;
    job->message.deposit_minute = now.minute();
    // Rounded up, so the message lives at least its granted lifetime.
    job->message.expiry_minute = static_cast<std::uint32_t>(
        (std::max<std::int64_t>(now.unix_seconds, 0) + granted + 59) / 60);
    job->sealed.reset(new std::byte[size]);
    std::memcpy(job->sealed.get(), request.sealed.data(), size);
    job->sealed_bytes = size;
    work.reserve(work.size() + 1U);
    ids_.emplace(*id, ItemRef{request.address, inbox.generation, 0U});
    ++next_order_;
    ++inbox.writing;
    inbox.writing_bytes += size;
    store_used_ += blocks_for(size);
    work.push_back(std::move(job));
    return {Status::Done, *id, granted, true};
}

bool MailboxTable::message_written(const Job& job) {
    const auto size = static_cast<std::uint32_t>(job.sealed_bytes);
    const bool stored = job.result == IoResult::Ok;
    store_used_ -= blocks_for(size);
    const auto found = inboxes_.find(job.address);
    const bool same =
        found != inboxes_.end() && found->second.generation == job.generation;
    if (same) {
        --found->second.writing;
        found->second.writing_bytes -= size;
    }
    const auto ref = ids_.find(job.message.id);
    if (!stored || !same) {
        // Refused, or written into an inbox that was closed since. That
        // close's job, queued after this write, removed the file.
        if (ref != ids_.end()) ids_.erase(ref);
        return stored;
    }
    Inbox& inbox = found->second;
    const std::uint64_t sequence = next_sequence_;
    StoredItem item;
    item.order = job.message.order;
    item.id = job.message.id;
    item.item_class = ItemClass::Message;
    item.size = size;
    item.deposit_minute = job.message.deposit_minute;
    item.expiry_minute = job.message.expiry_minute;
    message_expiries_.emplace(item.expiry_minute, item.id);
    try {
        inbox.items.emplace(sequence, std::move(item));
    } catch (...) {
        message_expiries_.erase({job.message.expiry_minute, job.message.id});
        throw;
    }
    ++next_sequence_;
    ref->second.sequence = sequence;
    ++inbox.messages;
    ++messages_;
    inbox.sealed_bytes += size;
    store_used_ += blocks_for(size);
    mark_due(job.address, inbox);
    return true;
}

// Taking and delivering.

void MailboxTable::take(StreamId stream, const TakenRequest& request,
                        Jobs& work) {
    const StreamState& state = streams_.at(stream);
    for (std::size_t index = 0U; index < request.count(); ++index) {
        const auto ref = ids_.find(request.id(index));
        if (ref == ids_.end() || ref->second.sequence == 0U ||
            !state.subscriptions.contains(ref->second.address))
            continue;
        const Address address = ref->second.address;
        const std::uint64_t sequence = ref->second.sequence;
        const auto inbox = inboxes_.find(address);
        if (inbox == inboxes_.end() || inbox->second.subscriber != stream)
            continue;
        const auto item = inbox->second.items.find(sequence);
        if (item == inbox->second.items.end()) continue;
        remove_item(inbox->second, item, address, work);
        ++taken_;
    }
}

std::optional<Delivery> MailboxTable::next_delivery(StreamId stream,
                                                    const Now& now) {
    StreamState& state = streams_.at(stream);
    while (!state.due.empty()) {
        const Address address = state.due.front();
        Subscription& subscription = state.subscriptions.at(address);
        const Inbox& inbox = inboxes_.at(address);
        const auto item = inbox.items.lower_bound(subscription.next);
        state.due.pop_front();
        if (item == inbox.items.end()) {
            subscription.due = false;
            continue;
        }
        // Round robin: the inbox goes to the back with its remaining items.
        state.due.push_back(address);
        subscription.next = item->first + 1U;
        const StoredItem& stored = item->second;
        Delivery delivery;
        delivery.head.item_class = stored.item_class;
        delivery.head.address = address;
        delivery.head.id = stored.id;
        delivery.head.deposit_minute = stored.deposit_minute;
        delivery.head.sealed_bytes = stored.size;
        delivery.sequence = item->first;
        if (stored.item_class == ItemClass::Ring) {
            const auto left = std::chrono::duration_cast<std::chrono::seconds>(
                stored.ring_deadline - now.steady);
            delivery.head.seconds_left = static_cast<std::uint32_t>(
                std::max<std::int64_t>(left.count(), 0));
            delivery.ring_bytes = stored.ring_bytes.get();
        } else {
            const std::int64_t left =
                static_cast<std::int64_t>(stored.expiry_minute) * 60 -
                now.unix_seconds;
            delivery.head.seconds_left = static_cast<std::uint32_t>(
                std::clamp<std::int64_t>(left, 0, UINT32_MAX));
            delivery.name = {stored.order, stored.id, stored.deposit_minute,
                             stored.expiry_minute};
        }
        return delivery;
    }
    return std::nullopt;
}

void MailboxTable::drop_message(const Address& address, std::uint64_t sequence,
                                Jobs& work) {
    const auto inbox = inboxes_.find(address);
    if (inbox == inboxes_.end()) return;
    const auto item = inbox->second.items.find(sequence);
    if (item == inbox->second.items.end()) return;
    remove_item(inbox->second, item, address, work);
    ++lost_messages_;
}

// Time.

void MailboxTable::expire(const Now& now, Jobs& work) {
    const auto remove_by_id = [&](const ItemId& id) {
        const auto ref = ids_.find(id);
        if (ref == ids_.end()) return;
        const Address address = ref->second.address;
        const auto inbox = inboxes_.find(address);
        if (inbox == inboxes_.end()) return;
        const auto item = inbox->second.items.find(ref->second.sequence);
        if (item != inbox->second.items.end())
            remove_item(inbox->second, item, address, work);
    };
    while (!ring_expiries_.empty() &&
           ring_expiries_.begin()->first <= now.steady) {
        const ItemId id = ring_expiries_.begin()->second;
        ring_expiries_.erase(ring_expiries_.begin());
        remove_by_id(id);
        ++expired_rings_;
    }
    while (!message_expiries_.empty() &&
           message_expiries_.begin()->first <= now.minute()) {
        const ItemId id = message_expiries_.begin()->second;
        message_expiries_.erase(message_expiries_.begin());
        remove_by_id(id);
        ++expired_messages_;
    }
    while (!registration_ends_.empty() &&
           registration_ends_.begin()->first <= now.day()) {
        const Address address = registration_ends_.begin()->second;
        registration_ends_.erase(registration_ends_.begin());
        const auto inbox = inboxes_.find(address);
        if (inbox == inboxes_.end()) continue;
        remove_inbox(inbox, work);
        ++ended_inboxes_;
    }
    forget_principals(now.steady, false);
}

std::optional<TimePoint> MailboxTable::next_deadline() const noexcept {
    std::optional<TimePoint> next;
    if (!ring_expiries_.empty()) next = ring_expiries_.begin()->first;
    if (!idle_.empty())
        next =
            next ? std::min(*next, idle_.begin()->first) : idle_.begin()->first;
    return next;
}

std::optional<std::int64_t> MailboxTable::next_wall_deadline() const noexcept {
    std::optional<std::int64_t> next;
    if (!message_expiries_.empty())
        next = static_cast<std::int64_t>(message_expiries_.begin()->first) * 60;
    if (!registration_ends_.empty()) {
        const std::int64_t end =
            static_cast<std::int64_t>(registration_ends_.begin()->first) *
            kSecondsPerDay;
        next = next ? std::min(*next, end) : end;
    }
    return next;
}

TableCounts MailboxTable::counts() const noexcept {
    TableCounts counts;
    counts.streams = streams_.size();
    counts.principals = principals_.size();
    counts.inboxes = inboxes_.size();
    counts.messages = messages_;
    counts.rings = rings_;
    counts.store_bytes = store_used_;
    counts.ring_bytes = ring_bytes_;
    counts.taken = taken_;
    counts.expired_messages = expired_messages_;
    counts.expired_rings = expired_rings_;
    counts.ended_inboxes = ended_inboxes_;
    counts.lost_messages = lost_messages_;
    return counts;
}

}  // namespace ito::mailbox
