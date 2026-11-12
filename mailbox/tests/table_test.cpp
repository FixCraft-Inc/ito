/* Copyright (C) 2026 FixCraft Inc. AGPL-3.0-or-later. */

// The policy table on virtual time: registration, deposits and their checks,
// delivery order, subscriptions, taking, quotas, rate windows, principal
// retention and every expiry. Expected values come from docs/MAILBOX.md.

#include "mailbox_table.hpp"

#include <algorithm>
#include <cstdio>
#include <vector>

#include "check.hpp"

namespace {

using namespace ito::mailbox;
using namespace std::chrono_literals;

// 2027-01-15 08:00 UTC: a whole minute, not a whole day.
constexpr std::int64_t kBase = 1'800'000'000;
static_assert(kBase % 60 == 0);

// IDs from a counter, so tests can predict them. fail and repeat break it.
class CountingRandom final : public RandomSource {
public:
    bool fill(std::span<std::uint8_t> out) noexcept override {
        if (fail) return false;
        std::fill(out.begin(), out.end(), std::uint8_t{0});
        for (std::size_t index = 0U; index < 8U && index < out.size(); ++index)
            out[index] = static_cast<std::uint8_t>(next >> (8U * index));
        if (!repeat) ++next;
        return true;
    }
    std::uint64_t next{1U};
    bool fail{false};
    bool repeat{false};
};

Now at(std::chrono::milliseconds offset) {
    return {
        TimePoint{} + 1h + offset,
        kBase +
            std::chrono::duration_cast<std::chrono::seconds>(offset).count()};
}

Principal principal(std::uint8_t label) {
    Principal out{};
    out.fill(label);
    return out;
}

Address address(std::uint8_t label) {
    Address out{};
    out.fill(label);
    out[0] = 0xadU;
    return out;
}

const std::vector<std::byte>& sealed_bytes() {
    static const std::vector<std::byte> bytes = [] {
        std::vector<std::byte> out(kLargeItemBytes);
        for (std::size_t index = 0U; index < out.size(); ++index)
            out[index] = static_cast<std::byte>(index * 31U + 7U);
        return out;
    }();
    return bytes;
}

DepositRequest deposit_of(const Address& to, ItemClass item_class,
                          std::size_t size = kSmallItemBytes,
                          std::uint32_t lifetime = 3600U) {
    DepositRequest request;
    request.address = to;
    request.item_class = item_class;
    request.lifetime_seconds = lifetime;
    request.sealed = std::span(sealed_bytes()).first(size);
    return request;
}

// One table with its random source and the job list the loop would submit.
struct Fixture final {
    explicit Fixture(const Limits& limits = Limits{}) : table(limits, random) {}

    // Registers address for stream as a stored OPEN would.
    void register_inbox(StreamId stream, const Address& to, const Now& now) {
        const std::array<Address, 1> one{to};
        work.clear();
        CHECK(table.begin_open(stream, one, now, work));
        CHECK(work.size() == 1U && work[0]->kind == Job::Kind::CreateInbox);
        table.inbox_created(to, work[0]->generation, true);
        work.clear();
        CHECK(open(stream, one, now) == std::vector{Status::Done});
    }

    std::vector<Status> open(StreamId stream, std::span<const Address> to,
                             const Now& now) {
        std::vector<Status> statuses(to.size(), Status::Later);
        table.finish_open(stream, to, now, statuses, work);
        return statuses;
    }

    // Deposits a message and completes its write.
    ItemId store_message(const Address& to, const Now& now,
                         std::size_t size = kSmallItemBytes) {
        work.clear();
        const auto outcome =
            table.deposit(deposit_of(to, ItemClass::Message, size), now, work);
        CHECK(outcome.status == Status::Done && outcome.waits_for_write);
        CHECK(work.size() == 1U && work[0]->kind == Job::Kind::WriteMessage);
        work[0]->result = IoResult::Ok;
        CHECK(table.message_written(*work[0]));
        work.clear();
        return outcome.id;
    }

    std::vector<StreamId> woken() {
        std::vector<StreamId> out;
        table.take_woken(out);
        return out;
    }

    CountingRandom random;
    MailboxTable table;
    Jobs work;
};

TakenRequest taken_of(const std::vector<ItemId>& ids,
                      std::vector<std::byte>& storage) {
    storage.clear();
    for (const auto& id : ids)
        for (const auto byte : id) storage.push_back(std::byte{byte});
    return TakenRequest{storage};
}

void test_registration_and_delivery() {
    Fixture f;
    const Now now = at(0ms);
    CHECK(f.table.add_stream(1U, principal(1U), now.steady));
    const std::array<Address, 1> one{address(1U)};
    CHECK(f.table.begin_open(1U, one, now, f.work));
    CHECK(f.work.size() == 1U);
    CHECK(f.work[0]->kind == Job::Kind::CreateInbox);
    CHECK(f.work[0]->day == now.day() + 30U);
    // A registration is not usable before it is stored.
    Jobs ignored;
    CHECK(
        f.table
            .deposit(deposit_of(address(1U), ItemClass::Message), now, ignored)
            .status == Status::NotHere);
    CHECK(ignored.empty());
    f.table.inbox_created(address(1U), f.work[0]->generation, true);
    f.work.clear();
    CHECK(f.open(1U, one, now) == std::vector{Status::Done});
    CHECK(f.work.empty());
    CHECK(f.table.counts().inboxes == 1U);
    CHECK(f.table.counts().store_bytes == kBlockBytes);

    // A message waits for its write, then reaches the subscribed stream.
    const auto outcome = f.table.deposit(
        deposit_of(address(1U), ItemClass::Message, kMediumItemBytes, 61U), now,
        f.work);
    CHECK(outcome.status == Status::Done && outcome.waits_for_write);
    CHECK(outcome.granted_seconds == 61U);
    const Job& write = *f.work[0];
    CHECK(write.kind == Job::Kind::WriteMessage);
    CHECK(write.sealed_bytes == kMediumItemBytes);
    CHECK(std::equal(write.sealed.get(), write.sealed.get() + kMediumItemBytes,
                     sealed_bytes().begin()));
    CHECK(write.message.id == outcome.id);
    CHECK(write.message.deposit_minute == kBase / 60);
    // Rounded up to a whole minute.
    CHECK(write.message.expiry_minute == kBase / 60 + 2);
    CHECK(f.woken().empty());
    f.work[0]->result = IoResult::Ok;
    CHECK(f.table.message_written(*f.work[0]));
    f.work.clear();
    CHECK(f.woken() == std::vector<StreamId>{1U});

    const Now later = at(10s);
    const auto delivery = f.table.next_delivery(1U, later);
    CHECK(delivery.has_value());
    CHECK(delivery->head.item_class == ItemClass::Message);
    CHECK(delivery->head.address == address(1U));
    CHECK(delivery->head.id == outcome.id);
    CHECK(delivery->head.deposit_minute == kBase / 60);
    CHECK(delivery->head.seconds_left == 110U);
    CHECK(delivery->head.sealed_bytes == kMediumItemBytes);
    CHECK(delivery->ring_bytes == nullptr);
    CHECK(delivery->name.expiry_minute == kBase / 60 + 2);
    CHECK(!f.table.next_delivery(1U, later).has_value());

    // A ring is answered at once and carries its bytes.
    const auto ring = f.table.deposit(
        deposit_of(address(1U), ItemClass::Ring, kSmallItemBytes, 3600U), now,
        f.work);
    CHECK(ring.status == Status::Done && !ring.waits_for_write);
    CHECK(ring.granted_seconds == 60U);
    CHECK(f.work.empty());
    CHECK(f.woken() == std::vector<StreamId>{1U});
    const auto rung = f.table.next_delivery(1U, at(15s));
    CHECK(rung.has_value() && rung->head.item_class == ItemClass::Ring);
    CHECK(rung->head.seconds_left == 45U);
    CHECK(rung->ring_bytes != nullptr);
    CHECK(std::equal(rung->ring_bytes, rung->ring_bytes + kSmallItemBytes,
                     sealed_bytes().begin()));
    const auto counts = f.table.counts();
    CHECK(counts.messages == 1U && counts.rings == 1U);
    CHECK(counts.store_bytes == 2U * kBlockBytes);
    CHECK(counts.ring_bytes == kSmallItemBytes);
}

void test_lifetime_caps() {
    Limits limits;
    limits.hold_time = 86'400s;
    Fixture f(limits);
    const Now now = at(0ms);
    CHECK(f.table.add_stream(1U, principal(1U), now.steady));
    f.register_inbox(1U, address(1U), now);
    auto outcome = f.table.deposit(deposit_of(address(1U), ItemClass::Message,
                                              kSmallItemBytes, 0xffffffffU),
                                   now, f.work);
    CHECK(outcome.granted_seconds == 86'400U);
    CHECK(f.work[0]->message.expiry_minute == kBase / 60 + 1440);
    f.work.clear();
    outcome = f.table.deposit(
        deposit_of(address(1U), ItemClass::Ring, kSmallItemBytes, 1U), now,
        f.work);
    CHECK(outcome.granted_seconds == 1U);
}

void test_deposit_refusals() {
    Limits limits;
    limits.max_items_per_inbox = 3U;
    limits.max_bytes_per_inbox = kLargeItemBytes + kMediumItemBytes;
    limits.max_rings_per_inbox = 1U;
    limits.max_ring_bytes = kLargeItemBytes;
    Fixture f(limits);
    const Now now = at(0ms);
    CHECK(f.table.add_stream(1U, principal(1U), now.steady));
    f.register_inbox(1U, address(1U), now);
    f.register_inbox(1U, address(2U), now);
    f.register_inbox(1U, address(3U), now);
    const auto status_of = [&](const DepositRequest& request) {
        Jobs jobs;
        const auto outcome = f.table.deposit(request, now, jobs);
        if (outcome.status != Status::Done) CHECK(jobs.empty());
        return outcome.status;
    };

    CHECK(status_of(deposit_of(address(9U), ItemClass::Message)) ==
          Status::NotHere);
    // Bytes: one large and one medium fit, then nothing more.
    f.store_message(address(1U), now, kLargeItemBytes);
    CHECK(status_of(deposit_of(address(1U), ItemClass::Message,
                               kMediumItemBytes)) == Status::Done);
    CHECK(status_of(deposit_of(address(1U), ItemClass::Message)) ==
          Status::NotHere);
    // Count: items being written count too.
    CHECK(status_of(deposit_of(address(2U), ItemClass::Message)) ==
          Status::Done);
    CHECK(status_of(deposit_of(address(2U), ItemClass::Ring)) == Status::Done);
    CHECK(status_of(deposit_of(address(2U), ItemClass::Message)) ==
          Status::Done);
    CHECK(status_of(deposit_of(address(2U), ItemClass::Message)) ==
          Status::NotHere);
    // Rings per inbox, then the service's ring memory.
    CHECK(status_of(deposit_of(address(3U), ItemClass::Ring,
                               kMediumItemBytes)) == Status::Done);
    CHECK(status_of(deposit_of(address(3U), ItemClass::Ring)) ==
          Status::NotHere);
    CHECK(f.table.counts().ring_bytes == kSmallItemBytes + kMediumItemBytes);
    Fixture g(limits);
    CHECK(g.table.add_stream(1U, principal(1U), now.steady));
    g.register_inbox(1U, address(1U), now);
    g.register_inbox(1U, address(2U), now);
    CHECK(
        g.table
            .deposit(deposit_of(address(1U), ItemClass::Ring, kLargeItemBytes),
                     now, g.work)
            .status == Status::Done);
    CHECK(g.table.deposit(deposit_of(address(2U), ItemClass::Ring), now, g.work)
              .status == Status::Later);

    // A failed random source, and a source that repeats itself.
    f.random.fail = true;
    CHECK(status_of(deposit_of(address(3U), ItemClass::Message)) ==
          Status::Later);
    f.random.fail = false;
    f.random.repeat = true;
    CHECK(status_of(deposit_of(address(3U), ItemClass::Message)) ==
          Status::Done);
    CHECK(status_of(deposit_of(address(3U), ItemClass::Message)) ==
          Status::Later);
}

void test_store_capacity() {
    Limits limits;
    limits.store_bytes = 2U * kBlockBytes;
    Fixture f(limits);
    const Now now = at(0ms);
    CHECK(f.table.add_stream(1U, principal(1U), now.steady));
    f.register_inbox(1U, address(1U), now);
    // One block left: a 4096-byte message fits, then nothing.
    f.store_message(address(1U), now, kMediumItemBytes);
    CHECK(f.table.counts().store_bytes == 2U * kBlockBytes);
    CHECK(f.table
              .deposit(deposit_of(address(1U), ItemClass::Message), now, f.work)
              .status == Status::Later);
    // A ring needs no store.
    CHECK(f.table.deposit(deposit_of(address(1U), ItemClass::Ring), now, f.work)
              .status == Status::Done);
    // Nor is there room for another registration.
    const std::array<Address, 1> second{address(2U)};
    f.work.clear();
    CHECK(!f.table.begin_open(1U, second, now, f.work));
    CHECK(f.work.empty());
    CHECK(f.open(1U, second, now) == std::vector{Status::Later});
}

void test_registration_quotas() {
    Limits limits;
    limits.max_inboxes_per_principal = 2U;
    limits.max_inboxes = 3U;
    Fixture f(limits);
    const Now now = at(0ms);
    CHECK(f.table.add_stream(1U, principal(1U), now.steady));
    CHECK(f.table.add_stream(2U, principal(2U), now.steady));
    const std::array<Address, 3> three{address(1U), address(2U), address(3U)};
    CHECK(f.table.begin_open(1U, three, now, f.work));
    CHECK(f.work.size() == 2U);
    for (const auto& job : f.work)
        f.table.inbox_created(job->address, job->generation, true);
    f.work.clear();
    CHECK(f.open(1U, three, now) ==
          (std::vector{Status::Done, Status::Done, Status::NotHere}));

    // The service's inbox limit answers "try later".
    const std::array<Address, 2> more{address(4U), address(5U)};
    CHECK(f.table.begin_open(2U, more, now, f.work));
    CHECK(f.work.size() == 1U);
    f.table.inbox_created(address(4U), f.work[0]->generation, true);
    f.work.clear();
    CHECK(f.open(2U, more, now) == (std::vector{Status::Done, Status::Later}));

    // An OPEN moves the charge to its principal while that one has room.
    const std::array<Address, 1> first{address(1U)};
    CHECK(f.open(2U, first, now) == std::vector{Status::Done});
    CHECK(f.open(1U, first, now) == std::vector{Status::Done});
    const std::array<Address, 1> fourth{address(4U)};
    CHECK(f.open(1U, fourth, now) == std::vector{Status::NotHere});

    // A refused creation leaves nothing behind.
    CHECK(f.table.close(address(4U), f.work));
    f.work.clear();
    const std::array<Address, 1> sixth{address(6U)};
    CHECK(f.table.begin_open(2U, sixth, now, f.work));
    const auto store_before = f.table.counts().store_bytes;
    f.table.inbox_created(address(6U), f.work[0]->generation, false);
    f.work.clear();
    CHECK(f.open(2U, sixth, now) == std::vector{Status::Later});
    CHECK(f.table.counts().inboxes == 2U);
    CHECK(f.table.counts().store_bytes == store_before - kBlockBytes);
}

void test_subscriptions() {
    Fixture f;
    const Now now = at(0ms);
    CHECK(f.table.add_stream(1U, principal(1U), now.steady));
    CHECK(f.table.add_stream(2U, principal(1U), now.steady));
    f.register_inbox(1U, address(1U), now);
    f.register_inbox(1U, address(2U), now);
    const ItemId a1 = f.store_message(address(1U), now);
    const ItemId a2 = f.store_message(address(1U), now);
    const ItemId b1 = f.store_message(address(2U), now);
    const ItemId b2 = f.store_message(address(2U), now);
    CHECK(f.woken() == std::vector<StreamId>{1U});
    // Round robin across inboxes, oldest first in each.
    std::vector<ItemId> order;
    while (const auto delivery = f.table.next_delivery(1U, now))
        order.push_back(delivery->head.id);
    CHECK(order == (std::vector{a1, b1, a2, b2}));

    // Opening again starts that inbox over.
    const std::array<Address, 1> first{address(1U)};
    CHECK(f.open(1U, first, now) == std::vector{Status::Done});
    CHECK(f.woken() == std::vector<StreamId>{1U});
    order.clear();
    while (const auto delivery = f.table.next_delivery(1U, now))
        order.push_back(delivery->head.id);
    CHECK(order == (std::vector{a1, a2}));

    // An OPEN on another stream moves the subscription.
    CHECK(f.open(2U, first, now) == std::vector{Status::Done});
    CHECK(f.woken() == std::vector<StreamId>{2U});
    f.store_message(address(1U), now);
    CHECK(f.woken() == std::vector<StreamId>{2U});
    CHECK(!f.table.next_delivery(1U, now).has_value());
    std::size_t delivered = 0U;
    while (f.table.next_delivery(2U, now)) ++delivered;
    CHECK(delivered == 3U);
    // Inbox 2 stays with stream 1.
    f.store_message(address(2U), now);
    CHECK(f.woken() == std::vector<StreamId>{1U});

    // Taking: only the subscriber's own inboxes, and repeating is harmless.
    std::vector<std::byte> storage;
    f.table.take(1U, taken_of({a1, b1}, storage), f.work);
    CHECK(f.work.size() == 1U);
    CHECK(f.work[0]->kind == Job::Kind::DeleteMessage);
    CHECK(f.work[0]->address == address(2U));
    CHECK(f.work[0]->message.id == b1);
    f.work.clear();
    f.table.take(1U, taken_of({b1}, storage), f.work);
    CHECK(f.work.empty());
    f.table.take(2U, taken_of({a1, a2, b2}, storage), f.work);
    CHECK(f.work.size() == 2U);
    f.work.clear();
    CHECK(f.table.counts().taken == 3U);
    CHECK(f.table.counts().messages == 3U);
    // A ring is taken without a disk job.
    const auto ring =
        f.table.deposit(deposit_of(address(1U), ItemClass::Ring), now, f.work);
    CHECK(f.woken() == std::vector<StreamId>{2U});
    f.table.take(2U, taken_of({ring.id}, storage), f.work);
    CHECK(f.work.empty());
    CHECK(f.table.counts().rings == 0U);

    // A closed stream holds nothing.
    f.table.remove_stream(2U);
    f.store_message(address(1U), now);
    CHECK(f.woken().empty());
    CHECK(f.table.counts().streams == 1U);
}

void test_rate_windows() {
    Fixture f;
    CHECK(f.table.add_stream(1U, principal(1U), at(0ms).steady));
    for (std::size_t index = 0U; index < 120U; ++index)
        CHECK(f.table.count_deposit(1U, at(0ms).steady));
    CHECK(!f.table.count_deposit(1U, at(0ms).steady));
    CHECK(!f.table.count_deposit(1U, at(59'999ms).steady));
    CHECK(f.table.count_deposit(1U, at(60s).steady));
    for (std::size_t index = 0U; index < 30U; ++index)
        CHECK(f.table.count_inbox_change(1U, at(1s).steady));
    CHECK(!f.table.count_inbox_change(1U, at(2s).steady));
    CHECK(f.table.count_inbox_change(1U, at(61s).steady));

    // A reconnect within the window keeps the principal's count.
    f.table.remove_stream(1U);
    CHECK(f.table.counts().principals == 1U);
    CHECK(f.table.add_stream(2U, principal(1U), at(62s).steady));
    for (std::size_t index = 0U; index < 29U; ++index)
        CHECK(f.table.count_inbox_change(2U, at(62s).steady));
    CHECK(!f.table.count_inbox_change(2U, at(62s).steady));
}

void test_principal_table() {
    Limits limits;
    limits.max_streams_per_principal = 2U;
    limits.max_principals = 1U;
    Fixture f(limits);
    CHECK(f.table.add_stream(1U, principal(1U), at(0ms).steady));
    CHECK(f.table.add_stream(2U, principal(1U), at(0ms).steady));
    CHECK(!f.table.add_stream(3U, principal(1U), at(0ms).steady));
    CHECK(!f.table.add_stream(3U, principal(2U), at(0ms).steady));
    // A principal that counted nothing is forgotten with its last stream.
    f.table.remove_stream(1U);
    f.table.remove_stream(2U);
    CHECK(f.table.counts().principals == 0U);
    CHECK(f.table.add_stream(3U, principal(2U), at(0ms).steady));
    // One that counted a frame is kept for the rest of its window.
    CHECK(f.table.count_deposit(3U, at(1s).steady));
    f.table.remove_stream(3U);
    CHECK(f.table.next_deadline() == at(61s).steady);
    CHECK(!f.table.add_stream(4U, principal(3U), at(30s).steady));
    CHECK(f.table.add_stream(4U, principal(3U), at(61s).steady));
    f.table.remove_stream(4U);

    // A principal with a registration stays without a stream.
    Fixture g(limits);
    CHECK(g.table.add_stream(1U, principal(1U), at(0ms).steady));
    g.register_inbox(1U, address(1U), at(0ms));
    g.table.remove_stream(1U);
    g.table.expire(at(1h), g.work);
    CHECK(g.table.counts().principals == 1U);
    CHECK(!g.table.add_stream(2U, principal(2U), at(1h).steady));
    // Closing its inbox releases it.
    CHECK(g.table.close(address(1U), g.work));
    CHECK(g.table.add_stream(2U, principal(2U), at(1h).steady));
}

void test_expiry() {
    Fixture f;
    const Now now = at(0ms);
    CHECK(f.table.add_stream(1U, principal(1U), now.steady));
    f.register_inbox(1U, address(1U), now);
    f.work.clear();
    const auto ring = f.table.deposit(
        deposit_of(address(1U), ItemClass::Ring, kSmallItemBytes, 30U), now,
        f.work);
    CHECK(ring.status == Status::Done);
    CHECK(f.table.next_deadline() == at(30s).steady);
    f.table.expire(at(29'999ms), f.work);
    CHECK(f.table.counts().rings == 1U);
    f.table.expire(at(30s), f.work);
    CHECK(f.table.counts().rings == 0U && f.table.counts().expired_rings == 1U);
    CHECK(f.work.empty());

    // A message lives until its expiry minute.
    f.work.clear();
    const auto outcome = f.table.deposit(
        deposit_of(address(1U), ItemClass::Message, kSmallItemBytes, 61U), now,
        f.work);
    f.work[0]->result = IoResult::Ok;
    CHECK(f.table.message_written(*f.work[0]));
    f.work.clear();
    CHECK(f.table.next_wall_deadline() == (kBase / 60 + 2) * 60);
    f.table.expire(at(119s), f.work);
    CHECK(f.table.counts().messages == 1U && f.work.empty());
    f.table.expire(at(120s), f.work);
    CHECK(f.table.counts().messages == 0U);
    CHECK(f.table.counts().expired_messages == 1U);
    CHECK(f.work.size() == 1U && f.work[0]->kind == Job::Kind::DeleteMessage);
    CHECK(f.work[0]->message.id == outcome.id);
    f.work.clear();
    CHECK(f.table.counts().store_bytes == kBlockBytes);

    // The registration ends at 00:00 UTC, 30 days after the day of the OPEN.
    const std::int64_t end = (now.day() + 30LL) * 86'400;
    CHECK(f.table.next_wall_deadline() == end);
    const auto until_end = std::chrono::seconds(end - kBase);
    f.table.expire(at(until_end - 1s), f.work);
    CHECK(f.table.counts().inboxes == 1U);
    CHECK(f.table
              .deposit(deposit_of(address(1U), ItemClass::Message),
                       at(until_end), f.work)
              .status == Status::NotHere);
    f.table.expire(at(until_end), f.work);
    CHECK(f.table.counts().inboxes == 0U);
    CHECK(f.table.counts().ended_inboxes == 1U);
    CHECK(f.work.size() == 1U && f.work[0]->kind == Job::Kind::CloseInbox);
    CHECK(f.table.counts().store_bytes == 0U);
}

void test_renewal() {
    Fixture f;
    const Now now = at(0ms);
    CHECK(f.table.add_stream(1U, principal(1U), now.steady));
    f.register_inbox(1U, address(1U), now);
    const std::array<Address, 1> one{address(1U)};
    // The same day changes nothing on disk.
    CHECK(f.open(1U, one, at(1h)) == std::vector{Status::Done});
    CHECK(f.work.empty());
    const Now tomorrow = at(24h);
    CHECK(f.open(1U, one, tomorrow) == std::vector{Status::Done});
    CHECK(f.work.size() == 1U);
    CHECK(f.work[0]->kind == Job::Kind::RenewRegistration);
    CHECK(f.work[0]->day == tomorrow.day() + 30U);
    f.work.clear();
    CHECK(f.open(1U, one, tomorrow) == std::vector{Status::Done});
    CHECK(f.work.empty());
    CHECK(f.table.next_wall_deadline() == (tomorrow.day() + 30LL) * 86'400);
}

void test_close_during_write() {
    Fixture f;
    const Now now = at(0ms);
    CHECK(f.table.add_stream(1U, principal(1U), now.steady));
    f.register_inbox(1U, address(1U), now);
    f.store_message(address(1U), now);
    CHECK(f.table.deposit(deposit_of(address(1U), ItemClass::Ring), now, f.work)
              .status == Status::Done);
    const auto pending = f.table.deposit(
        deposit_of(address(1U), ItemClass::Message, kLargeItemBytes), now,
        f.work);
    CHECK(pending.waits_for_write && f.work.size() == 1U);
    auto write = std::move(f.work[0]);
    f.work.clear();
    CHECK(!f.table.close(address(9U), f.work));
    CHECK(f.work.empty());
    CHECK(f.table.close(address(1U), f.work));
    CHECK(f.work.size() == 1U && f.work[0]->kind == Job::Kind::CloseInbox);
    f.work.clear();
    // The pending write keeps its reservation until it returns.
    CHECK(f.table.counts().store_bytes == blocks_for(kLargeItemBytes));
    CHECK(f.table.counts().rings == 0U && f.table.counts().ring_bytes == 0U);
    write->result = IoResult::Ok;
    CHECK(f.table.message_written(*write));
    const auto counts = f.table.counts();
    CHECK(counts.inboxes == 0U && counts.messages == 0U);
    CHECK(counts.store_bytes == 0U);
    // Its ID is free again: a TAKEN of it finds nothing.
    std::vector<std::byte> storage;
    f.table.take(1U, taken_of({pending.id}, storage), f.work);
    CHECK(f.work.empty());

    // A refused write is forgotten, and its reservation released.
    f.register_inbox(1U, address(2U), now);
    // Wake-ups from the deposits above.
    CHECK(f.woken() == std::vector<StreamId>{1U});
    const auto refused = f.table.deposit(
        deposit_of(address(2U), ItemClass::Message), now, f.work);
    CHECK(refused.waits_for_write);
    f.work[0]->result = IoResult::NoSpace;
    CHECK(!f.table.message_written(*f.work[0]));
    f.work.clear();
    CHECK(f.table.counts().messages == 0U);
    CHECK(f.table.counts().store_bytes == kBlockBytes);
    CHECK(f.woken().empty());
}

void test_import_and_loss() {
    Fixture f;
    LoadedInbox inbox;
    inbox.address = address(1U);
    inbox.registration_day = at(0ms).day() + 5U;
    for (std::uint8_t label = 1U; label <= 2U; ++label) {
        // Listed newest first, as a directory scan may list them.
        LoadedMessage message;
        message.name.order = 30U - 10U * label;
        message.name.id.fill(label);
        message.name.deposit_minute = kBase / 60 - label;
        message.name.expiry_minute = kBase / 60 + 100U;
        message.size = kMediumItemBytes;
        inbox.messages.push_back(message);
    }
    CHECK(f.table.import(LoadedInbox(inbox)));
    auto counts = f.table.counts();
    CHECK(counts.inboxes == 1U && counts.messages == 2U);
    CHECK(counts.store_bytes == 3U * kBlockBytes);
    // An ID the table already holds marks a store this service never wrote.
    inbox.address = address(2U);
    CHECK(!f.table.import(LoadedInbox(inbox)));
    CHECK(f.table.counts().inboxes == 1U);

    const Now now = at(0ms);
    CHECK(f.table.add_stream(1U, principal(1U), now.steady));
    const std::array<Address, 1> one{address(1U)};
    CHECK(f.open(1U, one, now) == std::vector{Status::Done});
    // The imported registration ends sooner than a new one, so it renews.
    CHECK(f.work.size() == 1U &&
          f.work[0]->kind == Job::Kind::RenewRegistration);
    f.work.clear();
    // Oldest deposit first, whatever the scan's order.
    const auto delivery = f.table.next_delivery(1U, now);
    CHECK(delivery.has_value() && delivery->head.id[0] == 2U);
    CHECK(delivery->head.deposit_minute == kBase / 60 - 2U);
    CHECK(delivery->name.order == 10U);
    CHECK(f.table.next_delivery(1U, now)->head.id[0] == 1U);
    // A message whose file is gone is forgotten and its file deleted.
    f.table.drop_message(address(1U), delivery->sequence, f.work);
    CHECK(f.work.size() == 1U && f.work[0]->kind == Job::Kind::DeleteMessage);
    counts = f.table.counts();
    CHECK(counts.messages == 1U && counts.lost_messages == 1U);
    CHECK(counts.store_bytes == 2U * kBlockBytes);
    f.work.clear();
    // A new deposit is ordered after every message on disk.
    CHECK(f.table
              .deposit(deposit_of(address(1U), ItemClass::Message), now, f.work)
              .waits_for_write);
    CHECK(f.work.size() == 1U && f.work[0]->message.order == 21U);
}

}  // namespace

int main() {
    test_registration_and_delivery();
    test_lifetime_caps();
    test_deposit_refusals();
    test_store_capacity();
    test_registration_quotas();
    test_subscriptions();
    test_rate_windows();
    test_principal_table();
    test_expiry();
    test_renewal();
    test_close_during_write();
    test_import_and_loss();
    std::puts("table: all checks passed");
    return 0;
}
