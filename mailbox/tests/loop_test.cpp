/* Copyright (C) 2026 FixCraft Inc. AGPL-3.0-or-later. */

// The event loop with a real store and lowered limits, for behavior the real
// program reaches only after minutes or days: expiry on a moved host clock,
// timeouts, slow readers, restarts and a failing random source. Clients
// connect to a real UNIX listener as the trusted daemon user would.

#include "mailbox.hpp"

#include <ftw.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <optional>
#include <string>
#include <thread>
#include <vector>

#include "check.hpp"
#include "sha256.hpp"

namespace {

using namespace ito::mailbox;
using namespace std::chrono_literals;
using Bytes = std::vector<std::byte>;

// 2027-01-15 08:00 UTC.
constexpr std::int64_t kBase = 1'800'000'000;
constexpr std::int64_t kDay = 86'400;

class TempDirectory final {
public:
    TempDirectory() {
        char pattern[] = "/tmp/ito-mailbox-loop-XXXXXX";
        CHECK(::mkdtemp(pattern) != nullptr);
        path_ = pattern;
        CHECK(::mkdir(data().c_str(), 0700) == 0);
    }
    ~TempDirectory() {
        ::nftw(
            path_.c_str(),
            [](const char* path, const struct stat*, int, FTW*) {
                return ::remove(path);
            },
            16, FTW_DEPTH | FTW_PHYS);
    }
    TempDirectory(const TempDirectory&) = delete;
    TempDirectory& operator=(const TempDirectory&) = delete;

    [[nodiscard]] std::string data() const { return path_ + "/data"; }
    [[nodiscard]] std::string socket() const { return path_ + "/mailbox.sock"; }

private:
    std::string path_;
};

class FailingRandom final : public RandomSource {
public:
    bool fill(std::span<std::uint8_t>) noexcept override { return false; }
};

Secret secret(std::uint8_t label) {
    Secret out{};
    out.fill(label);
    return out;
}

void put_u32(Bytes& out, std::uint32_t value) {
    for (const unsigned shift : {24U, 16U, 8U, 0U})
        out.push_back(static_cast<std::byte>(value >> shift));
}

std::uint32_t get_u32(const Bytes& bytes, std::size_t at) {
    return (std::to_integer<std::uint32_t>(bytes[at]) << 24U) |
           (std::to_integer<std::uint32_t>(bytes[at + 1U]) << 16U) |
           (std::to_integer<std::uint32_t>(bytes[at + 2U]) << 8U) |
           std::to_integer<std::uint32_t>(bytes[at + 3U]);
}

template <typename Field>
void append(Bytes& out, const Field& field) {
    for (const auto byte : field) out.push_back(std::byte{byte});
}

Bytes frame(std::uint8_t type, const Bytes& payload = {}) {
    Bytes out;
    put_u32(out, static_cast<std::uint32_t>(1U + payload.size()));
    out.push_back(std::byte{type});
    out.insert(out.end(), payload.begin(), payload.end());
    return out;
}

const Bytes kVersion{std::byte{0}, std::byte{1}};

Bytes open_frame(std::initializer_list<Secret> secrets) {
    Bytes payload = kVersion;
    for (const auto& one : secrets) append(payload, one);
    return frame(1U, payload);
}

Bytes close_frame(const Secret& one) {
    Bytes payload = kVersion;
    append(payload, one);
    return frame(5U, payload);
}

Bytes sealed(std::size_t size, std::uint8_t seed) {
    Bytes out(size);
    for (std::size_t index = 0U; index < size; ++index)
        out[index] = static_cast<std::byte>(seed + index * 7U);
    return out;
}

Bytes deposit_frame(const Secret& to, ItemClass item_class,
                    std::uint32_t lifetime, const Bytes& bytes) {
    Bytes payload = kVersion;
    append(payload, inbox_address(to));
    payload.push_back(static_cast<std::byte>(item_class));
    put_u32(payload, lifetime);
    payload.insert(payload.end(), bytes.begin(), bytes.end());
    return frame(7U, payload);
}

Bytes taken_frame(const std::vector<ItemId>& ids) {
    Bytes payload;
    for (const auto& id : ids) append(payload, id);
    return frame(4U, payload);
}

Bytes status_body(std::uint8_t type, std::uint8_t status) {
    return {std::byte{type}, std::byte{status}};
}

const Bytes kPing = frame(10U);
const Bytes kPong{std::byte{11}};

// One module connection, as yumed would open it.
class Client final {
public:
    // Connects, then writes the module header unless header is false.
    Client(const std::string& path, std::uint8_t principal,
           bool header = true) {
        socket_ = ::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
        CHECK(socket_ >= 0);
        sockaddr_un address{};
        address.sun_family = AF_UNIX;
        std::strncpy(address.sun_path, path.c_str(),
                     sizeof address.sun_path - 1U);
        CHECK(::connect(socket_, reinterpret_cast<sockaddr*>(&address),
                        sizeof address) == 0);
        if (!header) return;
        static constexpr char kDigits[] = "0123456789abcdef";
        std::string line = "yume-module 1 ";
        for (int index = 0; index < 32; ++index) {
            line += kDigits[principal >> 4U];
            line += kDigits[principal & 0x0fU];
        }
        line += " ito-mailbox\n";
        send(Bytes(
            reinterpret_cast<const std::byte*>(line.data()),
            reinterpret_cast<const std::byte*>(line.data()) + line.size()));
    }
    ~Client() {
        if (socket_ >= 0) ::close(socket_);
    }
    Client(const Client&) = delete;
    Client& operator=(const Client&) = delete;

    void send(const Bytes& bytes) const {
        std::size_t sent = 0U;
        while (sent < bytes.size()) {
            const ssize_t count = ::send(socket_, bytes.data() + sent,
                                         bytes.size() - sent, MSG_NOSIGNAL);
            CHECK(count > 0);
            sent += static_cast<std::size_t>(count);
        }
    }

    // count bytes, or fewer at end of stream or the deadline.
    Bytes read(std::size_t count, std::chrono::milliseconds limit) {
        Bytes out;
        const auto deadline = std::chrono::steady_clock::now() + limit;
        eof_ = false;
        while (out.size() < count) {
            const auto left =
                std::chrono::duration_cast<std::chrono::milliseconds>(
                    deadline - std::chrono::steady_clock::now());
            if (left <= 0ms) break;
            pollfd ready{socket_, POLLIN, 0};
            if (::poll(&ready, 1U, static_cast<int>(left.count())) <= 0) break;
            std::byte buffer[16384];
            const ssize_t got =
                ::recv(socket_, buffer,
                       std::min(sizeof buffer, count - out.size()), 0);
            if (got <= 0) {
                eof_ = true;
                break;
            }
            out.insert(out.end(), buffer, buffer + got);
        }
        return out;
    }

    // The next frame's body, type first, or nothing at the deadline or end
    // of stream.
    std::optional<Bytes> frame(std::chrono::milliseconds limit = 2s) {
        const Bytes length = read(4U, limit);
        if (length.size() < 4U) return std::nullopt;
        const Bytes body = read(get_u32(length, 0U), limit);
        CHECK(body.size() == get_u32(length, 0U));
        return body;
    }

    Bytes expect_frame(std::chrono::milliseconds limit = 2s) {
        auto body = frame(limit);
        CHECK(body.has_value());
        return std::move(*body);
    }

    void expect_quiet(std::chrono::milliseconds limit = 300ms) {
        CHECK(read(1U, limit).empty() && !eof_);
    }

    // End of stream with nothing before it.
    void expect_end(std::chrono::milliseconds limit = 2s) {
        CHECK(read(1U, limit).empty() && eof_);
    }

    void expect_refused(std::uint8_t reason) {
        CHECK(expect_frame() == status_body(12U, reason));
        expect_end();
    }

    ItemId deposit(const Secret& to, ItemClass item_class,
                   std::uint32_t lifetime, const Bytes& bytes,
                   std::uint32_t granted) {
        send(deposit_frame(to, item_class, lifetime, bytes));
        const Bytes reply = expect_frame();
        CHECK(reply.size() == 21U && reply[0] == std::byte{8});
        CHECK(get_u32(reply, 17U) == granted);
        ItemId id{};
        for (std::size_t index = 0U; index < id.size(); ++index)
            id[index] = std::to_integer<std::uint8_t>(reply[1U + index]);
        return id;
    }

    void open(std::initializer_list<Secret> secrets, const Bytes& statuses) {
        send(open_frame(secrets));
        Bytes expected{std::byte{2}};
        expected.insert(expected.end(), statuses.begin(), statuses.end());
        CHECK(expect_frame() == expected);
    }

    [[nodiscard]] int descriptor() const noexcept { return socket_; }

private:
    int socket_{-1};
    bool eof_{false};
};

struct Item final {
    ItemClass item_class{ItemClass::Message};
    Address address{};
    ItemId id{};
    std::uint32_t deposit_minute{0U};
    std::uint32_t seconds_left{0U};
    Bytes bytes;
};

Item parse_item(const Bytes& body) {
    CHECK(body.size() >= 58U && body[0] == std::byte{3});
    Item item;
    item.item_class = static_cast<ItemClass>(body[1]);
    for (std::size_t index = 0U; index < 32U; ++index)
        item.address[index] = std::to_integer<std::uint8_t>(body[2U + index]);
    for (std::size_t index = 0U; index < 16U; ++index)
        item.id[index] = std::to_integer<std::uint8_t>(body[34U + index]);
    item.deposit_minute = get_u32(body, 50U);
    item.seconds_left = get_u32(body, 54U);
    item.bytes.assign(body.begin() + 58, body.end());
    return item;
}

Bytes statuses(std::initializer_list<std::uint8_t> values) {
    Bytes out;
    for (const auto value : values) out.push_back(std::byte{value});
    return out;
}

// A running mailbox over a data directory that outlives it.
class Fixture final {
public:
    Fixture(const TempDirectory& directory, const Limits& limits,
            std::atomic<std::int64_t>& clock, RandomSource& random)
        : path_(directory.socket()) {
        StoreError store_error = StoreError::Unreadable;
        auto store =
            Store::open(directory.data().c_str(), ::geteuid(), store_error);
        CHECK(store.has_value());
        const std::int64_t now = clock.load();
        std::vector<LoadedInbox> loaded;
        LoadCounts counts;
        CHECK(store->load(static_cast<std::uint32_t>(now / kDay),
                          static_cast<std::uint32_t>(now / 60), loaded, counts,
                          store_error));
        ::unlink(path_.c_str());
        const int listener = ::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
        CHECK(listener >= 0);
        sockaddr_un address{};
        address.sun_family = AF_UNIX;
        std::strncpy(address.sun_path, path_.c_str(),
                     sizeof address.sun_path - 1U);
        CHECK(::bind(listener, reinterpret_cast<sockaddr*>(&address),
                     sizeof address) == 0);
        CHECK(::chmod(path_.c_str(), 0600) == 0);
        CHECK(::listen(listener, 64) == 0);
        MailboxOptions options;
        options.service = "ito-mailbox";
        options.daemon_uid = ::getuid();
        options.limits = limits;
        options.wall_clock = [&clock] { return clock.load(); };
        CreateError error = CreateError::Resources;
        mailbox_ =
            Mailbox::create(listener, -1, std::move(options), std::move(*store),
                            std::move(loaded), random, error);
        CHECK(mailbox_ != nullptr);
        thread_ = std::thread([this] { result_ = mailbox_->run(); });
    }
    ~Fixture() { finish(); }
    Fixture(const Fixture&) = delete;
    Fixture& operator=(const Fixture&) = delete;

    // Stops the loop and returns its final counts.
    MailboxCounts finish() {
        if (thread_.joinable()) {
            mailbox_->stop();
            thread_.join();
            CHECK(result_ == 0);
            ::unlink(path_.c_str());
        }
        return mailbox_->counts();
    }

    [[nodiscard]] Client connect(std::uint8_t principal,
                                 bool header = true) const {
        return Client(path_, principal, header);
    }

private:
    std::string path_;
    std::unique_ptr<Mailbox> mailbox_;
    std::thread thread_;
    int result_{-1};
};

Limits test_limits() {
    Limits limits;
    limits.max_streams = 16U;
    limits.drain_budget = 200ms;
    return limits;
}

void test_open_deposit_take() {
    TempDirectory directory;
    std::atomic<std::int64_t> clock{kBase};
    SystemRandom random;
    Fixture mailbox(directory, test_limits(), clock, random);
    auto owner = mailbox.connect(0xa1U);
    auto sender = mailbox.connect(0xb2U);
    owner.open({secret(1U)}, statuses({1U}));
    // An unknown address, and replies in request order.
    sender.send(deposit_frame(secret(9U), ItemClass::Message, 60U,
                              sealed(kSmallItemBytes, 1U)));
    sender.send(kPing);
    CHECK(sender.expect_frame() == status_body(9U, 2U));
    CHECK(sender.expect_frame() == kPong);

    const Bytes first = sealed(kMediumItemBytes, 3U);
    const ItemId id =
        sender.deposit(secret(1U), ItemClass::Message, 120U, first, 120U);
    const Item item = parse_item(owner.expect_frame());
    CHECK(item.item_class == ItemClass::Message);
    CHECK(item.address == inbox_address(secret(1U)));
    CHECK(item.id == id);
    CHECK(item.deposit_minute == kBase / 60);
    CHECK(item.seconds_left == 120U);
    CHECK(item.bytes == first);

    // A ring is delivered from memory.
    const Bytes ring = sealed(kSmallItemBytes, 4U);
    const ItemId ring_id =
        sender.deposit(secret(1U), ItemClass::Ring, 600U, ring, 60U);
    const Item rung = parse_item(owner.expect_frame());
    CHECK(rung.item_class == ItemClass::Ring && rung.id == ring_id);
    CHECK(rung.bytes == ring);

    // A taken item is not delivered again, and every OPEN starts the others
    // over.
    owner.send(taken_frame({id}));
    owner.open({secret(1U)}, statuses({1U}));
    CHECK(parse_item(owner.expect_frame()).id == ring_id);
    owner.expect_quiet();
    // The sender cannot take or close what it only deposits to.
    sender.send(taken_frame({ring_id}));
    owner.open({secret(1U)}, statuses({1U}));
    CHECK(parse_item(owner.expect_frame()).id == ring_id);

    // A second stream takes the subscription over.
    auto phone = mailbox.connect(0xa1U);
    phone.open({secret(1U)}, statuses({1U}));
    CHECK(parse_item(phone.expect_frame()).id == ring_id);
    sender.deposit(secret(1U), ItemClass::Message, 60U,
                   sealed(kSmallItemBytes, 5U), 60U);
    CHECK(parse_item(phone.expect_frame()).item_class == ItemClass::Message);
    owner.expect_quiet();

    // CLOSE deletes the inbox, and closing it again still answers 1.
    phone.send(close_frame(secret(1U)));
    CHECK(phone.expect_frame() == status_body(6U, 1U));
    phone.send(close_frame(secret(1U)));
    CHECK(phone.expect_frame() == status_body(6U, 1U));
    sender.send(deposit_frame(secret(1U), ItemClass::Message, 60U,
                              sealed(kSmallItemBytes, 6U)));
    CHECK(sender.expect_frame() == status_body(9U, 2U));

    const auto counts = mailbox.finish();
    CHECK(counts.table.inboxes == 0U && counts.table.messages == 0U);
    CHECK(counts.table.taken == 1U);
    CHECK(counts.deposit_statuses[0] == 3U);
    CHECK(counts.deposit_statuses[1] == 2U);
    CHECK(counts.close_statuses[0] == 2U);
    CHECK(counts.delivered == 6U);
    CHECK(counts.pending_jobs == 0U);
}

void test_limits_through_the_loop() {
    TempDirectory directory;
    std::atomic<std::int64_t> clock{kBase};
    SystemRandom random;
    Limits limits = test_limits();
    limits.max_inboxes_per_principal = 2U;
    limits.max_items_per_inbox = 2U;
    limits.max_streams_per_principal = 2U;
    Fixture mailbox(directory, limits, clock, random);
    auto owner = mailbox.connect(0xa1U);
    owner.open({secret(1U), secret(2U), secret(3U)}, statuses({1U, 1U, 2U}));
    auto sender = mailbox.connect(0xb2U);
    sender.deposit(secret(1U), ItemClass::Message, 60U,
                   sealed(kSmallItemBytes, 1U), 60U);
    sender.deposit(secret(1U), ItemClass::Ring, 60U,
                   sealed(kSmallItemBytes, 2U), 60U);
    sender.send(deposit_frame(secret(1U), ItemClass::Message, 60U,
                              sealed(kSmallItemBytes, 3U)));
    CHECK(sender.expect_frame() == status_body(9U, 2U));

    // A principal's third stream is refused for capacity.
    auto second = mailbox.connect(0xa1U);
    second.send(kPing);
    CHECK(second.expect_frame() == kPong);
    auto third = mailbox.connect(0xa1U);
    third.expect_refused(3U);

    // 30 OPEN and CLOSE frames per principal in a window, then "later".
    // The first OPEN above counted too. Inbox 2 is empty, so no ITEM comes
    // between the replies.
    for (int index = 0; index < 29; ++index)
        second.open({secret(2U)}, statuses({1U}));
    second.open({secret(2U), secret(8U)}, statuses({3U, 3U}));
    second.send(close_frame(secret(9U)));
    CHECK(second.expect_frame() == status_body(6U, 3U));
    // 120 DEPOSIT frames, stored or not, then "later".
    for (int index = 0; index < 117; ++index) {
        sender.send(deposit_frame(secret(7U), ItemClass::Ring, 60U,
                                  sealed(kSmallItemBytes, 4U)));
        CHECK(sender.expect_frame() == status_body(9U, 2U));
    }
    sender.send(deposit_frame(secret(2U), ItemClass::Ring, 60U,
                              sealed(kSmallItemBytes, 4U)));
    CHECK(sender.expect_frame() == status_body(9U, 3U));
}

void test_bad_requests() {
    TempDirectory directory;
    std::atomic<std::int64_t> clock{kBase};
    SystemRandom random;
    Fixture mailbox(directory, test_limits(), clock, random);
    {
        auto client = mailbox.connect(1U);
        client.send(frame(2U, {std::byte{1}}));
        client.expect_refused(6U);
    }
    {
        auto client = mailbox.connect(1U);
        Bytes payload{std::byte{0}, std::byte{2}};
        client.send(frame(1U, payload));
        client.expect_refused(2U);
    }
    {
        // Refused from the length alone, before any body arrives.
        auto client = mailbox.connect(1U);
        Bytes length;
        put_u32(length, 16425U);
        client.send(length);
        client.expect_refused(6U);
    }
    {
        // A size no item has.
        auto client = mailbox.connect(1U);
        client.send(deposit_frame(secret(1U), ItemClass::Message, 60U,
                                  sealed(2048U, 1U)));
        client.expect_refused(6U);
    }
    {
        // Replies already owed are flushed before the refusal.
        auto client = mailbox.connect(1U);
        Bytes both = kPing;
        const Bytes bad = frame(13U);
        both.insert(both.end(), bad.begin(), bad.end());
        client.send(both);
        CHECK(client.expect_frame() == kPong);
        client.expect_refused(6U);
    }
    const auto counts = mailbox.finish();
    CHECK(counts.refusals[5] == 4U && counts.refusals[1] == 1U);
}

void test_timeouts() {
    TempDirectory directory;
    std::atomic<std::int64_t> clock{kBase};
    SystemRandom random;
    Limits limits = test_limits();
    limits.parse_budget = 300ms;
    limits.idle_timeout = 700ms;
    Fixture mailbox(directory, limits, clock, random);

    // A header that never comes closes without a reply.
    auto silent = mailbox.connect(1U, false);
    silent.send(Bytes{std::byte{'y'}});
    // A frame that stops halfway.
    auto partial = mailbox.connect(1U);
    partial.send(Bytes{std::byte{0}, std::byte{0}});
    // No frame at all after the header.
    auto idle = mailbox.connect(2U);
    // A PING every 250 ms keeps a stream open. The first one comes within
    // the parse budget the header shares with the first frame.
    auto alive = mailbox.connect(3U);
    alive.send(kPing);
    CHECK(alive.expect_frame() == kPong);
    // A client that sends but never reads.
    auto deaf = mailbox.connect(4U);
    Bytes pings;
    for (int index = 0; index < 100'000; ++index)
        pings.insert(pings.end(), kPing.begin(), kPing.end());
    std::thread flood([&] {
        std::size_t sent = 0U;
        while (sent < pings.size()) {
            const ssize_t count = ::send(deaf.descriptor(), pings.data() + sent,
                                         pings.size() - sent, MSG_NOSIGNAL);
            if (count <= 0) return;
            sent += static_cast<std::size_t>(count);
        }
    });
    const auto start = std::chrono::steady_clock::now();
    partial.expect_refused(5U);
    CHECK(std::chrono::steady_clock::now() - start < 700ms);
    for (int beat = 0; beat < 6; ++beat) {
        std::this_thread::sleep_for(250ms);
        alive.send(kPing);
        CHECK(alive.expect_frame() == kPong);
    }
    idle.expect_refused(5U);
    // The deaf client is refused once the service could not read its next
    // request for the idle time. Its stream then ends after the drain
    // budget, whatever it still holds.
    std::size_t pongs = 0U;
    for (;;) {
        const auto body = deaf.frame(3s);
        if (!body) break;
        if (*body == kPong) {
            ++pongs;
            continue;
        }
        CHECK(*body == status_body(12U, 5U));
    }
    CHECK(pongs < 100'000U);
    flood.join();
    silent.expect_end(100ms);
    alive.send(kPing);
    CHECK(alive.expect_frame() == kPong);
    const auto counts = mailbox.finish();
    CHECK(counts.refusals[4] == 3U);
    CHECK(counts.rejected_headers == 1U);
}

// The host's clock moves forward by minutes and then days. Each OPEN arrives
// in the same pass that notices the move, and must not see what ended.
void test_wall_clock() {
    TempDirectory directory;
    std::atomic<std::int64_t> clock{kBase};
    SystemRandom random;
    Limits limits = test_limits();
    limits.hold_time = 30 * 86'400s;
    Fixture mailbox(directory, limits, clock, random);
    auto sender = mailbox.connect(0xb2U);
    {
        auto owner = mailbox.connect(0xa1U);
        owner.open({secret(1U)}, statuses({1U}));
    }
    sender.deposit(secret(1U), ItemClass::Message, 120U,
                   sealed(kSmallItemBytes, 1U), 120U);
    clock = kBase + 119;
    {
        auto owner = mailbox.connect(0xa1U);
        owner.open({secret(1U)}, statuses({1U}));
        CHECK(parse_item(owner.expect_frame()).seconds_left == 1U);
    }
    clock = kBase + 120;
    {
        auto owner = mailbox.connect(0xa1U);
        owner.open({secret(1U)}, statuses({1U}));
        owner.expect_quiet();
    }

    // The registration ends at 00:00 UTC on the 30th day after the OPEN,
    // before this message would expire.
    sender.deposit(secret(1U), ItemClass::Message, 30U * 86'400U,
                   sealed(kSmallItemBytes, 2U), 30U * 86'400U);
    const std::int64_t end = (kBase / kDay + 30) * kDay;
    clock = end - 1;
    sender.send(kPing);
    CHECK(sender.expect_frame() == kPong);
    clock = end;
    {
        auto owner = mailbox.connect(0xa1U);
        owner.open({secret(1U)}, statuses({1U}));
        owner.expect_quiet();
    }
    const auto counts = mailbox.finish();
    CHECK(counts.table.expired_messages == 1U);
    CHECK(counts.table.ended_inboxes == 1U);
    CHECK(counts.table.inboxes == 1U && counts.table.messages == 0U);
}

void test_restart_and_rings() {
    TempDirectory directory;
    std::atomic<std::int64_t> clock{kBase};
    SystemRandom random;
    Limits limits = test_limits();
    limits.ring_lifetime = 1s;
    // Several messages in the same minute, so only their stored order can
    // keep them oldest first across the restart.
    std::vector<ItemId> kept_order;
    ItemId kept{};
    {
        Fixture mailbox(directory, limits, clock, random);
        auto owner = mailbox.connect(0xa1U);
        owner.open({secret(1U), secret(2U)}, statuses({1U, 1U}));
        owner.send(close_frame(secret(2U)));
        CHECK(owner.expect_frame() == status_body(6U, 1U));
        auto sender = mailbox.connect(0xb2U);
        kept = sender.deposit(secret(1U), ItemClass::Message, 3600U,
                              sealed(kLargeItemBytes, 1U), 3600U);
        CHECK(parse_item(owner.expect_frame()).id == kept);
        // Rings are held in memory for their lifetime only.
        sender.deposit(secret(1U), ItemClass::Ring, 60U,
                       sealed(kSmallItemBytes, 2U), 1U);
        CHECK(parse_item(owner.expect_frame()).item_class == ItemClass::Ring);
        std::this_thread::sleep_for(1100ms);
        owner.open({secret(1U)}, statuses({1U}));
        CHECK(parse_item(owner.expect_frame()).id == kept);
        owner.expect_quiet();
        sender.deposit(secret(1U), ItemClass::Ring, 60U,
                       sealed(kSmallItemBytes, 3U), 1U);
        CHECK(parse_item(owner.expect_frame()).item_class == ItemClass::Ring);
        kept_order.push_back(kept);
        for (std::uint8_t index = 0U; index < 8U; ++index) {
            kept_order.push_back(sender.deposit(
                secret(1U), ItemClass::Message, 3600U,
                sealed(kSmallItemBytes, static_cast<std::uint8_t>(10U + index)),
                3600U));
            CHECK(parse_item(owner.expect_frame()).id == kept_order.back());
        }
        const auto counts = mailbox.finish();
        CHECK(counts.table.expired_rings == 1U && counts.table.rings == 1U);
    }
    // A restart keeps the message and the registration, loses the ring and
    // never brings back the closed inbox.
    Fixture mailbox(directory, limits, clock, random);
    auto owner = mailbox.connect(0xa1U);
    owner.open({secret(1U)}, statuses({1U}));
    const Item item = parse_item(owner.expect_frame());
    CHECK(item.id == kept && item.bytes == sealed(kLargeItemBytes, 1U));
    for (std::size_t index = 1U; index < kept_order.size(); ++index)
        CHECK(parse_item(owner.expect_frame()).id == kept_order[index]);
    owner.expect_quiet();
    auto sender = mailbox.connect(0xb2U);
    sender.send(deposit_frame(secret(2U), ItemClass::Message, 60U,
                              sealed(kSmallItemBytes, 4U)));
    CHECK(sender.expect_frame() == status_body(9U, 2U));
}

// The phone drops its stream in the middle of a delivery and reconnects.
void test_reconnect_and_slow_reader() {
    TempDirectory directory;
    std::atomic<std::int64_t> clock{kBase};
    SystemRandom random;
    Fixture mailbox(directory, test_limits(), clock, random);
    auto sender = mailbox.connect(0xb2U);
    {
        auto owner = mailbox.connect(0xa1U);
        owner.open({secret(1U)}, statuses({1U}));
    }
    std::vector<ItemId> ids;
    for (std::uint8_t index = 0U; index < 40U; ++index)
        ids.push_back(sender.deposit(secret(1U), ItemClass::Message, 3600U,
                                     sealed(kLargeItemBytes, index), 3600U));
    {
        auto owner = mailbox.connect(0xa1U);
        owner.open({secret(1U)}, statuses({1U}));
        CHECK(owner.read(5000U, 2s).size() == 5000U);
    }
    // A reader that does not read holds only a bounded backlog, and the
    // service keeps serving others meanwhile.
    auto owner = mailbox.connect(0xa1U);
    owner.open({secret(1U)}, statuses({1U}));
    std::this_thread::sleep_for(300ms);
    sender.send(kPing);
    CHECK(sender.expect_frame() == kPong);
    std::vector<ItemId> received;
    for (std::size_t index = 0U; index < ids.size(); ++index) {
        const Item item = parse_item(owner.expect_frame());
        CHECK(item.bytes ==
              sealed(kLargeItemBytes, static_cast<std::uint8_t>(index)));
        received.push_back(item.id);
    }
    CHECK(received == ids);
    owner.send(taken_frame(ids));
    owner.open({secret(1U)}, statuses({1U}));
    owner.expect_quiet();
    const auto counts = mailbox.finish();
    CHECK(counts.table.messages == 0U && counts.table.taken == 40U);
}

void test_failing_random_source() {
    TempDirectory directory;
    std::atomic<std::int64_t> clock{kBase};
    FailingRandom random;
    Fixture mailbox(directory, test_limits(), clock, random);
    auto owner = mailbox.connect(0xa1U);
    owner.open({secret(1U)}, statuses({1U}));
    owner.send(deposit_frame(secret(1U), ItemClass::Message, 60U,
                             sealed(kSmallItemBytes, 1U)));
    CHECK(owner.expect_frame() == status_body(9U, 3U));
    owner.send(deposit_frame(secret(1U), ItemClass::Ring, 60U,
                             sealed(kSmallItemBytes, 1U)));
    CHECK(owner.expect_frame() == status_body(9U, 3U));
}

}  // namespace

int main() {
    test_open_deposit_take();
    test_limits_through_the_loop();
    test_bad_requests();
    test_timeouts();
    test_wall_clock();
    test_restart_and_rings();
    test_reconnect_and_slow_reader();
    test_failing_random_source();
    std::puts("loop: all checks passed");
    return 0;
}
