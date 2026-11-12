/* Copyright (C) 2026 FixCraft Inc. AGPL-3.0-or-later. */

#include "mailbox.hpp"

#include <fcntl.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <csignal>
#include <cstring>
#include <limits>
#include <map>
#include <new>
#include <optional>
#include <set>
#include <span>
#include <utility>
#include <variant>

#include "descriptor.hpp"
#include "listener.hpp"
#include "module_header.hpp"
#include "storage_worker.hpp"

namespace ito::mailbox {
namespace {

using module::Descriptor;

constexpr std::uint64_t kListenerKey = 1U;
constexpr std::uint64_t kSignalKey = 2U;
constexpr std::uint64_t kWakeKey = 3U;
constexpr std::uint64_t kStorageKey = 4U;
constexpr StreamId kFirstStream = 16U;

// A module header and one maximal request.
constexpr std::size_t kInputBytes =
    module::kMaxHeaderBytes + kMaxRequestFrameBytes;
// The longest reply and a refusal after it. Pushed items always leave this
// much room, so a request's reply never waits for space.
constexpr std::size_t kReplyReserve = kMaxOpenedFrameBytes + kStatusFrameBytes;
constexpr std::size_t kOutputBytes = kReplyReserve + 2U * kMaxItemFrameBytes;
constexpr std::size_t kAcceptsPerPass = 64U;
// Per-wake work bounds, so one busy stream cannot starve the others.
constexpr std::size_t kWriteBytesPerPass = 256U * 1024U;
constexpr std::size_t kDiscardBytesPerPass = 64U * 1024U;
constexpr int kEventsPerWait = 64;
constexpr std::chrono::milliseconds kAcceptRetry{100};
// Wall-clock deadlines are checked at least this often, so a clock change
// is noticed.
constexpr std::chrono::seconds kLongestWait{60};

enum class Phase {
    // Reading the module header.
    Header,
    // Admitted: reading requests, replying and pushing items.
    Serving,
    // Flushing what the stream holds, then closing at end of stream or at
    // the drain deadline. Input is read and discarded.
    Draining,
};

// The request whose reply waits for a storage job.
enum class Awaiting {
    None,
    Open,
    Close,
    Deposit,
};

struct Stream final {
    Stream(StreamId stream_id, Descriptor descriptor)
        : id(stream_id),
          socket(std::move(descriptor)),
          input(new std::byte[kInputBytes]),
          output(new std::byte[kOutputBytes]) {}
    Stream(const Stream&) = delete;
    Stream& operator=(const Stream&) = delete;
    ~Stream() {
        // Input held inbox secrets and sealed bytes.
        ::explicit_bzero(input.get(), kInputBytes);
        ::explicit_bzero(output.get(), kOutputBytes);
    }

    [[nodiscard]] std::size_t output_size() const noexcept {
        return output_end - output_begin;
    }
    [[nodiscard]] std::size_t output_free() const noexcept {
        return kOutputBytes - output_size();
    }

    const StreamId id;
    Descriptor socket;
    Phase phase{Phase::Header};
    // Set while the table counts this stream.
    bool admitted{false};
    std::unique_ptr<std::byte[]> input;
    std::size_t input_size{0U};
    std::unique_ptr<std::byte[]> output;
    std::size_t output_begin{0U};
    std::size_t output_end{0U};
    Awaiting awaiting{Awaiting::None};
    std::uint64_t awaited_job{0U};
    std::vector<Address> open_addresses;
    ItemId deposit_id{};
    std::uint32_t deposit_granted{0U};
    // The header and the first frame share one parse budget.
    bool first_frame{true};
    // Edge-triggered readiness: unread input may remain until a read
    // returns EAGAIN.
    bool read_ready{true};
    bool eof{false};
    bool write_shut{false};
    bool write_broken{false};
    bool in_ready{false};
    bool in_dirty{false};
    // Set while process_input runs for this stream. A reply's write can
    // free room for the next request, and the running call handles it once
    // the current request's bytes are consumed.
    bool processing{false};
    std::optional<TimePoint> parse_deadline;
    std::optional<TimePoint> idle_deadline;
    std::optional<TimePoint> drain_deadline;
    // Its entry in the timer set.
    std::optional<TimePoint> scheduled;
};

std::optional<TimePoint> earliest(std::optional<TimePoint> left,
                                  std::optional<TimePoint> right) noexcept {
    if (!left) return right;
    if (!right) return left;
    return std::min(*left, *right);
}

void append_number(std::string& line, std::string_view name,
                   std::uint64_t value) {
    line += ",\"";
    line += name;
    line += "\":";
    line += std::to_string(value);
}

template <std::size_t N>
void append_list(std::string& line, std::string_view name,
                 const std::array<std::uint64_t, N>& values) {
    line += ",\"";
    line += name;
    line += "\":[";
    for (std::size_t index = 0U; index < N; ++index) {
        if (index > 0U) line += ',';
        line += std::to_string(values[index]);
    }
    line += ']';
}

std::size_t status_index(Status status) noexcept {
    return static_cast<std::size_t>(status) - 1U;
}

}  // namespace

std::int64_t system_wall_clock() noexcept {
    timespec now{};
    ::clock_gettime(CLOCK_REALTIME, &now);
    return static_cast<std::int64_t>(now.tv_sec);
}

bool consistent_limits(const Limits& limits) noexcept {
    using std::chrono::milliseconds;
    using std::chrono::seconds;
    if (limits.max_streams == 0U || limits.max_streams > 65'536U ||
        limits.max_streams_per_principal == 0U || limits.max_principals == 0U ||
        limits.max_inboxes == 0U || limits.max_inboxes_per_principal == 0U ||
        limits.max_inboxes_per_principal > kMaxSecretsPerOpen * 1024U ||
        limits.max_items_per_inbox == 0U || limits.max_rings_per_inbox == 0U ||
        limits.registration_days == 0U)
        return false;
    if (limits.max_bytes_per_inbox < kLargeItemBytes ||
        limits.max_ring_bytes < kLargeItemBytes ||
        limits.store_bytes < kBlockBytes || limits.store_bytes > kMaxStoreBytes)
        return false;
    if (limits.ring_lifetime <= seconds::zero() ||
        limits.hold_time <= seconds::zero() ||
        limits.hold_time > seconds(kMaxHoldDays * 86'400LL) ||
        limits.rate_window <= milliseconds::zero() ||
        limits.parse_budget <= milliseconds::zero() ||
        limits.idle_timeout <= milliseconds::zero() ||
        limits.drain_budget <= milliseconds::zero())
        return false;
    return true;
}

std::string format_counts(const MailboxCounts& counts) {
    std::string line = "{\"ito_mailbox\":\"counts\"";
    append_number(line, "streams", counts.table.streams);
    append_number(line, "principals", counts.table.principals);
    append_number(line, "inboxes", counts.table.inboxes);
    append_number(line, "messages", counts.table.messages);
    append_number(line, "rings", counts.table.rings);
    append_number(line, "store_bytes", counts.table.store_bytes);
    append_number(line, "ring_bytes", counts.table.ring_bytes);
    append_number(line, "pending_jobs", counts.pending_jobs);
    append_number(line, "accepted", counts.accepted);
    append_number(line, "untrusted_peers", counts.untrusted_peers);
    append_number(line, "over_capacity", counts.over_capacity);
    append_number(line, "rejected_headers", counts.rejected_headers);
    append_number(line, "delivered", counts.delivered);
    append_number(line, "taken", counts.table.taken);
    append_number(line, "expired_messages", counts.table.expired_messages);
    append_number(line, "expired_rings", counts.table.expired_rings);
    append_number(line, "ended_inboxes", counts.table.ended_inboxes);
    append_number(line, "lost_messages", counts.table.lost_messages);
    append_number(line, "disk_full", counts.disk_full);
    append_list(line, "open_statuses", counts.open_statuses);
    append_list(line, "close_statuses", counts.close_statuses);
    append_list(line, "deposit_statuses", counts.deposit_statuses);
    append_list(line, "refusals", counts.refusals);
    line += "}\n";
    return line;
}

struct Mailbox::State final {
    State(Descriptor listening, Descriptor signal_source,
          MailboxOptions mailbox_options, Store opened, RandomSource& random)
        : options(std::move(mailbox_options)),
          limits(options.limits),
          listener(std::move(listening)),
          signals(std::move(signal_source)),
          store(std::move(opened)),
          table(options.limits, random) {}

    int run();
    void dispatch(const epoll_event& event);
    [[nodiscard]] int wait_milliseconds() const noexcept;
    void refresh_now() noexcept;

    // Streams.
    Stream* find(StreamId id) noexcept;
    void accept_streams();
    void add_stream(Descriptor connection);
    void read(Stream& stream);
    void read_requests(Stream& stream);
    void read_discard(Stream& stream);
    void write(Stream& stream);
    void close_stream(Stream& stream) noexcept;
    void close_all() noexcept;

    // Requests and replies.
    void process_input(Stream& stream);
    void process_requests(StreamId id);
    void consume_input(Stream& stream, std::size_t count) noexcept;
    void handle(Stream& stream, const Request& request);
    void handle_open(Stream& stream, const OpenRequest& request);
    void handle_close(Stream& stream, const CloseRequest& request);
    void handle_deposit(Stream& stream, const DepositRequest& request);
    void finish_open(Stream& stream);
    void await(Stream& stream, Awaiting kind, std::uint64_t job) noexcept;
    void resume(Stream& stream);
    std::span<std::byte> output_space(Stream& stream,
                                      std::size_t bytes) noexcept;
    void commit_output(Stream& stream, std::size_t bytes) noexcept;
    void fill(Stream& stream);

    // Storage.
    std::uint64_t submit(Jobs& work, StreamId waiting = 0U);
    void take_finished();
    void finished(Job& job);

    // Endings.
    void refuse(Stream& stream, RefusalReason reason);
    void begin_drain(Stream& stream);
    void leave_table(Stream& stream) noexcept;

    // Timers and scheduling.
    void fire_timers();
    void on_deadline(Stream& stream);
    void touch(Stream& stream) noexcept;
    void mark_ready(Stream& stream) noexcept;
    void run_ready();
    void settle();
    void reschedule(Stream& stream);
    void read_signals();
    void report_counts() noexcept;
    [[nodiscard]] MailboxCounts snapshot() const noexcept;

    const MailboxOptions options;
    const Limits& limits;
    Descriptor listener;
    Descriptor signals;
    Descriptor wake;
    Descriptor epoll;
    // The worker refers to the store, so it is declared after it and
    // destroyed first.
    Store store;
    std::unique_ptr<StorageWorker> worker;
    MailboxTable table;
    std::map<StreamId, std::unique_ptr<Stream>> streams;
    std::set<std::pair<TimePoint, StreamId>> timers;
    // Reserved to twice the stream limit at creation, so adding a stream id
    // never allocates. Each stream appears at most once in each.
    std::vector<StreamId> ready;
    std::vector<StreamId> ready_batch;
    std::vector<StreamId> dirty;
    std::vector<StreamId> dirty_batch;
    std::vector<StreamId> woken;
    Jobs work;
    std::vector<std::unique_ptr<Job>> returned;
    StreamId next_stream{kFirstStream};
    bool accept_pending{false};
    std::optional<TimePoint> accept_retry;
    bool stopping{false};
    bool failed{false};
    MailboxCounts counted;
    Now now;
};

std::unique_ptr<Mailbox> Mailbox::create(int listener, int signals,
                                         MailboxOptions options, Store store,
                                         std::vector<LoadedInbox> loaded,
                                         RandomSource& random,
                                         CreateError& error) {
    Descriptor listening(listener);
    Descriptor signal_source(signals);
    error = CreateError::Options;
    if (!consistent_limits(options.limits) ||
        !module::valid_service_name(options.service))
        return nullptr;
    if (!options.wall_clock) options.wall_clock = system_wall_clock;
    error = CreateError::Resources;
    try {
        const int flags = ::fcntl(listening.get(), F_GETFL);
        if (flags < 0 ||
            ::fcntl(listening.get(), F_SETFL, flags | O_NONBLOCK) != 0)
            return nullptr;
        auto state = std::make_unique<State>(
            std::move(listening), std::move(signal_source), std::move(options),
            std::move(store), random);
        for (auto& inbox : loaded) {
            if (!state->table.import(std::move(inbox))) {
                error = CreateError::DuplicateItem;
                return nullptr;
            }
        }
        loaded.clear();
        state->worker = StorageWorker::start(state->store);
        state->epoll = Descriptor(::epoll_create1(EPOLL_CLOEXEC));
        state->wake = Descriptor(::eventfd(0U, EFD_NONBLOCK | EFD_CLOEXEC));
        if (!state->worker || state->epoll.get() < 0 || state->wake.get() < 0)
            return nullptr;
        const auto watch = [&](int descriptor, std::uint64_t key,
                               std::uint32_t events) {
            epoll_event event{};
            event.events = events;
            event.data.u64 = key;
            return ::epoll_ctl(state->epoll.get(), EPOLL_CTL_ADD, descriptor,
                               &event) == 0;
        };
        if (!watch(state->listener.get(), kListenerKey, EPOLLIN | EPOLLET) ||
            !watch(state->wake.get(), kWakeKey, EPOLLIN) ||
            !watch(state->worker->completion_descriptor(), kStorageKey,
                   EPOLLIN) ||
            (state->signals.get() >= 0 &&
             !watch(state->signals.get(), kSignalKey, EPOLLIN)))
            return nullptr;
        const std::size_t ids = 2U * state->limits.max_streams;
        state->ready.reserve(ids);
        state->ready_batch.reserve(ids);
        state->dirty.reserve(ids);
        state->dirty_batch.reserve(ids);
        state->refresh_now();
        return std::unique_ptr<Mailbox>(new Mailbox(std::move(state)));
    } catch (const std::bad_alloc&) {
        return nullptr;
    }
}

Mailbox::Mailbox(std::unique_ptr<State> state) noexcept
    : state_(std::move(state)) {}
Mailbox::~Mailbox() = default;

int Mailbox::run() noexcept {
    try {
        return state_->run();
    } catch (...) {
        // An allocation failure the loop could not attribute to one stream.
        // Stored messages and registrations survive on disk.
        state_->close_all();
        return 1;
    }
}

void Mailbox::stop() noexcept {
    const std::uint64_t one = 1U;
    [[maybe_unused]] const auto written =
        ::write(state_->wake.get(), &one, sizeof one);
}

MailboxCounts Mailbox::counts() const noexcept {
    return state_->snapshot();
}

void Mailbox::State::refresh_now() noexcept {
    now.steady = Clock::now();
    now.unix_seconds = options.wall_clock();
}

int Mailbox::State::run() {
    std::array<epoll_event, kEventsPerWait> events{};
    while (!stopping && !failed) {
        refresh_now();
        const int count = ::epoll_wait(epoll.get(), events.data(),
                                       kEventsPerWait, wait_milliseconds());
        if (count < 0) {
            if (errno == EINTR) continue;
            close_all();
            return 1;
        }
        refresh_now();
        // Items and registrations whose time ended leave before this pass
        // serves anything, so no request or delivery acts on them, even
        // after the host's clock jumped.
        table.expire(now, work);
        submit(work);
        for (std::size_t index = 0U;
             index < static_cast<std::size_t>(count) && !stopping && !failed;
             ++index)
            dispatch(events[index]);
        if (stopping || failed) break;
        if (accept_retry && *accept_retry <= now.steady) {
            accept_retry.reset();
            accept_pending = true;
        }
        if (accept_pending) accept_streams();
        run_ready();
        fire_timers();
        settle();
    }
    close_all();
    return failed ? 1 : 0;
}

int Mailbox::State::wait_milliseconds() const noexcept {
    if (accept_pending || !ready.empty()) return 0;
    std::optional<TimePoint> next = table.next_deadline();
    if (!timers.empty()) next = earliest(next, timers.begin()->first);
    next = earliest(next, accept_retry);
    // A wall-clock deadline, measured from the wall clock now.
    if (const auto wall = table.next_wall_deadline()) {
        const auto ahead = std::chrono::seconds(
            std::max<std::int64_t>(*wall - now.unix_seconds, 0));
        next = earliest(
            next, now.steady + std::min<Clock::duration>(ahead, kLongestWait));
    }
    if (!next) return -1;
    if (*next <= now.steady) return 0;
    const auto wait =
        std::chrono::ceil<std::chrono::milliseconds>(*next - now.steady)
            .count();
    return static_cast<int>(
        std::min<std::int64_t>(wait, std::numeric_limits<int>::max()));
}

void Mailbox::State::dispatch(const epoll_event& event) {
    switch (event.data.u64) {
        case kListenerKey:
            accept_pending = true;
            return;
        case kWakeKey: {
            std::uint64_t value = 0U;
            [[maybe_unused]] const auto drained =
                ::read(wake.get(), &value, sizeof value);
            stopping = true;
            return;
        }
        case kSignalKey:
            read_signals();
            return;
        case kStorageKey:
            take_finished();
            return;
        default:
            break;
    }
    const StreamId id = event.data.u64;
    Stream* stream = find(id);
    if (!stream) return;
    if ((event.events & (EPOLLIN | EPOLLRDHUP | EPOLLHUP | EPOLLERR)) != 0U)
        stream->read_ready = true;
    if (stream->read_ready) {
        read(*stream);
        stream = find(id);
        if (!stream) return;
    }
    if ((event.events & (EPOLLOUT | EPOLLHUP | EPOLLERR)) != 0U) write(*stream);
}

Stream* Mailbox::State::find(StreamId id) noexcept {
    const auto found = streams.find(id);
    return found == streams.end() ? nullptr : found->second.get();
}

void Mailbox::State::accept_streams() {
    accept_pending = false;
    for (std::size_t pass = 0U; pass < kAcceptsPerPass; ++pass) {
        const int accepted = ::accept4(listener.get(), nullptr, nullptr,
                                       SOCK_NONBLOCK | SOCK_CLOEXEC);
        if (accepted < 0) {
            if (errno == EINTR || errno == ECONNABORTED) continue;
            if (errno != EAGAIN && errno != EWOULDBLOCK)
                accept_retry = now.steady + kAcceptRetry;
            return;
        }
        Descriptor connection(accepted);
        if (streams.size() >= limits.max_streams) {
            ++counted.over_capacity;
            continue;
        }
        ucred peer{};
        socklen_t length = sizeof peer;
        if (::getsockopt(connection.get(), SOL_SOCKET, SO_PEERCRED, &peer,
                         &length) != 0 ||
            length != sizeof peer ||
            !module::trusted_peer(peer.uid, options.daemon_uid)) {
            // Its header could be forged. Close before reading a byte.
            ++counted.untrusted_peers;
            continue;
        }
        add_stream(std::move(connection));
    }
    accept_pending = true;
}

void Mailbox::State::add_stream(Descriptor connection) {
    const StreamId id = next_stream++;
    std::unique_ptr<Stream> created;
    try {
        created = std::make_unique<Stream>(id, std::move(connection));
    } catch (const std::bad_alloc&) {
        return;
    }
    epoll_event event{};
    event.events = EPOLLIN | EPOLLOUT | EPOLLRDHUP | EPOLLET;
    event.data.u64 = id;
    if (::epoll_ctl(epoll.get(), EPOLL_CTL_ADD, created->socket.get(),
                    &event) != 0)
        return;
    created->parse_deadline = now.steady + limits.parse_budget;
    Stream& stream = *created;
    try {
        streams.emplace(id, std::move(created));
    } catch (const std::bad_alloc&) {
        return;
    }
    ++counted.accepted;
    touch(stream);
    mark_ready(stream);
}

void Mailbox::State::read(Stream& stream) {
    if (stream.phase == Phase::Draining) {
        read_discard(stream);
        return;
    }
    read_requests(stream);
}

void Mailbox::State::read_requests(Stream& first) {
    const StreamId id = first.id;
    for (;;) {
        Stream* stream = find(id);
        if (!stream) return;
        if (stream->phase == Phase::Draining) {
            if (stream->read_ready) mark_ready(*stream);
            return;
        }
        const std::size_t space = kInputBytes - stream->input_size;
        if (space == 0U) {
            // A whole request waits for its turn. Reading resumes when it
            // is handled.
            process_input(*stream);
            return;
        }
        const ssize_t got =
            ::recv(stream->socket.get(),
                   stream->input.get() + stream->input_size, space, 0);
        if (got > 0) {
            stream->input_size += static_cast<std::size_t>(got);
            process_input(*stream);
            continue;
        }
        if (got == 0 || errno == ECONNRESET) {
            stream->eof = true;
            stream->read_ready = false;
            process_input(*stream);
            return;
        }
        if (errno == EINTR) continue;
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            stream->read_ready = false;
            return;
        }
        close_stream(*stream);
        return;
    }
}

void Mailbox::State::read_discard(Stream& first) {
    const StreamId id = first.id;
    std::size_t budget = kDiscardBytesPerPass;
    std::array<std::byte, 16U * 1024U> scratch;
    for (;;) {
        Stream* stream = find(id);
        if (!stream || stream->phase != Phase::Draining) return;
        const ssize_t got = ::recv(stream->socket.get(), scratch.data(),
                                   std::min(scratch.size(), budget), 0);
        if (got > 0) {
            budget -= static_cast<std::size_t>(got);
            if (budget == 0U) {
                mark_ready(*stream);
                return;
            }
            continue;
        }
        if (got == 0 || errno == ECONNRESET) {
            stream->eof = true;
            stream->read_ready = false;
            if (stream->output_size() == 0U) close_stream(*stream);
            return;
        }
        if (errno == EINTR) continue;
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            stream->read_ready = false;
            return;
        }
        close_stream(*stream);
        return;
    }
}

void Mailbox::State::write(Stream& stream) {
    if (stream.write_broken) return;
    const StreamId id = stream.id;
    std::size_t budget = kWriteBytesPerPass;
    bool progress = false;
    for (;;) {
        if (stream.output_size() == 0U) {
            fill(stream);
            if (stream.output_size() == 0U) break;
        }
        const std::size_t length = std::min(stream.output_size(), budget);
        const ssize_t sent = ::send(stream.socket.get(),
                                    stream.output.get() + stream.output_begin,
                                    length, MSG_NOSIGNAL | MSG_DONTWAIT);
        if (sent > 0) {
            const auto count = static_cast<std::size_t>(sent);
            ::explicit_bzero(stream.output.get() + stream.output_begin, count);
            stream.output_begin += count;
            if (stream.output_begin == stream.output_end)
                stream.output_begin = stream.output_end = 0U;
            budget -= count;
            progress = true;
            if (budget == 0U) {
                // The rest waits for the next pass.
                touch(stream);
                return;
            }
            fill(stream);
            continue;
        }
        if (sent < 0 && errno == EINTR) continue;
        if (sent < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) break;
        stream.write_broken = true;
        close_stream(stream);
        return;
    }
    if (progress && stream.phase == Phase::Serving) {
        // Room for the next reply: a request may be waiting for it.
        process_input(stream);
        if (!find(id)) return;
    }
    if (stream.output_size() == 0U && stream.phase == Phase::Draining) {
        if (!stream.write_shut) {
            ::shutdown(stream.socket.get(), SHUT_WR);
            stream.write_shut = true;
        }
        if (stream.eof) {
            close_stream(stream);
            return;
        }
    }
    touch(stream);
}

void Mailbox::State::close_stream(Stream& stream) noexcept {
    leave_table(stream);
    if (stream.scheduled) timers.erase({*stream.scheduled, stream.id});
    // Closing the descriptor also removes it from the epoll set. A storage
    // job this stream waits for still updates the table when it returns.
    streams.erase(stream.id);
}

void Mailbox::State::close_all() noexcept {
    for (auto& [id, stream] : streams) leave_table(*stream);
    timers.clear();
    streams.clear();
}

void Mailbox::State::leave_table(Stream& stream) noexcept {
    if (!stream.admitted) return;
    table.remove_stream(stream.id);
    stream.admitted = false;
}

// Requests.

void Mailbox::State::process_input(Stream& first) {
    if (first.processing) return;
    const StreamId id = first.id;
    first.processing = true;
    process_requests(id);
    if (Stream* stream = find(id)) stream->processing = false;
}

void Mailbox::State::process_requests(StreamId id) {
    for (;;) {
        Stream* stream = find(id);
        if (!stream) return;
        const std::span<const std::byte> input{stream->input.get(),
                                               stream->input_size};
        if (stream->phase == Phase::Header) {
            const auto header =
                module::parse_module_header(input, options.service);
            if (header.status == module::HeaderStatus::Incomplete) {
                if (stream->eof) close_stream(*stream);
                return;
            }
            if (header.status != module::HeaderStatus::Accepted) {
                // yumed writes canonical headers. Anything else is a
                // misconfigured daemon, never a client to answer.
                ++counted.rejected_headers;
                close_stream(*stream);
                return;
            }
            consume_input(*stream, header.consumed);
            bool admitted = false;
            try {
                admitted =
                    table.add_stream(stream->id, header.principal, now.steady);
            } catch (const std::bad_alloc&) {
                admitted = false;
            }
            stream->phase = Phase::Serving;
            if (!admitted) {
                refuse(*stream, RefusalReason::Capacity);
                return;
            }
            stream->admitted = true;
            stream->idle_deadline = now.steady + limits.idle_timeout;
            touch(*stream);
            continue;
        }
        if (stream->phase != Phase::Serving ||
            stream->awaiting != Awaiting::None)
            return;
        if (stream->output_free() < kReplyReserve) return;
        const auto parsed = parse_request(input);
        switch (parsed.status) {
            case RequestStatus::Incomplete:
                if (stream->eof) {
                    // Every whole request was answered. A partial one
                    // never completes.
                    leave_table(*stream);
                    begin_drain(*stream);
                    return;
                }
                if (stream->input_size > 0U && !stream->parse_deadline) {
                    stream->parse_deadline = now.steady + limits.parse_budget;
                    touch(*stream);
                } else if (stream->input_size == 0U && !stream->first_frame &&
                           stream->parse_deadline) {
                    stream->parse_deadline.reset();
                    touch(*stream);
                }
                if (stream->read_ready && stream->input_size < kInputBytes)
                    mark_ready(*stream);
                return;
            case RequestStatus::Invalid:
                refuse(*stream, RefusalReason::InvalidRequest);
                return;
            case RequestStatus::Unsupported:
                refuse(*stream, RefusalReason::UnsupportedProtocol);
                return;
            case RequestStatus::Decoded:
                break;
        }
        stream->first_frame = false;
        stream->parse_deadline.reset();
        stream->idle_deadline = now.steady + limits.idle_timeout;
        touch(*stream);
        handle(*stream, parsed.request);
        // The request's views into the input end here, and the bytes go.
        if ((stream = find(id))) consume_input(*stream, parsed.consumed);
        if (stream && stream->read_ready) mark_ready(*stream);
    }
}

void Mailbox::State::consume_input(Stream& stream, std::size_t count) noexcept {
    const std::size_t remaining = stream.input_size - count;
    std::memmove(stream.input.get(), stream.input.get() + count, remaining);
    ::explicit_bzero(stream.input.get() + remaining, count);
    stream.input_size = remaining;
}

void Mailbox::State::handle(Stream& stream, const Request& request) {
    if (const auto* open = std::get_if<OpenRequest>(&request)) {
        handle_open(stream, *open);
    } else if (const auto* close = std::get_if<CloseRequest>(&request)) {
        handle_close(stream, *close);
    } else if (const auto* deposit = std::get_if<DepositRequest>(&request)) {
        handle_deposit(stream, *deposit);
    } else if (const auto* taken = std::get_if<TakenRequest>(&request)) {
        table.take(stream.id, *taken, work);
        submit(work);
    } else {
        const auto space = output_space(stream, kSignalFrameBytes);
        commit_output(stream, encode_signal(FrameType::Pong, space));
    }
    write(stream);
}

void Mailbox::State::handle_open(Stream& stream, const OpenRequest& request) {
    stream.open_addresses.clear();
    if (!table.count_inbox_change(stream.id, now.steady)) {
        std::array<Status, kMaxSecretsPerOpen> statuses;
        statuses.fill(Status::Later);
        const std::span<const Status> answer(statuses.data(), request.count());
        counted.open_statuses[status_index(Status::Later)] += request.count();
        const auto space =
            output_space(stream, kFrameLengthBytes + 1U + answer.size());
        commit_output(stream, encode_opened(answer, space));
        return;
    }
    stream.open_addresses.reserve(request.count());
    for (std::size_t index = 0U; index < request.count(); ++index) {
        Secret secret = request.secret(index);
        stream.open_addresses.push_back(inbox_address(secret));
        ::explicit_bzero(secret.data(), secret.size());
    }
    const bool waits =
        table.begin_open(stream.id, stream.open_addresses, now, work);
    submit(work);
    if (waits) {
        // A barrier returns after every creation queued before it.
        auto barrier = std::make_unique<Job>();
        barrier->kind = Job::Kind::Barrier;
        work.push_back(std::move(barrier));
        await(stream, Awaiting::Open, submit(work, stream.id));
        return;
    }
    finish_open(stream);
}

void Mailbox::State::finish_open(Stream& stream) {
    std::array<Status, kMaxSecretsPerOpen> statuses;
    const std::span<Status> answer(statuses.data(),
                                   stream.open_addresses.size());
    table.finish_open(stream.id, stream.open_addresses, now, answer, work);
    submit(work);
    for (const Status status : answer)
        ++counted.open_statuses[status_index(status)];
    const auto space =
        output_space(stream, kFrameLengthBytes + 1U + answer.size());
    commit_output(stream, encode_opened(answer, space));
    stream.open_addresses.clear();
}

void Mailbox::State::handle_close(Stream& stream, const CloseRequest& request) {
    if (!table.count_inbox_change(stream.id, now.steady)) {
        ++counted.close_statuses[status_index(Status::Later)];
        commit_output(stream,
                      encode_status(FrameType::Closed, Status::Later,
                                    output_space(stream, kStatusFrameBytes)));
        return;
    }
    Secret secret = request.secret();
    const Address address = inbox_address(secret);
    ::explicit_bzero(secret.data(), secret.size());
    if (table.close(address, work)) {
        // The close job is the last one the table appended.
        await(stream, Awaiting::Close, submit(work, stream.id));
        return;
    }
    ++counted.close_statuses[status_index(Status::Done)];
    commit_output(stream,
                  encode_status(FrameType::Closed, Status::Done,
                                output_space(stream, kStatusFrameBytes)));
}

void Mailbox::State::handle_deposit(Stream& stream,
                                    const DepositRequest& request) {
    DepositOutcome outcome;
    if (table.count_deposit(stream.id, now.steady))
        outcome = table.deposit(request, now, work);
    if (outcome.status != Status::Done) {
        ++counted.deposit_statuses[status_index(outcome.status)];
        commit_output(stream,
                      encode_status(FrameType::Rejected, outcome.status,
                                    output_space(stream, kStatusFrameBytes)));
        return;
    }
    if (outcome.waits_for_write) {
        stream.deposit_id = outcome.id;
        stream.deposit_granted = outcome.granted_seconds;
        await(stream, Awaiting::Deposit, submit(work, stream.id));
        return;
    }
    ++counted.deposit_statuses[status_index(Status::Done)];
    commit_output(stream,
                  encode_deposited(outcome.id, outcome.granted_seconds,
                                   output_space(stream, kDepositedFrameBytes)));
}

void Mailbox::State::await(Stream& stream, Awaiting kind,
                           std::uint64_t job) noexcept {
    stream.awaiting = kind;
    stream.awaited_job = job;
    // Time spent on the disk is not the client's idle time.
    stream.idle_deadline.reset();
    touch(stream);
}

void Mailbox::State::resume(Stream& stream) {
    stream.awaiting = Awaiting::None;
    stream.awaited_job = 0U;
    stream.idle_deadline = now.steady + limits.idle_timeout;
    touch(stream);
    const StreamId id = stream.id;
    write(stream);
    if (Stream* still = find(id)) process_input(*still);
}

std::span<std::byte> Mailbox::State::output_space(Stream& stream,
                                                  std::size_t bytes) noexcept {
    if (stream.output_end + bytes > kOutputBytes) {
        const std::size_t held = stream.output_size();
        std::memmove(stream.output.get(),
                     stream.output.get() + stream.output_begin, held);
        stream.output_begin = 0U;
        stream.output_end = held;
    }
    // Callers check the room first: replies use the reserve that pushed
    // items leave, and items wait for room.
    return {stream.output.get() + stream.output_end, bytes};
}

void Mailbox::State::commit_output(Stream& stream, std::size_t bytes) noexcept {
    stream.output_end += bytes;
}

void Mailbox::State::fill(Stream& stream) {
    while (stream.phase == Phase::Serving && stream.admitted &&
           stream.output_free() >= kReplyReserve + kMaxItemFrameBytes) {
        const auto delivery = table.next_delivery(stream.id, now);
        if (!delivery) return;
        const std::size_t frame_bytes =
            kItemHeadBytes + delivery->head.sealed_bytes;
        const auto space = output_space(stream, frame_bytes);
        encode_item_head(delivery->head, space.first<kItemHeadBytes>());
        const auto sealed = space.subspan(kItemHeadBytes);
        if (delivery->ring_bytes != nullptr) {
            std::memcpy(sealed.data(), delivery->ring_bytes, sealed.size());
        } else {
            switch (store.read_message(delivery->head.address, delivery->name,
                                       sealed)) {
                case Store::ReadResult::Ok:
                    break;
                case Store::ReadResult::Missing:
                    ::explicit_bzero(space.data(), space.size());
                    table.drop_message(delivery->head.address,
                                       delivery->sequence, work);
                    submit(work);
                    continue;
                case Store::ReadResult::Failed:
                    ::explicit_bzero(space.data(), space.size());
                    failed = true;
                    return;
            }
        }
        commit_output(stream, frame_bytes);
        ++counted.delivered;
    }
}

// Storage.

std::uint64_t Mailbox::State::submit(Jobs& jobs, StreamId waiting) {
    std::uint64_t last = 0U;
    if (waiting != 0U && !jobs.empty()) jobs.back()->stream = waiting;
    for (auto& job : jobs) last = worker->submit(std::move(job));
    jobs.clear();
    return last;
}

void Mailbox::State::take_finished() {
    returned.clear();
    worker->take_finished(returned);
    for (auto& job : returned) {
        finished(*job);
        if (failed) break;
    }
    returned.clear();
}

void Mailbox::State::finished(Job& job) {
    if (job.result == IoResult::Failed) {
        // The disk may no longer match the table. Restart from the disk.
        failed = true;
        return;
    }
    if (job.result == IoResult::NoSpace) ++counted.disk_full;
    bool stored = false;
    switch (job.kind) {
        case Job::Kind::CreateInbox:
            table.inbox_created(job.address, job.generation,
                                job.result == IoResult::Ok);
            break;
        case Job::Kind::WriteMessage:
            stored = table.message_written(job);
            break;
        case Job::Kind::RenewRegistration:
        case Job::Kind::DeleteMessage:
        case Job::Kind::CloseInbox:
        case Job::Kind::Barrier:
            break;
    }
    if (job.stream == 0U) return;
    Stream* stream = find(job.stream);
    if (!stream || stream->awaited_job != job.sequence) return;
    switch (stream->awaiting) {
        case Awaiting::Open:
            finish_open(*stream);
            break;
        case Awaiting::Close:
            ++counted.close_statuses[status_index(Status::Done)];
            commit_output(
                *stream,
                encode_status(FrameType::Closed, Status::Done,
                              output_space(*stream, kStatusFrameBytes)));
            break;
        case Awaiting::Deposit:
            if (stored) {
                ++counted.deposit_statuses[status_index(Status::Done)];
                commit_output(*stream,
                              encode_deposited(
                                  stream->deposit_id, stream->deposit_granted,
                                  output_space(*stream, kDepositedFrameBytes)));
            } else {
                ++counted.deposit_statuses[status_index(Status::Later)];
                commit_output(
                    *stream,
                    encode_status(FrameType::Rejected, Status::Later,
                                  output_space(*stream, kStatusFrameBytes)));
            }
            break;
        case Awaiting::None:
            return;
    }
    resume(*stream);
}

// Endings.

void Mailbox::State::refuse(Stream& stream, RefusalReason reason) {
    ++counted.refusals[static_cast<std::size_t>(reason) - 1U];
    leave_table(stream);
    const auto space = output_space(stream, kStatusFrameBytes);
    commit_output(stream, encode_refused(reason, space));
    begin_drain(stream);
}

void Mailbox::State::begin_drain(Stream& stream) {
    const StreamId id = stream.id;
    stream.phase = Phase::Draining;
    stream.parse_deadline.reset();
    stream.idle_deadline.reset();
    stream.drain_deadline = now.steady + limits.drain_budget;
    ::explicit_bzero(stream.input.get(), stream.input_size);
    stream.input_size = 0U;
    touch(stream);
    write(stream);
    if (Stream* still = find(id); still && still->read_ready)
        mark_ready(*still);
}

// Timers.

void Mailbox::State::fire_timers() {
    while (!timers.empty() && timers.begin()->first <= now.steady) {
        const StreamId id = timers.begin()->second;
        timers.erase(timers.begin());
        Stream* stream = find(id);
        if (!stream) continue;
        stream->scheduled.reset();
        on_deadline(*stream);
        if ((stream = find(id))) touch(*stream);
    }
}

void Mailbox::State::on_deadline(Stream& stream) {
    if (stream.drain_deadline && *stream.drain_deadline <= now.steady) {
        close_stream(stream);
        return;
    }
    if (stream.parse_deadline && *stream.parse_deadline <= now.steady) {
        stream.parse_deadline.reset();
        if (stream.phase == Phase::Header) {
            ++counted.rejected_headers;
            close_stream(stream);
        } else {
            refuse(stream, RefusalReason::Timeout);
        }
        return;
    }
    if (stream.idle_deadline && *stream.idle_deadline <= now.steady) {
        stream.idle_deadline.reset();
        refuse(stream, RefusalReason::Timeout);
    }
}

void Mailbox::State::touch(Stream& stream) noexcept {
    if (stream.in_dirty) return;
    stream.in_dirty = true;
    dirty.push_back(stream.id);
}

void Mailbox::State::mark_ready(Stream& stream) noexcept {
    if (stream.in_ready) return;
    stream.in_ready = true;
    ready.push_back(stream.id);
}

void Mailbox::State::run_ready() {
    ready_batch.swap(ready);
    for (const StreamId id : ready_batch) {
        Stream* stream = find(id);
        if (!stream) continue;
        stream->in_ready = false;
        if (stream->read_ready) read(*stream);
    }
    ready_batch.clear();
}

void Mailbox::State::settle() {
    // New items reach their subscribed streams.
    table.take_woken(woken);
    for (const StreamId id : woken) {
        if (Stream* stream = find(id)) write(*stream);
        if (failed) return;
    }
    // Rescheduling can end a stream, so repeat until none is left.
    while (!dirty.empty()) {
        dirty_batch.swap(dirty);
        for (const StreamId id : dirty_batch) {
            Stream* stream = find(id);
            if (!stream) continue;
            stream->in_dirty = false;
            reschedule(*stream);
        }
        dirty_batch.clear();
    }
}

void Mailbox::State::reschedule(Stream& stream) {
    const auto due =
        earliest(earliest(stream.parse_deadline, stream.idle_deadline),
                 stream.drain_deadline);
    if (due == stream.scheduled) return;
    if (stream.scheduled) timers.erase({*stream.scheduled, stream.id});
    stream.scheduled.reset();
    if (!due) return;
    try {
        timers.emplace(*due, stream.id);
        stream.scheduled = due;
    } catch (const std::bad_alloc&) {
        // A stream without its deadline could outlive every bound.
        close_stream(stream);
    }
}

void Mailbox::State::read_signals() {
    signalfd_siginfo info{};
    while (::read(signals.get(), &info, sizeof info) ==
           static_cast<ssize_t>(sizeof info)) {
        if (info.ssi_signo == SIGUSR1) {
            report_counts();
        } else {
            stopping = true;
        }
    }
}

void Mailbox::State::report_counts() noexcept {
    try {
        const auto line = format_counts(snapshot());
        [[maybe_unused]] const auto written =
            ::write(STDERR_FILENO, line.data(), line.size());
    } catch (const std::bad_alloc&) {
        // Counts are diagnostics. The mailbox keeps serving without them.
    }
}

MailboxCounts Mailbox::State::snapshot() const noexcept {
    MailboxCounts counts = counted;
    counts.table = table.counts();
    counts.pending_jobs = worker ? worker->outstanding() : 0U;
    return counts;
}

}  // namespace ito::mailbox
