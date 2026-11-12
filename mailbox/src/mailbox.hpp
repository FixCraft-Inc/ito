/* Copyright (C) 2026 FixCraft Inc. AGPL-3.0-or-later. */

// The mailbox's event loop. One thread owns every stream, the table and the
// timers, so inbox state is serialized without locks. The storage worker's
// thread does the disk writes the loop decides on, and each finished job
// comes back to this thread before its reply is sent.

#pragma once

#include <sys/types.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <vector>

#include "limits.hpp"
#include "mailbox_table.hpp"
#include "store.hpp"
#include "wire.hpp"

namespace ito::mailbox {

struct MailboxOptions final {
    // The exact service name yumed writes in each module header.
    std::string service;
    // The only user, besides root, whose connections carry a trusted header.
    uid_t daemon_uid{0};
    Limits limits{};
    // The host's clock in Unix seconds. Tests replace it to reach expiries.
    std::function<std::int64_t()> wall_clock;
};

// Aggregate counts. They carry no principal, secret, address or item ID.
struct MailboxCounts final {
    TableCounts table;
    std::uint64_t accepted{0U};
    std::uint64_t untrusted_peers{0U};
    std::uint64_t over_capacity{0U};
    std::uint64_t rejected_headers{0U};
    std::uint64_t delivered{0U};
    std::uint64_t pending_jobs{0U};
    // Registrations and messages the disk had no room for.
    std::uint64_t disk_full{0U};
    // By status - 1: Done, NotHere, Later.
    std::array<std::uint64_t, 3> open_statuses{};
    std::array<std::uint64_t, 3> close_statuses{};
    std::array<std::uint64_t, 3> deposit_statuses{};
    std::array<std::uint64_t, kRefusalReasons> refusals{};
};

enum class CreateError {
    // The limits or the service name are inconsistent.
    Options,
    // The store holds an item ID twice.
    DuplicateItem,
    // The event loop or the storage worker could not be created.
    Resources,
};

class Mailbox final {
public:
    // Takes ownership of listener, a listening UNIX stream socket the caller
    // has checked, of signals, a signalfd delivering SIGTERM, SIGINT and
    // SIGUSR1, or -1, and of the store with what its scan loaded. Null on
    // failure, with error set.
    [[nodiscard]] static std::unique_ptr<Mailbox> create(
        int listener, int signals, MailboxOptions options, Store store,
        std::vector<LoadedInbox> loaded, RandomSource& random,
        CreateError& error);
    // Finishes the storage worker's queued jobs before it returns.
    ~Mailbox();

    Mailbox(const Mailbox&) = delete;
    Mailbox& operator=(const Mailbox&) = delete;

    // Serves until SIGTERM, SIGINT or stop(). Every stream is closed on
    // return. 0 after a requested stop, 1 when the event loop or the disk
    // failed.
    [[nodiscard]] int run() noexcept;
    // Asks a running loop to stop. Safe from any thread.
    void stop() noexcept;
    // Counts as of the last loop iteration. Call from the loop's thread or
    // after run() returned.
    [[nodiscard]] MailboxCounts counts() const noexcept;

    struct State;

private:
    explicit Mailbox(std::unique_ptr<State> state) noexcept;
    std::unique_ptr<State> state_;
};

// The host's clock in whole seconds since 1970-01-01 00:00 UTC, the wall
// clock a mailbox uses unless its options name another.
[[nodiscard]] std::int64_t system_wall_clock() noexcept;

// Whether the limits hold together, such as nonzero quotas and a hold time
// of one to 30 days.
[[nodiscard]] bool consistent_limits(const Limits& limits) noexcept;

// One line of JSON with the counts, newline included.
[[nodiscard]] std::string format_counts(const MailboxCounts& counts);

}  // namespace ito::mailbox
