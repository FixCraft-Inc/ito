/* Copyright (C) 2026 FixCraft Inc. AGPL-3.0-or-later. */

// A stand-in for the mailbox service (docs/MAILBOX.md) on one machine, so
// two Linux endpoints can pair without a server: a private directory with
// one subdirectory per inbox and one file per item. It is a development
// tool. It checks no inbox secret and keeps no hold time, so anyone who can
// read the directory can read and take every item. Items are sealed, so it
// learns no more than a real mailbox does.

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace ito::cli {

// Where an item goes: a mailbox (server fingerprint and service name) and
// an inbox address on it.
struct MailboxTarget final {
    std::array<std::uint8_t, 32> server{};
    std::string service;
    std::array<std::uint8_t, 32> address{};
};

struct StubItem final {
    std::string name;
    std::vector<std::uint8_t> bytes;
};

class StubMailbox final {
public:
    // Creates the directory 0700 when absent. Refuses links, other owners
    // and group or world access.
    explicit StubMailbox(std::string directory);

    // Adds the item to the target's inbox as one new file, published by a
    // rename after it is synced. Items are 1024, 4096 or 16384 bytes.
    void deposit(const MailboxTarget& target, const std::uint8_t* item,
                 std::size_t size) const;
    // The items waiting in the target's inbox, oldest first. A link, a
    // special file, another owner's file or a wrong size is refused.
    [[nodiscard]] std::vector<StubItem> waiting(
        const MailboxTarget& target) const;
    // Removes an item the endpoint has taken.
    void take(const MailboxTarget& target, const std::string& name) const;

private:
    [[nodiscard]] std::string inbox(const MailboxTarget& target) const;

    std::string directory_;
};

}  // namespace ito::cli
