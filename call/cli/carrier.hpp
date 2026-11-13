/* Copyright (C) 2026 FixCraft Inc. AGPL-3.0-or-later. */

// How the Linux endpoint moves sealed items: a stub directory on one
// machine, or a mailbox service (docs/MAILBOX.md) through one YUME stream.
// The core decides what each item is. The carrier only deposits, collects
// and takes.

#pragma once

#include <ito/message.h>

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "mailbox_client.hpp"

namespace ito::cli {

// An item waiting at one of the inboxes passed to collect.
struct WaitingItem final {
    std::size_t inbox{0U};
    std::string name;  // the stub's file name
    ItemId id{};       // the mailbox's item ID
    std::vector<std::uint8_t> bytes;
};

class Carrier {
public:
    Carrier() = default;
    Carrier(const Carrier&) = delete;
    Carrier& operator=(const Carrier&) = delete;
    virtual ~Carrier() = default;

    // Deposits an item at its target and returns the hold time granted, or
    // 0 when the carrier has none. Throws when the item is not stored.
    virtual std::uint32_t deposit(const ito_mailbox_target& target,
                                  const std::uint8_t* item, std::size_t size,
                                  bool ring = false) = 0;
    // Opens the inboxes this carrier has not opened yet. A mailbox refuses
    // deposits to an inbox nobody opened.
    virtual void open(const std::vector<ito_inbox>& inboxes) = 0;
    // Opens these inboxes and returns waiting items, oldest first per inbox.
    // restart replays untaken items; false keeps the current subscription.
    [[nodiscard]] virtual std::vector<WaitingItem> collect(
        const std::vector<ito_inbox>& inboxes, bool restart = true) = 0;
    // Removes an item the endpoint is done with.
    virtual void take(const std::vector<ito_inbox>& inboxes,
                      const WaitingItem& item) = 0;
    // The mailbox service this carrier reached and verified, if any.
    [[nodiscard]] virtual const ito_authority* authority() const noexcept = 0;
};

[[nodiscard]] std::unique_ptr<Carrier> stub_carrier(
    const std::string& directory);
// Opens service on the YUME client configured in config_dir. Throws
// std::runtime_error when the stream cannot be opened.
[[nodiscard]] std::unique_ptr<Carrier> mailbox_carrier(
    const std::string& config_dir, const std::string& resolver,
    const std::string& service);

}  // namespace ito::cli
