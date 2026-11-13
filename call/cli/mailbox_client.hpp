/* Copyright (C) 2026 FixCraft Inc. AGPL-3.0-or-later. */

// The client side of the mailbox framing (docs/MAILBOX.md) over one byte
// stream: OPEN, DEPOSIT and TAKEN from a phone, and the ITEM frames the
// service pushes. Replies come in request order. ITEM frames that arrive
// before a reply are kept for next_item.

#pragma once

#include <ito/call.h>

#include <array>
#include <cstdint>
#include <deque>
#include <optional>
#include <stdexcept>
#include <vector>

namespace ito::cli {

using MailboxAddress = std::array<std::uint8_t, 32>;
using InboxSecret = std::array<std::uint8_t, 32>;
using ItemId = std::array<std::uint8_t, 16>;

inline constexpr std::uint8_t kMessageClass = 1U;
inline constexpr std::uint8_t kStatusDone = 1U;

struct MailboxItem final {
    MailboxAddress address{};
    ItemId id{};
    std::uint8_t item_class{0U};
    std::uint32_t deposit_minute{0U};
    std::uint32_t seconds_left{0U};
    std::vector<std::uint8_t> sealed;
};

// The service refused a request or the stream, or broke the framing.
struct MailboxError final : std::runtime_error {
    using std::runtime_error::runtime_error;
};

class MailboxClient final {
public:
    explicit MailboxClient(const ito_transport& transport) noexcept
        : transport_(transport) {}

    // Registers and subscribes the inboxes, and returns one status per
    // secret, in order. The items they hold follow as ITEM frames.
    [[nodiscard]] std::vector<std::uint8_t> open(
        const std::vector<InboxSecret>& secrets);
    // Stores a sealed item and returns the lifetime the service granted.
    // Throws MailboxError with the REJECTED status.
    std::uint32_t deposit(const MailboxAddress& address,
                          std::uint8_t item_class, std::uint32_t lifetime,
                          const std::uint8_t* sealed, std::size_t size);
    // Tells the service these items are stored. It has no reply.
    void taken(const std::vector<ItemId>& ids);
    // The next pushed item, or nothing when none begins within timeout_ms.
    [[nodiscard]] std::optional<MailboxItem> next_item(
        std::uint32_t timeout_ms);

private:
    struct Frame final {
        std::uint8_t type{0U};
        std::vector<std::uint8_t> payload;
    };

    void write_frame(std::uint8_t type,
                     const std::vector<std::uint8_t>& payload);
    // Fills out completely. false when nothing arrived within timeout_ms and
    // idle is allowed. A frame already begun must finish within its budget.
    [[nodiscard]] bool read_exact(std::uint8_t* out, std::size_t size,
                                  std::uint32_t timeout_ms, bool idle);
    [[nodiscard]] std::optional<Frame> read_frame(std::uint32_t timeout_ms);
    // The reply of the given type to the last request. ITEM frames that
    // come first are queued.
    [[nodiscard]] Frame reply(std::uint8_t type);
    [[nodiscard]] static MailboxItem parse_item(const Frame& frame);

    ito_transport transport_;
    std::deque<MailboxItem> pushed_;
};

}  // namespace ito::cli
