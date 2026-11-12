/* Copyright (C) 2026 FixCraft Inc. AGPL-3.0-or-later. */

#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>

namespace ito::mailbox {

// The version-1 limits of docs/MAILBOX.md, "Limits". The operator sets the
// hold time and may lower the store size. Tests build smaller values to reach
// time and size bounds without waiting for them.
struct Limits final {
    std::size_t max_streams{1024U};
    std::size_t max_streams_per_principal{4U};
    std::size_t max_principals{16384U};
    std::size_t max_inboxes{65536U};
    std::size_t max_inboxes_per_principal{512U};
    std::size_t max_items_per_inbox{512U};
    std::uint64_t max_bytes_per_inbox{8U * 1024U * 1024U};
    std::size_t max_rings_per_inbox{4U};
    // Sealed ring bytes the service holds in memory, across every inbox.
    std::uint64_t max_ring_bytes{32U * 1024U * 1024U};
    // The store's size in whole blocks: one per inbox, and each message's
    // size rounded up.
    std::uint64_t store_bytes{2ULL * 1024U * 1024U * 1024U};
    std::chrono::seconds ring_lifetime{60};
    // The longest lifetime a message is granted.
    std::chrono::seconds hold_time{7 * 86'400};
    // A registration ends at 00:00 UTC this many days after its last OPEN.
    std::uint32_t registration_days{30U};
    std::chrono::milliseconds rate_window{60'000};
    // Bounds the module header with the first frame, and each later frame
    // from its first byte.
    std::chrono::milliseconds parse_budget{5'000};
    std::chrono::milliseconds idle_timeout{600'000};
    // Time a refused stream may spend flushing what it holds and waiting for
    // the peer's end of stream before the descriptor closes.
    std::chrono::milliseconds drain_budget{1'000};
};

// The rolling-window quotas. They size the retained timestamp buckets, so
// they are constants.
inline constexpr std::size_t kMaxDepositsPerWindow = 120U;
inline constexpr std::size_t kMaxInboxChangesPerWindow = 30U;

inline constexpr std::uint64_t kBlockBytes = 4096U;
inline constexpr std::uint32_t kMinHoldDays = 1U;
inline constexpr std::uint32_t kMaxHoldDays = 30U;
inline constexpr std::uint64_t kMaxStoreBytes = 2ULL * 1024U * 1024U * 1024U;

// The store blocks an item of size bytes occupies.
[[nodiscard]] constexpr std::uint64_t blocks_for(std::uint64_t size) noexcept {
    return (size + kBlockBytes - 1U) / kBlockBytes * kBlockBytes;
}

}  // namespace ito::mailbox
