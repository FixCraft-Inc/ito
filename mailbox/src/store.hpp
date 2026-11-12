/* Copyright (C) 2026 FixCraft Inc. AGPL-3.0-or-later. */

// The mailbox's data directory. It holds registrations and messages, never a
// principal, a secret or a ring:
//
//   format                      "ito/mailbox-store/1\n"
//   inboxes/<address hex>/      one directory per registered inbox
//     l1-<day hex>              empty file: the registration ends at 00:00
//                               UTC on this day (days since 1970-01-01)
//     i1-<order hex>-<id hex>-<deposit minute hex>-<expiry minute hex>
//                               a message's sealed bytes and nothing else
//     t1-<id hex>               a message being written
//
// Names carry the metadata, so a file holds exactly the sealed bytes and the
// startup scan reads directories only. Every operation works relative to the
// directory descriptors opened at startup, refuses symbolic links in the
// store, and reports a full disk apart from any other failure. The storage
// worker's thread calls the mutating operations in submission order. The
// event loop's thread reads messages at the same time, which is safe because
// the loop reads only messages whose write completed and that it has not
// handed to a delete.

#pragma once

#include <sys/types.h>

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string_view>
#include <vector>

#include "descriptor.hpp"
#include "wire.hpp"

namespace ito::mailbox {

// A message's on-disk identity: its file name's fields.
struct MessageName final {
    // The message's place in the store's deposit order. A later deposit has
    // a larger number, across restarts, so a restart keeps delivery oldest
    // first even within one minute.
    std::uint64_t order{0U};
    ItemId id{};
    std::uint32_t deposit_minute{0U};
    std::uint32_t expiry_minute{0U};
};

enum class IoResult {
    Ok,
    // The disk or the user's quota is full. Nothing of the operation remains.
    NoSpace,
    // Any other failure. The disk may no longer match what the service
    // believes, so the caller stops and restarts from the disk.
    Failed,
};

enum class StoreError {
    // The path is missing or is not a directory.
    NotDirectory,
    // The directory belongs to another user or is open to group or others.
    Unsafe,
    // It is not empty and holds no mailbox store, or holds an entry the store
    // never writes.
    NotStore,
    // Reading or initializing it failed.
    Unreadable,
    // Memory for the scan ran out.
    NoMemory,
};

[[nodiscard]] std::string_view describe(StoreError error) noexcept;

struct LoadedMessage final {
    MessageName name;
    std::uint32_t size{0U};
};

struct LoadedInbox final {
    Address address{};
    std::uint32_t registration_day{0U};
    std::vector<LoadedMessage> messages;
};

// What the startup scan removed. The counts hold no address or ID.
struct LoadCounts final {
    std::uint64_t ended_inboxes{0U};
    std::uint64_t unregistered_inboxes{0U};
    std::uint64_t expired_messages{0U};
    std::uint64_t damaged_messages{0U};
    std::uint64_t partial_writes{0U};
};

class Store final {
public:
    // Opens path, which must be a directory owned by owner with no group or
    // other permission, and initializes it when it is empty. The final path
    // component may be a symbolic link, as systemd's state directories are
    // for dynamic users. Nothing inside the store may be one.
    [[nodiscard]] static std::optional<Store> open(const char* path,
                                                   uid_t owner,
                                                   StoreError& error) noexcept;

    Store(Store&&) noexcept = default;
    Store& operator=(Store&&) noexcept = default;

    // Reads every registration and message. Removes registrations that ended
    // by today and their messages, directories without a registration (a
    // close or a creation the service did not finish), messages that expired
    // by now_minute or have a size no message has, and unfinished writes.
    [[nodiscard]] bool load(std::uint32_t today, std::uint32_t now_minute,
                            std::vector<LoadedInbox>& inboxes,
                            LoadCounts& counts, StoreError& error) noexcept;

    // Storage worker operations, each synced as docs/MAILBOX.md requires.
    [[nodiscard]] IoResult create_inbox(const Address& address,
                                        std::uint32_t day) const noexcept;
    [[nodiscard]] IoResult renew_registration(const Address& address,
                                              std::uint32_t day) const noexcept;
    [[nodiscard]] IoResult write_message(
        const Address& address, const MessageName& name,
        std::span<const std::byte> sealed) const noexcept;
    // A missing message is not a failure. The deletion is not synced.
    [[nodiscard]] IoResult delete_message(
        const Address& address, const MessageName& name) const noexcept;
    // Removes the registration and syncs that, then the messages and the
    // directory. A missing inbox is not a failure.
    [[nodiscard]] IoResult close_inbox(const Address& address) const noexcept;

    enum class ReadResult {
        Ok,
        // The file is gone or no longer has the message's size.
        Missing,
        Failed,
    };
    // Reads a message's sealed bytes, exactly out.size() of them.
    [[nodiscard]] ReadResult read_message(
        const Address& address, const MessageName& name,
        std::span<std::byte> out) const noexcept;

private:
    explicit Store(module::Descriptor root, module::Descriptor inboxes) noexcept
        : root_(std::move(root)), inboxes_(std::move(inboxes)) {}

    module::Descriptor root_;
    module::Descriptor inboxes_;
};

}  // namespace ito::mailbox
