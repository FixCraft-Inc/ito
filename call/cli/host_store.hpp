/* Copyright (C) 2026 FixCraft Inc. AGPL-3.0-or-later. */

// The Linux endpoint's host test store: the core's plaintext snapshot in one
// owner-only file, each contact's session snapshot in sessions/, and the
// messages received from each contact in history/, every file replaced or
// created atomically. It is a test and development store. Unlike Android's
// Keystore-sealed store it encrypts nothing, so the directory's permissions
// are its only protection.

#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace ito::cli {

class HostStore final {
public:
    // Creates the directory 0700 when absent. Refuses links, other owners
    // and group or world access. Holds an exclusive lock on the store for
    // this object's life, so a second process cannot interleave snapshots
    // or overwrite a spent record with an older state.
    explicit HostStore(std::string directory);
    HostStore(const HostStore&) = delete;
    HostStore& operator=(const HostStore&) = delete;
    ~HostStore();

    // Reads the snapshot. An absent file is an empty snapshot. Throws
    // std::runtime_error with a fixed message for unreadable state.
    [[nodiscard]] std::vector<std::uint8_t> load() const;
    // Writes a private temporary file, syncs it and renames it over the
    // snapshot. Returns an ITO_PERSIST_* result.
    [[nodiscard]] int persist(const std::uint8_t* bytes,
                              std::size_t size) const;

    // The same for one contact's session, named by the contact's key in hex.
    [[nodiscard]] std::vector<std::uint8_t> load_session(
        const std::string& contact) const;
    [[nodiscard]] int persist_session(const std::string& contact,
                                      const std::uint8_t* bytes,
                                      std::size_t size) const;

    // The history: one file per received message ID, created once and
    // synced. hold stores a record unless the ID is already held, and
    // returns false only when it could not.
    [[nodiscard]] bool hold(const std::string& contact, const std::string& id,
                            const std::string& record) const;
    [[nodiscard]] bool holds(const std::string& contact,
                             const std::string& id) const;
    // Every record held for a contact, ordered by ID.
    [[nodiscard]] std::vector<std::string> history(
        const std::string& contact) const;

private:
    std::string directory_;
    int lock_{-1};
};

// A contact's session file, for the session's persistence callback.
struct SessionFile final {
    const HostStore* store{nullptr};
    std::string contact;
};
int session_file_persist(void* user_data, const std::uint8_t* snapshot,
                         std::size_t size);

// Creates the directory 0700 when absent and refuses a link, another owner,
// or group or world access. what names it in the fixed error messages.
void require_private_directory(const std::string& directory, const char* what);

// The C persistence callback for a HostStore.
int host_store_persist(void* user_data, const std::uint8_t* snapshot,
                       std::size_t size);

}  // namespace ito::cli
