/* Copyright (C) 2026 FixCraft Inc. AGPL-3.0-or-later. */

// Startup checks and process plumbing every Ito module shares: the daemon UID
// option, systemd's socket-activation variables, the descriptor limit and the
// signals that stop a module or ask for its counts.

#pragma once

#include <sys/types.h>

#include <cstddef>
#include <optional>
#include <string_view>

namespace ito::module {

// A decimal user ID of at most ten digits. (uid_t)-1, which the kernel reads
// as "no user", is refused.
[[nodiscard]] std::optional<uid_t> parse_uid(std::string_view text) noexcept;

// systemd describes the descriptors it passes. Anything other than exactly
// one listener for this process is a misconfigured unit. Clears the
// variables once they match, so no child inherits them.
[[nodiscard]] bool activation_matches() noexcept;

// Raises the soft open-file limit to hold `streams` connections plus the
// module's own descriptors. False when the hard limit is too low.
[[nodiscard]] bool reserve_descriptors(std::size_t streams,
                                       std::size_t own) noexcept;

// Blocks SIGTERM, SIGINT and SIGUSR1 and returns a nonblocking signalfd that
// delivers them, or -1.
[[nodiscard]] int signal_descriptor() noexcept;

// Writes all of text, retrying short writes. Stops quietly on an error, since
// its callers report status on standard streams that may be closed.
void write_text(int descriptor, std::string_view text) noexcept;

}  // namespace ito::module
