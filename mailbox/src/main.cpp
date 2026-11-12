/* Copyright (C) 2026 FixCraft Inc. AGPL-3.0-or-later. */

// ito-mailbox serves docs/MAILBOX.md as a YUME module: yumed connects to the
// inherited listener once for each authorized stream of the configured
// service. Exit status 0 after SIGTERM or SIGINT, 1 when the mailbox cannot
// start, its event loop fails or its disk fails, 2 for a usage error.

#include <unistd.h>

#include <charconv>
#include <csignal>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "limits.hpp"
#include "listener.hpp"
#include "mailbox.hpp"
#include "module_header.hpp"
#include "process.hpp"
#include "store.hpp"

namespace {

using namespace std::string_view_literals;

constexpr std::string_view kVersion = "ito-mailbox 0.1.0, mailbox protocol 1\n";

constexpr std::string_view kUsage =
    "usage: ito-mailbox --service NAME --daemon-uid UID --data DIR\n"
    "                   [--hold-days DAYS] [--store-mib MIB]\n"
    "\n"
    "Holds sealed items for offline phones and pushes them to connected\n"
    "ones, on the listening UNIX socket inherited as descriptor 3, as a\n"
    "YUME module. Only UID, the user yumed runs as, and root may connect.\n"
    "\n"
    "  --service NAME     the stream service name configured in yumed\n"
    "  --daemon-uid UID   the numeric user yumed runs as\n"
    "  --data DIR         the store, a directory of this user closed to "
    "others\n"
    "  --hold-days DAYS   the longest a message is held, 1 to 30 (default 7)\n"
    "  --store-mib MIB    the store's size, 1 to 2048 (default 2048)\n"
    "  --help             show this help\n"
    "  --version          show the version\n"
    "\n"
    "SIGUSR1 writes aggregate counts to standard error. SIGTERM stops it.\n";

// Descriptors the mailbox needs besides one per stream: the listener, epoll,
// signalfd, eventfds, the store's directories, the files it opens at once and
// standard streams, with margin.
constexpr std::size_t kReservedDescriptors = 48U;
constexpr std::uint32_t kMaxStoreMib = 2048U;

void print(int descriptor, std::string_view text) noexcept {
    ito::module::write_text(descriptor, text);
}

// Status lines are JSON with fixed reasons, so a supervisor's log holds no
// principal, secret, address or path.
void status(std::string_view event, std::string_view reason = {}) noexcept {
    try {
        std::string line = "{\"ito_mailbox\":\"";
        line += event;
        line += '"';
        if (!reason.empty()) {
            line += ",\"reason\":\"";
            line += reason;
            line += '"';
        }
        line += "}\n";
        print(STDERR_FILENO, line);
    } catch (...) {
        print(STDERR_FILENO, "{\"ito_mailbox\":\"status unavailable\"}\n");
    }
}

int usage_error(std::string_view message) {
    print(STDERR_FILENO, "ito-mailbox: ");
    print(STDERR_FILENO, message);
    print(STDERR_FILENO, "\nTry 'ito-mailbox --help'.\n");
    return 2;
}

// A decimal number from low to high, without sign or leading zero.
std::optional<std::uint32_t> parse_count(std::string_view text,
                                         std::uint32_t low,
                                         std::uint32_t high) noexcept {
    if (text.empty() || text.size() > 4U || text.front() < '1' ||
        text.front() > '9')
        return std::nullopt;
    std::uint32_t value = 0U;
    const auto [end, error] =
        std::from_chars(text.data(), text.data() + text.size(), value);
    if (error != std::errc{} || end != text.data() + text.size() ||
        value < low || value > high)
        return std::nullopt;
    return value;
}

void report_load(const ito::mailbox::LoadCounts& counts,
                 std::size_t inboxes) noexcept {
    try {
        std::string line = "{\"ito_mailbox\":\"loaded\",\"inboxes\":";
        line += std::to_string(inboxes);
        line += ",\"ended_inboxes\":";
        line += std::to_string(counts.ended_inboxes);
        line += ",\"unregistered_inboxes\":";
        line += std::to_string(counts.unregistered_inboxes);
        line += ",\"expired_messages\":";
        line += std::to_string(counts.expired_messages);
        line += ",\"damaged_messages\":";
        line += std::to_string(counts.damaged_messages);
        line += ",\"partial_writes\":";
        line += std::to_string(counts.partial_writes);
        line += "}\n";
        print(STDERR_FILENO, line);
    } catch (...) {
        // Diagnostics only.
    }
}

int serve(ito::mailbox::MailboxOptions options, const std::string& data) {
    using namespace ito::mailbox;
    using namespace ito::module;
    if (::geteuid() == 0U) {
        status("failed", "the mailbox refuses to run as root");
        return 1;
    }
    if (!activation_matches()) {
        status("failed",
               "LISTEN_FDS must pass exactly one descriptor to this process");
        return 1;
    }
    const auto check = check_listener(kInheritedListener, options.daemon_uid);
    if (check != ListenerCheck::Accepted) {
        status("failed", describe(check));
        return 1;
    }
    StoreError store_error = StoreError::Unreadable;
    auto store = Store::open(data.c_str(), ::geteuid(), store_error);
    if (!store) {
        status("failed", describe(store_error));
        return 1;
    }
    const Now now{Clock::now(), system_wall_clock()};
    std::vector<LoadedInbox> loaded;
    LoadCounts load_counts;
    if (!store->load(now.day(), now.minute(), loaded, load_counts,
                     store_error)) {
        status("failed", describe(store_error));
        return 1;
    }
    report_load(load_counts, loaded.size());
    if (!reserve_descriptors(options.limits.max_streams,
                             kReservedDescriptors)) {
        status("failed", "the descriptor limit cannot hold every stream");
        return 1;
    }
    std::signal(SIGPIPE, SIG_IGN);
    const int signals = signal_descriptor();
    if (signals < 0) {
        status("failed", "signals could not be set up");
        return 1;
    }
    SystemRandom random;
    CreateError create_error = CreateError::Resources;
    const auto mailbox = Mailbox::create(
        kInheritedListener, signals, std::move(options), std::move(*store),
        std::move(loaded), random, create_error);
    if (!mailbox) {
        status("failed", create_error == CreateError::DuplicateItem
                             ? "the store holds an item ID twice"
                             : "the event loop could not be created");
        return 1;
    }
    status("ready");
    const int result = mailbox->run();
    print(STDERR_FILENO, format_counts(mailbox->counts()));
    status(result == 0 ? "stopped" : "failed",
           result == 0 ? "" : "the event loop or the disk failed");
    return result;
}

}  // namespace

int main(int argc, char** argv) {
    ito::mailbox::MailboxOptions options;
    std::optional<std::string> service;
    std::optional<uid_t> daemon_uid;
    std::optional<std::string> data;
    std::optional<std::uint32_t> hold_days;
    std::optional<std::uint32_t> store_mib;
    for (int index = 1; index < argc; ++index) {
        const std::string_view word(argv[index]);
        if (word == "--help"sv) {
            print(STDOUT_FILENO, kUsage);
            return 0;
        }
        if (word == "--version"sv) {
            print(STDOUT_FILENO, kVersion);
            return 0;
        }
        if (word != "--service"sv && word != "--daemon-uid"sv &&
            word != "--data"sv && word != "--hold-days"sv &&
            word != "--store-mib"sv)
            return usage_error("unknown argument");
        if (index + 1 >= argc) return usage_error("an option needs a value");
        const std::string_view value(argv[++index]);
        if (word == "--service"sv) {
            if (service)
                return usage_error("--service is given more than once");
            if (!ito::module::valid_service_name(value))
                return usage_error(
                    "--service must be a canonical YUME service name of "
                    "at most 64 bytes");
            service.emplace(value);
        } else if (word == "--daemon-uid"sv) {
            if (daemon_uid)
                return usage_error("--daemon-uid is given more than once");
            daemon_uid = ito::module::parse_uid(value);
            if (!daemon_uid)
                return usage_error("--daemon-uid must be a numeric user ID");
        } else if (word == "--data"sv) {
            if (data) return usage_error("--data is given more than once");
            if (value.empty() || value.front() != '/')
                return usage_error("--data must be an absolute path");
            data.emplace(value);
        } else if (word == "--hold-days"sv) {
            if (hold_days)
                return usage_error("--hold-days is given more than once");
            hold_days = parse_count(value, ito::mailbox::kMinHoldDays,
                                    ito::mailbox::kMaxHoldDays);
            if (!hold_days)
                return usage_error("--hold-days must be a number from 1 to 30");
        } else {
            if (store_mib)
                return usage_error("--store-mib is given more than once");
            store_mib = parse_count(value, 1U, kMaxStoreMib);
            if (!store_mib)
                return usage_error(
                    "--store-mib must be a number from 1 to 2048");
        }
    }
    if (!service) return usage_error("--service is required");
    if (!daemon_uid) return usage_error("--daemon-uid is required");
    if (!data) return usage_error("--data is required");
    options.service = std::move(*service);
    options.daemon_uid = *daemon_uid;
    if (hold_days)
        options.limits.hold_time = std::chrono::seconds(*hold_days * 86'400LL);
    if (store_mib)
        options.limits.store_bytes = std::uint64_t{*store_mib} * 1024U * 1024U;
    try {
        return serve(std::move(options), *data);
    } catch (...) {
        status("failed", "the mailbox could not start");
        return 1;
    }
}
