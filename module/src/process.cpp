/* Copyright (C) 2026 FixCraft Inc. AGPL-3.0-or-later. */

#include "process.hpp"

#include <sys/resource.h>
#include <sys/signalfd.h>
#include <unistd.h>

#include <cerrno>
#include <charconv>
#include <csignal>
#include <cstdint>
#include <cstdlib>

namespace ito::module {

std::optional<uid_t> parse_uid(std::string_view text) noexcept {
    if (text.empty() || text.size() > 10U || text.front() < '0' ||
        text.front() > '9')
        return std::nullopt;
    std::uint32_t value = 0U;
    const auto [end, error] =
        std::from_chars(text.data(), text.data() + text.size(), value);
    if (error != std::errc{} || end != text.data() + text.size() ||
        value == UINT32_MAX)
        return std::nullopt;
    return static_cast<uid_t>(value);
}

bool activation_matches() noexcept {
    const char* count = std::getenv("LISTEN_FDS");
    if (count == nullptr) return true;
    const char* pid = std::getenv("LISTEN_PID");
    if (std::string_view(count) != "1" || pid == nullptr) return false;
    // A decimal PID fits in this buffer, so the check allocates nothing.
    char own[24];
    const auto [end, error] =
        std::to_chars(own, own + sizeof own, static_cast<long>(::getpid()));
    if (error != std::errc{} ||
        std::string_view(own, static_cast<std::size_t>(end - own)) != pid)
        return false;
    ::unsetenv("LISTEN_FDS");
    ::unsetenv("LISTEN_PID");
    ::unsetenv("LISTEN_FDNAMES");
    return true;
}

bool reserve_descriptors(std::size_t streams, std::size_t own) noexcept {
    rlimit limit{};
    if (::getrlimit(RLIMIT_NOFILE, &limit) != 0) return false;
    const rlim_t needed = static_cast<rlim_t>(streams) + own;
    if (limit.rlim_cur != RLIM_INFINITY && limit.rlim_cur < needed) {
        if (limit.rlim_max != RLIM_INFINITY && limit.rlim_max < needed)
            return false;
        limit.rlim_cur = needed;
        if (::setrlimit(RLIMIT_NOFILE, &limit) != 0) return false;
    }
    return true;
}

int signal_descriptor() noexcept {
    sigset_t handled;
    sigemptyset(&handled);
    sigaddset(&handled, SIGTERM);
    sigaddset(&handled, SIGINT);
    sigaddset(&handled, SIGUSR1);
    if (::sigprocmask(SIG_BLOCK, &handled, nullptr) != 0) return -1;
    return ::signalfd(-1, &handled, SFD_NONBLOCK | SFD_CLOEXEC);
}

void write_text(int descriptor, std::string_view text) noexcept {
    while (!text.empty()) {
        const ssize_t written = ::write(descriptor, text.data(), text.size());
        if (written < 0 && errno == EINTR) continue;
        if (written <= 0) return;
        text.remove_prefix(static_cast<std::size_t>(written));
    }
}

}  // namespace ito::module
