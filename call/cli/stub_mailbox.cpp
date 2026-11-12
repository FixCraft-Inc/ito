/* Copyright (C) 2026 FixCraft Inc. AGPL-3.0-or-later. */

#include "stub_mailbox.hpp"

#include <dirent.h>
#include <fcntl.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cstdio>
#include <memory>
#include <stdexcept>

#include "host_store.hpp"

namespace ito::cli {
namespace {

constexpr const char* kItemSuffix = ".item";
constexpr const char* kPartSuffix = ".part";
// A name is 20 decimal digits of deposit time in nanoseconds, a hyphen and
// 32 hex digits of randomness, so names sort by deposit time.
constexpr std::size_t kNameChars = 20U + 1U + 32U;

class Descriptor final {
public:
    explicit Descriptor(int value) noexcept : value_(value) {}
    Descriptor(const Descriptor&) = delete;
    Descriptor& operator=(const Descriptor&) = delete;
    ~Descriptor() {
        if (value_ >= 0) (void)::close(value_);
    }
    [[nodiscard]] int get() const noexcept { return value_; }

private:
    int value_;
};

struct DirectoryCloser final {
    void operator()(DIR* directory) const noexcept {
        (void)::closedir(directory);
    }
};

[[nodiscard]] bool item_size(std::size_t size) noexcept {
    return size == 1024U || size == 4096U || size == 16384U;
}

std::string hex(const std::uint8_t* bytes, std::size_t size) {
    static constexpr char kDigits[] = "0123456789abcdef";
    std::string out;
    out.reserve(size * 2U);
    for (std::size_t index = 0U; index < size; ++index) {
        out += kDigits[bytes[index] >> 4U];
        out += kDigits[bytes[index] & 15U];
    }
    return out;
}

std::string new_name() {
    std::array<std::uint8_t, 16> random{};
    if (::getrandom(random.data(), random.size(), 0) !=
        static_cast<ssize_t>(random.size())) {
        throw std::runtime_error("no randomness for a stub item name");
    }
    const auto now = std::chrono::duration_cast<std::chrono::nanoseconds>(
                         std::chrono::system_clock::now().time_since_epoch())
                         .count();
    char time[21];
    std::snprintf(time, sizeof(time), "%020lld", static_cast<long long>(now));
    return std::string(time) + "-" + hex(random.data(), random.size());
}

[[nodiscard]] bool valid_name(const std::string& name) {
    if (name.size() != kNameChars) return false;
    for (std::size_t index = 0U; index < name.size(); ++index) {
        const char character = name[index];
        const bool ok = index < 20U ? (character >= '0' && character <= '9')
                        : index == 20U
                            ? character == '-'
                            : ((character >= '0' && character <= '9') ||
                               (character >= 'a' && character <= 'f'));
        if (!ok) return false;
    }
    return true;
}

void write_all(int descriptor, const std::uint8_t* bytes, std::size_t size) {
    while (size != 0U) {
        const ssize_t written = ::write(descriptor, bytes, size);
        if (written < 0 && errno == EINTR) continue;
        if (written <= 0) throw std::runtime_error("cannot write a stub item");
        bytes += written;
        size -= static_cast<std::size_t>(written);
    }
}

void sync_directory(const std::string& path) {
    const Descriptor directory(
        ::open(path.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC));
    if (directory.get() < 0 || ::fsync(directory.get()) != 0) {
        throw std::runtime_error("cannot sync the stub mailbox");
    }
}

// Opens without following a link and without blocking on a FIFO, then
// checks the open file is a private regular item before reading it.
std::vector<std::uint8_t> read_item(const std::string& path) {
    const Descriptor file(
        ::open(path.c_str(), O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC));
    struct stat info{};
    if (file.get() < 0 || ::fstat(file.get(), &info) != 0 ||
        !S_ISREG(info.st_mode) || info.st_uid != ::geteuid() ||
        (info.st_mode & 0077) != 0 ||
        !item_size(static_cast<std::size_t>(info.st_size))) {
        throw std::runtime_error("a stub item is not a private item file");
    }
    std::vector<std::uint8_t> bytes(static_cast<std::size_t>(info.st_size));
    std::size_t offset = 0U;
    while (offset < bytes.size()) {
        const ssize_t got =
            ::read(file.get(), bytes.data() + offset, bytes.size() - offset);
        if (got < 0 && errno == EINTR) continue;
        if (got <= 0) throw std::runtime_error("a stub item is unreadable");
        offset += static_cast<std::size_t>(got);
    }
    return bytes;
}

}  // namespace

StubMailbox::StubMailbox(std::string directory)
    : directory_(std::move(directory)) {
    if (directory_.empty()) throw std::runtime_error("--stub is required");
    require_private_directory(directory_, "stub mailbox");
}

std::string StubMailbox::inbox(const MailboxTarget& target) const {
    // Hex keeps every component a plain name whatever the service holds.
    return directory_ + "/" + hex(target.server.data(), target.server.size()) +
           "-" +
           hex(reinterpret_cast<const std::uint8_t*>(target.service.data()),
               target.service.size()) +
           "-" + hex(target.address.data(), target.address.size());
}

void StubMailbox::deposit(const MailboxTarget& target, const std::uint8_t* item,
                          std::size_t size) const {
    if (!item_size(size)) throw std::runtime_error("not a mailbox item size");
    const std::string directory = inbox(target);
    require_private_directory(directory, "stub inbox");
    const std::string name = new_name();
    const std::string part = directory + "/" + name + kPartSuffix;
    {
        const Descriptor file(
            ::open(part.c_str(),
                   O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600));
        if (file.get() < 0)
            throw std::runtime_error("cannot create a stub item");
        write_all(file.get(), item, size);
        if (::fsync(file.get()) != 0) {
            throw std::runtime_error("cannot sync a stub item");
        }
    }
    const std::string published = directory + "/" + name + kItemSuffix;
    if (::rename(part.c_str(), published.c_str()) != 0) {
        (void)::unlink(part.c_str());
        throw std::runtime_error("cannot publish a stub item");
    }
    sync_directory(directory);
}

std::vector<StubItem> StubMailbox::waiting(const MailboxTarget& target) const {
    const std::string directory = inbox(target);
    struct stat info{};
    if (::lstat(directory.c_str(), &info) != 0) {
        if (errno == ENOENT) return {};
        throw std::runtime_error("the stub inbox is unreadable");
    }
    require_private_directory(directory, "stub inbox");
    const std::unique_ptr<DIR, DirectoryCloser> listing(
        ::opendir(directory.c_str()));
    if (listing == nullptr)
        throw std::runtime_error("the stub inbox is unreadable");
    std::vector<std::string> names;
    while (const dirent* entry = ::readdir(listing.get())) {
        const std::string file = entry->d_name;
        if (file == "." || file == ".." || file.ends_with(kPartSuffix))
            continue;
        const std::size_t suffix = std::char_traits<char>::length(kItemSuffix);
        const std::string name =
            file.size() > suffix ? file.substr(0, file.size() - suffix) : "";
        if (!file.ends_with(kItemSuffix) || !valid_name(name)) {
            throw std::runtime_error("the stub inbox holds a foreign file");
        }
        names.push_back(name);
    }
    std::sort(names.begin(), names.end());
    std::vector<StubItem> items;
    items.reserve(names.size());
    for (const std::string& name : names) {
        items.push_back(
            StubItem{name, read_item(directory + "/" + name + kItemSuffix)});
    }
    return items;
}

void StubMailbox::take(const MailboxTarget& target,
                       const std::string& name) const {
    if (!valid_name(name)) throw std::runtime_error("not a stub item name");
    const std::string directory = inbox(target);
    const std::string path = directory + "/" + name + kItemSuffix;
    if (::unlink(path.c_str()) != 0) {
        throw std::runtime_error("cannot take a stub item");
    }
    sync_directory(directory);
}

}  // namespace ito::cli
