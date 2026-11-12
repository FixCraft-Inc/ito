/* Copyright (C) 2026 FixCraft Inc. AGPL-3.0-or-later. */

#include "store.hpp"

#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <new>

namespace ito::mailbox {
namespace {

using module::Descriptor;

constexpr std::string_view kFormatName = "format";
constexpr std::string_view kFormatNewName = "format-new";
constexpr std::string_view kInboxesName = "inboxes";
constexpr std::string_view kFormatText = "ito/mailbox-store/1\n";

constexpr std::string_view kRegistrationPrefix = "l1-";
constexpr std::string_view kMessagePrefix = "i1-";
constexpr std::string_view kPartialPrefix = "t1-";
constexpr std::size_t kRegistrationNameBytes = 3U + 8U;
constexpr std::size_t kMessageNameBytes =
    3U + 16U + 1U + 32U + 1U + 8U + 1U + 8U;
constexpr std::size_t kPartialNameBytes = 3U + 32U;

constexpr int kDirectoryFlags = O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC;
constexpr char kHexDigits[] = "0123456789abcdef";

// A file or directory name, NUL-terminated, built without allocating.
struct Name final {
    char text[72]{};
    std::size_t size{0U};

    void append(std::string_view part) noexcept {
        std::memcpy(text + size, part.data(), part.size());
        size += part.size();
        text[size] = '\0';
    }
    void append_hex(const std::uint8_t* bytes, std::size_t count) noexcept {
        for (std::size_t index = 0U; index < count; ++index) {
            text[size++] = kHexDigits[bytes[index] >> 4U];
            text[size++] = kHexDigits[bytes[index] & 0x0fU];
        }
        text[size] = '\0';
    }
    void append_u32(std::uint32_t value) noexcept {
        for (int shift = 28; shift >= 0; shift -= 4)
            text[size++] = kHexDigits[(value >> shift) & 0x0fU];
        text[size] = '\0';
    }
    void append_u64(std::uint64_t value) noexcept {
        append_u32(static_cast<std::uint32_t>(value >> 32U));
        append_u32(static_cast<std::uint32_t>(value));
    }
    [[nodiscard]] const char* c_str() const noexcept { return text; }
};

Name inbox_name(const Address& address) noexcept {
    Name name;
    name.append_hex(address.data(), address.size());
    return name;
}

Name registration_name(std::uint32_t day) noexcept {
    Name name;
    name.append(kRegistrationPrefix);
    name.append_u32(day);
    return name;
}

Name message_name(const MessageName& message) noexcept {
    Name name;
    name.append(kMessagePrefix);
    name.append_u64(message.order);
    name.append("-");
    name.append_hex(message.id.data(), message.id.size());
    name.append("-");
    name.append_u32(message.deposit_minute);
    name.append("-");
    name.append_u32(message.expiry_minute);
    return name;
}

Name partial_name(const ItemId& id) noexcept {
    Name name;
    name.append(kPartialPrefix);
    name.append_hex(id.data(), id.size());
    return name;
}

int hex_value(char character) noexcept {
    if (character >= '0' && character <= '9') return character - '0';
    if (character >= 'a' && character <= 'f') return character - 'a' + 10;
    return -1;
}

// Exactly 2 * N lowercase hex digits.
template <std::size_t N>
bool parse_hex(std::string_view text,
               std::array<std::uint8_t, N>& out) noexcept {
    if (text.size() != 2U * N) return false;
    for (std::size_t index = 0U; index < N; ++index) {
        const int high = hex_value(text[2U * index]);
        const int low = hex_value(text[2U * index + 1U]);
        if (high < 0 || low < 0) return false;
        out[index] = static_cast<std::uint8_t>((high << 4) | low);
    }
    return true;
}

// Exactly eight lowercase hex digits.
bool parse_u32(std::string_view text, std::uint32_t& out) noexcept {
    if (text.size() != 8U) return false;
    std::uint32_t value = 0U;
    for (const char character : text) {
        const int digit = hex_value(character);
        if (digit < 0) return false;
        value = (value << 4U) | static_cast<std::uint32_t>(digit);
    }
    out = value;
    return true;
}

bool parse_message_name(std::string_view text, MessageName& out) noexcept {
    std::uint32_t order_high = 0U;
    std::uint32_t order_low = 0U;
    if (text.size() != kMessageNameBytes || !text.starts_with(kMessagePrefix) ||
        text[19] != '-' || text[52] != '-' || text[61] != '-' ||
        !parse_u32(text.substr(3U, 8U), order_high) ||
        !parse_u32(text.substr(11U, 8U), order_low) ||
        !parse_hex(text.substr(20U, 32U), out.id) ||
        !parse_u32(text.substr(53U, 8U), out.deposit_minute) ||
        !parse_u32(text.substr(62U, 8U), out.expiry_minute))
        return false;
    out.order = (std::uint64_t{order_high} << 32U) | order_low;
    return true;
}

bool no_space(int error) noexcept {
    return error == ENOSPC || error == EDQUOT;
}

IoResult failure_for(int error) noexcept {
    return no_space(error) ? IoResult::NoSpace : IoResult::Failed;
}

bool sync_directory(int directory) noexcept {
    return ::fsync(directory) == 0;
}

// Closes a directory stream, and with it the descriptor it owns.
struct DirectoryStream final {
    explicit DirectoryStream(DIR* opened) noexcept : stream(opened) {}
    DirectoryStream(const DirectoryStream&) = delete;
    DirectoryStream& operator=(const DirectoryStream&) = delete;
    ~DirectoryStream() {
        if (stream != nullptr) ::closedir(stream);
    }
    DIR* stream;
};

// Visits each entry of directory except "." and "..". The visitor returns
// false to stop, and may throw. False when the directory could not be read.
template <typename Visitor>
bool for_each_entry(int directory, Visitor&& visit) {
    const int duplicate =
        ::openat(directory, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (duplicate < 0) return false;
    DirectoryStream listing(::fdopendir(duplicate));
    if (listing.stream == nullptr) {
        ::close(duplicate);
        return false;
    }
    for (;;) {
        errno = 0;
        const dirent* entry = ::readdir(listing.stream);
        if (entry == nullptr) return errno == 0;
        const std::string_view name(entry->d_name);
        if (name == "." || name == "..") continue;
        if (!visit(name)) return true;
    }
}

bool write_all(int descriptor, std::span<const std::byte> bytes,
               int& error) noexcept {
    while (!bytes.empty()) {
        const ssize_t written = ::write(descriptor, bytes.data(), bytes.size());
        if (written < 0) {
            if (errno == EINTR) continue;
            error = errno;
            return false;
        }
        bytes = bytes.subspan(static_cast<std::size_t>(written));
    }
    return true;
}

// Removes the registration first and syncs that, so a crash in the middle
// leaves a directory the next startup removes, never a registration whose
// messages are half gone.
IoResult remove_inbox(int inboxes, const char* name) noexcept {
    Descriptor directory(::openat(inboxes, name, kDirectoryFlags));
    if (directory.get() < 0)
        return errno == ENOENT ? IoResult::Ok : IoResult::Failed;
    bool removed = true;
    const auto remove = [&](std::string_view entry) {
        if (::unlinkat(directory.get(), entry.data(), 0) != 0 &&
            errno != ENOENT)
            removed = false;
        return removed;
    };
    const auto remove_registration = [&](std::string_view entry) {
        return !entry.starts_with(kRegistrationPrefix) || remove(entry);
    };
    if (!for_each_entry(directory.get(), remove_registration) || !removed ||
        !sync_directory(directory.get()))
        return IoResult::Failed;
    if (!for_each_entry(directory.get(), remove) || !removed)
        return IoResult::Failed;
    directory.reset();
    if (::unlinkat(inboxes, name, AT_REMOVEDIR) != 0 && errno != ENOENT)
        return IoResult::Failed;
    return IoResult::Ok;
}

bool read_format(int root) noexcept {
    Descriptor file(
        ::openat(root, kFormatName.data(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC));
    if (file.get() < 0) return false;
    struct stat info {};
    if (::fstat(file.get(), &info) != 0 || !S_ISREG(info.st_mode) ||
        static_cast<std::size_t>(info.st_size) != kFormatText.size())
        return false;
    char text[32]{};
    std::size_t got = 0U;
    while (got < kFormatText.size()) {
        const ssize_t count =
            ::read(file.get(), text + got, kFormatText.size() - got);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) return false;
        got += static_cast<std::size_t>(count);
    }
    return std::string_view(text, got) == kFormatText;
}

// Writes the format file through a temporary name, then the inbox directory.
bool initialize(int root) noexcept {
    if (::unlinkat(root, kFormatNewName.data(), 0) != 0 && errno != ENOENT)
        return false;
    {
        Descriptor file(::openat(
            root, kFormatNewName.data(),
            O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600));
        int error = 0;
        if (file.get() < 0 ||
            !write_all(file.get(), std::as_bytes(std::span(kFormatText)),
                       error) ||
            ::fsync(file.get()) != 0)
            return false;
    }
    return ::renameat(root, kFormatNewName.data(), root, kFormatName.data()) ==
               0 &&
           ::mkdirat(root, kInboxesName.data(), 0700) == 0 &&
           sync_directory(root);
}

// What the startup scan makes of one entry.
enum class Scan {
    // Loaded or removed: read the next entry.
    Next,
    // An entry the store never writes.
    Foreign,
    // Reading or removing it failed.
    Failed,
};

// One file of an inbox directory: its registration, a message to load, or an
// unfinished write, expired message or damaged message to remove. Throws
// bad_alloc when the message list cannot grow.
Scan scan_file(int directory, std::string_view name, std::uint32_t now_minute,
               bool& registered, LoadedInbox& inbox, LoadCounts& counts) {
    if (name.size() == kRegistrationNameBytes &&
        name.starts_with(kRegistrationPrefix)) {
        if (registered || !parse_u32(name.substr(3U), inbox.registration_day))
            return Scan::Foreign;
        registered = true;
        return Scan::Next;
    }
    if (name.size() == kPartialNameBytes && name.starts_with(kPartialPrefix)) {
        ItemId unused{};
        if (!parse_hex(name.substr(3U), unused)) return Scan::Foreign;
        if (::unlinkat(directory, name.data(), 0) != 0) return Scan::Failed;
        ++counts.partial_writes;
        return Scan::Next;
    }
    LoadedMessage message;
    if (!parse_message_name(name, message.name)) return Scan::Foreign;
    struct stat file {};
    if (::fstatat(directory, name.data(), &file, AT_SYMLINK_NOFOLLOW) != 0)
        return Scan::Failed;
    if (!S_ISREG(file.st_mode)) return Scan::Foreign;
    const auto size = static_cast<std::size_t>(file.st_size);
    const bool damaged = !valid_item_size(size);
    if (damaged || message.name.expiry_minute <= now_minute) {
        if (::unlinkat(directory, name.data(), 0) != 0) return Scan::Failed;
        ++(damaged ? counts.damaged_messages : counts.expired_messages);
        return Scan::Next;
    }
    message.size = static_cast<std::uint32_t>(size);
    inbox.messages.push_back(message);
    return Scan::Next;
}

// One inbox directory: appends it to loaded, or removes it when its
// registration ended or never finished. Throws bad_alloc when a list cannot
// grow.
Scan scan_inbox(int inboxes, std::string_view entry, std::uint32_t today,
                std::uint32_t now_minute, std::vector<LoadedInbox>& loaded,
                LoadCounts& counts) {
    LoadedInbox inbox;
    if (!parse_hex(entry, inbox.address)) return Scan::Foreign;
    struct stat info {};
    if (::fstatat(inboxes, entry.data(), &info, AT_SYMLINK_NOFOLLOW) != 0)
        return Scan::Failed;
    if (!S_ISDIR(info.st_mode)) return Scan::Foreign;
    Descriptor directory(::openat(inboxes, entry.data(), kDirectoryFlags));
    if (directory.get() < 0) return Scan::Failed;
    bool registered = false;
    Scan result = Scan::Next;
    const auto visit = [&](std::string_view name) {
        result = scan_file(directory.get(), name, now_minute, registered, inbox,
                           counts);
        return result == Scan::Next;
    };
    if (!for_each_entry(directory.get(), visit)) return Scan::Failed;
    if (result != Scan::Next) return result;
    directory.reset();
    if (!registered || inbox.registration_day <= today) {
        ++(registered ? counts.ended_inboxes : counts.unregistered_inboxes);
        return remove_inbox(inboxes, entry.data()) == IoResult::Ok
                   ? Scan::Next
                   : Scan::Failed;
    }
    loaded.push_back(std::move(inbox));
    return Scan::Next;
}

}  // namespace

std::string_view describe(StoreError error) noexcept {
    switch (error) {
        case StoreError::NotDirectory:
            return "the data directory is missing or is not a directory";
        case StoreError::Unsafe:
            return "the data directory must belong to the service's user and "
                   "be closed to group and others";
        case StoreError::NotStore:
            return "the data directory holds something other than a mailbox "
                   "store";
        case StoreError::Unreadable:
            return "the data directory could not be read or initialized";
        case StoreError::NoMemory:
            return "memory for the store ran out";
    }
    return "unknown store error";
}

std::optional<Store> Store::open(const char* path, uid_t owner,
                                 StoreError& error) noexcept {
    Descriptor root(::open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC));
    if (root.get() < 0) {
        error = StoreError::NotDirectory;
        return std::nullopt;
    }
    struct stat info {};
    if (::fstat(root.get(), &info) != 0 || !S_ISDIR(info.st_mode)) {
        error = StoreError::NotDirectory;
        return std::nullopt;
    }
    if (info.st_uid != owner || (info.st_mode & (S_IRWXG | S_IRWXO)) != 0U) {
        error = StoreError::Unsafe;
        return std::nullopt;
    }
    bool has_format = false;
    bool has_inboxes = false;
    bool has_partial_format = false;
    bool foreign = false;
    const auto classify = [&](std::string_view entry) {
        if (entry == kFormatName) {
            has_format = true;
        } else if (entry == kInboxesName) {
            has_inboxes = true;
        } else if (entry == kFormatNewName) {
            has_partial_format = true;
        } else {
            foreign = true;
        }
        return true;
    };
    if (!for_each_entry(root.get(), classify)) {
        error = StoreError::Unreadable;
        return std::nullopt;
    }
    if (foreign || (has_inboxes && !has_format)) {
        error = StoreError::NotStore;
        return std::nullopt;
    }
    if (!has_format) {
        // Empty, or an initialization that stopped before its rename.
        if (!initialize(root.get())) {
            error = StoreError::Unreadable;
            return std::nullopt;
        }
    } else {
        if (!read_format(root.get())) {
            error = StoreError::NotStore;
            return std::nullopt;
        }
        if (has_partial_format &&
            ::unlinkat(root.get(), kFormatNewName.data(), 0) != 0) {
            error = StoreError::Unreadable;
            return std::nullopt;
        }
        if (!has_inboxes &&
            (::mkdirat(root.get(), kInboxesName.data(), 0700) != 0 ||
             !sync_directory(root.get()))) {
            error = StoreError::Unreadable;
            return std::nullopt;
        }
    }
    Descriptor inboxes(
        ::openat(root.get(), kInboxesName.data(), kDirectoryFlags));
    if (inboxes.get() < 0) {
        error = errno == ENOTDIR || errno == ELOOP ? StoreError::NotStore
                                                   : StoreError::Unreadable;
        return std::nullopt;
    }
    return Store(std::move(root), std::move(inboxes));
}

bool Store::load(std::uint32_t today, std::uint32_t now_minute,
                 std::vector<LoadedInbox>& inboxes, LoadCounts& counts,
                 StoreError& error) noexcept {
    try {
        Scan result = Scan::Next;
        const auto visit = [&](std::string_view entry) {
            result = scan_inbox(inboxes_.get(), entry, today, now_minute,
                                inboxes, counts);
            return result == Scan::Next;
        };
        const bool listed = for_each_entry(inboxes_.get(), visit);
        if (result == Scan::Foreign) {
            error = StoreError::NotStore;
            return false;
        }
        if (!listed || result == Scan::Failed ||
            !sync_directory(inboxes_.get())) {
            error = StoreError::Unreadable;
            return false;
        }
        return true;
    } catch (const std::bad_alloc&) {
        error = StoreError::NoMemory;
        return false;
    }
}

IoResult Store::create_inbox(const Address& address,
                             std::uint32_t day) const noexcept {
    const Name directory_name = inbox_name(address);
    if (::mkdirat(inboxes_.get(), directory_name.c_str(), 0700) != 0)
        return failure_for(errno);
    Descriptor directory(
        ::openat(inboxes_.get(), directory_name.c_str(), kDirectoryFlags));
    const Name registration = registration_name(day);
    int error = 0;
    bool created = false;
    if (directory.get() >= 0) {
        const int file = ::openat(
            directory.get(), registration.c_str(),
            O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
        created = file >= 0;
        if (created) ::close(file);
    }
    if (created && sync_directory(directory.get()) &&
        sync_directory(inboxes_.get()))
        return IoResult::Ok;
    error = errno;
    if (!no_space(error)) return IoResult::Failed;
    // Nothing of a refused registration may remain.
    if (directory.get() >= 0)
        ::unlinkat(directory.get(), registration.c_str(), 0);
    directory.reset();
    if (::unlinkat(inboxes_.get(), directory_name.c_str(), AT_REMOVEDIR) != 0)
        return IoResult::Failed;
    return IoResult::NoSpace;
}

IoResult Store::renew_registration(const Address& address,
                                   std::uint32_t day) const noexcept {
    const Name directory_name = inbox_name(address);
    Descriptor directory(
        ::openat(inboxes_.get(), directory_name.c_str(), kDirectoryFlags));
    if (directory.get() < 0) return IoResult::Failed;
    Name current;
    const auto find_registration = [&](std::string_view entry) {
        if (entry.size() != kRegistrationNameBytes ||
            !entry.starts_with(kRegistrationPrefix))
            return true;
        current.append(entry);
        return false;
    };
    if (!for_each_entry(directory.get(), find_registration) ||
        current.size == 0U)
        return IoResult::Failed;
    const Name renewed = registration_name(day);
    if (std::string_view(current.c_str()) == renewed.c_str())
        return IoResult::Ok;
    if (::renameat(directory.get(), current.c_str(), directory.get(),
                   renewed.c_str()) != 0 ||
        !sync_directory(directory.get()))
        return IoResult::Failed;
    return IoResult::Ok;
}

IoResult Store::write_message(
    const Address& address, const MessageName& name,
    std::span<const std::byte> sealed) const noexcept {
    Descriptor directory(
        ::openat(inboxes_.get(), inbox_name(address).c_str(), kDirectoryFlags));
    if (directory.get() < 0) return IoResult::Failed;
    const Name partial = partial_name(name.id);
    const Name final_name = message_name(name);
    int error = 0;
    {
        Descriptor file(::openat(
            directory.get(), partial.c_str(),
            O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600));
        if (file.get() < 0) return failure_for(errno);
        if (!write_all(file.get(), sealed, error) ||
            ::fdatasync(file.get()) != 0) {
            if (error == 0) error = errno;
            file.reset();
            ::unlinkat(directory.get(), partial.c_str(), 0);
            return failure_for(error);
        }
    }
    if (::renameat(directory.get(), partial.c_str(), directory.get(),
                   final_name.c_str()) != 0) {
        error = errno;
        ::unlinkat(directory.get(), partial.c_str(), 0);
        return failure_for(error);
    }
    if (!sync_directory(directory.get())) {
        error = errno;
        if (!no_space(error)) return IoResult::Failed;
        ::unlinkat(directory.get(), final_name.c_str(), 0);
        return IoResult::NoSpace;
    }
    return IoResult::Ok;
}

IoResult Store::delete_message(const Address& address,
                               const MessageName& name) const noexcept {
    Descriptor directory(
        ::openat(inboxes_.get(), inbox_name(address).c_str(), kDirectoryFlags));
    if (directory.get() < 0)
        return errno == ENOENT ? IoResult::Ok : IoResult::Failed;
    if (::unlinkat(directory.get(), message_name(name).c_str(), 0) != 0 &&
        errno != ENOENT)
        return IoResult::Failed;
    return IoResult::Ok;
}

IoResult Store::close_inbox(const Address& address) const noexcept {
    return remove_inbox(inboxes_.get(), inbox_name(address).c_str());
}

Store::ReadResult Store::read_message(const Address& address,
                                      const MessageName& name,
                                      std::span<std::byte> out) const noexcept {
    Descriptor directory(
        ::openat(inboxes_.get(), inbox_name(address).c_str(), kDirectoryFlags));
    if (directory.get() < 0)
        return errno == ENOENT ? ReadResult::Missing : ReadResult::Failed;
    Descriptor file(::openat(directory.get(), message_name(name).c_str(),
                             O_RDONLY | O_NOFOLLOW | O_CLOEXEC));
    if (file.get() < 0)
        return errno == ENOENT ? ReadResult::Missing : ReadResult::Failed;
    struct stat info {};
    if (::fstat(file.get(), &info) != 0) return ReadResult::Failed;
    if (!S_ISREG(info.st_mode) ||
        static_cast<std::size_t>(info.st_size) != out.size())
        return ReadResult::Missing;
    std::size_t got = 0U;
    while (got < out.size()) {
        const ssize_t count =
            ::pread(file.get(), out.data() + got, out.size() - got,
                    static_cast<off_t>(got));
        if (count < 0 && errno == EINTR) continue;
        if (count < 0) return ReadResult::Failed;
        if (count == 0) return ReadResult::Missing;
        got += static_cast<std::size_t>(count);
    }
    return ReadResult::Ok;
}

}  // namespace ito::mailbox
