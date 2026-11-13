/* Copyright (C) 2026 FixCraft Inc. AGPL-3.0-or-later. */

#include "host_store.hpp"

#include <ito/call.h>

#include <dirent.h>
#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <stdexcept>
#include <string>

namespace ito::cli {
namespace {

constexpr const char* kSnapshot = "snapshot";
constexpr const char* kSessions = "sessions";
constexpr const char* kHistory = "history";
constexpr const char* kLock = "lock";
constexpr std::size_t kMaxSnapshot = 1024U * 1024U;
constexpr std::size_t kMaxRecord = 16U * 1024U;

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

[[nodiscard]] bool write_all(int descriptor, const std::uint8_t* bytes,
                             std::size_t size) {
    while (size != 0U) {
        const ssize_t written = ::write(descriptor, bytes, size);
        if (written < 0 && errno == EINTR) continue;
        if (written <= 0) return false;
        bytes += written;
        size -= static_cast<std::size_t>(written);
    }
    return true;
}

}  // namespace

void require_private_directory(const std::string& directory, const char* what) {
    if (::mkdir(directory.c_str(), 0700) != 0 && errno != EEXIST) {
        throw std::runtime_error(std::string("cannot create the ") + what +
                                 " directory");
    }
    struct stat info{};
    if (::lstat(directory.c_str(), &info) != 0 || !S_ISDIR(info.st_mode) ||
        info.st_uid != ::geteuid() || (info.st_mode & 0077) != 0) {
        throw std::runtime_error(std::string("the ") + what +
                                 " directory must be a private 0700 directory");
    }
}

HostStore::HostStore(std::string directory) : directory_(std::move(directory)) {
    require_private_directory(directory_, "store");
    require_private_directory(directory_ + "/" + kSessions, "sessions");
    require_private_directory(directory_ + "/" + kHistory, "history");
    const std::string lock = directory_ + "/" + kLock;
    lock_ =
        ::open(lock.c_str(), O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (lock_ < 0) throw std::runtime_error("cannot open the store lock");
    if (::flock(lock_, LOCK_EX | LOCK_NB) != 0) {
        ::close(lock_);
        throw std::runtime_error("another ito-call is using this store");
    }
}

HostStore::~HostStore() {
    ::close(lock_);
}

namespace {

// Reads one private regular file of at most limit bytes. An absent file is
// empty.
std::vector<std::uint8_t> read_private(const std::string& path,
                                       std::size_t limit, const char* what) {
    const int raw =
        ::open(path.c_str(), O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    if (raw < 0) {
        if (errno == ENOENT) return {};
        throw std::runtime_error(std::string(what) + " is unreadable");
    }
    const Descriptor descriptor(raw);
    struct stat info{};
    if (::fstat(raw, &info) != 0 || !S_ISREG(info.st_mode) ||
        info.st_uid != ::geteuid() || (info.st_mode & 0077) != 0 ||
        static_cast<std::size_t>(info.st_size) > limit) {
        throw std::runtime_error(std::string(what) +
                                 " is not a private regular file");
    }
    std::vector<std::uint8_t> bytes(static_cast<std::size_t>(info.st_size));
    std::size_t offset = 0U;
    while (offset < bytes.size()) {
        const ssize_t got =
            ::read(raw, bytes.data() + offset, bytes.size() - offset);
        if (got < 0 && errno == EINTR) continue;
        if (got <= 0) {
            if (!bytes.empty()) explicit_bzero(bytes.data(), bytes.size());
            throw std::runtime_error(std::string(what) + " is unreadable");
        }
        offset += static_cast<std::size_t>(got);
    }
    return bytes;
}

// Writes a private temporary file, syncs it, renames it over name and syncs
// the directory. Returns an ITO_PERSIST_* result.
int replace(const std::string& directory, const std::string& name,
            const std::uint8_t* bytes, std::size_t size) {
    const std::string temporary = directory + "/" + name + ".tmp";
    const std::string target = directory + "/" + name;
    (void)::unlink(temporary.c_str());
    {
        const Descriptor file(
            ::open(temporary.c_str(),
                   O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600));
        if (file.get() < 0) return ITO_PERSIST_NOT_COMMITTED;
        if (!write_all(file.get(), bytes, size) || ::fsync(file.get()) != 0) {
            (void)::unlink(temporary.c_str());
            return ITO_PERSIST_NOT_COMMITTED;
        }
    }
    if (::rename(temporary.c_str(), target.c_str()) != 0) {
        (void)::unlink(temporary.c_str());
        return ITO_PERSIST_NOT_COMMITTED;
    }
    // After the rename the new file may be what storage holds even if the
    // directory sync fails, so that failure is ambiguous.
    const Descriptor handle(
        ::open(directory.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC));
    if (handle.get() < 0 || ::fsync(handle.get()) != 0) {
        return ITO_PERSIST_AMBIGUOUS;
    }
    return ITO_PERSIST_COMMITTED;
}

// A file name the endpoint made: lowercase hex only.
[[nodiscard]] bool hex_name(const std::string& name) {
    return !name.empty() && name.size() <= 64U &&
           std::all_of(name.begin(), name.end(), [](char character) {
               return (character >= '0' && character <= '9') ||
                      (character >= 'a' && character <= 'f');
           });
}

}  // namespace

std::vector<std::uint8_t> HostStore::load() const {
    return read_private(directory_ + "/" + kSnapshot, kMaxSnapshot,
                        "the snapshot");
}

int HostStore::persist(const std::uint8_t* bytes, std::size_t size) const {
    return replace(directory_, kSnapshot, bytes, size);
}

std::vector<std::uint8_t> HostStore::load_session(
    const std::string& contact) const {
    if (!hex_name(contact)) throw std::runtime_error("bad session name");
    return read_private(directory_ + "/" + kSessions + "/" + contact,
                        kMaxSnapshot, "a session");
}

int HostStore::persist_session(const std::string& contact,
                               const std::uint8_t* bytes,
                               std::size_t size) const {
    if (!hex_name(contact)) return ITO_PERSIST_NOT_COMMITTED;
    return replace(directory_ + "/" + kSessions, contact, bytes, size);
}

bool HostStore::hold(const std::string& contact, const std::string& id,
                     const std::string& record) const {
    if (!hex_name(contact) || !hex_name(id) || record.size() > kMaxRecord) {
        return false;
    }
    const std::string folder = directory_ + "/" + kHistory + "/" + contact;
    try {
        require_private_directory(folder, "history");
    } catch (const std::runtime_error&) {
        return false;
    }
    if (holds(contact, id)) return true;
    return replace(folder, id,
                   reinterpret_cast<const std::uint8_t*>(record.data()),
                   record.size()) == ITO_PERSIST_COMMITTED;
}

bool HostStore::holds(const std::string& contact, const std::string& id) const {
    if (!hex_name(contact) || !hex_name(id)) return false;
    const std::string path =
        directory_ + "/" + kHistory + "/" + contact + "/" + id;
    struct stat info{};
    return ::lstat(path.c_str(), &info) == 0 && S_ISREG(info.st_mode);
}

std::vector<std::string> HostStore::history(const std::string& contact) const {
    if (!hex_name(contact)) throw std::runtime_error("bad history name");
    const std::string folder = directory_ + "/" + kHistory + "/" + contact;
    std::vector<std::string> names;
    DIR* raw = ::opendir(folder.c_str());
    if (raw == nullptr) {
        if (errno == ENOENT) return {};
        throw std::runtime_error("the history is unreadable");
    }
    while (const dirent* entry = ::readdir(raw)) {
        const std::string name = entry->d_name;
        if (hex_name(name)) names.push_back(name);
    }
    (void)::closedir(raw);
    std::sort(names.begin(), names.end());
    std::vector<std::string> records;
    for (const std::string& name : names) {
        const std::vector<std::uint8_t> bytes =
            read_private(folder + "/" + name, kMaxRecord, "a history record");
        records.emplace_back(bytes.begin(), bytes.end());
    }
    return records;
}

int session_file_persist(void* user_data, const std::uint8_t* snapshot,
                         std::size_t size) {
    try {
        const auto* file = static_cast<const SessionFile*>(user_data);
        return file->store->persist_session(file->contact, snapshot, size);
    } catch (...) {
        return ITO_PERSIST_AMBIGUOUS;
    }
}

int host_store_persist(void* user_data, const std::uint8_t* snapshot,
                       std::size_t size) {
    try {
        return static_cast<const HostStore*>(user_data)->persist(snapshot,
                                                                 size);
    } catch (...) {
        return ITO_PERSIST_AMBIGUOUS;
    }
}

}  // namespace ito::cli
