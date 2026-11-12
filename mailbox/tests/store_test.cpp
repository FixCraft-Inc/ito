/* Copyright (C) 2026 FixCraft Inc. AGPL-3.0-or-later. */

// The data directory: what Store::open accepts and initializes, the files
// each operation leaves, what the startup scan keeps and removes, and a full
// disk. The full-disk case mounts a small tmpfs in a private user and mount
// namespace, and exits 77 (skipped) when the host forbids that.

#include "store.hpp"

#include <dirent.h>
#include <fcntl.h>
#include <ftw.h>
#include <sched.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <optional>
#include <string>
#include <vector>

#include "check.hpp"

namespace {

using namespace ito::mailbox;

constexpr int kSkipped = 77;
// 2027-01-15, as days and minutes since 1970.
constexpr std::uint32_t kToday = 20'833U;
constexpr std::uint32_t kNowMinute = 30'000'000U;

class TempDirectory final {
public:
    TempDirectory() {
        char pattern[] = "/tmp/ito-mailbox-store-XXXXXX";
        CHECK(::mkdtemp(pattern) != nullptr);
        path_ = pattern;
    }
    ~TempDirectory() {
        ::nftw(
            path_.c_str(),
            [](const char* path, const struct stat*, int, FTW*) {
                return ::remove(path);
            },
            16, FTW_DEPTH | FTW_PHYS);
    }
    TempDirectory(const TempDirectory&) = delete;
    TempDirectory& operator=(const TempDirectory&) = delete;

    [[nodiscard]] const std::string& path() const noexcept { return path_; }
    [[nodiscard]] std::string operator/(const std::string& name) const {
        return path_ + "/" + name;
    }

private:
    std::string path_;
};

std::vector<std::string> entries(const std::string& path) {
    std::vector<std::string> out;
    DIR* directory = ::opendir(path.c_str());
    CHECK(directory != nullptr);
    while (const dirent* entry = ::readdir(directory)) {
        const std::string name(entry->d_name);
        if (name != "." && name != "..") out.push_back(name);
    }
    ::closedir(directory);
    std::sort(out.begin(), out.end());
    return out;
}

void write_file(const std::string& path, std::size_t size,
                const char* content = nullptr) {
    const int file = ::open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
    CHECK(file >= 0);
    std::vector<char> bytes(size, 'x');
    if (content != nullptr) bytes.assign(content, content + size);
    CHECK(::write(file, bytes.data(), bytes.size()) ==
          static_cast<ssize_t>(bytes.size()));
    ::close(file);
}

std::string read_file(const std::string& path) {
    const int file = ::open(path.c_str(), O_RDONLY);
    CHECK(file >= 0);
    char buffer[256];
    const ssize_t got = ::read(file, buffer, sizeof buffer);
    ::close(file);
    CHECK(got >= 0);
    return std::string(buffer, static_cast<std::size_t>(got));
}

Address address(std::uint8_t label) {
    Address out{};
    out.fill(label);
    return out;
}

std::string hex(std::span<const std::uint8_t> bytes) {
    static constexpr char kDigits[] = "0123456789abcdef";
    std::string out;
    for (const auto byte : bytes) {
        out += kDigits[byte >> 4U];
        out += kDigits[byte & 0x0fU];
    }
    return out;
}

MessageName message(std::uint8_t label, std::uint32_t expiry) {
    MessageName name;
    name.order = 0x0102030405060700ULL + label;
    name.id.fill(label);
    name.deposit_minute = kNowMinute - 5U;
    name.expiry_minute = expiry;
    return name;
}

std::vector<std::byte> sealed(std::size_t size, std::uint8_t seed) {
    std::vector<std::byte> out(size);
    for (std::size_t index = 0U; index < size; ++index)
        out[index] = static_cast<std::byte>(seed + index * 13U);
    return out;
}

// A message file's name, spelled out here rather than by the store.
std::string file_name(const MessageName& name) {
    char text[80];
    std::snprintf(text, sizeof text, "i1-%016llx-%s-%08x-%08x",
                  static_cast<unsigned long long>(name.order),
                  hex(name.id).c_str(), name.deposit_minute,
                  name.expiry_minute);
    return text;
}

std::optional<Store> open_store(const std::string& path, StoreError& error) {
    return Store::open(path.c_str(), ::geteuid(), error);
}

Store must_open(const std::string& path) {
    StoreError error = StoreError::Unreadable;
    auto store = open_store(path, error);
    CHECK(store.has_value());
    return std::move(*store);
}

StoreError open_error(const std::string& path, uid_t owner = ::geteuid()) {
    StoreError error = StoreError::Unreadable;
    CHECK(!Store::open(path.c_str(), owner, error).has_value());
    return error;
}

void test_open_rules() {
    TempDirectory root;
    CHECK(open_error(root / "missing") == StoreError::NotDirectory);
    write_file(root / "file", 1U);
    CHECK(open_error(root / "file") == StoreError::NotDirectory);

    const std::string data = root / "data";
    CHECK(::mkdir(data.c_str(), 0750) == 0);
    CHECK(open_error(data) == StoreError::Unsafe);
    CHECK(::chmod(data.c_str(), 0700) == 0);
    CHECK(open_error(data, ::geteuid() + 1U) == StoreError::Unsafe);

    // An empty directory becomes a store.
    must_open(data);
    CHECK(entries(data) == (std::vector<std::string>{"format", "inboxes"}));
    CHECK(read_file(data + "/format") == "ito/mailbox-store/1\n");
    struct stat info {};
    CHECK(::stat((data + "/inboxes").c_str(), &info) == 0);
    CHECK((info.st_mode & 0777U) == 0700U);
    must_open(data);

    // A symbolic link may name the directory, as systemd's state directory
    // for a dynamic user does.
    CHECK(::symlink(data.c_str(), (root / "link").c_str()) == 0);
    must_open(root / "link");

    // An unfinished initialization is completed, a finished one tidied.
    write_file(data + "/format-new", 3U);
    must_open(data);
    CHECK(entries(data) == (std::vector<std::string>{"format", "inboxes"}));
    const std::string fresh = root / "fresh";
    CHECK(::mkdir(fresh.c_str(), 0700) == 0);
    write_file(fresh + "/format-new", 3U);
    must_open(fresh);
    CHECK(read_file(fresh + "/format") == "ito/mailbox-store/1\n");

    // Anything the store never writes.
    const std::string other = root / "other";
    CHECK(::mkdir(other.c_str(), 0700) == 0);
    write_file(other + "/notes.txt", 1U);
    CHECK(open_error(other) == StoreError::NotStore);
    const std::string orphan = root / "orphan";
    CHECK(::mkdir(orphan.c_str(), 0700) == 0);
    CHECK(::mkdir((orphan + "/inboxes").c_str(), 0700) == 0);
    CHECK(open_error(orphan) == StoreError::NotStore);
    const std::string wrong = root / "wrong";
    CHECK(::mkdir(wrong.c_str(), 0700) == 0);
    write_file(wrong + "/format", 20U, "ito/mailbox-store/2\n");
    CHECK(open_error(wrong) == StoreError::NotStore);
    const std::string linked = root / "linked";
    CHECK(::mkdir(linked.c_str(), 0700) == 0);
    write_file(linked + "/format", 20U, "ito/mailbox-store/1\n");
    CHECK(::symlink(data.c_str(), (linked + "/inboxes").c_str()) == 0);
    CHECK(open_error(linked) == StoreError::NotStore);
}

void test_operations() {
    TempDirectory root;
    const std::string data = root / "data";
    CHECK(::mkdir(data.c_str(), 0700) == 0);
    const Store store = must_open(data);
    const Address inbox = address(0x11U);
    const std::string directory = data + "/inboxes/" + hex(inbox);

    CHECK(store.create_inbox(inbox, kToday + 30U) == IoResult::Ok);
    CHECK(entries(directory) == std::vector<std::string>{"l1-0000517f"});
    CHECK(store.renew_registration(inbox, kToday + 31U) == IoResult::Ok);
    CHECK(store.renew_registration(inbox, kToday + 31U) == IoResult::Ok);
    CHECK(entries(directory) == std::vector<std::string>{"l1-00005180"});
    CHECK(store.renew_registration(address(0x12U), kToday) == IoResult::Failed);

    const MessageName first = message(0xa1U, kNowMinute + 60U);
    const auto first_bytes = sealed(kMediumItemBytes, 3U);
    CHECK(store.write_message(inbox, first, first_bytes) == IoResult::Ok);
    const std::string first_file =
        "i1-01020304050607a1-" + hex(first.id) + "-01c9c37b-01c9c3bc";
    CHECK(first_file == file_name(first));
    CHECK(entries(directory) ==
          (std::vector<std::string>{first_file, "l1-00005180"}));
    struct stat info {};
    CHECK(::stat((directory + "/" + first_file).c_str(), &info) == 0);
    CHECK((info.st_mode & 0777U) == 0600U);

    std::vector<std::byte> out(kMediumItemBytes);
    CHECK(store.read_message(inbox, first, out) == Store::ReadResult::Ok);
    CHECK(out == first_bytes);
    // A size the file does not have reads as missing.
    std::vector<std::byte> small(kSmallItemBytes);
    CHECK(store.read_message(inbox, first, small) ==
          Store::ReadResult::Missing);
    CHECK(store.read_message(address(0x12U), first, out) ==
          Store::ReadResult::Missing);

    CHECK(store.delete_message(inbox, first) == IoResult::Ok);
    CHECK(store.delete_message(inbox, first) == IoResult::Ok);
    CHECK(store.delete_message(address(0x12U), first) == IoResult::Ok);
    CHECK(store.read_message(inbox, first, out) == Store::ReadResult::Missing);

    const MessageName second = message(0xa2U, kNowMinute + 60U);
    CHECK(store.write_message(inbox, second, sealed(kSmallItemBytes, 9U)) ==
          IoResult::Ok);
    CHECK(store.close_inbox(inbox) == IoResult::Ok);
    CHECK(entries(data + "/inboxes").empty());
    CHECK(store.close_inbox(inbox) == IoResult::Ok);
    // A write into a closed inbox fails: the loop never submits one.
    CHECK(store.write_message(inbox, second, sealed(kSmallItemBytes, 9U)) ==
          IoResult::Failed);
}

void test_load() {
    TempDirectory root;
    const std::string data = root / "data";
    CHECK(::mkdir(data.c_str(), 0700) == 0);
    {
        const Store store = must_open(data);
        CHECK(store.create_inbox(address(1U), kToday + 1U) == IoResult::Ok);
        CHECK(store.write_message(address(1U), message(0x01U, kNowMinute + 1U),
                                  sealed(kSmallItemBytes, 1U)) == IoResult::Ok);
        CHECK(store.write_message(address(1U), message(0x02U, kNowMinute + 2U),
                                  sealed(kLargeItemBytes, 2U)) == IoResult::Ok);
        // Expired by now.
        CHECK(store.write_message(address(1U), message(0x03U, kNowMinute),
                                  sealed(kSmallItemBytes, 3U)) == IoResult::Ok);
        // Ended today.
        CHECK(store.create_inbox(address(2U), kToday) == IoResult::Ok);
        CHECK(store.write_message(address(2U), message(0x04U, kNowMinute + 9U),
                                  sealed(kSmallItemBytes, 4U)) == IoResult::Ok);
    }
    const std::string first = data + "/inboxes/" + hex(address(1U));
    // A message cut short, and a write that never finished.
    write_file(first + "/" + file_name(message(0x05U, kNowMinute + 9U)), 1000U);
    write_file(first + "/t1-" + hex(message(0x06U, 0U).id), 10U);
    // A directory whose registration was removed by an unfinished close.
    const std::string closing = data + "/inboxes/" + hex(address(3U));
    CHECK(::mkdir(closing.c_str(), 0700) == 0);
    write_file(closing + "/" + file_name(message(0x07U, kNowMinute + 9U)),
               kSmallItemBytes);

    Store store = must_open(data);
    std::vector<LoadedInbox> loaded;
    LoadCounts counts;
    StoreError error = StoreError::Unreadable;
    CHECK(store.load(kToday, kNowMinute, loaded, counts, error));
    CHECK(loaded.size() == 1U);
    CHECK(loaded[0].address == address(1U));
    CHECK(loaded[0].registration_day == kToday + 1U);
    CHECK(loaded[0].messages.size() == 2U);
    std::sort(loaded[0].messages.begin(), loaded[0].messages.end(),
              [](const LoadedMessage& left, const LoadedMessage& right) {
                  return left.name.id < right.name.id;
              });
    CHECK(loaded[0].messages[0].name.id == message(0x01U, 0U).id);
    CHECK(loaded[0].messages[0].name.order == message(0x01U, 0U).order);
    CHECK(loaded[0].messages[0].name.expiry_minute == kNowMinute + 1U);
    CHECK(loaded[0].messages[0].name.deposit_minute == kNowMinute - 5U);
    CHECK(loaded[0].messages[0].size == kSmallItemBytes);
    CHECK(loaded[0].messages[1].size == kLargeItemBytes);
    CHECK(counts.ended_inboxes == 1U);
    CHECK(counts.unregistered_inboxes == 1U);
    CHECK(counts.expired_messages == 1U);
    CHECK(counts.damaged_messages == 1U);
    CHECK(counts.partial_writes == 1U);
    CHECK(entries(data + "/inboxes") ==
          std::vector<std::string>{hex(address(1U))});
    CHECK(entries(first).size() == 3U);

    // A second scan finds nothing more to remove.
    loaded.clear();
    LoadCounts again;
    CHECK(store.load(kToday, kNowMinute, loaded, again, error));
    CHECK(loaded.size() == 1U && loaded[0].messages.size() == 2U);
    CHECK(again.expired_messages == 0U && again.partial_writes == 0U);
}

// Each entry the store never writes stops the scan before it removes anything
// else.
void test_load_refusals() {
    const auto refused = [](auto&& damage) {
        TempDirectory root;
        const std::string data = root / "data";
        CHECK(::mkdir(data.c_str(), 0700) == 0);
        {
            const Store store = must_open(data);
            CHECK(store.create_inbox(address(1U), kToday + 9U) == IoResult::Ok);
        }
        damage(data + "/inboxes", data + "/inboxes/" + hex(address(1U)));
        Store store = must_open(data);
        std::vector<LoadedInbox> loaded;
        LoadCounts counts;
        StoreError error = StoreError::Unreadable;
        CHECK(!store.load(kToday, kNowMinute, loaded, counts, error));
        CHECK(error == StoreError::NotStore);
    };
    refused([](const std::string& inboxes, const std::string&) {
        write_file(inboxes + "/README", 1U);
    });
    refused([](const std::string& inboxes, const std::string&) {
        write_file(inboxes + "/" + hex(address(2U)), 1U);
    });
    refused([](const std::string& inboxes, const std::string& inbox) {
        CHECK(::symlink(inbox.c_str(),
                        (inboxes + "/" + hex(address(2U))).c_str()) == 0);
    });
    refused([](const std::string&, const std::string& inbox) {
        write_file(inbox + "/l1-00005200", 0U);
    });
    refused([](const std::string&, const std::string& inbox) {
        write_file(inbox + "/i1-short", kSmallItemBytes);
    });
    refused([](const std::string&, const std::string& inbox) {
        write_file(inbox + "/I1-" + std::string(16U, '0') + "-" +
                       std::string(32U, '0') + "-01c9c37b-01c9c3bc",
                   kSmallItemBytes);
    });
    // A message name without its order.
    refused([](const std::string&, const std::string& inbox) {
        write_file(
            inbox + "/i1-" + std::string(32U, '0') + "-01c9c37b-01c9c3bc",
            kSmallItemBytes);
    });
    refused([](const std::string&, const std::string& inbox) {
        const std::string target = inbox + "/../../format";
        CHECK(::symlink(target.c_str(),
                        (inbox + "/" + file_name(message(0x08U, kNowMinute)))
                            .c_str()) == 0);
    });
}

// Inside a private user and mount namespace: a tmpfs small enough to fill.
// The child keeps its own user ID, so the store's owner check still applies.
int run_full_disk(const std::string& mount_point) {
    const uid_t uid = ::geteuid();
    const gid_t gid = ::getegid();
    if (::unshare(CLONE_NEWUSER | CLONE_NEWNS) != 0) return kSkipped;
    const auto put = [](const char* path, const std::string& text) {
        const int file = ::open(path, O_WRONLY | O_CLOEXEC);
        if (file < 0) return false;
        const bool written = ::write(file, text.data(), text.size()) ==
                             static_cast<ssize_t>(text.size());
        ::close(file);
        return written;
    };
    if (!put("/proc/self/setgroups", "deny") ||
        !put("/proc/self/uid_map",
             std::to_string(uid) + " " + std::to_string(uid) + " 1") ||
        !put("/proc/self/gid_map",
             std::to_string(gid) + " " + std::to_string(gid) + " 1"))
        return kSkipped;
    if (::mount("none", "/", nullptr, MS_REC | MS_PRIVATE, nullptr) != 0 ||
        ::mount("ito-mailbox-test", mount_point.c_str(), "tmpfs",
                MS_NOSUID | MS_NODEV | MS_NOEXEC,
                "size=256k,nr_inodes=64,mode=0700") != 0)
        return kSkipped;

    const std::string data = mount_point + "/data";
    const std::string filler = mount_point + "/filler";
    CHECK(::mkdir(data.c_str(), 0700) == 0);
    CHECK(::mkdir(filler.c_str(), 0700) == 0);
    const Store store = must_open(data);
    const std::string inboxes = data + "/inboxes";

    // Inodes: use every one, then free one at a time.
    std::size_t fillers = 0U;
    for (;; ++fillers) {
        const std::string name = filler + "/" + std::to_string(fillers);
        const int file =
            ::open(name.c_str(), O_WRONLY | O_CREAT | O_EXCL, 0600);
        if (file < 0) {
            CHECK(errno == ENOSPC);
            break;
        }
        ::close(file);
    }
    CHECK(fillers > 2U);
    const auto free_one = [&] {
        CHECK(::unlink((filler + "/" + std::to_string(--fillers)).c_str()) ==
              0);
    };
    CHECK(store.create_inbox(address(1U), kToday + 30U) == IoResult::NoSpace);
    CHECK(entries(inboxes).empty());
    // Room for the directory but not its registration.
    free_one();
    CHECK(store.create_inbox(address(1U), kToday + 30U) == IoResult::NoSpace);
    CHECK(entries(inboxes).empty());
    free_one();
    CHECK(store.create_inbox(address(1U), kToday + 30U) == IoResult::Ok);
    while (fillers > 0U) free_one();

    // Bytes: fill the disk, then free less than a large message needs.
    const std::string ballast = filler + "/ballast";
    const int file = ::open(ballast.c_str(), O_WRONLY | O_CREAT, 0600);
    CHECK(file >= 0);
    const std::vector<char> chunk(4096U, 'b');
    off_t size = 0;
    for (;;) {
        const ssize_t written = ::write(file, chunk.data(), chunk.size());
        if (written < 0) {
            CHECK(errno == ENOSPC);
            break;
        }
        size += written;
    }
    CHECK(::ftruncate(file, size / 4096 * 4096 - 8192) == 0);
    const std::string inbox = inboxes + "/" + hex(address(1U));
    const MessageName name = message(0x0aU, kNowMinute + 60U);
    const auto bytes = sealed(kLargeItemBytes, 5U);
    CHECK(store.write_message(address(1U), name, bytes) == IoResult::NoSpace);
    CHECK(entries(inbox) == std::vector<std::string>{"l1-0000517f"});
    CHECK(::ftruncate(file, 0) == 0);
    ::close(file);
    CHECK(store.write_message(address(1U), name, bytes) == IoResult::Ok);
    std::vector<std::byte> out(kLargeItemBytes);
    CHECK(store.read_message(address(1U), name, out) == Store::ReadResult::Ok);
    CHECK(out == bytes);
    return 0;
}

// Runs the full-disk case in a child, which may enter namespaces because
// this process has no other thread.
bool test_full_disk() {
    TempDirectory root;
    std::fflush(nullptr);
    const pid_t child = ::fork();
    CHECK(child >= 0);
    if (child == 0) std::_Exit(run_full_disk(root.path()));
    int status = 0;
    CHECK(::waitpid(child, &status, 0) == child);
    CHECK(WIFEXITED(status));
    if (WEXITSTATUS(status) == kSkipped) return false;
    CHECK(WEXITSTATUS(status) == 0);
    return true;
}

}  // namespace

int main() {
    test_open_rules();
    test_operations();
    test_load();
    test_load_refusals();
    if (!test_full_disk()) {
        std::puts("store: the full-disk case needs user namespaces; skipped");
        return kSkipped;
    }
    std::puts("store: all checks passed");
    return 0;
}
