/* Copyright (C) 2026 FixCraft Inc. AGPL-3.0-or-later. */

// ito-call: the Linux call endpoint. It manages a local identity and its
// contacts in a host test store, pairs with identity 2 and exchanges
// messages through a mailbox service or a stub mailbox directory, and
// places or answers a profile-1 test call through a libyume stream to the
// call relay. It uses only the public Ito and YUME C interfaces. It doubles
// as the host test peer.
//
// Commands print one JSON object. Secrets never appear in output: the
// invitation and the pairing code go only to the file named for them, as
// the out-of-band channel, and message text only to the history files.

#include <ito/call.h>
#include <ito/message.h>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <map>
#include <memory>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#include "carrier.hpp"
#include "host_store.hpp"
#include "yume_transport.hpp"

namespace {

using Bytes = std::vector<uint8_t>;
using Clock = std::chrono::steady_clock;

constexpr const char* kUsage =
    "usage: ito-call --store DIR COMMAND [options]\n"
    "  version\n"
    "  identity create | identity show | identity upgrade\n"
    "  contact add CODE NAME | contact verify CODE FINGERPRINT\n"
    "  contact block CODE | contact replace OLD_CODE NEW_CODE | contact list\n"
    "  contact safety-code CODE | contact compare CODE DIGITS\n"
    "  pair code --kind in-person|link MAILBOX --name NAME --code-out FILE\n"
    "            [CARRIER]\n"
    "  pair scan --code FILE --source scanned|link MAILBOX --name NAME "
    "CARRIER\n"
    "  pair collect CARRIER | pair confirm CODE CARRIER\n"
    "  pair decide ID match|differ | pair cancel ID | pair list\n"
    "  message send CODE --text FILE [--drop] CARRIER\n"
    "  message collect CARRIER | message check CODE --hold SECONDS CARRIER\n"
    "  message resend CODE ID CARRIER\n"
    "  message outbox CODE | message history CODE\n"
    "  mailbox show CARRIER\n"
    "  call --peer CODE --invitation-out FILE CONNECTION [DATA]\n"
    "  answer --invitation FILE [--decline | --no-decision] CONNECTION [DATA]\n"
    "CONNECTION: --yume-config DIR --service NAME [--resolver PATH]\n"
    "            [--lifetime SECONDS] --result FILE\n"
    "DATA: [--send FILE] [--expect-bytes N] [--received-out FILE]\n"
    "      [--hangup-after-ms N] [--hold-ms N]\n"
    "MAILBOX: --mailbox FINGERPRINT --mailbox-service NAME\n"
    "CARRIER: --stub DIR | --yume-config DIR --service NAME [--resolver "
    "PATH]\n";

struct Failure final : std::runtime_error {
    using std::runtime_error::runtime_error;
};

uint64_t now_unix() {
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch())
            .count());
}

uint64_t now_ms() {
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch())
            .count());
}

std::string hex(const uint8_t* bytes, size_t size) {
    static constexpr char digits[] = "0123456789abcdef";
    std::string out;
    for (size_t index = 0; index < size; ++index) {
        out += digits[bytes[index] >> 4];
        out += digits[bytes[index] & 15];
    }
    return out;
}

void require(ito_status status, const char* step) {
    if (status != ITO_STATUS_OK) {
        throw Failure(std::string(step) + ": " + ito_status_name(status));
    }
}

// A minimal JSON object writer for fixed keys and plain values.
class Json final {
public:
    Json& text(const std::string& key, const std::string& value) {
        add(key, "\"" + value + "\"");
        return *this;
    }
    Json& number(const std::string& key, uint64_t value) {
        add(key, std::to_string(value));
        return *this;
    }
    Json& boolean(const std::string& key, bool value) {
        add(key, value ? "true" : "false");
        return *this;
    }
    Json& raw(const std::string& key, const std::string& value) {
        add(key, value);
        return *this;
    }
    [[nodiscard]] std::string str() const { return "{" + body_ + "}"; }

private:
    void add(const std::string& key, const std::string& value) {
        if (!body_.empty()) body_ += ",";
        body_ += "\"" + key + "\":" + value;
    }
    std::string body_;
};

struct Options final {
    std::string store;
    std::vector<std::string> positional;
    std::map<std::string, std::string> values;
    bool has(const std::string& key) const { return values.count(key) != 0U; }
    std::string get(const std::string& key) const {
        const auto found = values.find(key);
        if (found == values.end()) throw Failure("missing --" + key);
        return found->second;
    }
    std::string get_or(const std::string& key,
                       const std::string& fallback) const {
        const auto found = values.find(key);
        return found == values.end() ? fallback : found->second;
    }
};

Options parse(int argc, char** argv) {
    static const char* flags[] = {"decline", "no-decision", "drop"};
    Options options;
    for (int index = 1; index < argc; ++index) {
        const std::string argument = argv[index];
        if (!argument.starts_with("--")) {
            options.positional.push_back(argument);
            continue;
        }
        const std::string key = argument.substr(2);
        bool flag = false;
        for (const char* name : flags) flag = flag || key == name;
        if (flag) {
            options.values[key] = "1";
        } else if (index + 1 < argc) {
            options.values[key] = argv[++index];
        } else {
            throw Failure("--" + key + " needs a value");
        }
    }
    options.store = options.get_or("store", "");
    return options;
}

// Reads at most limit bytes, so a huge file or a FIFO cannot grow the buffer.
Bytes read_file(const std::string& path, size_t limit) {
    std::ifstream input(path, std::ios::binary);
    if (!input) throw Failure("cannot read " + path);
    Bytes bytes(limit + 1U);
    input.read(reinterpret_cast<char*>(bytes.data()),
               static_cast<std::streamsize>(bytes.size()));
    const auto got = static_cast<size_t>(input.gcount());
    if (got > limit) throw Failure(path + " is too large");
    bytes.resize(got);
    return bytes;
}

// Writes owner-only, failing if the file exists.
void write_private(const std::string& path, const uint8_t* bytes, size_t size) {
    const int descriptor =
        ::open(path.c_str(),
               O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (descriptor < 0) throw Failure("cannot create " + path);
    size_t offset = 0;
    while (offset < size) {
        const ssize_t written =
            ::write(descriptor, bytes + offset, size - offset);
        if (written <= 0) {
            ::close(descriptor);
            throw Failure("cannot write " + path);
        }
        offset += static_cast<size_t>(written);
    }
    const bool synced = ::fsync(descriptor) == 0;
    ::close(descriptor);
    if (!synced) throw Failure("cannot sync " + path);
}

void write_text(const std::string& path, const std::string& text) {
    write_private(path, reinterpret_cast<const uint8_t*>(text.data()),
                  text.size());
}

// The context and store, destroyed in order.
struct Session final {
    ito_context* context = nullptr;
    ito_store* store = nullptr;
    std::unique_ptr<ito::cli::HostStore> host;

    explicit Session(const std::string& directory) {
        if (directory.empty()) throw Failure("--store is required");
        host = std::make_unique<ito::cli::HostStore>(directory);
        require(ito_context_create(&context), "context");
        Bytes snapshot = host->load();
        ito_persistence persistence{sizeof(persistence), host.get(),
                                    ito::cli::host_store_persist};
        const ito_status opened = ito_store_open(
            context, snapshot.data(), snapshot.size(), &persistence, &store);
        if (!snapshot.empty()) explicit_bzero(snapshot.data(), snapshot.size());
        require(opened, "store");
    }
    Session(const Session&) = delete;
    Session& operator=(const Session&) = delete;
    ~Session() {
        if (store != nullptr) (void)ito_store_destroy(store);
        if (context != nullptr) (void)ito_context_destroy(context);
    }
};

std::array<uint8_t, ITO_KEY_BYTES> key_of(const std::string& code) {
    std::array<uint8_t, ITO_KEY_BYTES> key{};
    require(ito_contact_code_parse(code.data(), code.size(), key.data()),
            "contact code");
    return key;
}

const char* trust_name(uint32_t trust) {
    static const char* names[] = {"", "unverified", "verified", "blocked"};
    return names[trust <= 3U ? trust : 0U];
}

std::string contact_code(const uint8_t key[ITO_KEY_BYTES]) {
    char code[ITO_CONTACT_CODE_CHARS + 1];
    require(ito_contact_code_format(key, code, sizeof(code)), "format");
    return code;
}

std::string contact_json(ito_context* context, const ito_contact& contact) {
    char fingerprint[ITO_FINGERPRINT_CHARS + 1];
    require(
        ito_fingerprint(context, contact.key, fingerprint, sizeof(fingerprint)),
        "fingerprint");
    return Json()
        .text("code", contact_code(contact.key))
        .text("fingerprint", fingerprint)
        .text("trust", trust_name(contact.trust))
        .boolean("replaced", (contact.flags & ITO_CONTACT_REPLACED) != 0U)
        .boolean("replaces_other", (contact.flags & ITO_CONTACT_REPLACES) != 0U)
        .boolean("paired", (contact.flags & ITO_CONTACT_PAIRED) != 0U)
        .number("name_bytes", contact.name_size)
        .str();
}

std::string identity_command(Session& session, const Options& options) {
    const std::string action =
        options.positional.size() > 1 ? options.positional[1] : "";
    if (action == "create")
        require(ito_store_create_identity(session.store, now_unix()), "create");
    else if (action == "upgrade")
        require(ito_message_identity_upgrade(session.store), "upgrade");
    else if (action != "show")
        throw Failure(kUsage);
    uint8_t key[ITO_KEY_BYTES];
    require(ito_store_identity(session.store, key), "identity");
    char fingerprint[ITO_FINGERPRINT_CHARS + 1];
    require(
        ito_fingerprint(session.context, key, fingerprint, sizeof(fingerprint)),
        "fingerprint");
    Json json;
    json.text("code", contact_code(key)).text("fingerprint", fingerprint);
    uint8_t fingerprint2[ITO_FINGERPRINT2_BYTES];
    const ito_status upgraded =
        ito_message_identity_fingerprint(session.store, fingerprint2);
    if (upgraded == ITO_STATUS_OK) {
        json.text("fingerprint2", hex(fingerprint2, sizeof(fingerprint2)));
    } else if (upgraded != ITO_STATUS_WRONG_STATE) {
        require(upgraded, "fingerprint2");
    }
    return json.str();
}

std::string contact_command(Session& session, const Options& options) {
    const auto& args = options.positional;
    const std::string action = args.size() > 1 ? args[1] : "";
    if (action == "list") {
        size_t count = 0;
        require(ito_store_contact_count(session.store, &count), "count");
        std::string list = "[";
        for (size_t index = 0; index < count; ++index) {
            ito_contact contact{};
            contact.struct_size = sizeof(contact);
            require(ito_store_contact_at(session.store, index, &contact),
                    "contact");
            list += (index == 0 ? "" : ",") +
                    contact_json(session.context, contact);
        }
        return Json().raw("contacts", list + "]").str();
    }
    if (args.size() < 3) throw Failure(kUsage);
    const auto key = key_of(args[2]);
    if (action == "safety-code" && args.size() == 3) {
        char digits[ITO_SAFETY_CODE_DIGITS + 1];
        require(ito_message_safety_code(session.store, key.data(), digits,
                                        sizeof(digits)),
                "safety code");
        return Json().text("code", args[2]).text("safety_code", digits).str();
    }
    if (action == "add" && args.size() == 4) {
        require(ito_store_add_contact(session.store, key.data(), args[3].data(),
                                      args[3].size(), now_unix()),
                "add");
    } else if (action == "verify" && args.size() == 4) {
        require(
            ito_store_verify_contact(session.store, key.data(), args[3].data(),
                                     args[3].size(), now_unix()),
            "verify");
    } else if (action == "compare" && args.size() == 4) {
        require(ito_message_verify_safety_code(session.store, key.data(),
                                               args[3].data(), args[3].size(),
                                               now_unix()),
                "compare");
    } else if (action == "block" && args.size() == 3) {
        require(ito_store_block_contact(session.store, key.data()), "block");
    } else if (action == "replace" && args.size() == 4) {
        const auto replacement = key_of(args[3]);
        require(ito_store_replace_contact(session.store, key.data(),
                                          replacement.data(), now_unix()),
                "replace");
    } else {
        throw Failure(kUsage);
    }
    ito_contact contact{};
    contact.struct_size = sizeof(contact);
    require(ito_store_find_contact(session.store, key.data(), &contact),
            "find");
    return contact_json(session.context, contact);
}

// Pairing and messages (ito/message.h) through a carrier.

template <size_t Size>
std::array<uint8_t, Size> parse_hex(const std::string& text, const char* what) {
    std::array<uint8_t, Size> bytes{};
    const auto digit = [&](char character) -> unsigned {
        if (character >= '0' && character <= '9') {
            return static_cast<unsigned>(character - '0');
        }
        if (character >= 'a' && character <= 'f') {
            return static_cast<unsigned>(character - 'a' + 10);
        }
        if (character >= 'A' && character <= 'F') {
            return static_cast<unsigned>(character - 'A' + 10);
        }
        throw Failure(std::string(what) + " must be hex");
    };
    if (text.size() != 2U * Size) {
        throw Failure(std::string(what) + " must be " +
                      std::to_string(2U * Size) + " hex digits");
    }
    for (size_t index = 0; index < Size; ++index) {
        bytes[index] = static_cast<uint8_t>((digit(text[2U * index]) << 4U) |
                                            digit(text[2U * index + 1U]));
    }
    return bytes;
}

ito_authority mailbox_of(const Options& options) {
    ito_authority authority{};
    authority.struct_size = sizeof(authority);
    const auto server =
        parse_hex<ITO_KEY_BYTES>(options.get("mailbox"), "--mailbox");
    std::copy(server.begin(), server.end(), authority.server_fingerprint);
    const std::string service = options.get("mailbox-service");
    if (service.size() > ITO_MAX_SERVICE_BYTES)
        throw Failure("--mailbox-service is too long");
    authority.service_size = service.size();
    std::copy(service.begin(), service.end(), authority.service);
    return authority;
}

// --stub DIR, or a mailbox service through a YUME client configuration.
std::unique_ptr<ito::cli::Carrier> carrier_of(const Options& options) {
    if (options.has("stub")) return ito::cli::stub_carrier(options.get("stub"));
    return ito::cli::mailbox_carrier(options.get("yume-config"),
                                     options.get_or("resolver", ""),
                                     options.get("service"));
}

Json target_fields(const ito_mailbox_target& target, size_t bytes) {
    Json json;
    json.text("mailbox", hex(target.server_fingerprint, ITO_KEY_BYTES))
        .text("service", std::string(target.service, target.service_size))
        .text("address", hex(target.address, ITO_MAILBOX_ADDRESS_BYTES))
        .number("bytes", bytes);
    return json;
}

const char* pairing_kind_name(uint32_t kind) {
    return kind == ITO_PAIRING_IN_PERSON ? "in-person" : "link";
}

const char* role_name(uint32_t role) {
    return role == ITO_PAIRING_ROLE_OWNER ? "owner" : "scanner";
}

std::string event_json(const ito_pairing_event& event) {
    static const char* kinds[] = {"",          "replied", "paired",
                                  "confirmed", "matched", "completed",
                                  "rejected"};
    return Json()
        .text("event", kinds[event.kind <= 6U ? event.kind : 0U])
        .text("pairing_id", hex(event.pairing_id, ITO_PAIRING_ID_BYTES))
        .text("role", role_name(event.role))
        .text("kind", pairing_kind_name(event.pairing_kind))
        .text("peer", contact_code(event.peer_key))
        .text("trust", trust_name(event.trust))
        .text("short_code", event.short_code)
        .number("peer_name_bytes", event.peer_name_size)
        .str();
}

std::string pairing_json(const ito_pairing_info& info) {
    static const char* states[] = {"", "open", "replied", "confirmed"};
    Json json;
    json.text("pairing_id", hex(info.pairing_id, ITO_PAIRING_ID_BYTES))
        .text("role", role_name(info.role))
        .text("kind", pairing_kind_name(info.kind))
        .text("state", states[info.state <= 3U ? info.state : 0U])
        .number("deadline", info.deadline_unix)
        .boolean("matched", info.matched != 0U)
        .text("short_code", info.short_code);
    if (info.has_peer != 0U) json.text("peer", contact_code(info.peer_key));
    return json.str();
}

std::vector<ito_pairing_info> pairing_list(Session& session) {
    size_t count = 0;
    require(ito_pairing_count(session.store, &count), "pairings");
    std::vector<ito_pairing_info> list(count);
    for (size_t index = 0; index < count; ++index) {
        list[index].struct_size = sizeof(ito_pairing_info);
        require(ito_pairing_at(session.store, index, &list[index]), "pairing");
    }
    return list;
}

// Whether a refusal comes from this machine (storage, clock, memory), so
// the item stays in the inbox for a later collect. Any other answer is
// final and the item is taken.
bool local_failure(ito_status status) {
    switch (status) {
        case ITO_STATUS_STORAGE_FAILED:
        case ITO_STATUS_STORAGE_AMBIGUOUS:
        case ITO_STATUS_CLOCK_REGRESSED:
        case ITO_STATUS_BUSY:
        case ITO_STATUS_RESOURCE_LIMIT:
        case ITO_STATUS_DEPENDENCY_FAILURE:
        case ITO_STATUS_OUT_OF_MEMORY:
        case ITO_STATUS_INTERNAL:
            return true;
        default:
            return false;
    }
}

using MessageId = std::array<uint8_t, ITO_MESSAGE_ID_BYTES>;

// A contact's message session, opened from its file, or started from the
// pairing when there is none. A file from an earlier pairing gives way to
// the new pairing's session.
class ContactSession final {
public:
    ContactSession(Session& base, const std::array<uint8_t, ITO_KEY_BYTES>& key)
        : file_{base.host.get(), hex(key.data(), key.size())} {
        Bytes snapshot = base.host->load_session(file_.contact);
        const ito_persistence persistence{sizeof(persistence), &file_,
                                          ito::cli::session_file_persist};
        ito_status opened = ito_session_open(base.store, key.data(),
                                             snapshot.data(), snapshot.size(),
                                             &persistence, now_ms(), &session_);
        if (!snapshot.empty()) explicit_bzero(snapshot.data(), snapshot.size());
        if (opened == ITO_STATUS_WRONG_STATE && !snapshot.empty()) {
            opened = ito_session_open(base.store, key.data(), nullptr, 0U,
                                      &persistence, now_ms(), &session_);
        }
        require(opened, "session");
    }
    ContactSession(const ContactSession&) = delete;
    ContactSession& operator=(const ContactSession&) = delete;
    ~ContactSession() {
        if (session_ != nullptr) (void)ito_session_destroy(session_);
    }
    [[nodiscard]] ito_session* get() const noexcept { return session_; }

private:
    ito::cli::SessionFile file_;
    ito_session* session_{nullptr};
};

const char* message_kind_name(uint32_t kind) {
    switch (kind) {
        case ITO_MESSAGE_TEXT:
            return "text";
        case ITO_MESSAGE_RECEIPT:
            return "receipt";
        case ITO_MESSAGE_CHECK:
            return "check";
        case ITO_MESSAGE_MISSING:
            return "missing";
        case ITO_MESSAGE_PROFILE:
            return "profile";
        case ITO_MESSAGE_TIMER:
            return "timer";
        default:
            return "other";
    }
}

std::string ids_json(const uint8_t* ids, size_t count) {
    std::string list = "[";
    for (size_t index = 0; index < count; ++index) {
        list += (index == 0 ? "\"" : ",\"") +
                hex(ids + index * ITO_MESSAGE_ID_BYTES, ITO_MESSAGE_ID_BYTES) +
                "\"";
    }
    return list + "]";
}

// What one received message asks of this endpoint: receipts for the
// messages it holds, a Missing list for a check, and resends.
struct Delivery final {
    const ito::cli::HostStore* host{nullptr};
    std::string contact;
    std::string json;
    std::vector<MessageId> confirm;
    std::vector<MessageId> missing;
    std::vector<MessageId> resend;
};

MessageId id_at(const uint8_t* ids, size_t index) {
    MessageId id{};
    std::copy_n(ids + index * ITO_MESSAGE_ID_BYTES, id.size(), id.begin());
    return id;
}

// The history callback. Text, profile and timer messages are stored once
// by ID, and every other kind is answered after the session is saved.
int32_t deliver(void* user_data, const ito_message* message) {
    try {
        auto* delivery = static_cast<Delivery*>(user_data);
        const std::string id = hex(message->id, ITO_MESSAGE_ID_BYTES);
        Json json;
        json.text("kind", message_kind_name(message->kind))
            .text("id", id)
            .number("sent_ms", message->sent_ms)
            .boolean("resent", (message->flags & ITO_MESSAGE_RESENT) != 0U);
        if (message->kind == ITO_MESSAGE_TIMER) {
            json.number("timer", message->timer);
        }
        if (message->ids != nullptr) {
            json.raw("ids", ids_json(message->ids, message->id_count));
        }
        if (message->kind == ITO_MESSAGE_RECEIPT) {
            json.text("receipt", message->receipt == ITO_RECEIPT_READ
                                     ? "read"
                                     : "delivered");
        }
        // The collect output names the message. Only the history holds text.
        delivery->json = json.str();
        if (message->text != nullptr) {
            json.text("text_hex", hex(message->text, message->text_size));
        }
        switch (message->kind) {
            case ITO_MESSAGE_TEXT:
            case ITO_MESSAGE_PROFILE:
            case ITO_MESSAGE_TIMER:
                if (!delivery->host->hold(delivery->contact, id,
                                          json.str() + "\n")) {
                    return ITO_PERSIST_NOT_COMMITTED;
                }
                delivery->confirm.push_back(id_at(message->id, 0U));
                break;
            case ITO_MESSAGE_CHECK:
                for (size_t index = 0; index < message->id_count; ++index) {
                    const MessageId checked = id_at(message->ids, index);
                    const bool held = delivery->host->holds(
                        delivery->contact, hex(checked.data(), checked.size()));
                    (held ? delivery->confirm : delivery->missing)
                        .push_back(checked);
                }
                break;
            case ITO_MESSAGE_MISSING:
                for (size_t index = 0; index < message->id_count; ++index) {
                    delivery->resend.push_back(id_at(message->ids, index));
                }
                break;
            default:
                break;
        }
        return ITO_PERSIST_COMMITTED;
    } catch (...) {
        return ITO_PERSIST_NOT_COMMITTED;
    }
}

// Whether a refused message stays in its inbox for a later collect: the
// contact is not Verified yet, or the failure is this machine's.
bool keep_message(ito_status status) {
    return status == ITO_STATUS_UNTRUSTED || local_failure(status);
}

// Opens every inbox the store lists that the carrier has not opened. A
// mailbox refuses deposits to an inbox nobody opened, so a new inbox opens
// before a code or an item that names it leaves this phone.
void open_inboxes(Session& session, ito::cli::Carrier& carrier) {
    size_t count = 0;
    require(ito_message_inbox_count(session.store, &count), "inboxes");
    std::vector<ito_inbox> inboxes(count);
    try {
        for (size_t index = 0; index < count; ++index) {
            inboxes[index].struct_size = sizeof(ito_inbox);
            require(ito_message_inbox_at(session.store, index, &inboxes[index]),
                    "inbox");
        }
        carrier.open(inboxes);
    } catch (...) {
        for (ito_inbox& inbox : inboxes) {
            explicit_bzero(inbox.secret, sizeof(inbox.secret));
        }
        throw;
    }
    for (ito_inbox& inbox : inboxes) {
        explicit_bzero(inbox.secret, sizeof(inbox.secret));
    }
}

std::string deposit_json(ito::cli::Carrier& carrier,
                         const ito_mailbox_target& target, const uint8_t* item,
                         size_t size) {
    const uint32_t hold = carrier.deposit(target, item, size);
    return target_fields(target, size).number("hold", hold).str();
}

// Seals and deposits one message of IDs, in lists of at most 64.
void send_ids(ito_session* session, ito::cli::Carrier& carrier, uint32_t kind,
              const std::vector<MessageId>& ids, std::string& sent) {
    for (size_t first = 0; first < ids.size(); first += ITO_MAX_MESSAGE_IDS) {
        const size_t count =
            std::min<size_t>(ITO_MAX_MESSAGE_IDS, ids.size() - first);
        ito_message message{};
        message.struct_size = sizeof(message);
        message.kind = kind;
        message.receipt = ITO_RECEIPT_DELIVERED;
        message.ids = ids[first].data();
        message.id_count = count;
        uint8_t id[ITO_MESSAGE_ID_BYTES];
        ito_mailbox_target target{};
        target.struct_size = sizeof(target);
        std::vector<uint8_t> item(ITO_MAX_ITEM_BYTES);
        size_t item_size = 0;
        require(ito_session_send(session, &message, now_ms(), id, &target,
                                 item.data(), item.size(), &item_size),
                "send");
        const std::string deposited =
            deposit_json(carrier, target, item.data(), item_size);
        sent += (sent.size() == 1U ? "" : ",") +
                Json()
                    .text("kind", message_kind_name(kind))
                    .raw("ids", ids_json(ids[first].data(), count))
                    .raw("deposited", deposited)
                    .str();
    }
}

// One pass of what the platform does: every inbox the store lists, every
// item waiting there, handed to the core. Pairing items come first. A
// reply or confirm the core returns is deposited before the item it answers
// is taken, so a crash in between delivers that item again, which the core
// then refuses as spent. Messages at a contact's inbox go to its session,
// and the answers they ask for are sent once every item is handled.
std::string collect(Session& session, ito::cli::Carrier& carrier) {
    size_t count = 0;
    require(ito_message_inbox_count(session.store, &count), "inboxes");
    std::vector<ito_inbox> inboxes(count);
    for (size_t index = 0; index < count; ++index) {
        inboxes[index].struct_size = sizeof(ito_inbox);
        require(ito_message_inbox_at(session.store, index, &inboxes[index]),
                "inbox");
    }
    std::vector<ito::cli::WaitingItem> waiting;
    try {
        waiting = carrier.collect(inboxes);
    } catch (...) {
        for (ito_inbox& inbox : inboxes) {
            explicit_bzero(inbox.secret, sizeof(inbox.secret));
        }
        throw;
    }
    for (ito_inbox& inbox : inboxes) {
        explicit_bzero(inbox.secret, sizeof(inbox.secret));
    }
    std::map<std::string, std::unique_ptr<ContactSession>> sessions;
    std::map<std::string, Delivery> answers;
    std::string results = "[";
    std::vector<uint8_t> answer(ITO_MAX_ITEM_BYTES);
    for (const ito::cli::WaitingItem& item : waiting) {
        const ito_inbox& inbox = inboxes[item.inbox];
        ito_pairing_event event{};
        event.struct_size = sizeof(event);
        ito_mailbox_target to{};
        to.struct_size = sizeof(to);
        size_t answer_size = 0;
        ito_status status = ito_pairing_receive(
            session.store, inbox.mailbox.address, item.bytes.data(),
            item.bytes.size(), now_unix(), &event, &to, answer.data(),
            answer.size(), &answer_size);
        Json row;
        row.text("address",
                 hex(inbox.mailbox.address, ITO_MAILBOX_ADDRESS_BYTES));
        bool keep = local_failure(status);
        if (status == ITO_STATUS_OK) {
            row.raw("event", event_json(event));
            if (event.has_item != 0U) {
                // The answer names a new inbox of ours for the contact.
                open_inboxes(session, carrier);
                row.raw("deposited",
                        deposit_json(carrier, to, answer.data(), answer_size));
            }
        } else if (status == ITO_STATUS_NOT_FOUND &&
                   inbox.purpose == ITO_INBOX_CONTACT) {
            const std::array<uint8_t, ITO_KEY_BYTES> key = [&] {
                std::array<uint8_t, ITO_KEY_BYTES> result{};
                std::copy_n(inbox.contact_key, result.size(), result.begin());
                return result;
            }();
            const std::string contact = hex(key.data(), key.size());
            row.text("peer", contact_code(key.data()));
            auto& open = sessions[contact];
            try {
                if (!open)
                    open = std::make_unique<ContactSession>(session, key);
            } catch (const Failure& error) {
                // Such as a lost session, which needs pairing again. Its
                // items stay where they are.
                results += (results.size() == 1U ? "" : ",") +
                           row.text("status", error.what())
                               .boolean("taken", false)
                               .str();
                sessions.erase(contact);
                continue;
            }
            Delivery delivery{session.host.get(), contact, "", {}, {}, {}};
            const ito_message_sink sink{sizeof(sink), &delivery, deliver};
            status = ito_session_receive(open->get(), item.bytes.data(),
                                         item.bytes.size(), now_ms(), &sink);
            if (status == ITO_STATUS_OK) {
                row.raw("message", delivery.json);
                Delivery& owed = answers[contact];
                const auto append = [](std::vector<MessageId>& into,
                                       const std::vector<MessageId>& from) {
                    into.insert(into.end(), from.begin(), from.end());
                };
                append(owed.confirm, delivery.confirm);
                append(owed.missing, delivery.missing);
                append(owed.resend, delivery.resend);
            }
            keep = keep_message(status);
        }
        row.text("status", ito_status_name(status));
        if (!keep) carrier.take(inboxes, item);
        row.boolean("taken", !keep);
        results += (results.size() == 1U ? "" : ",") + row.str();
    }
    std::string sent = "[";
    for (auto& [contact, owed] : answers) {
        ito_session* open = sessions.at(contact)->get();
        send_ids(open, carrier, ITO_MESSAGE_RECEIPT, owed.confirm, sent);
        send_ids(open, carrier, ITO_MESSAGE_MISSING, owed.missing, sent);
        for (const MessageId& id : owed.resend) {
            ito_mailbox_target target{};
            target.struct_size = sizeof(target);
            std::vector<uint8_t> item(ITO_MAX_ITEM_BYTES);
            size_t item_size = 0;
            const ito_status resent =
                ito_session_resend(open, id.data(), now_ms(), &target,
                                   item.data(), item.size(), &item_size);
            // Confirmed since the contact asked: nothing to send.
            if (resent == ITO_STATUS_NOT_FOUND) continue;
            require(resent, "resend");
            sent += (sent.size() == 1U ? "" : ",") +
                    Json()
                        .text("kind", "resent")
                        .text("id", hex(id.data(), id.size()))
                        .raw("deposited", deposit_json(carrier, target,
                                                       item.data(), item_size))
                        .str();
        }
    }
    return Json().raw("received", results + "]").raw("sent", sent + "]").str();
}

std::string pair_command(Session& session, const Options& options) {
    const auto& args = options.positional;
    const std::string action = args.size() > 1 ? args[1] : "";
    if (action == "code" && args.size() == 2) {
        const std::string kind = options.get("kind");
        if (kind != "in-person" && kind != "link") throw Failure(kUsage);
        const ito_authority mailbox = mailbox_of(options);
        const std::string name = options.get("name");
        uint8_t id[ITO_PAIRING_ID_BYTES];
        char code[ITO_MAX_PAIRING_CODE_CHARS + 1];
        size_t code_size = 0;
        require(ito_pairing_code_create(
                    session.store,
                    kind == "link" ? ITO_PAIRING_LINK : ITO_PAIRING_IN_PERSON,
                    &mailbox, name.data(), name.size(), now_unix(), id, code,
                    sizeof(code), &code_size),
                "pairing code");
        // The code holds the pairing secret: it goes only to its file, once
        // its pairing inbox is open on the mailbox, when one is given.
        try {
            if (options.has("stub") || options.has("yume-config")) {
                open_inboxes(session, *carrier_of(options));
            }
            write_private(options.get("code-out"),
                          reinterpret_cast<const uint8_t*>(code), code_size);
        } catch (...) {
            explicit_bzero(code, sizeof(code));
            (void)ito_pairing_cancel(session.store, id);
            throw;
        }
        explicit_bzero(code, sizeof(code));
        for (const ito_pairing_info& info : pairing_list(session)) {
            if (std::memcmp(info.pairing_id, id, sizeof(id)) == 0) {
                return pairing_json(info);
            }
        }
        throw Failure("the new pairing is missing");
    }
    if (action == "scan" && args.size() == 2) {
        const std::string source = options.get("source");
        if (source != "scanned" && source != "link") throw Failure(kUsage);
        const ito_authority mailbox = mailbox_of(options);
        const std::string name = options.get("name");
        const std::unique_ptr<ito::cli::Carrier> carrier = carrier_of(options);
        Bytes code =
            read_file(options.get("code"), ITO_MAX_PAIRING_CODE_CHARS + 1U);
        if (!code.empty() && code.back() == '\n') code.pop_back();
        uint8_t id[ITO_PAIRING_ID_BYTES];
        ito_mailbox_target target{};
        target.struct_size = sizeof(target);
        std::vector<uint8_t> hello(ITO_MAX_ITEM_BYTES);
        size_t hello_size = 0;
        const ito_status scanned = ito_pairing_scan(
            session.store, reinterpret_cast<const char*>(code.data()),
            code.size(),
            source == "scanned" ? ITO_PAIRING_SOURCE_SCANNED
                                : ITO_PAIRING_SOURCE_LINK,
            &mailbox, name.data(), name.size(), now_unix(), id, &target,
            hello.data(), hello.size(), &hello_size);
        if (!code.empty()) explicit_bzero(code.data(), code.size());
        require(scanned, "scan");
        // The hello names the inbox the reply comes to.
        open_inboxes(session, *carrier);
        return Json()
            .text("pairing_id", hex(id, sizeof(id)))
            .raw("deposited",
                 deposit_json(*carrier, target, hello.data(), hello_size))
            .str();
    }
    if (action == "collect" && args.size() == 2) {
        return collect(session, *carrier_of(options));
    }
    if (action == "confirm" && args.size() == 3) {
        const auto key = key_of(args[2]);
        const std::unique_ptr<ito::cli::Carrier> carrier = carrier_of(options);
        ito_mailbox_target target{};
        target.struct_size = sizeof(target);
        std::vector<uint8_t> item(ITO_MAX_ITEM_BYTES);
        size_t item_size = 0;
        require(ito_pairing_confirm_item(session.store, key.data(), &target,
                                         item.data(), item.size(), &item_size),
                "confirm");
        return Json()
            .raw("deposited",
                 deposit_json(*carrier, target, item.data(), item_size))
            .str();
    }
    if (action == "decide" && args.size() == 4 &&
        (args[3] == "match" || args[3] == "differ")) {
        const auto id =
            parse_hex<ITO_PAIRING_ID_BYTES>(args[2], "the pairing ID");
        ito_pairing_event event{};
        event.struct_size = sizeof(event);
        require(ito_pairing_decide(session.store, id.data(), args[3] == "match",
                                   now_unix(), &event),
                "decide");
        return event_json(event);
    }
    if (action == "cancel" && args.size() == 3) {
        const auto id =
            parse_hex<ITO_PAIRING_ID_BYTES>(args[2], "the pairing ID");
        require(ito_pairing_cancel(session.store, id.data()), "cancel");
        return Json()
            .text("pairing_id", args[2])
            .boolean("canceled", true)
            .str();
    }
    if (action == "list" && args.size() == 2) {
        std::string list = "[";
        for (const ito_pairing_info& info : pairing_list(session)) {
            list += (list.size() == 1U ? "" : ",") + pairing_json(info);
        }
        return Json().raw("pairings", list + "]").str();
    }
    throw Failure(kUsage);
}

std::string outbox_json(const ito_outbox_entry& entry) {
    return Json()
        .text("id", hex(entry.id, ITO_MESSAGE_ID_BYTES))
        .text("kind", message_kind_name(entry.kind))
        .number("sent_ms", entry.sent_ms)
        .number("sealed", entry.sealed_unix)
        .number("checked", entry.checked_unix)
        .str();
}

std::string message_command(Session& session, const Options& options) {
    const auto& args = options.positional;
    const std::string action = args.size() > 1 ? args[1] : "";
    if (action == "collect" && args.size() == 2) {
        return collect(session, *carrier_of(options));
    }
    if (args.size() < 3) throw Failure(kUsage);
    const auto key = key_of(args[2]);
    if (action == "history" && args.size() == 3) {
        std::string list = "[";
        for (std::string record :
             session.host->history(hex(key.data(), key.size()))) {
            if (!record.empty() && record.back() == '\n') record.pop_back();
            list += (list.size() == 1U ? "" : ",") + record;
        }
        return Json().raw("history", list + "]").str();
    }
    ContactSession chat(session, key);
    if (action == "outbox" && args.size() == 3) {
        size_t count = 0;
        require(ito_session_outbox_count(chat.get(), &count), "outbox");
        std::string list = "[";
        for (size_t index = 0; index < count; ++index) {
            ito_outbox_entry entry{};
            entry.struct_size = sizeof(entry);
            require(ito_session_outbox_at(chat.get(), index, &entry), "entry");
            list += (index == 0 ? "" : ",") + outbox_json(entry);
        }
        return Json().raw("outbox", list + "]").str();
    }
    ito_mailbox_target target{};
    target.struct_size = sizeof(target);
    std::vector<uint8_t> item(ITO_MAX_ITEM_BYTES);
    size_t item_size = 0;
    if (action == "send" && args.size() == 3) {
        Bytes text = read_file(options.get("text"), ITO_MAX_TEXT_BYTES);
        ito_message message{};
        message.struct_size = sizeof(message);
        message.kind = ITO_MESSAGE_TEXT;
        message.text = text.data();
        message.text_size = text.size();
        uint8_t id[ITO_MESSAGE_ID_BYTES];
        const ito_status sent =
            ito_session_send(chat.get(), &message, now_ms(), id, &target,
                             item.data(), item.size(), &item_size);
        if (!text.empty()) explicit_bzero(text.data(), text.size());
        require(sent, "send");
        Json json;
        json.text("id", hex(id, sizeof(id))).number("bytes", item_size);
        // --drop seals without depositing, as a relay that lost the item.
        if (options.has("drop")) return json.boolean("deposited", false).str();
        const std::unique_ptr<ito::cli::Carrier> carrier = carrier_of(options);
        return json
            .raw("deposited",
                 deposit_json(*carrier, target, item.data(), item_size))
            .str();
    }
    if (action == "resend" && args.size() == 4) {
        const auto id = parse_hex<ITO_MESSAGE_ID_BYTES>(args[3], "the ID");
        require(ito_session_resend(chat.get(), id.data(), now_ms(), &target,
                                   item.data(), item.size(), &item_size),
                "resend");
        const std::unique_ptr<ito::cli::Carrier> carrier = carrier_of(options);
        return Json()
            .text("id", args[3])
            .raw("deposited",
                 deposit_json(*carrier, target, item.data(), item_size))
            .str();
    }
    if (action == "check" && args.size() == 3) {
        const uint64_t hold = std::stoull(options.get("hold"));
        const std::unique_ptr<ito::cli::Carrier> carrier = carrier_of(options);
        std::string checks = "[";
        for (;;) {
            const ito_status status =
                ito_session_check(chat.get(), now_ms(), hold, &target,
                                  item.data(), item.size(), &item_size);
            if (status == ITO_STATUS_NOT_FOUND) break;
            require(status, "check");
            checks += (checks.size() == 1U ? "" : ",") +
                      deposit_json(*carrier, target, item.data(), item_size);
        }
        return Json().raw("checks", checks + "]").str();
    }
    throw Failure(kUsage);
}

ito_call_status status_of(ito_call* call) {
    ito_call_status status{};
    status.struct_size = sizeof(status);
    require(ito_call_status_get(call, &status), "status");
    return status;
}

// Exchanges the test payload once media is authorized: sends --send in DATA
// frames while collecting received DATA, until --expect-bytes arrived and the
// send finished. Payloads that arrived before the call ended stay readable
// after it, so draining continues until the core reports the queue empty.
// Returns what arrived.
Bytes exchange(ito_call* call, const Options& options,
               const std::atomic<bool>& running) {
    const Bytes payload = options.has("send")
                              ? read_file(options.get("send"), 64U << 20)
                              : Bytes{};
    const size_t expected = std::stoull(options.get_or("expect-bytes", "0"));
    Bytes received;
    size_t sent = 0;
    std::vector<uint8_t> buffer(ITO_MAX_DATA_BYTES);
    bool drained = false;
    while (!drained &&
           ((running && sent < payload.size()) || received.size() < expected)) {
        bool progressed = false;
        if (running && sent < payload.size()) {
            const size_t size =
                std::min<size_t>(ITO_MAX_DATA_BYTES, payload.size() - sent);
            const ito_status status =
                ito_call_send(call, payload.data() + sent, size);
            if (status == ITO_STATUS_OK) {
                sent += size;
                progressed = true;
            } else if (status != ITO_STATUS_WOULD_BLOCK) {
                break;
            }
        }
        size_t size = 0;
        ito_status taken = ITO_STATUS_OK;
        while ((taken = ito_call_receive(call, buffer.data(), buffer.size(),
                                         &size)) == ITO_STATUS_OK) {
            received.insert(received.end(), buffer.begin(),
                            buffer.begin() + static_cast<std::ptrdiff_t>(size));
            progressed = true;
        }
        // WRONG_STATE: the call ended and nothing more is queued.
        drained = taken == ITO_STATUS_WRONG_STATE;
        if (!progressed)
            std::this_thread::sleep_for(std::chrono::milliseconds(2));
    }
    return received;
}

std::string call_command(Session& session, const Options& options,
                         bool initiator) {
    const auto started = Clock::now();
    const std::string result_path = options.get("result");
    ito::cli::YumeStream stream(options.get("yume-config"),
                                options.get_or("resolver", ""),
                                options.get("service"), 30'000U);
    const ito_authority authority = stream.authority();
    ito_call* call = nullptr;
    if (initiator) {
        const auto peer = key_of(options.get("peer"));
        // The core checks 1..600; only refuse what uint32_t cannot carry.
        const unsigned long long requested =
            std::stoull(options.get_or("lifetime", "120"));
        if (requested > UINT32_MAX) throw Failure("--lifetime is out of range");
        const auto lifetime = static_cast<uint32_t>(requested);
        require(
            ito_call_create_initiator(session.store, peer.data(), &authority,
                                      lifetime, now_unix(), &call),
            "create");
    } else {
        Bytes invitation =
            read_file(options.get("invitation"), ITO_MAX_INVITATION_BYTES);
        ito_invitation* opened = nullptr;
        const ito_status status = ito_invitation_open(
            session.store, invitation.data(), invitation.size(), &authority,
            now_unix(), &opened);
        if (!invitation.empty())
            explicit_bzero(invitation.data(), invitation.size());
        require(status, "invitation");
        ito_invitation_info info{};
        info.struct_size = sizeof(info);
        const ito_status inspected = ito_invitation_info_get(opened, &info);
        if (inspected != ITO_STATUS_OK || info.profile != 1U) {
            (void)ito_invitation_destroy(opened);
            require(
                inspected != ITO_STATUS_OK ? inspected : ITO_STATUS_UNSUPPORTED,
                "diagnostic-profile");
        }
        const ito_status created = ito_call_create_responder(
            session.store, opened, &authority, now_unix(), &call);
        if (created != ITO_STATUS_OK) (void)ito_invitation_destroy(opened);
        require(created, "create");
    }
    std::atomic<bool> running{true};
    std::atomic<int> run_result{ITO_STATUS_INTERNAL};
    ito_transport transport = stream.transport();
    std::thread runner([&] {
        run_result = ito_call_run(call, &transport);
        running = false;
    });
    // Whatever unwinds this function stops the attempt and joins its runner
    // before the call, its store or its transport can go away.
    struct Join final {
        ito_call* call;
        std::thread& runner;
        ~Join() {
            if (runner.joinable()) {
                (void)ito_call_cancel(call);
                runner.join();
            }
        }
    } join_guard{call, runner};
    bool invitation_written = false;
    bool decided = false;
    bool exchanged = false;
    Bytes received;
    const uint64_t hangup_after =
        std::stoull(options.get_or("hangup-after-ms", "0"));
    const uint64_t hold = std::stoull(options.get_or("hold-ms", "0"));
    while (running) {
        const ito_call_status status = status_of(call);
        if (initiator && !invitation_written &&
            (status.flags & ITO_CALL_FLAG_INVITATION_READY)) {
            uint8_t invitation[ITO_MAX_INVITATION_BYTES];
            size_t size = 0;
            require(ito_call_copy_invitation(call, invitation,
                                             sizeof(invitation), &size),
                    "copy");
            write_private(options.get("invitation-out"), invitation, size);
            explicit_bzero(invitation, sizeof(invitation));
            invitation_written = true;
        }
        if (!initiator && !decided &&
            (status.flags & ITO_CALL_FLAG_CONSENT_PENDING) &&
            !options.has("no-decision")) {
            require(ito_call_decide(call, options.has("decline") ? 0 : 1),
                    "decide");
            decided = true;
        }
        if (status.state == ITO_CALL_MEDIA_AUTHORIZED && !exchanged) {
            received = exchange(call, options, running);
            exchanged = true;
            if (hold != 0)
                std::this_thread::sleep_for(std::chrono::milliseconds(hold));
            // The initiator ends a completed test call. The responder waits
            // for its END unless told otherwise.
            if (initiator || hangup_after != 0) {
                if (hangup_after != 0)
                    std::this_thread::sleep_for(
                        std::chrono::milliseconds(hangup_after));
                (void)ito_call_hangup(call);
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    runner.join();
    const ito_call_status final_status = status_of(call);
    std::string evidence;
#if defined(ITO_CALL_EVIDENCE)
    std::vector<char> text(1U << 16);
    size_t size = 0;
    if (ito_call_evidence_json(call, text.data(), text.size(), &size) ==
        ITO_STATUS_OK) {
        evidence.assign(text.data(), size);
    }
#endif
    // The call's TLS and secrets go before its transport closes.
    require(ito_call_destroy(call), "destroy");
    if (options.has("received-out")) {
        write_private(options.get("received-out"), received.data(),
                      received.size());
    }
    char version[128];
    require(ito_component_version(version, sizeof(version)), "version");
    const std::string json =
        Json()
            .text("role", initiator ? "initiator" : "responder")
            .text("result",
                  ito_status_name(static_cast<ito_status>(run_result.load())))
            .number("state", final_status.state)
            .boolean("peer_authenticated",
                     final_status.flags & ITO_CALL_FLAG_PEER_AUTHENTICATED)
            .boolean("remote_end_attributed",
                     final_status.flags & ITO_CALL_FLAG_REMOTE_END_ATTRIBUTED)
            .number("local_end", final_status.local_end_reason)
            .number("remote_end", final_status.remote_end_reason)
            .number("relay_refusal", final_status.relay_refusal)
            .number("data_sent", final_status.data_bytes_sent)
            .number("data_received", final_status.data_bytes_received)
            .number("frames_sent", final_status.frames_sent)
            .number("frames_received", final_status.frames_received)
            .number("key_updates_sent", final_status.key_updates_sent)
            .number("key_updates_received", final_status.key_updates_received)
            .text("relay_fingerprint",
                  hex(authority.server_fingerprint, ITO_KEY_BYTES))
            .text("component", version)
            .number("milliseconds",
                    static_cast<uint64_t>(
                        std::chrono::duration_cast<std::chrono::milliseconds>(
                            Clock::now() - started)
                            .count()))
            .raw("evidence", evidence.empty() ? "null" : evidence)
            .str();
    write_text(result_path, json + "\n");
    return json;
}

}  // namespace

int main(int argc, char** argv) {
    try {
        const Options options = parse(argc, argv);
        if (options.positional.empty()) throw Failure(kUsage);
        const std::string& command = options.positional[0];
        if (command == "version") {
            char version[128];
            require(ito_component_version(version, sizeof(version)), "version");
            std::printf("%s\n",
                        Json().text("component", version).str().c_str());
            return 0;
        }
        Session session(options.store);
        std::string output;
        if (command == "identity") {
            output = identity_command(session, options);
        } else if (command == "contact") {
            output = contact_command(session, options);
        } else if (command == "pair") {
            output = pair_command(session, options);
        } else if (command == "message") {
            output = message_command(session, options);
        } else if (command == "mailbox" && options.positional.size() == 2 &&
                   options.positional[1] == "show") {
            // The verified service a pairing code should name as its mailbox.
            const std::unique_ptr<ito::cli::Carrier> carrier =
                carrier_of(options);
            const ito_authority* authority = carrier->authority();
            if (authority == nullptr) throw Failure("a stub has no authority");
            output = Json()
                         .text("mailbox", hex(authority->server_fingerprint,
                                              ITO_KEY_BYTES))
                         .text("service", std::string(authority->service,
                                                      authority->service_size))
                         .str();
        } else if (command == "call" || command == "answer") {
            output = call_command(session, options, command == "call");
        } else {
            throw Failure(kUsage);
        }
        std::printf("%s\n", output.c_str());
        return 0;
    } catch (const std::exception& error) {
        std::fprintf(stderr, "ito-call: %s\n", error.what());
        return 2;
    }
}
