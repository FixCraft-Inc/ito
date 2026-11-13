/* Copyright (C) 2026 FixCraft Inc. AGPL-3.0-or-later. */

// Message sessions through the packaged library (ito/message.h), the way a
// platform uses them: two phones pair, open a session each and exchange
// messages through a mailbox keyed by inbox address. Then the outbox with
// check and resend, trust, the save order under refused and ambiguous
// storage, and an allocation failure at every index of pairing and of each
// session operation. This file sees only the public headers.

#include <ito/message.h>

#include <algorithm>
#include <array>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <new>
#include <string>
#include <vector>

#include "check.hpp"
#include "message_platform.hpp"

// Allocation failure for this test binary only, as in api_test: once armed
// on a thread, the replacement operator new fails that thread's Nth
// allocation, the packaged library's included, and operator delete reports
// a freed block that still holds the armed secret.
namespace {

thread_local std::size_t t_fail_at = 0U;  // 0: disarmed
thread_local std::size_t t_allocations = 0U;
thread_local bool t_failed = false;
thread_local const uint8_t* t_secret = nullptr;  // 32 bytes
thread_local bool t_secret_freed = false;

struct alignas(std::max_align_t) Header {
    std::size_t size;
};

void* allocate(std::size_t size) {
    if (t_fail_at != 0U && ++t_allocations == t_fail_at) {
        t_failed = true;
        throw std::bad_alloc();
    }
    auto* header = static_cast<Header*>(std::malloc(sizeof(Header) + size));
    if (header == nullptr) throw std::bad_alloc();
    header->size = size;
    return header + 1;
}

void release(void* memory) noexcept {
    if (memory == nullptr) return;
    Header* header = static_cast<Header*>(memory) - 1;
    if (t_fail_at != 0U && t_secret != nullptr && header->size >= 32U) {
        const auto* bytes = static_cast<const uint8_t*>(memory);
        if (std::search(bytes, bytes + header->size, t_secret, t_secret + 32) !=
            bytes + header->size) {
            t_secret_freed = true;
        }
    }
    std::free(header);
}

// Platform callbacks run disarmed: a callback that cannot allocate is the
// platform's failure, not the core's.
class Disarmed final {
public:
    Disarmed() noexcept : saved_(t_fail_at) { t_fail_at = 0U; }
    Disarmed(const Disarmed&) = delete;
    Disarmed& operator=(const Disarmed&) = delete;
    ~Disarmed() { t_fail_at = saved_; }

private:
    std::size_t saved_;
};

}  // namespace

void* operator new(std::size_t size) {
    return allocate(size);
}
void* operator new[](std::size_t size) {
    return allocate(size);
}
void* operator new(std::size_t size, const std::nothrow_t&) noexcept {
    try {
        return allocate(size);
    } catch (const std::bad_alloc&) {
        return nullptr;
    }
}
void* operator new[](std::size_t size, const std::nothrow_t&) noexcept {
    try {
        return allocate(size);
    } catch (const std::bad_alloc&) {
        return nullptr;
    }
}
void operator delete(void* memory) noexcept {
    release(memory);
}
void operator delete[](void* memory) noexcept {
    release(memory);
}
void operator delete(void* memory, std::size_t) noexcept {
    release(memory);
}
void operator delete[](void* memory, std::size_t) noexcept {
    release(memory);
}
void operator delete(void* memory, const std::nothrow_t&) noexcept {
    release(memory);
}
void operator delete[](void* memory, const std::nothrow_t&) noexcept {
    release(memory);
}

namespace {

using namespace ito::call::testing;
using Id = std::array<uint8_t, ITO_MESSAGE_ID_BYTES>;

constexpr std::size_t kMaxInjections = 8192U;

template <class Operation>
bool fails_at(std::size_t n, Operation&& operation) {
    t_allocations = 0U;
    t_failed = false;
    t_fail_at = n;
    operation();
    t_fail_at = 0U;
    return t_failed;
}

// What the platform's history received.
struct Received final {
    uint32_t kind{0U};
    Id id{};
    uint64_t sent_ms{0U};
    uint32_t flags{0U};
    std::string text;
    uint32_t receipt{0U};
    std::vector<Id> ids;
    uint32_t timer{0U};
};

struct History final {
    std::vector<Received> arrivals;
    std::map<Id, Received> held;
    int32_t result{ITO_PERSIST_COMMITTED};
    std::size_t calls{0U};
};

int32_t deliver(void* user_data, const ito_message* message) {
    const Disarmed disarmed;
    auto* history = static_cast<History*>(user_data);
    ++history->calls;
    if (history->result != ITO_PERSIST_COMMITTED) return history->result;
    CHECK(message->struct_size == sizeof(ito_message));
    Received received;
    received.kind = message->kind;
    std::memcpy(received.id.data(), message->id, received.id.size());
    received.sent_ms = message->sent_ms;
    received.flags = message->flags;
    if (message->text != nullptr) {
        received.text.assign(reinterpret_cast<const char*>(message->text),
                             message->text_size);
    }
    received.receipt = message->receipt;
    for (size_t index = 0U; index < message->id_count; ++index) {
        Id id{};
        std::memcpy(id.data(), message->ids + index * ITO_MESSAGE_ID_BYTES,
                    id.size());
        received.ids.push_back(id);
    }
    received.timer = message->timer;
    history->arrivals.push_back(received);
    // A repeat with a known ID is recognized, not stored twice.
    history->held.emplace(received.id, received);
    return ITO_PERSIST_COMMITTED;
}

ito_message text_message(const std::string& text) {
    ito_message message{};
    message.struct_size = sizeof(message);
    message.kind = ITO_MESSAGE_TEXT;
    message.text = reinterpret_cast<const uint8_t*>(text.data());
    message.text_size = text.size();
    return message;
}

ito_message ids_message(uint32_t kind, const std::vector<Id>& ids,
                        uint32_t receipt = 0U) {
    ito_message message{};
    message.struct_size = sizeof(message);
    message.kind = kind;
    message.receipt = receipt;
    message.ids = ids.empty() ? nullptr : ids.front().data();
    message.id_count = ids.size();
    return message;
}

// One phone's session with one contact, its snapshot file and history.
struct Chat final {
    Phone& phone;
    const Phone& peer;
    Disk disk;
    History history;
    ito_session* session{nullptr};
    Address inbox{};

    Chat(Phone& own, const Phone& contact) : phone(own), peer(contact) {
        disk.bytes.reserve(1U << 20U);
        ito_paired_contact paired{};
        paired.struct_size = sizeof(paired);
        CHECK(ito_message_contact_get(phone.store, peer.key, &paired) ==
              ITO_STATUS_OK);
        std::memcpy(inbox.data(), paired.receive.address, inbox.size());
    }
    Chat(const Chat&) = delete;
    Chat& operator=(const Chat&) = delete;
    ~Chat() { close(); }

    ito_status open(uint64_t now_ms, bool from_disk) {
        const ito_persistence persistence{sizeof(ito_persistence), &disk,
                                          persist_disk};
        const uint8_t* bytes = from_disk ? disk.bytes.data() : nullptr;
        const size_t size = from_disk ? disk.bytes.size() : 0U;
        return ito_session_open(phone.store, peer.key, bytes, size,
                                &persistence, now_ms, &session);
    }
    void close() {
        if (session != nullptr) {
            CHECK(ito_session_destroy(session) == ITO_STATUS_OK);
        }
        session = nullptr;
    }

    // Seals a message and deposits it when the core says so.
    ito_status send(const ito_message& message, uint64_t now_ms, Id& id) {
        ito_mailbox_target target{};
        target.struct_size = sizeof(target);
        std::vector<uint8_t> item(ITO_MAX_ITEM_BYTES);
        size_t item_size = 0U;
        const ito_status status =
            ito_session_send(session, &message, now_ms, id.data(), &target,
                             item.data(), item.size(), &item_size);
        if (status == ITO_STATUS_OK) deposit(target, item.data(), item_size);
        return status;
    }
    Id send_text(const std::string& text, uint64_t now_ms) {
        Id id{};
        CHECK(send(text_message(text), now_ms, id) == ITO_STATUS_OK);
        return id;
    }

    // The items waiting at this chat's inbox, oldest first.
    std::vector<Bytes> take() {
        std::vector<Bytes> items = std::move(g_mailbox[inbox]);
        g_mailbox.erase(inbox);
        return items;
    }
    ito_status receive(const Bytes& item, uint64_t now_ms) {
        const ito_message_sink sink{sizeof(ito_message_sink), &history,
                                    deliver};
        return ito_session_receive(session, item.data(), item.size(), now_ms,
                                   &sink);
    }
    // Receives everything waiting, each expected to succeed.
    void receive_all(uint64_t now_ms) {
        for (const Bytes& item : take()) {
            CHECK(receive(item, now_ms) == ITO_STATUS_OK);
        }
    }

    std::vector<ito_outbox_entry> outbox() const {
        size_t count = 0U;
        CHECK(ito_session_outbox_count(session, &count) == ITO_STATUS_OK);
        std::vector<ito_outbox_entry> entries(count);
        for (size_t index = 0U; index < count; ++index) {
            entries[index].struct_size = sizeof(ito_outbox_entry);
            CHECK(ito_session_outbox_at(session, index, &entries[index]) ==
                  ITO_STATUS_OK);
        }
        return entries;
    }
};

uint64_t g_ms = 0U;

// Two upgraded phones on one mailbox.
struct Couple final {
    Phone ana;
    Phone ben;
    explicit Couple(ito_context* context)
        : ana(context, 0xA1), ben(context, 0xA1) {
        CHECK(ito_message_identity_upgrade(ana.store) == ITO_STATUS_OK);
        CHECK(ito_message_identity_upgrade(ben.store) == ITO_STATUS_OK);
    }
};

void test_conversation(ito_context* context) {
    Couple couple(context);
    pair(couple.ana, couple.ben, ITO_PAIRING_IN_PERSON);
    Chat ana(couple.ana, couple.ben);
    Chat ben(couple.ben, couple.ana);

    // The scanner deposits its confirm before the session takes the
    // pairing's keys. After that it cannot be rebuilt.
    ito_mailbox_target target{};
    target.struct_size = sizeof(target);
    std::vector<uint8_t> item(ITO_MAX_ITEM_BYTES);
    size_t item_size = 0U;
    CHECK(ito_pairing_confirm_item(couple.ben.store, couple.ana.key, &target,
                                   item.data(), item.size(),
                                   &item_size) == ITO_STATUS_OK);
    CHECK(ben.open(g_ms, false) == ITO_STATUS_OK);
    CHECK(ito_pairing_confirm_item(couple.ben.store, couple.ana.key, &target,
                                   item.data(), item.size(),
                                   &item_size) == ITO_STATUS_WRONG_STATE);
    // One session per contact, and a store outlives its sessions.
    ito_session* second = nullptr;
    const ito_persistence persistence{sizeof(ito_persistence), &ben.disk,
                                      persist_disk};
    CHECK(ito_session_open(couple.ben.store, couple.ana.key, nullptr, 0U,
                           &persistence, g_ms, &second) == ITO_STATUS_BUSY);
    CHECK(ito_store_destroy(couple.ben.store) == ITO_STATUS_WRONG_STATE);
    // A lost snapshot cannot be rebuilt once the keys are gone.
    ben.close();
    CHECK(ben.open(g_ms, false) == ITO_STATUS_CORRUPT_STATE);
    CHECK(ben.open(g_ms, true) == ITO_STATUS_OK);

    // The owner may send first, from its own first chain.
    CHECK(ana.open(g_ms, false) == ITO_STATUS_OK);
    const Id hello = ana.send_text("Hello Ben", g_ms += 1000U);
    const Id first = ben.send_text("Running late", g_ms += 1000U);
    const Id second_text = ben.send_text("Train stopped", g_ms += 1000U);
    CHECK(ben.outbox().size() == 2U);
    ben.receive_all(g_ms += 1000U);
    CHECK(ben.history.arrivals.size() == 1U &&
          ben.history.arrivals[0].text == "Hello Ben" &&
          ben.history.arrivals[0].id == hello &&
          ben.history.arrivals[0].kind == ITO_MESSAGE_TEXT);
    const std::vector<Bytes> waiting = ana.take();
    CHECK(waiting.size() == 2U);
    // A damaged item fails, reaches no history and changes nothing.
    Bytes damaged = waiting[0];
    damaged[200] ^= 1U;
    Bytes before = ana.disk.bytes;
    CHECK(ana.receive(damaged, g_ms) == ITO_STATUS_AUTHENTICATION_FAILED);
    CHECK(ana.history.calls == 0U && ana.disk.bytes == before);
    for (const Bytes& received : waiting) {
        CHECK(ana.receive(received, g_ms) == ITO_STATUS_OK);
    }
    CHECK(ana.history.arrivals.size() == 2U &&
          ana.history.arrivals[0].id == first &&
          ana.history.arrivals[1].text == "Train stopped" &&
          ana.history.arrivals[1].flags == 0U);
    // A repeat delivery names a used key: no history call, no change.
    before = ana.disk.bytes;
    const std::size_t calls = ana.history.calls;
    CHECK(ana.receive(waiting[0], g_ms) == ITO_STATUS_ALREADY_SPENT);
    CHECK(ana.receive(damaged, g_ms) == ITO_STATUS_ALREADY_SPENT);
    CHECK(ana.history.calls == calls && ana.disk.bytes == before);

    // A Delivered receipt for one of them leaves the other in the outbox.
    Id receipt_id{};
    CHECK(ana.send(
              ids_message(ITO_MESSAGE_RECEIPT, {first}, ITO_RECEIPT_DELIVERED),
              g_ms += 1000U, receipt_id) == ITO_STATUS_OK);
    ben.receive_all(g_ms);
    CHECK(ben.history.arrivals.back().kind == ITO_MESSAGE_RECEIPT &&
          ben.history.arrivals.back().receipt == ITO_RECEIPT_DELIVERED &&
          ben.history.arrivals.back().ids == std::vector<Id>{first});
    std::vector<ito_outbox_entry> outbox = ben.outbox();
    CHECK(outbox.size() == 1U &&
          std::memcmp(outbox[0].id, second_text.data(), 16U) == 0 &&
          outbox[0].kind == ITO_MESSAGE_TEXT && outbox[0].checked_unix == 0U);
    // Receipts are not kept: the outbox of Ana stays at her one text.
    CHECK(ana.outbox().size() == 1U);

    // Profile and timer travel and wait for receipts like text.
    ito_message profile{};
    profile.struct_size = sizeof(profile);
    profile.kind = ITO_MESSAGE_PROFILE;
    const std::string name = "Ana K.";
    profile.text = reinterpret_cast<const uint8_t*>(name.data());
    profile.text_size = name.size();
    Id profile_id{};
    CHECK(ana.send(profile, g_ms += 1000U, profile_id) == ITO_STATUS_OK);
    ito_message timer{};
    timer.struct_size = sizeof(timer);
    timer.kind = ITO_MESSAGE_TIMER;
    timer.timer = ITO_TIMER_WEEK;
    Id timer_id{};
    CHECK(ana.send(timer, g_ms += 1000U, timer_id) == ITO_STATUS_OK);
    ben.receive_all(g_ms);
    const std::size_t count = ben.history.arrivals.size();
    CHECK(ben.history.arrivals[count - 2U].kind == ITO_MESSAGE_PROFILE &&
          ben.history.arrivals[count - 2U].text == name &&
          ben.history.arrivals[count - 1U].kind == ITO_MESSAGE_TIMER &&
          ben.history.arrivals[count - 1U].timer == ITO_TIMER_WEEK);
    CHECK(ana.outbox().size() == 3U);
    Id read_id{};
    CHECK(ben.send(ids_message(ITO_MESSAGE_RECEIPT,
                               {timer_id, hello, profile_id}, ITO_RECEIPT_READ),
                   g_ms += 1000U, read_id) == ITO_STATUS_OK);
    ana.receive_all(g_ms);
    CHECK(ana.outbox().empty());

    // The caller's input must follow each kind's rules.
    Id unused{};
    const std::string control = "bell\x07";
    CHECK(ana.send(text_message(control), g_ms, unused) ==
          ITO_STATUS_INVALID_ARGUMENT);
    CHECK(ana.send(text_message(std::string(ITO_MAX_TEXT_BYTES + 1U, 'a')),
                   g_ms, unused) == ITO_STATUS_INVALID_ARGUMENT);
    CHECK(ana.send(text_message(std::string(ITO_MAX_TEXT_BYTES, 'a')), g_ms,
                   unused) == ITO_STATUS_OK);
    CHECK(ana.send(ids_message(ITO_MESSAGE_CHECK, {first}), g_ms, unused) ==
          ITO_STATUS_INVALID_ARGUMENT);
    CHECK(ana.send(ids_message(ITO_MESSAGE_MISSING, {first, first}), g_ms,
                   unused) == ITO_STATUS_INVALID_ARGUMENT);
    CHECK(ana.send(ids_message(ITO_MESSAGE_RECEIPT, {first}, 3U), g_ms,
                   unused) == ITO_STATUS_INVALID_ARGUMENT);
    CHECK(ana.send(ids_message(ITO_MESSAGE_MISSING,
                               std::vector<Id>(ITO_MAX_MESSAGE_IDS + 1U)),
                   g_ms, unused) == ITO_STATUS_INVALID_ARGUMENT);
    timer.timer = 4U;
    CHECK(ana.send(timer, g_ms, unused) == ITO_STATUS_INVALID_ARGUMENT);
    ito_message ring{};
    ring.struct_size = sizeof(ring);
    ring.kind = 5U;
    CHECK(ana.send(ring, g_ms, unused) == ITO_STATUS_INVALID_ARGUMENT);
    const ito_message small = text_message("x");
    CHECK(ito_session_send(ana.session, &small, g_ms, unused.data(), &target,
                           item.data(), ITO_MAX_ITEM_BYTES - 1U,
                           &item_size) == ITO_STATUS_BUFFER_TOO_SMALL);
    ben.receive_all(g_ms);
    CHECK(ben.history.arrivals.back().text.size() == ITO_MAX_TEXT_BYTES);
    CHECK(g_mailbox.empty());
}

void test_check_and_resend(ito_context* context) {
    Couple couple(context);
    pair(couple.ana, couple.ben, ITO_PAIRING_IN_PERSON);
    Chat ana(couple.ana, couple.ben);
    Chat ben(couple.ben, couple.ana);
    CHECK(ana.open(g_ms, false) == ITO_STATUS_OK);
    CHECK(ben.open(g_ms, false) == ITO_STATUS_OK);
    const uint64_t sent = g_ms += 1000U;
    const Id one = ben.send_text("one", sent);
    const Id two = ben.send_text("two", sent);
    const Id three = ben.send_text("three", sent);
    // The relay lost the second.
    std::vector<Bytes> items = ana.take();
    CHECK(items.size() == 3U);
    CHECK(ana.receive(items[0], sent) == ITO_STATUS_OK);
    CHECK(ana.receive(items[2], sent) == ITO_STATUS_OK);
    Id unused{};
    CHECK(ana.send(ids_message(ITO_MESSAGE_RECEIPT, {three, one},
                               ITO_RECEIPT_DELIVERED),
                   sent, unused) == ITO_STATUS_OK);
    ben.receive_all(sent);
    CHECK(ben.outbox().size() == 1U);

    // A check waits a hold period after the sealing, then lists the message.
    constexpr uint64_t kHold = 3600U;
    ito_mailbox_target target{};
    target.struct_size = sizeof(target);
    std::vector<uint8_t> item(ITO_MAX_ITEM_BYTES);
    size_t item_size = 0U;
    CHECK(ito_session_check(ben.session, sent + kHold * 1000U - 1000U, kHold,
                            &target, item.data(), item.size(),
                            &item_size) == ITO_STATUS_NOT_FOUND);
    CHECK(ito_session_check(ben.session, sent, 0U, &target, item.data(),
                            item.size(),
                            &item_size) == ITO_STATUS_INVALID_ARGUMENT);
    const uint64_t due = sent + kHold * 1000U;
    CHECK(ito_session_check(ben.session, due, kHold, &target, item.data(),
                            item.size(), &item_size) == ITO_STATUS_OK);
    deposit(target, item.data(), item_size);
    CHECK(ben.outbox()[0].checked_unix == due / 1000U);
    CHECK(ito_session_check(ben.session, due, kHold, &target, item.data(),
                            item.size(), &item_size) == ITO_STATUS_NOT_FOUND);

    // Ana does not hold it and says so. Ben resends it.
    ana.receive_all(due);
    const Received& check = ana.history.arrivals.back();
    CHECK(check.kind == ITO_MESSAGE_CHECK && check.ids == std::vector<Id>{two});
    CHECK(ana.history.held.count(two) == 0U);
    CHECK(ana.send(ids_message(ITO_MESSAGE_MISSING, {two}), due, unused) ==
          ITO_STATUS_OK);
    ben.receive_all(due);
    CHECK(ben.history.arrivals.back().kind == ITO_MESSAGE_MISSING);
    CHECK(ito_session_resend(ben.session, two.data(), due, &target, item.data(),
                             item.size(), &item_size) == ITO_STATUS_OK);
    deposit(target, item.data(), item_size);
    ana.receive_all(due);
    const Received& resent = ana.history.arrivals.back();
    CHECK(resent.id == two && resent.text == "two" &&
          resent.flags == ITO_MESSAGE_RESENT && resent.sent_ms == sent);
    CHECK(
        ana.send(ids_message(ITO_MESSAGE_RECEIPT, {two}, ITO_RECEIPT_DELIVERED),
                 due, unused) == ITO_STATUS_OK);
    ben.receive_all(due);
    CHECK(ben.outbox().empty());
    CHECK(ito_session_resend(ben.session, two.data(), due, &target, item.data(),
                             item.size(), &item_size) == ITO_STATUS_NOT_FOUND);

    // A check is repeated each hold period, and lists at most 64.
    for (int index = 0; index < 70; ++index) (void)ben.send_text("x", due);
    CHECK(ben.outbox().size() == 70U);
    const uint64_t later = due + kHold * 1000U;
    CHECK(ito_session_check(ben.session, later, kHold, &target, item.data(),
                            item.size(), &item_size) == ITO_STATUS_OK);
    deposit(target, item.data(), item_size);
    CHECK(ito_session_check(ben.session, later, kHold, &target, item.data(),
                            item.size(), &item_size) == ITO_STATUS_OK);
    deposit(target, item.data(), item_size);
    CHECK(ito_session_check(ben.session, later, kHold, &target, item.data(),
                            item.size(), &item_size) == ITO_STATUS_NOT_FOUND);
    CHECK(ito_session_check(ben.session, later + kHold * 1000U, kHold, &target,
                            item.data(), item.size(),
                            &item_size) == ITO_STATUS_OK);
    deposit(target, item.data(), item_size);
    ana.receive_all(later + kHold * 1000U);
    std::size_t listed = 0U;
    for (std::size_t index = ana.history.arrivals.size() - 3U;
         index < ana.history.arrivals.size(); ++index) {
        CHECK(ana.history.arrivals[index].kind == ITO_MESSAGE_CHECK);
        listed += ana.history.arrivals[index].ids.size();
    }
    CHECK(listed == 64U + 6U + 64U);

    // The outbox holds 128. Receipts are never kept, so they still go.
    for (int index = 70; index < 128; ++index) (void)ben.send_text("x", later);
    CHECK(ben.send(text_message("full"), later, unused) == ITO_STATUS_CAPACITY);
    CHECK(ben.send(ids_message(ITO_MESSAGE_RECEIPT, {one}, ITO_RECEIPT_READ),
                   later, unused) == ITO_STATUS_OK);
    ana.receive_all(later);
    ben.receive_all(later);
    g_mailbox.clear();
}

void test_trust(ito_context* context) {
    // A link leaves both sides Not verified: no messages until they compare
    // the safety code. The item waits on the mailbox.
    Couple couple(context);
    pair(couple.ana, couple.ben, ITO_PAIRING_LINK);
    Chat ana(couple.ana, couple.ben);
    Chat ben(couple.ben, couple.ana);
    CHECK(ana.open(g_ms, false) == ITO_STATUS_OK);
    CHECK(ben.open(g_ms, false) == ITO_STATUS_OK);
    Id id{};
    CHECK(ben.send(text_message("early"), g_ms, id) == ITO_STATUS_UNTRUSTED);
    char code[ITO_SAFETY_CODE_DIGITS + 1U]{};
    CHECK(ito_message_safety_code(couple.ben.store, couple.ana.key, code,
                                  sizeof(code)) == ITO_STATUS_OK);
    CHECK(ito_message_verify_safety_code(couple.ben.store, couple.ana.key, code,
                                         ITO_SAFETY_CODE_DIGITS,
                                         now_unix()) == ITO_STATUS_OK);
    const Id early = ben.send_text("early", g_ms += 1000U);
    std::vector<Bytes> items = ana.take();
    CHECK(ana.receive(items[0], g_ms) == ITO_STATUS_UNTRUSTED);
    CHECK(ana.history.calls == 0U);
    CHECK(ito_message_verify_safety_code(couple.ana.store, couple.ben.key, code,
                                         ITO_SAFETY_CODE_DIGITS,
                                         now_unix()) == ITO_STATUS_OK);
    CHECK(ana.receive(items[0], g_ms) == ITO_STATUS_OK);
    CHECK(ana.history.arrivals.back().id == early);

    // Blocking stops both directions and a new session.
    CHECK(ito_store_block_contact(couple.ana.store, couple.ben.key) ==
          ITO_STATUS_OK);
    CHECK(ana.send(text_message("no"), g_ms, id) == ITO_STATUS_UNTRUSTED);
    (void)ben.send_text("blocked", g_ms);
    items = ana.take();
    CHECK(ana.receive(items[0], g_ms) == ITO_STATUS_UNTRUSTED);
    ana.close();
    CHECK(ana.open(g_ms, true) == ITO_STATUS_UNTRUSTED);

    // Pairing again gives a new pairing: the old session and its snapshot
    // answer WRONG_STATE, and a new session starts.
    Couple again(context);
    pair(again.ana, again.ben, ITO_PAIRING_IN_PERSON);
    Chat old(again.ben, again.ana);
    CHECK(old.open(g_ms, false) == ITO_STATUS_OK);
    (void)old.send_text("before", g_ms);
    std::vector<Bytes> stale;
    {
        const Chat earlier(again.ana, again.ben);
        stale = std::move(g_mailbox[earlier.inbox]);
        g_mailbox.erase(earlier.inbox);
    }
    pair(again.ana, again.ben, ITO_PAIRING_IN_PERSON);
    CHECK(old.send(text_message("after"), g_ms, id) == ITO_STATUS_WRONG_STATE);
    old.close();
    CHECK(old.open(g_ms, true) == ITO_STATUS_WRONG_STATE);
    CHECK(old.open(g_ms, false) == ITO_STATUS_OK);
    Chat fresh(again.ana, again.ben);
    CHECK(fresh.open(g_ms, false) == ITO_STATUS_OK);
    // The item sealed under the earlier pairing does not open.
    CHECK(stale.size() == 1U);
    CHECK(fresh.receive(stale[0], g_ms) == ITO_STATUS_AUTHENTICATION_FAILED);
    (void)old.send_text("after", g_ms);
    fresh.receive_all(g_ms);
    CHECK(fresh.history.arrivals.back().text == "after");
    g_mailbox.clear();
}

void test_save_order(ito_context* context) {
    Couple couple(context);
    pair(couple.ana, couple.ben, ITO_PAIRING_IN_PERSON);
    Chat ana(couple.ana, couple.ben);
    Chat ben(couple.ben, couple.ana);

    // Starting saves the session first. A refusal there keeps the seed.
    ben.disk.result = ITO_PERSIST_NOT_COMMITTED;
    CHECK(ben.open(g_ms, false) == ITO_STATUS_STORAGE_FAILED);
    CHECK(ben.session == nullptr && ben.disk.bytes.empty());
    // Then the store forgets the seed. A refusal there returns no session,
    // and the next open from the saved snapshot takes the seed.
    ben.disk.result = ITO_PERSIST_COMMITTED;
    couple.ben.disk.result = ITO_PERSIST_NOT_COMMITTED;
    CHECK(ben.open(g_ms, false) == ITO_STATUS_STORAGE_FAILED);
    CHECK(ben.session == nullptr && !ben.disk.bytes.empty());
    ito_mailbox_target target{};
    target.struct_size = sizeof(target);
    std::vector<uint8_t> item(ITO_MAX_ITEM_BYTES);
    size_t item_size = 0U;
    CHECK(ito_pairing_confirm_item(couple.ben.store, couple.ana.key, &target,
                                   item.data(), item.size(),
                                   &item_size) == ITO_STATUS_OK);
    couple.ben.disk.result = ITO_PERSIST_COMMITTED;
    CHECK(ben.open(g_ms, true) == ITO_STATUS_OK);
    CHECK(ito_pairing_confirm_item(couple.ben.store, couple.ana.key, &target,
                                   item.data(), item.size(),
                                   &item_size) == ITO_STATUS_WRONG_STATE);
    CHECK(ana.open(g_ms, false) == ITO_STATUS_OK);

    // A refused save hands out no item and changes nothing.
    Id id{};
    Bytes saved = ben.disk.bytes;
    ben.disk.result = ITO_PERSIST_NOT_COMMITTED;
    CHECK(ben.send(text_message("lost"), g_ms += 1000U, id) ==
          ITO_STATUS_STORAGE_FAILED);
    CHECK(ben.disk.bytes == saved && g_mailbox.empty() && ben.outbox().empty());
    ben.disk.result = ITO_PERSIST_COMMITTED;
    const Id kept = ben.send_text("kept", g_ms);
    // An ambiguous save latches the session until it is opened again from
    // what storage holds.
    saved = ben.disk.bytes;
    ben.disk.result = ITO_PERSIST_AMBIGUOUS;
    CHECK(ben.send(text_message("unsure"), g_ms, id) ==
          ITO_STATUS_STORAGE_AMBIGUOUS);
    ben.disk.result = ITO_PERSIST_COMMITTED;
    CHECK(ben.send(text_message("later"), g_ms, id) ==
          ITO_STATUS_STORAGE_AMBIGUOUS);
    ben.close();
    CHECK(ben.open(g_ms, true) == ITO_STATUS_OK && ben.disk.bytes == saved);
    const Id after = ben.send_text("after", g_ms);

    // Receiving: the history first, then the session. A history that
    // cannot store leaves the session as it was and the item waiting.
    std::vector<Bytes> items = ana.take();
    CHECK(items.size() == 2U);
    saved = ana.disk.bytes;
    ana.history.result = ITO_PERSIST_NOT_COMMITTED;
    CHECK(ana.receive(items[0], g_ms) == ITO_STATUS_STORAGE_FAILED);
    CHECK(ana.disk.bytes == saved && ana.history.calls == 1U);
    ana.history.result = ITO_PERSIST_COMMITTED;
    // A session that cannot save after the history stored the message: the
    // repeat delivery hands the same ID to the history again.
    ana.disk.result = ITO_PERSIST_NOT_COMMITTED;
    CHECK(ana.receive(items[0], g_ms) == ITO_STATUS_STORAGE_FAILED);
    CHECK(ana.disk.bytes == saved && ana.history.arrivals.size() == 1U);
    ana.disk.result = ITO_PERSIST_COMMITTED;
    CHECK(ana.receive(items[0], g_ms) == ITO_STATUS_OK);
    CHECK(ana.history.arrivals.size() == 2U &&
          ana.history.arrivals[0].id == kept &&
          ana.history.arrivals[1].id == kept && ana.history.held.size() == 1U);
    // Saved, but not yet taken from the mailbox: the repeat is a used key.
    CHECK(ana.receive(items[0], g_ms) == ITO_STATUS_ALREADY_SPENT);
    CHECK(ana.receive(items[1], g_ms) == ITO_STATUS_OK);
    CHECK(ana.history.arrivals.back().id == after);
    // An ambiguous save on receive latches as well.
    const Id last = ben.send_text("last", g_ms);
    items = ana.take();
    ana.disk.result = ITO_PERSIST_AMBIGUOUS;
    CHECK(ana.receive(items[0], g_ms) == ITO_STATUS_STORAGE_AMBIGUOUS);
    ana.disk.result = ITO_PERSIST_COMMITTED;
    CHECK(ana.receive(items[0], g_ms) == ITO_STATUS_STORAGE_AMBIGUOUS);
    ana.close();
    CHECK(ana.open(g_ms, true) == ITO_STATUS_OK);
    CHECK(ana.receive(items[0], g_ms) == ITO_STATUS_OK);
    CHECK(ana.history.arrivals.back().id == last);
    // A callback cannot call back into its session.
    struct Reentry final {
        ito_session* session;
        ito_status status{ITO_STATUS_OK};
    };
    Reentry reentry{ana.session};
    const ito_message_sink sink{
        sizeof(ito_message_sink), &reentry,
        [](void* user_data, const ito_message*) -> int32_t {
            auto* data = static_cast<Reentry*>(user_data);
            size_t count = 0U;
            data->status = ito_session_outbox_count(data->session, &count);
            return ITO_PERSIST_COMMITTED;
        }};
    (void)ben.send_text("reentry", g_ms);
    items = ana.take();
    CHECK(ito_session_receive(ana.session, items[0].data(), items[0].size(),
                              g_ms, &sink) == ITO_STATUS_OK);
    CHECK(reentry.status == ITO_STATUS_REENTRANT);
}

// The store's observable pairing state, compared across failed attempts.
std::string pairing_state(ito_store* store) {
    std::string state;
    size_t count = 0U;
    CHECK(ito_pairing_count(store, &count) == ITO_STATUS_OK);
    for (size_t index = 0U; index < count; ++index) {
        ito_pairing_info info{};
        info.struct_size = sizeof(info);
        CHECK(ito_pairing_at(store, index, &info) == ITO_STATUS_OK);
        state += std::to_string(info.role) + ":" + std::to_string(info.state) +
                 ":" + std::to_string(info.matched) + ";";
    }
    CHECK(ito_store_contact_count(store, &count) == ITO_STATUS_OK);
    state += "contacts " + std::to_string(count);
    CHECK(ito_message_inbox_count(store, &count) == ITO_STATUS_OK);
    return state + " inboxes " + std::to_string(count);
}

// The same, read from what the store's persistence holds.
std::string durable_state(ito_context* context, const Disk& disk) {
    Bytes copy;
    const ito_persistence persistence{sizeof(ito_persistence), &copy, persist};
    ito_store* store = nullptr;
    CHECK(ito_store_open(context, disk.bytes.data(), disk.bytes.size(),
                         &persistence, &store) == ITO_STATUS_OK);
    std::string state = pairing_state(store);
    CHECK(ito_store_destroy(store) == ITO_STATUS_OK);
    return state;
}

// Fails each allocation of operation in turn. Every failure is typed and
// leaves the live and the durable state as they were, and no freed block
// holds secret. The operation then succeeds.
template <class Operation, class State>
void sweep(const char* what, const uint8_t* secret, Operation&& operation,
           State&& state) {
    const std::string before = state();
    for (std::size_t n = 1U;; ++n) {
        CHECK(n < kMaxInjections);
        ito_status status = ITO_STATUS_OK;
        t_secret = secret;
        t_secret_freed = false;
        const bool failed = fails_at(n, [&] { status = operation(); });
        t_secret = nullptr;
        if (t_secret_freed) {
            std::fprintf(stderr, "%s: secret freed at allocation %zu\n", what,
                         n);
        }
        CHECK(!t_secret_freed);
        if (!failed) {
            CHECK(n > 1U);
            CHECK(status == ITO_STATUS_OK);
            std::printf("%s: %zu allocations failed in turn\n", what, n - 1U);
            return;
        }
        if (status != ITO_STATUS_OUT_OF_MEMORY) {
            std::fprintf(stderr, "%s: allocation %zu gave %s\n", what, n,
                         ito_status_name(status));
        }
        CHECK(status == ITO_STATUS_OUT_OF_MEMORY);
        CHECK(state() == before);
    }
}

void test_pairing_allocation(ito_context* context) {
    Couple couple(context);
    Phone& ana = couple.ana;
    Phone& ben = couple.ben;
    ana.disk.bytes.reserve(1U << 20U);
    ben.disk.bytes.reserve(1U << 20U);
    // The Ed25519 seed follows snapshot 2's 24-byte domain.
    const Bytes ana_seed(ana.disk.bytes.begin() + 24,
                         ana.disk.bytes.begin() + 56);
    const Bytes ben_seed(ben.disk.bytes.begin() + 24,
                         ben.disk.bytes.begin() + 56);
    const uint64_t now = now_unix();
    const auto ana_state = [&] {
        return pairing_state(ana.store) + "|" +
               durable_state(context, ana.disk);
    };
    const auto ben_state = [&] {
        return pairing_state(ben.store) + "|" +
               durable_state(context, ben.disk);
    };

    uint8_t id[ITO_PAIRING_ID_BYTES]{};
    char code[ITO_MAX_PAIRING_CODE_CHARS + 1U]{};
    size_t code_size = 0U;
    sweep(
        "pairing code", ana_seed.data(),
        [&] {
            return ito_pairing_code_create(ana.store, ITO_PAIRING_IN_PERSON,
                                           &ana.mailbox, "Ana", 3U, now, id,
                                           code, sizeof(code), &code_size);
        },
        ana_state);

    ito_mailbox_target target{};
    target.struct_size = sizeof(target);
    std::vector<uint8_t> item(ITO_MAX_ITEM_BYTES);
    size_t item_size = 0U;
    uint8_t scanned[ITO_PAIRING_ID_BYTES]{};
    sweep(
        "pairing scan", ben_seed.data(),
        [&] {
            return ito_pairing_scan(ben.store, code, code_size,
                                    ITO_PAIRING_SOURCE_SCANNED, &ben.mailbox,
                                    "Ben", 3U, now, scanned, &target,
                                    item.data(), item.size(), &item_size);
        },
        ben_state);
    deposit(target, item.data(), item_size);

    // Each received item: the hello, the reply and the confirm.
    const auto receive = [&](Phone& phone, const Bytes& seed,
                             const char* what) {
        ito_inbox inbox{};
        inbox.struct_size = sizeof(inbox);
        size_t count = 0U;
        CHECK(ito_message_inbox_count(phone.store, &count) == ITO_STATUS_OK);
        Bytes received;
        Address address{};
        for (size_t index = 0U; index < count && received.empty(); ++index) {
            CHECK(ito_message_inbox_at(phone.store, index, &inbox) ==
                  ITO_STATUS_OK);
            std::memcpy(address.data(), inbox.mailbox.address, address.size());
            if (!g_mailbox[address].empty()) {
                received = g_mailbox[address].front();
                g_mailbox.erase(address);
            }
        }
        CHECK(!received.empty());
        ito_pairing_event event{};
        event.struct_size = sizeof(event);
        const auto state = [&] {
            return pairing_state(phone.store) + "|" +
                   durable_state(context, phone.disk);
        };
        sweep(
            what, seed.data(),
            [&] {
                return ito_pairing_receive(phone.store, address.data(),
                                           received.data(), received.size(),
                                           now, &event, &target, item.data(),
                                           item.size(), &item_size);
            },
            state);
        if (event.has_item != 0U) deposit(target, item.data(), item_size);
        return event;
    };
    CHECK(receive(ana, ana_seed, "pairing hello").kind == ITO_PAIRING_REPLIED);
    CHECK(receive(ben, ben_seed, "pairing reply").kind == ITO_PAIRING_PAIRED);
    CHECK(receive(ana, ana_seed, "pairing confirm").kind ==
          ITO_PAIRING_CONFIRMED);
    ito_pairing_event decided{};
    decided.struct_size = sizeof(decided);
    sweep(
        "pairing decision", ana_seed.data(),
        [&] { return ito_pairing_decide(ana.store, id, 1, now, &decided); },
        ana_state);
    CHECK(decided.kind == ITO_PAIRING_COMPLETED);
    CHECK(g_mailbox.empty());
}

void test_session_allocation(ito_context* context) {
    Couple couple(context);
    pair(couple.ana, couple.ben, ITO_PAIRING_IN_PERSON);
    couple.ana.disk.bytes.reserve(1U << 20U);
    couple.ben.disk.bytes.reserve(1U << 20U);
    Chat ana(couple.ana, couple.ben);
    Chat ben(couple.ben, couple.ana);
    // Opening: a failure leaves the seed with the store and no session.
    // A first snapshot may have been saved, which the next open replaces.
    sweep(
        "session start", nullptr, [&] { return ben.open(g_ms, false); },
        [&] {
            return std::string(couple.ben.disk.bytes.begin(),
                               couple.ben.disk.bytes.end()) +
                   (ben.session != nullptr ? "open" : "");
        });
    CHECK(ana.open(g_ms, false) == ITO_STATUS_OK);
    // The session's root key follows its domain, contact and transcript.
    const auto root = [&](const Chat& chat) {
        return Bytes(chat.disk.bytes.begin() + 87,
                     chat.disk.bytes.begin() + 119);
    };
    const auto session_state = [&](const Chat& chat) {
        return [&chat] {
            return std::string(chat.disk.bytes.begin(), chat.disk.bytes.end()) +
                   std::to_string(g_mailbox.size());
        };
    };

    // Buffers exist before each sweep, so only the core's allocations fail.
    ito_mailbox_target target{};
    target.struct_size = sizeof(target);
    std::vector<uint8_t> item(ITO_MAX_ITEM_BYTES);
    size_t item_size = 0U;
    Bytes secret = root(ben);
    Id id{};
    const std::string hello = "hello";
    const ito_message message = text_message(hello);
    sweep(
        "session send", secret.data(),
        [&] {
            return ito_session_send(ben.session, &message, g_ms, id.data(),
                                    &target, item.data(), item.size(),
                                    &item_size);
        },
        session_state(ben));
    deposit(target, item.data(), item_size);
    std::vector<Bytes> items = ana.take();
    CHECK(items.size() == 1U);
    secret = root(ana);
    sweep(
        "session receive", secret.data(),
        [&] { return ana.receive(items[0], g_ms); }, session_state(ana));
    CHECK(ana.history.held.count(id) == 1U);
    secret = root(ben);
    sweep(
        "session resend", secret.data(),
        [&] {
            return ito_session_resend(ben.session, id.data(), g_ms, &target,
                                      item.data(), item.size(), &item_size);
        },
        session_state(ben));
    secret = root(ben);
    sweep(
        "session check", secret.data(),
        [&] {
            return ito_session_check(ben.session, g_ms + 2000U, 1U, &target,
                                     item.data(), item.size(), &item_size);
        },
        session_state(ben));
    g_mailbox.clear();
}

}  // namespace

int main() {
    ito_context* context = nullptr;
    CHECK(ito_context_create(&context) == ITO_STATUS_OK);
    g_ms = now_unix() * 1000U;
    test_conversation(context);
    test_check_and_resend(context);
    test_trust(context);
    test_save_order(context);
    test_pairing_allocation(context);
    test_session_allocation(context);
    CHECK(g_mailbox.empty());
    CHECK(ito_context_destroy(context) == ITO_STATUS_OK);
    std::puts("session tests passed");
    return 0;
}
