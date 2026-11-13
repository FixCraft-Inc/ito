/* Copyright (C) 2026 FixCraft Inc. AGPL-3.0-or-later. */

// A platform for the message tests, over the public headers only: phones
// with in-memory stores, a mailbox keyed by inbox address, the pass that
// hands each waiting pairing item to the core, and an in-person pairing.

#pragma once

#include <ito/message.h>

#include <array>
#include <chrono>
#include <cstring>
#include <map>
#include <string>
#include <vector>

#include "check.hpp"

namespace ito::call::testing {

using Bytes = std::vector<uint8_t>;
using Address = std::array<uint8_t, ITO_MAILBOX_ADDRESS_BYTES>;

inline uint64_t now_unix() {
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch())
            .count());
}

inline int32_t persist(void* user_data, const uint8_t* snapshot, size_t size) {
    static_cast<Bytes*>(user_data)->assign(snapshot, snapshot + size);
    return ITO_PERSIST_COMMITTED;
}

inline ito_authority mailbox_of(uint8_t server) {
    ito_authority result{};
    result.struct_size = sizeof(result);
    std::memset(result.server_fingerprint, server, ITO_KEY_BYTES);
    const char service[] = "ito-mailbox";
    result.service_size = sizeof(service) - 1U;
    std::memcpy(result.service, service, result.service_size);
    return result;
}

// Every deposited item, by inbox address. The real mailbox also keys by
// server and service, which the targets here always match.
inline std::map<Address, std::vector<Bytes>> g_mailbox;

inline void deposit(const ito_mailbox_target& target, const uint8_t* item,
                    size_t size) {
    CHECK(target.struct_size == sizeof(target));
    CHECK(size == 1024U || size == 4096U || size == 16384U);
    Address address{};
    std::memcpy(address.data(), target.address, address.size());
    g_mailbox[address].emplace_back(item, item + size);
}

// One snapshot file. result is what the next persist answers: only a
// committed persist replaces the bytes.
struct Disk final {
    Bytes bytes;
    int32_t result{ITO_PERSIST_COMMITTED};
    std::size_t writes{0U};
};

inline int32_t persist_disk(void* user_data, const uint8_t* snapshot,
                            size_t size) {
    auto* disk = static_cast<Disk*>(user_data);
    ++disk->writes;
    if (disk->result == ITO_PERSIST_COMMITTED) {
        disk->bytes.assign(snapshot, snapshot + size);
    }
    return disk->result;
}

struct Phone final {
    Disk disk;
    ito_store* store{nullptr};
    ito_authority mailbox{};
    uint8_t key[ITO_KEY_BYTES]{};

    Phone(ito_context* context, uint8_t server) : mailbox(mailbox_of(server)) {
        const ito_persistence persistence{sizeof(ito_persistence), &disk,
                                          persist_disk};
        CHECK(ito_store_open(context, nullptr, 0U, &persistence, &store) ==
              ITO_STATUS_OK);
        CHECK(ito_message_identity_upgrade(store) == ITO_STATUS_NOT_FOUND);
        CHECK(ito_store_create_identity(store, now_unix()) == ITO_STATUS_OK);
        CHECK(ito_store_identity(store, key) == ITO_STATUS_OK);
    }
    Phone(const Phone&) = delete;
    Phone& operator=(const Phone&) = delete;
    ~Phone() { CHECK(ito_store_destroy(store) == ITO_STATUS_OK); }
};

// One pass of the platform: open every listed inbox, hand each waiting
// item to the core, deposit what it answers. Returns the last event.
inline ito_pairing_event collect(Phone& phone,
                                 ito_status expected = ITO_STATUS_OK) {
    ito_pairing_event last{};
    last.struct_size = sizeof(last);
    size_t count = 0U;
    CHECK(ito_message_inbox_count(phone.store, &count) == ITO_STATUS_OK);
    std::vector<ito_inbox> inboxes(count);
    for (size_t index = 0U; index < count; ++index) {
        inboxes[index].struct_size = sizeof(ito_inbox);
        CHECK(ito_message_inbox_at(phone.store, index, &inboxes[index]) ==
              ITO_STATUS_OK);
        CHECK(inboxes[index].mailbox.struct_size == sizeof(ito_mailbox_target));
    }
    for (ito_inbox& inbox : inboxes) {
        Address address{};
        std::memcpy(address.data(), inbox.mailbox.address, address.size());
        const std::vector<Bytes> items = std::move(g_mailbox[address]);
        g_mailbox.erase(address);
        for (const Bytes& received : items) {
            ito_pairing_event event{};
            event.struct_size = sizeof(event);
            ito_mailbox_target target{};
            target.struct_size = sizeof(target);
            std::vector<uint8_t> item(ITO_MAX_ITEM_BYTES);
            size_t item_size = 0U;
            CHECK(ito_pairing_receive(phone.store, address.data(),
                                      received.data(), received.size(),
                                      now_unix(), &event, &target, item.data(),
                                      item.size(), &item_size) == expected);
            if (expected != ITO_STATUS_OK) continue;
            if (event.has_item != 0U) deposit(target, item.data(), item_size);
            last = event;
        }
        std::memset(inbox.secret, 0, sizeof(inbox.secret));
    }
    return last;
}

// Pairs two upgraded phones: the owner shows a code, the scanner reads it,
// and the items travel through the mailbox. In person, the owner also says
// the short codes match.
inline void pair(Phone& owner, Phone& scanner, uint32_t kind) {
    uint8_t id[ITO_PAIRING_ID_BYTES]{};
    char code[ITO_MAX_PAIRING_CODE_CHARS + 1U]{};
    size_t code_size = 0U;
    CHECK(ito_pairing_code_create(owner.store, kind, &owner.mailbox, "Owner",
                                  5U, now_unix(), id, code, sizeof(code),
                                  &code_size) == ITO_STATUS_OK);
    uint8_t scanned[ITO_PAIRING_ID_BYTES]{};
    ito_mailbox_target target{};
    target.struct_size = sizeof(target);
    std::vector<uint8_t> item(ITO_MAX_ITEM_BYTES);
    size_t item_size = 0U;
    const uint32_t source = kind == ITO_PAIRING_IN_PERSON
                                ? ITO_PAIRING_SOURCE_SCANNED
                                : ITO_PAIRING_SOURCE_LINK;
    CHECK(ito_pairing_scan(scanner.store, code, code_size, source,
                           &scanner.mailbox, "Scanner", 7U, now_unix(), scanned,
                           &target, item.data(), item.size(),
                           &item_size) == ITO_STATUS_OK);
    deposit(target, item.data(), item_size);
    CHECK(collect(owner).kind == ITO_PAIRING_REPLIED);
    CHECK(collect(scanner).kind == ITO_PAIRING_PAIRED);
    const ito_pairing_event last = collect(owner);
    if (kind == ITO_PAIRING_LINK) {
        CHECK(last.kind == ITO_PAIRING_COMPLETED);
        return;
    }
    CHECK(last.kind == ITO_PAIRING_CONFIRMED);
    ito_pairing_event decided{};
    decided.struct_size = sizeof(decided);
    CHECK(ito_pairing_decide(owner.store, id, 1, now_unix(), &decided) ==
          ITO_STATUS_OK);
    CHECK(decided.kind == ITO_PAIRING_COMPLETED);
}

}  // namespace ito::call::testing
