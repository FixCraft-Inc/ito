/* Copyright (C) 2026 FixCraft Inc. AGPL-3.0-or-later. */

// ito/message.h through the packaged library, the way a platform uses it:
// items go into a mailbox keyed by inbox address, and each phone collects
// from the inboxes the core lists and hands every item to the core. This
// file sees only the public headers.

#include <ito/message.h>

#include <cstdio>
#include <cstring>
#include <vector>

#include "check.hpp"
#include "message_platform.hpp"

namespace {

using namespace ito::call::testing;

size_t pairing_count(const Phone& phone) {
    size_t count = 0U;
    CHECK(ito_pairing_count(phone.store, &count) == ITO_STATUS_OK);
    return count;
}

void test_refusals(ito_context* context) {
    Phone ana(context, 0xA1);
    uint8_t id[ITO_PAIRING_ID_BYTES]{};
    char code[ITO_MAX_PAIRING_CODE_CHARS + 1U]{};
    size_t code_size = 0U;
    // Before the upgrade there is no identity 2 to pair with.
    CHECK(ito_pairing_code_create(ana.store, ITO_PAIRING_IN_PERSON,
                                  &ana.mailbox, "Ana", 3U, now_unix(), id, code,
                                  sizeof(code),
                                  &code_size) == ITO_STATUS_WRONG_STATE);
    uint8_t fingerprint[ITO_FINGERPRINT2_BYTES]{};
    CHECK(ito_message_identity_fingerprint(ana.store, fingerprint) ==
          ITO_STATUS_WRONG_STATE);
    CHECK(ito_message_identity_upgrade(ana.store) == ITO_STATUS_OK);
    CHECK(ito_message_identity_upgrade(ana.store) == ITO_STATUS_WRONG_STATE);
    CHECK(ito_message_identity_fingerprint(ana.store, fingerprint) ==
          ITO_STATUS_OK);

    // Arguments are checked, and output space too, before anything changes.
    CHECK(ito_pairing_code_create(nullptr, ITO_PAIRING_IN_PERSON, &ana.mailbox,
                                  "Ana", 3U, now_unix(), id, code, sizeof(code),
                                  &code_size) == ITO_STATUS_INVALID_ARGUMENT);
    CHECK(ito_pairing_code_create(ana.store, 3U, &ana.mailbox, "Ana", 3U,
                                  now_unix(), id, code, sizeof(code),
                                  &code_size) == ITO_STATUS_INVALID_ARGUMENT);
    ito_authority small = ana.mailbox;
    small.struct_size = sizeof(small) - 1U;
    CHECK(ito_pairing_code_create(ana.store, ITO_PAIRING_LINK, &small, "Ana",
                                  3U, now_unix(), id, code, sizeof(code),
                                  &code_size) == ITO_STATUS_INVALID_ARGUMENT);
    CHECK(ito_pairing_code_create(ana.store, ITO_PAIRING_LINK, &ana.mailbox,
                                  "Ana", 0U, now_unix(), id, code, sizeof(code),
                                  &code_size) == ITO_STATUS_INVALID_ARGUMENT);
    CHECK(ito_pairing_code_create(ana.store, ITO_PAIRING_LINK, &ana.mailbox,
                                  "Ana", 3U, now_unix(), id, code,
                                  ITO_MAX_PAIRING_CODE_CHARS,
                                  &code_size) == ITO_STATUS_BUFFER_TOO_SMALL);
    CHECK(pairing_count(ana) == 0U);

    CHECK(ito_pairing_code_create(ana.store, ITO_PAIRING_LINK, &ana.mailbox,
                                  "Ana", 3U, now_unix(), id, code, sizeof(code),
                                  &code_size) == ITO_STATUS_OK);
    CHECK(code_size == std::strlen(code) &&
          code_size <= ITO_MAX_PAIRING_CODE_CHARS &&
          std::strncmp(code, "ito-pair:1:", 11U) == 0);
    char again[ITO_MAX_PAIRING_CODE_CHARS + 1U]{};
    size_t again_size = 0U;
    CHECK(ito_pairing_code_get(ana.store, id, again, sizeof(again),
                               &again_size) == ITO_STATUS_OK);
    CHECK(again_size == code_size && std::strcmp(again, code) == 0);

    Phone ben(context, 0xB1);
    CHECK(ito_message_identity_upgrade(ben.store) == ITO_STATUS_OK);
    uint8_t scanned[ITO_PAIRING_ID_BYTES]{};
    ito_mailbox_target target{};
    target.struct_size = sizeof(target);
    std::vector<uint8_t> item(ITO_MAX_ITEM_BYTES);
    size_t item_size = 0U;
    CHECK(ito_pairing_scan(ben.store, code, code_size, 3U, &ben.mailbox, "Ben",
                           3U, now_unix(), scanned, &target, item.data(),
                           item.size(),
                           &item_size) == ITO_STATUS_INVALID_ARGUMENT);
    CHECK(ito_pairing_scan(ben.store, code, code_size, ITO_PAIRING_SOURCE_LINK,
                           &ben.mailbox, "Ben", 3U, now_unix(), scanned,
                           &target, item.data(), item.size() - 1U,
                           &item_size) == ITO_STATUS_BUFFER_TOO_SMALL);
    CHECK(ito_pairing_scan(ben.store, "ito-pair:1:", 11U,
                           ITO_PAIRING_SOURCE_LINK, &ben.mailbox, "Ben", 3U,
                           now_unix(), scanned, &target, item.data(),
                           item.size(), &item_size) == ITO_STATUS_MALFORMED);
    CHECK(pairing_count(ben) == 0U);

    // An item at an address the store does not hold belongs to messaging.
    ito_pairing_event event{};
    event.struct_size = sizeof(event);
    const uint8_t unknown[ITO_MAILBOX_ADDRESS_BYTES]{};
    CHECK(ito_pairing_receive(ana.store, unknown, item.data(), 1024U,
                              now_unix(), &event, &target, item.data(),
                              item.size(), &item_size) == ITO_STATUS_NOT_FOUND);
    CHECK(ito_pairing_cancel(ana.store, id) == ITO_STATUS_OK);
    CHECK(ito_pairing_cancel(ana.store, id) == ITO_STATUS_NOT_FOUND);
    CHECK(pairing_count(ana) == 0U);
}

void test_pairing(ito_context* context) {
    Phone ana(context, 0xA1);
    Phone ben(context, 0xB1);
    CHECK(ito_message_identity_upgrade(ana.store) == ITO_STATUS_OK);
    CHECK(ito_message_identity_upgrade(ben.store) == ITO_STATUS_OK);

    uint8_t id[ITO_PAIRING_ID_BYTES]{};
    char code[ITO_MAX_PAIRING_CODE_CHARS + 1U]{};
    size_t code_size = 0U;
    CHECK(ito_pairing_code_create(ana.store, ITO_PAIRING_IN_PERSON,
                                  &ana.mailbox, "Ana", 3U, now_unix(), id, code,
                                  sizeof(code), &code_size) == ITO_STATUS_OK);
    uint8_t scanned[ITO_PAIRING_ID_BYTES]{};
    ito_mailbox_target target{};
    target.struct_size = sizeof(target);
    std::vector<uint8_t> item(ITO_MAX_ITEM_BYTES);
    size_t item_size = 0U;
    CHECK(ito_pairing_scan(ben.store, code, code_size,
                           ITO_PAIRING_SOURCE_SCANNED, &ben.mailbox, "Ben", 3U,
                           now_unix(), scanned, &target, item.data(),
                           item.size(), &item_size) == ITO_STATUS_OK);
    CHECK(std::memcmp(scanned, id, sizeof(id)) == 0 && item_size == 16384U);
    CHECK(target.service_size == ana.mailbox.service_size &&
          std::memcmp(target.server_fingerprint, ana.mailbox.server_fingerprint,
                      ITO_KEY_BYTES) == 0);
    deposit(target, item.data(), item_size);
    CHECK(ito_pairing_scan(ben.store, code, code_size,
                           ITO_PAIRING_SOURCE_SCANNED, &ben.mailbox, "Ben", 3U,
                           now_unix(), scanned, &target, item.data(),
                           item.size(),
                           &item_size) == ITO_STATUS_ALREADY_SPENT);

    const ito_pairing_event replied = collect(ana);
    CHECK(replied.kind == ITO_PAIRING_REPLIED &&
          replied.role == ITO_PAIRING_ROLE_OWNER && replied.has_item == 1U &&
          replied.trust == 0U &&
          std::strlen(replied.short_code) == ITO_SHORT_CODE_DIGITS &&
          std::memcmp(replied.peer_key, ben.key, ITO_KEY_BYTES) == 0 &&
          replied.peer_name_size == 3U &&
          std::strcmp(replied.peer_name, "Ben") == 0);
    ito_pairing_info info{};
    info.struct_size = sizeof(info);
    CHECK(ito_pairing_at(ana.store, 0U, &info) == ITO_STATUS_OK);
    CHECK(info.state == ITO_PAIRING_STATE_REPLIED && info.has_peer == 1U &&
          std::strcmp(info.short_code, replied.short_code) == 0);
    CHECK(ito_pairing_at(ana.store, 1U, &info) == ITO_STATUS_NOT_FOUND);

    const ito_pairing_event paired = collect(ben);
    CHECK(paired.kind == ITO_PAIRING_PAIRED &&
          paired.trust == ITO_TRUST_VERIFIED &&
          std::strcmp(paired.short_code, replied.short_code) == 0 &&
          std::strcmp(paired.peer_name, "Ana") == 0);
    const ito_pairing_event confirmed = collect(ana);
    CHECK(confirmed.kind == ITO_PAIRING_CONFIRMED && confirmed.has_item == 0U);
    ito_pairing_event decided{};
    decided.struct_size = sizeof(decided);
    CHECK(ito_pairing_decide(ana.store, id, 1, now_unix(), &decided) ==
          ITO_STATUS_OK);
    CHECK(decided.kind == ITO_PAIRING_COMPLETED &&
          decided.trust == ITO_TRUST_VERIFIED);
    CHECK(pairing_count(ana) == 0U && pairing_count(ben) == 0U);

    // A lost confirm is built again, and the owner recognizes the resend.
    CHECK(ito_pairing_confirm_item(ben.store, ana.key, &target, item.data(),
                                   item.size(), &item_size) == ITO_STATUS_OK);
    CHECK(item_size == 1024U);
    deposit(target, item.data(), item_size);
    collect(ana, ITO_STATUS_ALREADY_SPENT);

    ito_contact contact{};
    contact.struct_size = sizeof(contact);
    CHECK(ito_store_find_contact(ana.store, ben.key, &contact) ==
          ITO_STATUS_OK);
    CHECK((contact.flags & ITO_CONTACT_PAIRED) != 0U &&
          contact.trust == ITO_TRUST_VERIFIED &&
          std::strcmp(contact.name, "Ben") == 0);
    ito_paired_contact owner{};
    owner.struct_size = sizeof(owner);
    ito_paired_contact scanner{};
    scanner.struct_size = sizeof(scanner);
    CHECK(ito_message_contact_get(ana.store, ben.key, &owner) == ITO_STATUS_OK);
    CHECK(ito_message_contact_get(ben.store, ana.key, &scanner) ==
          ITO_STATUS_OK);
    CHECK(std::memcmp(owner.send.address, scanner.receive.address,
                      ITO_MAILBOX_ADDRESS_BYTES) == 0 &&
          std::memcmp(scanner.send.address, owner.receive.address,
                      ITO_MAILBOX_ADDRESS_BYTES) == 0);
    CHECK(owner.role == ITO_PAIRING_ROLE_OWNER &&
          scanner.role == ITO_PAIRING_ROLE_SCANNER &&
          owner.verified_by == ITO_VERIFIED_IN_PERSON);
    uint8_t ben_fingerprint[ITO_FINGERPRINT2_BYTES]{};
    CHECK(ito_message_identity_fingerprint(ben.store, ben_fingerprint) ==
          ITO_STATUS_OK);
    CHECK(std::memcmp(owner.fingerprint, ben_fingerprint,
                      sizeof(ben_fingerprint)) == 0);

    char owner_code[ITO_SAFETY_CODE_DIGITS + 1U]{};
    char scanner_code[ITO_SAFETY_CODE_DIGITS + 1U]{};
    CHECK(ito_message_safety_code(ana.store, ben.key, owner_code,
                                  ITO_SAFETY_CODE_DIGITS) ==
          ITO_STATUS_BUFFER_TOO_SMALL);
    CHECK(ito_message_safety_code(ana.store, ben.key, owner_code,
                                  sizeof(owner_code)) == ITO_STATUS_OK);
    CHECK(ito_message_safety_code(ben.store, ana.key, scanner_code,
                                  sizeof(scanner_code)) == ITO_STATUS_OK);
    CHECK(std::strlen(owner_code) == ITO_SAFETY_CODE_DIGITS &&
          std::strcmp(owner_code, scanner_code) == 0);
    CHECK(ito_message_verify_safety_code(ana.store, ben.key, owner_code, 59U,
                                         now_unix()) ==
          ITO_STATUS_AUTHENTICATION_FAILED);
    CHECK(ito_message_verify_safety_code(ana.store, ben.key, owner_code,
                                         ITO_SAFETY_CODE_DIGITS,
                                         now_unix()) == ITO_STATUS_OK);

    // Both now keep only the contact inbox open, and a Blocked contact's
    // inbox drops from the list.
    size_t inboxes = 0U;
    CHECK(ito_message_inbox_count(ana.store, &inboxes) == ITO_STATUS_OK &&
          inboxes == 1U);
    ito_inbox inbox{};
    inbox.struct_size = sizeof(inbox);
    CHECK(ito_message_inbox_at(ana.store, 0U, &inbox) == ITO_STATUS_OK);
    CHECK(inbox.purpose == ITO_INBOX_CONTACT &&
          std::memcmp(inbox.contact_key, ben.key, ITO_KEY_BYTES) == 0 &&
          std::memcmp(inbox.mailbox.address, owner.receive.address,
                      ITO_MAILBOX_ADDRESS_BYTES) == 0);
    CHECK(ito_store_block_contact(ana.store, ben.key) == ITO_STATUS_OK);
    CHECK(ito_message_inbox_count(ana.store, &inboxes) == ITO_STATUS_OK &&
          inboxes == 0U);
    CHECK(ito_message_verify_safety_code(ana.store, ben.key, owner_code,
                                         ITO_SAFETY_CODE_DIGITS,
                                         now_unix()) == ITO_STATUS_UNTRUSTED);

    // The snapshot reopens to the same pairing.
    ito_store* reopened = nullptr;
    Bytes disk;
    const ito_persistence persistence{sizeof(ito_persistence), &disk, persist};
    CHECK(ito_store_open(context, ben.disk.bytes.data(), ben.disk.bytes.size(),
                         &persistence, &reopened) == ITO_STATUS_OK);
    ito_paired_contact reread{};
    reread.struct_size = sizeof(reread);
    CHECK(ito_message_contact_get(reopened, ana.key, &reread) == ITO_STATUS_OK);
    CHECK(std::memcmp(&reread, &scanner, sizeof(reread)) == 0);
    CHECK(ito_store_destroy(reopened) == ITO_STATUS_OK);
}

}  // namespace

int main() {
    ito_context* context = nullptr;
    CHECK(ito_context_create(&context) == ITO_STATUS_OK);
    test_refusals(context);
    test_pairing(context);
    CHECK(g_mailbox.empty());
    CHECK(ito_context_destroy(context) == ITO_STATUS_OK);
    std::puts("message api tests passed");
    return 0;
}
