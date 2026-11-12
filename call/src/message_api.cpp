/* Copyright (C) 2026 FixCraft Inc. AGPL-3.0-or-later. */

// The C interface of ito/message.h. Like api.cpp, each function validates
// its arguments, checks every output buffer before the store changes, and
// contains every exception. Secret copies made here wipe themselves.

#include <ito/message.h>

#include <algorithm>
#include <cstring>
#include <optional>
#include <string_view>

#include "api_support.hpp"
#include "identity.hpp"
#include "pairing.hpp"
#include "store.hpp"

namespace call = ito::call;

using ito::call::api::authority_of;
using ito::call::api::contained;
using ito::call::api::key_of;
using ito::call::api::sized;
using ito::call::api::to_c;

namespace {

// Status and event values the header defines, kept in step with the core.
static_assert(ITO_PAIRING_IN_PERSON ==
              static_cast<uint32_t>(call::PairingKind::InPerson));
static_assert(ITO_PAIRING_LINK ==
              static_cast<uint32_t>(call::PairingKind::Link));
static_assert(ITO_PAIRING_ROLE_OWNER ==
              static_cast<uint32_t>(call::PairingRole::Owner));
static_assert(ITO_PAIRING_ROLE_SCANNER ==
              static_cast<uint32_t>(call::PairingRole::Scanner));
static_assert(ITO_PAIRING_REPLIED ==
              static_cast<uint32_t>(call::PairingEventKind::Replied));
static_assert(ITO_PAIRING_REJECTED ==
              static_cast<uint32_t>(call::PairingEventKind::Rejected));
static_assert(ITO_PAIRING_STATE_CONFIRMED ==
              static_cast<uint32_t>(call::CodeState::Confirmed));
static_assert(ITO_INBOX_CONTACT ==
              static_cast<uint32_t>(call::InboxPurpose::ContactInbox));
static_assert(ITO_VERIFIED_SAFETY_CODE ==
              static_cast<uint32_t>(call::VerifiedBy::Compared));
static_assert(ITO_MAX_PAIRING_CODE_CHARS == call::kMaxPairingCodeChars);
static_assert(ITO_MAX_ITEM_BYTES == call::kLargeItemBytes);
static_assert(ITO_PAIRING_ID_BYTES == call::kPairingIdBytes);

// Bounds a caller's text before the core reads it. Longer input cannot be
// a pairing code, a name or a safety code.
constexpr size_t kMaxTextInput = 1024U;

template <class T>
void clear_sized(T* out) noexcept {
    const size_t size = out->struct_size;
    std::memset(out, 0, sizeof(*out));
    out->struct_size = size;
}

void fill_target(const call::Authority& mailbox, const call::Hash& address,
                 ito_mailbox_target* out) noexcept {
    std::memset(out, 0, sizeof(*out));
    out->struct_size = sizeof(*out);
    std::copy(mailbox.server_fingerprint.begin(),
              mailbox.server_fingerprint.end(), out->server_fingerprint);
    out->service_size = mailbox.service.size();
    std::copy(mailbox.service.begin(), mailbox.service.end(), out->service);
    std::copy(address.begin(), address.end(), out->address);
}

void copy_name(const std::string& name, size_t& size, char* out) noexcept {
    size = name.size();
    std::copy(name.begin(), name.end(), out);
    out[name.size()] = '\0';
}

void copy_short_code(const std::optional<call::ShortCode>& code,
                     char* out) noexcept {
    if (!code) return;
    std::copy(code->begin(), code->end(), out);
    out[code->size()] = '\0';
}

void fill_event(const call::PairingEvent& event, bool has_item,
                ito_pairing_event* out) noexcept {
    clear_sized(out);
    out->kind = static_cast<uint32_t>(event.kind);
    out->role = static_cast<uint32_t>(event.role);
    out->pairing_kind = static_cast<uint32_t>(event.pairing_kind);
    std::copy(event.id.begin(), event.id.end(), out->pairing_id);
    std::copy(event.peer.begin(), event.peer.end(), out->peer_key);
    if (event.kind == call::PairingEventKind::Paired ||
        event.kind == call::PairingEventKind::Completed) {
        out->trust = static_cast<uint32_t>(event.trust);
    }
    copy_short_code(event.short_code, out->short_code);
    copy_name(event.peer_name, out->peer_name_size, out->peer_name);
    out->has_item = has_item ? 1U : 0U;
}

void copy_item(const call::OutgoingItem& item, ito_mailbox_target* target,
               uint8_t* out, size_t* size) noexcept {
    fill_target(item.mailbox, item.address, target);
    std::copy(item.item.begin(), item.item.end(), out);
    *size = item.item.size();
}

[[nodiscard]] call::PairingId pairing_id_of(const uint8_t* bytes) noexcept {
    call::PairingId id{};
    std::copy_n(bytes, id.size(), id.begin());
    return id;
}

// Writes a pairing code and its NUL. The capacity was checked first.
void copy_code(const call::SecretBytes& text, char* out,
               size_t* size) noexcept {
    std::copy(text.data(), text.data() + text.size(), out);
    out[text.size()] = '\0';
    *size = text.size();
}

}  // namespace

extern "C" {

ito_status ito_message_identity_upgrade(ito_store* store) noexcept {
    return contained([&] {
        if (store == nullptr) return ITO_STATUS_INVALID_ARGUMENT;
        return to_c(store->store->upgrade_identity());
    });
}

ito_status ito_message_identity_fingerprint(ito_store* store,
                                            uint8_t fingerprint[32]) noexcept {
    return contained([&] {
        if (store == nullptr || fingerprint == nullptr) {
            return ITO_STATUS_INVALID_ARGUMENT;
        }
        call::Identity2 identity;
        call::Hash own{};
        const call::Status status = store->store->identity2(identity, own);
        if (status == call::Status::Ok) {
            std::copy(own.begin(), own.end(), fingerprint);
        }
        return to_c(status);
    });
}

ito_status ito_pairing_code_create(ito_store* store, uint32_t kind,
                                   const ito_authority* mailbox,
                                   const char* name, size_t name_size,
                                   uint64_t now_unix, uint8_t pairing_id[16],
                                   char* code, size_t code_capacity,
                                   size_t* code_size) noexcept {
    return contained([&] {
        call::Authority authority;
        if (store == nullptr || name == nullptr || pairing_id == nullptr ||
            code == nullptr || code_size == nullptr ||
            name_size > kMaxTextInput || !authority_of(mailbox, authority) ||
            (kind != ITO_PAIRING_IN_PERSON && kind != ITO_PAIRING_LINK)) {
            return ITO_STATUS_INVALID_ARGUMENT;
        }
        if (code_capacity <= ITO_MAX_PAIRING_CODE_CHARS) {
            return ITO_STATUS_BUFFER_TOO_SMALL;
        }
        call::PairingId id{};
        call::SecretBytes text;
        const call::Status status = store->store->create_code(
            static_cast<call::PairingKind>(kind), authority,
            std::string_view(name, name_size), now_unix, call::Clock::now(), id,
            text);
        if (status != call::Status::Ok) return to_c(status);
        std::copy(id.begin(), id.end(), pairing_id);
        copy_code(text, code, code_size);
        return ITO_STATUS_OK;
    });
}

ito_status ito_pairing_code_get(ito_store* store, const uint8_t pairing_id[16],
                                char* code, size_t code_capacity,
                                size_t* code_size) noexcept {
    return contained([&] {
        if (store == nullptr || pairing_id == nullptr || code == nullptr ||
            code_size == nullptr) {
            return ITO_STATUS_INVALID_ARGUMENT;
        }
        if (code_capacity <= ITO_MAX_PAIRING_CODE_CHARS) {
            return ITO_STATUS_BUFFER_TOO_SMALL;
        }
        call::SecretBytes text;
        const call::Status status =
            store->store->code_text(pairing_id_of(pairing_id), text);
        if (status != call::Status::Ok) return to_c(status);
        copy_code(text, code, code_size);
        return ITO_STATUS_OK;
    });
}

ito_status ito_pairing_scan(ito_store* store, const char* code,
                            size_t code_size, uint32_t source,
                            const ito_authority* own_mailbox, const char* name,
                            size_t name_size, uint64_t now_unix,
                            uint8_t pairing_id[16], ito_mailbox_target* target,
                            uint8_t* item, size_t item_capacity,
                            size_t* item_size) noexcept {
    return contained([&] {
        call::Authority authority;
        if (store == nullptr || code == nullptr || name == nullptr ||
            pairing_id == nullptr || !sized(target) || item == nullptr ||
            item_size == nullptr || code_size > kMaxTextInput ||
            name_size > kMaxTextInput ||
            !authority_of(own_mailbox, authority) ||
            (source != ITO_PAIRING_SOURCE_SCANNED &&
             source != ITO_PAIRING_SOURCE_LINK)) {
            return ITO_STATUS_INVALID_ARGUMENT;
        }
        if (item_capacity < ITO_MAX_ITEM_BYTES) {
            return ITO_STATUS_BUFFER_TOO_SMALL;
        }
        call::PairingId id{};
        call::OutgoingItem hello;
        const call::Status status =
            store->store->scan(std::string_view(code, code_size),
                               source == ITO_PAIRING_SOURCE_SCANNED, authority,
                               std::string_view(name, name_size), now_unix,
                               call::Clock::now(), id, hello);
        if (status != call::Status::Ok) return to_c(status);
        std::copy(id.begin(), id.end(), pairing_id);
        copy_item(hello, target, item, item_size);
        return ITO_STATUS_OK;
    });
}

ito_status ito_pairing_receive(ito_store* store, const uint8_t address[32],
                               const uint8_t* received, size_t received_size,
                               uint64_t now_unix, ito_pairing_event* event,
                               ito_mailbox_target* target, uint8_t* item,
                               size_t item_capacity,
                               size_t* item_size) noexcept {
    return contained([&] {
        if (store == nullptr || address == nullptr ||
            (received == nullptr && received_size != 0U) || !sized(event) ||
            !sized(target) || item == nullptr || item_size == nullptr) {
            return ITO_STATUS_INVALID_ARGUMENT;
        }
        if (item_capacity < ITO_MAX_ITEM_BYTES) {
            return ITO_STATUS_BUFFER_TOO_SMALL;
        }
        call::Hash inbox{};
        std::copy_n(address, inbox.size(), inbox.begin());
        call::PairingEvent result;
        std::optional<call::OutgoingItem> answer;
        const call::Status status = store->store->receive_pairing(
            inbox, call::ByteView(received, received_size), now_unix,
            call::Clock::now(), result, answer);
        if (status != call::Status::Ok) return to_c(status);
        fill_event(result, answer.has_value(), event);
        *item_size = 0U;
        if (answer) copy_item(*answer, target, item, item_size);
        return ITO_STATUS_OK;
    });
}

ito_status ito_pairing_decide(ito_store* store, const uint8_t pairing_id[16],
                              int matches, uint64_t now_unix,
                              ito_pairing_event* event) noexcept {
    return contained([&] {
        if (store == nullptr || pairing_id == nullptr || !sized(event)) {
            return ITO_STATUS_INVALID_ARGUMENT;
        }
        call::PairingEvent result;
        const call::Status status = store->store->decide_pairing(
            pairing_id_of(pairing_id), matches != 0, now_unix,
            call::Clock::now(), result);
        if (status != call::Status::Ok) return to_c(status);
        fill_event(result, false, event);
        return ITO_STATUS_OK;
    });
}

ito_status ito_pairing_cancel(ito_store* store,
                              const uint8_t pairing_id[16]) noexcept {
    return contained([&] {
        if (store == nullptr || pairing_id == nullptr) {
            return ITO_STATUS_INVALID_ARGUMENT;
        }
        return to_c(store->store->cancel_pairing(pairing_id_of(pairing_id)));
    });
}

ito_status ito_pairing_count(ito_store* store, size_t* count) noexcept {
    return contained([&] {
        if (store == nullptr || count == nullptr) {
            return ITO_STATUS_INVALID_ARGUMENT;
        }
        *count = store->store->pairings().size();
        return ITO_STATUS_OK;
    });
}

ito_status ito_pairing_at(ito_store* store, size_t index,
                          ito_pairing_info* out) noexcept {
    return contained([&] {
        if (store == nullptr || !sized(out)) return ITO_STATUS_INVALID_ARGUMENT;
        const std::vector<call::PairingInfo> pairings =
            store->store->pairings();
        if (index >= pairings.size()) return ITO_STATUS_NOT_FOUND;
        const call::PairingInfo& info = pairings[index];
        clear_sized(out);
        std::copy(info.id.begin(), info.id.end(), out->pairing_id);
        out->role = static_cast<uint32_t>(info.role);
        out->kind = static_cast<uint32_t>(info.kind);
        out->state = static_cast<uint32_t>(info.state);
        out->deadline_unix = info.deadline;
        out->matched = info.matched ? 1U : 0U;
        if (info.peer) {
            out->has_peer = 1U;
            std::copy(info.peer->begin(), info.peer->end(), out->peer_key);
        }
        copy_short_code(info.short_code, out->short_code);
        copy_name(info.peer_name, out->peer_name_size, out->peer_name);
        return ITO_STATUS_OK;
    });
}

ito_status ito_pairing_confirm_item(ito_store* store,
                                    const uint8_t peer_key[32],
                                    ito_mailbox_target* target, uint8_t* item,
                                    size_t item_capacity,
                                    size_t* item_size) noexcept {
    return contained([&] {
        if (store == nullptr || peer_key == nullptr || !sized(target) ||
            item == nullptr || item_size == nullptr) {
            return ITO_STATUS_INVALID_ARGUMENT;
        }
        if (item_capacity < ITO_MAX_ITEM_BYTES) {
            return ITO_STATUS_BUFFER_TOO_SMALL;
        }
        call::OutgoingItem confirm;
        const call::Status status =
            store->store->confirm_item(key_of(peer_key), confirm);
        if (status != call::Status::Ok) return to_c(status);
        copy_item(confirm, target, item, item_size);
        return ITO_STATUS_OK;
    });
}

ito_status ito_message_inbox_count(ito_store* store, size_t* count) noexcept {
    return contained([&] {
        if (store == nullptr || count == nullptr) {
            return ITO_STATUS_INVALID_ARGUMENT;
        }
        *count = store->store->inbox_count();
        return ITO_STATUS_OK;
    });
}

ito_status ito_message_inbox_at(ito_store* store, size_t index,
                                ito_inbox* out) noexcept {
    return contained([&] {
        if (store == nullptr || !sized(out)) return ITO_STATUS_INVALID_ARGUMENT;
        call::Inbox inbox;
        const call::Status status = store->store->inbox_at(index, inbox);
        if (status != call::Status::Ok) return to_c(status);
        clear_sized(out);
        out->purpose = static_cast<uint32_t>(inbox.purpose);
        fill_target(inbox.mailbox, inbox.address, &out->mailbox);
        std::copy(inbox.secret.data(),
                  inbox.secret.data() + inbox.secret.size(), out->secret);
        std::copy(inbox.pairing.begin(), inbox.pairing.end(), out->pairing_id);
        std::copy(inbox.contact.begin(), inbox.contact.end(), out->contact_key);
        return ITO_STATUS_OK;
    });
}

ito_status ito_message_contact_get(ito_store* store, const uint8_t key[32],
                                   ito_paired_contact* out) noexcept {
    return contained([&] {
        if (store == nullptr || key == nullptr || !sized(out)) {
            return ITO_STATUS_INVALID_ARGUMENT;
        }
        call::PairedView view;
        const call::Status status =
            store->store->paired_contact(key_of(key), view);
        if (status != call::Status::Ok) return to_c(status);
        const call::PairedContact& paired = view.paired;
        clear_sized(out);
        std::copy(view.fingerprint.begin(), view.fingerprint.end(),
                  out->fingerprint);
        fill_target(paired.send_mailbox, paired.send_address, &out->send);
        fill_target(paired.receive_mailbox, view.receive_address,
                    &out->receive);
        out->paired_unix = paired.paired_at;
        out->verified_by = static_cast<uint32_t>(paired.verified_by);
        out->role = static_cast<uint32_t>(view.role);
        return ITO_STATUS_OK;
    });
}

ito_status ito_message_safety_code(ito_store* store, const uint8_t key[32],
                                   char* out, size_t out_size) noexcept {
    return contained([&] {
        if (store == nullptr || key == nullptr || out == nullptr) {
            return ITO_STATUS_INVALID_ARGUMENT;
        }
        if (out_size <= ITO_SAFETY_CODE_DIGITS) {
            return ITO_STATUS_BUFFER_TOO_SMALL;
        }
        call::SafetyCode code{};
        const call::Status status =
            store->store->safety_code(key_of(key), code);
        if (status != call::Status::Ok) return to_c(status);
        std::copy(code.begin(), code.end(), out);
        out[code.size()] = '\0';
        return ITO_STATUS_OK;
    });
}

ito_status ito_message_verify_safety_code(ito_store* store,
                                          const uint8_t key[32],
                                          const char* compared,
                                          size_t compared_size,
                                          uint64_t now_unix) noexcept {
    return contained([&] {
        if (store == nullptr || key == nullptr || compared == nullptr ||
            compared_size > kMaxTextInput) {
            return ITO_STATUS_INVALID_ARGUMENT;
        }
        return to_c(store->store->verify_safety_code(
            key_of(key), std::string_view(compared, compared_size), now_unix));
    });
}

}  // extern "C"
