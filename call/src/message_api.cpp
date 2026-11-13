/* Copyright (C) 2026 FixCraft Inc. AGPL-3.0-or-later. */

// The C interface of ito/message.h. Like api.cpp, each function validates
// its arguments, checks every output buffer before the store or a session
// changes, and contains every exception. Secret copies made here wipe
// themselves.

#include <ito/message.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <memory>
#include <optional>
#include <string_view>
#include <vector>

#include "api_support.hpp"
#include "envelope.hpp"
#include "identity.hpp"
#include "pairing.hpp"
#include "session.hpp"
#include "store.hpp"

namespace call = ito::call;

struct ito_session {
    ito_store* store{nullptr};
    std::unique_ptr<call::Session> session;
};

using ito::call::api::authority_of;
using ito::call::api::CallbackScope;
using ito::call::api::contained;
using ito::call::api::key_of;
using ito::call::api::persist_of;
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
static_assert(ITO_MESSAGE_TEXT ==
              static_cast<uint32_t>(call::MessageKind::Text));
static_assert(ITO_MESSAGE_RECEIPT ==
              static_cast<uint32_t>(call::MessageKind::Receipt));
static_assert(ITO_MESSAGE_CHECK ==
              static_cast<uint32_t>(call::MessageKind::Check));
static_assert(ITO_MESSAGE_MISSING ==
              static_cast<uint32_t>(call::MessageKind::Missing));
static_assert(ITO_MESSAGE_PROFILE ==
              static_cast<uint32_t>(call::MessageKind::Profile));
static_assert(ITO_MESSAGE_TIMER ==
              static_cast<uint32_t>(call::MessageKind::Timer));
static_assert(ITO_RECEIPT_READ ==
              static_cast<uint32_t>(call::ReceiptKind::Read));
static_assert(ITO_TIMER_MONTH ==
              static_cast<uint32_t>(call::TimerSetting::Month));
static_assert(ITO_MESSAGE_RESENT == call::kEnvelopeResent);
static_assert(ITO_MESSAGE_ID_BYTES == call::kMessageIdBytes);
static_assert(ITO_MAX_TEXT_BYTES == call::kMaxTextBytes);
static_assert(ITO_MAX_MESSAGE_IDS == call::kMaxMessageIds);
static_assert(ITO_MAX_OUTBOX == call::kMaxOutbox);

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

// The payload a caller's message asks for. INVALID_ARGUMENT for a kind
// that cannot be sent this way or fields outside its rules.
[[nodiscard]] ito_status payload_of(const ito_message& message,
                                    call::MessageKind& kind,
                                    call::SecretBytes& payload) {
    switch (message.kind) {
        case ITO_MESSAGE_TEXT:
        case ITO_MESSAGE_PROFILE:
            if (message.text == nullptr || message.text_size == 0U ||
                message.text_size > ITO_MAX_TEXT_BYTES) {
                return ITO_STATUS_INVALID_ARGUMENT;
            }
            kind = static_cast<call::MessageKind>(message.kind);
            payload.reserve(message.text_size);
            payload.append(call::ByteView(message.text, message.text_size));
            return ITO_STATUS_OK;
        case ITO_MESSAGE_RECEIPT:
        case ITO_MESSAGE_MISSING: {
            const bool receipt = message.kind == ITO_MESSAGE_RECEIPT;
            if (message.ids == nullptr || message.id_count == 0U ||
                message.id_count > ITO_MAX_MESSAGE_IDS ||
                (receipt && message.receipt != ITO_RECEIPT_DELIVERED &&
                 message.receipt != ITO_RECEIPT_READ)) {
                return ITO_STATUS_INVALID_ARGUMENT;
            }
            kind = static_cast<call::MessageKind>(message.kind);
            std::vector<call::MessageId> ids(message.id_count);
            for (size_t index = 0U; index < ids.size(); ++index) {
                std::copy_n(message.ids + index * ITO_MESSAGE_ID_BYTES,
                            ITO_MESSAGE_ID_BYTES, ids[index].begin());
            }
            const auto receipt_kind =
                static_cast<call::ReceiptKind>(receipt ? message.receipt : 1U);
            return to_c(call::encode_ids(kind, receipt_kind, ids, payload));
        }
        case ITO_MESSAGE_TIMER: {
            if (message.timer > ITO_TIMER_MONTH) {
                return ITO_STATUS_INVALID_ARGUMENT;
            }
            kind = call::MessageKind::Timer;
            const std::array<uint8_t, 1> setting{
                static_cast<uint8_t>(message.timer)};
            payload.append(setting);
            return ITO_STATUS_OK;
        }
        default:
            return ITO_STATUS_INVALID_ARGUMENT;
    }
}

// A received envelope as the caller sees it. The pointers borrow the
// envelope's payload for the duration of the delivery.
void fill_message(const call::Envelope& envelope, ito_message& out) noexcept {
    std::copy(envelope.id.begin(), envelope.id.end(), out.id);
    out.kind = static_cast<uint32_t>(envelope.kind);
    out.sent_ms = envelope.sent_ms;
    out.flags = envelope.resent ? ITO_MESSAGE_RESENT : 0U;
    const call::ByteView payload = envelope.payload.view();
    switch (envelope.kind) {
        case call::MessageKind::Text:
        case call::MessageKind::Profile:
            out.text = payload.data();
            out.text_size = payload.size();
            break;
        case call::MessageKind::Receipt:
        case call::MessageKind::Check:
        case call::MessageKind::Missing: {
            if (envelope.kind == call::MessageKind::Receipt) {
                out.receipt = payload[0];
            }
            const call::ByteView ids =
                call::payload_ids(envelope.kind, payload);
            out.ids = ids.data();
            out.id_count = ids.size() / ITO_MESSAGE_ID_BYTES;
            break;
        }
        case call::MessageKind::Timer:
            out.timer = payload[0];
            break;
        case call::MessageKind::Ring:
        case call::MessageKind::RingEnd:
        case call::MessageKind::Inbox:
            break;
    }
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

ito_status ito_session_open(ito_store* store, const uint8_t contact[32],
                            const uint8_t* snapshot, size_t snapshot_size,
                            const ito_persistence* persistence, uint64_t now_ms,
                            ito_session** out) noexcept {
    return contained([&] {
        if (store == nullptr || contact == nullptr || out == nullptr ||
            !sized(persistence) || persistence->persist == nullptr ||
            (snapshot == nullptr && snapshot_size != 0U)) {
            return ITO_STATUS_INVALID_ARGUMENT;
        }
        auto handle = std::make_unique<ito_session>();
        handle->store = store;
        const call::Status opened = call::Session::open(
            *store->store, key_of(contact),
            call::ByteView(snapshot, snapshot_size), persist_of(*persistence),
            now_ms, handle->session);
        if (opened != call::Status::Ok) return to_c(opened);
        *out = handle.release();
        return ITO_STATUS_OK;
    });
}

ito_status ito_session_destroy(ito_session* session) noexcept {
    return contained([&] {
        if (session == nullptr) return ITO_STATUS_INVALID_ARGUMENT;
        delete session;
        return ITO_STATUS_OK;
    });
}

ito_status ito_session_send(ito_session* session, const ito_message* message,
                            uint64_t now_ms, uint8_t id[16],
                            ito_mailbox_target* target, uint8_t* item,
                            size_t item_capacity, size_t* item_size) noexcept {
    return contained([&] {
        if (session == nullptr || !sized(message) || id == nullptr ||
            target == nullptr || item == nullptr || item_size == nullptr) {
            return ITO_STATUS_INVALID_ARGUMENT;
        }
        if (item_capacity < ITO_MAX_ITEM_BYTES) {
            return ITO_STATUS_BUFFER_TOO_SMALL;
        }
        call::MessageKind kind = call::MessageKind::Text;
        call::SecretBytes payload;
        const ito_status built = payload_of(*message, kind, payload);
        if (built != ITO_STATUS_OK) return built;
        call::MessageId sent{};
        call::OutgoingItem out;
        const call::Status status =
            session->session->send(kind, payload.view(), now_ms, sent, out);
        if (status != call::Status::Ok) return to_c(status);
        std::copy(sent.begin(), sent.end(), id);
        copy_item(out, target, item, item_size);
        return ITO_STATUS_OK;
    });
}

ito_status ito_session_receive(ito_session* session, const uint8_t* item,
                               size_t item_size, uint64_t now_ms,
                               const ito_message_sink* sink) noexcept {
    return contained([&] {
        if (session == nullptr || item == nullptr || !sized(sink) ||
            sink->deliver == nullptr) {
            return ITO_STATUS_INVALID_ARGUMENT;
        }
        const ito_message_sink callback = *sink;
        const call::Deliver deliver =
            [&callback](const call::Envelope& envelope) {
                ito_message message{};
                message.struct_size = sizeof(message);
                fill_message(envelope, message);
                int32_t result = ITO_PERSIST_AMBIGUOUS;
                {
                    CallbackScope scope;
                    result = callback.deliver(callback.user_data, &message);
                }
                return result == ITO_PERSIST_COMMITTED;
            };
        return to_c(session->session->receive(call::ByteView(item, item_size),
                                              now_ms, deliver));
    });
}

ito_status ito_session_resend(ito_session* session, const uint8_t id[16],
                              uint64_t now_ms, ito_mailbox_target* target,
                              uint8_t* item, size_t item_capacity,
                              size_t* item_size) noexcept {
    return contained([&] {
        if (session == nullptr || id == nullptr || target == nullptr ||
            item == nullptr || item_size == nullptr) {
            return ITO_STATUS_INVALID_ARGUMENT;
        }
        if (item_capacity < ITO_MAX_ITEM_BYTES) {
            return ITO_STATUS_BUFFER_TOO_SMALL;
        }
        call::MessageId wanted{};
        std::copy_n(id, wanted.size(), wanted.begin());
        call::OutgoingItem out;
        const call::Status status =
            session->session->resend(wanted, now_ms, out);
        if (status != call::Status::Ok) return to_c(status);
        copy_item(out, target, item, item_size);
        return ITO_STATUS_OK;
    });
}

ito_status ito_session_check(ito_session* session, uint64_t now_ms,
                             uint64_t hold_seconds, ito_mailbox_target* target,
                             uint8_t* item, size_t item_capacity,
                             size_t* item_size) noexcept {
    return contained([&] {
        if (session == nullptr || target == nullptr || item == nullptr ||
            item_size == nullptr) {
            return ITO_STATUS_INVALID_ARGUMENT;
        }
        if (item_capacity < ITO_MAX_ITEM_BYTES) {
            return ITO_STATUS_BUFFER_TOO_SMALL;
        }
        call::OutgoingItem out;
        const call::Status status =
            session->session->check(now_ms, hold_seconds, out);
        if (status != call::Status::Ok) return to_c(status);
        copy_item(out, target, item, item_size);
        return ITO_STATUS_OK;
    });
}

ito_status ito_session_outbox_count(ito_session* session,
                                    size_t* count) noexcept {
    return contained([&] {
        if (session == nullptr || count == nullptr) {
            return ITO_STATUS_INVALID_ARGUMENT;
        }
        *count = session->session->outbox().size();
        return ITO_STATUS_OK;
    });
}

ito_status ito_session_outbox_at(ito_session* session, size_t index,
                                 ito_outbox_entry* out) noexcept {
    return contained([&] {
        if (session == nullptr || !sized(out)) {
            return ITO_STATUS_INVALID_ARGUMENT;
        }
        const std::vector<call::OutboxInfo> outbox = session->session->outbox();
        if (index >= outbox.size()) return ITO_STATUS_NOT_FOUND;
        const call::OutboxInfo& entry = outbox[index];
        clear_sized(out);
        std::copy(entry.id.begin(), entry.id.end(), out->id);
        out->kind = static_cast<uint32_t>(entry.kind);
        out->sent_ms = entry.sent_ms;
        out->sealed_unix = entry.sealed_at;
        out->checked_unix = entry.checked_at;
        return ITO_STATUS_OK;
    });
}

}  // extern "C"
