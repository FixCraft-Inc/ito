/* Copyright (C) 2026 FixCraft Inc. AGPL-3.0-or-later. */

/*
 * Ito's messaging identity and pairing, from docs/MESSAGE_SECURITY.md:
 * identity 2 (an Ed25519 key and an ML-DSA-87 key that sign together),
 * pairing two phones once through their mailboxes, and the safety code.
 * It extends the store of ito/call.h, lives in the same library and follows
 * that header's rules for handles, struct_size, statuses, persistence and
 * callbacks.
 *
 * The core seals and opens every pairing item. The platform carries them:
 * it opens the store's inboxes on their mailboxes, deposits each item the
 * core returns at the target the core names, and hands every item that
 * arrives to ito_pairing_receive. Items are exactly 1024, 4096 or 16384
 * bytes, and the core reads and writes only those sizes.
 *
 * Calls that take now_unix admit the platform's wall clock under the rule of
 * ito_invitation_open, and refuse with ITO_STATUS_CLOCK_REGRESSED the same
 * way. Pairings whose deadline has passed are removed by the next pairing
 * change.
 */

#ifndef ITO_MESSAGE_H
#define ITO_MESSAGE_H

#include <ito/call.h>

#ifdef __cplusplus
extern "C" {
#endif

/* The version of this C interface, independent of ito/call.h's. */
#define ITO_MESSAGE_INTERFACE_VERSION 1u

#define ITO_FINGERPRINT2_BYTES 32u
#define ITO_PAIRING_ID_BYTES 16u
#define ITO_MAILBOX_ADDRESS_BYTES 32u
#define ITO_INBOX_SECRET_BYTES 32u
/* "ito-pair:1:" and unpadded base64url of the longest code record. */
#define ITO_MAX_PAIRING_CODE_CHARS 302u
#define ITO_SAFETY_CODE_DIGITS 60u
#define ITO_SHORT_CODE_DIGITS 6u
#define ITO_MAX_ITEM_BYTES 16384u

#define ITO_PAIRING_IN_PERSON 1u /* shown on screen, lives 10 minutes */
#define ITO_PAIRING_LINK 2u      /* shared as text, lives 3 days */

/* How the scanner got the code. Only an in-person code read from the
 * owner's own screen makes the owner Verified on the scanner's side. */
#define ITO_PAIRING_SOURCE_SCANNED 1u
#define ITO_PAIRING_SOURCE_LINK 2u

/* Adds the ML-DSA-87 key to the store's identity, which makes it identity 2
 * and switches its snapshot to version 2. NOT_FOUND without an identity,
 * WRONG_STATE when it is already identity 2. A store never upgraded keeps
 * writing snapshot 1. */
ITO_CALL_API ito_status ito_message_identity_upgrade(ito_store* store)
    ITO_CALL_NOEXCEPT;
/* The identity 2 fingerprint: SHA-256 of "ito/contact-identity/2", zero,
 * both public keys. WRONG_STATE before the upgrade. */
ITO_CALL_API ito_status ito_message_identity_fingerprint(
    ito_store* store,
    uint8_t fingerprint[ITO_FINGERPRINT2_BYTES]) ITO_CALL_NOEXCEPT;

/* Where an item goes: a mailbox (the YUME server and the mailbox's service
 * name) and an inbox address on it. */
typedef struct ito_mailbox_target {
    size_t struct_size;
    uint8_t server_fingerprint[ITO_KEY_BYTES];
    size_t service_size;
    char service[ITO_MAX_SERVICE_BYTES];
    uint8_t address[ITO_MAILBOX_ADDRESS_BYTES];
} ito_mailbox_target;

/* The owner shows a code. mailbox is the owner's mailbox, name the name the
 * owner offers the scanner (1..128 bytes of UTF-8). The code text holds the
 * pairing secret: show it on a secure window or share it as a link, never
 * log it. At most eight shown codes are open. code_capacity must be more
 * than ITO_MAX_PAIRING_CODE_CHARS, because the text is NUL terminated. */
ITO_CALL_API ito_status ito_pairing_code_create(
    ito_store* store, uint32_t kind, const ito_authority* mailbox,
    const char* name, size_t name_size, uint64_t now_unix,
    uint8_t pairing_id[ITO_PAIRING_ID_BYTES], char* code, size_t code_capacity,
    size_t* code_size) ITO_CALL_NOEXCEPT;
/* The text of a code that is still open, to show it again. */
ITO_CALL_API ito_status ito_pairing_code_get(
    ito_store* store, const uint8_t pairing_id[ITO_PAIRING_ID_BYTES],
    char* code, size_t code_capacity, size_t* code_size) ITO_CALL_NOEXCEPT;

/* The scanner reads a code and gets its hello, a 16384-byte item, to
 * deposit at target. own_mailbox is the scanner's mailbox, name the name it
 * offers. MALFORMED or UNSUPPORTED for text that is not a pairing code 1,
 * EXPIRED for an expired code, INVALID_ARGUMENT for one's own code,
 * ALREADY_SPENT for a code already scanned and pending. At most eight
 * scanned codes wait for replies. A hello that is lost fails the pairing:
 * cancel it and pair with a new code. */
ITO_CALL_API ito_status ito_pairing_scan(
    ito_store* store, const char* code, size_t code_size, uint32_t source,
    const ito_authority* own_mailbox, const char* name, size_t name_size,
    uint64_t now_unix, uint8_t pairing_id[ITO_PAIRING_ID_BYTES],
    ito_mailbox_target* target, uint8_t* item, size_t item_capacity,
    size_t* item_size) ITO_CALL_NOEXCEPT;

#define ITO_PAIRING_ROLE_OWNER 1u
#define ITO_PAIRING_ROLE_SCANNER 2u

/* What a received item or a decision did. */
#define ITO_PAIRING_REPLIED 1u   /* owner answered: deposit the reply */
#define ITO_PAIRING_PAIRED 2u    /* scanner saved it: deposit the confirm */
#define ITO_PAIRING_CONFIRMED 3u /* owner waits for its short-code answer */
#define ITO_PAIRING_MATCHED 4u   /* codes match, owner waits for the confirm */
#define ITO_PAIRING_COMPLETED 5u /* owner: contact saved */
#define ITO_PAIRING_REJECTED 6u  /* owner: codes differ, pairing removed */

typedef struct ito_pairing_event {
    size_t struct_size;
    uint32_t kind;
    uint32_t role;
    uint32_t pairing_kind;
    uint8_t pairing_id[ITO_PAIRING_ID_BYTES];
    /* The contact's Ed25519 key, the key of its ito_contact record. */
    uint8_t peer_key[ITO_KEY_BYTES];
    /* ITO_TRUST_* once a contact was saved (PAIRED, COMPLETED), else 0. */
    uint32_t trust;
    /* Six digits and a NUL after an in-person exchange, else empty. */
    char short_code[ITO_SHORT_CODE_DIGITS + 1u];
    /* The name the contact offered, display only. */
    size_t peer_name_size;
    char peer_name[ITO_MAX_NAME_BYTES + 1u];
    /* Nonzero when an item must be deposited at the target. */
    uint32_t has_item;
} ito_pairing_event;

/* An item that arrived at one of the store's inboxes. NOT_FOUND when the
 * address is no pairing inbox, because the item belongs to messaging, not
 * pairing. ALREADY_SPENT for a second hello to a used code or a resent
 * confirm, EXPIRED past the pairing's deadline, AUTHENTICATION_FAILED for an
 * item that does not open or verify, MALFORMED for one that opens but is not
 * canonical, UNTRUSTED for a Blocked peer or a known Ed25519 key with
 * another ML-DSA key. A refused item leaves every pairing and contact as it
 * was, though clock admission may save a newer floor. When the event has an
 * item, it is written to item (capacity at least ITO_MAX_ITEM_BYTES) for the
 * platform to deposit at target. A lost reply fails the pairing. A lost
 * confirm can be built again with ito_pairing_confirm_item. */
ITO_CALL_API ito_status ito_pairing_receive(
    ito_store* store, const uint8_t address[ITO_MAILBOX_ADDRESS_BYTES],
    const uint8_t* received, size_t received_size, uint64_t now_unix,
    ito_pairing_event* event, ito_mailbox_target* target, uint8_t* item,
    size_t item_capacity, size_t* item_size) ITO_CALL_NOEXCEPT;

/* The owner's answer after comparing the six digits of an in-person code
 * with the scanner's screen. matches nonzero saves the contact as Verified
 * once the confirm is in, or at once if it already is. Zero removes the
 * pairing. WRONG_STATE for a link, an open code or a scanned code. */
ITO_CALL_API ito_status ito_pairing_decide(
    ito_store* store, const uint8_t pairing_id[ITO_PAIRING_ID_BYTES],
    int matches, uint64_t now_unix, ito_pairing_event* event) ITO_CALL_NOEXCEPT;
/* Removes a shown or scanned pairing in any state and wipes its secrets. */
ITO_CALL_API ito_status ito_pairing_cancel(
    ito_store* store,
    const uint8_t pairing_id[ITO_PAIRING_ID_BYTES]) ITO_CALL_NOEXCEPT;

/* Pairing states. A scanned code stays OPEN until its reply arrives. */
#define ITO_PAIRING_STATE_OPEN 1u
#define ITO_PAIRING_STATE_REPLIED 2u
#define ITO_PAIRING_STATE_CONFIRMED 3u

typedef struct ito_pairing_info {
    size_t struct_size;
    uint8_t pairing_id[ITO_PAIRING_ID_BYTES];
    uint32_t role;
    uint32_t kind;
    uint32_t state;
    /* When the pairing is removed if it has not finished. */
    uint64_t deadline_unix;
    uint32_t matched;
    uint32_t has_peer;
    uint8_t peer_key[ITO_KEY_BYTES];
    char short_code[ITO_SHORT_CODE_DIGITS + 1u];
    size_t peer_name_size;
    char peer_name[ITO_MAX_NAME_BYTES + 1u];
} ito_pairing_info;

/* Shown codes in pairing ID order, then scanned codes in the same order. */
ITO_CALL_API ito_status ito_pairing_count(ito_store* store,
                                          size_t* count) ITO_CALL_NOEXCEPT;
ITO_CALL_API ito_status ito_pairing_at(ito_store* store, size_t index,
                                       ito_pairing_info* out) ITO_CALL_NOEXCEPT;

/* The scanner's confirm for a paired contact, the same bytes each time, to
 * deposit again when the first deposit failed. WRONG_STATE when this store
 * showed the code. */
ITO_CALL_API ito_status ito_pairing_confirm_item(
    ito_store* store, const uint8_t peer_key[ITO_KEY_BYTES],
    ito_mailbox_target* target, uint8_t* item, size_t item_capacity,
    size_t* item_size) ITO_CALL_NOEXCEPT;

#define ITO_INBOX_SHOWN_CODE 1u       /* a shown code's pairing inbox */
#define ITO_INBOX_AWAITING_CONFIRM 2u /* named in a reply, until completion */
#define ITO_INBOX_AWAITING_REPLY 3u   /* a scanned code's inbox */
#define ITO_INBOX_CONTACT 4u          /* a paired contact that is not Blocked */

typedef struct ito_inbox {
    size_t struct_size;
    uint32_t purpose;
    ito_mailbox_target mailbox;
    /* Opens the inbox on its mailbox. Wipe every copy after use. */
    uint8_t secret[ITO_INBOX_SECRET_BYTES];
    uint8_t pairing_id[ITO_PAIRING_ID_BYTES]; /* the first three purposes */
    uint8_t contact_key[ITO_KEY_BYTES];       /* ITO_INBOX_CONTACT */
} ito_inbox;

/* Every inbox the platform keeps open. An inbox missing from the list,
 * such as a used code's or a Blocked contact's, is one to close. The core
 * sets the struct_size of the nested mailbox target. */
ITO_CALL_API ito_status ito_message_inbox_count(ito_store* store, size_t* count)
    ITO_CALL_NOEXCEPT;
ITO_CALL_API ito_status ito_message_inbox_at(ito_store* store, size_t index,
                                             ito_inbox* out) ITO_CALL_NOEXCEPT;

#define ITO_VERIFIED_NONE 0u
#define ITO_VERIFIED_IN_PERSON 1u
#define ITO_VERIFIED_SAFETY_CODE 2u

/* The identity 2 part of a paired contact. Contacts without it are identity
 * 1 contacts, which pair again. ito_contact's flags carry
 * ITO_CONTACT_PAIRED (ito/call.h) for the same contacts. */
typedef struct ito_paired_contact {
    size_t struct_size;
    uint8_t fingerprint[ITO_FINGERPRINT2_BYTES];
    /* Where the contact receives from this store. */
    ito_mailbox_target send;
    /* Where this store's inbox for the contact lives. */
    ito_mailbox_target receive;
    uint64_t paired_unix;
    uint32_t verified_by;
    uint32_t role;
} ito_paired_contact;

/* NOT_FOUND for an unknown key, WRONG_STATE for an identity 1 contact. */
ITO_CALL_API ito_status
ito_message_contact_get(ito_store* store, const uint8_t key[ITO_KEY_BYTES],
                        ito_paired_contact* out) ITO_CALL_NOEXCEPT;

/* The safety code with a paired contact: 60 digits and a NUL, the same on
 * both phones. Shown as 12 groups of five. */
ITO_CALL_API ito_status
ito_message_safety_code(ito_store* store, const uint8_t key[ITO_KEY_BYTES],
                        char* out, size_t out_size) ITO_CALL_NOEXCEPT;
/* Verified when compared holds exactly the 60 digits, ignoring spaces and
 * hyphens. AUTHENTICATION_FAILED otherwise, WRONG_STATE for an identity 1
 * contact, which ito_store_verify_contact handles, and UNTRUSTED for a
 * Blocked one. */
ITO_CALL_API ito_status ito_message_verify_safety_code(
    ito_store* store, const uint8_t key[ITO_KEY_BYTES], const char* compared,
    size_t compared_size, uint64_t now_unix) ITO_CALL_NOEXCEPT;

#ifdef __cplusplus
}
#endif

#endif /* ITO_MESSAGE_H */
