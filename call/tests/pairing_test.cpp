/* Copyright (C) 2026 FixCraft Inc. AGPL-3.0-or-later. */

// Identity 2 and pairing (docs/MESSAGE_SECURITY.md). First the layouts
// against tests/vectors.txt, which an independent Python writer produced,
// then the measured snapshot bound, then stores pairing through the items
// they hand each other, and every refusal leaving pairings and contacts as
// they were.

#include <chrono>
#include <cstdio>
#include <map>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#include "check.hpp"
#include "codec.hpp"
#include "identity.hpp"
#include "pairing.hpp"
#include "store.hpp"

using namespace ito::call;

namespace {

using Bytes = std::vector<unsigned char>;
std::map<std::string, Bytes> v;

template <std::size_t Size>
std::array<Byte, Size> fixed(const char* name) {
    const Bytes& bytes = v.at(name);
    CHECK(bytes.size() == Size);
    std::array<Byte, Size> result{};
    std::copy(bytes.begin(), bytes.end(), result.begin());
    return result;
}

template <std::size_t Size>
void secret(SecretArray<Size>& out, const char* name) {
    const std::array<Byte, Size> bytes = fixed<Size>(name);
    out.assign(bytes);
}

bool same(ByteView actual, const Bytes& expected) {
    return std::equal(actual.begin(), actual.end(), expected.begin(),
                      expected.end());
}

std::string text_of(ByteView bytes) {
    return std::string(bytes.begin(), bytes.end());
}

template <std::size_t Size>
std::string text_of(const std::array<char, Size>& digits) {
    return std::string(digits.begin(), digits.end());
}

Authority authority(const char* server, const char* service) {
    Authority result;
    result.server_fingerprint = fixed<kKeyBytes>(server);
    result.service = text_of(v.at(service));
    return result;
}

// Ana's in-person code from the vectors, where she is identity 1.
PairingCode vector_code() {
    PairingCode code;
    code.kind = PairingKind::InPerson;
    code.id = fixed<kPairingIdBytes>("pairing_id");
    secret(code.secret, "pairing_secret");
    code.owner = fixed<kHashBytes>("fingerprint2_1");
    code.mailbox = authority("mailbox_server", "mailbox_service");
    code.inbox = fixed<kHashBytes>("pairing_inbox");
    code.expires_at = 1'700'000'600U;
    return code;
}

Identity2 vector_identity(const char* ed25519, const char* ml_dsa) {
    return Identity2{fixed<kKeyBytes>(ed25519),
                     fixed<kMlDsaPublicKeyBytes>(ml_dsa)};
}

void test_identity_vectors(const CryptoContext& crypto) {
    Secret32 seed;
    secret(seed, "ml_dsa_seed_1");
    CHECK(crypto.ml_dsa_public_key(seed) ==
          fixed<kMlDsaPublicKeyBytes>("ml_dsa_public_1"));
    secret(seed, "ml_dsa_seed_2");
    CHECK(crypto.ml_dsa_public_key(seed) ==
          fixed<kMlDsaPublicKeyBytes>("ml_dsa_public_2"));

    const Identity2 ana = vector_identity("public_1", "ml_dsa_public_1");
    const Identity2 ben = vector_identity("public_2", "ml_dsa_public_2");
    const Hash ana_fingerprint = fingerprint2(crypto, ana);
    const Hash ben_fingerprint = fingerprint2(crypto, ben);
    CHECK(ana_fingerprint == fixed<kHashBytes>("fingerprint2_1"));
    CHECK(ben_fingerprint == fixed<kHashBytes>("fingerprint2_2"));

    // The same code on both phones, whichever fingerprint comes first.
    const SafetyCode code =
        safety_code(crypto, ana_fingerprint, ben_fingerprint);
    CHECK(text_of(code) == text_of(v.at("safety_code")));
    CHECK(safety_code(crypto, ben_fingerprint, ana_fingerprint) == code);
    std::string grouped;
    for (std::size_t index = 0U; index < code.size(); ++index) {
        if (index != 0U && index % 5U == 0U) grouped += index % 10U ? " " : "-";
        grouped += code[index];
    }
    CHECK(safety_code_matches(grouped, code));
    const std::string digits = text_of(code);
    CHECK(!safety_code_matches(digits.substr(0, 59), code));
    CHECK(!safety_code_matches(digits + "0", code));
    CHECK(!safety_code_matches(digits.substr(0, 59) + "a", code));
    std::string changed = digits;
    changed[30] = changed[30] == '9' ? '0' : static_cast<char>(changed[30] + 1);
    CHECK(!safety_code_matches(changed, code));

    // A composite signature is valid only when both halves verify for the
    // signer whose fingerprint the message names.
    const std::string_view label{"ito/test/composite\0", 19U};
    const std::array<ByteView, 1> body{as_bytes("body")};
    CompositeSignature signature =
        fixed<kCompositeSignatureBytes>("composite_signature_1");
    CHECK(verify_composite(crypto, ana, label, body, signature) ==
          Verification::Valid);
    CHECK(verify_composite(crypto, ben, label, body, signature) ==
          Verification::Invalid);
    const std::array<ByteView, 1> other_body{as_bytes("bodz")};
    CHECK(verify_composite(crypto, ana, label, other_body, signature) ==
          Verification::Invalid);
    CHECK(verify_composite(crypto, ana,
                           std::string_view{"ito/test/other\0", 15U}, body,
                           signature) == Verification::Invalid);
    // Ana's Ed25519 key beside Ben's ML-DSA key names another fingerprint,
    // so even the valid Ed25519 half fails.
    const Identity2 mixed{ana.ed25519, ben.ml_dsa};
    CHECK(verify_composite(crypto, mixed, label, body, signature) ==
          Verification::Invalid);
    for (const std::size_t at :
         {std::size_t{0}, kSignatureBytes - 1U, kSignatureBytes,
          kCompositeSignatureBytes - 1U}) {
        signature[at] ^= 1U;
        CHECK(verify_composite(crypto, ana, label, body, signature) ==
              Verification::Invalid);
        signature[at] ^= 1U;
    }

    // ML-DSA signing is hedged, so a fresh signature differs and verifies.
    Seed ed25519;
    secret(ed25519, "seed_1");
    secret(seed, "ml_dsa_seed_1");
    const CompositeSignature fresh =
        sign_composite(crypto, ed25519, seed, ana_fingerprint, label, body);
    CHECK(verify_composite(crypto, ana, label, body, fresh) ==
          Verification::Valid);
}

void test_code_vectors(const CryptoContext& crypto) {
    Secret32 inbox;
    secret(inbox, "pairing_inbox_secret");
    CHECK(mailbox_address(crypto, inbox) == fixed<kHashBytes>("pairing_inbox"));

    const PairingCode code = vector_code();
    CHECK(fixed<8>("code_expires") ==
          (std::array<Byte, 8>{0, 0, 0, 0, 0x65, 0x53, 0xF3, 0x58}));
    CHECK(same(encode_code_record(code).view(), v.at("code_record")));
    const std::string text = text_of(v.at("pairing_code"));
    CHECK(text_of(format_pairing_code(code).view()) == text);
    CHECK(text.size() <= kMaxPairingCodeChars);

    PairingCode parsed;
    CHECK(parse_pairing_code(text, parsed) == CodecStatus::Ok);
    CHECK(same(encode_code_record(parsed).view(), v.at("code_record")));
    CHECK(parsed.kind == code.kind && parsed.id == code.id &&
          parsed.owner == code.owner && parsed.mailbox == code.mailbox &&
          parsed.inbox == code.inbox && parsed.expires_at == code.expires_at);

    // One canonical text: no padding, no lone last character, no other
    // alphabet, and exactly this prefix and version.
    CHECK(parse_pairing_code(text + "=", parsed) == CodecStatus::Malformed);
    CHECK(parse_pairing_code(text + "A", parsed) == CodecStatus::Malformed);
    std::string plus = text;
    plus[20] = '+';
    CHECK(parse_pairing_code(plus, parsed) == CodecStatus::Malformed);
    CHECK(parse_pairing_code("ITO-PAIR:1:" + text.substr(11), parsed) ==
          CodecStatus::Malformed);
    CHECK(parse_pairing_code("ito-pair:2:" + text.substr(11), parsed) ==
          CodecStatus::Unsupported);
    CHECK(parse_pairing_code("ito-pair:x:" + text.substr(11), parsed) ==
          CodecStatus::Malformed);
    CHECK(parse_pairing_code("ito-contact:1:" + text.substr(11), parsed) ==
          CodecStatus::Malformed);

    // A ten-letter service leaves 164 record bytes, whose last character
    // carries two spare bits. Setting one is a second spelling, refused.
    PairingCode shorter = vector_code();
    shorter.mailbox.service = "ito-mailbo";
    std::string spare = text_of(format_pairing_code(shorter).view());
    CHECK(parse_pairing_code(spare, parsed) == CodecStatus::Ok);
    spare.back() = static_cast<char>(spare.back() + 1);
    CHECK(parse_pairing_code(spare, parsed) == CodecStatus::Malformed);

    const Bytes& record = v.at("code_record");
    for (std::size_t size = 0U; size < record.size(); ++size) {
        CHECK(parse_code_record(ByteView(record.data(), size), parsed) ==
              CodecStatus::Malformed);
    }
    Bytes longer = record;
    longer.push_back(0U);
    CHECK(parse_code_record(longer, parsed) == CodecStatus::Malformed);
    Bytes kind = record;
    for (const Byte value : {Byte{0}, Byte{3}}) {
        kind[0] = value;
        CHECK(parse_code_record(kind, parsed) == CodecStatus::Malformed);
    }
    Bytes expiry = record;
    std::fill(expiry.end() - 8, expiry.end(), Byte{0});
    CHECK(parse_code_record(expiry, parsed) == CodecStatus::Malformed);
    Bytes service = record;
    service[1U + kPairingIdBytes + 32U + kHashBytes + kKeyBytes + 1U] = ' ';
    CHECK(parse_code_record(service, parsed) == CodecStatus::Malformed);
}

void test_exchange_vectors(const CryptoContext& crypto) {
    const PairingCode code = vector_code();

    // Ana opens Ben's hello.
    ReceivedHello hello;
    CHECK(open_hello(crypto, code, v.at("hello"), hello) == Status::Ok);
    CHECK(same(hello.body_bytes, v.at("hello_body")));
    CHECK(hello.body.sender == vector_identity("public_2", "ml_dsa_public_2"));
    CHECK(hello.body.name == "Ben");
    CHECK(hello.body.mailbox.server_fingerprint ==
          fixed<kKeyBytes>("scan_server"));
    Secret32 ben_inbox;
    secret(ben_inbox, "scan_inbox_secret");
    CHECK(hello.body.inbox == mailbox_address(crypto, ben_inbox));
    CHECK(verify_hello(crypto, code, hello) == Verification::Valid);
    CHECK(hello_transcript(crypto, code, hello) ==
          fixed<kHashBytes>("hello_transcript"));

    // Ben signed the whole code: the same hello does not verify for another
    // code of Ana's, even one it decrypts under.
    PairingCode later = vector_code();
    later.expires_at += 1U;
    CHECK(verify_hello(crypto, later, hello) == Verification::Invalid);

    ReceivedHello refused;
    CHECK(open_hello(crypto, code, v.at("hello_bad_padding"), refused) ==
          Status::Malformed);
    Bytes flipped = v.at("hello");
    flipped[100] ^= 1U;
    CHECK(open_hello(crypto, code, flipped, refused) ==
          Status::AuthenticationFailed);
    flipped = v.at("hello");
    flipped[0] ^= 1U;  // the salt, which is also the associated data
    CHECK(open_hello(crypto, code, flipped, refused) ==
          Status::AuthenticationFailed);
    PairingCode guessed = vector_code();
    guessed.secret.data()[0] ^= 1U;
    CHECK(open_hello(crypto, guessed, v.at("hello"), refused) ==
          Status::AuthenticationFailed);
    CHECK(open_hello(crypto, code,
                     ByteView(v.at("hello").data(), kMediumItemBytes),
                     refused) == Status::Malformed);

    // Ben opens Ana's reply with the secrets his hello used.
    ScanSecrets secrets;
    secret(secrets.share, "scan_share");
    secret(secrets.kem, "scan_kem_seed");
    secret(secrets.inbox, "scan_inbox_secret");
    const Hash first = fixed<kHashBytes>("hello_transcript");
    ReceivedReply reply;
    CHECK(open_reply(crypto, code, secrets, first, v.at("reply"), reply) ==
          Status::Ok);
    CHECK(same(reply.body_bytes, v.at("reply_body")));
    CHECK(reply.body.name == "Ana");
    Secret32 ratchet;
    secret(ratchet, "reply_ratchet");
    CHECK(reply.body.ratchet == crypto.x25519_public_key(ratchet));
    CHECK(verify_reply(crypto, code, first, reply) == Verification::Valid);
    Hash transcript{};
    Secret32 root;
    finish_reply(crypto, first, reply, transcript, root);
    CHECK(transcript == fixed<kHashBytes>("transcript"));
    CHECK(same(root.view(), v.at("root")));
    CHECK(text_of(short_code(crypto, root, transcript)) ==
          text_of(v.at("short_code")));

    // The reply must come from the fingerprint in the code.
    PairingCode impostor = vector_code();
    impostor.owner = fixed<kHashBytes>("fingerprint2_2");
    CHECK(verify_reply(crypto, impostor, first, reply) ==
          Verification::Invalid);
    ReceivedReply refused_reply;
    Hash other_hello = first;
    other_hello[0] ^= 1U;
    CHECK(open_reply(crypto, code, secrets, other_hello, v.at("reply"),
                     refused_reply) == Status::AuthenticationFailed);
    Bytes changed = v.at("reply");
    changed[kKeyBytes + 5U] ^= 1U;  // inside the ML-KEM ciphertext
    CHECK(open_reply(crypto, code, secrets, first, changed, refused_reply) ==
          Status::AuthenticationFailed);
    changed = v.at("reply");
    std::fill_n(changed.begin(), kKeyBytes, Byte{0});  // a small-order share
    CHECK(open_reply(crypto, code, secrets, first, changed, refused_reply) ==
          Status::AuthenticationFailed);

    // Ben's confirm is the same bytes every time it is built.
    secret(ratchet, "confirm_ratchet");
    const Key ben_ratchet = crypto.x25519_public_key(ratchet);
    CHECK(same(seal_confirm(crypto, root, transcript, ben_ratchet),
               v.at("confirm")));
    Key opened{};
    CHECK(open_confirm(crypto, root, transcript, v.at("confirm"), opened) ==
          Status::Ok);
    CHECK(opened == ben_ratchet);
    CHECK(open_confirm(crypto, root, other_hello, v.at("confirm"), opened) ==
          Status::AuthenticationFailed);
    changed = v.at("confirm");
    changed.back() ^= 1U;
    CHECK(open_confirm(crypto, root, transcript, changed, opened) ==
          Status::AuthenticationFailed);
}

void test_snapshot2_vector(const CryptoContext& crypto) {
    const Bytes& snapshot = v.at("snapshot_2");
    StoreState state;
    CHECK(decode_snapshot(crypto, snapshot, state) == Status::Ok);
    CHECK(state.has_identity && state.has_identity2);
    CHECK(state.public_key == fixed<kKeyBytes>("public_1"));
    CHECK(state.fingerprint2 == fixed<kHashBytes>("fingerprint2_1"));
    CHECK(state.contacts.size() == 1U && state.contact_secrets.size() == 1U);
    const Contact& ben = state.contacts[0];
    CHECK(ben.key == fixed<kKeyBytes>("public_2") && ben.name == "Ben" &&
          ben.trust == Trust::Verified && ben.paired.has_value());
    CHECK(ben.paired->ml_dsa ==
              fixed<kMlDsaPublicKeyBytes>("ml_dsa_public_2") &&
          ben.paired->verified_by == VerifiedBy::InPerson &&
          ben.paired->send_mailbox ==
              authority("scan_server", "mailbox_service"));
    const ContactSecrets& secrets = state.contact_secrets[0];
    CHECK(secrets.role == PairingRole::Owner &&
          same(secrets.root.view(), v.at("root")) &&
          secrets.transcript == fixed<kHashBytes>("transcript"));
    CHECK(state.spent.size() == 1U);
    CHECK(state.codes.size() == 1U && state.codes[0].state == CodeState::Open &&
          state.codes[0].code.kind == PairingKind::Link &&
          state.codes[0].own_name == "Ana");
    CHECK(state.scans.size() == 1U && state.scans[0].scanned);
    CHECK(same(encode_snapshot(state).view(), snapshot));

    for (std::size_t size = 0U; size < snapshot.size(); ++size) {
        StoreState partial;
        CHECK(decode_snapshot(crypto, ByteView(snapshot.data(), size),
                              partial) == Status::CorruptState);
    }
    Bytes longer = snapshot;
    longer.push_back(0U);
    StoreState refused;
    CHECK(decode_snapshot(crypto, longer, refused) == Status::CorruptState);
    // Domain 24, Ed25519 seed and key 64, identity time 8.
    constexpr std::size_t kMlDsaSeedAt = 24U + 64U + 8U;
    // Then the ML-DSA seed, clock, pruned floor, contact count, Ben's key.
    constexpr std::size_t kTrustAt = kMlDsaSeedAt + 32U + 8U + 8U + 2U + 32U;
    // Another ML-DSA seed is another fingerprint, which no longer owns the
    // stored code.
    Bytes other_seed = snapshot;
    other_seed[kMlDsaSeedAt] ^= 1U;
    CHECK(decode_snapshot(crypto, other_seed, refused) == Status::CorruptState);
    // A paired contact Unverified while it names how it was verified.
    Bytes unverified = snapshot;
    CHECK(unverified[kTrustAt] == static_cast<Byte>(Trust::Verified));
    unverified[kTrustAt] = static_cast<Byte>(Trust::Unverified);
    CHECK(decode_snapshot(crypto, unverified, refused) == Status::CorruptState);
}

// Every list at its bound and every field at its longest. The constant the
// store and the platform rely on must be what the encoder writes, exactly.
void test_snapshot2_bound() {
    StoreState state;
    state.has_identity = true;
    state.has_identity2 = true;
    Authority longest;
    longest.service.assign(kMaxServiceBytes, 's');
    const std::string name(kMaxNameBytes, 'n');
    for (std::size_t index = 0U; index < kMaxContacts; ++index) {
        Contact contact;
        contact.key[0] = static_cast<Byte>(index >> 8U);
        contact.key[1] = static_cast<Byte>(index);
        contact.trust = Trust::Blocked;
        contact.replaced_by = Key{};
        contact.replaces = Key{};
        contact.name = name;
        contact.paired = PairedContact{};
        contact.paired->send_mailbox = longest;
        contact.paired->receive_mailbox = longest;
        ContactSecrets secrets;
        secrets.key = contact.key;
        state.contacts.push_back(std::move(contact));
        state.contact_secrets.push_back(std::move(secrets));
    }
    state.spent.resize(kMaxSpentInvitations);
    for (std::size_t index = 0U; index < kMaxOwnedCodes; ++index) {
        OwnedCode owned;
        owned.code.mailbox = longest;
        owned.own_name = name;
        owned.state = CodeState::Confirmed;
        owned.peer_mailbox = longest;
        owned.peer_name = name;
        state.codes.push_back(std::move(owned));
    }
    for (std::size_t index = 0U; index < kMaxPendingScans; ++index) {
        PendingScan scan;
        scan.code.mailbox = longest;
        scan.own_mailbox = longest;
        state.scans.push_back(std::move(scan));
    }
    const SecretBytes encoded = encode_snapshot(state);
    std::printf("largest snapshot 2: %zu bytes of %zu\n", encoded.size(),
                kMaxSnapshotBytes);
    CHECK(encoded.size() == max_snapshot2_bytes());
    CHECK(encoded.size() <= kMaxSnapshotBytes);
}

// Persists into memory and can be told to refuse.
struct Disk final {
    std::vector<Byte> committed;
    PersistResult next{PersistResult::Committed};
    int calls{0};

    Persist persist() {
        return [this](ByteView snapshot) {
            ++calls;
            if (next == PersistResult::Committed) {
                committed.assign(snapshot.begin(), snapshot.end());
            }
            return next;
        };
    }
};

// One installation and the mailbox it receives on.
struct Phone final {
    Disk disk;
    std::unique_ptr<Store> store;
    Authority mailbox;
};

// Wall seconds and a monotonic reading that agree, as on a steady device.
TimePoint at(std::uint64_t now) {
    return TimePoint{} + std::chrono::seconds(now);
}

std::unique_ptr<Phone> phone(const CryptoContext& crypto, Byte server,
                             std::uint64_t now) {
    auto result = std::make_unique<Phone>();
    CHECK(Store::open(crypto, {}, result->disk.persist(), result->store) ==
          Status::Ok);
    CHECK(result->store->create_identity(now) == Status::Ok);
    CHECK(result->store->upgrade_identity() == Status::Ok);
    result->mailbox.server_fingerprint.fill(server);
    result->mailbox.service = "ito-mailbox";
    return result;
}

Key key_of(const Phone& phone) {
    Key key{};
    CHECK(phone.store->identity(key) == Status::Ok);
    return key;
}

// Whether the phone keeps an inbox open where the item goes.
bool lists_inbox(const Phone& phone, const OutgoingItem& item,
                 InboxPurpose purpose) {
    for (std::size_t index = 0U; index < phone.store->inbox_count(); ++index) {
        Inbox inbox;
        CHECK(phone.store->inbox_at(index, inbox) == Status::Ok);
        if (inbox.address == item.address) {
            return inbox.purpose == purpose && inbox.mailbox == item.mailbox;
        }
    }
    return false;
}

struct Received final {
    Status status{Status::Internal};
    PairingEvent event;
    std::optional<OutgoingItem> out;
};

// What the mailbox does: hand the item to the phone holding its inbox.
Received deliver(Phone& to, const OutgoingItem& item, std::uint64_t now) {
    Received result;
    result.status = to.store->receive_pairing(
        item.address, item.item, now, at(now), result.event, result.out);
    return result;
}

struct Started final {
    PairingId id{};
    std::string text;
    OutgoingItem hello;
};

// Ana shows a code and Ben reads it, which gives the hello for Ana's
// pairing inbox.
Started start(Phone& ana, Phone& ben, PairingKind kind, bool scanned,
              std::uint64_t now) {
    Started result;
    SecretBytes text;
    CHECK(ana.store->create_code(kind, ana.mailbox, "Ana", now, at(now),
                                 result.id, text) == Status::Ok);
    result.text = text_of(text.view());
    PairingId read{};
    CHECK(ben.store->scan(result.text, scanned, ben.mailbox, "Ben", now,
                          at(now), read, result.hello) == Status::Ok);
    CHECK(read == result.id);
    CHECK(result.hello.mailbox == ana.mailbox &&
          result.hello.item.size() == kLargeItemBytes);
    CHECK(lists_inbox(ana, result.hello, InboxPurpose::ShownCode));
    return result;
}

// Both sides derived the same root and transcript, and each holds the
// other's first ratchet key.
void check_same_session(const CryptoContext& crypto, const Phone& ana,
                        const Phone& ben) {
    StoreState owner;
    StoreState scanner;
    CHECK(decode_snapshot(crypto, ana.disk.committed, owner) == Status::Ok);
    CHECK(decode_snapshot(crypto, ben.disk.committed, scanner) == Status::Ok);
    CHECK(owner.contact_secrets.size() == 1U &&
          scanner.contact_secrets.size() == 1U);
    const ContactSecrets& a = owner.contact_secrets[0];
    const ContactSecrets& b = scanner.contact_secrets[0];
    CHECK(a.role == PairingRole::Owner && b.role == PairingRole::Scanner);
    CHECK(constant_time_equal(a.root.view(), b.root.view()));
    CHECK(a.transcript == b.transcript);
    CHECK(a.peer_ratchet == crypto.x25519_public_key(b.own_ratchet));
    CHECK(b.peer_ratchet == crypto.x25519_public_key(a.own_ratchet));
}

void test_in_person(const CryptoContext& crypto) {
    auto ana = phone(crypto, 0xA1, 1000U);
    auto ben = phone(crypto, 0xB1, 1000U);
    const Started started =
        start(*ana, *ben, PairingKind::InPerson, true, 1000U);

    Received replied = deliver(*ana, started.hello, 1001U);
    CHECK(replied.status == Status::Ok &&
          replied.event.kind == PairingEventKind::Replied &&
          replied.event.peer == key_of(*ben) &&
          replied.event.peer_name == "Ben" &&
          replied.event.short_code.has_value() && replied.out.has_value());
    CHECK(lists_inbox(*ben, *replied.out, InboxPurpose::AwaitingReply));
    // The first valid hello spent the code and closed its pairing inbox.
    CHECK(deliver(*ana, started.hello, 1001U).status == Status::AlreadySpent);
    CHECK(!lists_inbox(*ana, started.hello, InboxPurpose::ShownCode));

    Received paired = deliver(*ben, *replied.out, 1002U);
    CHECK(paired.status == Status::Ok &&
          paired.event.kind == PairingEventKind::Paired &&
          paired.event.role == PairingRole::Scanner &&
          paired.event.trust == Trust::Verified &&
          paired.event.peer == key_of(*ana) &&
          paired.event.peer_name == "Ana" &&
          paired.event.short_code == replied.event.short_code &&
          paired.out.has_value());
    CHECK(lists_inbox(*ana, *paired.out, InboxPurpose::AwaitingConfirm));
    // Ben's reply inbox is now his inbox for Ana, which messaging owns.
    CHECK(deliver(*ben, *replied.out, 1002U).status == Status::NotFound);

    const Received confirmed = deliver(*ana, *paired.out, 1003U);
    CHECK(confirmed.status == Status::Ok &&
          confirmed.event.kind == PairingEventKind::Confirmed &&
          confirmed.event.short_code == replied.event.short_code &&
          !confirmed.out.has_value());
    // Nothing is saved until Ana says the digits match.
    CHECK(!ana->store->find_contact(key_of(*ben)).has_value());
    PairingEvent decided;
    CHECK(ana->store->decide_pairing(started.id, true, 1004U, at(1004U),
                                     decided) == Status::Ok);
    CHECK(decided.kind == PairingEventKind::Completed &&
          decided.trust == Trust::Verified);
    CHECK(ana->store->pairings().empty() && ben->store->pairings().empty());

    // A confirm deposited again is the same bytes, recognized as a resend.
    OutgoingItem again;
    CHECK(ben->store->confirm_item(key_of(*ana), again) == Status::Ok);
    CHECK(again.item == paired.out->item &&
          again.address == paired.out->address);
    CHECK(deliver(*ana, again, 1005U).status == Status::AlreadySpent);
    CHECK(ana->store->confirm_item(key_of(*ben), again) == Status::WrongState);

    // Each side receives where the other sends.
    PairedView owner;
    PairedView scanner;
    CHECK(ana->store->paired_contact(key_of(*ben), owner) == Status::Ok);
    CHECK(ben->store->paired_contact(key_of(*ana), scanner) == Status::Ok);
    CHECK(owner.paired.send_address == scanner.receive_address &&
          scanner.paired.send_address == owner.receive_address);
    CHECK(owner.paired.send_mailbox == ben->mailbox &&
          owner.paired.receive_mailbox == ana->mailbox &&
          scanner.paired.send_mailbox == ana->mailbox &&
          scanner.paired.receive_mailbox == ben->mailbox);
    CHECK(owner.role == PairingRole::Owner &&
          scanner.role == PairingRole::Scanner);
    CHECK(owner.paired.verified_by == VerifiedBy::InPerson &&
          scanner.paired.verified_by == VerifiedBy::InPerson);
    Identity2 identity;
    Hash fingerprint{};
    CHECK(ben->store->identity2(identity, fingerprint) == Status::Ok &&
          owner.fingerprint == fingerprint);
    SafetyCode owner_code{};
    SafetyCode scanner_code{};
    CHECK(ana->store->safety_code(key_of(*ben), owner_code) == Status::Ok);
    CHECK(ben->store->safety_code(key_of(*ana), scanner_code) == Status::Ok);
    CHECK(owner_code == scanner_code);
    CHECK(lists_inbox(*ana,
                      OutgoingItem{ana->mailbox, owner.receive_address, {}},
                      InboxPurpose::ContactInbox));
    check_same_session(crypto, *ana, *ben);

    // The pairing survives a restart.
    std::unique_ptr<Store> reopened;
    CHECK(Store::open(crypto, ana->disk.committed, ana->disk.persist(),
                      reopened) == Status::Ok);
    PairedView reread;
    CHECK(reopened->paired_contact(key_of(*ben), reread) == Status::Ok &&
          reread.paired == owner.paired &&
          reread.receive_address == owner.receive_address);
}

void test_matched_before_confirm(const CryptoContext& crypto) {
    auto ana = phone(crypto, 0xA1, 1000U);
    auto ben = phone(crypto, 0xB1, 1000U);
    const Started started =
        start(*ana, *ben, PairingKind::InPerson, true, 1000U);
    const Received replied = deliver(*ana, started.hello, 1001U);
    CHECK(replied.status == Status::Ok);
    const Received paired = deliver(*ben, *replied.out, 1002U);
    CHECK(paired.status == Status::Ok);
    // Ana taps Matches before the confirm arrives.
    PairingEvent decided;
    CHECK(ana->store->decide_pairing(started.id, true, 1003U, at(1003U),
                                     decided) == Status::Ok);
    CHECK(decided.kind == PairingEventKind::Matched &&
          decided.short_code == replied.event.short_code);
    CHECK(!ana->store->find_contact(key_of(*ben)).has_value());
    const Received completed = deliver(*ana, *paired.out, 1004U);
    CHECK(completed.status == Status::Ok &&
          completed.event.kind == PairingEventKind::Completed &&
          completed.event.trust == Trust::Verified);
    CHECK(ana->store->is_verified(key_of(*ben)));
    check_same_session(crypto, *ana, *ben);
}

void test_link(const CryptoContext& crypto) {
    auto ana = phone(crypto, 0xA1, 1000U);
    auto ben = phone(crypto, 0xB1, 1000U);
    const Started started = start(*ana, *ben, PairingKind::Link, false, 1000U);
    const Received replied = deliver(*ana, started.hello, 1001U);
    CHECK(replied.status == Status::Ok &&
          !replied.event.short_code.has_value());
    // A link has no short code to compare.
    PairingEvent decided;
    CHECK(ana->store->decide_pairing(started.id, true, 1001U, at(1001U),
                                     decided) == Status::WrongState);
    const Received paired = deliver(*ben, *replied.out, 1002U);
    CHECK(paired.status == Status::Ok &&
          paired.event.trust == Trust::Unverified &&
          !paired.event.short_code.has_value());
    const Received completed = deliver(*ana, *paired.out, 1003U);
    CHECK(completed.status == Status::Ok &&
          completed.event.kind == PairingEventKind::Completed &&
          completed.event.trust == Trust::Unverified);
    check_same_session(crypto, *ana, *ben);

    // Only the full safety code verifies, never the identity 1 fingerprint.
    const Key ben_key = key_of(*ben);
    CHECK(ana->store->verify_contact(ben_key,
                                     to_hex(fingerprint(crypto, ben_key)),
                                     1004U) == Status::WrongState);
    SafetyCode code{};
    CHECK(ana->store->safety_code(ben_key, code) == Status::Ok);
    std::string wrong = text_of(code);
    wrong[59] = wrong[59] == '0' ? '1' : '0';
    CHECK(ana->store->verify_safety_code(ben_key, wrong, 1004U) ==
          Status::AuthenticationFailed);
    CHECK(!ana->store->is_verified(ben_key));
    const std::string spaced =
        text_of(code).substr(0, 30) + " " + text_of(code).substr(30);
    CHECK(ana->store->verify_safety_code(ben_key, spaced, 1004U) == Status::Ok);
    PairedView view;
    CHECK(ana->store->paired_contact(ben_key, view) == Status::Ok &&
          view.paired.verified_by == VerifiedBy::Compared);
    CHECK(ana->store->is_verified(ben_key));
    CHECK(!ben->store->is_verified(key_of(*ana)));
}

void test_copied_code(const CryptoContext& crypto) {
    // Eve photographed Ana's screen and sends her hello before Ben.
    auto ana = phone(crypto, 0xA1, 1000U);
    auto eve = phone(crypto, 0xE1, 1000U);
    auto ben = phone(crypto, 0xB1, 1000U);
    const Started stolen =
        start(*ana, *eve, PairingKind::InPerson, true, 1000U);
    OutgoingItem hello;
    PairingId id{};
    CHECK(ben->store->scan(stolen.text, true, ben->mailbox, "Ben", 1000U,
                           at(1000U), id, hello) == Status::Ok);
    const Received replied = deliver(*ana, stolen.hello, 1001U);
    CHECK(replied.status == Status::Ok && replied.event.peer == key_of(*eve));
    CHECK(deliver(*ana, hello, 1001U).status == Status::AlreadySpent);
    const Received paired = deliver(*eve, *replied.out, 1002U);
    CHECK(paired.status == Status::Ok);
    // Ben's screen shows no digits, so Ana taps Doesn't match.
    PairingEvent decided;
    CHECK(ana->store->decide_pairing(stolen.id, false, 1003U, at(1003U),
                                     decided) == Status::Ok);
    CHECK(decided.kind == PairingEventKind::Rejected);
    CHECK(ana->store->pairings().empty() && ana->store->contacts().empty());
    CHECK(deliver(*ana, *paired.out, 1004U).status == Status::NotFound);
    // Ben's pairing waits for a reply that never comes, until he cancels.
    CHECK(ben->store->pairings().size() == 1U);
    CHECK(ben->store->cancel_pairing(id) == Status::Ok);
    CHECK(ben->store->pairings().empty() && ben->store->inbox_count() == 0U);
}

void test_refusals(const CryptoContext& crypto) {
    auto ana = phone(crypto, 0xA1, 1000U);
    auto ben = phone(crypto, 0xB1, 1000U);
    PairingId id{};
    SecretBytes text;
    CHECK(ana->store->create_code(PairingKind::InPerson, ana->mailbox, "",
                                  1000U, at(1000U), id,
                                  text) == Status::InvalidArgument);
    Authority bad = ana->mailbox;
    bad.service = "ito mailbox";
    CHECK(ana->store->create_code(PairingKind::InPerson, bad, "Ana", 1000U,
                                  at(1000U), id,
                                  text) == Status::InvalidArgument);
    const Started started =
        start(*ana, *ben, PairingKind::InPerson, true, 1000U);
    SecretBytes shown;
    CHECK(ana->store->code_text(started.id, shown) == Status::Ok &&
          text_of(shown.view()) == started.text);

    OutgoingItem hello;
    CHECK(ana->store->scan(started.text, true, ana->mailbox, "Ana", 1000U,
                           at(1000U), id, hello) == Status::InvalidArgument);
    CHECK(ben->store->scan(started.text, true, ben->mailbox, "Ben", 1000U,
                           at(1000U), id, hello) == Status::AlreadySpent);
    CHECK(ben->store->scan("ito-pair:9:AAAA", true, ben->mailbox, "Ben", 1000U,
                           at(1000U), id, hello) == Status::Unsupported);

    // A forged or damaged hello, an unknown inbox and a failed save all
    // leave the code open and its snapshot unwritten.
    const int calls = ana->disk.calls;
    OutgoingItem damaged = started.hello;
    damaged.item[200] ^= 1U;
    CHECK(deliver(*ana, damaged, 1000U).status == Status::AuthenticationFailed);
    OutgoingItem elsewhere = started.hello;
    elsewhere.address[0] ^= 1U;
    CHECK(deliver(*ana, elsewhere, 1000U).status == Status::NotFound);
    ana->disk.next = PersistResult::NotCommitted;
    CHECK(deliver(*ana, started.hello, 1000U).status == Status::StorageFailed);
    ana->disk.next = PersistResult::Committed;
    CHECK(ana->disk.calls == calls + 1);
    const std::vector<PairingInfo> open = ana->store->pairings();
    CHECK(open.size() == 1U && open[0].state == CodeState::Open &&
          !open[0].peer.has_value());
    CHECK(deliver(*ana, started.hello, 1000U).status == Status::Ok);

    // Expiry: a code read at its expiry, and a hello that arrives then.
    auto late = phone(crypto, 0xB2, 2000U);
    const Started expiring =
        start(*ana, *late, PairingKind::InPerson, true, 2000U);
    auto later = phone(crypto, 0xB3, 2600U);
    CHECK(later->store->scan(expiring.text, true, later->mailbox, "Late", 2600U,
                             at(2600U), id, hello) == Status::Expired);
    CHECK(deliver(*ana, expiring.hello, 2600U).status == Status::Expired);

    // Eight shown codes at most.
    auto busy = phone(crypto, 0xC1, 3000U);
    for (std::size_t index = 0U; index < kMaxOwnedCodes; ++index) {
        CHECK(busy->store->create_code(PairingKind::Link, busy->mailbox, "Busy",
                                       3000U, at(3000U), id,
                                       text) == Status::Ok);
    }
    CHECK(busy->store->create_code(PairingKind::Link, busy->mailbox, "Busy",
                                   3000U, at(3000U), id,
                                   text) == Status::Capacity);

    // A wall clock behind the saved floor is refused before any item opens.
    auto regressed = phone(crypto, 0xC2, 5000U);
    auto sender = phone(crypto, 0xC3, 5000U);
    const Started back =
        start(*regressed, *sender, PairingKind::Link, false, 5000U);
    CHECK(deliver(*regressed, back.hello, 4000U).status ==
          Status::ClockRegressed);
}

void test_trust_rules(const CryptoContext& crypto) {
    // A Blocked key cannot pair, whatever it signs.
    auto ana = phone(crypto, 0xA1, 1000U);
    auto ben = phone(crypto, 0xB1, 1000U);
    CHECK(ana->store->add_contact(key_of(*ben), "Ben", 1000U) == Status::Ok);
    CHECK(ana->store->block_contact(key_of(*ben)) == Status::Ok);
    const Started blocked =
        start(*ana, *ben, PairingKind::InPerson, true, 1000U);
    CHECK(deliver(*ana, blocked.hello, 1001U).status == Status::Untrusted);
    CHECK(ana->store->pairings()[0].state == CodeState::Open);

    // A Verified identity 1 contact who pairs by link is Not verified: that
    // comparison never covered the ML-DSA key. The name and record stay.
    auto cara = phone(crypto, 0xA2, 1000U);
    auto dan = phone(crypto, 0xB2, 1000U);
    const Key dan_key = key_of(*dan);
    CHECK(cara->store->add_contact(dan_key, "Dan", 1000U) == Status::Ok);
    CHECK(cara->store->verify_contact(dan_key,
                                      to_hex(fingerprint(crypto, dan_key)),
                                      1000U) == Status::Ok);
    SafetyCode code{};
    CHECK(cara->store->safety_code(dan_key, code) == Status::WrongState);
    const Started link = start(*cara, *dan, PairingKind::Link, false, 1000U);
    const Received replied = deliver(*cara, link.hello, 1001U);
    const Received paired = deliver(*dan, *replied.out, 1002U);
    const Received completed = deliver(*cara, *paired.out, 1003U);
    CHECK(completed.status == Status::Ok &&
          completed.event.trust == Trust::Unverified);
    const std::optional<Contact> kept = cara->store->find_contact(dan_key);
    CHECK(kept && kept->name == "Dan" && kept->added_at == 1000U &&
          kept->paired && kept->paired->verified_by == VerifiedBy::None);

    // A block between the hello and the confirm stops the completion.
    auto eli = phone(crypto, 0xA3, 1000U);
    auto fay = phone(crypto, 0xB3, 1000U);
    const Started late_block =
        start(*eli, *fay, PairingKind::Link, false, 1000U);
    const Received answered = deliver(*eli, late_block.hello, 1001U);
    const Received scanned = deliver(*fay, *answered.out, 1002U);
    CHECK(eli->store->add_contact(key_of(*fay), "Fay", 1003U) == Status::Ok);
    CHECK(eli->store->block_contact(key_of(*fay)) == Status::Ok);
    CHECK(deliver(*eli, *scanned.out, 1003U).status == Status::Untrusted);
    const std::optional<Contact> blocked_fay =
        eli->store->find_contact(key_of(*fay));
    CHECK(blocked_fay && blocked_fay->trust == Trust::Blocked &&
          !blocked_fay->paired);

    // An in-person code that reached the scanner as a link is no proof of
    // whose screen it came from.
    auto gil = phone(crypto, 0xA4, 1000U);
    auto hal = phone(crypto, 0xB4, 1000U);
    const Started forwarded =
        start(*gil, *hal, PairingKind::InPerson, false, 1000U);
    const Received offered = deliver(*gil, forwarded.hello, 1001U);
    const Received unproven = deliver(*hal, *offered.out, 1002U);
    CHECK(unproven.status == Status::Ok &&
          unproven.event.trust == Trust::Unverified &&
          unproven.event.short_code == offered.event.short_code);
}

// Ana from snapshot_2 already paired with Ben's identity 2. A hello under
// Ben's Ed25519 key with any other ML-DSA key is refused before its
// signature is checked. Ben's own identity may pair again.
void test_known_key_other_ml_dsa(const CryptoContext& crypto) {
    for (const Byte ml_dsa_fill : {Byte{0x23}, Byte{0x22}}) {
        Disk disk;
        const Bytes& snapshot = v.at("snapshot_2");
        disk.committed.assign(snapshot.begin(), snapshot.end());
        std::unique_ptr<Store> ana;
        CHECK(Store::open(crypto, disk.committed, disk.persist(), ana) ==
              Status::Ok);
        constexpr std::uint64_t kNow = 1'700'000'200U;
        PairingId id{};
        SecretBytes text;
        Authority mailbox = authority("mailbox_server", "mailbox_service");
        CHECK(ana->create_code(PairingKind::InPerson, mailbox, "Ana", kNow,
                               at(kNow), id, text) == Status::Ok);
        PairingCode code;
        CHECK(parse_pairing_code(text_of(text.view()), code) ==
              CodecStatus::Ok);

        Seed ed25519;
        secret(ed25519, "seed_2");
        Secret32 ml_dsa;
        std::array<Byte, 32> fill{};
        fill.fill(ml_dsa_fill);
        ml_dsa.assign(fill);
        HelloBody body;
        body.sender = Identity2{fixed<kKeyBytes>("public_2"),
                                crypto.ml_dsa_public_key(ml_dsa)};
        ScanSecrets secrets;
        crypto.random(std::span<Byte>(secrets.share.data(), 32U));
        crypto.random(std::span<Byte>(secrets.kem.data(), kMlKemSeedBytes));
        body.share = crypto.x25519_public_key(secrets.share);
        body.kem = crypto.ml_kem_public_key(secrets.kem);
        body.mailbox = authority("scan_server", "mailbox_service");
        body.name = "Ben";
        const Hash signer = fingerprint2(crypto, body.sender);
        const BuiltHello hello =
            build_hello(crypto, Signer{ed25519, ml_dsa, signer}, code, body);
        PairingEvent event;
        std::optional<OutgoingItem> out;
        const Status status = ana->receive_pairing(code.inbox, hello.item, kNow,
                                                   at(kNow), event, out);
        if (ml_dsa_fill == 0x22) {
            CHECK(status == Status::Ok &&
                  event.kind == PairingEventKind::Replied);
        } else {
            CHECK(status == Status::Untrusted);
        }
    }
}

void test_upgrade(const CryptoContext& crypto) {
    Disk disk;
    std::unique_ptr<Store> store;
    CHECK(Store::open(crypto, {}, disk.persist(), store) == Status::Ok);
    CHECK(store->upgrade_identity() == Status::NotFound);
    CHECK(store->create_identity(1000U) == Status::Ok);
    Key dan{};
    Seed seed;
    crypto.generate_identity(seed, dan);
    CHECK(store->add_contact(dan, "Dan", 1000U) == Status::Ok);
    const std::string_view one{"ito/identity-snapshot/1\0", 24U};
    const std::string_view two{"ito/identity-snapshot/2\0", 24U};
    CHECK(text_of(ByteView(disk.committed).first(24U)) == one);
    Identity2 identity;
    Hash fingerprint{};
    CHECK(store->identity2(identity, fingerprint) == Status::WrongState);
    PairingId id{};
    SecretBytes text;
    Authority mailbox;
    mailbox.service = "ito-mailbox";
    CHECK(store->create_code(PairingKind::Link, mailbox, "Me", 1000U, at(1000U),
                             id, text) == Status::WrongState);

    CHECK(store->upgrade_identity() == Status::Ok);
    CHECK(store->upgrade_identity() == Status::WrongState);
    CHECK(text_of(ByteView(disk.committed).first(24U)) == two);
    CHECK(store->identity2(identity, fingerprint) == Status::Ok);
    Key own{};
    CHECK(store->identity(own) == Status::Ok && identity.ed25519 == own &&
          fingerprint == fingerprint2(crypto, identity));

    std::unique_ptr<Store> reopened;
    CHECK(Store::open(crypto, disk.committed, disk.persist(), reopened) ==
          Status::Ok);
    Identity2 reread;
    Hash again{};
    CHECK(reopened->identity2(reread, again) == Status::Ok &&
          reread == identity && again == fingerprint);
    // The identity 1 contact is kept and pairs again.
    const std::optional<Contact> kept = reopened->find_contact(dan);
    CHECK(kept && kept->name == "Dan" && !kept->paired);
    PairedView view;
    CHECK(reopened->paired_contact(dan, view) == Status::WrongState);
}

}  // namespace

int main() {
    v = testing::load_vectors(ITO_CALL_VECTORS);
    const CryptoContext crypto;
    test_identity_vectors(crypto);
    test_code_vectors(crypto);
    test_exchange_vectors(crypto);
    test_snapshot2_vector(crypto);
    test_snapshot2_bound();
    test_upgrade(crypto);
    test_in_person(crypto);
    test_matched_before_confirm(crypto);
    test_link(crypto);
    test_copied_code(crypto);
    test_refusals(crypto);
    test_trust_rules(crypto);
    test_known_key_other_ml_dsa(crypto);
    return 0;
}
