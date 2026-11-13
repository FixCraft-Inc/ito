/* Copyright (C) 2026 FixCraft Inc. AGPL-3.0-or-later. */

// Ringing through the authenticated ratchet, then the real TLS call engine.
// Virtual time keeps the 45/90 second edges exact. Fixed Python vectors
// separately check every new domain and both halves of the call proof.

#include <algorithm>
#include <array>
#include <cstdio>
#include <memory>
#include <span>
#include <string>
#include <string_view>

#include "engine_harness.hpp"
#include "envelope.hpp"
#include "session.hpp"

using namespace ito::call;
using namespace ito::call::testing;

namespace {
constexpr std::uint64_t kUnix = 1'800'000'000U;
const TimePoint kTime = TimePoint{} + std::chrono::hours(100);

void pair(Identity& a, Identity& b, bool upgrade = true) {
    if (upgrade) {
        CHECK(a.store->upgrade_identity() == Status::Ok);
        CHECK(b.store->upgrade_identity() == Status::Ok);
    }
    Authority mailbox = authority("ito-mailbox");
    PairingId id{};
    PairingId scanned{};
    SecretBytes text;
    CHECK(a.store->create_code(PairingKind::InPerson, mailbox, "A", kUnix,
                               kTime, id, text) == Status::Ok);
    OutgoingItem hello;
    CHECK(b.store->scan(
              std::string_view(reinterpret_cast<const char*>(text.data()),
                               text.size()),
              true, mailbox, "B", kUnix, kTime, scanned, hello) == Status::Ok);
    PairingEvent event;
    std::optional<OutgoingItem> reply;
    std::optional<OutgoingItem> confirm;
    std::optional<OutgoingItem> none;
    CHECK(a.store->receive_pairing(hello.address, hello.item, kUnix, kTime,
                                   event, reply) == Status::Ok &&
          reply);
    CHECK(b.store->receive_pairing(reply->address, reply->item, kUnix, kTime,
                                   event, confirm) == Status::Ok &&
          confirm);
    CHECK(a.store->receive_pairing(confirm->address, confirm->item, kUnix,
                                   kTime, event, none) == Status::Ok &&
          !none);
    CHECK(a.store->decide_pairing(id, true, kUnix, kTime, event) == Status::Ok);
}

struct Ring final {
    Identity a;
    Identity b;
    FakeRelay relay;
    Wire wire{relay};
    std::unique_ptr<Session> chat_a;
    std::unique_ptr<Session> chat_b;
    std::unique_ptr<CallEngine> caller;
    std::unique_ptr<CallEngine> callee;
    Bytes disk_a;
    Bytes disk_b;
    PersistResult save_b{PersistResult::Committed};
    SecretBytes invitation;
    Invitation parsed;
    OutgoingItem sealed;

    explicit Ring(const CryptoContext& crypto)
        : a(crypto, kUnix), b(crypto, kUnix), relay(crypto) {
        pair(a, b);
        CHECK(Session::open(
                  *a.store, b.key, {},
                  [this](ByteView bytes) {
                      disk_a.assign(bytes.begin(), bytes.end());
                      return PersistResult::Committed;
                  },
                  kUnix * 1000U, chat_a) == Status::Ok);
        CHECK(Session::open(
                  *b.store, a.key, {},
                  [this](ByteView bytes) {
                      if (save_b == PersistResult::Committed)
                          disk_b.assign(bytes.begin(), bytes.end());
                      return save_b;
                  },
                  kUnix * 1000U, chat_b) == Status::Ok);
        EngineOptions options;
        options.profile = kRingProfile;
        CHECK(CallEngine::create_initiator(*a.store, b.key, authority(),
                                           kRingRoomSeconds, kUnix, kTime,
                                           caller, options) == Status::Ok);
        wire.engines[0] = caller.get();
        caller->start(kTime);
        wire.pump(kTime);
        CHECK(caller->snapshot().invitation_ready);
        std::array<Byte, kMaxInvitationBytes> bytes{};
        std::size_t size = 0U;
        CHECK(caller->copy_invitation(bytes, size) == Status::Ok);
        invitation.append(ByteView(bytes).first(size));
        wipe(bytes.data(), bytes.size());
        CHECK(parse_invitation(invitation.view(), parsed) == CodecStatus::Ok);
        CHECK(parsed.version == 2U && parsed.profile == kRingProfile);
        CHECK(parsed.expires_at - parsed.issued_at == 90U);
        MessageId id{};
        CHECK(chat_a->send(MessageKind::Ring, invitation.view(), kUnix * 1000U,
                           id, sealed) == Status::Ok);
        CHECK(chat_a->outbox().empty());
        CHECK(chat_a->resend(id, kUnix * 1000U, sealed) == Status::NotFound);
    }

    Status open(std::unique_ptr<OpenedInvitation>& out, std::uint64_t age = 0U,
                const Authority& selected = authority()) {
        return chat_b->receive_ring(sealed.item, selected,
                                    (kUnix + age) * 1000U, kTime + Seconds(age),
                                    out);
    }

    void accept(std::unique_ptr<OpenedInvitation>& opened,
                std::uint64_t age = 0U) {
        CHECK(CallEngine::create_responder(*b.store, opened, authority(),
                                           kUnix + age, kTime + Seconds(age),
                                           callee) == Status::Ok);
        CHECK(!opened);
        wire.engines[1] = callee.get();
        callee->start(kTime + Seconds(age));
        wire.pump(kTime + Seconds(age));
    }
};

void reservation(const CryptoContext& crypto) {
    Identity a(crypto, kUnix);
    Identity b(crypto, kUnix);
    pair(a, b);
    EngineOptions options;
    options.profile = kRingProfile;
    std::unique_ptr<CallEngine> caller;
    CHECK(CallEngine::create_initiator(*a.store, b.key, authority(), 89U, kUnix,
                                       kTime, caller,
                                       options) == Status::InvalidArgument);
    Authority wrong = authority();
    wrong.server_fingerprint[0] ^= 1U;
    CHECK(CallEngine::create_initiator(*a.store, b.key, wrong, 90U, kUnix,
                                       kTime, caller,
                                       options) == Status::AuthorityMismatch);
    CHECK(CallEngine::create_initiator(*a.store, b.key, authority(), 90U, kUnix,
                                       kTime, caller, options) == Status::Ok);
    FakeRelay relay(crypto);
    relay.grant_override = 60'000U;
    Wire wire{relay};
    wire.engines[0] = caller.get();
    caller->start(kTime);
    wire.pump(kTime);
    CHECK(caller->snapshot().result == Status::ProtocolFailure);
    CHECK(!caller->snapshot().invitation_ready && !relay.paired);
}

void established(const CryptoContext& crypto) {
    Ring ring(crypto);
    std::unique_ptr<OpenedInvitation> opened;
    // Unsigned bytes alone never authorize a call.
    CHECK(open_invitation(*ring.b.store, ring.invitation.view(), authority(),
                          kUnix, kTime, opened) == Status::Unsupported);
    CHECK(!opened);
    CHECK(ring.open(opened) == Status::Ok);
    std::unique_ptr<OpenedInvitation> replay;
    CHECK(ring.open(replay) == Status::AlreadySpent && !replay);
    ring.accept(opened);
    CHECK(ring.caller->snapshot().state == CallState::MediaAuthorized);
    CHECK(ring.callee->snapshot().state == CallState::MediaAuthorized);
    CHECK(ring.callee->snapshot().peer_authenticated);
    CHECK(!ring.callee->snapshot().consent_pending);
    CHECK(ring.callee->decide(true, kTime) == Status::WrongState);
    CHECK(ring.b.store->check_unspent(ring.parsed.invitation_id,
                                      ring.parsed.expires_at) ==
          Status::AlreadySpent);
    const std::array<Byte, 3> data{1U, 2U, 3U};
    CHECK(ring.caller->send(data, kTime) == Status::Ok);
    ring.wire.pump(kTime);
    std::array<Byte, 4> received{};
    std::size_t size = 0U;
    CHECK(ring.callee->receive(received, size) == Status::Ok &&
          size == data.size());
    CHECK(std::equal(data.begin(), data.end(), received.begin()));
    // After acceptance the invitation's 90 seconds is not an active-call timer.
    ring.wire.pump(kTime + Seconds(91));
    CHECK(ring.callee->snapshot().state == CallState::MediaAuthorized);
    CHECK(!contains(ring.relay.tap[0], ring.parsed.psk.view()));
    CHECK(!contains(ring.relay.tap[1], ring.parsed.psk.view()));
    CHECK(!contains(ring.relay.tap[0], ring.parsed.initiator));
    CHECK(ring.caller->hangup(kTime + Seconds(91)) == Status::Ok);
}

void paired_again(const CryptoContext& crypto) {
    Ring ring(crypto);
    std::unique_ptr<OpenedInvitation> opened;
    CHECK(ring.open(opened) == Status::Ok);
    ring.accept(opened);
    pair(ring.a, ring.b, false);
    ring.wire.pump(kTime);
    CHECK(ring.caller->snapshot().result == Status::Untrusted);
    CHECK(ring.callee->snapshot().result == Status::Untrusted);
}

void refusals(const CryptoContext& crypto) {
    {
        Ring ring(crypto);
        std::unique_ptr<OpenedInvitation> opened;
        const Bytes before = ring.disk_b;
        CHECK(ring.open(opened, 0U, authority("other-call")) ==
              Status::AuthorityMismatch);
        CHECK(!opened && ring.disk_b == before);
        Bytes damaged = ring.sealed.item;
        damaged.back() ^= 1U;
        CHECK(ring.chat_b->receive_ring(damaged, authority(), kUnix * 1000U,
                                        kTime, opened) ==
              Status::AuthenticationFailed);
        CHECK(!opened && ring.disk_b == before);
        ring.save_b = PersistResult::NotCommitted;
        CHECK(ring.open(opened) == Status::StorageFailed);
        CHECK(!opened && ring.disk_b == before);
        ring.save_b = PersistResult::Committed;
        CHECK(ring.open(opened) == Status::Ok);
        CHECK(ring.b.store->block_contact(ring.a.key) == Status::Ok);
        CHECK(CallEngine::create_responder(*ring.b.store, opened, authority(),
                                           kUnix, kTime,
                                           ring.callee) == Status::Untrusted &&
              opened);
    }
    {
        Ring ring(crypto);
        std::unique_ptr<OpenedInvitation> opened;
        const Bytes before = ring.disk_b;
        ring.save_b = PersistResult::Ambiguous;
        CHECK(ring.open(opened) == Status::StorageAmbiguous);
        CHECK(!opened && ring.disk_b == before);
        ring.save_b = PersistResult::Committed;
        CHECK(ring.open(opened) == Status::StorageAmbiguous);
    }
    {
        Ring ring(crypto);
        std::unique_ptr<OpenedInvitation> opened;
        CHECK(ring.open(opened, 45U) == Status::Expired && !opened);
        ring.wire.pump(kTime + Seconds(45));
        CHECK(ring.caller->snapshot().result == Status::Timeout);
    }
    {
        Ring ring(crypto);
        std::unique_ptr<OpenedInvitation> opened;
        CHECK(ring.open(opened) == Status::Ok);
        CHECK(CallEngine::create_responder(*ring.b.store, opened, authority(),
                                           kUnix + 45U, kTime + Seconds(45),
                                           ring.callee) == Status::Expired &&
              opened);
    }
    {
        Ring ring(crypto);
        std::unique_ptr<OpenedInvitation> opened;
        CHECK(ring.open(opened, 44U) == Status::Ok);
        ring.accept(opened, 44U);
        CHECK(ring.callee->snapshot().state == CallState::MediaAuthorized);
    }
    {
        Ring ring(crypto);
        std::unique_ptr<OpenedInvitation> opened;
        CHECK(ring.open(opened) == Status::Ok);
        CHECK(CallEngine::create_responder(*ring.b.store, opened, authority(),
                                           kUnix + 44U, kTime + Seconds(44),
                                           ring.callee) == Status::Ok);
        ring.callee->start(kTime + Seconds(45));
        CHECK(ring.callee->snapshot().result == Status::Expired);
        CHECK(ring.relay.tap[1].empty());
    }
    {
        Ring ring(crypto);
        const auto original = ring.parsed.responder;
        ring.parsed.responder[0] ^= 1U;
        const SecretBytes wrong = encode_invitation_body(ring.parsed);
        MessageId id{};
        OutgoingItem out;
        CHECK(ring.chat_a->send(MessageKind::Ring, wrong.view(), kUnix * 1000U,
                                id, out) == Status::Untrusted);
        ring.parsed.responder = original;
        ring.parsed.authority.server_fingerprint[0] ^= 1U;
        const SecretBytes moved = encode_invitation_body(ring.parsed);
        CHECK(ring.chat_a->send(MessageKind::Ring, moved.view(), kUnix * 1000U,
                                id, out) == Status::AuthorityMismatch);
    }
}

// A malicious paired sender can bypass its own Session::send checks. Seal
// such a ring directly and exercise the receiver's independent trust checks.
void bad_received_ring(const CryptoContext& crypto) {
    for (unsigned mutation = 0U; mutation < 3U; ++mutation) {
        Ring ring(crypto);
        if (mutation == 0U) ring.parsed.initiator[0] ^= 1U;
        if (mutation == 1U) ring.parsed.responder[0] ^= 1U;
        if (mutation == 2U) ring.parsed.authority.server_fingerprint[0] ^= 1U;
        Envelope envelope;
        envelope.kind = MessageKind::Ring;
        crypto.random(envelope.id);
        envelope.sent_ms = kUnix * 1000U;
        envelope.payload = encode_invitation_body(ring.parsed);
        Bytes plaintext;
        const WipeOnExit wiped(plaintext);
        plaintext.reserve(envelope_size(envelope));
        Writer writer(plaintext);
        write_envelope(writer, envelope);
        SessionState state;
        CHECK(decode_session(crypto, ring.disk_a, state) == Status::Ok);
        MessagePeer peer;
        CHECK(ring.a.store->message_peer(ring.b.key, peer) == Status::Ok);
        MessageRandom random;
        crypto.random(random.salt);
        crypto.random(
            std::span<Byte>(random.ratchet.data(), random.ratchet.size()));
        crypto.random(std::span<Byte>(random.kem.data(), random.kem.size()));
        Bytes sealed;
        CHECK(seal_message(crypto, state.ratchet,
                           {peer.own_fingerprint, peer.peer_fingerprint},
                           plaintext, random, sealed) == Status::Ok);
        const Bytes before = ring.disk_b;
        std::unique_ptr<OpenedInvitation> opened;
        const Authority selected =
            mutation == 2U ? ring.parsed.authority : authority();
        CHECK(ring.chat_b->receive_ring(sealed, selected, kUnix * 1000U, kTime,
                                        opened) ==
              (mutation == 2U ? Status::AuthorityMismatch : Status::Untrusted));
        CHECK(!opened && ring.disk_b == before);
    }
}

void bad_proofs(const CryptoContext& crypto) {
    for (unsigned mutation = 0U; mutation < 5U; ++mutation) {
        Ring ring(crypto);
        RawPeer raw(crypto, TlsRole::Server, ring.parsed.invitation_id,
                    ring.parsed.psk);
        ring.wire.raws[1] = &raw;
        ring.relay.raw[1] = true;
        ring.relay.paired = true;
        ring.relay.pending[0] = {0U, 0U, 0U, 1U, 5U};
        ring.wire.pump(kTime);
        CHECK(raw.established && raw.last(FrameType::Offer));
        raw.send(FrameType::Select, profile_body(mutation == 4U ? 2U : 3U));
        ring.wire.pump(kTime);
        if (mutation == 4U) {
            CHECK(ring.caller->snapshot().result == Status::Unsupported);
            continue;
        }
        CHECK(raw.last(FrameType::Auth));
        const std::array<ByteView, 1> whole{ring.invitation.view()};
        const Hash hash = crypto.sha256(whole);
        const auto profile = profile_body(3U);
        const Hash context =
            context_hash(crypto, hash, ring.parsed, profile, profile);
        Hash exporter = raw.tls.exporter();
        if (mutation == 3U) exporter[0] ^= 1U;
        const AuthMessage message =
            auth_message(Role::Responder, exporter, context, kRingProfile);
        const std::array<ByteView, 1> body{
            ByteView(message).subspan(kAuth2Domain.size())};
        CompositeSignature proof{};
        CHECK(ring.b.store->sign2(kAuth2Domain, body, proof) == Status::Ok);
        if (mutation < 2U) proof[mutation == 0U ? 0U : kSignatureBytes] ^= 1U;
        raw.send(FrameType::Auth,
                 ByteView(proof).first(mutation == 2U ? kSignatureBytes
                                                      : proof.size()));
        ring.wire.pump(kTime);
        CHECK(!ring.caller->snapshot().peer_authenticated);
        CHECK(ring.caller->snapshot().result ==
              (mutation == 2U ? Status::ProtocolFailure
                              : Status::AuthenticationFailed));
    }
    for (unsigned half = 0U; half < 2U; ++half) {
        Ring ring(crypto);
        RawPeer raw(crypto, TlsRole::Client, ring.parsed.invitation_id,
                    ring.parsed.psk);
        ring.wire.engines[0] = nullptr;
        ring.wire.raws[0] = &raw;
        ring.relay.raw[0] = true;
        std::unique_ptr<OpenedInvitation> opened;
        CHECK(ring.open(opened) == Status::Ok);
        ring.accept(opened);
        raw.start();
        ring.wire.pump(kTime);
        CHECK(raw.established);
        const auto profile = profile_body(3U);
        raw.send(FrameType::Offer, profile);
        ring.wire.pump(kTime);
        CHECK(raw.last(FrameType::Select));
        const std::array<ByteView, 1> whole{ring.invitation.view()};
        const Hash hash = crypto.sha256(whole);
        const Hash context =
            context_hash(crypto, hash, ring.parsed, profile, profile);
        const AuthMessage message = auth_message(
            Role::Initiator, raw.tls.exporter(), context, kRingProfile);
        const std::array<ByteView, 1> body{
            ByteView(message).subspan(kAuth2Domain.size())};
        CompositeSignature proof{};
        CHECK(ring.a.store->sign2(kAuth2Domain, body, proof) == Status::Ok);
        proof[half == 0U ? 0U : kSignatureBytes] ^= 1U;
        raw.send(FrameType::Auth, proof);
        ring.wire.pump(kTime);
        CHECK(!ring.callee->snapshot().peer_authenticated);
        CHECK(!raw.last(FrameType::Auth));
        CHECK(ring.callee->snapshot().result == Status::AuthenticationFailed);
    }
}

void ring_end(const CryptoContext& crypto) {
    for (Byte reason = 1U; reason <= 4U; ++reason) {
        Ring ring(crypto);
        std::unique_ptr<OpenedInvitation> opened;
        CHECK(ring.open(opened) == Status::Ok);
        opened.reset();  // Decline/busy/missed: no responder engine or JOIN.
        Bytes payload(ring.parsed.invitation_id.begin(),
                      ring.parsed.invitation_id.end());
        payload.push_back(reason);
        MessageId id{};
        OutgoingItem end;
        CHECK(ring.chat_b->send(MessageKind::RingEnd, payload, kUnix * 1000U,
                                id, end) == Status::Ok);
        CHECK(ring.chat_b->outbox().empty());
        bool received = false;
        CHECK(ring.chat_a->receive(
                  end.item, kUnix * 1000U,
                  [&](const Envelope& envelope) {
                      received = envelope.kind == MessageKind::RingEnd &&
                                 std::equal(payload.begin(), payload.end(),
                                            envelope.payload.view().begin(),
                                            envelope.payload.view().end());
                      return true;
                  }) == Status::Ok &&
              received);
        CHECK(!ring.relay.paired && ring.relay.tap[1].empty());
    }
    for (Byte reason : {Byte{0U}, Byte{5U}, Byte{255U}}) {
        Bytes payload(33U, 0U);
        payload.back() = reason;
        CHECK(check_payload(MessageKind::RingEnd, payload) ==
              Status::Malformed);
    }
}

void vectors(const CryptoContext& crypto) {
    const auto v = load_vectors(ITO_CALL_VECTORS);
    Invitation invitation;
    CHECK(parse_invitation(v.at("ring_invitation"), invitation) ==
          CodecStatus::Ok);
    const SecretBytes encoded = encode_invitation_body(invitation);
    CHECK(std::equal(encoded.view().begin(), encoded.view().end(),
                     v.at("ring_invitation").begin(),
                     v.at("ring_invitation").end()));
    const std::array<ByteView, 1> whole{encoded.view()};
    const Hash hash = crypto.sha256(whole);
    CHECK(std::equal(hash.begin(), hash.end(), v.at("ring_hash").begin()));
    const auto profile = profile_body(3U);
    const Hash context =
        context_hash(crypto, hash, invitation, profile, profile);
    CHECK(std::equal(context.begin(), context.end(),
                     v.at("ring_context").begin()));
    Hash exporter{};
    exporter.fill(0x11U);
    std::array<CompositeSignature, 2> proofs{};
    for (std::size_t index = 0U; index < proofs.size(); ++index) {
        const std::string number = std::to_string(index + 1U);
        Identity2 identity;
        const Bytes& ed = v.at("public_" + number);
        const Bytes& ml = v.at("ml_dsa_public_" + number);
        std::copy(ed.begin(), ed.end(), identity.ed25519.begin());
        std::copy(ml.begin(), ml.end(), identity.ml_dsa.begin());
        const Bytes& signature = v.at("ring_proof_" + number);
        std::copy(signature.begin(), signature.end(), proofs[index].begin());
        const Role role = index == 0U ? Role::Initiator : Role::Responder;
        const AuthMessage message =
            auth_message(role, exporter, context, kRingProfile);
        const std::array<ByteView, 1> body{
            ByteView(message).subspan(kAuth2Domain.size())};
        CHECK(verify_composite(crypto, identity, kAuth2Domain, body,
                               proofs[index]) == Verification::Valid);
        for (std::size_t offset : {std::size_t{0U}, kSignatureBytes}) {
            auto damaged = proofs[index];
            damaged[offset] ^= 1U;
            CHECK(verify_composite(crypto, identity, kAuth2Domain, body,
                                   damaged) == Verification::Invalid);
        }
        CHECK(verify_composite(crypto, identity, kAuthDomain, body,
                               proofs[index]) == Verification::Invalid);
        auto moved = message;
        moved[kAuth2Domain.size()] ^= 3U;  // other role
        const std::array<ByteView, 1> other{
            ByteView(moved).subspan(kAuth2Domain.size())};
        CHECK(verify_composite(crypto, identity, kAuth2Domain, other,
                               proofs[index]) == Verification::Invalid);
        FrameAssembler assembler;
        SecretBytes frame;
        encode_frame(frame, FrameType::Auth, 1U, proofs[index]);
        for (const Byte byte : frame.view())
            CHECK(assembler.feed(ByteView(&byte, 1U)) == 1U);
        CHECK(assembler.frame() &&
              assembler.frame()->payload.size() == kCompositeSignatureBytes);
    }
    const Hash accept = accept_body(crypto, context, proofs[0], proofs[1]);
    CHECK(
        std::equal(accept.begin(), accept.end(), v.at("ring_accept").begin()));
    for (const char* key : {"ring_envelope", "ring_end_envelope"}) {
        Envelope envelope;
        CHECK(read_envelope(v.at(key), envelope) == Status::Ok);
        envelope.resent = true;
        CHECK(check_envelope(envelope) == Status::Malformed);
    }
    for (std::size_t size = 0U; size < encoded.size(); ++size) {
        Invitation refused;
        CHECK(parse_invitation(encoded.view().first(size), refused) ==
              CodecStatus::Malformed);
    }
}
}  // namespace

int main() {
    const CryptoContext crypto;
    vectors(crypto);
    reservation(crypto);
    established(crypto);
    paired_again(crypto);
    refusals(crypto);
    bad_proofs(crypto);
    bad_received_ring(crypto);
    ring_end(crypto);
    std::puts(
        "ringing: vectors, authenticated delivery, TLS proofs, consent, expiry "
        "and rollback passed");
}
