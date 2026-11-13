/* Copyright (C) 2026 FixCraft Inc. AGPL-3.0-or-later. */

#include "invitation.hpp"

#include <algorithm>
#include <array>
#include <limits>

namespace ito::call {

OpenedInvitation::OpenedInvitation(Store& store, Invitation&& invitation,
                                   const Hash& hash, TimePoint deadline,
                                   TimePoint accept_deadline, const Key& peer)
    : store_(store),
      invitation_(std::move(invitation)),
      hash_(hash),
      peer_(peer),
      deadline_(deadline),
      accept_deadline_(accept_deadline) {
    store_.add_borrower();
}

void OpenedInvitation::forget_secrets() noexcept {
    invitation_.psk = Psk{};
    invitation_.encoded.clear();
    // No later owner needs this bearer, including an abandoned handoff.
    wipe(invitation_.responder_token.data(),
         invitation_.responder_token.size());
}

OpenedInvitation::~OpenedInvitation() {
    forget_secrets();
    store_.release_pending();
    store_.remove_borrower();
}

Status check_invitation_time(std::uint64_t issued_at, std::uint64_t expires_at,
                             std::uint64_t now) noexcept {
    if (expires_at <= issued_at) return Status::Malformed;
    const std::uint64_t lifetime = expires_at - issued_at;
    if (lifetime < kMinInvitationLifetime ||
        lifetime > kMaxInvitationLifetime) {
        return Status::Malformed;
    }
    // Issued more than 60 seconds in the verifier's future: not yet valid.
    if (issued_at > now && issued_at - now > kMaxIssuedSkew) {
        return Status::Expired;
    }
    // No grace after expiry.
    if (now >= expires_at) return Status::Expired;
    return Status::Ok;
}

namespace {

Status open_received(Store& store, const Key* authenticated_peer,
                     ByteView encoded, const Authority& expected,
                     std::uint64_t now, TimePoint observed,
                     std::unique_ptr<OpenedInvitation>& out) {
    if (encoded.empty() || encoded.size() > kMaxInvitationBytes) {
        return Status::Malformed;
    }
    Invitation invitation;
    switch (parse_invitation(encoded, invitation)) {
        case CodecStatus::Ok:
            break;
        case CodecStatus::Malformed:
            return Status::Malformed;
        case CodecStatus::Unsupported:
            return Status::Unsupported;
    }
    if (invitation.version != (authenticated_peer != nullptr ? 2U : 1U))
        return Status::Unsupported;
    // Independently generated selectors and two distinct parties.
    if (invitation.invitation_id == invitation.room_id ||
        invitation.initiator == invitation.responder) {
        return Status::Malformed;
    }
    const Status clock = store.check_clock(now, observed);
    if (clock != Status::Ok) return clock;
    const Status time =
        check_invitation_time(invitation.issued_at, invitation.expires_at, now);
    if (time != Status::Ok) return time;
    const auto remaining = std::chrono::seconds(invitation.expires_at - now);
    if (observed > TimePoint::max() - remaining) return Status::InvalidArgument;
    const TimePoint deadline = observed + remaining;
    TimePoint accept_deadline = deadline;
    if (authenticated_peer != nullptr) {
        // Ringing ends at 45 seconds, while a call accepted in time may
        // finish its handshake within the invitation's 90 seconds.
        const std::uint64_t age =
            now > invitation.issued_at ? now - invitation.issued_at : 0U;
        const auto budget =
            static_cast<std::uint64_t>(kRingBudget.count() / 1000);
        if (age >= budget) return Status::Expired;
        accept_deadline = std::min(deadline, observed + Seconds(budget - age));
    }
    Key peer = invitation.initiator;
    if (authenticated_peer != nullptr) {
        peer = *authenticated_peer;
        MessagePeer paired;
        const Status found = store.message_peer(peer, paired);
        if (found != Status::Ok) return found;
        if (paired.trust != Trust::Verified ||
            invitation.initiator != paired.peer_fingerprint ||
            invitation.responder != paired.own_fingerprint)
            return Status::Untrusted;
        if (invitation.authority.server_fingerprint !=
            paired.receive_mailbox.server_fingerprint)
            return Status::AuthorityMismatch;
    } else {
        Key own{};
        if (store.identity(own) != Status::Ok) return Status::WrongState;
        if (invitation.responder != own || !store.is_verified(peer))
            return Status::Untrusted;
    }
    if (!(invitation.authority == expected)) return Status::AuthorityMismatch;
    // The expensive peer-selected work comes after every cheap refusal.
    const CryptoContext& crypto = store.crypto();
    if (authenticated_peer == nullptr &&
        crypto.verify(invitation.initiator, invitation_signed_bytes(invitation),
                      invitation.signature) != Verification::Valid) {
        return Status::AuthenticationFailed;
    }
    const Status unspent =
        store.check_unspent(invitation.invitation_id, invitation.expires_at);
    if (unspent != Status::Ok) return unspent;
    const std::array<ByteView, 1> whole{invitation.encoded.view()};
    const Hash hash = crypto.sha256(whole);
    ClockAdmission admission;
    const Status admitted = store.admit_clock(now, observed, admission);
    if (admitted != Status::Ok) return admitted;
    const Status slot = store.acquire_pending();
    if (slot != Status::Ok) return slot;
    try {
        out = std::make_unique<OpenedInvitation>(store, std::move(invitation),
                                                 hash, deadline,
                                                 accept_deadline, peer);
    } catch (...) {
        store.release_pending();
        throw;
    }
    return Status::Ok;
}

}  // namespace

Status open_invitation(Store& store, ByteView encoded,
                       const Authority& expected, std::uint64_t now,
                       TimePoint observed,
                       std::unique_ptr<OpenedInvitation>& out) {
    return open_received(store, nullptr, encoded, expected, now, observed, out);
}

Status open_ring(Store& store, const Key& peer, ByteView encoded,
                 const Authority& expected, std::uint64_t now,
                 TimePoint observed, std::unique_ptr<OpenedInvitation>& out) {
    return open_received(store, &peer, encoded, expected, now, observed, out);
}

Status sign_new_invitation(Store& store, Invitation& invitation,
                           const ClockAdmission& admission, TimePoint observed,
                           std::uint64_t lifetime, std::uint16_t profile) {
    if (profile != kProfile && profile != kContentProfile &&
        profile != kRingProfile)
        return Status::InvalidArgument;
    std::uint64_t lower = 0U;
    std::uint64_t now = 0U;
    const Status projected = admission.project(observed, lower, now);
    if (projected != Status::Ok) return projected;
    if (lifetime < kMinInvitationLifetime ||
        lifetime > kMaxInvitationLifetime ||
        now > std::numeric_limits<std::uint64_t>::max() - lifetime) {
        return Status::InvalidArgument;
    }
    const Status admitted = store.advance_clock(admission, observed);
    if (admitted != Status::Ok) return admitted;
    const CryptoContext& crypto = store.crypto();
    crypto.random(invitation.invitation_id);
    // The PSK is independent of every other field and never reaches the relay.
    crypto.random(
        std::span<Byte>(invitation.psk.data(), invitation.psk.size()));
    invitation.issued_at = now;
    invitation.expires_at = now + lifetime;
    invitation.profile = profile;
    invitation.version = profile == kRingProfile ? 2U : 1U;
    SecretBytes body = encode_invitation_body(invitation);
    if (invitation.version == 1U) {
        const Status signed_status =
            store.sign(body.view(), invitation.signature);
        if (signed_status != Status::Ok) return signed_status;
        body.append(invitation.signature);
    }
    invitation.encoded = std::move(body);
    return Status::Ok;
}

}  // namespace ito::call
