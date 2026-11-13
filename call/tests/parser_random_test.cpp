/* Copyright (C) 2026 FixCraft Inc. AGPL-3.0-or-later. */

// A bounded, deterministic random pass over every parser the core exposes
// to peer or user input: byte flips, truncations, extensions and random
// bytes seeded from the fixed vectors. Each parse must stay in bounds (the
// sanitizers check that) and anything accepted must re-encode to exactly
// the bytes that were parsed. This is a smoke pass, not a fuzz campaign.

#include <algorithm>
#include <cstdio>
#include <map>
#include <random>
#include <string>
#include <vector>

#include "check.hpp"
#include "codec.hpp"
#include "envelope.hpp"
#include "ratchet.hpp"
#include "session.hpp"
#include "store.hpp"

using namespace ito::call;

namespace {

using Bytes = std::vector<Byte>;
constexpr int kRounds = 20'000;

Bytes mutate(const Bytes& seed, std::mt19937_64& random) {
    Bytes out = seed;
    switch (random() % 5U) {
        case 0:
            if (!out.empty())
                out[random() % out.size()] ^=
                    static_cast<Byte>(1U << (random() % 8U));
            break;
        case 1:
            out.resize(out.empty() ? 0 : random() % out.size());
            break;
        case 2:
            for (std::size_t count = random() % 8U; count > 0; --count) {
                out.push_back(static_cast<Byte>(random()));
            }
            break;
        case 3:
            if (!out.empty())
                out[random() % out.size()] = static_cast<Byte>(random());
            break;
        default:
            out.resize(random() % 600U);
            for (Byte& byte : out) byte = static_cast<Byte>(random());
            break;
    }
    return out;
}

void invitations(const Bytes& seed, std::mt19937_64& random, int& accepted) {
    for (int round = 0; round < kRounds; ++round) {
        const Bytes input = mutate(seed, random);
        Invitation invitation;
        if (parse_invitation(input, invitation) != CodecStatus::Ok) continue;
        ++accepted;
        SecretBytes body = encode_invitation_body(invitation);
        if (invitation.version == 1U) body.append(invitation.signature);
        CHECK(std::equal(body.view().begin(), body.view().end(), input.begin(),
                         input.end()));
    }
}

void contact_codes(const Bytes& seed, std::mt19937_64& random, int& accepted) {
    for (int round = 0; round < kRounds; ++round) {
        const Bytes input = mutate(seed, random);
        const std::string code(input.begin(), input.end());
        Key key{};
        if (parse_contact_code(code, key) != CodecStatus::Ok) continue;
        ++accepted;
        CHECK(format_contact_code(key) == code);
    }
}

void relay_replies(const std::vector<Bytes>& seeds, std::mt19937_64& random,
                   int& accepted) {
    for (int round = 0; round < kRounds; ++round) {
        const Bytes input = mutate(seeds[random() % seeds.size()], random);
        RelayReply reply;
        std::size_t consumed = 0;
        if (parse_relay_reply(input, reply, consumed) !=
            ParseProgress::Complete) {
            continue;
        }
        ++accepted;
        CHECK(consumed >= 5U && consumed <= input.size());
    }
}

void frames(const std::vector<Bytes>& seeds, std::mt19937_64& random,
            int& accepted) {
    for (int round = 0; round < kRounds; ++round) {
        const Bytes input = mutate(seeds[random() % seeds.size()], random);
        FrameAssembler assembler;
        std::size_t offset = 0;
        // Random read boundaries.
        while (offset < input.size() && !assembler.malformed()) {
            const std::size_t step =
                1U +
                random() % std::max<std::size_t>(1U, input.size() - offset);
            const std::size_t taken = assembler.feed(ByteView(
                input.data() + offset, std::min(step, input.size() - offset)));
            offset += taken;
            if (const auto frame = assembler.frame()) {
                ++accepted;
                SecretBytes again;
                encode_frame(again, frame->type, frame->sequence,
                             frame->payload);
                CHECK(again.size() ==
                      frame->payload.size() + kFrameHeaderBytes);
                assembler.take();
            } else if (taken == 0U) {
                break;
            }
        }
    }
}

void snapshots(const CryptoContext& crypto, const Bytes& seed,
               std::mt19937_64& random, int& accepted) {
    for (int round = 0; round < kRounds / 4; ++round) {
        const Bytes input = mutate(seed, random);
        StoreState state;
        if (decode_snapshot(crypto, input, state) != Status::Ok) continue;
        ++accepted;
        const SecretBytes again = encode_snapshot(state);
        CHECK(std::equal(again.view().begin(), again.view().end(),
                         input.begin(), input.end()));
    }
}

// An envelope is accepted with zero padding after it and re-encodes to the
// bytes before the padding.
void envelopes(const std::vector<Bytes>& seeds, std::mt19937_64& random,
               int& accepted) {
    for (int round = 0; round < kRounds; ++round) {
        const Bytes input = mutate(seeds[random() % seeds.size()], random);
        Envelope envelope;
        if (read_envelope(input, envelope) != Status::Ok) continue;
        ++accepted;
        Bytes again;
        Writer write(again);
        write_envelope(write, envelope);
        CHECK(again.size() <= input.size() &&
              std::equal(again.begin(), again.end(), input.begin()) &&
              std::all_of(
                  input.begin() + static_cast<std::ptrdiff_t>(again.size()),
                  input.end(), [](Byte byte) { return byte == 0U; }));
    }
}

void sessions(const CryptoContext& crypto, const Bytes& seed,
              std::mt19937_64& random, int& accepted) {
    for (int round = 0; round < kRounds / 4; ++round) {
        const Bytes input = mutate(seed, random);
        SessionState state;
        if (decode_session(crypto, input, state) != Status::Ok) continue;
        ++accepted;
        const SecretBytes again = encode_session(state);
        CHECK(std::equal(again.view().begin(), again.view().end(),
                         input.begin(), input.end()));
    }
}

// Ratchet messages against Ana's first state. Every mutation of a sealed
// item must be refused, and each refusal stays in bounds.
void messages(const CryptoContext& crypto,
              const std::map<std::string, std::vector<unsigned char>>& v,
              std::mt19937_64& random, int& accepted) {
    SessionSeed seed;
    seed.role = PairingRole::Owner;
    seed.root.assign(std::span<const Byte, 32>(v.at("root").data(), 32U));
    seed.own_ratchet.assign(
        std::span<const Byte, 32>(v.at("reply_ratchet").data(), 32U));
    Secret32 scanner;
    scanner.assign(
        std::span<const Byte, 32>(v.at("confirm_ratchet").data(), 32U));
    seed.peer_ratchet = crypto.x25519_public_key(scanner);
    RatchetState start;
    CHECK(start_ratchet(crypto, seed, start) == Status::Ok);
    Fingerprints fingerprints;
    std::copy_n(v.at("fingerprint2_1").begin(), 32, fingerprints.own.begin());
    std::copy_n(v.at("fingerprint2_2").begin(), 32, fingerprints.peer.begin());
    const std::vector<Bytes> seeds{v.at("message_1"), v.at("message_2")};
    for (int round = 0; round < kRounds / 20; ++round) {
        const Bytes& original = seeds[random() % seeds.size()];
        const Bytes input = mutate(original, random);
        RatchetState state;
        state.copy_from(start);
        SecretBytes plaintext;
        if (open_message(crypto, state, fingerprints, input, plaintext) !=
            Status::Ok) {
            continue;
        }
        ++accepted;
        CHECK(input == original);
    }
}

}  // namespace

int main() {
    const auto v = testing::load_vectors(ITO_CALL_VECTORS);
    const CryptoContext crypto;
    std::mt19937_64 random(0x17C0A11ULL);
    int accepted[8] = {0, 0, 0, 0, 0, 0, 0, 0};
    invitations(v.at("invitation_1"), random, accepted[0]);
    invitations(v.at("ring_invitation"), random, accepted[0]);
    contact_codes(v.at("contact_code_1"), random, accepted[1]);
    relay_replies({v.at("relay_reserved"), v.at("relay_waiting"),
                   v.at("relay_paired"), v.at("relay_refused")},
                  random, accepted[2]);
    frames({v.at("frame_offer"), v.at("frame_data"), v.at("frame_end")}, random,
           accepted[3]);
    snapshots(crypto, v.at("snapshot_1"), random, accepted[4]);
    snapshots(crypto, v.at("snapshot_2"), random, accepted[4]);
    envelopes({v.at("envelope_1"), v.at("envelope_3"), v.at("envelope_5"),
               v.at("envelope_6"), v.at("envelope_8"), v.at("envelope_9"),
               v.at("ring_envelope"), v.at("ring_end_envelope")},
              random, accepted[5]);
    sessions(crypto, v.at("session_ben"), random, accepted[6]);
    messages(crypto, v, random, accepted[7]);
    std::printf(
        "accepted: invitation %d, contact %d, relay %d, frame %d, "
        "snapshot %d, envelope %d, session %d, message %d\n",
        accepted[0], accepted[1], accepted[2], accepted[3], accepted[4],
        accepted[5], accepted[6], accepted[7]);
    return 0;
}
