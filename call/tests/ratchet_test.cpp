/* Copyright (C) 2026 FixCraft Inc. AGPL-3.0-or-later. */

// The message ratchet and the session snapshot (docs/MESSAGE_SECURITY.md).
// First the conversation in tests/vectors.txt, which an independent Python
// writer produced: every message opens to its envelope, and the messages
// without a fresh ML-KEM ciphertext are sealed again byte for byte. Then
// every bound and refusal of the ratchet, the snapshot's checks and its
// measured largest size, and a long random conversation.

#include <algorithm>
#include <array>
#include <cstdio>
#include <map>
#include <random>
#include <string>
#include <vector>

#include "check.hpp"
#include "envelope.hpp"
#include "ratchet.hpp"
#include "session.hpp"

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

// The times of the Python conversation, in Unix seconds.
constexpr std::uint64_t kBenPaired = 1'700'000'001U;
constexpr std::uint64_t kAnaPaired = 1'700'000'002U;

// Ana showed the code (owner), Ben scanned it.
SessionSeed seed_for(const CryptoContext& crypto, PairingRole role) {
    SessionSeed seed;
    seed.role = role;
    secret(seed.root, "root");
    seed.transcript = fixed<kHashBytes>("transcript");
    Secret32 other;
    if (role == PairingRole::Scanner) {
        secret(seed.own_ratchet, "confirm_ratchet");
        secret(other, "reply_ratchet");
        seed.paired_at = kBenPaired;
    } else {
        secret(seed.own_ratchet, "reply_ratchet");
        secret(other, "confirm_ratchet");
        seed.paired_at = kAnaPaired;
    }
    seed.peer_ratchet = crypto.x25519_public_key(other);
    return seed;
}

MessageRandom random_with(Byte salt, const char* ratchet = nullptr,
                          const char* kem = nullptr) {
    MessageRandom random;
    random.salt.fill(salt);
    if (ratchet != nullptr) secret(random.ratchet, ratchet);
    if (kem != nullptr) secret(random.kem, kem);
    return random;
}

MessageRandom fresh(const CryptoContext& crypto) {
    MessageRandom random;
    crypto.random(random.salt);
    crypto.random(
        std::span<Byte>(random.ratchet.data(), random.ratchet.size()));
    crypto.random(std::span<Byte>(random.kem.data(), random.kem.size()));
    return random;
}

// Opens an item and checks that its plaintext is exactly the envelope and
// zero padding.
void opens_to(const CryptoContext& crypto, RatchetState& state,
              const Fingerprints& fingerprints, ByteView item,
              const Bytes& envelope) {
    SecretBytes plaintext;
    CHECK(open_message(crypto, state, fingerprints, item, plaintext) ==
          Status::Ok);
    CHECK(plaintext.size() >= envelope.size());
    CHECK(std::equal(envelope.begin(), envelope.end(), plaintext.data()));
    CHECK(std::all_of(plaintext.data() + envelope.size(),
                      plaintext.data() + plaintext.size(),
                      [](Byte byte) { return byte == 0U; }));
    Envelope parsed;
    CHECK(read_envelope(plaintext.view(), parsed) == Status::Ok);
}

void opens_vector(const CryptoContext& crypto, RatchetState& state,
                  const Fingerprints& fingerprints, const char* message,
                  const char* envelope) {
    opens_to(crypto, state, fingerprints, v.at(message), v.at(envelope));
}

Status open_status(const CryptoContext& crypto, const RatchetState& state,
                   const Fingerprints& fingerprints, ByteView item) {
    RatchetState copy;
    copy.copy_from(state);
    SecretBytes plaintext;
    return open_message(crypto, copy, fingerprints, item, plaintext);
}

Bytes seal_vector(const CryptoContext& crypto, RatchetState& state,
                  const Fingerprints& fingerprints, const char* envelope,
                  const MessageRandom& random) {
    std::vector<Byte> item;
    CHECK(seal_message(crypto, state, fingerprints, v.at(envelope), random,
                       item) == Status::Ok);
    return item;
}

void test_vectors(const CryptoContext& crypto) {
    const Fingerprints ana_fp{fixed<kHashBytes>("fingerprint2_1"),
                              fixed<kHashBytes>("fingerprint2_2")};
    const Fingerprints ben_fp{ana_fp.peer, ana_fp.own};
    RatchetState ana;
    RatchetState ben;
    CHECK(start_ratchet(crypto, seed_for(crypto, PairingRole::Owner), ana) ==
          Status::Ok);
    CHECK(start_ratchet(crypto, seed_for(crypto, PairingRole::Scanner), ben) ==
          Status::Ok);
    CHECK(same(ana.root.view(), v.at("ratchet_root_1")));
    CHECK(same(ben.root.view(), v.at("ratchet_root_1")));
    CHECK(same(ben.send_key.view(), v.at("ratchet_chain_1")));
    CHECK(same(ana.receive_key.view(), v.at("ratchet_chain_1")));
    CHECK(ben.sending && !ben.receiving && ana.receiving && !ana.sending);

    // Ben's first chain, sealed again exactly.
    advance_time(ben, 1'700'000'100U);
    CHECK(
        same(seal_vector(crypto, ben, ben_fp, "envelope_1", random_with(0xA1)),
             v.at("message_1")));
    advance_time(ben, 1'700'000'200U);
    CHECK(
        same(seal_vector(crypto, ben, ben_fp, "envelope_2", random_with(0xA3)),
             v.at("message_2")));

    // A message whose padding is not zero decrypts, but is no envelope.
    advance_time(ana, 1'700'000'300U);
    {
        RatchetState copy;
        copy.copy_from(ana);
        SecretBytes plaintext;
        CHECK(open_message(crypto, copy, ana_fp, v.at("message_1_bad_padding"),
                           plaintext) == Status::Ok);
        Envelope envelope;
        CHECK(read_envelope(plaintext.view(), envelope) == Status::Malformed);
    }
    opens_vector(crypto, ana, ana_fp, "message_1", "envelope_1");
    opens_vector(crypto, ana, ana_fp, "message_2", "envelope_2");
    CHECK(open_status(crypto, ana, ana_fp, v.at("message_1")) ==
          Status::AlreadySpent);

    // Ana's first chain a day after pairing advertises her ML-KEM key.
    advance_time(ana, 1'700'090'000U);
    CHECK(same(seal_vector(crypto, ana, ana_fp, "envelope_3",
                           random_with(0xB3, "ratchet_a_2", "ana_kem_seed")),
               v.at("message_3")));
    CHECK(same(ana.root.view(), v.at("ratchet_root_2")));
    CHECK(ana.own_kem && ana.own_kem_id == 1U);

    // Ben opens it, and his session snapshot matches the Python writer's.
    advance_time(ben, 1'700'090'000U);
    opens_vector(crypto, ben, ben_fp, "message_3", "envelope_3");
    CHECK(same(ben.root.view(), v.at("ratchet_root_2")));
    CHECK(ben.peer_kem && ben.peer_kem_id == 1U && !ben.sending &&
          ben.last_length == 2U && ben.quantum_steps == 1U);
    SessionState session;
    session.contact = fixed<kKeyBytes>("public_1");
    session.transcript = fixed<kHashBytes>("transcript");
    session.ratchet.copy_from(ben);
    session.outbox.resize(1U);
    CHECK(read_envelope(v.at("envelope_2"), session.outbox[0].envelope) ==
          Status::Ok);
    session.outbox[0].sealed_at = 1'700'000'200U;
    CHECK(same(encode_session(session).view(), v.at("session_ben")));
    SessionState decoded;
    CHECK(decode_session(crypto, v.at("session_ben"), decoded) == Status::Ok);
    CHECK(same(encode_session(decoded).view(), v.at("session_ben")));

    // Ben's next chain answers Ana's key with a fresh encapsulation, so Ana
    // opens the vector's copy and Ben continues from the vector's root.
    advance_time(ben, 1'700'090'100U);
    {
        const Bytes own = seal_vector(crypto, ben, ben_fp, "envelope_4",
                                      random_with(0xC3, "ratchet_b_2"));
        RatchetState copy;
        copy.copy_from(ana);
        opens_to(crypto, copy, ana_fp, own, v.at("envelope_4"));
    }
    // Answering is Ben's post-quantum step, so he advertises nothing.
    CHECK(ben.send_answers && ben.answered_id == 1U && !ben.peer_kem &&
          !ben.own_kem && ben.quantum_steps == 0U);
    secret(ben.root, "ratchet_root_3");
    advance_time(ana, 1'700'090'100U);
    opens_vector(crypto, ana, ana_fp, "message_4", "envelope_4");
    CHECK(same(ana.root.view(), v.at("ratchet_root_3")));
    // The decapsulation key opened one chain and is gone.
    CHECK(!ana.own_kem && !ana.peer_kem && ana.quantum_steps == 0U);

    // Ana's second chain, sealed exactly again. Ben receives it backwards.
    advance_time(ana, 1'700'090'200U);
    CHECK(same(seal_vector(crypto, ana, ana_fp, "envelope_5",
                           random_with(0xD2, "ratchet_a_3")),
               v.at("message_5")));
    advance_time(ana, 1'700'090'300U);
    CHECK(
        same(seal_vector(crypto, ana, ana_fp, "envelope_6", random_with(0xD4)),
             v.at("message_6")));
    CHECK(same(ana.root.view(), v.at("ratchet_root_4")));
    advance_time(ben, 1'700'090'300U);
    opens_vector(crypto, ben, ben_fp, "message_6", "envelope_6");
    CHECK(same(ben.root.view(), v.at("ratchet_root_4")));
    CHECK(ben.skipped.size() == 1U);
    opens_vector(crypto, ben, ben_fp, "message_5", "envelope_5");
    CHECK(ben.skipped.empty());
    CHECK(open_status(crypto, ben, ben_fp, v.at("message_5")) ==
          Status::AlreadySpent);
    CHECK(open_status(crypto, ben, ben_fp, v.at("message_3")) ==
          Status::AlreadySpent);

    // A day after his last step, Ben's third chain advertises his key.
    advance_time(ben, 1'700'180'000U);
    CHECK(same(seal_vector(crypto, ben, ben_fp, "envelope_7",
                           random_with(0xE2, "ratchet_b_3", "ben_kem_seed")),
               v.at("message_7")));
    CHECK(same(ben.root.view(), v.at("ratchet_root_5")));
    CHECK(ben.own_kem && ben.own_kem_id == 1U);
    advance_time(ben, 1'700'180'100U);
    CHECK(
        same(seal_vector(crypto, ben, ben_fp, "envelope_8", random_with(0xE3)),
             v.at("message_8")));
    advance_time(ana, 1'700'180'100U);
    opens_vector(crypto, ana, ana_fp, "message_7", "envelope_7");
    opens_vector(crypto, ana, ana_fp, "message_8", "envelope_8");
    CHECK(ana.peer_kem && ana.peer_kem_id == 1U);

    // Ana's answer holds a fresh encapsulation: Ben opens the vector's copy.
    advance_time(ana, 1'700'180'200U);
    {
        const Bytes own = seal_vector(crypto, ana, ana_fp, "envelope_9",
                                      random_with(0xF2, "ratchet_a_4"));
        RatchetState copy;
        copy.copy_from(ben);
        opens_to(crypto, copy, ben_fp, own, v.at("envelope_9"));
    }
    CHECK(ana.send_answers && !ana.peer_kem && !ana.own_kem);
    advance_time(ben, 1'700'180'200U);
    opens_vector(crypto, ben, ben_fp, "message_9", "envelope_9");
    CHECK(same(ben.root.view(), v.at("ratchet_root_6")));
    CHECK(!ben.own_kem && ben.quantum_steps == 0U);
}

// Two fresh sessions from the vector pairing.
struct Pair final {
    Fingerprints ana_fp;
    Fingerprints ben_fp;
    RatchetState ana;
    RatchetState ben;

    explicit Pair(const CryptoContext& crypto) {
        ana_fp = {fixed<kHashBytes>("fingerprint2_1"),
                  fixed<kHashBytes>("fingerprint2_2")};
        ben_fp = {ana_fp.peer, ana_fp.own};
        CHECK(start_ratchet(crypto, seed_for(crypto, PairingRole::Owner),
                            ana) == Status::Ok);
        CHECK(start_ratchet(crypto, seed_for(crypto, PairingRole::Scanner),
                            ben) == Status::Ok);
    }
};

Bytes text_envelope(const std::string& text) {
    Envelope envelope;
    envelope.kind = MessageKind::Text;
    envelope.id.fill(0x11U);
    envelope.payload.append(as_bytes(text));
    std::vector<Byte> bytes;
    Writer write(bytes);
    write_envelope(write, envelope);
    return bytes;
}

std::vector<Byte> seal_text(const CryptoContext& crypto, RatchetState& state,
                            const Fingerprints& fingerprints,
                            const std::string& text) {
    std::vector<Byte> item;
    CHECK(seal_message(crypto, state, fingerprints, text_envelope(text),
                       fresh(crypto), item) == Status::Ok);
    return item;
}

void test_header_refusals(const CryptoContext& crypto) {
    Pair pair(crypto);
    const std::vector<Byte> item =
        seal_text(crypto, pair.ben, pair.ben_fp, "hi");
    CHECK(item.size() == kSmallItemBytes);
    const auto mutated = [&](std::size_t offset, Byte value) {
        std::vector<Byte> copy = item;
        copy[offset] = value;
        return open_status(crypto, pair.ana, pair.ana_fp, copy);
    };
    CHECK(mutated(0U, 2U) == Status::Unsupported);
    CHECK(mutated(1U, 4U) == Status::Malformed);
    // A message number of 2^20 or more, and one that is merely wrong.
    CHECK(mutated(1U + 1U + 32U + 4U + 1U, 0x10U) == Status::Malformed);
    CHECK(mutated(1U + 1U + 32U + 4U + 3U, 1U) == Status::AuthenticationFailed);
    // Salt, ciphertext and tag are all authenticated.
    CHECK(mutated(50U, static_cast<Byte>(item[50] ^ 1U)) ==
          Status::AuthenticationFailed);
    CHECK(mutated(500U, static_cast<Byte>(item[500] ^ 1U)) ==
          Status::AuthenticationFailed);
    CHECK(mutated(item.size() - 1U,
                  static_cast<Byte>(item[item.size() - 1U] ^ 1U)) ==
          Status::AuthenticationFailed);
    // Only the three mailbox sizes.
    for (const std::size_t size :
         {std::size_t{0U}, std::size_t{58U}, std::size_t{1023U},
          std::size_t{1025U}, std::size_t{4096U}}) {
        std::vector<Byte> resized = item;
        resized.resize(size);
        const Status status =
            open_status(crypto, pair.ana, pair.ana_fp, resized);
        CHECK(size == 4096U ? status == Status::AuthenticationFailed
                            : status == Status::Malformed);
    }
    // The other direction's associated data differs.
    CHECK(open_status(crypto, pair.ana, pair.ben_fp, item) ==
          Status::AuthenticationFailed);
    SecretBytes plaintext;
    CHECK(open_message(crypto, pair.ana, pair.ana_fp, item, plaintext) ==
          Status::Ok);
}

void test_skip_bounds(const CryptoContext& crypto) {
    Pair pair(crypto);
    std::vector<std::vector<Byte>> chain;
    for (int index = 0; index < 1002; ++index) {
        chain.push_back(seal_text(crypto, pair.ben, pair.ben_fp, "m"));
    }
    // Message 1001 needs 1001 skipped keys in one chain.
    CHECK(open_status(crypto, pair.ana, pair.ana_fp, chain[1001]) ==
          Status::Capacity);
    SecretBytes plaintext;
    CHECK(open_message(crypto, pair.ana, pair.ana_fp, chain[1000], plaintext) ==
          Status::Ok);
    CHECK(pair.ana.skipped.size() == 1000U);
    // The kept keys open their messages in any order, once each.
    for (int index = 999; index >= 0; --index) {
        CHECK(open_message(crypto, pair.ana, pair.ana_fp,
                           chain[static_cast<std::size_t>(index)],
                           plaintext) == Status::Ok);
    }
    CHECK(pair.ana.skipped.empty());
    CHECK(open_status(crypto, pair.ana, pair.ana_fp, chain[7]) ==
          Status::AlreadySpent);
    CHECK(open_message(crypto, pair.ana, pair.ana_fp, chain[1001], plaintext) ==
          Status::Ok);

    // 2000 kept keys across chains, then one more is refused.
    std::vector<std::vector<Byte>> kept;
    for (int round = 0; round < 3; ++round) {
        // Ana answers, so Ben's next message starts a chain.
        const std::vector<Byte> answer =
            seal_text(crypto, pair.ana, pair.ana_fp, "a");
        CHECK(open_message(crypto, pair.ben, pair.ben_fp, answer, plaintext) ==
              Status::Ok);
        std::vector<std::vector<Byte>> next;
        for (int index = 0; index < 1001; ++index) {
            next.push_back(seal_text(crypto, pair.ben, pair.ben_fp, "m"));
        }
        if (round < 2) {
            CHECK(open_message(crypto, pair.ana, pair.ana_fp, next[1000],
                               plaintext) == Status::Ok);
            CHECK(pair.ana.skipped.size() ==
                  1000U * static_cast<std::size_t>(round + 1));
            kept.push_back(next[3]);
        } else {
            CHECK(open_status(crypto, pair.ana, pair.ana_fp, next[1000]) ==
                  Status::Capacity);
            CHECK(pair.ana.skipped.size() == kMaxSkippedKeys);
        }
    }
    // Kept keys expire after 30 days. A late message of the current or the
    // previous chain then reads as a repeat.
    advance_time(pair.ana, pair.ana.time + kSkippedKeyLifetime - 1U);
    CHECK(pair.ana.skipped.size() == kMaxSkippedKeys);
    advance_time(pair.ana, pair.ana.time + 1U);
    CHECK(pair.ana.skipped.empty());
    CHECK(open_status(crypto, pair.ana, pair.ana_fp, kept[1]) ==
          Status::AlreadySpent);
    CHECK(open_status(crypto, pair.ana, pair.ana_fp, kept[0]) ==
          Status::AlreadySpent);
    // A clock that moves back moves nothing.
    const std::uint64_t time = pair.ana.time;
    advance_time(pair.ana, time - 100U);
    CHECK(pair.ana.time == time);
}

void test_chain_full(const CryptoContext& crypto) {
    Pair pair(crypto);
    pair.ben.send_next = kMaxChainMessages - 1U;
    (void)seal_text(crypto, pair.ben, pair.ben_fp, "last");
    std::vector<Byte> item;
    CHECK(seal_message(crypto, pair.ben, pair.ben_fp, text_envelope("x"),
                       fresh(crypto), item) == Status::Capacity);
}

void test_post_quantum(const CryptoContext& crypto) {
    Pair pair(crypto);
    SecretBytes plaintext;
    const auto ben_to_ana = [&](const char* text) {
        const auto item = seal_text(crypto, pair.ben, pair.ben_fp, text);
        CHECK(open_message(crypto, pair.ana, pair.ana_fp, item, plaintext) ==
              Status::Ok);
    };
    const auto ana_to_ben = [&](const char* text) {
        const auto item = seal_text(crypto, pair.ana, pair.ana_fp, text);
        CHECK(open_message(crypto, pair.ben, pair.ben_fp, item, plaintext) ==
              Status::Ok);
    };
    // Each exchange is a root step on each side for each direction. Ben's
    // 20th step is the chain he starts in the eleventh exchange, so he
    // advertises there, and Ana's next chain answers.
    for (int exchange = 1; exchange <= 10; ++exchange) {
        ben_to_ana("b");
        ana_to_ben("a");
        CHECK(!pair.ben.own_kem && !pair.ana.own_kem);
    }
    CHECK(pair.ben.quantum_steps == 19U && pair.ana.quantum_steps == 19U);
    ben_to_ana("b");
    CHECK(pair.ben.own_kem && pair.ben.own_kem_id == 1U);
    CHECK(pair.ana.peer_kem && pair.ana.peer_kem_id == 1U);
    ana_to_ben("a");
    CHECK(pair.ana.answered_id == 1U && pair.ana.quantum_steps == 0U);
    CHECK(!pair.ben.own_kem && pair.ben.quantum_steps == 0U);
    CHECK(!pair.ana.own_kem);

    // A chain that answers a key the receiver does not hold is refused.
    ben_to_ana("b");
    pair.ana.quantum_steps = kPostQuantumSteps;
    const auto advert = seal_text(crypto, pair.ana, pair.ana_fp, "advert");
    CHECK(pair.ana.own_kem && pair.ana.own_kem_id == 1U);
    CHECK(open_message(crypto, pair.ben, pair.ben_fp, advert, plaintext) ==
          Status::Ok);
    const auto answer = seal_text(crypto, pair.ben, pair.ben_fp, "answer");
    CHECK(pair.ben.send_answers && !pair.ben.peer_kem);
    RatchetState wrong;
    wrong.copy_from(pair.ana);
    ++wrong.own_kem_id;
    SecretBytes ignored;
    CHECK(open_message(crypto, wrong, pair.ana_fp, answer, ignored) ==
          Status::AuthenticationFailed);
    CHECK(open_message(crypto, pair.ana, pair.ana_fp, answer, plaintext) ==
          Status::Ok);
    CHECK(!pair.ana.own_kem && pair.ana.quantum_steps == 0U);

    // A day without a step is due too, in the middle of a chain, and the
    // chain that already answers a key then also advertises one.
    CHECK(pair.ben.sending && pair.ben.send_answers && !pair.ben.own_kem);
    advance_time(pair.ben, pair.ben.time + kPostQuantumSeconds);
    const auto both = seal_text(crypto, pair.ben, pair.ben_fp, "late");
    CHECK(pair.ben.own_kem && pair.ben.send_answers);
    CHECK(both.size() == kMediumItemBytes);
    CHECK(open_message(crypto, pair.ana, pair.ana_fp, both, plaintext) ==
          Status::Ok);
    CHECK(pair.ana.peer_kem);
}

void test_snapshot_refusals(const CryptoContext& crypto) {
    const Bytes good = v.at("session_ben");
    SessionState state;
    const auto refused = [&](Bytes bytes) {
        return decode_session(crypto, bytes, state) == Status::CorruptState;
    };
    CHECK(decode_session(crypto, good, state) == Status::Ok);
    CHECK(refused(Bytes(good.begin(), good.end() - 1)));
    Bytes longer = good;
    longer.push_back(0U);
    CHECK(refused(longer));
    // The clock is older than the last post-quantum step.
    constexpr std::size_t kTime = 23U + 32U + 32U + 32U;
    Bytes clock = good;
    std::fill_n(clock.begin() + kTime, 8, 0U);
    CHECK(refused(clock));
    // The advertised key was already answered.
    constexpr std::size_t kAnswered = kTime + 8U + 8U + 4U + 32U + 32U + 1U +
                                      4U + 1U + 48U + 4U + 1U + 4U + 1U;
    CHECK(good[kAnswered + 4U] == 1U);
    Bytes answered = good;
    answered[kAnswered + 3U] = 1U;
    CHECK(refused(answered));
    // An outbox entry carries no Resent flag.
    const std::size_t envelope = good.size() - 16U - v.at("envelope_2").size();
    Bytes resent = good;
    resent[envelope + 1U + 16U + 8U] = kEnvelopeResent;
    CHECK(refused(resent));
    // Kept keys are in ascending order.
    SessionState keys;
    CHECK(decode_session(crypto, good, keys) == Status::Ok);
    const auto encoded = [](const SessionState& session) {
        const SecretBytes bytes = encode_session(session);
        return Bytes(bytes.view().begin(), bytes.view().end());
    };
    keys.ratchet.skipped.resize(2U);
    keys.ratchet.skipped[0].number = 5U;
    keys.ratchet.skipped[1].number = 4U;
    CHECK(refused(encoded(keys)));
    keys.ratchet.skipped[1].number = 6U;
    CHECK(decode_session(crypto, encoded(keys), state) == Status::Ok);
    // Outbox IDs are distinct.
    SessionState twice;
    CHECK(decode_session(crypto, good, twice) == Status::Ok);
    twice.outbox.resize(2U);
    twice.outbox[1].copy_from(twice.outbox[0]);
    CHECK(refused(encoded(twice)));
}

// Every list at its bound and every field at its longest is exactly the
// computed bound, under the identity snapshot's 1 MiB.
void test_largest_snapshot(const CryptoContext& crypto) {
    SessionState state;
    CHECK(decode_session(crypto, v.at("session_ben"), state) == Status::Ok);
    RatchetState& ratchet = state.ratchet;
    ratchet.sending = true;
    ratchet.send_answers = true;
    ratchet.answered_id = 7U;
    ratchet.send_answer_id = 7U;
    ratchet.has_previous = true;
    ratchet.own_kem = true;
    ratchet.own_kem_id = 3U;
    ratchet.peer_kem_id = 8U;
    ratchet.skipped.resize(kMaxSkippedKeys);
    for (std::size_t index = 0U; index < kMaxSkippedKeys; ++index) {
        ratchet.skipped[index].number = static_cast<std::uint32_t>(index);
    }
    const std::string text(kMaxTextBytes, 'a');
    state.outbox.resize(kMaxOutbox);
    for (std::size_t index = 0U; index < kMaxOutbox; ++index) {
        Envelope& envelope = state.outbox[index].envelope;
        envelope.kind = MessageKind::Text;
        envelope.id.fill(static_cast<Byte>(index));
        envelope.payload.clear();
        envelope.payload.append(as_bytes(text));
    }
    const SecretBytes encoded = encode_session(state);
    std::printf("largest session snapshot: %zu bytes of %zu\n", encoded.size(),
                kMaxSnapshotBytes);
    CHECK(encoded.size() == max_session_bytes());
    CHECK(encoded.size() <= kMaxSnapshotBytes);
    SessionState decoded;
    CHECK(decode_session(crypto, encoded.view(), decoded) == Status::Ok);
    CHECK(same(encode_session(decoded).view(),
               Bytes(encoded.view().begin(), encoded.view().end())));
}

// A long conversation with reordering, delays and clock jumps. Every message
// opens once to its own text.
void test_random_conversation(const CryptoContext& crypto) {
    Pair pair(crypto);
    std::mt19937 random(20261112U);
    struct InFlight {
        bool to_ana;
        std::vector<Byte> item;
        std::string text;
    };
    std::vector<InFlight> flight;
    std::uint64_t time = kAnaPaired;
    std::size_t delivered = 0U;
    std::size_t quantum_steps = 0U;
    for (int round = 0; round < 400; ++round) {
        time += (random() % 50U == 0U) ? kPostQuantumSeconds : random() % 600U;
        advance_time(pair.ana, time);
        advance_time(pair.ben, time);
        const bool from_ben = random() % 2U == 0U;
        RatchetState& sender = from_ben ? pair.ben : pair.ana;
        const Fingerprints& fingerprints = from_ben ? pair.ben_fp : pair.ana_fp;
        const std::size_t count = 1U + random() % 3U;
        for (std::size_t index = 0U; index < count; ++index) {
            const std::string text =
                "r" + std::to_string(round) + "." + std::to_string(index);
            flight.push_back({from_ben,
                              seal_text(crypto, sender, fingerprints, text),
                              text});
            // The first message of a chain that answers a key.
            if (sender.send_next == 1U && sender.send_answers) ++quantum_steps;
        }
        // Deliver some of what is in flight, in random order.
        std::shuffle(flight.begin(), flight.end(), random);
        const std::size_t deliver = flight.size() - flight.size() / 3U;
        for (std::size_t index = 0U; index < deliver; ++index) {
            InFlight& message = flight[index];
            RatchetState& receiver = message.to_ana ? pair.ana : pair.ben;
            const Fingerprints& own =
                message.to_ana ? pair.ana_fp : pair.ben_fp;
            opens_to(crypto, receiver, own, message.item,
                     text_envelope(message.text));
            ++delivered;
        }
        flight.erase(flight.begin(),
                     flight.begin() + static_cast<std::ptrdiff_t>(deliver));
    }
    for (InFlight& message : flight) {
        RatchetState& receiver = message.to_ana ? pair.ana : pair.ben;
        const Fingerprints& own = message.to_ana ? pair.ana_fp : pair.ben_fp;
        opens_to(crypto, receiver, own, message.item,
                 text_envelope(message.text));
        ++delivered;
    }
    std::printf("random conversation: %zu messages, %zu post-quantum chains\n",
                delivered, quantum_steps);
    CHECK(quantum_steps >= 5U);
    CHECK(pair.ana.skipped.empty() && pair.ben.skipped.empty());
}

}  // namespace

int main() {
    v = testing::load_vectors(ITO_CALL_VECTORS);
    const CryptoContext crypto;
    test_vectors(crypto);
    test_header_refusals(crypto);
    test_skip_bounds(crypto);
    test_chain_full(crypto);
    test_post_quantum(crypto);
    test_snapshot_refusals(crypto);
    test_largest_snapshot(crypto);
    test_random_conversation(crypto);
    std::printf("ratchet_test passed\n");
    return 0;
}
