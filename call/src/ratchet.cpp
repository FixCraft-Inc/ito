/* Copyright (C) 2026 FixCraft Inc. AGPL-3.0-or-later. */

#include "ratchet.hpp"

#include <algorithm>
#include <iterator>
#include <limits>

namespace ito::call {
namespace {

struct MessageHeader final {
    std::uint8_t flags{0U};
    Key ratchet{};
    std::uint32_t previous{0U};
    std::uint32_t number{0U};
    Salt salt{};
    std::uint32_t advert_id{0U};
    MlKemPublicKey advert{};
    std::uint32_t answer_id{0U};
    MlKemCiphertext ciphertext{};

    [[nodiscard]] bool advertises() const noexcept {
        return (flags & kHeaderAdvertises) != 0U;
    }
    [[nodiscard]] bool answers() const noexcept {
        return (flags & kHeaderAnswers) != 0U;
    }
};

void write_header(Writer& write, const MessageHeader& header) {
    write.u8(kMessageVersion);
    write.u8(header.flags);
    write.bytes(header.ratchet);
    write.u32(header.previous);
    write.u32(header.number);
    write.bytes(header.salt);
    if (header.advertises()) {
        write.u32(header.advert_id);
        write.bytes(header.advert);
    }
    if (header.answers()) {
        write.u32(header.answer_id);
        write.bytes(header.ciphertext);
    }
}

[[nodiscard]] Status read_header(Reader& in, MessageHeader& header) {
    std::uint8_t version = 0U;
    if (!in.u8(version)) return Status::Malformed;
    if (version != kMessageVersion) return Status::Unsupported;
    if (!in.u8(header.flags) ||
        (header.flags & ~(kHeaderAdvertises | kHeaderAnswers)) != 0U ||
        !in.fixed(header.ratchet) || !in.u32(header.previous) ||
        !in.u32(header.number) || !in.fixed(header.salt)) {
        return Status::Malformed;
    }
    // Key IDs count from 1, so 0 names no key.
    if (header.advertises() &&
        (!in.u32(header.advert_id) || header.advert_id == 0U ||
         !in.fixed(header.advert))) {
        return Status::Malformed;
    }
    if (header.answers() &&
        (!in.u32(header.answer_id) || header.answer_id == 0U ||
         !in.fixed(header.ciphertext))) {
        return Status::Malformed;
    }
    if (header.previous >= kMaxChainMessages ||
        header.number >= kMaxChainMessages) {
        return Status::Malformed;
    }
    return Status::Ok;
}

// HKDF-Extract with the root key as salt over the X25519 secret, a flag
// byte and the ML-KEM secret when there is one, then 80 bytes of expansion:
// the next root key and a chain key.
void root_step(const CryptoContext& crypto, Secret32& root,
               const Secret32& shared, const Secret32* encapsulated,
               ChainKey& chain) {
    SecretArray<2U * kSharedSecretBytes + 1U> input;
    std::copy_n(shared.data(), kSharedSecretBytes, input.data());
    std::size_t size = kSharedSecretBytes + 1U;
    input.data()[kSharedSecretBytes] = encapsulated != nullptr ? 1U : 0U;
    if (encapsulated != nullptr) {
        std::copy_n(encapsulated->data(), kSharedSecretBytes,
                    input.data() + size);
        size += kSharedSecretBytes;
    }
    Prk prk;
    crypto.hkdf_extract(root.view(), ByteView(input.data(), size), prk);
    SecretArray<32U + kChainKeyBytes> output;
    const std::array<ByteView, 1> info{as_bytes(kRatchetRootLabel)};
    crypto.hkdf_expand(prk.view(), info,
                       std::span<Byte>(output.data(), output.size()));
    root.assign(output.view().first<32U>());
    chain.assign(output.view().subspan<32U, kChainKeyBytes>());
}

// HMAC-SHA-384 of the chain key with byte 1 is the message key, with byte 2
// the next chain key.
void chain_step(const CryptoContext& crypto, ChainKey& chain,
                MessageKey& message) {
    static constexpr std::array<Byte, 1> kMessageByte{1U};
    static constexpr std::array<Byte, 1> kChainByte{2U};
    crypto.hmac_sha384(
        chain.view(), kMessageByte,
        std::span<Byte, kChainKeyBytes>(message.data(), kChainKeyBytes));
    ChainKey next;
    crypto.hmac_sha384(
        chain.view(), kChainByte,
        std::span<Byte, kChainKeyBytes>(next.data(), kChainKeyBytes));
    chain = std::move(next);
}

struct KeyNonce final {
    SecretArray<kAeadKeyBytes> key;
    Nonce nonce{};
};

// The message key, extracted with the header's salt, expands to the
// AES-256-GCM key and nonce. The salt keeps a session restored from an old
// snapshot from repeating a key and nonce on different text.
[[nodiscard]] KeyNonce message_aead(const CryptoContext& crypto,
                                    const MessageKey& message,
                                    const Salt& salt) {
    Prk prk;
    crypto.hkdf_extract(salt, message.view(), prk);
    SecretArray<kAeadKeyBytes + kAeadNonceBytes> material;
    const std::array<ByteView, 1> info{as_bytes(kMessageKeyLabel)};
    crypto.hkdf_expand(prk.view(), info,
                       std::span<Byte>(material.data(), material.size()));
    KeyNonce result;
    result.key.assign(material.view().first<kAeadKeyBytes>());
    std::copy_n(material.data() + kAeadKeyBytes, kAeadNonceBytes,
                result.nonce.begin());
    return result;
}

[[nodiscard]] std::vector<Byte> associated_data(const Hash& sender,
                                                const Hash& recipient,
                                                ByteView header) {
    std::vector<Byte> out;
    out.reserve(kMessageDataLabel.size() + 2U * kHashBytes + header.size());
    Writer write(out);
    write.text(kMessageDataLabel);
    write.bytes(sender);
    write.bytes(recipient);
    write.bytes(header);
    return out;
}

[[nodiscard]] bool skipped_less(const SkippedKey& key, const Key& ratchet,
                                std::uint32_t number) noexcept {
    if (key.ratchet != ratchet) {
        return std::lexicographical_compare(key.ratchet.begin(),
                                            key.ratchet.end(), ratchet.begin(),
                                            ratchet.end());
    }
    return key.number < number;
}

[[nodiscard]] std::vector<SkippedKey>::iterator find_skipped(
    std::vector<SkippedKey>& skipped, const Key& ratchet,
    std::uint32_t number) {
    const auto found =
        std::lower_bound(skipped.begin(), skipped.end(), ratchet,
                         [&](const SkippedKey& key, const Key& wanted) {
                             return skipped_less(key, wanted, number);
                         });
    return found != skipped.end() && found->ratchet == ratchet &&
                   found->number == number
               ? found
               : skipped.end();
}

// Keeps the keys of a receiving chain's messages from next up to until, so
// they can still arrive. Every key the chain had before next is already
// used or kept, so the new ones go right after them.
[[nodiscard]] Status skip(const CryptoContext& crypto, RatchetState& state,
                          const Key& ratchet, ChainKey& chain,
                          std::uint32_t& next, std::uint32_t until) {
    const std::size_t count = until - next;
    if (count > kMaxSkipPerChain ||
        count > kMaxSkippedKeys - state.skipped.size()) {
        return Status::Capacity;
    }
    std::vector<SkippedKey> added(count);
    for (SkippedKey& key : added) {
        key.ratchet = ratchet;
        key.number = next++;
        key.stored_at = state.time;
        chain_step(crypto, chain, key.key);
    }
    const auto position = std::lower_bound(
        state.skipped.begin(), state.skipped.end(), ratchet,
        [&](const SkippedKey& key, const Key& wanted) {
            return skipped_less(key, wanted,
                                std::numeric_limits<std::uint32_t>::max());
        });
    state.skipped.insert(position, std::make_move_iterator(added.begin()),
                         std::make_move_iterator(added.end()));
    return Status::Ok;
}

void count_step(RatchetState& state, bool quantum) noexcept {
    if (quantum) {
        state.quantum_steps = 0U;
        state.quantum_time = state.time;
    } else if (state.quantum_steps <
               std::numeric_limits<std::uint32_t>::max()) {
        ++state.quantum_steps;
    }
}

[[nodiscard]] bool quantum_due(const RatchetState& state) noexcept {
    return state.quantum_steps >= kPostQuantumSteps ||
           state.time - state.quantum_time >= kPostQuantumSeconds;
}

// The contact changed direction: the current receiving chain ends at the
// header's previous length, a root step starts the new receiving chain, and
// the next message we seal starts a new sending chain.
[[nodiscard]] Status turn(const CryptoContext& crypto, RatchetState& state,
                          const MessageHeader& header) {
    if (state.receiving) {
        if (header.previous < state.receive_next) {
            return Status::AuthenticationFailed;
        }
        const Status skipped =
            skip(crypto, state, state.peer_ratchet, state.receive_key,
                 state.receive_next, header.previous);
        if (skipped != Status::Ok) return skipped;
        state.has_previous = true;
        state.previous_ratchet = state.peer_ratchet;
        state.previous_next = state.receive_next;
    }
    Secret32 encapsulated;
    const Secret32* quantum = nullptr;
    if (header.answers()) {
        // Only the key this side advertised and still holds can be answered.
        if (!state.own_kem || header.answer_id != state.own_kem_id) {
            return Status::AuthenticationFailed;
        }
        crypto.ml_kem_decapsulate(state.own_kem_seed, header.ciphertext,
                                  encapsulated);
        quantum = &encapsulated;
    }
    Secret32 shared;
    if (!crypto.x25519_agree(state.own_ratchet, header.ratchet, shared)) {
        return Status::AuthenticationFailed;
    }
    root_step(crypto, state.root, shared, quantum, state.receive_key);
    state.receiving = true;
    state.receive_next = 0U;
    state.peer_ratchet = header.ratchet;
    if (state.sending) {
        state.last_length = state.send_next;
        state.sending = false;
        state.send_answers = false;
    }
    if (quantum != nullptr) {
        // Each decapsulation key opens one chain and is then forgotten.
        state.own_kem = false;
        wipe(state.own_kem_seed.data(), state.own_kem_seed.size());
    }
    count_step(state, quantum != nullptr);
    return Status::Ok;
}

[[nodiscard]] Status receive_key(const CryptoContext& crypto,
                                 RatchetState& state,
                                 const MessageHeader& header, MessageKey& key) {
    const auto kept =
        find_skipped(state.skipped, header.ratchet, header.number);
    if (kept != state.skipped.end()) {
        key = std::move(kept->key);
        state.skipped.erase(kept);
        return Status::Ok;
    }
    const bool current =
        state.receiving && header.ratchet == state.peer_ratchet;
    if (current && header.number < state.receive_next) {
        return Status::AlreadySpent;
    }
    if (!current && state.has_previous &&
        header.ratchet == state.previous_ratchet) {
        // That chain's keys were all used or kept when it ended.
        return header.number < state.previous_next
                   ? Status::AlreadySpent
                   : Status::AuthenticationFailed;
    }
    if (!current) {
        const Status turned = turn(crypto, state, header);
        if (turned != Status::Ok) return turned;
    }
    const Status skipped =
        skip(crypto, state, state.peer_ratchet, state.receive_key,
             state.receive_next, header.number);
    if (skipped != Status::Ok) return skipped;
    chain_step(crypto, state.receive_key, key);
    state.receive_next = header.number + 1U;
    return Status::Ok;
}

// The first message after a turn starts a sending chain with a new ratchet
// key, and answers the contact's advertised ML-KEM key if there is one.
[[nodiscard]] Status start_sending(const CryptoContext& crypto,
                                   RatchetState& state,
                                   const MessageRandom& random) {
    Secret32 shared;
    // The contact's key gave a secret when it arrived, so a fresh key does.
    if (!crypto.x25519_agree(random.ratchet, state.peer_ratchet, shared)) {
        return Status::Internal;
    }
    Secret32 encapsulated;
    const Secret32* quantum = nullptr;
    state.send_answers = false;
    if (state.peer_kem) {
        // The key passed FIPS 203's check when it arrived.
        if (!crypto.ml_kem_encapsulate(state.peer_kem_key,
                                       state.send_ciphertext, encapsulated)) {
            return Status::Internal;
        }
        quantum = &encapsulated;
        state.send_answers = true;
        state.send_answer_id = state.peer_kem_id;
        state.answered_id = state.peer_kem_id;
        state.peer_kem = false;
    }
    root_step(crypto, state.root, shared, quantum, state.send_key);
    state.own_ratchet.assign(random.ratchet.view());
    state.sending = true;
    state.send_previous = state.last_length;
    state.send_next = 0U;
    count_step(state, quantum != nullptr);
    return Status::Ok;
}

}  // namespace

void SkippedKey::copy_from(const SkippedKey& other) {
    ratchet = other.ratchet;
    number = other.number;
    key.assign(other.key.view());
    stored_at = other.stored_at;
}

void RatchetState::copy_from(const RatchetState& other) {
    root.assign(other.root.view());
    time = other.time;
    quantum_time = other.quantum_time;
    quantum_steps = other.quantum_steps;
    own_ratchet.assign(other.own_ratchet.view());
    peer_ratchet = other.peer_ratchet;
    sending = other.sending;
    send_key.assign(other.send_key.view());
    send_next = other.send_next;
    send_previous = other.send_previous;
    last_length = other.last_length;
    send_answers = other.send_answers;
    send_answer_id = other.send_answer_id;
    send_ciphertext = other.send_ciphertext;
    receiving = other.receiving;
    receive_key.assign(other.receive_key.view());
    receive_next = other.receive_next;
    has_previous = other.has_previous;
    previous_ratchet = other.previous_ratchet;
    previous_next = other.previous_next;
    own_kem_id = other.own_kem_id;
    own_kem = other.own_kem;
    own_kem_seed.assign(other.own_kem_seed.view());
    answered_id = other.answered_id;
    peer_kem = other.peer_kem;
    peer_kem_id = other.peer_kem_id;
    peer_kem_key = other.peer_kem_key;
    skipped.clear();
    skipped.resize(other.skipped.size());
    for (std::size_t index = 0U; index < skipped.size(); ++index) {
        skipped[index].copy_from(other.skipped[index]);
    }
}

Status start_ratchet(const CryptoContext& crypto, const SessionSeed& seed,
                     RatchetState& out) {
    Secret32 shared;
    if (!crypto.x25519_agree(seed.own_ratchet, seed.peer_ratchet, shared)) {
        return Status::Malformed;
    }
    out.root.assign(seed.root.view());
    out.time = seed.paired_at;
    out.quantum_time = seed.paired_at;
    out.quantum_steps = 0U;
    out.own_ratchet.assign(seed.own_ratchet.view());
    out.peer_ratchet = seed.peer_ratchet;
    if (seed.role == PairingRole::Scanner) {
        // The scanner's first chain is the Double Ratchet's first sending
        // chain, under the owner's first ratchet key.
        root_step(crypto, out.root, shared, nullptr, out.send_key);
        out.sending = true;
    } else {
        // The confirm gave the owner the scanner's first ratchet key, so the
        // owner takes the receiving step at once and may send first too.
        root_step(crypto, out.root, shared, nullptr, out.receive_key);
        out.receiving = true;
    }
    return Status::Ok;
}

void advance_time(RatchetState& state, std::uint64_t now) {
    state.time = std::max(state.time, now);
    std::erase_if(state.skipped, [&](const SkippedKey& key) {
        return state.time - key.stored_at >= kSkippedKeyLifetime;
    });
}

std::size_t item_size_for(std::size_t header, std::size_t envelope) noexcept {
    const std::size_t needed = header + envelope + kAeadTagBytes;
    for (const std::size_t size :
         {kSmallItemBytes, kMediumItemBytes, kLargeItemBytes}) {
        if (needed <= size) return size;
    }
    return 0U;
}

Status seal_message(const CryptoContext& crypto, RatchetState& state,
                    const Fingerprints& fingerprints, ByteView envelope,
                    const MessageRandom& random, std::vector<Byte>& item) {
    if (state.sending && state.send_next >= kMaxChainMessages) {
        return Status::Capacity;
    }
    if (!state.sending) {
        const Status started = start_sending(crypto, state, random);
        if (started != Status::Ok) return started;
    }
    if (!state.own_kem && quantum_due(state) &&
        state.own_kem_id < std::numeric_limits<std::uint32_t>::max()) {
        ++state.own_kem_id;
        state.own_kem = true;
        state.own_kem_seed.assign(random.kem.view());
    }
    MessageHeader header;
    header.flags =
        static_cast<std::uint8_t>((state.own_kem ? kHeaderAdvertises : 0U) |
                                  (state.send_answers ? kHeaderAnswers : 0U));
    header.ratchet = crypto.x25519_public_key(state.own_ratchet);
    header.previous = state.send_previous;
    header.number = state.send_next;
    header.salt = random.salt;
    if (state.own_kem) {
        header.advert_id = state.own_kem_id;
        header.advert = crypto.ml_kem_public_key(state.own_kem_seed);
    }
    if (state.send_answers) {
        header.answer_id = state.send_answer_id;
        header.ciphertext = state.send_ciphertext;
    }
    std::vector<Byte> header_bytes;
    header_bytes.reserve(kMaxHeaderBytes);
    Writer write(header_bytes);
    write_header(write, header);
    const std::size_t size =
        item_size_for(header_bytes.size(), envelope.size());
    if (size == 0U) return Status::InvalidArgument;

    MessageKey key;
    chain_step(crypto, state.send_key, key);
    ++state.send_next;
    std::vector<Byte> plaintext(size - header_bytes.size() - kAeadTagBytes, 0U);
    const WipeOnExit wiped(plaintext);
    std::copy(envelope.begin(), envelope.end(), plaintext.begin());
    const KeyNonce aead = message_aead(crypto, key, header.salt);
    const std::vector<Byte> aad =
        associated_data(fingerprints.own, fingerprints.peer, header_bytes);
    item.assign(size, 0U);
    std::copy(header_bytes.begin(), header_bytes.end(), item.begin());
    crypto.seal(aead.key.view(), aead.nonce, aad, plaintext,
                std::span<Byte>(item).subspan(header_bytes.size()));
    return Status::Ok;
}

Status open_message(const CryptoContext& crypto, RatchetState& state,
                    const Fingerprints& fingerprints, ByteView item,
                    SecretBytes& plaintext) {
    if (item.size() != kSmallItemBytes && item.size() != kMediumItemBytes &&
        item.size() != kLargeItemBytes) {
        return Status::Malformed;
    }
    Reader in(item);
    MessageHeader header;
    const Status parsed = read_header(in, header);
    if (parsed != Status::Ok) return parsed;
    const std::size_t header_size = in.consumed();
    if (item.size() - header_size <= kAeadTagBytes) return Status::Malformed;

    MessageKey key;
    const Status found = receive_key(crypto, state, header, key);
    if (found != Status::Ok) return found;
    const KeyNonce aead = message_aead(crypto, key, header.salt);
    const std::vector<Byte> aad = associated_data(
        fingerprints.peer, fingerprints.own, item.first(header_size));
    std::vector<Byte> buffer(item.size() - header_size - kAeadTagBytes);
    const WipeOnExit wiped(buffer);
    if (!crypto.open(aead.key.view(), aead.nonce, aad,
                     item.subspan(header_size), buffer)) {
        return Status::AuthenticationFailed;
    }
    // A newer advertised key replaces an older one that no chain answered.
    if (header.advertises() && header.advert_id > state.answered_id &&
        (!state.peer_kem || header.advert_id > state.peer_kem_id)) {
        if (!crypto.ml_kem_key_usable(header.advert)) return Status::Malformed;
        state.peer_kem = true;
        state.peer_kem_id = header.advert_id;
        state.peer_kem_key = header.advert;
    }
    plaintext.clear();
    plaintext.reserve(buffer.size());
    plaintext.append(buffer);
    return Status::Ok;
}

}  // namespace ito::call
