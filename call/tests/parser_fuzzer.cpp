/* Copyright (C) 2026 FixCraft Inc. AGPL-3.0-or-later. */

// libFuzzer entry for the core's peer-facing parsers. The first byte selects
// the parser and the rest is its input. Build with ITO_CALL_FUZZERS=ON and
// Clang, which instruments the parsers as well as this file.

#include <cstddef>
#include <cstdint>
#include <string>

#include "codec.hpp"
#include "envelope.hpp"
#include "ratchet.hpp"
#include "session.hpp"
#include "store.hpp"

using namespace ito::call;

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data,
                                      std::size_t size) {
    if (size == 0U) return 0;
    const ByteView input(data + 1, size - 1U);
    switch (data[0] % 8U) {
        case 0: {
            Invitation invitation;
            (void)parse_invitation(input, invitation);
            break;
        }
        case 1: {
            Key key{};
            (void)parse_contact_code(std::string(input.begin(), input.end()),
                                     key);
            break;
        }
        case 2: {
            RelayReply reply;
            std::size_t consumed = 0U;
            (void)parse_relay_reply(input, reply, consumed);
            break;
        }
        case 3: {
            FrameAssembler assembler;
            std::size_t offset = 0U;
            while (offset < input.size() && !assembler.malformed()) {
                const std::size_t taken = assembler.feed(input.subspan(offset));
                if (assembler.frame()) assembler.take();
                if (taken == 0U) break;
                offset += taken;
            }
            break;
        }
        case 4: {
            static const CryptoContext crypto;
            StoreState state;
            (void)decode_snapshot(crypto, input, state);
            break;
        }
        case 5: {
            Envelope envelope;
            (void)read_envelope(input, envelope);
            break;
        }
        case 6: {
            static const CryptoContext crypto;
            SessionState state;
            (void)decode_session(crypto, input, state);
            break;
        }
        default: {
            // A fixed owner's first state: every input is a message to it.
            static const CryptoContext crypto;
            static const RatchetState start = [] {
                SessionSeed seed;
                Secret32 scanner;
                for (std::size_t index = 0U; index < 32U; ++index) {
                    seed.own_ratchet.data()[index] = 1U;
                    scanner.data()[index] = 2U;
                }
                seed.peer_ratchet = crypto.x25519_public_key(scanner);
                RatchetState state;
                (void)start_ratchet(crypto, seed, state);
                return state;
            }();
            RatchetState state;
            state.copy_from(start);
            SecretBytes plaintext;
            (void)open_message(crypto, state, Fingerprints{}, input, plaintext);
            break;
        }
    }
    return 0;
}
