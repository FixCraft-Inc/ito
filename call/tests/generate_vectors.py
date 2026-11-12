#!/usr/bin/env python3
# Copyright (C) 2026 FixCraft Inc. AGPL-3.0-or-later.
"""Writes tests/vectors.txt: fixed vectors for docs/CALL_SECURITY.md and
for identity 2 and pairing in docs/MESSAGE_SECURITY.md.

An independent implementation of the byte layouts, written from the
contracts' tables with Python's hashlib and hmac and the `cryptography`
package's Ed25519, ML-DSA-87, X25519, ML-KEM-1024 and AES-GCM, so the C++
codec is checked against a second writer rather than against itself. HKDF is
written out here from RFC 5869. ML-DSA signing and ML-KEM encapsulation are
randomized, so a rerun changes the hello, reply and their transcripts, and
the C++ tests read rather than rebuild those. Each line is `name hex`. Rerun
only for a deliberate contract or vector correction, and review the changed
bytes.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import struct
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA87PrivateKey
from cryptography.hazmat.primitives.asymmetric.mlkem import MLKEM1024PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import (X25519PrivateKey,
                                                              X25519PublicKey)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

# RFC 8032 section 7.1, TEST 1 and TEST 2 secret keys. Published test data.
SEED_1 = bytes.fromhex('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60')
SEED_2 = bytes.fromhex('4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb')


def public(seed: bytes) -> bytes:
    return Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(
        Encoding.Raw, PublicFormat.Raw)


def sign(seed: bytes, message: bytes) -> bytes:
    return Ed25519PrivateKey.from_private_bytes(seed).sign(message)


def sha256(*parts: bytes) -> bytes:
    digest = hashlib.sha256()
    for part in parts:
        digest.update(part)
    return digest.digest()


def u16(value: int) -> bytes:
    return struct.pack('>H', value)


def u32(value: int) -> bytes:
    return struct.pack('>I', value)


def u64(value: int) -> bytes:
    return struct.pack('>Q', value)


def filled(byte: int, size: int = 32) -> bytes:
    return bytes([byte]) * size


def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    return hmac.new(salt, ikm, hashlib.sha384).digest()


def hkdf_expand(prk: bytes, info: bytes, size: int) -> bytes:
    output, block, counter = b'', b'', 1
    while len(output) < size:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha384).digest()
        output += block
        counter += 1
    return output[:size]


def label(text: str) -> bytes:
    """A contract label: its ASCII text and one zero byte."""
    return text.encode() + b'\0'


def ml_dsa_public(seed: bytes) -> bytes:
    return MLDSA87PrivateKey.from_seed_bytes(seed).public_key().public_bytes_raw()


def x25519_public(private: bytes) -> bytes:
    return X25519PrivateKey.from_private_bytes(private).public_key().public_bytes(
        Encoding.Raw, PublicFormat.Raw)


def x25519(private: bytes, peer: bytes) -> bytes:
    return X25519PrivateKey.from_private_bytes(private).exchange(
        X25519PublicKey.from_public_bytes(peer))


def fingerprint2(ed_public: bytes, ml_dsa_public_key: bytes) -> bytes:
    return sha256(label('ito/contact-identity/2'), ed_public, ml_dsa_public_key)


def composite_sign(ed_seed: bytes, ml_dsa_seed: bytes, signer: bytes, domain: str,
                   *body: bytes) -> bytes:
    message = label(domain) + signer + b''.join(body)
    return (Ed25519PrivateKey.from_private_bytes(ed_seed).sign(message) +
            MLDSA87PrivateKey.from_seed_bytes(ml_dsa_seed).sign(message))


def digits(number: bytes, count: int) -> bytes:
    """The lowest count decimal digits of a big-endian number."""
    return str(int.from_bytes(number, 'big') % 10 ** count).zfill(count).encode()


def authority(server: bytes, service: bytes) -> bytes:
    return server + bytes([len(service)]) + service


def name_field(name: bytes) -> bytes:
    return bytes([len(name)]) + name


def mailbox_address(secret: bytes) -> bytes:
    return sha256(label('ito/mailbox-address/1'), secret)


def seal(key_nonce: bytes, aad: bytes, plaintext: bytes) -> bytes:
    return AESGCM(key_nonce[:32]).encrypt(key_nonce[32:44], plaintext, aad)


def padded(plaintext: bytes, size: int) -> bytes:
    assert len(plaintext) <= size
    return plaintext + bytes(size - len(plaintext))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path,
                        default=Path(__file__).resolve().parent / 'vectors.txt')
    out = parser.parse_args().output

    vectors: list[tuple[str, bytes]] = []
    pub_1, pub_2 = public(SEED_1), public(SEED_2)
    vectors += [('seed_1', SEED_1), ('public_1', pub_1),
                ('seed_2', SEED_2), ('public_2', pub_2)]

    code = 'ito-contact:1:' + base64.urlsafe_b64encode(pub_1).decode().rstrip('=')
    vectors.append(('contact_code_1', code.encode()))
    vectors.append(('fingerprint_1', sha256(b'ito/contact-identity/1\0', pub_1)))

    # An invitation from identity 1 to identity 2.
    invitation_id, room, relay, token, psk = (filled(0x01), filled(0x02),
                                              filled(0x03), filled(0x04),
                                              filled(0x05))
    service = b'ito-call'
    issued, expires = 1_700_000_000, 1_700_000_300
    body = (b'ito/invitation/1\0' + invitation_id + room + pub_1 + pub_2 + relay +
            u16(len(service)) + service + token + u64(issued) + u64(expires) +
            u16(1) + psk)
    invitation = body + sign(SEED_1, body)
    invitation_hash = sha256(invitation)
    vectors += [('invitation_id', invitation_id), ('room', room), ('relay', relay),
                ('token', token), ('psk', psk), ('service', service),
                ('issued', u64(issued)), ('expires', u64(expires)),
                ('invitation_1', invitation), ('invitation_hash_1', invitation_hash)]

    offer = select = u16(1)
    context = sha256(b'ito/call-context/1\0', invitation_hash, room, pub_1, pub_2, relay,
                     u16(len(service)), service, offer, select)
    exporter = filled(0x11)
    auth_1 = b'ito/call-auth/1\0' + bytes([1]) + exporter + context
    auth_2 = b'ito/call-auth/1\0' + bytes([2]) + exporter + context
    signature_1, signature_2 = sign(SEED_1, auth_1), sign(SEED_2, auth_2)
    vectors += [('context_hash_1', context), ('exporter', exporter),
                ('auth_message_1', auth_1), ('auth_message_2', auth_2),
                ('auth_signature_1', signature_1), ('auth_signature_2', signature_2),
                ('accept_1', sha256(context, signature_1, signature_2))]

    def frame(kind: int, sequence: int, payload: bytes) -> bytes:
        return u32(9 + len(payload)) + bytes([kind]) + u64(sequence) + payload

    vectors += [('frame_offer', frame(1, 0, offer)),
                ('frame_data', frame(5, 5, b'abc')),
                ('frame_end', frame(6, 7, bytes([2])))]

    def relay_frame(kind: int, payload: bytes) -> bytes:
        return u32(1 + len(payload)) + bytes([kind]) + payload

    vectors += [('relay_reserve', relay_frame(1, u16(1) + u32(300_000))),
                ('relay_join', relay_frame(3, u16(1) + room + bytes([2]) + token)),
                ('relay_cancel', relay_frame(6, b'')),
                ('relay_reserved', relay_frame(2, room + filled(0x06) + token + u32(299_000))),
                ('relay_waiting', relay_frame(4, b'')),
                ('relay_paired', relay_frame(5, b'')),
                ('relay_refused', relay_frame(7, bytes([3])))]

    # A store snapshot: identity 2, contact 1 Verified, one received spend.
    name = 'Alice'.encode()
    snapshot = (b'ito/identity-snapshot/1\0' + bytes([1]) + SEED_2 + pub_2 +
                u64(1_700_000_000) + u64(1_700_000_100) + u64(0) + u16(1) +
                pub_1 + bytes([2, 0]) + u64(1_700_000_001) + u64(1_700_000_002) +
                bytes([len(name)]) + name + u16(1) + invitation_id + invitation_hash +
                u64(expires) + bytes([2]))
    vectors.append(('snapshot_1', snapshot))

    vectors += pairing_vectors(pub_1, pub_2, invitation_id, invitation_hash, expires)

    out.write_text(''.join(f'{key} {value.hex()}\n' for key, value in vectors))


# Identity 2 for the RFC 8032 seeds, with fixed ML-DSA-87 seeds. Owner Ana
# is identity 1 and scanner Ben identity 2.
ML_DSA_1 = filled(0x21)
ML_DSA_2 = filled(0x22)


def pairing_vectors(pub_1: bytes, pub_2: bytes, invitation_id: bytes,
                    invitation_hash: bytes, expires: int) -> list[tuple[str, bytes]]:
    vectors: list[tuple[str, bytes]] = []
    ml_1, ml_2 = ml_dsa_public(ML_DSA_1), ml_dsa_public(ML_DSA_2)
    fp_1, fp_2 = fingerprint2(pub_1, ml_1), fingerprint2(pub_2, ml_2)
    vectors += [('ml_dsa_seed_1', ML_DSA_1), ('ml_dsa_public_1', ml_1),
                ('ml_dsa_seed_2', ML_DSA_2), ('ml_dsa_public_2', ml_2),
                ('fingerprint2_1', fp_1), ('fingerprint2_2', fp_2)]

    low, high = sorted([fp_1, fp_2])
    vectors.append(('safety_code', digits(sha256(label('ito/safety-code/1'), low, high), 60)))
    composite = composite_sign(SEED_1, ML_DSA_1, fp_1, 'ito/test/composite', b'body')
    vectors.append(('composite_signature_1', composite))

    # Ana's in-person code on a mailbox, read from her screen by Ben.
    server, service = filled(0x41), b'ito-mailbox'
    pairing_id, pairing_secret = filled(0x42, 16), filled(0x43)
    inbox_secret = filled(0x44)
    inbox = mailbox_address(inbox_secret)
    code_expires = 1_700_000_600
    record = (bytes([1]) + pairing_id + pairing_secret + fp_1 +
              authority(server, service) + inbox + u64(code_expires))
    code = 'ito-pair:1:' + base64.urlsafe_b64encode(record).decode().rstrip('=')
    vectors += [('mailbox_server', server), ('mailbox_service', service),
                ('pairing_id', pairing_id), ('pairing_secret', pairing_secret),
                ('pairing_inbox_secret', inbox_secret), ('pairing_inbox', inbox),
                ('code_expires', u64(code_expires)), ('code_record', record),
                ('pairing_code', code.encode())]

    # Ben's hello.
    share_b, kem_seed = filled(0x51), filled(0x52, 64)
    ben_inbox_secret = filled(0x53)
    ben_server, ben_service = filled(0x54), b'ito-mailbox'
    kem = MLKEM1024PrivateKey.from_seed_bytes(kem_seed)
    hello_body = (pub_2 + ml_2 + x25519_public(share_b) + kem.public_key().public_bytes_raw() +
                  authority(ben_server, ben_service) + mailbox_address(ben_inbox_secret) +
                  name_field(b'Ben'))
    hello_signature = composite_sign(SEED_2, ML_DSA_2, fp_2, 'ito/pair/1 hello', record,
                                     hello_body)
    salt = filled(0x55)
    hello_key = hkdf_expand(hkdf_extract(salt, pairing_secret),
                            label('ito/pair/1 hello key') + pairing_id, 44)
    hello_plain = hello_body + hello_signature
    hello = salt + seal(hello_key, salt, padded(hello_plain, 16384 - 32 - 16))
    hello_transcript = sha256(label('ito/pair/1 hello transcript'), record, hello_body,
                              hello_signature)
    vectors += [('scan_share', share_b), ('scan_kem_seed', kem_seed),
                ('scan_inbox_secret', ben_inbox_secret), ('scan_server', ben_server),
                ('hello_body', hello_body), ('hello', hello),
                ('hello_transcript', hello_transcript)]
    # The same hello with one padding byte set: it opens, but is not canonical.
    vectors.append(('hello_bad_padding', salt + seal(
        hello_key, salt, padded(hello_plain, 16384 - 32 - 16)[:-1] + b'\1')))

    # Ana's reply.
    share_a, ratchet_a, ana_inbox_secret = filled(0x61), filled(0x62), filled(0x63)
    shared_kem, ciphertext = kem.public_key().encapsulate()
    exchanged = x25519(share_a, x25519_public(share_b))
    prk = hkdf_extract(pairing_secret, exchanged + shared_kem)
    reply_public = x25519_public(share_a) + ciphertext
    reply_body = (pub_1 + ml_1 + x25519_public(ratchet_a) + mailbox_address(ana_inbox_secret) +
                  name_field(b'Ana'))
    reply_signature = composite_sign(SEED_1, ML_DSA_1, fp_1, 'ito/pair/1 reply',
                                     hello_transcript, reply_public, reply_body)
    reply_key = hkdf_expand(prk, label('ito/pair/1 reply key') + hello_transcript, 44)
    reply = reply_public + seal(reply_key, reply_public,
                                padded(reply_body + reply_signature, 16384 - 1600 - 16))
    transcript = sha256(label('ito/pair/1 transcript'), hello_transcript, reply_public,
                        reply_body, reply_signature)
    root = hkdf_expand(prk, label('ito/pair/1 root') + transcript, 32)
    after_root = hkdf_extract(transcript, root)
    short = digits(hkdf_expand(after_root, label('ito/pair/1 short-code'), 8), 6)
    vectors += [('reply_ratchet', ratchet_a), ('reply_inbox_secret', ana_inbox_secret),
                ('reply_body', reply_body), ('reply', reply), ('transcript', transcript),
                ('root', root), ('short_code', short)]

    # Ben's confirm, which is deterministic.
    ratchet_b = filled(0x71)
    confirm_key = hkdf_expand(after_root, label('ito/pair/1 confirm'), 44)
    confirm = seal(confirm_key, b'', padded(transcript + x25519_public(ratchet_b), 1008))
    vectors += [('confirm_ratchet', ratchet_b), ('confirm', confirm)]

    # Ana's snapshot 2 after a completed pairing with Ben, one spent
    # invitation, one shown code still open and one scanned code waiting.
    contact = (pub_2 + bytes([2, 4]) + u64(1_700_000_001) + u64(1_700_000_002) +
               name_field(b'Ben') + ml_2 + authority(ben_server, ben_service) +
               mailbox_address(ben_inbox_secret) + authority(server, service) +
               u64(1_700_000_002) + bytes([1, 1]) + ana_inbox_secret + root + transcript +
               ratchet_a + x25519_public(ratchet_b))
    open_record = (bytes([2]) + filled(0x81, 16) + filled(0x82) + fp_1 +
                   authority(server, service) + mailbox_address(filled(0x83)) +
                   u64(1_700_259_200))
    scanned_record = (bytes([1]) + filled(0x91, 16) + filled(0x92) + filled(0x93) +
                      authority(ben_server, ben_service) + filled(0x94) +
                      u64(1_700_000_600))
    snapshot = (b'ito/identity-snapshot/2\0' + SEED_1 + pub_1 + u64(1_700_000_000) +
                ML_DSA_1 + u64(1_700_000_100) + u64(0) + u16(1) + contact + u16(1) +
                invitation_id + invitation_hash + u64(expires) + bytes([2]) +
                bytes([1]) + open_record + filled(0x83) + name_field(b'Ana') + bytes([1]) +
                u64(1_700_259_200) +
                bytes([1]) + scanned_record + bytes([1]) + authority(server, service) +
                filled(0x95) + filled(0x96, 64) + filled(0x97) + filled(0x98) +
                u64(1_700_605_400))
    vectors.append(('snapshot_2', snapshot))
    return vectors


if __name__ == '__main__':
    main()
