# Ito call core

`call/` implements the endpoint side of
[calling security](../docs/CALL_SECURITY.md): the local communication
identity, contact trust, one-use invitations, the external-PSK TLS 1.3
channel and the call state machine. It speaks the relay's control framing
from [the relay contract](../docs/CALL_RELAY.md) and then carries TLS
records through the relay. It also implements identity 2, pairing and the
message sessions of [message security](../docs/MESSAGE_SECURITY.md). It is
C++20 with no Android, JNI or Kotlin dependency. The Android app and the
Linux `ito-call` endpoint both run it through one library and its C
interfaces, [`include/ito/call.h`](include/ito/call.h) and, for identity 2,
pairing and messages, [`include/ito/message.h`](include/ito/message.h).

The call core carries profile-1 authenticated DATA. Its portable
`ito/content.h` codec validates bounded Opus/chat envelopes described in
[the content contract](../docs/CONTENT_CHANNEL.md). Android owns platform
Opus and audio devices through [its adapter](https://github.com/FixCraft-Inc/ito4a/blob/main/docs/VOICE.md). The Linux
CLI remains a test-DATA endpoint. Profile 3 rings through the mailbox and uses
identity 2 proofs. This core owns no microphone, playback or background service.

## Owners

| Source | Responsibility |
| --- | --- |
| `codec.*` | Contact codes, fingerprints, invitations, call context, proofs, relay control frames and in-TLS frames. Pure and bounded |
| `crypto.*` | The private OpenSSL library context, SHA-256, Ed25519, ML-DSA-87, X25519, ML-KEM-1024, HKDF-SHA-384, HMAC-SHA-384, AES-256-GCM and the random source |
| `identity.*` | Identity 2: the fingerprint, composite signatures and the safety code |
| `pairing.*` | The pairing code and the hello, reply and confirm items, as pure functions with no trust policy |
| `ratchet.*` | The message ratchet: start, root and chain steps, ML-KEM steps, kept keys, and sealing and opening one message against a state value |
| `envelope.*` | Message envelopes and their payload rules |
| `session.*`, `store_session.cpp` | One contact's message session: its snapshot, the outbox, checks and resends, the order of saving, and the pairing seed taken once from the store |
| `tls.*` | The external-PSK TLS 1.3 channel over memory BIOs and its exact policy check |
| `store.*`, `store_pairing.cpp`, `snapshot.cpp` | Identity 1 and 2, contacts, spent invitations, pairings, clock admission, both snapshot formats and every trust and replay rule |
| `invitation.*` | Validation of a received invitation and signing of a new one |
| `engine.*` | One attempt as a sans-I/O state machine: relay exchange, TLS, frame order, consent, deadlines and quotas |
| `driver.*` | Runs an engine over a blocking transport with 20 ms I/O slices |
| `api.cpp`, `message_api.cpp` | The C interfaces, their handles, borrow counts and status mapping |
| `cli/` | The Linux endpoint: a host test store with session files and a message history, a mailbox client, a stub mailbox directory and a libyume stream transport |

The platform seals the store's plaintext snapshot. On Android that is
Kotlin's `IdentityStore` with a Keystore key, as
[secret storage](https://github.com/FixCraft-Inc/ito4a/blob/main/docs/SECRET_STORAGE.md#call-identity-storage)
describes. On Linux `ito-call` keeps it in an owner-only file without
encryption, as a test and development store.

## Building and testing

The [main README](../README.md#building) lists the tools the build needs.
Packaging and qualification link stock OpenSSL 3.5.9 statically from a
prefix built from the pinned archive in
[`tools/security-component.json`](../tools/security-component.json).
`ITO_CALL_OPENSSL_ROOT` names that prefix, which must hold `include/`,
`lib/libssl.a` and `lib/libcrypto.a`. Build it with the options
`tools/build_call_core.sh` uses for Android, and the Linux target:

```sh
curl -fLO https://github.com/openssl/openssl/releases/download/openssl-3.5.9/openssl-3.5.9.tar.gz
echo '603f5602e2eef00d77fbd429d34dcd5822bb301757a1bc9cdb24c670f1eb859a  openssl-3.5.9.tar.gz' | sha256sum -c
tar -xzf openssl-3.5.9.tar.gz
cd openssl-3.5.9
./Configure linux-x86_64 no-shared no-module no-tests --libdir=lib \
  --prefix=/path/to/openssl-3.5.9
make -j4 build_libs
make install_dev
```

On another architecture, use its OpenSSL target, such as `linux-aarch64`.
Then build and test the core. `$YUME_BUILD` is the YUME build directory that
[the main README](../README.md#the-yume-shared-library) describes:

```sh
cmake -S call -B build/call -G Ninja -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DITO_CALL_OPENSSL_ROOT=/path/to/openssl-3.5.9 \
  -DITO_CALL_YUME_INCLUDE=/path/to/yume/include \
  -DITO_CALL_LIBYUME="$YUME_BUILD/src/libyume.so"
cmake --build build/call
ctest --test-dir build/call --output-on-failure
```

Without `ITO_CALL_YUME_INCLUDE` and `ITO_CALL_LIBYUME`, the build skips the
`ito-call` endpoint and the tests that drive it.

Without `ITO_CALL_OPENSSL_ROOT`, and with `-DITO_CALL_OPENSSL_VERSION=`, the
build uses the system's OpenSSL 3.5 or later for quick local checks. That
build is not the pinned component, and it skips the exported-symbol test.
`ITO_CALL_SANITIZE=address,undefined` adds sanitizers. `ITO_CALL_FUZZERS=ON`
with Clang builds a libFuzzer target over every parser.

The tests are:

- `codec_test` checks every encoding against `tests/vectors.txt`, which
  `tests/generate_vectors.py` writes independently in Python from the
  contract's tables.
- `crypto_test`, `store_test`, `tls_test` and `engine_test` cover the
  owners. The engine test drives two engines, and scripted raw TLS peers that
  hold the invitation PSK, through an in-memory relay with virtual time.
  Its `--buffered-eof` selector checks queued DATA/END across orderly EOF,
  split/coalesced records, incomplete input and immediate terminal overrides.
  Its `--handshake-budget` selector feeds real fragmented TLS records to both
  endpoint roles and checks the exact 256 KiB inbound threshold and the next
  byte's typed refusal without changing the 64 KiB BIO bound.
  Its `--hello-retry` selector completes a real one-HRR handshake, keeps
  authentication failures after one HRR typed, and replays the real server HRR
  after ClientHello2. Coalesced and byte-fragmented second HRRs terminate with
  `ProtocolFailure`.
- `ring_test` checks invitation 2, composite call proofs and Ring/Ring end
  against the Python vectors, then drives authenticated ratchet delivery
  into a real TLS call. It covers replay, wrong identities and relays,
  rejected/ambiguous storage, exact acceptance deadlines, decline without
  JOIN, modified proofs, wrong exporters and downgrade attempts.
- `parser_random_test` mutates the vectors through every parser.
- `driver_test` ends an attempt typed when a C++ platform transport throws.
  Its `--write-end` selector checks that terminal writes are not followed by a
  stale read and that write-side EOF remains a transport failure.
- `api_test` runs a threaded call through the packaged library, and fails
  each allocation of a store change, an invitation opening and a responder's
  call creation in turn through a test-local `operator new`. Each failure
  must be typed, preserve identity, trust and replay state, keep the caller's
  invitation and borrows intact, and leave no identity seed in freed memory.
  A completed independent clock checkpoint can survive a later failure.
  Each injection loop must exercise a failure before success.
- `pairing_test` checks identity 2 and pairing against the vectors, measures
  the largest snapshot 2 against its bound, and pairs stores in person, by
  link, with a copied code and through every refusal.
- `ratchet_test` checks the ratchet against the vectors, sealing again
  every message without a fresh ML-KEM ciphertext byte for byte, then every
  bound and refusal, the session snapshot's checks and measured largest
  size, and a long random conversation with reordering and clock jumps.
- `message_api_test` drives `ito/message.h` through the packaged library as a
  platform does, keeping a mailbox by inbox address.
- `session_test` drives message sessions the same way: a conversation, the
  outbox with checks and resends, trust and pairing again, the order of
  saving under refused and ambiguous storage, and an allocation failure at
  each index of every pairing and session operation. Each failure must be
  typed and keep the live and the durable state. Pairing failures must
  leave no identity seed, and those after a session's start no root key,
  in freed memory.
- `pair_harness.py` and `message_harness.py`, registered when `ito-call` is
  built, pair Linux endpoints and exchange messages through a stub mailbox
  directory. `message_harness.py --yumed ...` runs the same endpoints through
  a real yumed and `ito-mailbox`, the way `call_harness.py` runs calls.
- `exports_test` checks that `libitocall.so` exports only `ito_*` and imports
  no OpenSSL symbol.
- `failure_test`, driven by `tests/failure_sweep.py`, runs each allocation
  index in a fresh child. Its executable links the production core objects
  and its own pinned OpenSSL, with test-local C++ and OpenSSL allocators.
  The packaged library binds its OpenSSL privately and is not interposed.
  RESERVED/JOIN failures inspect buffers before free for the bearer tokens
  and actual invitation PSK. A test-only RAND wrapper delegates to the real
  RNG and captures the initiator PSK for observation without changing it.
  Signing/verification and both first-flight TLS roles exercise actual
  OpenSSL allocation failures. Operation cases finish observation before
  the outer context/provider teardown; this is not whole-process erasure.
  The cold-context case includes initialization and destruction. A failed
  base-lock allocation in the pinned OpenSSL can recursively enter global
  initialization and stall; the sweep kills and waits for that child and
  reports a failed gate. Warming initialization does not qualify this path.

The endpoint harness requires a zero CLI exit for every written call result
and rejects sanitizer diagnostics in each private stderr log. It reaps both
CLI children on setup and scenario failures. `python3 -B
tests/test_call_harness.py` checks these process failures without native builds.

`tests/call_harness.py` runs two `ito-call` endpoints through a real yumed
and `ito-call-relay`, reusing the relay's yumed harness. A recording tap on
the relay's module socket checks that only TLS records pass after pairing.
Evidence builds (`ITO_CALL_EVIDENCE=ON`, never a product) report their
secrets, and the tap shows none of them, and no payload, crossed the relay.
Build the evidence endpoint in its own directory, then pass both endpoints
to the harness:

```sh
cmake -S call -B build/call-evidence -G Ninja -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DITO_CALL_EVIDENCE=ON -DITO_CALL_OPENSSL_ROOT=/path/to/openssl-3.5.9 \
  -DITO_CALL_YUME_INCLUDE=/path/to/yume/include \
  -DITO_CALL_LIBYUME="$YUME_BUILD/src/libyume.so"
cmake --build build/call-evidence --target ito-call
python3 -B call/tests/call_harness.py --relay build/relay/ito-call-relay \
  --yumed "$YUME_BUILD/bin/yumed" --setup "$YUME_BUILD/bin/yume-setup" \
  --libyume "$YUME_BUILD/src/libyume.so" --resolver "$YUME_BUILD/bin/yume-resolver" \
  --ito-call build/call/ito-call --ito-call-evidence build/call-evidence/ito-call
```

`tests/ring_harness.py` combines both services on one yumed and pairs two
Linux endpoints. It accepts a profile-3 call, declines and reports busy
without a responder JOIN, and checks the unanswered 45-second timeout. The
mailbox tap checks class 2 with a 60-second hold and no ring ciphertext in
the mailbox's store. The call tap checks TLS and the absence of PSKs, both
proof halves and DATA plaintext. The busy case also leaves an unrelated
text for the history collector. Pass the same `--yumed`, `--setup`,
`--libyume`, `--resolver`, `--ito-call` and `--ito-call-evidence` paths as
the call harness, plus `--mailbox`, `--relay` and `--result`.

Clock admission uses the caller's current Unix seconds and the core's monotonic
clock. Detected rollback returns `clock_regressed` before new invitation use.
The uncertainty checkpoint remains across reopening. Automatic recovery from
that state is not implemented, and a corrected display clock alone cannot
clear it.
Opened invitations keep their original monotonic deadline across handoff.
Reload retains identity/trust/replay and the clock floor, without restoring
pending secrets or deadlines. The exact observation, persistence and detection
limits are in [calling security](../docs/CALL_SECURITY.md). Clock refusal is
never a reason to remove or recreate the host store.

## Symbol isolation

`libitocall.so` links OpenSSL with `--exclude-libs,ALL`, `-Bsymbolic` and a
version script that exports only the C interface. Its OpenSSL therefore
neither interposes on nor binds to the patched OpenSSL inside libyume when
both load in one process. `tools/build_call_core.sh` builds it for Android
and refuses a library whose exported or imported surface differs.

The Android output includes `ito/call.h`, `ito/content.h` and `ito/message.h`.
`provenance.json` binds all three through `headers_sha256`, keyed by basename;
`header_sha256` remains the hash of `call.h`. The consumer checks these copies
before generating its native dependency notices.

## The Linux endpoint

```sh
ito-call --store DIR identity create
ito-call --store DIR identity upgrade
ito-call --store DIR contact add CODE NAME
ito-call --store DIR contact verify CODE FINGERPRINT
ito-call --store DIR mailbox show CARRIER
ito-call --store DIR pair code --kind in-person --mailbox FINGERPRINT \
  --mailbox-service ito-mailbox --name NAME --code-out FILE [CARRIER]
ito-call --store DIR pair scan --code FILE --source scanned \
  --mailbox FINGERPRINT --mailbox-service ito-mailbox --name NAME CARRIER
ito-call --store DIR pair collect CARRIER
ito-call --store DIR pair decide PAIRING_ID match
ito-call --store DIR contact compare CODE SAFETY_CODE
ito-call --store DIR message send CODE --text FILE CARRIER
ito-call --store DIR message collect CARRIER
ito-call --store DIR message check CODE --hold SECONDS CARRIER
ito-call --store DIR message outbox CODE
ito-call --store DIR message history CODE
ito-call --store DIR ring --peer CODE --yume-config DIR --service ito-call \
  --mailbox-service ito-mailbox --result FILE
ito-call --store DIR answer-ring --peer CODE --yume-config DIR --service ito-call \
  --mailbox-service ito-mailbox --result FILE [--decline | --busy | --no-decision]
ito-call --store DIR call --peer CODE --invitation-out FILE \
  --yume-config DIR --service ito-call --result FILE [--send FILE --expect-bytes N]
ito-call --store DIR answer --invitation FILE \
  --yume-config DIR --service ito-call --result FILE [--decline]
```

`ring` and `answer-ring` are profile-3 test endpoints on one shared relay,
with both the call and mailbox service grants. `ring` reserves for 90 seconds,
seals the invitation through its contact's session, deposits class 2 for at
most 60 seconds, and waits at most 45 seconds. `answer-ring` waits for a ring
from `--peer` and accepts it without a second prompt. `--decline`, `--busy`
and `--no-decision` send a ring end without joining. A caller stops on a
matching ring end, and sends missed or canceled on unanswered termination.
The ringing wait keeps one mailbox subscription, within the OPEN rate limit.
No invitation file is written. The stub carrier refuses rings because its
files cannot satisfy the memory-only mailbox rule. `call` and `answer` keep
profile 1 and a private invitation file for transport diagnostics.

`--yume-config` names a YUME client configuration directory with
`yume.json`. The invitation file stands in for an authenticated and
confidential channel. It holds the invitation PSK, so the caller moves it
privately and wipes it after use.

The pairing code file holds the pairing secret and travels the same way.
CARRIER is how items move. `--yume-config DIR --service ito-mailbox` reaches
a mailbox service through the YUME client in DIR, and `mailbox show` prints
the server fingerprint and service that stream verified, which a pairing
code names as its mailbox. Items for a mailbox on another relay are refused
until a second connection exists. `--stub DIR` names a private directory
that stands in for every mailbox: one subdirectory per inbox, one file per
item. It checks no inbox secret, so anyone who can read it can take every
item.

A mailbox refuses deposits to an inbox nobody opened, so `pair code` given a
CARRIER, `pair scan` and `collect` open each new inbox before the code or
item that names it leaves the endpoint.

`pair collect` and `message collect` are one pass: every inbox the store
lists, every item waiting there, handed to pairing first and then to the
contact's message session. The pass deposits what the core answers, and
takes each item except after a local storage or clock failure, or a
message from a contact who is not Verified yet. It then sends a Delivered
receipt for every text, profile and timer message it holds, a Missing list
for each check, and every message the contact said is missing.

Sessions live in the store's `sessions/` directory, one file per contact,
and received messages in `history/`, one file per message ID. Message text
appears in no command's output except `message history`. `message send
--drop` seals a message without depositing it, as a relay that lost it,
for the check and resend tests.
