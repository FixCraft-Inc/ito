# Message security, pairing and ringing

This page specifies the keys behind the [messenger design](MESSENGER.md): a
post-quantum identity, pairing two phones once, the message ratchet, and
call invitations sent as messages. Identity 2 and pairing are implemented in
[`call/`](../call/README.md) and specified here to the byte. The ratchet, the
messages inside it and calls without a QR code are still design. Their byte
layouts, vectors and tests come with their implementation.
[Calling security](CALL_SECURITY.md) stays the contract for everything this
page does not change.

## Goals and attacker

The attacker is the same as in calling security: the network, the provider
directory and every relay and mailbox can watch, delay, replay, reorder,
replace or drop traffic. Messages add stored ciphertext on the relay's disk.

Against that attacker, messages must keep their text secret and intact, prove
which contact sent them, and accept each message at most once. Keys move
forward with every message, so a key taken from a phone today opens neither
older messages nor, after the next refresh, newer ones. Every secret mixes a
classical and a post-quantum key exchange, and every identity proof carries a
classical and a post-quantum signature, so an attacker has to break both.

Out of scope, as for calls: a compromised phone, a compromised channel used to
compare codes, traffic analysis, availability, and a contact who keeps or
shares what they receive. The relay's view of who talks to whom is listed in
the messenger design.

## Identity 2

An identity 2 is a pair of signing keys that always sign together: the
installation's Ed25519 key and an ML-DSA-87 key (FIPS 204, the same algorithm
and level as YUME's server identities). `ito_message_identity_upgrade` adds
the ML-DSA key to an identity 1 by drawing a 32-byte FIPS 204 seed from the
core's random source. Both seeds live in the identity snapshot, and each
public key is derived from its seed whenever the snapshot is opened. A store
that is never upgraded keeps its identity 1 and writes snapshot 1 unchanged.

The fingerprint is SHA-256 over ASCII `ito/contact-identity/2`, one zero
byte, the Ed25519 public key (32 bytes) and the ML-DSA-87 public key (2592
bytes). Advanced mode shows it as 64 hex digits. Contact records stay keyed
by the Ed25519 key, so an identity 1 contact pairs again in place and keeps
its name and history. A store holds one ML-DSA key per Ed25519 key, and it
refuses a pairing that names a known Ed25519 key with any other ML-DSA key
(UNTRUSTED).

A composite signature is 4691 bytes: an Ed25519 signature (64 bytes)
followed by an ML-DSA-87 signature (4627 bytes), both over one message. The
message is the label (its ASCII text and one zero byte), the signer's
fingerprint, then the signed fields. ML-DSA signs it in pure mode with the
empty context string and OpenSSL's hedged randomness, so two signatures of
one message differ. The signature is valid only when both halves verify
under the keys the named fingerprint covers, which binds each half to the
other.

Two people compare a safety code. It is SHA-256 over ASCII
`ito/safety-code/1`, one zero byte and both fingerprints, the bytewise
smaller first. The digest is read as a big-endian number, and the code is its
value modulo 10^60 written as 60 decimal digits with leading zeros, shown as
12 groups of five and as a QR code the other person can scan. The QR code's
text is defined with the app's single scanner, which tells every Ito code
apart. Both phones compute the same code only when each holds
the other's real identity. A comparison accepts exactly those 60 digits with
any spaces and hyphens between them, and refuses any other character, a
prefix or a longer string.

A paired contact becomes Verified in one of two ways: an in-person pairing
that the owner confirms (below), or the full safety code compared over a
channel the two people trust. The identity 1 comparison
(`ito_store_verify_contact`) refuses a paired contact with WRONG_STATE,
because its fingerprint covers only the Ed25519 key. For the same reason a
Verified identity 1 contact that pairs again by link becomes Not verified.
Pairing again with an identity 2 that was already Verified keeps that trust.
Trust states stay Unverified, Verified and Blocked, with calling security's
rules for replaced keys.

## Pairing

The owner shows a code and the scanner reads it. The scanner sends a hello
to the code's pairing inbox, the owner answers with a reply, and the
scanner's confirm proves to the owner that both phones hold the same root
key. The items travel through [the mailbox](MAILBOX.md) as message items:
the hello and the reply fill 16384 bytes and the confirm 1024. The core
seals, opens and checks every item. The platform deposits what the core
returns at the target the core names, and hands every item that arrives at a
listed inbox to `ito_pairing_receive`.

An inbox address is SHA-256 over ASCII `ito/mailbox-address/1`, one zero
byte and the inbox's 32-byte secret, which only the inbox's owner holds.
Every key and nonce on this page is HKDF with SHA-384 (RFC 5869), and every
label is its ASCII text and one zero byte. Integers are big-endian.

### The code

The code is the text `ito-pair:1:` followed by unpadded base64url
(RFC 4648, section 5) of this record:

| Field | Bytes | Contents |
| --- | --- | --- |
| Kind | 1 | 1 in person, 2 link |
| Pairing ID | 16 | Random |
| Pairing secret | 32 | Random |
| Owner | 32 | The owner's fingerprint |
| Mailbox server | 32 | The YUME server fingerprint of the owner's mailbox |
| Service length | 1 | 1 to 64 |
| Service | 1 to 64 | The mailbox's service name, in YUME's service-name grammar |
| Pairing inbox | 32 | The address of the code's pairing inbox |
| Expiry | 8 | Unix seconds, neither 0 nor 2^64 - 1 |

A record is 155 to 218 bytes and its text at most 302 characters. A reader
refuses padding, characters outside the base64url alphabet, nonzero unused
bits in the last character, a lone last character, anything but exactly one
canonical record, and other prefixes (MALFORMED). Another decimal version
after `ito-pair:` is UNSUPPORTED.

The pairing secret makes the code a credential: whoever reads it can write
the one hello the owner accepts. The code carries no server address, so a
link shared in public points no censor at a server. The secret that opens the
pairing inbox never leaves the owner's phone, so someone who copies the code
still cannot collect the scanner's hello.

An in-person code lives 600 seconds and a link three days (259,200 seconds).
Each works once. A phone keeps at most eight shown codes open and at most
eight scanned codes waiting for replies. A scanner keeps its secrets until
the earlier of the code's expiry and its kind's lifetime from the scan, plus
seven days for the reply, however far ahead a code claims to expire.

### The hello

The hello is 32 random salt bytes followed by AES-256-GCM of a 16336-byte
plaintext, with the salt as associated data and the 16-byte tag at the end.
Its key and nonce are the 44 bytes expanded from HKDF-Extract(salt, pairing
secret) with info `ito/pair/1 hello key` and the pairing ID. The plaintext is
the hello body, the scanner's composite signature, then zeros.

| Hello body field | Bytes |
| --- | --- |
| The scanner's Ed25519 key | 32 |
| The scanner's ML-DSA-87 key | 2592 |
| A fresh X25519 public key | 32 |
| A fresh ML-KEM-1024 encapsulation key | 1568 |
| The scanner's mailbox: server, service length, service | 33 + service |
| The scanner's inbox address for the owner | 32 |
| Name hint length and name hint, 1 to 128 bytes of UTF-8 | 1 + name |

The signature has label `ito/pair/1 hello` and signs the code record, then
the hello body. The hello transcript H1 is SHA-256 over label
`ito/pair/1 hello transcript`, the record, the body and the signature.

### The reply

The owner draws a fresh X25519 key and encapsulates to the scanner's ML-KEM
key. The pairing key PRK is HKDF-Extract with the pairing secret as salt and,
as input, the X25519 result followed by the ML-KEM-1024 shared secret.

The reply starts with the owner's X25519 public key (32 bytes) and the
ML-KEM-1024 ciphertext (1568 bytes) in the clear. AES-256-GCM of a
14768-byte plaintext follows, with those 1600 bytes as associated data. Its
key and nonce expand PRK with info `ito/pair/1 reply key` and H1. The
plaintext is the reply body, the owner's composite signature, then zeros.

| Reply body field | Bytes |
| --- | --- |
| The owner's Ed25519 key | 32 |
| The owner's ML-DSA-87 key | 2592 |
| The owner's first ratchet X25519 public key | 32 |
| The owner's inbox address for the scanner | 32 |
| Name hint length and name hint | 1 + name |

The signature has label `ito/pair/1 reply` and signs H1, the owner's X25519
key, the ciphertext and the reply body. Only the scanner can read the reply,
so someone who copied the code never sees the owner's public keys. The
transcript T is SHA-256 over label `ito/pair/1 transcript`, H1, the X25519
key, the ciphertext, the reply body and its signature. The root key is 32
bytes expanded from PRK with info `ito/pair/1 root` and T.

### The confirm and the short code

Values after the root expand PRK2 = HKDF-Extract(T, root key). The confirm is
AES-256-GCM, with no associated data, of 1008 bytes: T, the scanner's first
ratchet X25519 public key, then zeros. Its key and nonce expand PRK2 with info
`ito/pair/1 confirm`. The scanner's ratchet key is fixed once the reply is
in, so the confirm is the same bytes each time it is built. A resend is
therefore safe and never puts new plaintext under the same nonce.

The short code is 8 bytes expanded from PRK2 with info
`ito/pair/1 short-code`, read as a big-endian number and shown modulo 10^6 as
six digits. Both phones show it after an in-person exchange.

The message ratchet starts from the root key, T and the two first ratchet
keys.

### Checks and outcomes

The owner takes a hello only at an open code's pairing inbox and before the
code's expiry. It opens the item (AUTHENTICATION_FAILED when the AEAD refuses
it) and reads one canonical body with zero padding (MALFORMED). It checks the
scanner before paying for its signature: never itself, never a Blocked key,
never a known Ed25519 key with another ML-DSA key (UNTRUSTED), and room for
one more contact (CAPACITY). Then it verifies the composite signature. A
scanner X25519 or ML-KEM key that cannot be used is MALFORMED. The first
valid hello spends the code: one snapshot saves the reply's state, the
pairing inbox closes, and every later hello is ALREADY_SPENT. A refused hello
leaves the code open.

The scanner opens the reply with its saved secrets. A reply whose X25519 key
gives the all-zero shared secret is refused like any forgery
(AUTHENTICATION_FAILED). After the same checks of the owner, the reply's keys
must hash to the fingerprint in the code and its signature must verify. The
scanner saves the owner as a paired contact, Verified only when the code is
in person and was read from the owner's screen
(`ITO_PAIRING_SOURCE_SCANNED`). Its reply inbox becomes its inbox for the
owner, and the core returns the confirm.

The owner opens the confirm at the inbox its reply named, and the confirm
must echo T. A link then completes, Not verified. An in-person pairing
completes once the confirm is in and the owner has compared the six digits
with the scanner's screen and tapped Matches, in either order. Completion
checks the scanner again, so a block placed after the hello refuses it. When
the digits differ, the owner removes the pairing. A copied code fails here:
whoever used it first gets the pairing, the real scanner's hello is refused,
and its screen shows no digits.

A pairing that has not finished is removed once its deadline passes: the
code's expiry while the code waits for a hello, then seven days after the
hello for the confirm and the decision. A confirm sent again after completion
is recognized and refused as ALREADY_SPENT. A refused item leaves pairings
and contacts as they were. Clock admission, which runs first, may still save
a newer clock floor.

Each side deletes its fresh X25519 and ML-KEM keys and the pairing secret
when the pairing completes or is removed. The paired contact keeps its inbox
secret, the root key, T and both first ratchet keys for the message ratchet.

A link leaves both contacts Not verified. Six digits are too few at a
distance, because whoever controls the link's channel can make two short
codes match by trying about a million keys. Verification then needs the full
safety code, compared over a trusted channel or by scanning in person.

### Identity snapshot 2

An upgraded store writes snapshot 2 (domain `ito/identity-snapshot/2`) and
reads either version. Beyond snapshot 1's contents it holds the ML-DSA seed,
each paired contact's ML-DSA key, mailboxes, addresses, pairing time,
verification method, role and secrets, and the shown and scanned codes with
their state. Opening refuses any malformed, reordered or inconsistent
snapshot: a seed that does not derive the stored key, a paired contact
without exactly one secret record, a Verified paired contact without a
verification method or an Unverified one with one, a shown code this identity
does not own or whose inbox secret does not give its address, and a pairing
ID used twice.

With every list at its bound (256 paired contacts, 1024 spent invitations,
eight shown and eight scanned codes) and every name and service at its
longest, snapshot 2 is 933,358 bytes. That is exactly the bound the core
computes field by field, which `pairing_test` measures, and it stays under
the 1 MiB that the core and ito4a's sealed identity store accept.

### Interface and tests

`ito/message.h` holds the calls: the upgrade and fingerprint, creating and
scanning codes, receiving items, the owner's decision, cancellation, the
inboxes the platform keeps open, rebuilding a lost confirm, paired contacts
and the safety code. `ITO_CONTACT_PAIRED` in `ito/call.h` marks paired
contacts. The Linux endpoint pairs with `ito-call pair` through a stub
mailbox directory until it reaches a mailbox service.

`tests/generate_vectors.py` writes the identity 2 and pairing vectors
independently in Python: keys, fingerprints, a composite signature, the
safety code, a code record and its text, a hello and a hello with one nonzero
padding byte, a reply, its transcript, root and short code, a confirm and a
snapshot 2. ML-DSA signing and ML-KEM encapsulation are randomized, so the
C++ tests open the vector hello and reply rather than rebuild them.
`pairing_test` checks the vectors, the snapshot bound and stores pairing
through every outcome above, `message_api_test` drives the C interface the
way a platform does, and `pair_harness.py` pairs Linux endpoints.

## Ratchet

The ratchet follows the published Double Ratchet. Each time the conversation
changes direction, a new X25519 exchange refreshes the root key. Each message
takes its own key from a chain that moves forward and forgets old links.

The post-quantum part adds ML-KEM-1024 steps. A phone advertises a fresh
ML-KEM encapsulation key in its message headers. When the contact next starts
a new sending chain, it encapsulates to that key, sends the ciphertext in its
header and mixes the shared secret into the same root step as that turn's
X25519 result. The receiver decapsulates and mixes the same secret. Each
decapsulation key is used once and then deleted. A phone advertises a new key
when its last post-quantum step is 20 turns or 24 hours old, whichever comes
first. The key and ciphertext add about 3 KB to a message, which is why the
step is periodic rather than in every message.

- Root step: HKDF-SHA-384 with the root key as salt and, as input, the X25519
  result, one flag byte and the ML-KEM secret when present. It gives a new root
  key and a chain key, label `ito/ratchet/1 root`.
- Chain step: HMAC-SHA-384 of the chain key with byte 1 gives the message key
  and with byte 2 the next chain key.
- Message: HKDF-SHA-384 from the message key gives an AES-256-GCM key and
  nonce, label `ito/message/1 key`. The associated data is the label, both
  fingerprints and the header. Each message key encrypts once.
- Header, in the clear: version, the sender's ratchet public key, the previous
  chain's length, the message number, and when present the advertised ML-KEM
  key or the ciphertext with the ID of the key it answers.

Bounds: at most 1000 skipped message keys per chain step and 2000 per contact,
each kept for 30 days at most. A message needing more is refused without
changing state. Message numbers stay below 2^20 per chain.

Order of saving. Sending: advance the chain, save the session, then hand the
sealed item to the mailbox. Receiving: decrypt into a candidate state, store
the message (ignoring a message ID already held), save the session, and only
then tell the mailbox the item was taken. A crash at any point leaves either a
repeat delivery, which the message ID catches, or nothing changed.

A message that fails authentication is dropped and counted, and the session
stays as it was. An unreadable or corrupt session stops that chat with
"Secure session broken, pair again". It is never reset silently, and the other
chats and the identity stay intact.

Each contact's session is its own snapshot (domain `ito/session-snapshot/1`)
that the core encodes and the app seals and publishes, as with the identity
snapshot. ML-KEM private keys are stored as their 64-byte seeds. With app lock
on and the app locked, sessions are not opened.

## Messages inside the ratchet

Each ratchet message holds one envelope: a kind, a random 16-byte message ID,
the sender's time in milliseconds, flags (Resent) and a payload. Padding
inside the encryption brings each item to 1, 4 or 16 KiB, so the relay sees
only those sizes.

| Kind | Payload |
| --- | --- |
| Text | 1–4096 bytes of strict UTF-8, under the content channel's text rules |
| Receipt | Delivered or Read, with up to 64 message IDs |
| Check | Up to 64 message IDs the sender has no receipt for |
| Missing | The IDs from a check that the receiver does not hold |
| Ring, Ring end | A call invitation, then canceled, declined, busy or missed |
| Inbox | A new inbox address and relay, sent before moving |
| Profile | A new name hint, display only |
| Timer | The chat's auto-delete setting: off, a day, a week or a month |

A receiver keeps the IDs of the messages it holds, plus deleted IDs for 30
days, so a resend after a deletion does not bring the message back. Receipts
and checks travel in batches.

## Calls without a QR code

A ring carries invitation 2, the canonical invitation of calling security with
these changes: domain `ito/invitation/2`, fingerprints in place of Ed25519
keys, call profile 3, and no signature, because the ratchet already proves who
sent it. Room, room token, call secret, lifetime and one-use rules are
unchanged, and so is the clock rule for opening an invitation. The caller
reserves the room on the recipient's relay for 90 seconds, enough for 45
seconds of ringing plus the handshake.

Profile 3 keeps today's TLS channel (external PSK, `X25519MLKEM768`,
`TLS_AES_256_GCM_SHA384`) and content envelope 1. Its proofs change to
composite signatures (labels `ito/call-context/2` and `ito/call-auth/2`), so
the call proves both identities with post-quantum signatures too. The call
secret stays a TLS PSK, which keeps the identity proofs hidden from a relay
that probes the handshake.

Accepting the ring is the responder's consent to that exact invitation, so no
second prompt follows the proofs. Declining, a busy line or no answer sends a
Ring end message. The responder never joins the room for those. The QR-code
invitation flow (profiles 1 and 2) leaves the app. Whether the Linux endpoint
keeps profile 1 for transport diagnostics is decided in the implementation.

## Labels and dependencies

All labels on this page are new, and no version 1 label changes meaning:
`ito/contact-identity/2`, `ito/safety-code/1`, `ito/identity-snapshot/2`,
`ito-pair:1:`, the `ito/pair/1` labels (`hello key`, `hello`,
`hello transcript`, `reply key`, `reply`, `transcript`, `root`, `confirm` and
`short-code`), `ito/mailbox-address/1`, `ito/ratchet/1`, `ito/message/1`,
`ito/session-snapshot/1`, `ito/invitation/2`, `ito/call-context/2` and
`ito/call-auth/2`.

Stock OpenSSL 3.5.9, already pinned for the call core, provides every
primitive here: X25519, ML-KEM-1024, Ed25519, ML-DSA-87, HKDF and HMAC with
SHA-384, and AES-256-GCM. The core fetches each from its private library
context with `provider=default` when an operation needs it. A missing
primitive ends that operation with DEPENDENCY_FAILURE, and nothing falls back
to another provider. The vector generator holds the identity 2 and pairing
vectors and gains the ratchet and invitation 2 vectors with their
implementation. ito4a's test reads only `snapshot_1`, whose bytes are
unchanged.

## Limits of the claim

The ratchet heals from a stolen key at the next turn against a classical
attacker and at the next post-quantum step against a quantum one. A phone has
one identity, and a second device is out of scope. The construction follows
published designs (Double Ratchet, PQXDH, Apple's PQ3), but this combination
has no formal analysis yet.
