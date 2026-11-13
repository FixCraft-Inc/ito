# Message security, pairing and ringing

This page specifies the keys behind the [messenger design](MESSENGER.md): a
post-quantum identity, pairing two phones once, the message ratchet, and
call invitations sent as messages. Identity 2, pairing, the ratchet and the
messages inside it are implemented in [`call/`](../call/README.md) and
specified here to the byte. Calls without a QR code are still design, and
their byte layouts, vectors and tests come with their implementation.
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
listed inbox to `ito_pairing_receive`. A mailbox refuses deposits to an
inbox nobody opened, so the platform opens each new inbox before the code or
item that names it leaves the phone.

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
is recognized and refused as ALREADY_SPENT until the contact's message
session starts. A refused item leaves pairings and contacts as they were.
Clock admission, which runs first, may still save a newer clock floor.

Each side deletes its fresh X25519 and ML-KEM keys and the pairing secret
when the pairing completes or is removed. The paired contact keeps its inbox
secret, T, and until its message session takes them the root key and both
first ratchet keys. The scanner can build its confirm again only while it
holds them, so it deposits the confirm before it opens the session.

A link leaves both contacts Not verified. Six digits are too few at a
distance, because whoever controls the link's channel can make two short
codes match by trying about a million keys. Verification then needs the full
safety code, compared over a trusted channel or by scanning in person.

### Identity snapshot 2

An upgraded store writes snapshot 2 (domain `ito/identity-snapshot/2`) and
reads either version. Beyond snapshot 1's contents it holds the ML-DSA seed,
each paired contact's ML-DSA key, mailboxes, addresses, pairing time,
verification method, role, inbox secret, T and a seed byte, which is 1 while
the root key and both first ratchet keys follow and 0 once the message
session took them, and the shown and scanned codes with their state. Opening refuses any malformed, reordered or inconsistent
snapshot: a seed that does not derive the stored key, a paired contact
without exactly one secret record, a Verified paired contact without a
verification method or an Unverified one with one, a shown code this identity
does not own or whose inbox secret does not give its address, and a pairing
ID used twice.

With every list at its bound (256 paired contacts, 1024 spent invitations,
eight shown and eight scanned codes) and every name and service at its
longest, snapshot 2 is 933,614 bytes. That is exactly the bound the core
computes field by field, which `pairing_test` measures, and it stays under
the 1 MiB that the core and ito4a's sealed identity store accept.

### Interface and tests

`ito/message.h` holds the calls: the upgrade and fingerprint, creating and
scanning codes, receiving items, the owner's decision, cancellation, the
inboxes the platform keeps open, rebuilding a lost confirm, paired contacts,
the safety code, and the message sessions below. `ITO_CONTACT_PAIRED` in
`ito/call.h` marks paired contacts. The Linux endpoint pairs and exchanges
messages with `ito-call pair` and `ito-call message`, through a mailbox
service or a stub mailbox directory.

`tests/generate_vectors.py` writes the identity 2, pairing and ratchet
vectors independently in Python: keys, fingerprints, a composite signature,
the safety code, a code record and its text, a hello and a hello with one
nonzero padding byte, a reply, its transcript, root and short code, a
confirm, a snapshot 2, a conversation of nine messages with their roots and
envelopes, one message with nonzero padding, and a session snapshot. ML-DSA
signing and ML-KEM encapsulation are randomized, so the C++ tests open the
vector hello, reply and the two messages that answer an ML-KEM key rather
than rebuild them, and seal every other message again byte for byte.
`pairing_test` checks the pairing vectors, the snapshot bound and stores
pairing through every outcome above. `ratchet_test` checks the ratchet
vectors, every bound and refusal of the ratchet, the session snapshot's
checks and its bound, and a long random conversation. `message_api_test`
and `session_test` drive `ito/message.h` the way a platform does,
`session_test` also through refused and ambiguous storage and an allocation
failure at each index of every pairing and session operation.
`pair_harness.py` pairs Linux endpoints, and `message_harness.py` pairs them
and exchanges messages through a stub directory or a real yumed and
`ito-mailbox`.

## Ratchet

Each paired contact has one message session. It follows the published
Double Ratchet: each time the conversation changes direction, a new X25519
exchange refreshes the root key, and each message takes its own key from a
chain that moves forward and forgets old links. ML-KEM-1024 steps add the
post-quantum part.

### Keys

- Root step: PRK is HKDF-Extract with the root key as salt over the X25519
  secret, a flag byte and, when the flag is 1, the 32-byte ML-KEM secret.
  HKDF-Expand of PRK with info `ito/ratchet/1 root` gives 80 bytes: the next
  root key (32) and a chain key (48).
- Chain step: HMAC-SHA-384 of the chain key over the byte 1 is the message
  key, and over the byte 2 the next chain key, both 48 bytes. A chain key
  serves one step and is then forgotten.
- Message: PRK is HKDF-Extract with the header's 16-byte salt over the
  message key, and HKDF-Expand of PRK with info `ito/message/1 key` gives
  the AES-256-GCM key (32 bytes) and nonce (12). Each message key encrypts
  once. The random salt adds a second guard: a phone that sealed again from
  an old copy of its session would still not repeat a key and nonce.

### Start and turns

The session starts from what pairing left: the root key, T, the owner's
first ratchet key (in the reply) and the scanner's (in the confirm). The
first root step, without an ML-KEM secret, takes the X25519 secret of those
two keys. For the scanner its chain key starts the first sending chain,
under the scanner's first ratchet key. For the owner the same chain key is
the first receiving chain, because the confirm already gave the owner the
scanner's key. Either phone may send first.

A sending chain starts with the first message a phone sends after the
contact's ratchet key changed, and with the owner's first message. It takes
a new X25519 key, whose secret with the contact's current ratchet key goes
into the chain's root step. Its headers carry the new public key and the
length of the phone's previous sending chain. When a message names a new
ratchet key, the receiver keeps the keys of the current receiving chain's
messages that have not arrived, up to the length the header names, takes
the same root step with its own current key, and the new chain begins.
Messages within one chain are numbered from 0.

### Post-quantum steps

A phone advertises an ML-KEM-1024 encapsulation key once its last
post-quantum step is 20 root steps or 24 hours old, whichever comes first.
The pairing counts as the first step. The same key goes in every header
until a chain answers it, and key IDs count from 1 on each phone.

When a phone starts a sending chain and holds the contact's newest
unanswered key, it encapsulates to that key and mixes the secret into the
chain's root step. Every message of that chain carries the ciphertext and
the key's ID, because any of them may be the first to arrive. That chain is
also the sender's own post-quantum step, so it advertises in it only if 24
hours then pass. The receiver decapsulates with its advertised key, mixes
the same secret into its root step, and deletes the key. ML-KEM keys are
stored as their 64-byte seeds.

### The message

| Field | Bytes | Contents |
| --- | --- | --- |
| Version | 1 | 1 |
| Flags | 1 | 1 when an advertised key follows, plus 2 when a ciphertext follows. Other bits zero |
| Ratchet key | 32 | The sender's current X25519 public key |
| Previous length | 4 | Messages in the sender's previous sending chain |
| Number | 4 | This message's number in its chain |
| Salt | 16 | Random |
| Advertised key | 4 + 1568 | Its ID, then the encapsulation key, with flag 1 |
| Answer | 4 + 1568 | The answered key's ID, then the ciphertext, with flag 2 |

The header of 58 to 3202 bytes is followed by AES-256-GCM of the envelope
and zero padding, the 16-byte tag last. The item is the smallest mailbox
size, 1024, 4096 or 16384 bytes, that holds them. The associated data is
`ito/message/1`, the sender's fingerprint 2, the recipient's fingerprint 2
and the header.

### Checks and bounds

A receiver refuses these and leaves the session as it was:

- MALFORMED: an item of another size, a header outside the table, a key ID
  of 0, a number or previous length of 2^20 or more, an envelope that is
  not canonical or whose padding is not zero, and an advertised key that
  fails FIPS 203's encapsulation key check.
- UNSUPPORTED: another version, or an envelope kind this core does not act
  on.
- ALREADY_SPENT: an earlier number in the current or the previous
  receiving chain whose key was used. A repeat delivery after a crash looks
  like this.
- CAPACITY: a message that needs more than 1000 kept keys in one chain, or
  more than 2000 in the session.
- AUTHENTICATION_FAILED: a message that does not decrypt, a new chain whose
  previous length is below what already arrived, and an answer to a key the
  receiver does not hold.

Kept keys live at most 30 days. Time is the session's clock, the newest
wall time the platform gave it, so a clock that moves back changes nothing.
A sending chain holds at most 2^20 messages (CAPACITY), which no
conversation reaches without a reply.

### Saving

Each contact's session is its own snapshot, which the core encodes and the
platform seals and publishes, as with the identity snapshot. It holds the
text of every unconfirmed message in the outbox, so it needs the same
protection as the history. The first opening takes the pairing's seed
exactly once: the core saves the session's first snapshot, then the
identity snapshot without the root key and both first ratchet keys, and
only then returns the session. A lost session therefore cannot start again
from the same keys. Pairing again gives a new T, and a session of the
earlier pairing is refused (WRONG_STATE).

Sending: advance the chain, save the session, then hand the sealed item to
the mailbox. Receiving: decrypt into a candidate state, hand the message to
the platform's history, which stores it or recognizes its ID as one it
holds, save the session, and only then tell the mailbox the item was taken.
A crash at any point leaves either a repeat delivery, which the history
recognizes by its message ID or the session refuses as ALREADY_SPENT, or
nothing changed. A refused save hands out nothing. An ambiguous save stops
the session until the platform opens it again from what storage holds.

A message that fails authentication is dropped and counted, and the session
stays as it was. An unreadable or corrupt session stops that chat with
"Secure session broken, pair again" (CORRUPT_STATE). It is never reset
silently, and the other chats and the identity stay intact.

Sessions open for paired contacts that are not Blocked, and sending and
receiving need a Verified contact (UNTRUSTED). An item from a contact not yet
Verified waits on the mailbox until the safety codes are compared. With app
lock on and the app locked, sessions are not opened.

| Session snapshot field | Bytes |
| --- | --- |
| Domain `ito/session-snapshot/1` | 23 |
| The contact's Ed25519 key, T | 32 + 32 |
| Root key | 32 |
| Session clock, last post-quantum step's time, root steps since it | 8 + 8 + 4 |
| Own ratchet private key, the contact's ratchet key | 32 + 32 |
| Sending flag, then with 1: chain key, next number, previous length, answer flag and with 1 the answered ID and ciphertext. With 0: the last sending chain's length | 1 + 48 + 4 + 4 + 1 + 4 + 1568, or 1 + 4 |
| Receiving flag, then chain key and next number | 1 + 48 + 4 |
| Previous receiving flag, then its ratchet key and next number | 1 + 32 + 4 |
| Last own key ID, flag, then the advertised key's seed | 4 + 1 + 64 |
| Highest answered ID of the contact, flag, then the contact's key ID and key | 4 + 1 + 4 + 1568 |
| Kept key count, then each: ratchet key, number, message key, time kept, ascending by ratchet key then number | 2 + 92 each |
| Outbox count, then each: envelope, time sealed, time last checked (0: never), in sealing order | 1 + 45 to 4140 each |

Opening refuses any malformed or inconsistent snapshot, such as a time
later than the session clock, a held key with ID 0, an answered ID above the
highest answered, a contact key that is not newer or fails FIPS 203's
check, kept keys out of order, and an outbox envelope that is not canonical,
is of a kind not kept, carries Resent or repeats an ID. With every list at
its bound and every field at its longest the snapshot is 717,492 bytes, the
bound the core computes, which `ratchet_test` measures, under the identity
snapshot's 1 MiB.

## Messages inside the ratchet

Each ratchet message holds one envelope.

| Field | Bytes | Contents |
| --- | --- | --- |
| Kind | 1 | Below |
| Message ID | 16 | Random. A resend keeps it |
| Sent | 8 | The sender's wall clock in milliseconds. A resend keeps it |
| Flags | 1 | 1 for Resent. Other bits zero |
| Payload length | 2 | At most 4096 |
| Payload | | As the kind says |

| Kind | Payload |
| --- | --- |
| 1 Text | 1–4096 bytes of UTF-8 without C0, DEL or C1 controls other than tab and newline, the content channel's chat text rule |
| 2 Receipt | 1 Delivered or 2 Read, then 1–64 message IDs |
| 3 Check | 1–64 message IDs the sender has no receipt for |
| 4 Missing | 1–64 IDs from a check that the receiver does not hold |
| 5 Ring, 6 Ring end | A call invitation, then canceled, declined, busy or missed. Specified with ringing |
| 7 Inbox | A new inbox address and relay, sent before moving. Specified with relay moves |
| 8 Profile | A new name hint, display only, under the contact name rules |
| 9 Timer | One byte: the chat's auto-delete setting, 0 off, 1 a day, 2 a week, 3 a month |

ID lists are strictly ascending, so each has one encoding, and only Text,
Profile and Timer carry Resent. Until ringing and relay moves are
implemented, a received kind 5, 6 or 7, like any other number, is
UNSUPPORTED.

Text, Profile and Timer wait in the sender's outbox until a Delivered or
Read receipt names them, at most 128 at once. Receipts, checks and missing
lists are rebuilt when needed and never kept. A check is due for a message
once the later of its sealing and its last check is one hold period old,
the hold time the recipient's mailbox granted (1 second to 30 days), and one
check lists up to 64 due messages, oldest first. A check is repeated each
hold period while anything stays unconfirmed. The receiver answers it with a
Delivered receipt for the IDs it holds and a Missing list for the others,
and the sender sends each missing one again: a new ratchet message with the
same envelope and the Resent flag.

A receiver keeps the IDs of the messages it holds, plus deleted IDs for 30
days, so a resend after a deletion does not bring the message back. That
record is the platform's history, which the core consults through the
receive call's delivery. Receipts and checks travel in batches.

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
`short-code`), `ito/mailbox-address/1`, `ito/ratchet/1 root`,
`ito/message/1 key`, `ito/message/1`, `ito/session-snapshot/1`,
`ito/invitation/2`, `ito/call-context/2` and `ito/call-auth/2`.

Stock OpenSSL 3.5.9, already pinned for the call core, provides every
primitive here: X25519, ML-KEM-1024, Ed25519, ML-DSA-87, HKDF and HMAC with
SHA-384, and AES-256-GCM. The core fetches each from its private library
context with `provider=default` when an operation needs it. A missing
primitive ends that operation with DEPENDENCY_FAILURE, and nothing falls back
to another provider. The vector generator holds the identity 2, pairing and
ratchet vectors and gains the invitation 2 vectors with ringing. ito4a's
test reads only `snapshot_1`, whose bytes are unchanged.

## Limits of the claim

The ratchet heals from a stolen key at the next turn against a classical
attacker and at the next post-quantum step against a quantum one. A phone has
one identity, and a second device is out of scope. The construction follows
published designs (Double Ratchet, PQXDH, Apple's PQ3), but this combination
has no formal analysis yet.
