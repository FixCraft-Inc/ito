# Mailbox service, version 1

The mailbox holds sealed items for a phone that is offline and pushes them to
a phone that is connected. It is the relay-host half of the
[messenger design](MESSENGER.md), and [mailbox/](../mailbox/README.md)
implements this contract as `ito-mailbox`. The items it carries are sealed end
to end by the [message ratchet](MESSAGE_SECURITY.md), so it stores nothing it
can read. The messenger's other parts are still designs.

## Where it runs

`ito-mailbox` is a YUME module beside `ito-call-relay` on the same host. It
follows the [relay contract](CALL_RELAY.md)'s ingress rules unchanged: yumed
checks the client's grant for the configured stream service, such as
`ito-mailbox`, before it opens the module socket. The service checks the
module header, the daemon UID with SO_PEERCRED and the private socket
directory, and refuses to run as root. A malformed header, another service
name or an untrusted peer closes the connection without a reply. The module
header's fingerprint is the transport principal that quotas and rate limits
count. YUME core does not change.

It is a separate process with its own dynamic user, because it keeps data on
disk and the call relay keeps none. Its configuration is the service name, the
numeric daemon UID and its data directory, given as command-line options, plus
an optional hold time and store size (see "Limits"). The data directory must
be a real directory owned by the service's user with no group or other
permission. The service refuses one that holds anything other than its own
store.

## Inboxes and addresses

An inbox is a queue of sealed items. Its owner creates a random 32-byte inbox
secret and keeps it. The inbox address is SHA-256 over ASCII
`ito/mailbox-address/1`, one zero byte and that secret. The owner gives the
address to one contact, in the pairing or later in an encrypted Inbox
message. That contact can deposit to the address but cannot read or delete
the inbox, because only the secret opens it.

| Secret | Address |
| --- | --- |
| bytes 0x00 to 0x1f in order | `9bedd192749f88c8b5eae4e9e6d52b83139294a47ba374bb032cc12906c1af00` |
| 32 bytes of 0xff | `849294bd70e8b7e1a3975968916f2b4afb25f0f1666eaca6004c5af8a526af09` |

Each phone has one inbox per contact, plus one short-lived pairing inbox per
open pairing code. Per-contact inboxes keep strangers out, let one contact be
blocked by closing one address, and keep identities off the disk. The service
never stores a secret. It derives the address and forgets the secret.

## Framing

After the module header, both sides send frames of a u32 big-endian body
length, a type byte and an exact payload. The length counts the type byte and
the payload. The service accepts bodies of 1 to 16424 bytes and refuses any
other length as soon as its four bytes arrive, before it buffers the body. The
longest body it sends is an ITEM of 16442 bytes. All integers are big-endian.

| Type | Frame | From | Payload |
| --- | --- | --- | --- |
| 1 | OPEN | Owner | u16 version = 1, then 1 to 512 inbox secrets of 32 bytes |
| 2 | OPENED | Service | One status byte per secret, in the order of the OPEN |
| 3 | ITEM | Service | u8 class, address 32, item ID 16, u32 deposit minute, u32 seconds left, sealed bytes |
| 4 | TAKEN | Owner | 1 to 512 item IDs of 16 bytes |
| 5 | CLOSE | Owner | u16 version = 1, inbox secret 32 |
| 6 | CLOSED | Service | One status byte |
| 7 | DEPOSIT | Sender | u16 version = 1, address 32, u8 class, u32 requested lifetime in seconds, sealed bytes |
| 8 | DEPOSITED | Service | Item ID 16, u32 granted lifetime in seconds |
| 9 | REJECTED | Service | One status byte. The deposit was not stored and the stream continues |
| 10 | PING | Either side's client | No payload |
| 11 | PONG | Service | No payload |
| 12 | REFUSED | Service | One reason byte, then the service closes the stream |

Classes are 1 message and 2 ring. Sealed bytes are exactly 1024, 4096 or
16384 bytes, which the frame length implies. A deposit minute counts whole
minutes since 1970-01-01 00:00 UTC, rounded down. Seconds left is how long the
service will still hold the item, rounded down.

OPENED, CLOSED and REJECTED share one status space:

| Status | Meaning |
| --- | --- |
| 1 | Done: the inbox is open, or closed |
| 2 | Not for this inbox. OPEN: this principal already holds 512 inboxes. DEPOSIT: the address is unknown, its registration ended, or the inbox is full |
| 3 | Try later: a rate limit, the service's capacity, or a full disk |

REJECTED never carries status 1, and CLOSED never carries status 2.

A client frame of an unknown or service-only type, a payload of the wrong
size, a class other than 1 or 2, or a requested lifetime of zero is invalid.
An OPEN, CLOSE or DEPOSIT whose first two payload bytes are a version other
than 1 is unsupported, whatever its length. REFUSED reasons keep the call
relay's numbers: 2 unsupported protocol, 3 capacity, 5 timeout and 6 invalid
request. There are no textual errors. After REFUSED the service flushes what
the stream already holds, for at most one second, and closes it.

## Order and timing

The service handles one request of a stream at a time, in the order the
stream sent them. It answers each OPEN, CLOSE, DEPOSIT and PING with exactly
one OPENED, CLOSED, DEPOSITED or REJECTED, or PONG, in that same order, so a
client can send several requests and match the replies by position. TAKEN has
no reply. ITEM frames are pushed whenever an item is ready and may come
between any two replies.

A request that needs the disk, such as a new registration, a message deposit
or a close, holds the stream's later requests until it is stored. The service
also reads the next request only when the stream has room for its reply, so a
client that stops reading stops being served.

The module header and the stream's first frame share a five-second budget.
After that, a frame must arrive completely within five seconds of its first
byte. A stream that sends no frame for ten minutes, or whose next frame the
service cannot read for ten minutes because the client is not reading, is
refused with reason 5. Phones send PING about every four minutes on an idle
background stream. The exact interval is tuned on real phones against mobile
network timeouts and battery use.

## Opening an inbox

OPEN registers each inbox, or renews its registration, and subscribes the
stream to it. For each secret, in order, the service derives the address and
answers:

- Status 1 when the inbox was registered, or is now. Its items follow.
- Status 2 when the inbox would be this principal's 513th.
- Status 3 when the principal sent more than 30 OPEN and CLOSE frames in the
  last 60 seconds (then every secret in the frame gets it), when the service
  holds its maximum number of inboxes, when the store is full, or when the
  disk refused the new registration.

A new registration is on disk and synced before its status 1 is sent.
Registrations count against the principal whose OPEN last succeeded for them.
The service keeps that link in memory only, so after a restart the next OPEN
counts the inbox again.

A registration lasts until 00:00 UTC on the 30th day after the UTC day of its
last OPEN, so between 29 and 30 days. An inbox whose phone stopped coming back
then disappears with its items.

An inbox has at most one subscribed stream. An OPEN on another stream moves
the subscription there, and the earlier stream receives nothing more from that
inbox. After its status 1, the stream receives every item the inbox holds,
oldest first, then each new item as soon as it is stored. Each OPEN starts the
inbox's delivery over from its oldest item, so a phone that lost an item can
ask again. A phone that only sends opens no inbox and stays connected only
while it deposits.

## Taking and closing

TAKEN names items the phone has stored. The service forgets each one that
belongs to an inbox this stream holds open, stops delivering it and deletes it
from disk. It ignores any other ID, so repeating a TAKEN is harmless. A
deletion is not synced: a crash just after it can deliver the item once more,
which the receiving phone recognizes by its message ID.

CLOSE deletes an inbox with everything in it. The deregistration is on disk
and synced before CLOSED 1 is sent, so a closed inbox never returns after a
restart, and the items are deleted after it. Closing an inbox nobody
registered also answers 1. A CLOSE beyond the principal's 30 OPEN and CLOSE
frames in 60 seconds answers 3 and changes nothing.

## Depositing

A DEPOSIT names the recipient's address, the class, a requested lifetime and
the sealed bytes. The service checks, in this order:

1. The principal's rate: more than 120 DEPOSIT frames in the last 60 seconds
   answers REJECTED 3. Every DEPOSIT counts, stored or not.
2. The inbox: an address nobody registered, a registration that ended, an
   inbox already holding 512 items or 8 MiB of sealed bytes, and a ring to an
   inbox already holding 4 rings all answer REJECTED 2, at once and after the
   same work.
3. The service: a full store, rings filling the memory reserved for them, or a
   failed random source answers REJECTED 3.

The service grants the requested lifetime up to a cap: 60 seconds for a ring
and the hold time for a message. It gives the item a random 16-byte ID, unique
in the service. A ring is held in memory only and is answered at once. A
message is written to disk and synced before DEPOSITED. If the disk is full,
the deposit answers REJECTED 3 and nothing remains of it. Once stored, the
item is pushed to the inbox's subscribed stream, if there is one.

## Holding and deleting

An item leaves the service when its owner takes it, when its lifetime ends,
or when its inbox is closed or its registration ends. A message expires at its
deposit time plus its granted lifetime, rounded up to a whole minute. A ring
expires exactly its granted lifetime after its deposit. A restart loses every
pending ring, as it loses call rooms today, and keeps every stored message
and registration. Expiry and registration days follow the host's clock, so
moving that clock moves them.

The hold time is the longest lifetime the service grants a message. The
default is 7 days, and an operator may set anything from one day to 30. On
disk a message is its sealed bytes, its address, its item ID, its expiry
minute, its deposit minute and its place in the store's deposit order, which
keeps delivery oldest first across a restart. A registration is its address
and the day it ends. Transport principals are used only in memory, for quotas and rate
limits, and are never written beside an item.

A full disk refuses the work that needed space. Any other storage failure
stops the service with exit status 1, so its supervisor restarts it from what
the disk holds. Streams end, and phones reconnect and open their inboxes
again.

## Limits

| Limit | Version 1 |
| --- | --- |
| Item sizes | 1024, 4096 or 16384 bytes exactly |
| Secrets per OPEN, item IDs per TAKEN | 512 |
| Items per inbox | 512, and 8 MiB of sealed bytes |
| Pending rings per inbox | 4 |
| Ring lifetime | At most 60 seconds |
| Message lifetime | At most the hold time: 7 days, or 1 to 30 days as the operator sets |
| Registration | 29 to 30 days after the last OPEN |
| Inboxes per transport principal | 512 |
| Inboxes in the service | 65536 |
| Store on disk | 2 GiB, or less as the operator sets. Each inbox counts one 4 KiB block and each message its size in whole 4 KiB blocks |
| Rings in memory | 32 MiB of sealed bytes |
| Streams | 1024, and 4 per principal |
| Principals in memory | 16384 |
| DEPOSIT frames per principal | 120 in any 60 seconds |
| OPEN and CLOSE frames per principal | 30 in any 60 seconds |
| Frame parsing budget | 5 seconds, as in the call relay |
| Idle stream | Refused after 10 minutes without a frame |

The hold time and the store size are the operator's settings. The other limits
are fixed in version 1. At a limit the service refuses the new work. It never
evicts another inbox's items or another principal. A principal stays in
memory while it has a stream or a registered inbox, and for 60 seconds after
its last counted frame. A new principal beyond the table's capacity, or a
fifth stream of one principal, is refused with reason 3.

## Reaching another relay

Phones deposit to the recipient's relay. When that is not their own, they open
a second short YUME connection to it, which works only with a grant for that
server's `ito-mailbox` service. A provider plan that covers all of the
provider's relay servers gives that grant. The service never forwards items to
another relay. Forwarding between relays belongs to the later federation
phases.

A relay open to anyone, run by a volunteer or another provider, comes with
YUME's decentralized network. The quotas above count per transport principal,
and on an open relay a new principal costs nothing, so that relay needs limits
of another kind before it can accept deposits from strangers.

## What the operator learns

The operator sees which transport principal opens which inboxes and which
principal deposits to which address, so it can tell which devices talk to
each other and when. It sees padded sizes, classes, how many inboxes a phone
opens, and when a phone keeps a stream open. It cannot read items, link an
address to a contact's name, or learn identity keys. A copy of the disk holds
sealed messages under addresses, with expiry and deposit minute, and no
principal, secret or ring.

The service logs fixed status lines and aggregate counts only, as the call
relay does. It never logs a principal, a secret, an address, an item ID or
sealed bytes.

## Acceptance

Tests use real native clients through yumed, like the call relay's harness,
including a client whose identity lacks the grant. They cover open, deposit,
push and take across a restart, and refusal of an unknown address, a full
inbox, a wrong size and an ungranted client. They also cover expiring
registrations and lifetimes, rings lost on restart, quotas and rate limits,
slow readers, a full disk, and a phone that reconnects in the middle of a
delivery. A sanitizer build runs the same suite.
