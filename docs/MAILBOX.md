# Mailbox service

Design, not implemented yet. The mailbox holds sealed messages for a
phone that is offline and pushes them to a phone that is connected. It is the
relay-host half of the [messenger design](MESSENGER.md). The messages it
carries are already encrypted end to end by the
[message ratchet](MESSAGE_SECURITY.md), so it stores nothing it can read.

## Where it runs

`ito-mailbox` is a new YUME module beside `ito-call-relay` on the same host.
It follows the [relay contract](CALL_RELAY.md)'s ingress rules unchanged:
yumed checks the client's grant for the named service (`ito-mailbox`) before
it opens the module socket, and the service checks the module header, the
daemon UID with SO_PEERCRED, the private socket directory, and refuses to run
as root. It is a separate process with its own dynamic user, because it keeps
data on disk and the call relay keeps none. YUME core does not change.

## Inboxes and addresses

An inbox is a queue of sealed items. Its owner creates a random 32-byte inbox
secret and keeps it. The inbox address is SHA-256 over ASCII
`ito/mailbox-address/1`, one zero byte and that secret. The owner gives the
address to one contact, in the pairing or later in an encrypted Inbox
message. That contact can deposit to the address but cannot read or delete
the inbox, because only the secret opens it.

Each phone has one inbox per contact, plus one short-lived pairing inbox per
open pairing code. Per-contact inboxes keep strangers out, let one contact be
blocked by closing one address, and keep identities off the disk.

## The conversation with the service

Each stream starts with the module header. After it, both sides send frames
of a u32 big-endian length, a type byte and an exact payload, as the call
relay does. Unknown types, extra bytes and frames in the wrong state end the
stream without a text reply.

| Frame | From | Meaning |
| --- | --- | --- |
| Open | Owner | Inbox secrets to open (up to 512). Each is registered, or its lease renewed, and its new items follow |
| Opened | Service | A status per secret: open, full or refused |
| Item | Service | Address, a random item ID, deposit time to the minute, and the sealed bytes |
| Taken | Owner | Item IDs the phone has stored. The service deletes them |
| Close | Owner | An inbox to delete with everything in it |
| Deposit | Sender | Address, class (message or ring), requested lifetime, sealed bytes |
| Deposited | Service | Item ID and the expiry the service granted |
| Ping, Pong | Either | Keepalive on a stream kept open in the background |
| Refused | Service | One reason byte, as in the call relay |

Opening an inbox also subscribes the stream to it. While that stream lives,
each deposit to the address is pushed to it at once, after it is safely
stored. A phone that only sends opens no inbox and stays connected only while
it deposits.

A deposit to an address nobody registered, or whose lease ran out, is refused
with the same reason and timing as a full inbox. Registrations last 30 days
from the last Open, so an inbox whose phone stopped coming back disappears.

## Holding and deleting

The service confirms a message deposit only after the item is on disk and
synced. An item leaves the disk when its owner sends Taken, when its lifetime
ends, or when its inbox is closed or expires. Ring items stay in memory only
and live at most 120 seconds, so a restart loses pending rings, as it loses
call rooms today.

The hold time is the longest lifetime the service grants a message. The
default is 7 days, and an operator may configure anything from one day to 30.
A sender may ask for less. On disk an item is its sealed bytes, its address,
its item ID, its expiry and its deposit minute. Transport principals are used
only in memory, for quotas and rate limits, and are never written beside an
item.

## Limits

Defaults for version 1, which an operator may lower:

| Limit | Default |
| --- | --- |
| Item sizes | 1, 4 or 16 KiB exactly. Other sizes are refused |
| Items per inbox | 512, and 8 MiB |
| Inboxes registered per transport principal | 512 |
| Open streams per principal | 4 |
| Deposits per principal | 120 in any 60 seconds |
| Pending rings per inbox | 4 |
| Disk for all items | 2 GiB, then new deposits are refused |
| Frame parsing budget | 5 seconds, as in the call relay |
| Idle stream | Closed after 10 minutes without a frame |

At a limit the service refuses the new work. It never evicts another inbox's
items. Phones send Ping about every four minutes on an idle background stream.
The exact interval is tuned on real phones against mobile network timeouts and
battery use.

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
each other and when. It sees padded sizes, how many inboxes a phone opens,
and when a phone keeps a stream open. It cannot read items, link an address
to a contact's name, or learn identity keys. A copy of the disk holds sealed
items under addresses, with expiry and deposit minute, and no principal. The
service logs counts and fixed reason codes only, as the call relay does.

## Acceptance

Tests use real native clients through yumed, like the call relay's harness.
They cover open, deposit, push and take across a restart, and refusal of an
unknown address, a full inbox, a wrong size and an ungranted client. They also
cover expiring leases and lifetimes, rings lost on restart, quotas and rate
limits, slow readers, a full disk, and a phone that reconnects in the middle
of a delivery. A sanitizer build runs the same suite.
