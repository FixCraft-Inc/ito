# Ito as a messenger

Ito pairs contacts once for messages and calls. This design covers the complete
messenger: two people verify each other once, then chat and call. The core
implements identity 2, pairing, the
ratchet, the messages inside it and ringing calls, and `mailbox/` the
mailbox. The Android consumer integrates foreground pairing, text, receipts
and per-chat history, authenticated incoming ringing and opt-in background
reachability. Two companion pages hold the
details: [message security](MESSAGE_SECURITY.md) for keys and protocol, and
[mailbox](MAILBOX.md) for the service that holds messages for a phone that is
offline. Until an implementation replaces part of them, the
[calling security](CALL_SECURITY.md), [relay](CALL_RELAY.md) and
[content channel](CONTENT_CHANNEL.md) contracts still describe Ito.

## What a person sees

Ito opens on a list of chats. Each chat holds the conversation with one
contact, a Call button and the contact's profile. The connection and Settings
keep their own tabs, and an ordinary day needs neither.

Adding someone takes one meeting. One phone shows a code and the other scans
it. Both screens then show the same six digits, the first person taps Matches,
and the chat opens. After that, messages and calls need no QR code. Tap Call
and the other phone rings, as long as it can reach its relay.

A message to someone who is offline waits, sealed, on their relay. When they
come back it arrives showing when it was written. If it waited longer than the
relay keeps messages, Ito asks the contact whether it arrived and sends it
again if not. The copy is marked Resent and still shows the original time.

## The parts

| Part | What it does | Owner |
| --- | --- | --- |
| [Identity 2](MESSAGE_SECURITY.md#identity-2) | Adds a post-quantum signing key to today's Ed25519 key | Core |
| [Pairing](MESSAGE_SECURITY.md#pairing) | The one meeting: swaps identities, starts the shared secret, records each other's relay | Core |
| [Ratchet](MESSAGE_SECURITY.md#ratchet) | Encrypts each message with its own key and refreshes the shared secret as the chat goes on | Core |
| [Ringing](MESSAGE_SECURITY.md#calls-without-a-qr-code) | Sends the call invitation as an encrypted message instead of a QR code | Core |
| [Mailbox](MAILBOX.md) | Holds sealed messages for an offline phone and pushes them to a connected one | Relay-host module, [mailbox/](../mailbox/README.md) |
| Screens, storage, background | Chats, profile, ringing, notifications and the stay-reachable setting | ito4a |

The protocol and its cryptography go in the portable core, beside the call
code, with a new C interface `ito/message.h` in the same library. The Linux
`ito-call` endpoint pairs, chats and rings as well, so the harness can test
two endpoints without phones. The app keeps the screens, the encrypted local
storage and the Android lifecycle. YUME needs no change: the mailbox is one
more module behind yumed's existing named-service grant check.

## First meeting

The meeting leaves both phones with each other's identity, a secret only the
two of them know, and the address where the other one receives messages.

1. Ana taps Add contact. Her phone shows a pairing code on a secure window.
   The code holds a one-time secret, her identity fingerprint and the name of
   her relay. It works once and expires after ten minutes.
2. Ben scans it. His phone sends Ana a sealed hello through her relay. Only a
   phone that saw the code can write that hello.
3. Ana's phone checks Ben's signatures and answers. Ben's phone checks that
   the answer comes from the identity whose fingerprint was in the code.
4. The phones now share a secret made from a classical and a post-quantum key
   exchange. Both show the same six-digit short code. Ana compares it with
   Ben's screen and taps Matches. Each is now Verified for the other.

Ben trusts Ana because he scanned her fingerprint from her own screen. Ana
trusts Ben because the phone she paired with is the one showing her code. If
someone photographed her screen and paired first, Ben's phone gets no answer
and shows no digits, and Ana taps Doesn't match.

Far apart, Ana shares a pairing link through any app instead. Ito cannot vouch
for that app, so the contact stays Not verified until the two compare their
full safety code (60 digits) over a channel they trust, such as an ordinary
phone call, or until they meet and scan. The six-digit code does not help at a
distance, because someone sitting inside that app could try key after key
until two short codes match. Chat and calls wait until a contact is
Verified, as calls do today, and a Not verified chat offers only Compare
safety codes.

Existing contacts have only an Ed25519 key and no shared secret, so each pair
meets once more after the upgrade. The app keeps their names and history.

Every Ito code goes through one scanner, which says what it found. A pairing
code starts pairing. A safety code opens the comparison for that contact. Any
other text gets a message naming what was scanned. The scanner never ignores
a code.

## Sending a message

Ben types and taps Send. His phone stores the message, the core encrypts it
with the next message key, and the app hands the sealed item to Ana's mailbox
over Ben's YUME connection. A mark under the bubble follows it:

| Mark | Meaning |
| --- | --- |
| Clock | Not sent yet, because Ben is offline or the relay has not accepted it |
| One tick | Ana's relay holds it |
| Two ticks | Ana's phone stored it |
| Two ticks, filled | Ana opened the chat |

Delivery receipts are always on, because Ito needs them to know what to send
again. Read receipts are on by default and a Settings switch turns them off.
That switch works both ways, so with it off a person also sees no read marks
from others.

Messages appear in the order they arrive, each labeled with the time its
sender wrote it. Details for a message show the arrival time too.

## When the contact is offline

- Ana's relay keeps the sealed message until the hold time runs out. The
  default is 7 days. An operator may configure anything from one day to 30.
- If no delivery receipt has arrived by then, the bubble reads "Not delivered
  yet". Ben's phone still has the message in its outbox.
- Ben's phone then sends one check listing every unconfirmed message. The
  check waits in Ana's mailbox like any message and is repeated each hold
  period while anything stays unconfirmed.
- When Ana comes back, her phone answers the check with the messages it has
  and the ones it lacks. Ben's phone sends the missing ones again. Each copy is
  a new encrypted message with the same message ID, the original time and a
  Resent mark.
- Ana's phone drops any message ID it already holds, so sending again is
  always safe. A resent message lands at the bottom of the chat, where Ana
  will see it, labeled Resent and showing when Ben wrote it.

## Calling without a QR code

1. Ben taps Call in Ana's chat. His phone reserves a room on Ana's relay and
   sends her a ring: an encrypted message with the same contents the QR code
   carries today (room, Ana's room token and a fresh call secret).
2. Ana's phone rings if Ito is open, or if she turned on "Get messages and
   calls while Ito is closed". The ring names Ben, because only Ben's phone
   could have encrypted it to her.
3. Ana taps Accept. Her phone joins the room and today's call handshake runs.
   Both identities are now proven with the post-quantum signatures as well.
   Decline sends Ben a short "declined" message instead.
4. If nobody answers within 45 seconds, Ben's phone stops, releases the room
   and leaves "Missed call" in the chat. Ana sees it when she next connects.

A ring lives at most 60 seconds on the relay, in memory, never on disk. Calls
keep today's end-to-end channel, audio and limits.

## Reaching a closed phone

This is off by default, and on only when the person turns it on in Settings.
The setting reads "Get messages and calls while Ito is closed". When it is
on, Ito keeps its YUME connection and its mailbox stream open from a
foreground service. Android shows a permanent notification for that, such as
"Ito is ready for messages". The relay pushes each new item down the open
stream. When the setting is off, messages wait on the relay until
Ito is opened, and only an open Ito can ring.

Authenticated incoming calls can wake the phone with an isolated Accept/Decline
screen over its device lock screen. Accept dismisses the device keyguard before
opening the full app. Android may require full-screen alert access or present
a notification instead. Showing the screen does not unlock Ito's app lock or
start audio. Answer starts audio once the call connects.

The cost is battery for the keepalive (one small exchange every few minutes)
and a radio that wakes for each message. Doze, vendor battery savers such as
Samsung's sleeping apps, and the foreground service type that Android 14 and
later require all need checking on real phones before any claim. Push through
Google or UnifiedPush stays a later, separate choice, because the push
operator learns when a phone receives something.

With app lock on and the app locked, Ito's keys stay locked too. An existing
mailbox stream can buffer sealed items and show a generic unlock notice. A
relay's item class is not peer authentication, so newly arrived items cannot
ring until unlock authenticates them. An invitation authenticated before lock
can show "Ito call, unlock to answer" until its original deadline. Unlock never
extends that deadline. Reconnecting needs new credential access and waits for
unlock. The Android [lifecycle contract](https://github.com/FixCraft-Inc/ito4a/blob/main/docs/MESSAGING_LIFECYCLE.md)
owns the implementation limits. With app lock off, a notification shows the
contact's name and the text, and the lock screen hides the text unless Android's own setting allows
private content there. Settings can hide the text everywhere.

Ito connects by itself while open and while the opt-in foreground service
owns its connection. It reconnects after a network change through the selected
service, under
the same network rule as today. It never switches to another service, a
direct route, or around a VPN. The Service tab keeps Disconnect for anyone
who wants to stay offline.

## Contacts on different relays

Each side records the other's home relay during pairing, and messages and
calls go to the recipient's relay. Usually both use the same one. A provider
plan that covers all of its relay servers (FixCraft One does) also lets Ben on
US2 reach Ana on JP: his phone opens a second, short YUME connection to JP.
Contacts with different operators can reach each other only when the sender
also has access to the recipient's relay. Relays forwarding messages to one
another belongs to the later federation phases.

The first implementation supports contacts on one shared relay. The second
connection comes next. When Ana moves to another relay, her phone tells each
contact the new address in an encrypted message before it leaves the old one.

Later, providers and volunteers may open their relays to people who are not
their customers, with YUME's decentralized network and its bootstrap servers.
Nothing in this design blocks that: inbox addresses are not tied to accounts,
and items are sealed end to end, so an open relay learns no more than a
provider's. It does need limits against abuse that do not rest on an account,
a trust policy for relays nobody vouches for, and meeting through relays of
independent operators, because a single relay still sees which devices talk.

## What each party learns

The relay is blind to content whether or not keys rotate, because it never
holds Ito's keys. Rotation does something else: if a phone's keys leak, the
thief can read only a short stretch of the conversation, not what came before
and, after the next refresh, not what comes after.

| Who | Sees | Does not see |
| --- | --- | --- |
| Relay operator | Which YUME device identities deposit to and fetch from each inbox, and so who talks to whom. Also when, padded sizes, how many contacts an inbox serves, when a phone is connected, and each call's timing and length | Text, audio, names, identity keys, safety codes |
| Provider | Which account owns each device identity, so with the relay's view it can name both people | The same as the relay |
| Network near a phone | A YUME connection to the server, with its timing and volume | That it carries Ito, or who the contact is |
| A copy of the relay's disk | Sealed items under random addresses, with deposit times and sizes | Who sent them or who receives them |
| The contact | Your messages, your name hint, your fingerprint, your relay, and when you read their messages if read receipts are on | Your other contacts |

Each contact gets its own inbox address. That stops strangers from dropping
messages into an inbox, makes blocking one closed address, and leaves no
identities on the relay's disk. It does not hide who talks to whom from a
running relay, because one connection opens all of a phone's inboxes. Circuits
would not change that while one operator runs every hop, and Ito's adapter
refuses circuits today. Item sizes are padded to a few fixed sizes. There is
no cover traffic.

## Screens

The tabs stay as they are, with Calls renamed Chats: Chats, Service, Settings.
The look is Ito's own: its palette (the system palette on Android 12 and
later, Ito's green before that), Material 3 components, and its own icons
where they carry meaning. The layout keeps the shapes people already know from
messengers (a list, bubbles, a call button at the top of a chat) and takes no
colors, icons, wallpapers or motion from any other app.

Trust shows in one place everywhere: the ring around a contact's picture. A
solid ring means Verified. A dashed ring means Not verified, and that chat
offers Compare safety codes in place of the message field.

```text
Chats                          Chat
┌───────────────────────────┐  ┌───────────────────────────┐
│ Ito                    ⌕  │  │ ←  (A) Ana             ☎  │
├───────────────────────────┤  ├───────────────────────────┤
│ (A) Ana          14:02  2 │  │        Tue 12 Nov         │
│     See you at six        │  │ ┌──────────────┐          │
│ (B) Ben            Mon    │  │ │ Running late │          │
│     Missed call           │  │ └──────────────┘          │
│ (K) Kenji      Not verif. │  │          ┌─────────────┐  │
│     Compare safety codes  │  │          │ No problem  │  │
│                           │  │          └──── 14:03 ✓✓┘  │
│                      [ + ]│  │   ( Outgoing call 4:12 )  │
├───────────────────────────┤  ├───────────────────────────┤
│  Chats  Service  Settings │  │ [ Message            ] ➤  │
└───────────────────────────┘  └───────────────────────────┘
```

- Chats: the title becomes "Connecting…" or "Waiting for network" while Ito
  is offline, and tapping it opens Service. Each row shows the picture with
  its ring, the name, the last message or call, the time and an unread count.
  Every contact has a chat, so there is no separate contacts list. The add
  button opens Add contact.
- Add contact: Show my code (the pairing code, large), Scan a code, Share a
  link. Pairing ends on the short-code comparison, then a name field filled
  with the name the contact offered.
- Chat: the top bar holds the picture and name, which open the profile, and
  Call. Calls appear in the timeline as small centered notes. A long press
  gives Copy, Delete for me and Details (written, arrived, resent). Banners
  explain when Ito is offline or the contact's relay is out of reach.
- Profile: picture, name (editable, local only), how and when the contact was
  verified, Message, Call, Safety code, Mute, Auto-delete, Remove contact and
  Block. The
  fingerprint and the home relay show in Advanced mode.
- Incoming call: full screen, with the picture, the name, Decline and Accept.
  The locked variant shows "Ito call, unlock to answer".
- Settings: Privacy (app lock, read receipts, notification text), "Get
  messages and calls while Ito is closed", your own safety code, display, Delete
  all chats, About.
- Service: today's page (provider, server, configuration file), with
  Disconnect.

Screen readers hear the marks as words (Sent, Delivered, Read). Bubbles mirror
in right-to-left languages, and large text wraps inside bubbles instead of
cutting them off.

## Local history

The Android consumer migrates its old global 256-message, 30-day store to
one encrypted history per chat, under the same content key and app lock.
Its [local storage contract](https://github.com/FixCraft-Inc/ito4a/blob/main/docs/LOCAL_CONTENT.md)
owns the exact bounds, publication and recovery behavior. History stays until
the person deletes it. Each chat can also turn on an
auto-delete timer (a day, a week or a month). The timer is shared: changing it
sends both phones the new setting, and both show it in the chat. It deletes
local copies only and promises nothing about a contact's screenshots or a
modified app.

## Outside this design

Group chats, more than one device per person, photos, files and voice notes,
push services, last seen and typing indicators, calls across operators without
access, and direct calls without a relay. Photos, files and voice notes come
after text works, and each item on this list needs its own design.
