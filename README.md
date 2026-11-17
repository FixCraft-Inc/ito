# Ito core

Ito (糸, Japanese for "thread") is a private calling system. This repository
holds its portable parts: the end-to-end call core, the operator's call relay
and mailbox, and the contracts they implement. The Android app is
[ito4a](https://github.com/FixCraft-Inc/ito4a), which consumes this repository
the way yume4a consumes YUME. The source is AGPL-3.0-or-later.

| Path | Contents |
| --- | --- |
| [call/](call/README.md) | The call core: C++20, no Android or JNI dependency, one library with the C interfaces [`ito/call.h`](call/include/ito/call.h) and [`ito/message.h`](call/include/ito/message.h), and the Linux `ito-call` test endpoint |
| [relay/](relay/README.md) | `ito-call-relay`, the opaque two-party relay that operators run as a YUME module |
| [mailbox/](mailbox/README.md) | `ito-mailbox`, the YUME module that holds sealed messages for offline phones and pushes them to connected ones |
| [module/](module/README.md) | The module header, listener checks and startup code the relay and the mailbox share |
| [docs/CALL_SECURITY.md](docs/CALL_SECURITY.md) | Local identity, contact verification and the end-to-end channel |
| [docs/CALL_RELAY.md](docs/CALL_RELAY.md) | The relay's service contract |
| [docs/CONTENT_CHANNEL.md](docs/CONTENT_CHANNEL.md) | Audio and chat envelopes inside a call |
| [docs/SECURITY_COMPONENT.md](docs/SECURITY_COMPONENT.md) | Why the channel uses this TLS component, and how to repeat the evaluation |
| [docs/MESSENGER.md](docs/MESSENGER.md) | Chats, ringing calls and offline messages between verified contacts, with the Android integration and its remaining device checks |
| [docs/MESSAGE_SECURITY.md](docs/MESSAGE_SECURITY.md) | Post-quantum identity 2, pairing, the message ratchet and the messages inside it, implemented in `call/`. Rings carry call invitations through the ratchet |
| [docs/MAILBOX.md](docs/MAILBOX.md) | The mailbox service's contract, implemented in `mailbox/` |
| [tools/](tools/) | The Android builder and the component evaluation |

The core reaches the network through [YUME](https://github.com/FixCraft-Inc/yume)'s
public C interface and has no private dependency on it. The app owns the
microphone, playback, codecs, secret storage and every screen.

## Building

[call/README](call/README.md#building-and-testing),
[relay/README](relay/README.md) and [mailbox/README](mailbox/README.md) give
the Linux builds and their test suites.

`tools/build_call_core.sh` builds `libitocall.so` for Android. It checks the
pinned OpenSSL archive and the library's exported surface, and writes
`provenance.json` with the source commit. It refuses a dirty tree or an
unsigned commit, and `--unverified-source` waives that for debug tests only.
`--verify-source-only` runs that check alone, which ito4a does before each
build.

## Versions

Each of these moves on its own. The core's version is in
[`call/CMakeLists.txt`](call/CMakeLists.txt), the exported interface's symbol
version (`ITO_CALL_1`) is in [`exports.map`](call/src/exports.map), each header
carries its own interface version (`ITO_CALL_INTERFACE_VERSION`,
`ITO_MESSAGE_INTERFACE_VERSION`), and wire and profile numbers are in their
contract pages. The relay's and the mailbox's program versions are in their
CMake projects, and the mailbox's store format is named in its `format` file.
The app's version is in ito4a and does not follow any of them.
