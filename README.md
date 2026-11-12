# Ito core

Ito (糸, Japanese for "thread") is a private calling system. This repository
holds its portable parts: the end-to-end call core, the operator's call relay
and the contracts they implement. The Android app is
[ito4a](https://github.com/FixCraft-Inc/ito4a), which consumes this repository
the way yume4a consumes YUME. The source is AGPL-3.0-or-later.

| Path | Contents |
| --- | --- |
| [call/](call/README.md) | The call core: C++20, no Android or JNI dependency, one C interface in [`ito/call.h`](call/include/ito/call.h), and the Linux `ito-call` test endpoint |
| [relay/](relay/README.md) | `ito-call-relay`, the opaque two-party relay that operators run as a YUME module |
| [docs/CALL_SECURITY.md](docs/CALL_SECURITY.md) | Local identity, contact verification and the end-to-end channel |
| [docs/CALL_RELAY.md](docs/CALL_RELAY.md) | The relay's service contract |
| [docs/CONTENT_CHANNEL.md](docs/CONTENT_CHANNEL.md) | Audio and chat envelopes inside a call |
| [docs/SECURITY_COMPONENT.md](docs/SECURITY_COMPONENT.md) | Why the channel uses this TLS component, and how to repeat the evaluation |
| [docs/MESSENGER.md](docs/MESSENGER.md) | Design, not implemented: chats, ringing calls and offline messages between verified contacts |
| [docs/MESSAGE_SECURITY.md](docs/MESSAGE_SECURITY.md) | Design, not implemented: post-quantum identity, pairing, the message ratchet and call invitations as messages |
| [docs/MAILBOX.md](docs/MAILBOX.md) | Design, not implemented: the relay-host service that holds sealed messages for offline phones |
| [tools/](tools/) | The Android builder and the component evaluation |

The core reaches the network through [YUME](https://github.com/FixCraft-Inc/yume)'s
public C interface and has no private dependency on it. The app owns the
microphone, playback, codecs, secret storage and every screen.

## Building

[call/README](call/README.md#building-and-testing) and
[relay/README](relay/README.md) give the Linux builds and their test suites.

`tools/build_call_core.sh` builds `libitocall.so` for Android. It checks the
pinned OpenSSL archive and the library's exported surface, and writes
`provenance.json` with the source commit. It refuses a dirty tree or an
unsigned commit, and `--unverified-source` waives that for debug tests only.
`--verify-source-only` runs that check alone, which ito4a does before each
build.

## Versions

Each of these moves on its own. The core's version is in
[`call/CMakeLists.txt`](call/CMakeLists.txt), the exported interface's symbol
version (`ITO_CALL_1`) is in [`exports.map`](call/src/exports.map), and wire and
profile numbers are in their contract pages. The app's version is in ito4a and
does not follow any of them.
