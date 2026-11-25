# Ito core

Ito is a messaging and audio calling app. Its name (糸, Japanese for
"thread") refers to the connection between the people using it. This
repository contains the portable call and messaging library, the operator's
call relay and mailbox, and their protocol documentation. The
[Android app](https://github.com/FixCraft-Inc/ito4a) uses this library.
The source is licensed under [AGPL-3.0-or-later](LICENSE).
[THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md) lists the third-party code
the builds include and its licenses.

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

The core uses [YUME](https://github.com/FixCraft-Inc/yume)'s public C
interface for transport. The Android app handles audio devices, codecs,
secret storage and screens.

## Building

The Linux builds need a C++20 compiler, CMake 3.25 or later and Ninja. The
tests need Python 3.11 or later.
[call/README](call/README.md#building-and-testing),
[relay/README](relay/README.md#build-and-test) and
[mailbox/README](mailbox/README.md#build-and-test) give the builds and their
test suites.

The `peer_credentials` cases of the relay and mailbox component tests run
processes as three different users. They need `unshare` and `setpriv` from
util-linux, `newuidmap` (the `uidmap` package on Debian and Ubuntu) and
subordinate user and group IDs for your account. Without them
`ito_relay_component_test` and `ito_mailbox_component_test` fail. The relay
and mailbox pages show how to run the rest of those tests without them.

### The YUME shared library

The Linux `ito-call` endpoint and the harnesses that run behind a real yumed
use YUME's shared C library, `libyume.so`. YUME builds it only when asked. In
a [YUME](https://github.com/FixCraft-Inc/yume) checkout:

```sh
YUME_CMAKE_ARGS=-DYUME_BUILD_SHARED_ABI=ON ./ezbuild.sh --no-pull
```

`--no-pull` builds the checkout as it is instead of fast-forwarding it first.
`$YUME_BUILD` in these pages is that YUME build directory, `build` inside the
checkout unless `YUME_BUILD_DIR` names another. It holds `bin/yumed`,
`bin/yume-setup`, `bin/yume-resolver` and `src/libyume.so`. The public header
is the checkout's `include/yume/yume.h`.

### The Android library

`tools/build_call_core.sh` builds `libitocall.so` for Android. It checks the
pinned OpenSSL archive and the library's exported surface, and writes
`provenance.json` with the source commit. It refuses a dirty tree or an
unsigned commit, and `--unverified-source` waives that for debug tests only.
`--verify-source-only` runs that check alone, which ito4a does before each
build.

The signature check runs `git verify-commit HEAD`, so your GnuPG keyring needs
the signer's public key:

```sh
curl -fsSL https://github.com/F1xGOD.gpg | gpg --import
```

Current commits on `main` are signed with the ed25519 key
`9672 78FF 6FA4 36F5 04CB  B005 8A15 88B5 E259 8DB1`.
`git verify-commit HEAD` prints the fingerprint of the key that signed the
checkout. Compare the two before you rely on the check.

## Versions

Each of these moves on its own. The core's version is in
[`call/CMakeLists.txt`](call/CMakeLists.txt), the exported interface's symbol
version (`ITO_CALL_1`) is in [`exports.map`](call/src/exports.map), each header
carries its own interface version (`ITO_CALL_INTERFACE_VERSION`,
`ITO_MESSAGE_INTERFACE_VERSION`), and wire and profile numbers are in their
contract pages. The relay's and the mailbox's program versions are in their
CMake projects, and the mailbox's store format is named in its `format` file.
The app's version is in ito4a and does not follow any of them.
