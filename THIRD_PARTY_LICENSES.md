# Dependency licenses

Ito's core uses AGPL-3.0-or-later, copyright 2026 FixCraft Inc.
[LICENSE](LICENSE) contains the complete terms. Third-party code retains its
respective grants and attributions.

## Call core

The [call core](call/README.md), `libitocall.so`, statically links stock,
unpatched OpenSSL 3.5.9 under Apache-2.0, built from the release archive that
[`tools/security-component.json`](tools/security-component.json) pins by hash.
The release carries no separate NOTICE file. This copy of OpenSSL is separate
from the patched one inside libyume, and neither library exports OpenSSL
symbols. An app that packages the library owns its packaged notices, as ito4a
does.

## Call relay

The [relay](relay/README.md) links only the C++ standard library of the
compiler that builds it. Its yumed harness loads the operator's libyume and
YUME programs at test time and redistributes none of them.
