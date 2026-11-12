# Shared module code

Every Ito service that runs as a YUME module receives its streams the same
way, and this directory holds that code once for the
[call relay](../relay/README.md) and the [mailbox](../mailbox/README.md):

- `module_header` parses the line yumed writes before each stream, with the
  client's key fingerprint and the service name, and checks the name against
  YUME's service-name grammar.
- `listener` checks the inherited listening socket, its file and its
  directory, so that only the daemon's user and root can connect, and
  `trusted_peer` applies the same rule to each connection's `SO_PEERCRED`.
- `process` parses the daemon UID option, matches systemd's activation
  variables, raises the open-file limit and sets up the stopping signals.
- `descriptor.hpp` owns one file descriptor.
- `tests/check.hpp` is the check macro the module tests use.

A module's CMake project adds this directory with `add_subdirectory` after
setting its compile options, so the library is built with the module's own
warnings and sanitizers. With `ITO_MODULE_TESTS` set, it also registers
`ito_module_test`, the header and option grammar vectors.

YUME's [module guide](https://github.com/FixCraft-Inc/yume/blob/main/docs/MODULES.md)
owns the header, socket and unit contract this code follows.
