# ito-mailbox

`ito-mailbox` holds sealed items for phones that are offline and pushes them
to phones that are connected, as [MAILBOX.md](../docs/MAILBOX.md) specifies.
Like the [call relay](../relay/README.md), it is a YUME module. yumed
authenticates each client and checks its grant for the configured stream
service, then hands the stream to this program over a private UNIX socket.
Items arrive sealed end to end, so the mailbox stores bytes it cannot read
under addresses it cannot link to a contact.

The program is separate from the Android application and its Gradle build.
It needs Linux, a C++20 compiler, CMake 3.25 or later and Ninja, and links
only the C++ standard library. The tests need Python 3.11 or later.

## Build and test

```sh
cmake -S mailbox -B build/mailbox -G Ninja -DCMAKE_BUILD_TYPE=RelWithDebInfo
cmake --build build/mailbox
ctest --test-dir build/mailbox --output-on-failure
```

Warnings are errors by default. `-DITO_MAILBOX_SANITIZE=address,undefined`
builds every target with those sanitizers. `-DITO_MAILBOX_TESTS=OFF` builds
only the program.

## Run it with yumed

Declare the stream service on the server and give it a `module` adapter
that names the mailbox's socket. YUME's [module guide](https://github.com/FixCraft-Inc/yume/blob/main/docs/MODULES.md)
owns the adapter, socket and unit contract.

```json
{
  "services": [
    {"name": "ito-mailbox", "kind": "stream", "max_concurrent_streams": 8}
  ],
  "adapters": [
    {"kind": "module", "service": "ito-mailbox", "socket": "/run/yume-modules/ito-mailbox.sock"}
  ]
}
```

Grant the service to each identity that may hold an inbox on this server or
deposit to one, as `{"service": "ito-mailbox", "kind": "stream"}` in its
authorized-keys entry. yumed refuses every other identity before the mailbox
sees a byte.

With the YUME Debian package, install the program and point the module
template at it with a drop-in. `--daemon-uid` is the numeric user yumed runs
as. The template gives each module a state directory, and the mailbox keeps
its store there. systemd creates that directory readable by everyone unless
told otherwise, and the store refuses a directory open to group or others,
so the drop-in also sets its mode.

```sh
sudo install -D -o root -g root -m 0755 build/mailbox/ito-mailbox \
  /usr/libexec/ito/ito-mailbox
sudo systemctl edit yume-module@ito-mailbox.service
```

```ini
[Service]
ExecStart=
ExecStart=/usr/libexec/ito/ito-mailbox --service ito-mailbox --daemon-uid 999 --data /var/lib/yume-modules/ito-mailbox
StateDirectoryMode=0700
```

Replace `999` with the output of `id -u yume`. Then enable the socket and
restart the daemon:

```sh
sudo systemctl enable --now yume-module@ito-mailbox.socket
sudo systemctl restart yumed
```

The module service needs no network. Its default account name,
`yume-module-ito-mailbox`, fits the dynamic-user limits. systemd hands the
state directory to each new dynamic user, so the store survives restarts.

For development as one user, a private directory and
`systemd-socket-activate` give the same descriptor:

```sh
mkdir -m 0700 -p "$XDG_RUNTIME_DIR/ito/mailbox-data"
(umask 077 && systemd-socket-activate -l "$XDG_RUNTIME_DIR/ito/ito-mailbox.sock" \
  build/mailbox/ito-mailbox --service ito-mailbox --daemon-uid "$(id -u)" \
  --data "$XDG_RUNTIME_DIR/ito/mailbox-data")
```

## Options

| Option | Meaning |
| --- | --- |
| `--service NAME` | The service name yumed writes in each module header. It uses YUME's service-name grammar, at most 64 bytes. |
| `--daemon-uid UID` | The numeric user yumed runs as. |
| `--data DIR` | The store: an absolute path to a directory of the service's user with no group or other permission. An empty directory becomes a store. |
| `--hold-days DAYS` | The longest lifetime a message is granted, 1 to 30 days. The default is 7. |
| `--store-mib MIB` | The store's size, 1 to 2048 MiB. The default is 2048. |
| `--help`, `--version` | Print usage or the version. |

The other limits in the contract are fixed in version 1.

## What the program checks and reports

At startup the mailbox refuses to run as root and checks descriptor 3 as the
call relay does: a listening UNIX stream socket with a filesystem path,
owned by the daemon user with no group or other permission, in a real
directory that others cannot write. It checks each connection's peer with
`SO_PEERCRED` and closes any connection that does not come from the daemon
user or root before reading it.

It then opens the store. The last component of `--data` may be a symbolic
link, as systemd's state directories for dynamic users are, but nothing
inside the store may be one, and an entry the store never writes stops the
program. The startup scan removes registrations that ended, inboxes whose
creation or close did not finish, messages that expired or have no valid
size, and writes that never completed.

Registrations, closes and messages are on disk and synced before their
replies. A full disk refuses the work that needed space. Any other storage
failure stops the program with status 1, so its supervisor restarts it from
what the disk holds. A restart loses every pending ring and keeps every
stored message and registration. The listening socket stays open, so
streams opened meanwhile wait for the next run.

Exit status is 0 after SIGTERM or SIGINT, 1 when the mailbox cannot start,
its event loop fails or its disk fails, and 2 for a usage error. Standard
error carries one JSON object per line: `ready`, `stopped` or `failed` with
a fixed reason, `loaded` with what the startup scan found and removed, and
the aggregate counts that SIGUSR1 requests and a stop prints. Counts hold
numbers only, such as inboxes, stored bytes and replies by status. The
mailbox never logs a principal, secret, address, item ID, path or sealed
byte.

## Test suites

- `ito_mailbox_sha256_test` checks SHA-256 against the FIPS 180-4 examples
  and the contract's inbox address vectors.
- `ito_mailbox_wire_test` checks every frame's grammar against the
  contract's byte layout.
- `ito_mailbox_store_test` checks the data directory's rules, the files each
  operation leaves, the startup scan and a full disk. The full-disk case
  fills a small tmpfs in a private user and mount namespace, and the test
  reports itself skipped when the host forbids unprivileged namespaces.
- `ito_mailbox_table_test` checks registrations, deposits, delivery order,
  subscriptions, quotas, rate windows and every expiry on virtual time.
- `ito_mailbox_loop_test` runs the event loop in process with a real store
  and lowered limits: a moved host clock, timeouts, slow readers, restarts
  and a failing random source.
- `ito_module_test`, from [module/](../module/README.md), checks the module
  header grammar shared with the call relay.
- `component_test.py` runs the real program with the default limits against
  peers that write module headers as yumed would. Its `full_disk` case needs
  unprivileged user namespaces. Its `peer_credentials` case needs `unshare`,
  `setpriv` and `newuidmap` with subordinate IDs, to run the mailbox, the
  daemon and an untrusted client as three users. `--without-namespace`
  leaves both out:

```sh
ctest --test-dir build/mailbox --output-on-failure -E ito_mailbox_component_test
python3 -B mailbox/tests/component_test.py --mailbox build/mailbox/ito-mailbox \
  --without-namespace
```

- `yumed_harness.py` runs the program behind a real yumed with three
  identities provisioned by `yume-setup`, two granted and one not, and
  clients that use the public libyume C ABI. It needs those programs and the
  shared library from a YUME build directory, `$YUME_BUILD`, which the
  [main README](../README.md#the-yume-shared-library) describes:

```sh
python3 -B mailbox/tests/yumed_harness.py --mailbox build/mailbox/ito-mailbox \
  --yumed "$YUME_BUILD/bin/yumed" --setup "$YUME_BUILD/bin/yume-setup" \
  --libyume "$YUME_BUILD/src/libyume.so" --resolver "$YUME_BUILD/bin/yume-resolver"
```

The Python tests import the generic stream and module-peer helpers from
`relay/tests`, as the call harness does.
