#!/usr/bin/env python3
# Copyright (C) 2026 FixCraft Inc. AGPL-3.0-or-later.
"""Qualifies ito-mailbox behind a real yumed with real libyume clients.

yume-setup provisions one server and three client identities. alice and bob
hold the ito-mailbox stream grant. carol is authenticated for the kit's
standard services only, so yumed must refuse her OPEN before the mailbox sees
a connection. Every client opens its streams through the public libyume C
ABI. The mailbox runs on the module socket that yumed's `module` adapter
names, from a listener this harness holds as a socket unit would.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import signal
import socket
import subprocess
import sys
import tempfile
import time
import traceback
from pathlib import Path
from typing import Callable

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from mailbox_peers import (CAPACITY, DONE, LATER, MESSAGE, NOT_HERE, PING, PONG,  # noqa: E402
                           RING, SERVICE, Failure, MailboxProcess, address_of, deposit,
                           deposit_ok, expect_frame, expect_quiet, expect_refused, open_ok,
                           read_item, rejected, require, sealed_bytes, secret_for, taken)
from yume_abi import (STATUS_OK, STATUS_PERMISSION_DENIED, AbiStream, Client,  # noqa: E402
                      Library, json_file)

GRANTED = ('alice', 'bob')
UNGRANTED = 'carol'


class Harness:
    def __init__(self, arguments: argparse.Namespace, root: Path) -> None:
        self.args = arguments
        self.root = root
        self.library = Library(arguments.libyume)
        self.clients: dict[str, Client] = {}
        self.fingerprints: dict[str, str] = {}
        # Fingerprints, secrets, addresses and item IDs, for the privacy check.
        self.secrets: set[str] = set()
        self.yumed: subprocess.Popen | None = None
        module = root / 'module'
        module.mkdir(mode=0o700)
        self.mailbox = MailboxProcess(arguments.mailbox, module)
        self.kit = root / 'kit'

    # Provisioning and processes.

    def setup(self, *arguments: str) -> None:
        run = subprocess.run([str(self.args.setup), *arguments], capture_output=True, text=True,
                             timeout=120, check=False)
        require(run.returncode == 0, f'yume-setup {arguments[0]}: {run.stderr.strip()}')

    def provision(self) -> None:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as reservation:
            reservation.bind(('127.0.0.1', 0))
            self.port = reservation.getsockname()[1]
        self.setup('init', '--host', 'localhost', '--port', str(self.port),
                   '--output', str(self.kit), '--client-name', 'alice')
        for name in ('bob', 'carol'):
            self.setup('add-client', '--server', str(self.kit / 'server'), '--host', 'localhost',
                       '--output', str(self.kit / name), '--client-name', name)
        self.directories = {'alice': self.kit / 'client', 'bob': self.kit / 'bob',
                            'carol': self.kit / 'carol'}
        service = {'name': SERVICE, 'kind': 'stream', 'max_concurrent_streams': 8}
        server_path = self.kit / 'server/yumed.json'
        server = json_file(server_path)
        server['services'].append(service)
        server['adapters'].append({'kind': 'module', 'service': SERVICE,
                                   'socket': str(self.mailbox.path)})
        server['endpoint']['listen_addresses'] = ['127.0.0.1']
        server_path.write_text(json.dumps(server, indent=2), encoding='utf-8')
        for directory in self.directories.values():
            path = directory / 'yume.json'
            client = json_file(path)
            # The embedding backend composes named services only.
            client['services'] = [service]
            client['adapters'] = []
            client['endpoint']['connect_address'] = '127.0.0.1'
            path.write_text(json.dumps(client, indent=2), encoding='utf-8')
        keys_path = self.kit / 'server/credentials/authorized-keys.json'
        keys = json_file(keys_path)
        names = {entry['name']: entry for entry in keys['keys']}
        require(set(names) == set(self.directories), f'authorized names {sorted(names)}')
        for name, entry in names.items():
            self.fingerprints[name] = entry['identity']['sha256']
            granted = [grant for grant in entry['capabilities'] if grant['service'] != SERVICE]
            if name in GRANTED:
                granted.append({'service': SERVICE, 'kind': 'stream'})
            entry['capabilities'] = granted
        keys_path.write_text(json.dumps(keys, indent=2), encoding='utf-8')
        self.secrets.update(self.fingerprints.values())
        self.mailbox.start()
        validate = subprocess.run([str(self.args.yumed), '--config', str(server_path), '--validate'],
                                  capture_output=True, text=True, timeout=60, check=False)
        require(validate.returncode == 0, f'yumed --validate: {validate.stderr.strip()}')

    def start_yumed(self) -> None:
        log = open(self.root / 'yumed.log', 'ab')
        self.yumed = subprocess.Popen([str(self.args.yumed), '--config',
                                       str(self.kit / 'server/yumed.json')],
                                      stdin=subprocess.DEVNULL, stdout=log, stderr=log,
                                      start_new_session=True)
        log.close()
        deadline = time.monotonic() + 30
        while True:
            require(self.yumed.poll() is None, f'yumed exited with {self.yumed.returncode}')
            try:
                with socket.create_connection(('127.0.0.1', self.port), timeout=1):
                    return
            except OSError:
                require(time.monotonic() < deadline, 'yumed did not listen')
                time.sleep(0.1)

    def client(self, name: str) -> Client:
        if name not in self.clients:
            client = Client(self.library, self.directories[name], self.args.resolver)
            status = client.start()
            require(status == STATUS_OK, f'{name} start {status}')
            self.clients[name] = client
        return self.clients[name]

    def open(self, name: str) -> AbiStream:
        status, stream = self.client(name).open(SERVICE)
        require(status == STATUS_OK and stream is not None, f'{name} {SERVICE} OPEN {status}')
        return stream

    def secret(self, label: str) -> bytes:
        value = secret_for(f'yumed/{label}')
        self.secrets.update({value.hex(), address_of(value).hex()})
        return value

    def remember(self, item_id: bytes) -> bytes:
        self.secrets.add(item_id.hex())
        return item_id

    def close(self) -> None:
        for client in self.clients.values():
            client.destroy()
        self.clients.clear()
        if self.yumed and self.yumed.poll() is None:
            os.killpg(self.yumed.pid, signal.SIGTERM)
            try:
                self.yumed.wait(10)
            except subprocess.TimeoutExpired:
                os.killpg(self.yumed.pid, signal.SIGKILL)
                self.yumed.wait(10)
        self.mailbox.close()


# Scenarios, in order. Later ones rely on the state earlier ones leave.

def granted_flow(h: Harness) -> dict:
    """alice opens her inbox, goes offline, and receives what bob left."""
    inbox = h.secret('alice-from-bob')
    alice = h.open('alice')
    open_ok(alice, [inbox], [DONE], 'alice OPEN')
    alice.close()
    bob = h.open('bob')
    sizes = (1024, 4096, 16384)
    sent = {}
    for size in sizes:
        sealed = sealed_bytes(f'yumed-{size}', size)
        sent[h.remember(deposit_ok(bob, address_of(inbox), MESSAGE, 3600, sealed,
                                   f'bob deposits {size}'))] = sealed
    bob.send(deposit(address_of(h.secret('nobody')), MESSAGE, 60, sealed_bytes('x', 1024)))
    expect_frame(bob, rejected(NOT_HERE), 'a deposit to an unknown address')
    # alice comes back and receives every message, oldest first.
    alice = h.open('alice')
    open_ok(alice, [inbox], [DONE], 'alice OPEN again')
    items = [read_item(alice, f'held item {index}', 10.0) for index in range(3)]
    require([item.id for item in items] == list(sent), 'held items out of order')
    require(all(item.sealed == sent[item.id] for item in items), 'held bytes differ')
    # While she is connected, a ring and a message are pushed at once.
    ring = sealed_bytes('yumed-ring', 1024)
    ring_id = h.remember(deposit_ok(bob, address_of(inbox), RING, 600, ring, 'ring', 60))
    pushed = read_item(alice, 'pushed ring', 10.0)
    require(pushed.id == ring_id and pushed.item_class == RING and pushed.sealed == ring,
            'pushed ring differs')
    alice.send(taken(list(sent) + [ring_id]))
    open_ok(alice, [inbox], [DONE], 'alice OPEN after TAKEN')
    expect_quiet(alice, 'an emptied inbox')
    bob.close()
    alice.close()
    counts = h.mailbox.wait_for(lambda c: c['streams'] == 0, 'granted flow cleanup', 10.0)
    require(counts['taken'] == 4 and counts['messages'] == 0, f'counts {counts}')
    return {'sizes': list(sizes), 'delivered': counts['delivered']}


def ungranted_refused(h: Harness) -> dict:
    before = h.mailbox.counts()['accepted']
    carol = h.client(UNGRANTED)
    status, stream = carol.open(SERVICE)
    require(status == STATUS_PERMISSION_DENIED and stream is None,
            f'ungranted {SERVICE} OPEN returned {status}')
    # A destination-routed OPEN is refused even for a granted identity.
    status, stream = h.client('alice').open(SERVICE, destination=('example.com', 443))
    require(status == STATUS_PERMISSION_DENIED and stream is None,
            f'destination-routed OPEN returned {status}')
    after = h.mailbox.counts()['accepted']
    require(after == before, f'the mailbox accepted {after - before} refused streams')
    require(carol.running(), "carol's session ended on a refused OPEN")
    return {'ungranted_status': STATUS_PERMISSION_DENIED, 'mailbox_connections_added': 0}


def principal_is_the_identity(h: Harness) -> dict:
    """Quotas count yumed's authenticated identity, not the connection."""
    streams = [h.open('alice') for _ in range(4)]
    for stream in streams:
        stream.send(PING)
        expect_frame(stream, PONG, 'one of four alice streams')
    extra = h.open('alice')
    expect_refused(extra, CAPACITY, "alice's fifth stream")
    extra.close()
    other = h.open('bob')
    other.send(PING)
    expect_frame(other, PONG, 'bob beside four alice streams')
    other.close()
    for stream in streams:
        stream.close()
    counts = h.mailbox.wait_for(lambda c: c['streams'] == 0, 'quota cleanup', 10.0)
    require(counts['refusals'][CAPACITY - 1] == 1, f'refusals {counts["refusals"]}')
    return {'alice_streams': 4, 'fifth_refused': CAPACITY}


def mailbox_restart(h: Harness) -> dict:
    """A restart ends streams, keeps messages and registrations, loses rings."""
    inbox = h.secret('restart')
    alice = h.open('alice')
    open_ok(alice, [inbox], [DONE], 'alice OPEN before the restart')
    alice.close()
    bob = h.open('bob')
    kept = h.remember(deposit_ok(bob, address_of(inbox), MESSAGE, 3600,
                                 sealed_bytes('restart', 4096), 'message before the restart'))
    deposit_ok(bob, address_of(inbox), RING, 60, sealed_bytes('lost', 1024), 'ring')
    require(h.mailbox.stop() == 0, 'orderly mailbox stop')
    _, ended = bob.read_until_end(10.0)
    require(ended, "bob's stream survived the mailbox stop")
    bob.close()
    h.mailbox.start()
    alice = h.open('alice')
    open_ok(alice, [inbox], [DONE], 'alice OPEN after the restart')
    item = read_item(alice, 'the kept message', 10.0)
    require(item.id == kept and item.sealed == sealed_bytes('restart', 4096), 'kept message')
    expect_quiet(alice, 'the ring lost with the restart')
    alice.send(taken([kept]))
    alice.close()
    return {'kept_messages': 1, 'lost_rings': 1}


def rate_through_yumed(h: Harness) -> dict:
    bob = h.open('bob')
    nowhere = address_of(h.secret('rate'))
    small = sealed_bytes('rate', 1024)
    for _ in range(120):
        bob.send(deposit(nowhere, RING, 60, small))
    for index in range(120):
        expect_frame(bob, rejected(NOT_HERE), f'deposit {index}', 10.0)
    bob.send(deposit(nowhere, RING, 60, small))
    expect_frame(bob, rejected(LATER), "bob's 121st deposit in a minute")
    bob.close()
    # A new session of the same identity is the same principal.
    bob = h.open('bob')
    bob.send(deposit(nowhere, RING, 60, small))
    expect_frame(bob, rejected(LATER), 'a deposit from a new bob stream')
    bob.close()
    return {'deposits_per_window': 120}


def log_privacy(h: Harness) -> dict:
    text = h.mailbox.log_path.read_text(encoding='ascii')
    for value in h.secrets:
        require(value not in text, 'the mailbox log holds a fingerprint, secret, address or ID')
    return {'secrets_checked': len(h.secrets), 'log_lines': len(text.splitlines())}


SCENARIOS: list[tuple[str, Callable[[Harness], dict]]] = [
    ('granted_offline_hold_and_push', granted_flow),
    ('ungranted_and_routed_refused_by_yumed', ungranted_refused),
    ('principal_is_the_transport_identity', principal_is_the_identity),
    ('mailbox_restart_under_yumed', mailbox_restart),
    ('deposit_rate_across_sessions', rate_through_yumed),
    ('log_privacy', log_privacy),
]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('mailbox', 'yumed', 'setup', 'libyume', 'resolver'):
        parser.add_argument(f'--{name}', type=Path, required=True)
    parser.add_argument('--result', type=Path)
    arguments = parser.parse_args()
    for name in ('mailbox', 'yumed', 'setup', 'libyume', 'resolver'):
        path = getattr(arguments, name).resolve(strict=True)
        require(path.is_file(), f'--{name} is not a regular file')
        setattr(arguments, name, path)
    os.umask(0o077)
    results = []
    with tempfile.TemporaryDirectory(prefix='ito-mailbox-yumed-', dir='/tmp') as temporary:
        harness = Harness(arguments, Path(temporary))
        yumed_log = ''
        try:
            harness.provision()
            harness.start_yumed()
            for name in ('alice', 'bob', 'carol'):
                harness.client(name)
            for name, scenario in SCENARIOS:
                started = time.monotonic()
                entry = {'scenario': name}
                try:
                    entry['details'] = scenario(harness)
                    entry['passed'] = True
                except (Failure, OSError, ValueError, subprocess.SubprocessError) as error:
                    entry['passed'] = False
                    entry['error'] = f'{type(error).__name__}: {error}'
                    entry['trace'] = traceback.format_exc(limit=4)
                entry['seconds'] = round(time.monotonic() - started, 2)
                print(f"{'PASS' if entry['passed'] else 'FAIL'} {name} ({entry['seconds']} s)"
                      + ('' if entry['passed'] else f": {entry['error']}"), flush=True)
                results.append(entry)
                if not entry['passed']:
                    break
            yumed_log = (harness.root / 'yumed.log').read_text(encoding='utf-8', errors='replace')
        finally:
            harness.close()
            mailbox_log = harness.mailbox.log_path.read_text(encoding='ascii') \
                if harness.mailbox.log_path.exists() else ''
    binding = {name: hashlib.sha256(getattr(arguments, name).read_bytes()).hexdigest()
               for name in ('mailbox', 'yumed', 'setup', 'libyume', 'resolver')}
    summary = {'schema': 1, 'binaries_sha256': binding, 'scenarios': results,
               'expected': [name for name, _ in SCENARIOS],
               'passed': len(results) == len(SCENARIOS) and all(r['passed'] for r in results),
               'mailbox_log': mailbox_log, 'yumed_log_tail': yumed_log[-4000:]}
    if arguments.result:
        arguments.result.write_text(json.dumps(summary, indent=2) + '\n', encoding='utf-8')
    return 0 if summary['passed'] else 1


if __name__ == '__main__':
    try:
        sys.exit(main())
    except Failure as failure:
        print(f'yumed harness: {failure}', file=sys.stderr)
        sys.exit(1)
