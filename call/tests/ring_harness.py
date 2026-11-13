#!/usr/bin/env python3
# Copyright (C) 2026 FixCraft Inc. AGPL-3.0-or-later.
"""Profile-3 ringing through ito-mailbox and ito-call on one real yumed.

Pairs two Linux endpoints, accepts a call with composite proofs, declines
and reports busy without JOIN, and leaves an unanswered ring to time out.
Module taps check the mailbox class/hold and the call relay's opaque TLS.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import time
import traceback
from contextlib import ExitStack
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.dont_write_bytecode = True
sys.path.insert(0, str(HERE))
from call_harness import cli_child, cli_stderr  # noqa: E402
from message_harness import Endpoints, in_person  # noqa: E402
from relay_peers import RelayProcess, require  # noqa: E402
from relay_tap import Tap, search, secrets_from, split_connection  # noqa: E402

MAILBOX_TESTS = HERE.parents[1] / 'mailbox/tests'
sys.path.insert(0, str(MAILBOX_TESTS))
SPEC = importlib.util.spec_from_file_location('ring_mailbox_yumed',
                                             MAILBOX_TESTS / 'yumed_harness.py')
assert SPEC is not None and SPEC.loader is not None
MAILBOX = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MAILBOX)


class Harness(MAILBOX.Harness):
    def __init__(self, args: argparse.Namespace, root: Path) -> None:
        super().__init__(args, root)
        directory = root / 'calls'
        directory.mkdir(mode=0o700)
        self.relay = RelayProcess(args.relay, directory)
        self.call_tap = Tap(directory, self.relay.path)
        self.mail_tap = Tap(root / 'module', self.mailbox.path)

    def provision(self) -> None:
        super().provision()
        self.relay.start()
        path = self.kit / 'server/yumed.json'
        server = json.loads(path.read_text())
        service = {'name': 'ito-call', 'kind': 'stream', 'max_concurrent_streams': 8}
        server['services'].append(service)
        for adapter in server['adapters']:
            if adapter.get('service') == 'ito-mailbox':
                adapter['socket'] = str(self.mail_tap.path)
        server['adapters'].append({'kind': 'module', 'service': 'ito-call',
                                   'socket': str(self.call_tap.path)})
        path.write_text(json.dumps(server), encoding='utf-8')
        for directory in self.directories.values():
            path = directory / 'yume.json'
            config = json.loads(path.read_text())
            config['services'].append(service)
            path.write_text(json.dumps(config), encoding='utf-8')
        path = self.kit / 'server/credentials/authorized-keys.json'
        keys = json.loads(path.read_text())
        for entry in keys['keys']:
            if entry['name'] in ('alice', 'bob'):
                entry['capabilities'].append({'service': 'ito-call', 'kind': 'stream'})
        path.write_text(json.dumps(keys), encoding='utf-8')
        checked = subprocess.run([str(self.args.yumed), '--config',
                                  str(self.kit / 'server/yumed.json'), '--validate'],
                                 capture_output=True, timeout=60, check=False)
        require(checked.returncode == 0, 'combined services validate')

    def close(self) -> None:
        try:
            super().close()
        finally:
            self.relay.close()
            self.call_tap.close()
            self.mail_tap.close()


def frames(data: bytes) -> list[bytes]:
    """Client-to-service frames after the module header, with exact bounds."""
    newline = data.find(b'\n')
    require(0 < newline <= 144 and data.startswith(b'yume-module 1 '), 'module header')
    offset, result = newline + 1, []
    while offset < len(data):
        require(offset + 4 <= len(data), 'whole control header')
        size = int.from_bytes(data[offset:offset + 4], 'big')
        require(0 < size <= 16424 and offset + 4 + size <= len(data), 'whole control frame')
        result.append(data[offset + 4:offset + 4 + size])
        offset += 4 + size
    return result


def ring(e: Endpoints, args: argparse.Namespace, label: str,
         decision: str | None) -> dict:
    root = e.root / label
    root.mkdir(mode=0o700)
    accepted = decision == 'accept'
    binary = args.ito_call_evidence if accepted else args.ito_call
    payloads = [os.urandom(64 * 1024), os.urandom(16 * 1024)] if accepted else []
    pending_text = 'Keep this message while the call rings' if decision == 'busy' else None
    if pending_text:
        e.send('ben', 'ana', pending_text)
    before = len(e.h.call_tap.snapshot())
    began = time.monotonic()
    with ExitStack() as children:
        processes = {}
        for index, (name, peer, command) in enumerate((('ana', 'ben', 'ring'),
                                                       ('ben', 'ana', 'answer-ring'))):
            if command == 'answer-ring' and decision is None:
                continue
            connection = e.carrier(name)
            connection[connection.index('--service') + 1] = 'ito-call'
            command_args = [str(binary), '--store', str(e.store(name)), command,
                            '--peer', e.codes[peer], '--result', str(root / f'{name}.json'),
                            *connection]
            if accepted:
                source = root / f'{name}.send'
                source.write_bytes(payloads[index])
                command_args += ['--send', str(source), '--expect-bytes',
                                 str(len(payloads[1 - index])), '--received-out',
                                 str(root / f'{name}.received')]
            elif command == 'answer-ring':
                command_args.append(f'--{decision}')
            processes[name] = children.enter_context(cli_child(command_args,
                                                                root / f'{name}.stderr'))
        outcome = {}
        for name, process in reversed(list(processes.items())):
            process.wait(timeout=100)
            error = cli_stderr(root / f'{name}.stderr', name)
            require(process.returncode == 0 and (root / f'{name}.json').is_file(),
                    f'{label} {name} failed: {error}')
            outcome[name] = json.loads((root / f'{name}.json').read_text())
    elapsed = time.monotonic() - began
    captures = e.h.call_tap.snapshot()[before:]
    if accepted:
        require(len(captures) == 2, 'accepted ring has two call streams')
        for index, name in enumerate(('ana', 'ben')):
            result = outcome[name]
            require(result['peer_authenticated'], f'{name} authenticated profile 3')
            evidence = result['evidence']
            require(evidence is not None and len(bytes.fromhex(evidence['own_signature'])) == 4691,
                    'composite proof evidence')
            require((root / f'{name}.received').read_bytes() == payloads[1 - index],
                    f'{name} received intact DATA')
            secrets = secrets_from(evidence)
            for side in ('own_signature', 'peer_signature'):
                secrets[f'{side}_ed'] = secrets[side][:64]
                secrets[f'{side}_mldsa'] = secrets[side][64:]
            search(captures, secrets, payloads)
            search(e.h.mail_tap.snapshot(), secrets, payloads)
        parsed = [split_connection(record) for record in captures]
        outcome = {'authenticated': True, 'tls': parsed, 'bytes': [len(p) for p in payloads]}
    else:
        require(len(captures) == 1, f'{label} must not open a responder call stream')
        sent = frames(captures[0]['to_relay'])
        require([body[0] for body in sent] == [1, 3, 6], f'{label} reserve, join, cancel')
        require(int.from_bytes(sent[0][-4:], 'big') == 90000, '90-second room reservation')
        caller = outcome['ana']
        require(not caller['peer_authenticated'] and caller['data_sent'] == 0, 'no media on refusal')
        if decision is None:
            require(caller['result'] == 'timeout' and 45 <= elapsed < 65,
                    f'unanswered ring uses 45-second budget ({elapsed:.2f})')
        else:
            expected = {'decline': 2, 'busy': 3}[decision]
            require(outcome['ben']['joined'] == 0 and caller['remote_ring_end'] == expected,
                    f'{label} authenticated ring end stops caller without JOIN')
    if pending_text:
        e.collect('ana')
        require(any(bytes.fromhex(row.get('text_hex', '')) == pending_text.encode()
                    for row in e.history('ana', 'ben')), 'ring wait preserves unrelated text')
        e.collect('ben')
    require(e.outbox('ana', 'ben') == [] and e.outbox('ben', 'ana') == [], 'rings have no outbox')
    return {'scenario': label, 'seconds': round(elapsed, 3), 'passed': True, 'result': outcome}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('ito-call', 'ito-call-evidence', 'yumed', 'setup', 'libyume',
                 'resolver', 'mailbox', 'relay', 'result'):
        parser.add_argument(f'--{name}', type=Path, required=True)
    args = parser.parse_args()
    for name, path in vars(args).items():
        if name != 'result':
            require(path.is_file(), f'{name} binary exists')
    os.umask(0o077)
    results = []
    with tempfile.TemporaryDirectory(prefix='ito-ring-', dir='/tmp') as directory:
        root = Path(directory)
        harness = Harness(args, root)
        try:
            harness.provision()
            harness.start_yumed()
            stores = root / 'stores'
            stores.mkdir(mode=0o700)
            endpoints = Endpoints(str(args.ito_call), stores, harness)
            in_person(endpoints)
            for label, decision in (('accepted', 'accept'), ('declined', 'decline'),
                                    ('busy', 'busy'), ('unanswered', None)):
                results.append(ring(endpoints, args, label, decision))
                print(f'{label}: passed', flush=True)
            deposited = [body for record in harness.mail_tap.snapshot()
                         for body in frames(record['to_relay']) if body[0] == 7]
            rings = [body for body in deposited if body[35] == 2]
            require(len(rings) == 4 and all(int.from_bytes(body[36:40], 'big') == 60
                                            for body in rings), 'all rings use class 2 and hold 60')
            disk = b''.join(path.read_bytes() for path in harness.mailbox.data.rglob('*')
                            if path.is_file())
            require(len(disk) > 20, 'scan includes a held class-1 item')
            require(all(body[40:] not in disk for body in rings), 'ring ciphertext is memory only')
            results.append({'scenario': 'mailbox_class_and_storage', 'passed': True,
                            'ring_deposits': len(rings)})
        except Exception as error:
            results.append({'scenario': 'failure', 'passed': False,
                            'error': str(error), 'traceback': traceback.format_exc()})
        finally:
            harness.close()
    summary = {'schema': 1, 'scenarios': results,
               'binaries_sha256': {name: hashlib.sha256(path.read_bytes()).hexdigest()
                                    for name, path in vars(args).items() if name != 'result'},
               'passed': all(row['passed'] for row in results)}
    args.result.write_text(json.dumps(summary, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'passed': summary['passed']}))
    return 0 if summary['passed'] else 1


if __name__ == '__main__':
    sys.exit(main())
