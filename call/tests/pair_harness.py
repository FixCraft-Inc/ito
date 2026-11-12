#!/usr/bin/env python3
# Copyright (C) 2026 FixCraft Inc. AGPL-3.0-or-later.
"""Linux ito-call endpoints pairing through a stub mailbox directory.

Each endpoint keeps its own host test store. The pairing code passes through
a private file, as it would through a screen or a shared link, and must
never appear in any command's output. Scenarios: an in-person code with the
short-code decision, a link verified by the full safety code, and a code
two people scan where the first hello wins and the owner rejects it.
"""
from __future__ import annotations

import argparse
import json
import os
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

SERVICE = 'ito-mailbox'
TIMEOUT = 60


class Failure(Exception):
    pass


def require(condition: bool, what: str) -> None:
    if not condition:
        raise Failure(what)


class Endpoints:
    def __init__(self, binary: str, root: Path) -> None:
        self.binary = binary
        self.root = root
        self.stub = root / 'stub'
        self.outputs: list[str] = []
        self.codes: dict[str, str] = {}
        self.servers: dict[str, str] = {}
        self.shown = 0

    def store(self, name: str) -> str:
        return str(self.root / f'store-{name}')

    def run(self, name: str, *args: str, ok: bool = True) -> dict:
        run = subprocess.run([self.binary, '--store', self.store(name), *args],
                             capture_output=True, text=True, timeout=TIMEOUT, check=False)
        self.outputs += [run.stdout, run.stderr]
        if ok:
            require(run.returncode == 0, f'{name} {" ".join(args[:2])}: {run.stderr.strip()}')
            return json.loads(run.stdout)
        require(run.returncode == 2 and run.stderr.startswith('ito-call: '),
                f'{name} {" ".join(args[:2])} should fail')
        return {'error': run.stderr.strip()}

    def create(self, name: str, server: str) -> None:
        self.run(name, 'identity', 'create')
        identity = self.run(name, 'identity', 'upgrade')
        require(len(identity.get('fingerprint2', '')) == 64, f'{name} has identity 2')
        self.codes[name] = identity['code']
        self.servers[name] = server

    def mailbox(self, name: str) -> list[str]:
        return ['--mailbox', self.servers[name], '--mailbox-service', SERVICE]

    def show_code(self, owner: str, kind: str) -> tuple[str, Path]:
        self.shown += 1
        path = self.root / f'code-{self.shown}'
        shown = self.run(owner, 'pair', 'code', '--kind', kind, *self.mailbox(owner),
                         '--name', owner, '--code-out', str(path))
        require(shown['role'] == 'owner' and shown['state'] == 'open', 'a shown code is open')
        require(stat.S_IMODE(path.stat().st_mode) == 0o600, 'the code file is private')
        require(path.read_text().startswith('ito-pair:1:'), 'a pairing code 1')
        return shown['pairing_id'], path

    def scan(self, scanner: str, path: Path, source: str) -> dict:
        return self.run(scanner, 'pair', 'scan', '--code', str(path), '--source', source,
                        *self.mailbox(scanner), '--name', scanner, '--stub', str(self.stub))

    def collect(self, name: str) -> list[dict]:
        return self.run(name, 'pair', 'collect', '--stub', str(self.stub))['received']

    def contact(self, owner: str, other: str) -> dict:
        contacts = self.run(owner, 'contact', 'list')['contacts']
        found = [c for c in contacts if c['code'] == self.codes[other]]
        require(len(found) == 1, f'{owner} holds {other}')
        return found[0]

    def safety_code(self, owner: str, other: str) -> str:
        return self.run(owner, 'contact', 'safety-code', self.codes[other])['safety_code']

    def waiting_items(self) -> list[Path]:
        return sorted(self.stub.rglob('*.item')) if self.stub.exists() else []


def one(received: list[dict], status: str = 'ok') -> dict:
    require(len(received) == 1, f'one item collected, not {len(received)}')
    require(received[0]['status'] == status, f'{received[0]["status"]} is {status}')
    require(received[0]['taken'], 'the item was taken')
    return received[0]


def in_person(e: Endpoints) -> None:
    e.create('ana', 'a1' * 32)
    e.create('ben', 'b1' * 32)
    pairing, path = e.show_code('ana', 'in-person')
    scanned = e.scan('ben', path, 'scanned')
    require(scanned['pairing_id'] == pairing, 'ben read the shown code')
    require(scanned['deposited']['bytes'] == 16384, 'a hello fills a large item')

    replied = one(e.collect('ana'))
    require(replied['event']['event'] == 'replied' and len(replied['event']['short_code']) == 6,
            'ana answered with a short code')
    paired = one(e.collect('ben'))['event']
    require(paired['event'] == 'paired' and paired['trust'] == 'verified', 'ben trusts the scan')
    require(paired['short_code'] == replied['event']['short_code'], 'both show one short code')
    confirmed = one(e.collect('ana'))['event']
    require(confirmed['event'] == 'confirmed', 'ana waits for her decision')
    decided = e.run('ana', 'pair', 'decide', pairing, 'match')
    require(decided['event'] == 'completed' and decided['trust'] == 'verified', 'ana trusts the match')

    for owner, other in (('ana', 'ben'), ('ben', 'ana')):
        contact = e.contact(owner, other)
        require(contact['paired'] and contact['trust'] == 'verified', f'{owner} paired with {other}')
        require(e.run(owner, 'pair', 'list')['pairings'] == [], f'{owner} has nothing open')
    require(e.safety_code('ana', 'ben') == e.safety_code('ben', 'ana'), 'one safety code')

    # A confirm deposited again is recognized as a resend.
    e.run('ben', 'pair', 'confirm', e.codes['ana'], '--stub', str(e.stub))
    one(e.collect('ana'), 'already_spent')
    require(e.waiting_items() == [], 'every item was taken')


def link(e: Endpoints) -> None:
    e.create('cara', 'a2' * 32)
    e.create('dan', 'b2' * 32)
    _, path = e.show_code('cara', 'link')
    e.scan('dan', path, 'link')
    replied = one(e.collect('cara'))['event']
    require(replied['short_code'] == '', 'a link has no short code')
    paired = one(e.collect('dan'))['event']
    require(paired['trust'] == 'unverified', 'a link leaves the owner Not verified')
    completed = one(e.collect('cara'))['event']
    require(completed['event'] == 'completed' and completed['trust'] == 'unverified',
            'a link completes Not verified')
    code = e.safety_code('cara', 'dan')
    wrong = code[:-1] + ('1' if code[-1] == '0' else '0')
    e.run('cara', 'contact', 'compare', e.codes['dan'], wrong, ok=False)
    require(e.contact('cara', 'dan')['trust'] == 'unverified', 'a wrong code verifies nothing')
    grouped = ' '.join(code[index:index + 5] for index in range(0, 60, 5))
    require(e.run('cara', 'contact', 'compare', e.codes['dan'], grouped)['trust'] == 'verified',
            'the full safety code verifies')


def copied(e: Endpoints) -> None:
    e.create('owen', 'a3' * 32)
    e.create('eve', 'e3' * 32)
    e.create('pia', 'b3' * 32)
    pairing, path = e.show_code('owen', 'in-person')
    e.scan('eve', path, 'scanned')
    pia = e.scan('pia', path, 'scanned')
    received = e.collect('owen')
    require([row['status'] for row in received] == ['ok', 'already_spent'],
            'the first hello wins and the second is refused')
    require(all(row['taken'] for row in received), 'both hellos were taken')
    require(received[0]['event']['peer'] == e.codes['eve'], 'the code went to whoever was first')
    rejected = e.run('owen', 'pair', 'decide', pairing, 'differ')
    require(rejected['event'] == 'rejected', 'owen rejects the stranger')
    require(e.run('owen', 'contact', 'list')['contacts'] == [], 'owen saved no one')
    one(e.collect('eve'))
    require(e.collect('owen') == [], 'the rejected pairing listens no more')
    e.run('pia', 'pair', 'cancel', pia['pairing_id'])
    require(e.run('pia', 'pair', 'list')['pairings'] == [], 'pia canceled her scan')


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--ito-call', required=True)
    parser.add_argument('--result')
    args = parser.parse_args()
    scenarios = {'in_person': in_person, 'link': link, 'copied': copied}
    results: dict[str, str] = {}
    with tempfile.TemporaryDirectory(prefix='ito-pair-') as directory:
        root = Path(directory)
        os.chmod(root, 0o700)
        endpoints = Endpoints(args.ito_call, root)
        for name, scenario in scenarios.items():
            try:
                scenario(endpoints)
                results[name] = 'passed'
            except (Failure, subprocess.TimeoutExpired, json.JSONDecodeError, KeyError) as error:
                results[name] = f'failed: {error}'
        # The pairing codes held secrets: none may reach any output.
        codes = [path.read_text().strip() for path in root.glob('code-*')]
        leaked = any(code and code[11:] in output for code in codes for output in endpoints.outputs)
        results['no_code_in_output'] = 'failed' if leaked else 'passed'
    summary = json.dumps({'scenarios': results}, sort_keys=True)
    print(summary)
    if args.result:
        Path(args.result).write_text(summary + '\n')
    return 0 if all(value == 'passed' for value in results.values()) else 1


if __name__ == '__main__':
    sys.exit(main())
