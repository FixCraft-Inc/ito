#!/usr/bin/env python3
# Copyright (C) 2026 FixCraft Inc. AGPL-3.0-or-later.
"""Linux ito-call endpoints pairing and exchanging messages.

Without --yumed the items travel through a stub mailbox directory. With it
they travel through a real yumed and ito-mailbox: the mailbox's yumed
harness provisions one server and the clients alice and bob, who hold the
ito-mailbox grant, and each endpoint reaches the mailbox through its own
YUME client.

Scenarios: an in-person pairing, messages both ways with the delivery
receipts each collect sends, and a message the relay lost, which a check
finds and the sender resends. Through the stub also a repeated delivery, a
damaged item and a contact whose session snapshot is gone. Through yumed
also a mailbox restart between deposit and collect, with the held item's
store checked for text. No message text may appear in any command's output
other than an explicit history read.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import traceback
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.dont_write_bytecode = True
SERVICE = 'ito-mailbox'
TIMEOUT = 120


class Failure(Exception):
    pass


def require(condition: bool, what: str) -> None:
    if not condition:
        raise Failure(what)


class Endpoints:
    def __init__(self, binary: str, root: Path, harness=None) -> None:
        self.binary = binary
        self.root = root
        self.h = harness
        self.stub = root / 'stub'
        self.outputs: list[str] = []
        self.texts: list[bytes] = []
        self.codes: dict[str, str] = {}
        self.mailboxes: dict[str, list[str]] = {}
        self.counter = 0

    def store(self, name: str) -> Path:
        return self.root / f'store-{name}'

    def run(self, name: str, *args: str, ok: bool = True, history: bool = False) -> dict:
        run = subprocess.run([self.binary, '--store', str(self.store(name)), *args],
                             capture_output=True, text=True, timeout=TIMEOUT, check=False)
        if not history:
            self.outputs += [run.stdout, run.stderr]
        require(run.returncode == 0 if ok else run.returncode == 2,
                f'{name} {" ".join(args[:2])}: {run.stderr.strip()}')
        return json.loads(run.stdout) if ok else {'error': run.stderr.strip()}

    def carrier(self, name: str) -> list[str]:
        if self.h is None:
            return ['--stub', str(self.stub)]
        client = {'ana': 'alice', 'ben': 'bob'}[name]
        return ['--yume-config', str(self.h.directories[client]), '--service', SERVICE,
                '--resolver', str(self.h.args.resolver)]

    def create(self, name: str, server: str) -> None:
        self.run(name, 'identity', 'create')
        identity = self.run(name, 'identity', 'upgrade')
        self.codes[name] = identity['code']
        if self.h is None:
            self.mailboxes[name] = ['--mailbox', server, '--mailbox-service', SERVICE]
            return
        # The mailbox a code names is the one the endpoint's stream verified.
        shown = self.run(name, 'mailbox', 'show', *self.carrier(name))
        require(shown['service'] == SERVICE, 'the stream reached the mailbox service')
        self.mailboxes[name] = ['--mailbox', shown['mailbox'], '--mailbox-service', SERVICE]

    def private(self, data: bytes) -> Path:
        self.counter += 1
        path = self.root / f'private-{self.counter}'
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, 'wb') as out:
            out.write(data)
        return path

    def collect(self, name: str) -> dict:
        return self.run(name, 'message', 'collect', *self.carrier(name))

    def send(self, sender: str, recipient: str, text: str, drop: bool = False) -> str:
        data = text.encode()
        self.texts.append(data)
        path = self.private(data)
        args = ['message', 'send', self.codes[recipient], '--text', str(path)]
        if drop:
            args.append('--drop')
        sent = self.run(sender, *args, *self.carrier(sender))
        path.unlink()
        require(sent['deposited'] is not False or drop, f'{sender} deposited')
        return sent['id']

    def history(self, owner: str, other: str) -> list[dict]:
        return self.run(owner, 'message', 'history', self.codes[other], history=True)['history']

    def outbox(self, owner: str, other: str) -> list[str]:
        return [entry['id'] for entry in
                self.run(owner, 'message', 'outbox', self.codes[other])['outbox']]


def statuses(collected: dict) -> list[str]:
    return [row['status'] for row in collected['received']]


def kinds(collected: dict) -> list[str]:
    return [row['message']['kind'] for row in collected['received'] if 'message' in row]


def sent_kinds(collected: dict) -> list[str]:
    return [row['kind'] for row in collected['sent']]


def in_person(e: Endpoints) -> dict:
    e.create('ana', 'a1' * 32)
    e.create('ben', 'a1' * 32)
    code = e.root / 'code'
    # The code leaves Ana's phone only once its pairing inbox is open.
    shown = e.run('ana', 'pair', 'code', '--kind', 'in-person', *e.mailboxes['ana'],
                  '--name', 'Ana', '--code-out', str(code), *e.carrier('ana'))
    e.run('ben', 'pair', 'scan', '--code', str(code), '--source', 'scanned',
          *e.mailboxes['ben'], '--name', 'Ben', *e.carrier('ben'))
    code.unlink()
    events = []
    for name in ('ana', 'ben', 'ana'):
        collected = e.run(name, 'pair', 'collect', *e.carrier(name))
        require(statuses(collected) == ['ok'], f'{name} took one pairing item')
        events.append(collected['received'][0]['event']['event'])
    require(events == ['replied', 'paired', 'confirmed'], f'pairing events {events}')
    decided = e.run('ana', 'pair', 'decide', shown['pairing_id'], 'match')
    require(decided['event'] == 'completed' and decided['trust'] == 'verified',
            'ana completed the pairing')
    return {'events': events}


def conversation(e: Endpoints) -> dict:
    first = e.send('ben', 'ana', 'Running late')
    second = e.send('ben', 'ana', 'Train stopped')
    # The owner sends before it received anything.
    third = e.send('ana', 'ben', 'No problem')
    got = e.collect('ana')
    require(statuses(got) == ['ok', 'ok'] and kinds(got) == ['text', 'text'],
            f'ana received two texts: {statuses(got)}')
    require(sent_kinds(got) == ['receipt'] and sorted(got['sent'][0]['ids']) ==
            sorted([first, second]), 'ana confirmed both')
    held = e.history('ana', 'ben')
    require({bytes.fromhex(entry['text_hex']) for entry in held} ==
            {b'Running late', b'Train stopped'}, 'ana holds both texts')
    got = e.collect('ben')
    require(sorted(kinds(got)) == ['receipt', 'text'], f'ben received {kinds(got)}')
    require(e.outbox('ben', 'ana') == [], 'ben has nothing unconfirmed')
    require(bytes.fromhex(e.history('ben', 'ana')[0]['text_hex']) == b'No problem',
            'ben holds ana\'s text')
    got = e.collect('ana')
    require(kinds(got) == ['receipt'] and e.outbox('ana', 'ben') == [],
            'ana\'s text was confirmed')
    return {'messages': [first, second, third]}


def lost_and_resent(e: Endpoints) -> dict:
    lost = e.send('ben', 'ana', 'This one the relay lost', drop=True)
    kept = e.send('ben', 'ana', 'This one arrived')
    e.collect('ana')
    e.collect('ben')
    require(e.outbox('ben', 'ana') == [lost], 'only the lost message waits')
    time.sleep(2.1)
    checks = e.run('ben', 'message', 'check', e.codes['ana'], '--hold', '1',
                   *e.carrier('ben'))['checks']
    require(len(checks) == 1, 'one check went out')
    got = e.collect('ana')
    require(kinds(got) == ['check'] and got['received'][0]['message']['ids'] == [lost],
            'ana got the check')
    require(sent_kinds(got) == ['missing'] and got['sent'][0]['ids'] == [lost],
            'ana said what she lacks')
    got = e.collect('ben')
    require(kinds(got) == ['missing'] and sent_kinds(got) == ['resent'], 'ben resent it')
    got = e.collect('ana')
    message = got['received'][0]['message']
    require(message['id'] == lost and message['resent'], 'the copy is marked Resent')
    entry = [item for item in e.history('ana', 'ben') if item['id'] == lost]
    require(len(entry) == 1 and entry[0]['resent'] and
            bytes.fromhex(entry[0]['text_hex']) == b'This one the relay lost',
            'ana holds the resent text')
    e.collect('ben')
    require(e.outbox('ben', 'ana') == [], 'the resend was confirmed')
    return {'lost': lost, 'kept': kept}


def stub_items(e: Endpoints) -> list[Path]:
    return sorted(e.stub.rglob('*.item'))


def repeats_and_damage(e: Endpoints) -> dict:
    e.send('ben', 'ana', 'Twice')
    [item] = stub_items(e)
    copy = item.with_name(item.name[:21] + 'f' * 32 + '.item')
    shutil.copy2(item, copy)
    got = e.collect('ana')
    require(statuses(got) == ['ok', 'already_spent'], f'a repeat is spent: {statuses(got)}')
    require(all(row['taken'] for row in got['received']), 'both were taken')
    e.collect('ben')
    e.send('ben', 'ana', 'Damaged')
    [item] = stub_items(e)
    data = bytearray(item.read_bytes())
    data[300] ^= 1
    item.write_bytes(bytes(data))
    got = e.collect('ana')
    require(statuses(got) == ['authentication_failed'] and got['received'][0]['taken'],
            'a damaged item fails and is taken')
    # The outbox keeps the damaged message for a later check.
    require(len(e.outbox('ben', 'ana')) == 1, 'ben still waits for a receipt')
    # A lost session snapshot cannot be rebuilt: the chat needs pairing again.
    session = next((e.store('ana') / 'sessions').iterdir())
    session.unlink()
    e.send('ben', 'ana', 'Orphan')
    got = e.collect('ana')
    row = got['received'][0]
    require('corrupt_state' in row['status'] and not row['taken'],
            f'a lost session keeps its items: {row["status"]}')
    return {'repeat': 'already_spent', 'damaged': 'authentication_failed'}


def mailbox_restart(e: Endpoints) -> dict:
    """A message held on the mailbox's disk across a restart. While it waits,
    the store holds its sealed bytes and none of the texts sent so far."""
    e.send('ana', 'ben', 'Held across a restart')
    require(e.h.mailbox.stop() == 0, 'an orderly mailbox stop')
    data = b''.join(path.read_bytes() for path in e.h.mailbox.data.rglob('*') if path.is_file())
    require(len(data) >= 1024, f'the store holds the sealed item ({len(data)} bytes)')
    leaked = [text for text in e.texts if text in data]
    require(leaked == [], 'the mailbox store holds no text')
    e.h.mailbox.start()
    got = e.collect('ben')
    require(kinds(got) == ['text'], 'ben received the held message')
    e.collect('ana')
    require(e.outbox('ana', 'ben') == [], 'it was confirmed')
    return {'store_bytes': len(data)}


def run_scenarios(endpoints: Endpoints, scenarios) -> list[dict]:
    results = []
    for name, scenario in scenarios:
        started = time.monotonic()
        entry = {'scenario': name}
        try:
            entry['details'] = scenario(endpoints)
            entry['passed'] = True
        except (Failure, subprocess.TimeoutExpired, json.JSONDecodeError, KeyError,
                ValueError, OSError) as error:
            entry['passed'] = False
            entry['error'] = f'{type(error).__name__}: {error}'
            entry['trace'] = traceback.format_exc(limit=4)
        entry['seconds'] = round(time.monotonic() - started, 2)
        print(f"{'PASS' if entry['passed'] else 'FAIL'} {name} ({entry['seconds']} s)"
              + ('' if entry['passed'] else f": {entry['error']}"), flush=True)
        results.append(entry)
        if not entry['passed']:
            break
    # No message text in any output except the history reads.
    leaked = [text for text in endpoints.texts
              if any(text.decode() in output or text.hex() in output
                     for output in endpoints.outputs)]
    results.append({'scenario': 'no_text_in_output', 'passed': leaked == []})
    return results


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--ito-call', type=Path, required=True)
    for name in ('yumed', 'setup', 'libyume', 'resolver', 'mailbox'):
        parser.add_argument(f'--{name}', type=Path)
    parser.add_argument('--result', type=Path)
    args = parser.parse_args()
    through_yumed = args.yumed is not None
    os.umask(0o077)
    with tempfile.TemporaryDirectory(prefix='ito-message-', dir='/tmp') as directory:
        root = Path(directory)
        if not through_yumed:
            endpoints = Endpoints(str(args.ito_call), root)
            results = run_scenarios(endpoints, [
                ('in_person', in_person), ('conversation', conversation),
                ('lost_and_resent', lost_and_resent),
                ('repeats_and_damage', repeats_and_damage)])
            binding = {}
        else:
            sys.path.insert(0, str(HERE.parents[1] / 'mailbox' / 'tests'))
            from yumed_harness import Harness  # noqa: E402
            for name in ('yumed', 'setup', 'libyume', 'resolver', 'mailbox'):
                path = getattr(args, name)
                require(path is not None and path.is_file(), f'--{name} is required')
            harness = Harness(args, root)
            try:
                harness.provision()
                harness.start_yumed()
                stores = root / 'stores'
                stores.mkdir(mode=0o700)
                endpoints = Endpoints(str(args.ito_call), stores, harness)
                results = run_scenarios(endpoints, [
                    ('in_person', in_person), ('conversation', conversation),
                    ('lost_and_resent', lost_and_resent),
                    ('mailbox_restart', mailbox_restart)])
            finally:
                harness.close()
            binding = {name: hashlib.sha256(getattr(args, name).read_bytes()).hexdigest()
                       for name in ('ito_call', 'yumed', 'setup', 'libyume', 'resolver',
                                    'mailbox')}
    summary = {'schema': 1, 'yumed': through_yumed, 'binaries_sha256': binding,
               'scenarios': results, 'passed': all(entry['passed'] for entry in results)}
    print(json.dumps({'passed': summary['passed']}))
    if args.result:
        args.result.write_text(json.dumps(summary, indent=2) + '\n', encoding='utf-8')
    return 0 if summary['passed'] else 1


if __name__ == '__main__':
    try:
        sys.exit(main())
    except Failure as failure:
        print(f'message harness: {failure}', file=sys.stderr)
        sys.exit(1)
