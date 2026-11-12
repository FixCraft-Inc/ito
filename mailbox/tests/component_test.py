#!/usr/bin/env python3
# Copyright (C) 2026 FixCraft Inc. AGPL-3.0-or-later.
"""Qualifies ito-mailbox with the version-1 default limits.

The test plays yumed: it holds the module listener and writes module headers
as the trusted daemon user. Each case starts its own mailbox. Expectations
come from docs/MAILBOX.md, not from the implementation. Expiry on a moved
clock and lowered limits are in loop_test.cpp, which runs the same event loop
on virtual time.
"""
from __future__ import annotations

import argparse
import ctypes
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
from typing import Callable

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from mailbox_peers import (CAPACITY, DONE, INVALID_REQUEST, LATER, LOG_KEY, MESSAGE,  # noqa: E402
                           NOT_HERE, PING, PONG, RING, SERVICE, SIZES, TIMEOUT, UNSUPPORTED,
                           Failure, MailboxProcess, ModulePeer, address_of, close_inbox,
                           closed, deposit, deposit_ok, expect_frame, expect_quiet,
                           expect_refused, frame, open_inboxes, open_ok, read_frame, read_item,
                           rejected, require, sealed_bytes, secret_for, taken)

MAX_LIFETIME = 0xFFFFFFFF


class Context:
    def __init__(self, program: Path, root: Path) -> None:
        self.program = program
        self.root = root
        self.serial = 0
        # Every principal, secret, address and item ID a case used, for the
        # log privacy check.
        self.secrets: set[str] = set()
        self.mailboxes: list[MailboxProcess] = []

    def principal(self, label: str) -> str:
        self.serial += 1
        value = hashlib.sha256(f'{label}/{self.serial}'.encode()).hexdigest()
        self.secrets.add(value)
        return value

    def secret(self, label: str) -> bytes:
        self.serial += 1
        value = secret_for(f'{label}/{self.serial}')
        self.secrets.update({value.hex(), address_of(value).hex()})
        return value

    def remember(self, item_id: bytes) -> bytes:
        self.secrets.add(item_id.hex())
        return item_id

    def mailbox(self, name: str) -> MailboxProcess:
        directory = self.root / name
        directory.mkdir(mode=0o700)
        mailbox = MailboxProcess(self.program, directory)
        self.mailboxes.append(mailbox)
        return mailbox


def run_startup(ctx: Context, arguments: list[str] | None, **options) -> tuple[int, MailboxProcess]:
    ctx.serial += 1
    mailbox = ctx.mailbox(f'startup-{ctx.serial}')
    mailbox.spawn(mailbox.arguments() if arguments is None else arguments, **options)
    return mailbox.wait(10.0), mailbox


def failed_reason(lines: list[dict]) -> str:
    failures = [line for line in lines if line.get(LOG_KEY) == 'failed']
    require(len(failures) == 1, f'expected one failure line, got {lines}')
    return failures[0].get('reason', '')


def case_usage(ctx: Context) -> dict:
    uid = str(os.getuid())
    base = ['--service', SERVICE, '--daemon-uid', uid, '--data', '/var/lib/ito-mailbox']
    results = {}
    for name, arguments in (
            ('missing', []), ('missing_data', base[:4]),
            ('relative_data', base[:5] + ['data']),
            ('bad_service', ['--service', 'Ito'] + base[2:]),
            ('reserved_service', ['--service', 'yume.mail'] + base[2:]),
            ('bad_uid', base[:2] + ['--daemon-uid', '-1'] + base[4:]),
            ('hold_zero', base + ['--hold-days', '0']),
            ('hold_31', base + ['--hold-days', '31']),
            ('hold_leading_zero', base + ['--hold-days', '07']),
            ('store_zero', base + ['--store-mib', '0']),
            ('store_2049', base + ['--store-mib', '2049']),
            ('duplicate', base + ['--hold-days', '2', '--hold-days', '3']),
            ('unknown', base + ['--verbose'])):
        code, mailbox = run_startup(ctx, arguments, pass_listener=False)
        text = mailbox.log_path.read_text(encoding='utf-8')
        require(code == 2 and text.startswith('ito-mailbox: '),
                f'usage {name}: exit {code}, {text!r}')
        results[name] = code
    help_run = subprocess.run([str(ctx.program), '--help'], capture_output=True, timeout=10,
                              check=False)
    require(help_run.returncode == 0 and help_run.stdout.startswith(b'usage: ito-mailbox'),
            'help output')
    version = subprocess.run([str(ctx.program), '--version'], capture_output=True, timeout=10,
                             check=False)
    require(version.returncode == 0 and b'mailbox protocol 1' in version.stdout,
            'version output')
    return results


def case_startup_checks(ctx: Context) -> dict:
    """The listener checks are the relay's, already covered there. These
    show that the mailbox applies them, and its own data directory rules."""
    results = {}

    def expect(name: str, fragment: str, arguments: list[str] | None = None,
               prepare: Callable[[MailboxProcess], None] | None = None, **options) -> None:
        ctx.serial += 1
        mailbox = ctx.mailbox(f'startup-{ctx.serial}')
        if prepare:
            prepare(mailbox)
        mailbox.spawn(arguments(mailbox) if callable(arguments) else
                      (mailbox.arguments() if arguments is None else arguments), **options)
        code = mailbox.wait(10.0)
        reason = failed_reason(mailbox.lines())
        require(code == 1 and fragment in reason, f'{name}: exit {code}, {reason!r}')
        results[name] = reason

    expect('no_descriptor', 'not a socket', pass_listener=False)
    expect('owner_is_not_daemon', 'belong to the daemon user',
           arguments=lambda m: ['--service', SERVICE, '--daemon-uid', str(os.getuid() + 1),
                                '--data', str(m.data)])
    expect('missing_data', 'missing or is not a directory',
           arguments=lambda m: m.arguments()[:4] + ['--data', str(m.directory / 'absent')])
    expect('open_data', 'closed to group and others',
           prepare=lambda m: os.chmod(m.data, 0o750))
    expect('foreign_data', 'something other than a mailbox store',
           prepare=lambda m: (m.data / 'notes.txt').write_text('x'))
    environment = {'PATH': '/usr/bin:/bin', 'LISTEN_FDS': '2', 'LISTEN_PID': '1'}
    expect('activation_count', 'LISTEN_FDS', environment=environment)

    # A store directory reached through a symbolic link is accepted, as
    # systemd's state directory for a dynamic user is one.
    mailbox = ctx.mailbox('startup-link')
    link = mailbox.directory / 'state'
    link.symlink_to(mailbox.data)
    mailbox.start(mailbox.arguments()[:4] + ['--data', str(link)])
    require(mailbox.stop() == 0, 'linked store stop')
    require((mailbox.data / 'format').read_text() == 'ito/mailbox-store/1\n',
            'the store was not initialized through the link')
    results['linked_data_accepted'] = True

    unshare = shutil.which('unshare')
    require(unshare is not None, 'unshare is required to check the root refusal')
    code, mailbox = run_startup(ctx, None, prefix=[unshare, '--user', '--map-root-user'])
    require(code == 1 and 'root' in failed_reason(mailbox.lines()), f'root refusal: exit {code}')
    results['root_refused'] = True
    return results


def case_headers(ctx: Context) -> dict:
    mailbox = ctx.mailbox('headers')
    mailbox.start()
    principal = ctx.principal('header')
    timings = {}

    def silent(name: str, raw: bytes) -> None:
        peer = mailbox.peer(None)
        peer.send(raw)
        peer.expect_end(name, 2.0)
        peer.close()

    silent('other_service', f'yume-module 1 {principal} ito-call\n'.encode() + PING)
    silent('version_2', f'yume-module 2 {principal} {SERVICE}\n'.encode() + PING)
    silent('uppercase_fingerprint', f'yume-module 1 {principal.upper()} {SERVICE}\n'.encode())

    # Byte by byte, header and request.
    peer = mailbox.peer(None)
    for byte in f'yume-module 1 {principal} {SERVICE}\n'.encode() + PING:
        peer.send(bytes([byte]))
        time.sleep(0.002)
    expect_frame(peer, PONG, 'PONG after a byte-wise header')
    peer.close()

    # The header and the first frame share five seconds. These wait together.
    incomplete = mailbox.peer(None)
    incomplete.send(f'yume-module 1 {principal} ito'.encode())
    no_request = mailbox.peer(principal)
    partial = mailbox.peer(principal)
    partial.send(frame(10)[:3])
    started = time.monotonic()
    expect_refused(no_request, TIMEOUT, 'no first request', 8.0)
    timings['no_request'] = round(time.monotonic() - started, 3)
    expect_refused(partial, TIMEOUT, 'a frame cut short', 3.0)
    incomplete.expect_end('incomplete header', 3.0)
    timings['incomplete_header'] = round(time.monotonic() - started, 3)
    require(4.5 <= timings['no_request'] <= 7.0, f'budget {timings["no_request"]} s')
    for peer in (incomplete, no_request, partial):
        peer.close()

    counts = mailbox.wait_for(lambda c: c['streams'] == 0, 'headers cleanup')
    require(counts['rejected_headers'] == 4, f'rejected headers {counts["rejected_headers"]}')
    require(counts['refusals'][TIMEOUT - 1] == 2, f'refusals {counts["refusals"]}')
    require(mailbox.stop() == 0, 'headers mailbox stop')
    return {'seconds': timings}


def case_framing(ctx: Context) -> dict:
    mailbox = ctx.mailbox('framing')
    mailbox.start()
    principal = ctx.principal('framing')
    address = address_of(ctx.secret('framing'))
    good = sealed_bytes('framing', 1024)
    results = {}

    def refusal(name: str, request: bytes, reason: int) -> None:
        peer = mailbox.peer(principal)
        peer.send(PING + request)
        expect_frame(peer, PONG, f'{name}: the reply owed before it')
        expect_refused(peer, reason, name)
        peer.close()
        results[name] = reason

    refusal('length_zero', b'\0\0\0\0', INVALID_REQUEST)
    # Refused from the length alone, before a body that never comes.
    refusal('length_over', (16425).to_bytes(4, 'big'), INVALID_REQUEST)
    refusal('unknown_type', frame(13), INVALID_REQUEST)
    refusal('service_type', frame(11), INVALID_REQUEST)
    refusal('ping_payload', frame(10, b'\0'), INVALID_REQUEST)
    refusal('open_empty', frame(1, b'\0\1'), INVALID_REQUEST)
    refusal('open_ragged', frame(1, b'\0\1' + bytes(33)), INVALID_REQUEST)
    refusal('open_513', open_inboxes([bytes(32)] * 513), INVALID_REQUEST)
    refusal('open_version_2', open_inboxes([bytes(32)], version=2), UNSUPPORTED)
    refusal('close_version_0', close_inbox(bytes(32), version=0), UNSUPPORTED)
    refusal('close_short', frame(5, b'\0\1' + bytes(31)), INVALID_REQUEST)
    refusal('taken_empty', frame(4), INVALID_REQUEST)
    refusal('taken_ragged', frame(4, bytes(17)), INVALID_REQUEST)
    refusal('taken_513', taken([bytes(16)] * 513), INVALID_REQUEST)
    refusal('deposit_version_2', deposit(address, MESSAGE, 60, good, version=2), UNSUPPORTED)
    refusal('deposit_class_0', deposit(address, 0, 60, good), INVALID_REQUEST)
    refusal('deposit_class_3', deposit(address, 3, 60, good), INVALID_REQUEST)
    refusal('deposit_lifetime_0', deposit(address, MESSAGE, 0, good), INVALID_REQUEST)
    for size in (0, 1023, 1025, 2048, 16383):
        refusal(f'deposit_size_{size}', deposit(address, MESSAGE, 60, bytes(size)),
                INVALID_REQUEST)
    # The largest frame a client may send is accepted.
    peer = mailbox.peer(principal)
    peer.send(deposit(address, RING, MAX_LIFETIME, sealed_bytes('largest', 16384)))
    expect_frame(peer, rejected(NOT_HERE), 'a largest-size deposit to an unknown address')
    # TAKEN has no reply, so the PING after it answers next.
    peer.send(taken([bytes(16)] * 512) + PING)
    expect_frame(peer, PONG, 'PING after a TAKEN of unknown IDs')
    peer.close()
    counts = mailbox.wait_for(lambda c: c['streams'] == 0, 'framing cleanup')
    require(sum(counts['refusals']) == len(results), f'refusals {counts["refusals"]}')
    require(mailbox.stop() == 0, 'framing mailbox stop')
    return results


def case_flow_and_restart(ctx: Context) -> dict:
    mailbox = ctx.mailbox('flow')
    hold = ['--hold-days', '2']
    mailbox.start(mailbox.arguments(*hold))
    owner_principal, sender_principal = ctx.principal('owner'), ctx.principal('sender')
    secret, other = ctx.secret('inbox'), ctx.secret('other')
    address = address_of(secret)
    owner = mailbox.peer(owner_principal)
    open_ok(owner, [secret, other], [DONE, DONE], 'owner OPEN')
    sender = mailbox.peer(sender_principal)
    sender.send(deposit(address_of(ctx.secret('unknown')), MESSAGE, 60,
                        sealed_bytes('unknown', 1024)) + PING)
    expect_frame(sender, rejected(NOT_HERE), 'deposit to an unknown address')
    expect_frame(sender, PONG, 'PING answered after the deposit')

    stored = {}
    for size in SIZES:
        sealed = sealed_bytes(f'message-{size}', size)
        lifetime = MAX_LIFETIME if size == 16384 else 3600
        item_id = ctx.remember(deposit_ok(sender, address, MESSAGE, lifetime, sealed,
                                          f'deposit {size}',
                                          2 * 86400 if size == 16384 else 3600))
        item = read_item(owner, f'push of {size}')
        require(item.id == item_id and item.sealed == sealed and item.item_class == MESSAGE
                and item.address == address, f'item {size} differs')
        require(abs(item.deposit_minute - int(time.time()) // 60) <= 1, 'deposit minute')
        stored[size] = item_id
    ring = sealed_bytes('ring', 1024)
    ring_id = ctx.remember(deposit_ok(sender, address, RING, 600, ring, 'ring', 60))
    rung = read_item(owner, 'ring push')
    require(rung.item_class == RING and rung.id == ring_id and rung.sealed == ring
            and 58 <= rung.seconds_left <= 60, f'ring {rung.seconds_left} s left')

    # A TAKEN from a stream that knows the address, not the secret, removes
    # nothing.
    sender.send(taken([stored[1024]]) + PING)
    expect_frame(sender, PONG, "PING after the sender's TAKEN")
    owner.send(taken([stored[1024]]))
    open_ok(owner, [secret], [DONE], 'reopen after TAKEN')
    order = [read_item(owner, 'redelivery').id for _ in range(3)]
    require(order == [stored[4096], stored[16384], ring_id], 'redelivery order')
    expect_quiet(owner, 'after the redelivery')

    # A ring nobody reads is held for its lifetime only.
    quiet = ctx.secret('quiet')
    opener = mailbox.peer(owner_principal)
    open_ok(opener, [quiet], [DONE], 'OPEN of an inbox nobody reads yet')
    opener.close()
    mailbox.wait_for(lambda c: c['streams'] == 2, 'the opener closed')
    sender.send(deposit(address_of(quiet), RING, 1, sealed_bytes('short', 1024)))
    require(len(read_frame(sender, 'short ring')) == 25, 'short ring stored')
    time.sleep(1.3)
    open_ok(owner, [quiet], [DONE], 'OPEN after the short ring expired')
    expect_quiet(owner, 'the expired ring')
    owner.send(close_inbox(other))
    expect_frame(owner, closed(DONE), 'CLOSE by the owner')
    sender.send(deposit(address_of(other), MESSAGE, 60, sealed_bytes('closed', 1024)))
    expect_frame(sender, rejected(NOT_HERE), 'deposit to a closed inbox')

    # An orderly stop keeps messages and registrations and loses rings.
    require(mailbox.stop() == 0, 'orderly stop')
    require(mailbox.lines()[-1] == {LOG_KEY: 'stopped'}, f'last line {mailbox.lines()[-1]}')
    for peer in (owner, sender):
        _, ended = peer.read_until_end(3.0)
        require(ended, 'a stream survived the stop')
        peer.close()
    # A stream opened while the service is down waits in the listener queue.
    queued = mailbox.peer(sender_principal)
    queued.send(deposit(address, MESSAGE, 60, sealed_bytes('queued', 1024)))
    mailbox.start(mailbox.arguments(*hold))
    queued_id = ctx.remember(read_frame(queued, 'queued deposit')[5:21])
    owner = mailbox.peer(owner_principal)
    open_ok(owner, [secret, other], [DONE, DONE], 'OPEN after the restart')
    after = [read_item(owner, 'after restart') for _ in range(3)]
    require([item.id for item in after] == [stored[4096], stored[16384], queued_id],
            'the restart did not keep exactly the messages')
    require(after[1].sealed == sealed_bytes('message-16384', 16384), 'stored bytes changed')
    expect_quiet(owner, 'the ring after a restart')

    # A crash keeps every message whose DEPOSITED was sent.
    mailbox.kill()
    owner.close()
    queued.close()
    mailbox.start(mailbox.arguments(*hold))
    owner = mailbox.peer(owner_principal)
    open_ok(owner, [secret], [DONE], 'OPEN after the crash')
    require(len([read_item(owner, 'after crash') for _ in range(3)]) == 3, 'after crash')
    expect_quiet(owner, 'after the crash')
    loaded = [line for line in mailbox.lines() if line.get(LOG_KEY) == 'loaded']
    # secret, quiet, and other again after its CLOSE.
    require(loaded[-1]['inboxes'] == 3 and loaded[-1]['partial_writes'] == 0,
            f'loaded {loaded[-1]}')
    owner.close()
    require(mailbox.stop() == 0, 'flow stop')
    return {'sizes': list(SIZES), 'loaded': loaded[-1]}


def case_inbox_limits(ctx: Context) -> dict:
    mailbox = ctx.mailbox('limits')
    mailbox.start()
    owner = mailbox.peer(ctx.principal('owner'))
    secret = ctx.secret('full')
    address = address_of(secret)
    open_ok(owner, [secret], [DONE], 'OPEN')
    # 512 items fill an inbox. A principal may deposit 120 times a minute, so
    # five principals share the work.
    senders = [mailbox.peer(ctx.principal(f'sender-{index}')) for index in range(5)]
    small = sealed_bytes('small', 1024)
    for index in range(512):
        senders[index % 5].send(deposit(address, MESSAGE, 3600, small))
    for index in range(512):
        reply = read_frame(senders[index % 5], f'deposit {index}', 30.0)
        require(len(reply) == 25 and reply[4] == 8, f'deposit {index}: {reply[:6].hex()}')
    senders[0].send(deposit(address, MESSAGE, 60, small))
    expect_frame(senders[0], rejected(NOT_HERE), 'the 513th item')
    senders[0].send(deposit(address, RING, 60, small))
    expect_frame(senders[0], rejected(NOT_HERE), 'a ring to a full inbox')
    # Four pending rings per inbox. The owner's stream already carries
    # pushed items, so this inbox gets a stream of its own.
    rings = ctx.secret('rings')
    ring_owner = mailbox.peer(ctx.principal('ring-owner'))
    open_ok(ring_owner, [rings], [DONE], 'OPEN for rings')
    for index in range(4):
        deposit_ok(senders[1], address_of(rings), RING, 60, small, f'ring {index}')
    senders[1].send(deposit(address_of(rings), RING, 60, small))
    expect_frame(senders[1], rejected(NOT_HERE), 'the fifth ring')
    deposit_ok(senders[1], address_of(rings), MESSAGE, 60, small, 'a message beside 4 rings')
    # Read what was pushed, so neither stream is a slow reader here.
    for index in range(512):
        read_item(owner, f'push {index}', 30.0)
    for index in range(5):
        read_item(ring_owner, f'ring push {index}')

    # 512 inboxes per principal, then "not for this inbox".
    collector = mailbox.peer(ctx.principal('collector'))
    many = [ctx.secret(f'many-{index}') for index in range(512)]
    collector.send(open_inboxes(many))
    expect_frame(collector, frame(2, bytes([DONE] * 512)), '512 inboxes', 60.0)
    collector.send(open_inboxes([ctx.secret('one-more'), many[0]]))
    expect_frame(collector, frame(2, bytes([NOT_HERE, DONE])), 'the 513th inbox')
    # An inbox charged to another principal moves only when this one has room.
    open_ok(collector, [secret], [NOT_HERE], 'taking over a full principal')
    counts = mailbox.counts()
    require(counts['inboxes'] == 514 and counts['messages'] == 513, f'counts {counts}')
    for peer in [owner, ring_owner, collector, *senders]:
        peer.close()
    require(mailbox.stop() == 0, 'limits stop')

    # The operator's store size: 1 MiB is 256 blocks, one for the inbox, and
    # a 16 KiB message takes four.
    small_store = ctx.mailbox('store-size')
    small_store.start(small_store.arguments('--store-mib', '1'))
    # The owner holds the inbox open and does not read its pushes.
    owner = small_store.peer(ctx.principal('owner'))
    open_ok(owner, [secret], [DONE], 'OPEN on a small store')
    sender = small_store.peer(ctx.principal('sender'))
    large = sealed_bytes('large', 16384)
    for index in range(63):
        deposit_ok(sender, address, MESSAGE, 60, large, f'large {index}')
    # Three blocks are left: no room for four, room for three of one.
    sender.send(deposit(address, MESSAGE, 60, large))
    expect_frame(sender, rejected(LATER), 'a large message beyond the store')
    for index in range(3):
        deposit_ok(sender, address, MESSAGE, 60, small, f'small {index}')
    sender.send(deposit(address, MESSAGE, 60, small))
    expect_frame(sender, rejected(LATER), 'a block beyond the store')
    open_ok(sender, [ctx.secret('no-room')], [LATER], 'a registration beyond the store')
    # Rings are held in memory, not in the store.
    deposit_ok(sender, address, RING, 60, small, 'a ring beside a full store')
    owner.close()
    sender.close()
    require(small_store.stop() == 0, 'small store stop')
    return {'items_per_inbox': 512, 'rings_per_inbox': 4, 'inboxes_per_principal': 512,
            'store_blocks': 256}


def case_rates_and_streams(ctx: Context) -> dict:
    mailbox = ctx.mailbox('rates')
    mailbox.start()
    alice = ctx.principal('alice')
    streams = [mailbox.peer(alice) for _ in range(4)]
    for stream in streams:
        stream.send(PING)
        expect_frame(stream, PONG, 'one of four streams')
    fifth = mailbox.peer(alice)
    expect_refused(fifth, CAPACITY, 'a fifth stream of one principal')
    fifth.close()

    # 120 DEPOSIT frames per principal in any 60 seconds, counted across its
    # streams, stored or not.
    nowhere = address_of(ctx.secret('nowhere'))
    small = sealed_bytes('rate', 1024)
    for index in range(120):
        streams[index % 4].send(deposit(nowhere, RING, 60, small))
    for index in range(120):
        expect_frame(streams[index % 4], rejected(NOT_HERE), f'deposit {index}')
    streams[0].send(deposit(nowhere, RING, 60, small))
    expect_frame(streams[0], rejected(LATER), 'the 121st deposit')
    # 30 OPEN and CLOSE frames, then "try later" for every secret.
    secret = ctx.secret('changes')
    for index in range(30):
        open_ok(streams[1], [secret], [DONE], f'change {index}')
    open_ok(streams[1], [secret, ctx.secret('later')], [LATER, LATER], 'the 31st change')
    streams[1].send(close_inbox(secret))
    expect_frame(streams[1], closed(LATER), 'a CLOSE beyond the rate')

    # A reconnect does not reset the windows: the principal stays in memory
    # for 60 seconds after its last counted frame, here also by its inbox.
    for stream in streams:
        stream.close()
    mailbox.wait_for(lambda c: c['streams'] == 0, 'streams closed')
    again = mailbox.peer(alice)
    again.send(deposit(nowhere, RING, 60, small))
    expect_frame(again, rejected(LATER), 'a deposit after reconnecting')
    other = mailbox.peer(ctx.principal('bob'))
    other.send(deposit(nowhere, RING, 60, small))
    expect_frame(other, rejected(NOT_HERE), 'another principal has its own window')
    counts = mailbox.counts()
    require(counts['principals'] == 2, f'principals {counts["principals"]}')
    require(counts['deposit_statuses'] == [0, 121, 2], f'deposits {counts["deposit_statuses"]}')
    again.close()
    other.close()
    require(mailbox.stop() == 0, 'rates stop')
    return {'deposits_per_window': 120, 'changes_per_window': 30, 'streams_per_principal': 4}


def case_slow_reader_and_reconnect(ctx: Context) -> dict:
    mailbox = ctx.mailbox('slow')
    mailbox.start()
    owner_principal = ctx.principal('owner')
    secret = ctx.secret('slow')
    address = address_of(secret)
    owner = mailbox.peer(owner_principal)
    open_ok(owner, [secret], [DONE], 'OPEN')
    sender = mailbox.peer(ctx.principal('sender'))
    sent = [sealed_bytes(f'slow-{index}', 16384) for index in range(100)]
    ids = [ctx.remember(deposit_ok(sender, address, MESSAGE, 3600, sealed, f'deposit {index}'))
           for index, sealed in enumerate(sent)]
    # The owner reads nothing. Its stream holds a bounded backlog and the
    # service keeps answering others.
    started = time.monotonic()
    sender.send(PING)
    expect_frame(sender, PONG, 'PING beside a slow reader')
    require(time.monotonic() - started < 1.0, 'a slow reader delayed another stream')
    delivered = mailbox.counts()['delivered']
    require(delivered < 40, f'{delivered} items pushed into a stream nobody reads')

    # The phone takes three items, then loses its stream inside the fourth.
    received = [read_item(owner, f'item {index}') for index in range(3)]
    owner.send(taken([item.id for item in received]))
    owner.read_exact(1000)
    owner.close()
    owner = mailbox.peer(owner_principal)
    open_ok(owner, [secret], [DONE], 'OPEN after the drop')
    rest = [read_item(owner, f'redelivery {index}', 10.0) for index in range(97)]
    require([item.id for item in rest] == ids[3:], 'redelivery is not oldest first')
    require(all(item.sealed == sent[3 + index] for index, item in enumerate(rest)),
            'redelivered bytes differ')
    owner.send(taken(ids[3:]))
    open_ok(owner, [secret], [DONE], 'OPEN after taking everything')
    expect_quiet(owner, 'an emptied inbox')
    counts = mailbox.counts()
    require(counts['messages'] == 0 and counts['taken'] == 100, f'counts {counts}')
    owner.close()
    sender.close()
    require(mailbox.stop() == 0, 'slow stop')
    return {'items': 100, 'pushed_while_unread': delivered}


# A full disk: a small tmpfs in a private user and mount namespace. The child
# keeps its own user ID, so the mailbox's ownership checks still apply.

MS_NOSUID, MS_NODEV, MS_NOEXEC, MS_REC, MS_PRIVATE = 2, 4, 8, 16384, 1 << 18


def _enter_disk_namespace() -> ctypes.CDLL:
    uid, gid = os.getuid(), os.getgid()
    os.unshare(os.CLONE_NEWUSER | os.CLONE_NEWNS)
    Path('/proc/self/setgroups').write_text('deny')
    Path('/proc/self/uid_map').write_text(f'{uid} {uid} 1')
    Path('/proc/self/gid_map').write_text(f'{gid} {gid} 1')
    libc = ctypes.CDLL(None, use_errno=True)
    libc.mount.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_ulong,
                           ctypes.c_char_p]
    if libc.mount(b'none', b'/', None, MS_REC | MS_PRIVATE, None) != 0:
        raise OSError(ctypes.get_errno(), 'making / private')
    return libc


def _mount_tmpfs(libc: ctypes.CDLL, path: Path, options: str) -> None:
    options += f',mode=0700,uid={os.getuid()},gid={os.getgid()}'
    if libc.mount(b'ito-mailbox-test', str(path).encode(), b'tmpfs',
                  MS_NOSUID | MS_NODEV | MS_NOEXEC, options.encode()) != 0:
        raise OSError(ctypes.get_errno(), f'mounting tmpfs on {path}')


def run_full_disk_child(program: Path, result: Path) -> int:
    libc = _enter_disk_namespace()
    root = Path(tempfile.mkdtemp(prefix='ito-mailbox-disk-', dir='/tmp'))
    principal = hashlib.sha256(b'disk-owner').hexdigest()
    details = {}
    bytes_box = MailboxProcess(program, root, 'bytes')
    inodes_box = MailboxProcess(program, root, 'inodes')
    try:
        # Bytes: 48 pages hold the format file and eleven 16 KiB messages.
        _mount_tmpfs(libc, bytes_box.data, 'size=192k,nr_inodes=4096')
        bytes_box.start()
        owner = bytes_box.peer(principal)
        secret = secret_for('disk')
        open_ok(owner, [secret], [DONE], 'OPEN on a small disk')
        sender = bytes_box.peer(hashlib.sha256(b'disk-sender').hexdigest())
        large = sealed_bytes('disk', 16384)
        stored = []
        while True:
            sender.send(deposit(address_of(secret), MESSAGE, 3600, large))
            reply = read_frame(sender, f'deposit {len(stored)}')
            if reply == rejected(LATER):
                break
            require(len(reply) == 25 and reply[4] == 8, f'unexpected {reply[:6].hex()}')
            stored.append(reply[5:21])
            require(len(stored) < 64, 'the small disk never filled')
        require(len(stored) >= 8, f'only {len(stored)} messages fit')
        inbox = bytes_box.data / 'inboxes' / address_of(secret).hex()
        names = sorted(path.name for path in inbox.iterdir())
        require(not any(name.startswith('t1-') for name in names),
                f'a refused write remains: {names}')
        require(len(names) == len(stored) + 1, f'{len(names)} files for {len(stored)} messages')
        # Taking frees room, and the next deposit fits.
        owner.send(taken(stored[:2]))
        deposit_ok(sender, address_of(secret), MESSAGE, 3600, large, 'deposit after TAKEN')
        counts = bytes_box.counts()
        require(counts['disk_full'] >= 1, f'disk_full {counts["disk_full"]}')
        details['bytes'] = {'stored_before_full': len(stored), 'disk_full': counts['disk_full']}
        for peer in (owner, sender):
            peer.close()
        bytes_box.kill()
        bytes_box.start()
        loaded = [line for line in bytes_box.lines() if line.get(LOG_KEY) == 'loaded'][-1]
        require(loaded['partial_writes'] == 0 and loaded['damaged_messages'] == 0,
                f'loaded {loaded}')
        require(bytes_box.stop() == 0, 'bytes mailbox stop')

        # Inodes: each inbox is a directory and a registration file.
        _mount_tmpfs(libc, inodes_box.data, 'size=4m,nr_inodes=12')
        inodes_box.start()
        owner = inodes_box.peer(principal)
        secrets = []
        while True:
            candidate = secret_for(f'inode-{len(secrets)}')
            owner.send(open_inboxes([candidate]))
            reply = read_frame(owner, 'OPEN on few inodes')
            if reply == frame(2, bytes([LATER])):
                break
            require(reply == frame(2, bytes([DONE])), f'unexpected {reply.hex()}')
            secrets.append(candidate)
            require(len(secrets) < 12, 'inodes never ran out')
        require(secrets, 'no inbox fit')
        require(sorted(path.name for path in (inodes_box.data / 'inboxes').iterdir()) ==
                sorted(address_of(s).hex() for s in secrets), 'a refused registration remains')
        owner.send(close_inbox(secrets[0]))
        expect_frame(owner, closed(DONE), 'CLOSE frees inodes')
        open_ok(owner, [secret_for('inode-after')], [DONE], 'OPEN after CLOSE')
        details['inodes'] = {'inboxes_before_full': len(secrets)}
        owner.close()
        require(inodes_box.stop() == 0, 'inodes mailbox stop')
    finally:
        for mailbox in (bytes_box, inodes_box):
            mailbox.close()
            libc.umount2(str(mailbox.data).encode(), 2)
        shutil.rmtree(root, ignore_errors=True)
    result.write_text(json.dumps(details) + '\n', encoding='utf-8')
    return 0


def case_full_disk(ctx: Context) -> dict:
    output = ctx.root / 'full-disk-result.json'
    run = subprocess.run([sys.executable, '-B', str(Path(__file__).resolve()), '--mailbox',
                          str(ctx.program), '--full-disk-child', str(output)],
                         capture_output=True, text=True, timeout=300, check=False)
    require(run.returncode == 0, f'full-disk child failed: {run.stderr.strip()[-800:]}')
    return json.loads(output.read_text(encoding='utf-8'))


NAMESPACE_DAEMON_UID = 1000
NAMESPACE_MAILBOX_UID = 1001
NAMESPACE_OTHER_UID = 1002


def _as_user(uid: int, action: Callable[[], bool]) -> bool:
    """Runs action in a child with only uid's credentials."""
    pid = os.fork()
    if pid == 0:
        code = 1
        try:
            os.setgroups([])
            os.setresgid(uid, uid, uid)
            os.setresuid(uid, uid, uid)
            code = 0 if action() else 1
        except BaseException as error:  # reported, then the child fails
            print(f'user {uid}: {type(error).__name__}: {error}', file=sys.stderr, flush=True)
        finally:
            os._exit(code)
    _, status = os.waitpid(pid, 0)
    return os.waitstatus_to_exitcode(status) == 0


def _answers(path: Path, principal: str) -> bool:
    peer = ModulePeer(path, principal, SERVICE)
    peer.send(PING)
    reply = peer.read_exact(5, 5.0)
    peer.close()
    return reply == PONG


def _closed_silently(path: Path, principal: str) -> bool:
    """The mailbox may close before the header is written, so a refused send
    counts as closed. Its untrusted-peer count shows it refused the peer."""
    peer = ModulePeer(path, None, SERVICE)
    try:
        peer.send(f'yume-module 1 {principal} {SERVICE}\n'.encode() + PING)
    except (BrokenPipeError, ConnectionResetError):
        pass
    data, ended = peer.read_until_end(5.0)
    peer.close()
    return ended and data == b''


def run_namespace_child(program: Path, result: Path) -> int:
    """Runs as root of a user namespace with subordinate IDs mapped."""
    require(os.getuid() == 0, 'the namespace child is not root in its namespace')
    os.umask(0o022)
    directory = Path(tempfile.mkdtemp(prefix='ito-mailbox-ns-', dir='/tmp'))
    os.chmod(directory, 0o755)
    mailbox = MailboxProcess(program, directory)
    os.chown(mailbox.path, NAMESPACE_DAEMON_UID, NAMESPACE_DAEMON_UID)
    os.chown(mailbox.data, NAMESPACE_MAILBOX_UID, NAMESPACE_MAILBOX_UID)
    setpriv = shutil.which('setpriv')
    require(setpriv is not None, 'setpriv is required')
    as_mailbox = [setpriv, f'--reuid={NAMESPACE_MAILBOX_UID}',
                  f'--regid={NAMESPACE_MAILBOX_UID}', '--clear-groups', '--']
    arguments = ['--service', SERVICE, '--daemon-uid', str(NAMESPACE_DAEMON_UID),
                 '--data', str(mailbox.data)]
    details = {}
    try:
        # A mailbox that assumes its own user is the daemon's refuses to start.
        mailbox.spawn(arguments[:3] + [str(NAMESPACE_MAILBOX_UID)] + arguments[4:],
                      prefix=as_mailbox)
        require(mailbox.wait(10.0) == 1, 'a mailbox trusting its own user started')
        require('belong to the daemon user' in failed_reason(mailbox.lines()),
                'wrong refusal for an assumed daemon user')
        mailbox.log_path.unlink()
        mailbox.spawn(arguments, prefix=as_mailbox)
        deadline = time.monotonic() + 10
        while not any(line.get(LOG_KEY) == 'ready' for line in mailbox.lines()):
            require(time.monotonic() < deadline and mailbox.poll() is None,
                    f'the mailbox as its own user did not start: {mailbox.lines()}')
            time.sleep(0.01)
        principal = hashlib.sha256(b'namespace').hexdigest()
        require(_as_user(NAMESPACE_DAEMON_UID, lambda: _answers(mailbox.path, principal)),
                'the pinned daemon user was refused')
        require(_answers(mailbox.path, principal), 'root was refused')
        # Open the socket file to everyone. Only SO_PEERCRED stands between a
        # third user and a forged header now.
        os.chmod(mailbox.path, 0o666)
        require(_as_user(NAMESPACE_OTHER_UID,
                         lambda: _closed_silently(mailbox.path, principal)),
                'a third user was served')
        require(_as_user(NAMESPACE_MAILBOX_UID,
                         lambda: _closed_silently(mailbox.path, principal)),
                "the mailbox's own user was served")
        counts = mailbox.counts()
        require(counts['untrusted_peers'] == 2, f'untrusted peers {counts["untrusted_peers"]}')
        require(counts['accepted'] == 2, f'accepted {counts["accepted"]}')
        details = {'mailbox_uid': NAMESPACE_MAILBOX_UID, 'daemon_uid': NAMESPACE_DAEMON_UID,
                   'untrusted_uids': [NAMESPACE_OTHER_UID, NAMESPACE_MAILBOX_UID]}
        require(mailbox.stop() == 0, 'namespace mailbox stop')
    finally:
        mailbox.close()
        shutil.rmtree(directory, ignore_errors=True)
    result.write_text(json.dumps(details) + '\n', encoding='utf-8')
    return 0


def case_peer_credentials(ctx: Context) -> dict:
    unshare = shutil.which('unshare')
    require(unshare is not None and shutil.which('newuidmap') is not None
            and shutil.which('setpriv') is not None,
            'unavailable: unshare, newuidmap and setpriv are required')
    output = ctx.root / 'namespace-result.json'
    run = subprocess.run([unshare, '--user', '--map-root-user', '--map-auto', '--fork',
                          sys.executable, '-B', str(Path(__file__).resolve()), '--mailbox',
                          str(ctx.program), '--namespace-child', str(output)],
                         capture_output=True, text=True, timeout=120, check=False)
    require(run.returncode == 0, f'namespace child failed: {run.stderr.strip()[-800:]}')
    return json.loads(output.read_text(encoding='utf-8'))


LOG_FIELDS = {LOG_KEY, 'reason', 'streams', 'principals', 'inboxes', 'messages', 'rings',
              'store_bytes', 'ring_bytes', 'pending_jobs', 'accepted', 'untrusted_peers',
              'over_capacity', 'rejected_headers', 'delivered', 'taken', 'expired_messages',
              'expired_rings', 'ended_inboxes', 'lost_messages', 'disk_full', 'open_statuses',
              'close_statuses', 'deposit_statuses', 'refusals', 'unregistered_inboxes',
              'damaged_messages', 'partial_writes'}


def case_log_privacy(ctx: Context) -> dict:
    lines = 0
    for mailbox in ctx.mailboxes:
        if not mailbox.log_path.exists():
            continue
        text = mailbox.log_path.read_text(encoding='ascii')
        for value in ctx.secrets:
            require(value not in text, f'{mailbox.log_path} holds a principal, secret, '
                                       'address or item ID')
        require(str(mailbox.data) not in text, f'{mailbox.log_path} names the data directory')
        for raw in text.splitlines():
            if not raw.startswith('{'):
                # Usage errors, which name only the option.
                require(raw.startswith(('ito-mailbox: ', "Try 'ito-mailbox --help'")),
                        f'unexpected log text {raw!r}')
                continue
            parsed = json.loads(raw)
            require(set(parsed) <= LOG_FIELDS, f'unexpected log fields {sorted(parsed)}')
            lines += 1
    return {'json_lines': lines, 'secrets_checked': len(ctx.secrets)}


CASES: list[tuple[str, Callable[[Context], dict]]] = [
    ('usage', case_usage),
    ('startup_checks', case_startup_checks),
    ('headers', case_headers),
    ('framing', case_framing),
    ('flow_and_restart', case_flow_and_restart),
    ('inbox_limits', case_inbox_limits),
    ('rates_and_streams', case_rates_and_streams),
    ('slow_reader_and_reconnect', case_slow_reader_and_reconnect),
    ('full_disk', case_full_disk),
    ('peer_credentials', case_peer_credentials),
    ('log_privacy', case_log_privacy),
]
NAMESPACE_CASES = ('full_disk', 'peer_credentials')


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mailbox', type=Path, required=True)
    parser.add_argument('--result', type=Path, help='write a JSON result here')
    parser.add_argument('--only', action='append', help='run only the named cases')
    parser.add_argument('--namespace-child', type=Path, help=argparse.SUPPRESS)
    parser.add_argument('--full-disk-child', type=Path, help=argparse.SUPPRESS)
    parser.add_argument('--without-namespace', action='store_true',
                        help='skip the cases that need user namespaces instead of failing')
    arguments = parser.parse_args()
    program = arguments.mailbox.resolve(strict=True)
    require(program.is_file(), 'the mailbox program is not a regular file')
    if arguments.namespace_child:
        return run_namespace_child(program, arguments.namespace_child)
    if arguments.full_disk_child:
        return run_full_disk_child(program, arguments.full_disk_child)
    selected = [case for case in CASES if not arguments.only or case[0] in arguments.only]
    if arguments.without_namespace:
        selected = [case for case in selected if case[0] not in NAMESPACE_CASES]
    require(selected, 'no case selected')
    results = []
    os.umask(0o077)
    with tempfile.TemporaryDirectory(prefix='ito-mailbox-', dir='/tmp') as temporary:
        ctx = Context(program, Path(temporary))
        try:
            for name, case in selected:
                started = time.monotonic()
                entry = {'case': name}
                try:
                    entry['details'] = case(ctx)
                    entry['passed'] = True
                except (Failure, OSError, ValueError, subprocess.SubprocessError) as error:
                    entry['passed'] = False
                    entry['error'] = f'{type(error).__name__}: {error}'
                    entry['trace'] = traceback.format_exc(limit=4)
                entry['seconds'] = round(time.monotonic() - started, 2)
                print(f"{'PASS' if entry['passed'] else 'FAIL'} {name} ({entry['seconds']} s)"
                      + ('' if entry['passed'] else f": {entry['error']}"), flush=True)
                results.append(entry)
        finally:
            for mailbox in ctx.mailboxes:
                mailbox.close()
    summary = {'schema': 1, 'program': str(program),
               'program_sha256': hashlib.sha256(program.read_bytes()).hexdigest(),
               'cases': results, 'passed': all(entry['passed'] for entry in results),
               'count': len(results),
               'skipped': [] if not arguments.without_namespace else list(NAMESPACE_CASES)}
    if arguments.result:
        arguments.result.write_text(json.dumps(summary, indent=2) + '\n', encoding='utf-8')
    return 0 if summary['passed'] and len(results) == len(selected) else 1


if __name__ == '__main__':
    try:
        sys.exit(main())
    except Failure as failure:
        print(f'component test: {failure}', file=sys.stderr)
        sys.exit(1)
