# Copyright (C) 2026 FixCraft Inc. AGPL-3.0-or-later.
"""Mailbox test helpers: version-1 frames, the mailbox process and its replies.

The byte-stream and module-peer classes come from relay/tests, which the call
harness also imports, so every Ito module test plays yumed the same way. The
frames here are written out from docs/MAILBOX.md, not from the service.
"""
from __future__ import annotations

import hashlib
import json
import os
import signal
import socket
import struct
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'relay' / 'tests'))
from relay_peers import Failure, ModulePeer, Stream, require  # noqa: E402,F401

SERVICE = 'ito-mailbox'
LOG_KEY = 'ito_mailbox'
MESSAGE, RING = 1, 2
DONE, NOT_HERE, LATER = 1, 2, 3
UNSUPPORTED, CAPACITY, TIMEOUT, INVALID_REQUEST = 2, 3, 5, 6
SIZES = (1024, 4096, 16384)
ITEM_HEAD = 58


def frame(kind: int, payload: bytes = b'') -> bytes:
    return struct.pack('>IB', 1 + len(payload), kind) + payload


def open_inboxes(secrets: list[bytes], version: int = 1) -> bytes:
    return frame(1, struct.pack('>H', version) + b''.join(secrets))


def close_inbox(secret: bytes, version: int = 1) -> bytes:
    return frame(5, struct.pack('>H', version) + secret)


def deposit(address: bytes, item_class: int, lifetime: int, sealed: bytes,
            version: int = 1) -> bytes:
    return frame(7, struct.pack('>H', version) + address +
                 struct.pack('>BI', item_class, lifetime) + sealed)


def taken(ids: list[bytes]) -> bytes:
    return frame(4, b''.join(ids))


PING = frame(10)
PONG = frame(11)


def opened(statuses: list[int]) -> bytes:
    return frame(2, bytes(statuses))


def closed(status: int) -> bytes:
    return frame(6, bytes([status]))


def rejected(status: int) -> bytes:
    return frame(9, bytes([status]))


def refused(reason: int) -> bytes:
    return frame(12, bytes([reason]))


def address_of(secret: bytes) -> bytes:
    return hashlib.sha256(b'ito/mailbox-address/1\0' + secret).digest()


def secret_for(label: str) -> bytes:
    return hashlib.sha256(b'mailbox-test-secret/' + label.encode()).digest()


def sealed_bytes(seed: str, size: int) -> bytes:
    """Deterministic stand-in for sealed bytes, independent of the service."""
    out = bytearray()
    counter = 0
    while len(out) < size:
        out += hashlib.sha256(f'{seed}/{counter}'.encode()).digest()
        counter += 1
    return bytes(out[:size])


@dataclass
class Item:
    item_class: int
    address: bytes
    id: bytes
    deposit_minute: int
    seconds_left: int
    sealed: bytes


def read_frame(stream: Stream, what: str, timeout: float = 5.0) -> bytes:
    """One whole frame, length prefix included."""
    try:
        head = stream.read_exact(4, timeout)
        return head + stream.read_exact(struct.unpack('>I', head)[0], timeout)
    except Failure as failure:
        raise Failure(f'{what}: {failure}') from None


def read_item(stream: Stream, what: str, timeout: float = 5.0) -> Item:
    data = read_frame(stream, what, timeout)
    require(data[4] == 3 and len(data) - 4 - ITEM_HEAD in SIZES,
            f'{what}: not an ITEM: {data[:8].hex()}')
    item_class = data[5]
    minute, left = struct.unpack('>II', data[54:62])
    return Item(item_class, data[6:38], data[38:54], minute, left, data[62:])


def expect_frame(stream: Stream, expected: bytes, what: str, timeout: float = 5.0) -> None:
    got = read_frame(stream, what, timeout)
    require(got == expected, f'{what}: expected {expected.hex()}, got {got[:24].hex()}')


def open_ok(stream: Stream, secrets: list[bytes], statuses: list[int], what: str) -> None:
    stream.send(open_inboxes(secrets))
    expect_frame(stream, opened(statuses), what)


def deposit_ok(stream: Stream, address: bytes, item_class: int, lifetime: int, sealed: bytes,
               what: str, granted: int | None = None) -> bytes:
    """Deposits and returns the item ID, checking the granted lifetime."""
    stream.send(deposit(address, item_class, lifetime, sealed))
    reply = read_frame(stream, what)
    require(len(reply) == 25 and reply[4] == 8, f'{what}: not DEPOSITED: {reply[:8].hex()}')
    expected = granted if granted is not None else lifetime
    got = struct.unpack('>I', reply[21:25])[0]
    require(got == expected, f'{what}: granted {got} s, expected {expected} s')
    return reply[5:21]


def expect_refused(stream: Stream, reason: int, what: str, timeout: float = 5.0) -> None:
    expect_frame(stream, refused(reason), what, timeout)
    stream.expect_end(f'{what}, after REFUSED')


def expect_quiet(stream: Stream, what: str, seconds: float = 0.5) -> None:
    data = stream.receive(1, seconds)
    require(data is None, f'{what}: expected nothing, got {data!r:.40}')


class MailboxProcess:
    """ito-mailbox serving a listener this object holds, as a socket unit does.

    The listener and the data directory outlive the program, so a restart
    reuses both, and connections made while no program runs wait in the
    listener's queue.
    """

    def __init__(self, program: Path, directory: Path, name: str = 'mailbox') -> None:
        self.program = program
        self.directory = directory
        self.data = directory / f'{name}-data'
        self.data.mkdir(mode=0o700)
        self.path = directory / f'{name}.sock'
        self.log_path = directory / f'{name}.log'
        self.listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.listener.bind(str(self.path))
        os.chmod(self.path, 0o600)
        self.listener.listen(4096)
        self.pid: int | None = None
        self.exit_code: int | None = None

    def arguments(self, *extra: str) -> list[str]:
        return ['--service', SERVICE, '--daemon-uid', str(os.getuid()),
                '--data', str(self.data), *extra]

    def spawn(self, arguments: list[str] | None = None, listener: socket.socket | None = None,
              environment: dict[str, str] | None = None, prefix: list[str] | None = None,
              pass_listener: bool = True) -> int:
        chosen = self.listener if listener is None else listener
        descriptor = chosen.fileno()
        # dup2 onto itself would keep close-on-exec.
        duplicate = os.dup(descriptor) if descriptor == 3 else None
        source = duplicate if duplicate is not None else descriptor
        log = os.open(self.log_path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        null = os.open(os.devnull, os.O_RDONLY)
        try:
            actions = [(os.POSIX_SPAWN_DUP2, null, 0), (os.POSIX_SPAWN_DUP2, log, 1),
                       (os.POSIX_SPAWN_DUP2, log, 2)]
            if pass_listener:
                actions.append((os.POSIX_SPAWN_DUP2, source, 3))
            argv = (prefix or []) + [str(self.program)] + (
                arguments if arguments is not None else self.arguments())
            env = {'PATH': '/usr/bin:/bin'} if environment is None else environment
            self.pid = os.posix_spawn(argv[0], argv, env, file_actions=actions)
            self.exit_code = None
            return self.pid
        finally:
            os.close(log)
            os.close(null)
            if duplicate is not None:
                os.close(duplicate)

    def lines(self) -> list[dict]:
        if not self.log_path.exists():
            return []
        # Only lines the program finished, with their newline, are parsed.
        complete = self.log_path.read_bytes().rpartition(b'\n')[0]
        return [json.loads(raw) for raw in complete.splitlines() if raw.startswith(b'{')]

    def start(self, arguments: list[str] | None = None, timeout: float = 10.0) -> None:
        ready_before = sum(1 for line in self.lines() if line.get(LOG_KEY) == 'ready')
        self.spawn(arguments)
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if sum(1 for line in self.lines() if line.get(LOG_KEY) == 'ready') > ready_before:
                return
            if self.poll() is not None:
                raise Failure(f'the mailbox exited with {self.exit_code} before it was ready: '
                              f'{self.lines()[-1:]}')
            time.sleep(0.01)
        raise Failure('the mailbox did not report ready')

    def poll(self) -> int | None:
        if self.pid is None or self.exit_code is not None:
            return self.exit_code
        pid, status = os.waitpid(self.pid, os.WNOHANG)
        if pid == 0:
            return None
        self.exit_code = os.waitstatus_to_exitcode(status)
        return self.exit_code

    def wait(self, timeout: float) -> int:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            code = self.poll()
            if code is not None:
                return code
            time.sleep(0.01)
        raise Failure('the mailbox did not exit in time')

    def stop(self) -> int:
        if self.poll() is None:
            os.kill(self.pid, signal.SIGTERM)
        return self.wait(20.0)

    def kill(self) -> None:
        if self.poll() is None:
            os.kill(self.pid, signal.SIGKILL)
            self.wait(10.0)

    def counts(self, timeout: float = 3.0) -> dict:
        before = sum(1 for line in self.lines() if line.get(LOG_KEY) == 'counts')
        os.kill(self.pid, signal.SIGUSR1)
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            counts = [line for line in self.lines() if line.get(LOG_KEY) == 'counts']
            if len(counts) > before:
                return counts[-1]
            time.sleep(0.01)
        raise Failure('the mailbox did not report its counts')

    def wait_for(self, condition: Callable[[dict], bool], what: str,
                 timeout: float = 5.0) -> dict:
        deadline = time.monotonic() + timeout
        counts = self.counts()
        while not condition(counts):
            require(time.monotonic() < deadline, f'{what}: counts stayed {counts}')
            time.sleep(0.1)
            counts = self.counts()
        return counts

    def peer(self, principal: str | None) -> ModulePeer:
        return ModulePeer(self.path, principal, SERVICE)

    def close(self) -> None:
        try:
            self.kill()
        finally:
            self.listener.close()
