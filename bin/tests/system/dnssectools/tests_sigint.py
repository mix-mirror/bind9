# Copyright (C) Internet Systems Consortium, Inc. ("ISC")
#
# SPDX-License-Identifier: MPL-2.0
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0.  If a copy of the MPL was not distributed with this
# file, you can obtain one at https://mozilla.org/MPL/2.0/.
#
# See the COPYRIGHT file distributed with this work for additional
# information regarding copyright ownership.

import fcntl
import os
import select
import signal
import subprocess
import time

import pytest

import isctest.vars

pytestmark = pytest.mark.extra_artifacts(
    [
        # generated from kasp.conf.j2 for the whole test directory
        "kasp.conf",
        # created by the tests below
        "Ksigint.example.*",
        "dsset-sigint.example.",
        "sigint-new.db",
        "sigint.db",
        "sigint.fifo",
    ]
)

# A tool that handles the interrupt gracefully cleans up and exits
# with status 1; a tool killed by the signal's default action reports
# -SIGINT instead, so the tests must not accept just any nonzero code.
GRACEFUL_EXIT = 1

# Upper bound on any wait for the cancellation itself; only reached
# when the interrupt handling is broken.
TIMEOUT = 10

# Upper bound on waits that include real signing work.
SIGN_TIMEOUT = 60

# Enough zone data (~2 MB) to exceed any pipe capacity (64 kB by
# default on Linux, 1 MB at most): once a write of this much has been
# consumed, the tool is provably reading the zone, and once this much
# dump output has been written to an unread pipe, the dump is provably
# blocked.
PIPE_SYNC_RECORDS = 65536

# Enough records that the signed zone dumped as text exceeds any pipe
# capacity, while keeping the signing time short.
DUMP_RECORDS = 8192

ZONE_HEADER = (
    "$TTL 300\n"
    "@ IN SOA ns root 1 300 300 300 300\n"
    "@ IN NS ns\n"
    "ns IN A 10.53.0.1\n"
)


def record(i):
    return f"host{i} IN A 10.{(i >> 16) & 255}.{(i >> 8) & 255}.{i & 255}\n"


def records(n):
    return "".join(record(i) for i in range(n))


def open_fifo_writer(path, proc, tool):
    """Open the write end of 'path' without blocking forever if
    'proc' never opens the read end."""
    deadline = time.monotonic() + TIMEOUT
    while time.monotonic() < deadline:
        try:
            fd = os.open(path, os.O_WRONLY | os.O_NONBLOCK)
            break
        except OSError:
            if proc.poll() is not None:
                pytest.fail(f"{tool} exited before opening the zone")
            time.sleep(0.05)
    else:
        pytest.fail(f"{tool} never opened the zone file")
    flags = fcntl.fcntl(fd, fcntl.F_GETFL)
    fcntl.fcntl(fd, fcntl.F_SETFL, flags & ~os.O_NONBLOCK)
    return fd


def interrupt_load(args, trailing_args=None):
    """Run a tool that reads a zone from a FIFO, interrupt it while
    the zone is provably still being loaded, and return its exit
    code.  The FIFO is kept open and incomplete, so the load cannot
    finish before the interrupt, however fast the machine."""
    tool = os.path.basename(args[0])
    if os.path.exists("sigint.fifo"):
        os.unlink("sigint.fifo")
    os.mkfifo("sigint.fifo")
    with subprocess.Popen(
        args + ["sigint.fifo"] + (trailing_args or []),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    ) as proc:
        fd = open_fifo_writer("sigint.fifo", proc, tool)
        try:
            # Once this write returns, more data than the pipe can
            # hold has been consumed: the tool is loading the zone,
            # and the loop manager's signal handlers are installed.
            os.write(fd, ZONE_HEADER.encode("ascii"))
            os.write(fd, records(PIPE_SYNC_RECORDS).encode("ascii"))
        except OSError:
            proc.wait()
            pytest.fail(f"{tool} exited while the zone was being fed")

        proc.send_signal(signal.SIGINT)

        # The loader only checks for cancellation between records, so
        # keep the stream flowing instead of leaving it blocked on a
        # read.
        i = PIPE_SYNC_RECORDS
        deadline = time.monotonic() + TIMEOUT
        try:
            while proc.poll() is None and time.monotonic() < deadline:
                os.write(fd, record(i).encode("ascii"))
                i += 1
        except OSError:
            pass
        os.close(fd)

        try:
            return proc.wait(timeout=TIMEOUT)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
            pytest.fail(f"{tool} did not exit after SIGINT")


def test_signzone_sigint_load():
    """Interrupt dnssec-signzone while it is loading a zone; it must
    cancel the load, clean up and exit with status 1."""
    args = [isctest.vars.ALL["SIGNER"], "-o", "sigint.example"]
    assert interrupt_load(args) == GRACEFUL_EXIT


def test_verify_sigint_load():
    """Interrupt dnssec-verify while it is loading a zone; it must
    cancel the load, clean up and exit with status 1."""
    args = [isctest.vars.ALL["VERIFY"], "-o", "sigint.example"]
    assert interrupt_load(args) == GRACEFUL_EXIT


def test_makejournal_sigint_load():
    """Interrupt named-makejournal while it is loading the old zone;
    it must cancel the load, clean up and exit with status 1."""
    with open("sigint-new.db", "w", encoding="ascii") as f:
        f.write(ZONE_HEADER)
    args = [isctest.vars.ALL["MAKEJOURNAL"], "sigint.example"]
    assert interrupt_load(args, ["sigint-new.db"]) == GRACEFUL_EXIT


def test_signzone_sigint_dump():
    """Interrupt dnssec-signzone while it is dumping the signed zone;
    it must cancel the dump, clean up and exit with status 1.

    The zone (complete this time, so that loading and signing can
    finish) is dumped to stdout, which is not read until after the
    interrupt: the dump blocks once the pipe is full, so it cannot
    finish early.  The first bytes on stdout show that the dump phase
    has started."""
    for keyflags in ([], ["-f", "KSK"]):
        subprocess.run(
            [isctest.vars.ALL["KEYGEN"], "-q", "-a", "ECDSAP256SHA256"]
            + keyflags
            + ["sigint.example"],
            check=True,
            stdout=subprocess.DEVNULL,
        )
    with open("sigint.db", "w", encoding="ascii") as f:
        f.write(ZONE_HEADER)
        f.write(records(DUMP_RECORDS))

    with subprocess.Popen(
        [
            isctest.vars.ALL["SIGNER"],
            "-S",
            "-o",
            "sigint.example",
            "-f",
            "-",
            "sigint.db",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    ) as proc:
        ready, _, _ = select.select([proc.stdout], [], [], SIGN_TIMEOUT)
        if not ready or not proc.stdout.read(1):
            proc.kill()
            proc.communicate()
            pytest.fail("the dump phase never started")

        proc.send_signal(signal.SIGINT)

        # Drain stdout so that the dumper unblocks and notices the
        # cancellation.
        try:
            proc.communicate(timeout=TIMEOUT)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.communicate()
            pytest.fail("dnssec-signzone did not exit after SIGINT")
        assert proc.returncode == GRACEFUL_EXIT
