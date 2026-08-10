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

import select
import signal
import subprocess
import time

import pytest

import isctest.vars

pytestmark = pytest.mark.extra_artifacts(
    [
        # created by setup.sh
        "good1.db.raw",
        "named-compilezone",
        "zones/bad-tsig.db",
        # created by the tests below
        "sigint.conf",
    ]
)

# A tool that handles the interrupt gracefully cleans up and exits
# with status 1; a tool killed by the signal's default action reports
# -SIGINT instead, so the tests must not accept just any nonzero code.
GRACEFUL_EXIT = 1

# Upper bound on any wait; only reached when the interrupt handling
# is broken.
TIMEOUT = 10

# Enough zone data (~2 MB) to exceed any pipe capacity (64 kB by
# default on Linux, 1 MB at most): once a write of this much has been
# consumed, the tool is provably reading the stream, and once this
# much dump output has been written to an unread pipe, the dump is
# provably blocked.
PIPE_SYNC_RECORDS = 65536

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


def interrupt_load(args):
    """Run a tool that reads a zone from stdin, interrupt it while
    the zone is provably still being loaded, and return its exit
    code."""
    with subprocess.Popen(
        args,
        stdin=subprocess.PIPE,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    ) as proc:
        # Feed an incomplete zone and keep the stream open, so the
        # load cannot finish before the interrupt, however fast the
        # machine.  Once the flush returns, more data than the pipe
        # can hold has been consumed: the tool is loading the zone,
        # and the loop manager's signal handlers are installed.
        try:
            proc.stdin.write(ZONE_HEADER.encode("ascii"))
            proc.stdin.write(records(PIPE_SYNC_RECORDS).encode("ascii"))
            proc.stdin.flush()
        except (BrokenPipeError, OSError):
            proc.wait()
            pytest.fail(f"{args[0]} exited while the zone was being fed")

        proc.send_signal(signal.SIGINT)

        # The loader only checks for cancellation between records, so
        # keep the stream flowing instead of leaving it blocked on a
        # read.
        i = PIPE_SYNC_RECORDS
        deadline = time.monotonic() + TIMEOUT
        try:
            while proc.poll() is None and time.monotonic() < deadline:
                proc.stdin.write(record(i).encode("ascii"))
                proc.stdin.flush()
                i += 1
        except (BrokenPipeError, OSError):
            pass
        try:
            proc.stdin.close()
        except (BrokenPipeError, OSError):
            pass

        try:
            return proc.wait(timeout=TIMEOUT)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
            pytest.fail(f"{args[0]} did not exit after SIGINT")


def test_checkzone_sigint():
    """Interrupt named-checkzone while it is loading a zone; it must
    cancel the load, clean up and exit with status 1."""
    args = [isctest.vars.ALL["CHECKZONE"], "-q", "example", "-"]
    assert interrupt_load(args) == GRACEFUL_EXIT


def test_checkconf_sigint():
    """Interrupt "named-checkconf -z" while it is loading a zone; it
    must cancel the load, clean up and exit with status 1.  The zone
    file "-" makes named-checkconf load the zone from stdin, driven
    the same way as in the named-checkzone test."""
    with open("sigint.conf", "w", encoding="utf-8") as f:
        f.write('zone "example" { type primary; file "-"; };\n')
    args = [isctest.vars.ALL["CHECKCONF"], "-z", "sigint.conf"]
    assert interrupt_load(args) == GRACEFUL_EXIT


def test_compilezone_sigint():
    """Interrupt named-compilezone while it is dumping a zone; it
    must cancel the dump, clean up and exit with status 1.

    The zone (complete this time, so that the load can finish) is
    dumped to stdout, which is not read until after the interrupt:
    the dump blocks once the pipe is full, so it cannot finish early.
    The first bytes on stdout show that the dump phase has started.
    """
    with subprocess.Popen(
        ["./named-compilezone", "-q", "-o", "-", "example", "-"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    ) as proc:
        try:
            proc.stdin.write(ZONE_HEADER.encode("ascii"))
            proc.stdin.write(records(PIPE_SYNC_RECORDS).encode("ascii"))
            proc.stdin.close()
        except (BrokenPipeError, OSError):
            proc.wait()
            pytest.fail("named-compilezone exited while the zone was being fed")

        ready, _, _ = select.select([proc.stdout], [], [], TIMEOUT)
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
            pytest.fail("named-compilezone did not exit after SIGINT")
        assert proc.returncode == GRACEFUL_EXIT
