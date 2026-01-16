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

import os

import requests

import isctest.mark

pytestmark = [isctest.mark.with_json_c, isctest.mark.with_developer]


def get_delegdb_contexts(ip, port):
    ids = []
    r = requests.get(f"http://{ip}:{port}/json/v1/mem", timeout=600)
    assert r.status_code == 200
    mem = r.json()["memory"]
    for c in mem["contexts"]:
        if c["name"] == "dns_delegdb":
            ids.append(c["id"])
    return ids


def test_delegdb_flush(ns1):
    statsport = os.getenv("EXTRAPORT1")

    ids1 = get_delegdb_contexts(ns1.ip, statsport)
    assert len(ids1) > 0

    with ns1.watch_log_from_here() as watcher:
        ns1.rndc("flush")
        watcher.wait_for_sequence(
            ["flushing caches in all views succeeded", "loop exclusive mode: ended"]
        )

    # The previous delegdb contexts can still be hanging around for a little
    # bit, until RCU reclamation run and it actually gets detached/freed.
    for id1 in ids1:
        with ns1.watch_log_from_start() as watcher:
            watcher.wait_for_line(f"destroyed mctx {id1}")

    # Every delegdb has been replaced by a fresh one.
    ids2 = get_delegdb_contexts(ns1.ip, statsport)
    assert len(ids1) == len(ids2)
    for id1, id2 in zip(ids1, ids2):
        assert id1 != id2
