#!/usr/bin/env python3

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

"""Demonstrate the pytest-xdist loadscope bug with "::" in test parameters.

LoadScopeScheduling._split_scope uses rsplit("::", 1) to extract the
test scope (file) from a node ID.  When a parametrized test value
contains "::" (e.g. IPv6 addresses), the split lands inside the
parameter instead of at the .py:: boundary, creating spurious scopes
that get assigned to different workers.

Usage:
    python3 util/verify-split-scope-fix.py
"""

from xdist.scheduler.loadscope import LoadScopeScheduling

NODEIDS = [
    "synthrecord/tests_synthrecord.py::test_synthrecord_checkconf",
    "synthrecord/tests_synthrecord.py::test_synthreverse_idn_compat[::1-dynamic-0--1.example.]",
    "synthrecord/tests_synthrecord.py::test_synthreverse_idn_compat[::-dynamic-0--0.example.]",
    "synthrecord/tests_synthrecord.py::test_synthrecord_forward[dynamic-cafe-cafe--cafe.example-AAAA-cafe:cafe::cafe-AAAA-3600]",
    "synthrecord/tests_synthrecord.py::test_synthrecord_forward[dynamic-cafe-cafe--cafe.example-ANY-cafe:cafe::cafe-AAAA-3600]",
    "synthrecord/tests_synthrecord.py::test_synthrecord_forward_nodata[dynamic-cafe:: .example-AAAA]",
    "synthrecord/tests_synthrecord.py::test_synthreverse_idn_compat[cafe:cafe::-dynamic-cafe-cafe--0.example.]",
]

EXPECTED_SCOPE = "synthrecord/tests_synthrecord.py"


def _fixed_split_scope(self, nodeid):
    if ".py::" in nodeid:
        return nodeid.split(".py::")[0] + ".py"
    return orig_split_scope(self, nodeid)


orig_split_scope = LoadScopeScheduling._split_scope
sched = LoadScopeScheduling.__new__(LoadScopeScheduling)

print("=== Before fix (upstream _split_scope) ===\n")

broken = 0
for nid in NODEIDS:
    scope = orig_split_scope(sched, nid)
    ok = scope == EXPECTED_SCOPE
    if not ok:
        broken += 1
    tag = "ok" if ok else "WRONG"
    print(f"  [{tag:>5s}]  scope = {scope}")

print(f"\n  {broken}/{len(NODEIDS)} tests get a wrong scope\n")

LoadScopeScheduling._split_scope = _fixed_split_scope

print("=== After fix ===\n")

fixed = 0
for nid in NODEIDS:
    scope = sched._split_scope(nid)
    ok = scope == EXPECTED_SCOPE
    if ok:
        fixed += 1
    tag = "ok" if ok else "WRONG"
    print(f"  [{tag:>5s}]  scope = {scope}")

print(f"\n  {fixed}/{len(NODEIDS)} tests get the correct scope\n")

LoadScopeScheduling._split_scope = orig_split_scope

if broken > 0 and fixed == len(NODEIDS):
    print("PASS: fix corrects all broken scopes")
else:
    print("FAIL")
    raise SystemExit(1)
