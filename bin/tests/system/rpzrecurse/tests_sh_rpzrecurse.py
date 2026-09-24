# Copyright (C) Internet Systems Consortium, Inc. ("ISC")
#
# SPDX-License-Identifier: MPL-2.0
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, you can obtain one at https://mozilla.org/MPL/2.0/.
#
# See the COPYRIGHT file distributed with this work for additional
# information regarding copyright ownership.

from pathlib import Path

import os
import subprocess

import pytest

from rpzrecurse import common

pytestmark = pytest.mark.extra_artifacts(
    [
        "dig.out.*",
        "dnsrps.cache",
        "dnsrps.conf",
        "ans*/ans.run",
        "ns2/*.queries",
        "ns2/*.local",
        "ns2/named.*.conf",
        "ns2/named.conf.header",
    ]
)


def bootstrap():
    common.bootstrap()


# before test_rpzrecurse(): tests.sh overwrites ns2/db.6a.00.policy.local
def test_bootstrap_matches_testgen(tmp_path):
    (tmp_path / "ns2").mkdir()
    testgen = Path("testgen.pl").resolve()
    subprocess.run([os.environ["PERL"], testgen], cwd=tmp_path, check=True)
    generated = list((tmp_path / "ns2").iterdir())
    assert len(generated) > 1000
    for path in generated:
        assert path.read_bytes() == Path("ns2", path.name).read_bytes(), path.name


def test_rpzrecurse(run_tests_sh):
    run_tests_sh()
