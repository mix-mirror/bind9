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

import pytest

pytest.importorskip("dns", minversion="2.0.0")
from dns import zone

import isctest

pytestmark = pytest.mark.extra_artifacts(
    [
        "good1.db.raw",
        "zones/good.zonemd.db",
        "zones/bad.zonemd.db",
        "named-compilezone",
        "test.*",
        "zones/bad-tsig.db",
        "zones/zone1_*.txt",
    ]
)

CHECKZONE = os.environ.get("CHECKZONE")


def test_checkzone_z():
    # create a zone with an unsigned but otherwise valid ZONEMD
    try:
        z = zone.from_file("zones/good1.db", origin="example")
        zonemd = z.compute_digest(1, 1)
        w = z.writer()
        w.add("@", 600, zonemd)
        w.commit()
        z.to_file("zones/good.zonemd.db")
    # pylint: disable=bare-except
    except:
        assert False, "unable to generate ZONEMD"

    output = isctest.run.cmd(
        [CHECKZONE, "-z", "fail", "example", "zones/good.zonemd.db"],
        raise_on_exception=True,
        log_stdout=True,
    )
    stream = (output.stdout + output.stderr).decode("utf-8").replace("\n", "")
    assert "OK" in stream

    # now use the same ZONEMD in different zone
    try:
        z = zone.from_file("zones/test1.db", origin="example")
        w = z.writer()
        w.add("@", 600, zonemd)
        w.commit()
        z.to_file("zones/bad.zonemd.db")
    # pylint: disable=bare-except
    except:
        assert False, "unable to add bad ZONEMD"

    output = isctest.run.cmd(
        [CHECKZONE, "-z", "fail", "example", "zones/bad.zonemd.db"],
        raise_on_exception=False,
        log_stdout=True,
    )
    stream = (output.stdout + output.stderr).decode("utf-8").replace("\n", "")
    assert "not loaded due to errors" in stream
