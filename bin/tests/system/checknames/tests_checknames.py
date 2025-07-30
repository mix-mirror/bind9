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

from dns import update

import pytest

import isctest
from isctest.compat import dns_rcode


pytestmark = pytest.mark.extra_artifacts(
    [
        "ns1/*.example.db",
        "ns1/*.update.db",
        "ns1/*.update.db.jnl",
        "ns4/*.update.db",
        "ns4/*.update.db.jnl",
        "ns5/*.update.db",
        "ns5/*.update.db.jnl",
    ]
)


def test_checknames_logging(ns1, ns2, ns3):
    # check failure on zone load for 'check-names fail;'
    msg = isctest.query.create("fail.example", "a")
    res = isctest.query.tcp(msg, "10.53.0.1")
    isctest.check.servfail(res)
    ns1.log.expect("xx_xx.fail.example: bad owner name (check-names)")

    # check warning on zone load for 'check-names warn;'
    msg = isctest.query.create("warn.example", "a")
    res = isctest.query.tcp(msg, "10.53.0.1")
    isctest.check.noerror(res)
    ns1.log.expect("xx_xx.warn.example: bad owner name (check-names)")

    # check no warning on zone load for 'check-names ignore;'
    ns1.log.prohibit("yy_yy.ignore.example: bad owner name (check-names)")

    # check 'check-names response warn;'
    msg = isctest.query.create("yy_yy.ignore.example", "a")
    res1 = isctest.query.tcp(msg, "10.53.0.1")
    res2 = isctest.query.tcp(msg, "10.53.0.2")
    isctest.check.noerror(res1)
    isctest.check.noerror(res2)
    isctest.check.same_data(res1, res2)
    ns2.log.expect("check-names warning yy_yy.ignore.example/A/IN")

    # check 'check-names response fail;' (for owner name)
    res3 = isctest.query.tcp(msg, "10.53.0.3")
    isctest.check.refused(res3)
    ns3.log.expect("check-names failure yy_yy.ignore.example/A/IN")

    # check 'check-names response fail;' (for rdata name)
    msg = isctest.query.create("mx.ignore.example", "mx")
    res1 = isctest.query.tcp(msg, "10.53.0.1")
    res3 = isctest.query.tcp(msg, "10.53.0.3")
    isctest.check.noerror(res1)
    isctest.check.servfail(res3)
    ns3.log.expect("check-names failure mx.ignore.example/MX/IN")


def test_checknames_update(ns1, ns4, ns5):
    # check updates are rejected with 'check-names fail;'
    up = update.UpdateMessage("fail.update.")
    up.add("xxx_xxx.fail.update.", 600, "A", "10.10.10.1")
    res = isctest.query.tcp(up, "10.53.0.1")
    isctest.check.refused(res)
    msg = isctest.query.create("xxx_xxx.fail.update", "a")
    res = isctest.query.tcp(msg, "10.53.0.1")
    isctest.check.nxdomain(res)
    ns1.log.expect("xxx_xxx.fail.update/A: bad owner name (check-names)")

    # check updates succeed and are logged with 'check-names warn;'
    up = update.UpdateMessage("warn.update.")
    up.add("xxx_xxx.warn.update.", 600, "A", "10.10.10.1")
    res = isctest.query.tcp(up, "10.53.0.1")
    isctest.check.noerror(res)
    msg = isctest.query.create("xxx_xxx.warn.update", "a")
    res = isctest.query.tcp(msg, "10.53.0.1")
    isctest.check.noerror(res)
    ns1.log.expect("xxx_xxx.warn.update/A: bad owner name (check-names)")

    # check updates succeed and aren't logged with 'check-names ignore;'
    up = update.UpdateMessage("ignore.update.")
    up.add("xxx_xxx.ignore.update.", 600, "A", "10.10.10.1")
    res = isctest.query.tcp(up, "10.53.0.1")
    isctest.check.noerror(res)
    msg = isctest.query.create("xxx_xxx.ignore.update", "a")
    res = isctest.query.tcp(msg, "10.53.0.1")
    isctest.check.noerror(res)
    ns1.log.prohibit("xxx_xxx.ignore.update/A: bad owner name (check-names)")

    # updates succeed and aren't logged with 'check-names primary ignore;'
    up = update.UpdateMessage("primary-ignore.update.")
    up.add("xxx_xxx.primary-ignore.update.", 600, "A", "10.10.10.1")
    res = isctest.query.tcp(up, "10.53.0.4")
    isctest.check.noerror(res)
    msg = isctest.query.create("xxx_xxx.primary-ignore.update", "a")
    res = isctest.query.tcp(msg, "10.53.0.4")
    isctest.check.noerror(res)
    ns4.log.prohibit("xxx_xxx.primary-ignore.update/A: bad owner name (check-names)")

    # updates succeed and aren't logged with 'check-names master ignore;'
    up = update.UpdateMessage("master-ignore.update.")
    up.add("xxx_xxx.master-ignore.update.", 600, "A", "10.10.10.1")
    res = isctest.query.tcp(up, "10.53.0.5")
    isctest.check.noerror(res)
    msg = isctest.query.create("xxx_xxx.master-ignore.update", "a")
    res = isctest.query.tcp(msg, "10.53.0.5")
    isctest.check.noerror(res)
    ns5.log.prohibit("xxx_xxx.master-ignore.update/A: bad owner name (check-names)")

    # updates succeed and aren't logged with 'check-names secondary ignore;'
    def wait_for_record1():
        msg = isctest.query.create("xxx_xxx.master-ignore.update", "a")
        res = isctest.query.tcp(msg, "10.53.0.4")
        return res.rcode() == dns_rcode.NOERROR

    isctest.run.retry_with_timeout(wait_for_record1, 10)
    ns4.log.prohibit("xxx_xxx.master-ignore.update/A: bad owner name (check-names)")

    def wait_for_record2():
        msg = isctest.query.create("xxx_xxx.primary-ignore.update", "a")
        res = isctest.query.tcp(msg, "10.53.0.4")
        return res.rcode() == dns_rcode.NOERROR

    isctest.run.retry_with_timeout(wait_for_record2, 10)
    ns4.log.prohibit("xxx_xxx.primary-ignore.update/A: bad owner name (check-names)")
