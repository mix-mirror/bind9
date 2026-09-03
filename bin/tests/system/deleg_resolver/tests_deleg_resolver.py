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

import pytest

import isctest


def test_deleg_resolver_delegonly(ns10):
    msg = isctest.query.create("a.delegonly", "A")
    res = isctest.query.udp(msg, ns10.ip)
    isctest.check.noerror(res)


def test_deleg_resovler_mixed(ns10):
    msg = isctest.query.create("a.mixed", "A")
    res = isctest.query.udp(msg, ns10.ip)
    isctest.check.noerror(res)


def test_deleg_resolver_delegname(ns10):
    msg = isctest.query.create("a.delegname", "A")
    res = isctest.query.udp(msg, ns10.ip)
    isctest.check.noerror(res)


def test_deleg_resolver_delegips(ns10):
    msg = isctest.query.create("a.delegips", "A")
    res = isctest.query.udp(msg, ns10.ip)
    isctest.check.noerror(res)


def test_deleg_resolver_mandatory(ns10):
    msg = isctest.query.create("a.delegmandatory", "A")
    res = isctest.query.udp(msg, ns10.ip)
    isctest.check.noerror(res)
