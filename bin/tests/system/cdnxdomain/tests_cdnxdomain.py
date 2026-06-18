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

"""
Regression test for issue #5877: a CD=1 (checking-disabled) NXDOMAIN response
is cached at dns_trust_pending_answer and must not evict a DNSSEC-validated
RRset cached at dns_trust_secure for the same name.

ns1 is a validating resolver that forwards "example" to the signed ns2.  We
prime the cache with a validated a.example/A (trust=secure), flip ns2 to a
version of the zone where a.example no longer exists, and send a CD=1 query
that makes the resolver cache an unvalidated NXDOMAIN for a.example.  The
originally cached, more-trusted A record must survive.
"""

import shutil

import isctest

RESOLVER = "10.53.0.1"
AUTH = "10.53.0.2"
A_RDATA = "10.53.0.99"


def _serve(ns2, system_test_dir, variant):
    """Make ns2 serve the 'full' or 'empty' (a.example-less) signed zone."""
    src = system_test_dir / "ns2" / f"example-{variant}.db.signed"
    shutil.copyfile(src, system_test_dir / "ns2" / "example.db.signed")
    ns2.reload()


def _prime_secure_a(ns1):
    """Cache a.example/A at trust=secure and confirm it validated (AD=1)."""
    ns1.rndc("flush")
    res = isctest.query.tcp(isctest.query.create("a.example", "A"), RESOLVER)
    isctest.check.noerror(res)
    isctest.check.adflag(res)
    assert A_RDATA in str(res.answer), res.answer


def test_cd1_nxdomain_keeps_secure_rrset(ns1, ns2, system_test_dir):
    # Prime the resolver with a DNSSEC-validated a.example/A (trust=secure).
    _serve(ns2, system_test_dir, "full")
    _prime_secure_a(ns1)

    # Flip the authoritative zone to a (still signed) version without
    # a.example, so the name now yields a signed NXDOMAIN; confirm at ns2.
    _serve(ns2, system_test_dir, "empty")
    direct = isctest.query.create("a.example", "A", dnssec=False)
    isctest.check.nxdomain(isctest.query.tcp(direct, AUTH))

    # A CD=1 query elicits an unvalidated NXDOMAIN for a.example, cached at
    # trust=pending_answer.  The the secure A record should not be evicted.
    cd_msg = isctest.query.create("a.example", "TXT", cd=True)
    isctest.query.tcp(cd_msg, RESOLVER)

    # The resolver should not refetch from the zone; the validated A
    # record should still be served from cache.
    res = isctest.query.tcp(isctest.query.create("a.example", "A"), RESOLVER)
    isctest.check.noerror(res)
    isctest.check.adflag(res)
    assert A_RDATA in str(res.answer), res.answer


def test_cd1_nxdomain_uncached_type_answer(ns1, ns2, system_test_dir):
    # Prime a.example/A at trust=secure, then make a.example yield NXDOMAIN.
    _serve(ns2, system_test_dir, "full")
    _prime_secure_a(ns1)
    _serve(ns2, system_test_dir, "empty")

    # CD=1 query for an UNCACHED type (AAAA): the unvalidated NXDOMAIN is
    # rejected in favour of the secure A.  Returning the cached A record (the
    # wrong type) in the answer section is incorrect; the answer must be empty.
    res = isctest.query.tcp(
        isctest.query.create("a.example", "AAAA", cd=True), RESOLVER
    )
    isctest.check.servfail(res)
    isctest.check.empty_answer(res)
