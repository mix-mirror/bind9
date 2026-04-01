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

import time

import dns.rcode

import isctest


def query_manytypes(ns3, name, rdtype):
    """Query ns3 for name/rdtype and return the response."""
    msg = isctest.query.create(name, rdtype)
    return isctest.query.udp(msg, ns3.ip)


def assert_cached(ns3, name, rdtype, expected_rcode="NOERROR"):
    """Verify that a response for name/rdtype is served from cache.

    Queries twice with a 1-second gap. If the TTL decreases between
    queries, the response was served from cache.
    """
    res1 = query_manytypes(ns3, name, rdtype)
    assert res1.rcode() == dns.rcode.from_text(expected_rcode)

    # Extract TTL from the first non-empty section
    section = res1.answer or res1.authority
    assert len(section) > 0, f"no RRsets in response for {name}/{rdtype}"
    ttl1 = section[0].ttl

    time.sleep(1)

    res2 = query_manytypes(ns3, name, rdtype)
    assert res2.rcode() == dns.rcode.from_text(expected_rcode)

    section = res2.answer or res2.authority
    assert len(section) > 0, f"no RRsets in cached response for {name}/{rdtype}"
    ttl2 = section[0].ttl

    assert ttl2 < ttl1, (
        f"{name}/{rdtype}: TTL did not decrease ({ttl1} -> {ttl2}), "
        f"response was not served from cache"
    )


def assert_not_cached(ns3, name, rdtype, expected_rcode="NOERROR"):
    """Verify that a response for name/rdtype is NOT served from cache.

    Queries twice. If the TTL is the same (the original zone TTL) both
    times, the entry was re-fetched from the authoritative server.
    """
    res1 = query_manytypes(ns3, name, rdtype)
    assert res1.rcode() == dns.rcode.from_text(expected_rcode)

    section = res1.answer or res1.authority
    assert len(section) > 0, f"no RRsets in response for {name}/{rdtype}"
    ttl1 = section[0].ttl

    res2 = query_manytypes(ns3, name, rdtype)
    assert res2.rcode() == dns.rcode.from_text(expected_rcode)

    section = res2.answer or res2.authority
    assert len(section) > 0, f"no RRsets in response for {name}/{rdtype}"
    ttl2 = section[0].ttl

    # Both queries should return the same (original) TTL, meaning
    # the entry was fetched fresh from the auth server each time.
    assert ttl1 == ttl2, (
        f"{name}/{rdtype}: TTL changed ({ttl1} -> {ttl2}), "
        f"response appears to be cached"
    )


def test_priority_nxdomain_cached_under_limit(ns3, templates):
    """Priority NXDOMAIN types under max-types-per-name get cached."""
    templates.render("ns3/named.conf", template="ns3/named5.conf.j2")
    ns3.rndc("reconfig")
    ns3.rndc("flush")

    for rdtype in ["AAAA", "MX", "NS"]:
        assert_cached(ns3, "manytypes.big", rdtype)


def test_nxdomain_cached_under_limit(ns3):
    """Non-priority NXDOMAIN types under the limit get cached."""
    ns3.rndc("flush")

    for i in range(65270, 65280):
        assert_cached(ns3, "manytypes.big", f"TYPE{i}")


def test_existing_types_cached_under_limit(ns3):
    """Existing types under the limit get cached.

    The cache already has 10 NXDOMAIN types from the previous test.
    Caching 10 positive types should evict those and get cached.
    """
    for i in range(65280, 65290):
        assert_cached(ns3, "manytypes.big", f"TYPE{i}")


def test_nxdomain_not_cached_over_limit(ns3):
    """Non-priority NXDOMAIN types over the limit don't get cached.

    After the previous test filled 10 type slots with TYPE65280-65289,
    querying for 10 NXDOMAIN non-priority types should not cache them
    since the limit is already reached.
    """
    for i in range(65270, 65280):
        assert_not_cached(ns3, "manytypes.big", f"TYPE{i}")


def test_priority_nxdomain_cached_over_limit(ns3):
    """Priority NXDOMAIN types over the limit get cached.

    Even though max-types-per-name is exceeded, priority types (AAAA,
    MX, NS) should still be cached because they evict non-priority
    entries.
    """
    for rdtype in ["AAAA", "MX", "NS"]:
        assert_cached(ns3, "manytypes.big", rdtype)


def test_priority_type_cached_over_limit(ns3):
    """Priority positive type (A) over the limit gets cached."""
    assert_cached(ns3, "manytypes.big", "A")


def test_priority_type_not_evicted(ns3):
    """Priority types don't get evicted by non-priority types."""
    ns3.rndc("flush")

    # Cache a priority type
    res = query_manytypes(ns3, "manytypes.big", "A")
    assert res.rcode() == dns.rcode.NOERROR

    # Fill 10 more non-priority type slots
    for i in range(65280, 65290):
        query_manytypes(ns3, "manytypes.big", f"TYPE{i}")

    time.sleep(1)

    # The A record should still be cached
    res = query_manytypes(ns3, "manytypes.big", "A")
    assert res.rcode() == dns.rcode.NOERROR
    section = res.answer
    assert len(section) > 0
    assert (
        section[0].ttl < 120
    ), "A record was re-fetched (TTL=120), should have been cached"

    # The first non-priority type should have been evicted
    res = query_manytypes(ns3, "manytypes.big", "TYPE65280")
    assert res.rcode() == dns.rcode.NOERROR
    section = res.answer
    assert len(section) > 0
    assert (
        section[0].ttl == 120
    ), "TYPE65280 should have been evicted and re-fetched with TTL=120"


def test_non_priority_eviction(ns3):
    """Non-priority types cause eviction when over the limit."""
    ns3.rndc("flush")

    # Cache 20 non-priority types (limit is 10)
    for i in range(65280, 65300):
        query_manytypes(ns3, "manytypes.big", f"TYPE{i}")

    time.sleep(1)

    # The last 10 (65290-65299) should be cached
    for i in range(65290, 65300):
        res = query_manytypes(ns3, "manytypes.big", f"TYPE{i}")
        assert res.rcode() == dns.rcode.NOERROR
        section = res.answer
        assert len(section) > 0
        assert (
            section[0].ttl < 120
        ), f"TYPE{i} should be cached (TTL < 120), got TTL={section[0].ttl}"

    # The first 10 (65280-65289) should have been evicted; re-querying
    # them re-fetches from auth (TTL=120) and evicts the last 10.
    for i in range(65280, 65290):
        res = query_manytypes(ns3, "manytypes.big", f"TYPE{i}")
        assert res.rcode() == dns.rcode.NOERROR
        section = res.answer
        assert len(section) > 0
        assert (
            section[0].ttl == 120
        ), f"TYPE{i} should have been evicted (TTL=120), got TTL={section[0].ttl}"

    # The last 10 (65290-65299) should now have been evicted by the
    # re-fetch of the first 10 above.
    for i in range(65290, 65300):
        res = query_manytypes(ns3, "manytypes.big", f"TYPE{i}")
        assert res.rcode() == dns.rcode.NOERROR
        section = res.answer
        assert len(section) > 0
        assert (
            section[0].ttl == 120
        ), f"TYPE{i} should have been evicted (TTL=120), got TTL={section[0].ttl}"


def test_signed_types_under_limit(ns3):
    """Signed types under the limit get cached (type + RRSIG count as 2)."""
    ns3.rndc("flush")

    # 10 types with signatures = 20 entries, limit is 10 types
    for i in range(65280, 65290):
        query_manytypes(ns3, "manytypes.signed", f"TYPE{i}")

    time.sleep(1)

    # The last 5 types should be cached
    for i in range(65285, 65290):
        res = query_manytypes(ns3, "manytypes.signed", f"TYPE{i}")
        assert res.rcode() == dns.rcode.NOERROR
        section = res.answer
        assert len(section) > 0
        assert (
            section[0].ttl < 120
        ), f"TYPE{i} should be cached (TTL < 120), got TTL={section[0].ttl}"

    # The first 5 types should have been evicted; re-querying them
    # re-fetches from auth (TTL=120) and evicts the last 5.
    for i in range(65280, 65285):
        res = query_manytypes(ns3, "manytypes.signed", f"TYPE{i}")
        assert res.rcode() == dns.rcode.NOERROR
        section = res.answer
        assert len(section) > 0
        assert (
            section[0].ttl == 120
        ), f"TYPE{i} should have been evicted (TTL=120), got TTL={section[0].ttl}"

    # The last 5 types should now have been evicted by the re-fetch above.
    for i in range(65285, 65290):
        res = query_manytypes(ns3, "manytypes.signed", f"TYPE{i}")
        assert res.rcode() == dns.rcode.NOERROR
        section = res.answer
        assert len(section) > 0
        assert (
            section[0].ttl == 120
        ), f"TYPE{i} should have been evicted (TTL=120), got TTL={section[0].ttl}"


def test_no_limit(ns3, templates):
    """With max-types-per-name 0, everything gets cached."""
    templates.render("ns3/named.conf", template="ns3/named6.conf.j2")
    ns3.rndc("reconfig")
    ns3.rndc("flush")

    # Cache all 255 types
    for i in range(65280, 65535):
        query_manytypes(ns3, "manytypes.big", f"TYPE{i}")

    time.sleep(1)

    # All should be cached
    for i in range(65280, 65535):
        res = query_manytypes(ns3, "manytypes.big", f"TYPE{i}")
        assert res.rcode() == dns.rcode.NOERROR
        section = res.answer
        assert len(section) > 0
        assert (
            section[0].ttl < 120
        ), f"TYPE{i} should be cached (TTL < 120), got TTL={section[0].ttl}"
