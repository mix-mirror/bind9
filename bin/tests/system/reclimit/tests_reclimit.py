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

from pathlib import Path

import os
import time

import dns.rcode
import dns.rdatatype

import isctest


def set_ans_limit(ans_id, limit):
    """Write the recursion chain limit for an ans server."""
    Path(f"ans{ans_id}/ans.limit").write_text(f"{limit}\n")


def reset_ans(ip):
    """Send a reset query to an ans server."""
    msg = isctest.query.create("reset", "A")
    isctest.query.udp(msg, ip)


def get_ans_count(ip):
    """Get the query count from an ans server."""
    msg = isctest.query.create("count", "TXT")
    res = isctest.query.udp(msg, ip)
    assert res.rcode() == dns.rcode.NOERROR
    assert len(res.answer) > 0
    # TXT rdata is quoted, strip quotes
    return int(str(res.answer[0][0]).strip('"'))


def ns3_sends_aaaa_queries(ns3):
    """Check whether ns3 sends AAAA queries during resolution."""
    log_path = os.path.join(ns3.identifier, "named.run")
    with open(log_path) as f:
        return "started AAAA fetch" in f.read()


def ns3_reset(ns3, templates, config=None):
    """Switch ns3 config and flush cache."""
    if config is not None:
        templates.render("ns3/named.conf", template=f"ns3/{config}.j2")
    ns3.rndc("reconfig")
    ns3.rndc("flush")


# ---------------------------------------------------------------------------
# Recursion depth and query limit tests
# ---------------------------------------------------------------------------

ANS2_IP = "10.53.0.2"
ANS4_IP = "10.53.0.4"
ANS7_IP = "10.53.0.7"


def test_excessive_depth_12(ns3):
    """max-recursion-depth=12: excessive depth lookup fails."""
    set_ans_limit(2, 1000)
    set_ans_limit(4, 1000)
    reset_ans(ANS2_IP)
    reset_ans(ANS4_IP)

    msg = isctest.query.create("indirect1.example.org", "A")
    res = isctest.query.udp(msg, ns3.ip)
    isctest.check.servfail(res)

    count = get_ans_count(ANS2_IP) + get_ans_count(ANS4_IP)
    if ns3_sends_aaaa_queries(ns3):
        assert count == 27, f"query count {count} != 27"
    else:
        assert count == 14, f"query count {count} != 14"


def test_permissible_depth_12(ns3, templates):
    """max-recursion-depth=12: permissible depth lookup succeeds."""
    set_ans_limit(2, 12)
    set_ans_limit(4, 12)
    ns3_reset(ns3, templates)
    reset_ans(ANS2_IP)
    reset_ans(ANS4_IP)

    msg = isctest.query.create("indirect2.example.org", "A")
    res = isctest.query.udp(msg, ns3.ip)
    isctest.check.noerror(res)

    count = get_ans_count(ANS2_IP) + get_ans_count(ANS4_IP)
    if ns3_sends_aaaa_queries(ns3):
        assert count == 50, f"query count {count} != 50"
    else:
        assert count == 26, f"query count {count} != 26"


def test_excessive_depth_5(ns3, templates):
    """max-recursion-depth=5: excessive depth lookup fails."""
    set_ans_limit(2, 12)
    ns3_reset(ns3, templates, config="named2.conf")
    reset_ans(ANS2_IP)
    reset_ans(ANS4_IP)

    msg = isctest.query.create("indirect3.example.org", "A")
    res = isctest.query.udp(msg, ns3.ip)
    isctest.check.servfail(res)

    count = get_ans_count(ANS2_IP) + get_ans_count(ANS4_IP)
    if ns3_sends_aaaa_queries(ns3):
        assert count == 13, f"query count {count} != 13"
    else:
        assert count == 7, f"query count {count} != 7"


def test_permissible_depth_5(ns3, templates):
    """max-recursion-depth=5: permissible depth lookup succeeds."""
    set_ans_limit(2, 5)
    set_ans_limit(4, 5)
    ns3_reset(ns3, templates)
    reset_ans(ANS2_IP)
    reset_ans(ANS4_IP)

    msg = isctest.query.create("indirect4.example.org", "A")
    res = isctest.query.udp(msg, ns3.ip)
    isctest.check.noerror(res)

    count = get_ans_count(ANS2_IP) + get_ans_count(ANS4_IP)
    if ns3_sends_aaaa_queries(ns3):
        assert count == 22, f"query count {count} != 22"
    else:
        assert count == 12, f"query count {count} != 12"


def test_excessive_queries_50(ns3, templates):
    """max-recursion-queries=50: excessive queries lookup fails."""
    set_ans_limit(2, 13)
    set_ans_limit(4, 13)
    ns3_reset(ns3, templates, config="named3.conf")
    reset_ans(ANS2_IP)
    reset_ans(ANS4_IP)

    msg = isctest.query.create("indirect5.example.org", "A")
    res = isctest.query.udp(msg, ns3.ip)
    if ns3_sends_aaaa_queries(ns3):
        isctest.check.servfail(res)

    count = get_ans_count(ANS2_IP)
    assert count <= 50, f"query count {count} > 50"


def test_permissible_queries_50(ns3, templates):
    """max-recursion-queries=50: permissible queries lookup succeeds."""
    set_ans_limit(2, 12)
    ns3_reset(ns3, templates)
    reset_ans(ANS2_IP)

    msg = isctest.query.create("indirect6.example.org", "A")
    res = isctest.query.udp(msg, ns3.ip)
    isctest.check.noerror(res)

    count = get_ans_count(ANS2_IP)
    assert count <= 50, f"query count {count} > 50"


def test_excessive_queries_40(ns3, templates):
    """max-recursion-queries=40: excessive queries lookup fails."""
    set_ans_limit(2, 11)
    ns3_reset(ns3, templates, config="named4.conf")
    reset_ans(ANS2_IP)

    msg = isctest.query.create("indirect7.example.org", "A")
    res = isctest.query.udp(msg, ns3.ip)
    if ns3_sends_aaaa_queries(ns3):
        isctest.check.servfail(res)

    count = get_ans_count(ANS2_IP)
    assert count <= 40, f"query count {count} > 40"


def test_permissible_queries_40(ns3, templates):
    """max-recursion-queries=40: permissible queries lookup succeeds."""
    set_ans_limit(2, 9)
    ns3_reset(ns3, templates)
    reset_ans(ANS2_IP)

    msg = isctest.query.create("indirect8.example.org", "A")
    res = isctest.query.udp(msg, ns3.ip)
    isctest.check.noerror(res)

    count = get_ans_count(ANS2_IP)
    assert count <= 40, f"query count {count} > 40"


def test_ns_explosion(ns3, templates):
    """NS explosion does not cause excessive queries."""
    ns3_reset(ns3, templates)
    reset_ans(ANS2_IP)

    msg = isctest.query.create("ns1.1.example.net", "A", rd=True)
    isctest.query.udp(msg, ns3.ip)

    count2 = get_ans_count(ANS2_IP)
    assert count2 < 50, f"ans2 query count {count2} >= 50"

    count7 = get_ans_count(ANS7_IP)
    assert count7 < 50, f"ans7 query count {count7} >= 50"


def test_max_records_per_type(ns3, templates):
    """RRset exceeding max-records-per-type returns SERVFAIL."""
    msg = isctest.query.create("biganswer.big", "A")
    res = isctest.query.udp(msg, ns3.ip)
    isctest.check.servfail(res)

    with ns3.watch_log_from_start() as watcher:
        watcher.wait_for_line("too many records (must not exceed 100)")

    # Switch to named5.conf (no max-records-per-type limit)
    ns3_reset(ns3, templates, config="named5.conf")

    msg = isctest.query.create("biganswer.big", "A")
    res = isctest.query.udp(msg, ns3.ip)
    isctest.check.noerror(res)


# ---------------------------------------------------------------------------
# Cache eviction tests (max-types-per-name)
# ---------------------------------------------------------------------------


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
