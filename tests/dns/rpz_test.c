/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * SPDX-License-Identifier: MPL-2.0
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * See the COPYRIGHT file distributed with this work for additional
 * information regarding copyright ownership.
 */

#include <arpa/inet.h>
#include <inttypes.h>
#include <sched.h> /* IWYU pragma: keep */
#include <setjmp.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#define UNIT_TESTING
#include <cmocka.h>

#include <isc/buffer.h>
#include <isc/lib.h>
#include <isc/util.h>

#include <dns/fixedname.h>
#include <dns/lib.h>
#include <dns/name.h>
#include <dns/rpz.h>

#include "../../lib/dns/rpz.c"

#include <tests/isc.h>

/*
 * Build a radix-tree CIDR key (host byte order, w[0] most significant) from a
 * textual IPv6 address, mirroring the conversion dns_rpz_find_ip() performs on
 * an incoming address before the summary-tree lookup.
 */
static void
ipv6_key(const char *addr, dns_rpz_cidr_key_t *key) {
	struct in6_addr in6;
	uint32_t netw[DNS_RPZ_CIDR_WORDS];

	assert_int_equal(inet_pton(AF_INET6, addr, &in6), 1);
	memmove(netw, &in6, sizeof(netw));
	for (int i = 0; i < DNS_RPZ_CIDR_WORDS; i++) {
		key->w[i] = ntohl(netw[i]);
	}
}

/*
 * Assert that ip2name() renders 'addr'/128 as the trigger name 'expect' (the
 * reversed-label, prefix-first RPZ form, without a policy-zone origin) in the
 * given zero-compression mode.  ip2name() is the query-time encoder: the name
 * it produces is the one the policy record is looked up under.
 */
static void
check_ip2name(const char *addr, bool single, const char *expect) {
	dns_rpz_cidr_key_t key;
	dns_fixedname_t gotf, expf;
	dns_name_t *got = dns_fixedname_initname(&gotf);
	dns_name_t *exp = dns_fixedname_initname(&expf);
	isc_buffer_t b;

	ipv6_key(addr, &key);

	assert_int_equal(ip2name(&key, 128, dns_rootname, got, single),
			 ISC_R_SUCCESS);

	isc_buffer_constinit(&b, expect, strlen(expect));
	isc_buffer_add(&b, strlen(expect));
	assert_int_equal(dns_name_fromtext(exp, &b, dns_rootname, 0),
			 ISC_R_SUCCESS);

	assert_true(dns_name_equal(got, exp));
}

/*
 * Pin ip2name()'s two encodings of RPZ IPv6 IP-trigger names.
 *
 * Canonical mode (single == false) leaves a single isolated zero 16-bit group
 * as a literal '.0', not the 'zz' marker -- RFC 5952 forbids '::' for one zero
 * group, so '.0' is the conformant, common spelling that round-trips and is
 * enforced.  The 'single' mode (single == true) that dns_rpz_find_ip() uses for
 * its fallback lookup compresses a single zero group to '.zz', reproducing the
 * non-canonical spelling an operator may have authored so the missed lookup can
 * be retried.  The multi-zero and equal-length tie-break cases are identical in
 * both modes.
 *
 * The single-leading-zero position is omitted: name2ipkey()'s 'i <= 6' guard
 * cannot parse 'zz' at the most-significant label, so it is a separate concern.
 */
ISC_RUN_TEST_IMPL(ip2name_canonical) {
	/* single isolated zero: '.0' canonical, '.zz' in single mode */
	check_ip2name("2001:db8:1:0:1:1:1:1", false,
		      "128.1.1.1.1.0.1.db8.2001");
	check_ip2name("2001:db8:1:0:1:1:1:1", true,
		      "128.1.1.1.1.zz.1.db8.2001");
	/* single trailing (least-significant) zero */
	check_ip2name("2001:db8:1:1:1:1:1:0", false,
		      "128.0.1.1.1.1.1.db8.2001");
	check_ip2name("2001:db8:1:1:1:1:1:0", true,
		      "128.zz.1.1.1.1.1.db8.2001");
	/* two consecutive zeros compress to '.zz' in both modes */
	check_ip2name("2001:db8:0:0:1:1:1:1", false, "128.1.1.1.1.zz.db8.2001");
	check_ip2name("2001:db8:0:0:1:1:1:1", true, "128.1.1.1.1.zz.db8.2001");
	/* no zero group: identical in both modes */
	check_ip2name("2001:db8:1:2:3:4:5:6", false,
		      "128.6.5.4.3.2.1.db8.2001");
	check_ip2name("2001:db8:1:2:3:4:5:6", true, "128.6.5.4.3.2.1.db8.2001");
	/*
	 * Two equal-length zero runs: the reversed format compresses the run
	 * nearer the most-significant end (the later run in label order),
	 * selected by the detector's '>=' tie-break -- unchanged by 'single'.
	 */
	check_ip2name("2001:db8:0:0:1:0:0:1", false, "128.1.0.0.1.zz.db8.2001");
	check_ip2name("2001:db8:0:0:1:0:0:1", true, "128.1.0.0.1.zz.db8.2001");
}

ISC_TEST_LIST_START

ISC_TEST_ENTRY(ip2name_canonical)

ISC_TEST_LIST_END

ISC_TEST_MAIN
