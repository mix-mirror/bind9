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

#include <inttypes.h>
#include <sched.h> /* IWYU pragma: keep */
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define UNIT_TESTING
#include <cmocka.h>

#include <isc/lib.h>
#include <isc/netaddr.h>
#include <isc/string.h>
#include <isc/util.h>

#include <dns/acl.h>
#include <dns/iptable.h>
#include <dns/lib.h>

#include <tests/dns.h>

#define BUFLEN	    255
#define BIGBUFLEN   (70 * 1024)
#define TEST_ORIGIN "test"

static void
netaddr_fromstring(isc_netaddr_t *na, const char *addrstr) {
	struct in_addr ina;
	struct in6_addr in6a;

	if (inet_pton(AF_INET, addrstr, &ina) == 1) {
		isc_netaddr_fromin(na, &ina);
	} else {
		assert_int_equal(inet_pton(AF_INET6, addrstr, &in6a), 1);
		isc_netaddr_fromin6(na, &in6a);
	}
}

static void
addprefix(dns_acl_t *acl, const char *addrstr, unsigned int bitlen) {
	isc_netaddr_t na;

	netaddr_fromstring(&na, addrstr);
	dns_iptable_addprefix(acl->iptable, &na, bitlen, RADIX_ALLOW);
}

static int
match_addr(dns_acl_t *acl, const char *addrstr) {
	isc_netaddr_t na;
	int match = 0;

	netaddr_fromstring(&na, addrstr);
	assert_int_equal(dns_acl_match(&na, NULL, acl, NULL, &match, NULL),
			 ISC_R_SUCCESS);
	return match;
}

/* test that dns_acl_isinsecure works */
ISC_RUN_TEST_IMPL(dns_acl_isinsecure) {
	isc_result_t result;
	dns_acl_t *any = NULL;
	dns_acl_t *none = NULL;
	dns_acl_t *notnone = NULL;
	dns_acl_t *notany = NULL;
#if defined(HAVE_GEOIP2)
	dns_acl_t *geoip = NULL;
	dns_acl_t *notgeoip = NULL;
	dns_aclelement_t *de;
#endif /* HAVE_GEOIP2 */

	UNUSED(state);

	dns_acl_any(isc_g_mctx, &any);

	dns_acl_none(isc_g_mctx, &none);

	dns_acl_create(isc_g_mctx, 1, &notnone);

	dns_acl_create(isc_g_mctx, 1, &notany);

	result = dns_acl_merge(notnone, none, false);
	assert_int_equal(result, ISC_R_SUCCESS);

	result = dns_acl_merge(notany, any, false);
	assert_int_equal(result, ISC_R_SUCCESS);

#if defined(HAVE_GEOIP2)
	dns_acl_create(isc_g_mctx, 1, &geoip);

	de = geoip->elements;
	assert_non_null(de);
	strlcpy(de->geoip_elem.as_string, "AU",
		sizeof(de->geoip_elem.as_string));
	de->geoip_elem.subtype = dns_geoip_country_code;
	de->type = dns_aclelementtype_geoip;
	de->negative = false;
	assert_true(geoip->length < geoip->alloc);
	dns_acl_node_count(geoip)++;
	de->node_num = dns_acl_node_count(geoip);
	geoip->length++;

	dns_acl_create(isc_g_mctx, 1, &notgeoip);

	result = dns_acl_merge(notgeoip, geoip, false);
	assert_int_equal(result, ISC_R_SUCCESS);
#endif /* HAVE_GEOIP2 */

	assert_true(dns_acl_isinsecure(any));	   /* any; */
	assert_false(dns_acl_isinsecure(none));	   /* none; */
	assert_false(dns_acl_isinsecure(notany));  /* !any; */
	assert_false(dns_acl_isinsecure(notnone)); /* !none; */

#if defined(HAVE_GEOIP2)
	assert_true(dns_acl_isinsecure(geoip));	    /* geoip; */
	assert_false(dns_acl_isinsecure(notgeoip)); /* !geoip; */
#endif						    /* HAVE_GEOIP2 */

	dns_acl_detach(&any);
	dns_acl_detach(&none);
	dns_acl_detach(&notany);
	dns_acl_detach(&notnone);
#if defined(HAVE_GEOIP2)
	dns_acl_detach(&geoip);
	dns_acl_detach(&notgeoip);
#endif /* HAVE_GEOIP2 */
}

/*
 * A negated nested ACL must deny addresses covered by its prefixes even
 * when a prefix lands on a radix glue node in the parent ACL:
 *
 *	{ 192.0.2.10; 192.0.2.200; !{ 192.0.2.0/24; }; }
 *
 * The two hosts differ first in bit 24, so inserting them creates a
 * glue node at 192.0.2.0/24, which the negated /24 then lands on.
 */
ISC_RUN_TEST_IMPL(dns_acl_merge_negated_nested) {
	isc_result_t result;
	dns_acl_t *outer = NULL;
	dns_acl_t *inner = NULL;

	UNUSED(state);

	dns_acl_create(isc_g_mctx, 1, &outer);
	dns_acl_create(isc_g_mctx, 1, &inner);

	addprefix(outer, "192.0.2.10", 32);
	addprefix(outer, "192.0.2.200", 32);
	addprefix(inner, "192.0.2.0", 24);

	result = dns_acl_merge(outer, inner, false);
	assert_int_equal(result, ISC_R_SUCCESS);

	/* The two listed hosts still match positively (first match). */
	assert_true(match_addr(outer, "192.0.2.10") > 0);
	assert_true(match_addr(outer, "192.0.2.200") > 0);

	/* Any other address in the /24 must be denied. */
	assert_true(match_addr(outer, "192.0.2.77") < 0);

	dns_acl_detach(&outer);
	dns_acl_detach(&inner);
}

/*
 * As above, but with the negated nested ACL's entry landing on an
 * existing node that had no entry for its address family yet:
 *
 *	{ ::/0; !{ any; }; }
 *
 * "any" adds 0.0.0.0/0 and ::/0 entries to a single radix node, which
 * already exists with only its IPv6 half set.  The IPv4 half is a new
 * entry and must be negated; the IPv6 half predates the merge and must
 * keep its positive sense.
 */
ISC_RUN_TEST_IMPL(dns_acl_merge_negated_nested_any) {
	isc_result_t result;
	dns_acl_t *outer = NULL;
	dns_acl_t *inner = NULL;

	UNUSED(state);

	dns_acl_create(isc_g_mctx, 1, &outer);
	dns_acl_any(isc_g_mctx, &inner);

	addprefix(outer, "::", 0);

	result = dns_acl_merge(outer, inner, false);
	assert_int_equal(result, ISC_R_SUCCESS);

	assert_true(match_addr(outer, "2001:db8::1") > 0);
	assert_true(match_addr(outer, "192.0.2.1") < 0);

	dns_acl_detach(&outer);
	dns_acl_detach(&inner);
}

ISC_TEST_LIST_START
ISC_TEST_ENTRY(dns_acl_isinsecure)
ISC_TEST_ENTRY(dns_acl_merge_negated_nested)
ISC_TEST_ENTRY(dns_acl_merge_negated_nested_any)
ISC_TEST_LIST_END

ISC_TEST_MAIN
