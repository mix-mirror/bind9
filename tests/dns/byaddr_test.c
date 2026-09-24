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

#include <sched.h> /* IWYU pragma: keep */
#include <setjmp.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

#define UNIT_TESTING
#include <cmocka.h>

#include <isc/lib.h>
#include <isc/netaddr.h>

#include <dns/byaddr.h>
#include <dns/fixedname.h>
#include <dns/name.h>

#include <tests/isc.h>

ISC_RUN_TEST_IMPL(byaddr_parseptrname) {
	struct {
		const char *ptrname;
		const char *address;
	} tests[] = {
		{ "1.0.168.192.in-addr.arpa.", "192.168.0.1" },
		{ "ab.0.168.192.in-addr.arpa.", NULL },
		{ "abcd.0.168.192.in-addr.arpa.", NULL },
		{ "1111.0.168.192.in-addr.arpa.", NULL },
		{ "1.0.168.192.in-addr.arp.", NULL },
		{ "4.1.999.4.in-addr.arpa.", NULL },
		{ "e.f.a.c.3.2.1.0.e.f.a.c.7.6.5.4.1.1.1.1.0.0.0.0.0.0.0."
		  "0.1.2.e.f.ip6.arpa.",
		  "fe21::1111:4567:cafe:123:cafe" },
		{ "e.f.a.c.3.g.1.0.e.f.a.c.7.6.5.4.1.1.1.1.0.0.0.0.0.0.0."
		  "0.1.2.e.f.ip6.arpa.",
		  NULL },
		{ "e.f.a.c.3.ee.1.0.e.f.a.c.7.6.5.4.1.1.1.1.0.0.0.0.0.0.0."
		  "0.1.2.e.f.ip6.arpa.",
		  NULL },
		{ "e.f.a.c.3.2.1.0.e.f.a.c.7.6.5.4.1.1.1.1.0.0.0.0.0.0.0."
		  "0.1.2.e.f.ip6.arp.",
		  NULL },
		{ "a::z.ip6.arpa.", NULL },
		{ "ed.f.a.c.3.2.1.0.e.f.a.c.7.6.5.4.1.1.1.1.0.0.0.0.0.0.0."
		  "0.1.2.e.f.ip6.arpa.",
		  NULL },
		{ "1.0. . "
		  ".0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0."
		  "ip6.arpa.",
		  NULL },
	};

	for (size_t i = 0; i < ARRAY_SIZE(tests); i++) {
		int result;
		isc_netaddr_t addr;
		dns_fixedname_t fixed;
		dns_name_t *name = dns_fixedname_initname(&fixed);

		dns_fixedname_fromstring(&fixed, tests[i].ptrname, NULL, 0);

		result = dns_byaddr_parseptrname(name, &addr);

		if (tests[i].address) {
			assert_int_equal(result, ISC_R_SUCCESS);
		} else {
			assert_int_not_equal(result, ISC_R_SUCCESS);
		}

		dns_fixedname_invalidate(&fixed);
		char bdata[128];
		isc_buffer_t b;
		isc_buffer_init(&b, bdata, sizeof(bdata));
		isc_netaddr_totext(&addr, &b);
		isc_buffer_putuint8(&b, 0);

		if (tests[i].address) {
			result = strcmp(tests[i].address, b.base);
			assert_int_equal(result, 0);
		}
	}
}

ISC_TEST_LIST_START
ISC_TEST_ENTRY(byaddr_parseptrname)
ISC_TEST_LIST_END
ISC_TEST_MAIN
