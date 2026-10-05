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

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#define UNIT_TESTING
#include <cmocka.h>

#include <isc/lib.h>
#include <isc/util.h>

#include <dns/lib.h>
#include <dns/ttl.h>

#include <tests/dns.h>

ISC_RUN_TEST_IMPL(fromtext) {
	const struct {
		const char *text;
		isc_result_t result;
		uint32_t ttl;
	} tests[] = {
		{ "0", ISC_R_SUCCESS, 0 },
		{ "123", ISC_R_SUCCESS, 123 },
		{ "1w2d3h4m5s", ISC_R_SUCCESS, 788645 },
		{ "1W2D3H4M5S", ISC_R_SUCCESS, 788645 },
		{ "0s1", ISC_R_SUCCESS, 1 },
		{ "4294967295", ISC_R_SUCCESS, UINT32_MAX },
		{ "4294967295s", ISC_R_SUCCESS, UINT32_MAX },
		{ "4294967295s1s", ISC_R_RANGE, 0 },
		{ "4294967295w", ISC_R_RANGE, 0 },
		{ "4294967296", DNS_R_SYNTAX, 0 },
		{ "4294967296s", DNS_R_SYNTAX, 0 },
		{ "18446744073709551616", DNS_R_SYNTAX, 0 },
		{ "", DNS_R_SYNTAX, 0 },
		{ "s", DNS_R_SYNTAX, 0 },
		{ "1x", DNS_R_SYNTAX, 0 },
		{ "1s2", DNS_R_SYNTAX, 0 },
		{ "1ss", DNS_R_SYNTAX, 0 },
		{ "+1", DNS_R_SYNTAX, 0 },
		{ "-1", DNS_R_SYNTAX, 0 },
		{ " 1", DNS_R_SYNTAX, 0 },
		{ "000000000000000000000000000000000000000000000000000000000000"
		  "001",
		  ISC_R_SUCCESS, 1 },
		{ "000000000000000000000000000000000000000000000000000000000000"
		  "0001",
		  DNS_R_SYNTAX, 0 },
	};

	for (size_t i = 0; i < ARRAY_SIZE(tests); i++) {
		/* Place a digit past the region to detect reads beyond it. */
		char text[65];
		isc_textregion_t source = {
			.base = text,
			.length = strlen(tests[i].text),
		};
		uint32_t ttl = 0;
		isc_result_t result = tests[i].result;

		memmove(text, tests[i].text, source.length);
		text[source.length] = '9';
		assert_int_equal(dns_counter_fromtext(&source, &ttl), result);
		if (result == ISC_R_SUCCESS) {
			assert_int_equal(ttl, tests[i].ttl);
		}
		if (result == DNS_R_SYNTAX) {
			result = DNS_R_BADTTL;
		}
		assert_int_equal(dns_ttl_fromtext(&source, &ttl), result);
		if (result == ISC_R_SUCCESS) {
			assert_int_equal(ttl, tests[i].ttl);
		}
	}
}

ISC_RUN_TEST_IMPL(embedded_nul) {
	char texts[][4] = {
		{ '\0', '1', '2', '3' }, { '1', '\0', '2', '3' },
		{ '1', 's', '\0', '2' }, { '1', '2', '3', '\0' },
		{ '1', '2', 's', '\0' },
	};

	for (size_t i = 0; i < ARRAY_SIZE(texts); i++) {
		isc_textregion_t source = {
			.base = texts[i],
			.length = sizeof(texts[i]),
		};
		uint32_t ttl = UINT32_MAX;

		assert_int_equal(dns_counter_fromtext(&source, &ttl),
				 DNS_R_SYNTAX);
		assert_int_equal(ttl, UINT32_MAX);
		assert_int_equal(dns_ttl_fromtext(&source, &ttl), DNS_R_BADTTL);
		assert_int_equal(ttl, UINT32_MAX);
	}
}

ISC_TEST_LIST_START
ISC_TEST_ENTRY(fromtext)
ISC_TEST_ENTRY(embedded_nul)
ISC_TEST_LIST_END

ISC_TEST_MAIN
