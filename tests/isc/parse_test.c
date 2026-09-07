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

/*! \file */

#include <inttypes.h>
#include <sched.h> /* IWYU pragma: keep */
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define UNIT_TESTING
#include <cmocka.h>

#include <isc/lib.h>
#include <isc/parseint.h>
#include <isc/util.h>

#include <tests/isc.h>

/* Test for 32 bit overflow on 64 bit machines in isc_parse_uint32 */
ISC_RUN_TEST_IMPL(parse_overflow) {
	isc_result_t result;
	uint32_t output;

	result = isc_parse_uint32(&output, "1234567890", 10);
	assert_int_equal(ISC_R_SUCCESS, result);
	assert_int_equal(1234567890, output);

	result = isc_parse_uint32(&output, "123456789012345", 10);
	assert_int_equal(ISC_R_RANGE, result);

	result = isc_parse_uint32(&output, "12345678901234567890", 10);
	assert_int_equal(ISC_R_RANGE, result);
}

ISC_RUN_TEST_IMPL(parse_uint32_region) {
	char text[] = { '0', 'x', 'f', 'f', 'x' };
	char overflow[] = "4294967296";
	isc_region_t source = { .base = (unsigned char *)text, .length = 4 };
	uint32_t output;

	UNUSED(state);

	assert_int_equal(isc_parse_uint32_region(&output, &source, 0),
			 ISC_R_SUCCESS);
	assert_int_equal(output, 255);

	source.length = 5;
	assert_int_equal(isc_parse_uint32_region(&output, &source, 0),
			 ISC_R_BADNUMBER);

	source = (isc_region_t){ .base = (unsigned char *)overflow,
				 .length = 10 };
	assert_int_equal(isc_parse_uint32_region(&output, &source, 10),
			 ISC_R_RANGE);
}

ISC_RUN_TEST_IMPL(parse_64_region) {
	char unsigned_text[] = { '1', '8', '4', '4', '6', '7', '4',
				 '4', '0', '7', '3', '7', '0', '9',
				 '5', '5', '1', '6', '1', '5' };
	char signed_text[] = {
		'-', '9', '2', '2', '3', '3', '7', '2', '0', '3',
		'6', '8', '5', '4', '7', '7', '5', '8', '0', '8'
	};
	isc_region_t source = { .base = (unsigned char *)unsigned_text,
				.length = sizeof(unsigned_text) };
	uint64_t u64;
	int64_t i64;

	UNUSED(state);

	assert_int_equal(isc_parse_uint64_region(&u64, &source, 10),
			 ISC_R_SUCCESS);
	assert_true(u64 == UINT64_MAX);

	source = (isc_region_t){ .base = (unsigned char *)signed_text,
				 .length = sizeof(signed_text) };
	assert_int_equal(isc_parse_int64_region(&i64, &source, 10),
			 ISC_R_SUCCESS);
	assert_true(i64 == INT64_MIN);

	source.base++;
	source.length--;
	assert_int_equal(isc_parse_int64_region(&i64, &source, 10),
			 ISC_R_RANGE);
}

ISC_TEST_LIST_START

ISC_TEST_ENTRY(parse_overflow)
ISC_TEST_ENTRY(parse_uint32_region)
ISC_TEST_ENTRY(parse_64_region)

ISC_TEST_LIST_END

ISC_TEST_MAIN
