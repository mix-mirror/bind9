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
#include <time.h>

#define UNIT_TESTING
#include <cmocka.h>

#include <isc/lib.h>
#include <isc/result.h>
#include <isc/tm.h>
#include <isc/util.h>

#include <tests/isc.h>

#if defined(__APPLE__) && defined(__arm__)
#define ISC_TIME_T 64
#elif defined(__TIMESIZE)
#define ISC_TIME_T __TIMESIZE
#endif

ISC_RUN_TEST_IMPL(isc_tm_timegm) {
	struct tests {
		struct tm tm;
		time_t result;
	} tests[] = {
		/* Thu  1 Jan 1970 00:00:00 UTC */
		{ .tm = { .tm_year = 1970 - 1900,
			  .tm_mon = 0,
			  .tm_mday = 1,
			  .tm_hour = 0,
			  .tm_min = 0,
			  .tm_sec = 0 },
		  .result = 0 },
		/* Wed 31 Dec 1980 23:59:59 UTC */
		{ .tm = { .tm_year = 1980 - 1900,
			  .tm_mon = 11,
			  .tm_mday = 31,
			  .tm_hour = 23,
			  .tm_min = 59,
			  .tm_sec = 59 },
		  .result = 347155199 },
		/* Tue 19 Jan 2038 03:14:07 UTC */
		{ .tm = { .tm_year = 2038 - 1900,
			  .tm_mon = 0,
			  .tm_mday = 19,
			  .tm_hour = 3,
			  .tm_min = 14,
			  .tm_sec = 7 },
		  .result = 2147483647 },
#if ISC_TIME_T == 64
		/* Tue 19 Jan 2038 03:14:08 UTC */
		{ .tm = { .tm_year = 2038 - 1900,
			  .tm_mon = 0,
			  .tm_mday = 19,
			  .tm_hour = 3,
			  .tm_min = 14,
			  .tm_sec = 8 },
		  .result = 2147483648 },
		/* Sun  7 Feb 2106 06:28:15 UTC */
		{ .tm = { .tm_year = 2106 - 1900,
			  .tm_mon = 1,
			  .tm_mday = 7,
			  .tm_hour = 6,
			  .tm_min = 28,
			  .tm_sec = 15 },
		  .result = 4294967295 },
		/* Fri 31 Dec 9999 23:59:59 UTC */
		{ .tm = { .tm_year = 9999 - 1900,
			  .tm_mon = 11,
			  .tm_mday = 31,
			  .tm_hour = 23,
			  .tm_min = 59,
			  .tm_sec = 59 },
		  .result = 253402300799LL },
#endif
	};

	for (size_t i = 0; i < ARRAY_SIZE(tests); i++) {
		time_t result = isc_tm_timegm(&tests[i].tm);
		assert_int_equal(result, tests[i].result);
	}
}

ISC_TEST_LIST_START

ISC_TEST_ENTRY(isc_tm_timegm)

ISC_TEST_LIST_END

ISC_TEST_MAIN
