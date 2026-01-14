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
#include <stdlib.h>
#include <string.h>

#define UNIT_TESTING
#include <cmocka.h>

#include <isc/lib.h>
#include <isc/mem.h>
#include <isc/stdtime.h>
#include <isc/timeout.h>
#include <isc/util.h>

#include <tests/isc.h>

/* Test basic timeout creation and destruction */
ISC_RUN_TEST_IMPL(timeout_create_destroy) {
	timeouts_t *wheel = NULL;

	UNUSED(state);

	timeouts_create(isc_g_mctx, &wheel);
	assert_non_null(wheel);

	timeouts_destroy(&wheel);
	assert_null(wheel);
}

/* Test adding a single timeout */
ISC_RUN_TEST_IMPL(timeout_add) {
	timeouts_t *wheel = NULL;
	timeout_t to = TIMEOUT_INITIALIZER;

	UNUSED(state);

	timeouts_create(isc_g_mctx, &wheel);
	assert_non_null(wheel);

	/* Add timeout expiring at time 100 */
	timeouts_add(wheel, &to, 100);
	assert_non_null(to.pending);

	/* Should have pending timeouts */
	assert_true(timeouts_pending(wheel));

	/* Should not have expired yet */
	assert_false(timeouts_expired(wheel));

	timeouts_destroy(&wheel);
}

/* Test timeout expiration */
ISC_RUN_TEST_IMPL(timeout_expire) {
	timeouts_t *wheel = NULL;
	timeout_t to = TIMEOUT_INITIALIZER;
	timeout_t *expired = NULL;

	UNUSED(state);

	timeouts_create(isc_g_mctx, &wheel);

	/* Add timeout expiring at time 10 */
	timeouts_add(wheel, &to, 10);

	/* Update to time 20 to trigger expiration */
	timeouts_update(wheel, 20);

	/* Should show as expired */
	assert_true(timeouts_expired(wheel));

	/* Get the expired timeout */
	expired = timeouts_get(wheel);
	assert_ptr_equal(expired, &to);
	assert_null(expired->pending);

	/* Should be empty now */
	assert_false(timeouts_expired(wheel));

	timeouts_destroy(&wheel);
}

/* Test timeout update */
ISC_RUN_TEST_IMPL(timeout_update) {
	timeouts_t *wheel = NULL;
	timeout_t to = TIMEOUT_INITIALIZER;

	UNUSED(state);

	timeouts_create(isc_g_mctx, &wheel);

	/* Add timeout at time 1000 */
	timeouts_add(wheel, &to, 1000);
	assert_int_equal(to.expires, 1000);

	/* Advance time to 500 - timeout shouldn't expire yet */
	timeouts_update(wheel, 500);

	/* Timeout should still be pending */
	assert_true(timeouts_pending(wheel));
	assert_false(timeouts_expired(wheel));

	/* Advance time past expiration */
	timeouts_update(wheel, 1010);

	/* Now it should be expired */
	assert_true(timeouts_expired(wheel));

	timeouts_destroy(&wheel);
}

/* Test deleting a timeout */
ISC_RUN_TEST_IMPL(timeout_delete) {
	timeouts_t *wheel = NULL;
	timeout_t to = TIMEOUT_INITIALIZER;

	UNUSED(state);

	timeouts_create(isc_g_mctx, &wheel);

	/* Add timeout */
	timeouts_add(wheel, &to, 1000);
	assert_non_null(to.pending);

	/* Delete it */
	timeouts_del(wheel, &to);
	assert_null(to.pending);

	/* Should be empty now */
	assert_false(timeouts_pending(wheel));

	timeouts_destroy(&wheel);
}

/* Test rescheduling timeout to same slot (fast path) */
ISC_RUN_TEST_IMPL(timeout_reschedule_same_slot) {
	timeouts_t *wheel = NULL;
	timeout_t to = TIMEOUT_INITIALIZER;
	timeout_list_t *oldpending = NULL;

	UNUSED(state);

	timeouts_create(isc_g_mctx, &wheel);

	/* Add timeout at time 1000 */
	timeouts_add(wheel, &to, 1000);
	oldpending = to.pending;

	/* Reschedule to nearby time (should be same slot due to granularity) */
	timeouts_add(wheel, &to, 1001);

	/* Should still be in same slot (fast path taken) */
	assert_ptr_equal(to.pending, oldpending);
	assert_int_equal(to.expires, 1001);

	timeouts_destroy(&wheel);
}

/* Test rescheduling timeout to same expiration (no-op fast path) */
ISC_RUN_TEST_IMPL(timeout_reschedule_same_time) {
	timeouts_t *wheel = NULL;
	timeout_t to = TIMEOUT_INITIALIZER;
	timeout_list_t *oldpending = NULL;

	UNUSED(state);

	timeouts_create(isc_g_mctx, &wheel);

	/* Add timeout at time 1000 */
	timeouts_add(wheel, &to, 1000);
	oldpending = to.pending;

	/* Reschedule to exact same time */
	timeouts_add(wheel, &to, 1000);

	/* Should still be in same slot with same expiration */
	assert_ptr_equal(to.pending, oldpending);
	assert_int_equal(to.expires, 1000);

	timeouts_destroy(&wheel);
}

/* Test multiple timeouts */
ISC_RUN_TEST_IMPL(timeout_multiple) {
	timeouts_t *wheel = NULL;
	timeout_t to1 = TIMEOUT_INITIALIZER;
	timeout_t to2 = TIMEOUT_INITIALIZER;
	timeout_t to3 = TIMEOUT_INITIALIZER;
	timeout_t *expired = NULL;

	UNUSED(state);

	timeouts_create(isc_g_mctx, &wheel);

	/* Add three timeouts */
	timeouts_add(wheel, &to1, 100);
	timeouts_add(wheel, &to2, 200);
	timeouts_add(wheel, &to3, 300);

	/* Advance past to1 expiration */
	timeouts_update(wheel, 110);
	assert_true(timeouts_expired(wheel));

	expired = timeouts_get(wheel);
	assert_ptr_equal(expired, &to1);
	assert_false(timeouts_expired(wheel));

	/* Advance past to2 expiration */
	timeouts_update(wheel, 210);
	assert_true(timeouts_expired(wheel));

	expired = timeouts_get(wheel);
	assert_ptr_equal(expired, &to2);
	assert_false(timeouts_expired(wheel));

	/* Advance past to3 expiration */
	timeouts_update(wheel, 310);
	assert_true(timeouts_expired(wheel));

	expired = timeouts_get(wheel);
	assert_ptr_equal(expired, &to3);
	assert_false(timeouts_expired(wheel));

	timeouts_destroy(&wheel);
}

/* Test timeout interval calculation */
ISC_RUN_TEST_IMPL(timeout_interval) {
	timeouts_t *wheel = NULL;
	timeout_t to = TIMEOUT_INITIALIZER;
	isc_stdtime_t interval;

	UNUSED(state);

	timeouts_create(isc_g_mctx, &wheel);

	/* No timeouts - should return max time */
	interval = timeouts_timeout(wheel);
	assert_int_equal(interval, ~ISC_STDTIME_C(0));

	/* Add timeout at 1000 */
	timeouts_add(wheel, &to, 1000);

	/* Should return some interval <= 1000 */
	interval = timeouts_timeout(wheel);
	assert_true(interval > 0);
	assert_true(interval <= 1000);

	timeouts_destroy(&wheel);
}

/* Test deleting non-existent timeout (should be safe) */
ISC_RUN_TEST_IMPL(timeout_delete_unlinked) {
	timeouts_t *wheel = NULL;
	timeout_t to = TIMEOUT_INITIALIZER;

	UNUSED(state);

	timeouts_create(isc_g_mctx, &wheel);

	/* Delete timeout that was never added (should be no-op) */
	timeouts_del(wheel, &to);
	assert_null(to.pending);

	/* Add and delete twice */
	timeouts_add(wheel, &to, 1000);
	timeouts_del(wheel, &to);
	timeouts_del(wheel, &to); /* Second delete should be no-op */
	assert_null(to.pending);

	timeouts_destroy(&wheel);
}

/* Test step function (relative time advancement) */
ISC_RUN_TEST_IMPL(timeout_step) {
	timeouts_t *wheel = NULL;
	timeout_t to = TIMEOUT_INITIALIZER;

	UNUSED(state);

	timeouts_create(isc_g_mctx, &wheel);

	/* Add timeout 100 seconds in the future */
	timeouts_add(wheel, &to, 100);

	/* Step forward 50 seconds - shouldn't expire */
	timeouts_step(wheel, 50);
	assert_false(timeouts_expired(wheel));

	/* Step forward another 60 seconds (total 110, past expiration) */
	timeouts_step(wheel, 60);
	assert_true(timeouts_expired(wheel));

	timeouts_destroy(&wheel);
}

/* Test large time values near the wheel maximum */
ISC_RUN_TEST_IMPL(timeout_large_values) {
	timeouts_t *wheel = NULL;
	timeout_t to1 = TIMEOUT_INITIALIZER;
	timeout_t to2 = TIMEOUT_INITIALIZER;

	UNUSED(state);

	timeouts_create(isc_g_mctx, &wheel);

	/* Add timeout at large value (near 24-bit limit) */
	timeouts_add(wheel, &to1, 0xFFFFFF);
	assert_non_null(to1.pending);

	/* Add another at smaller value */
	timeouts_add(wheel, &to2, 1000);

	/* Both should be pending */
	assert_true(timeouts_pending(wheel));

	timeouts_destroy(&wheel);
}

/* Test update with no time advancement (should be no-op) */
ISC_RUN_TEST_IMPL(timeout_update_same_time) {
	timeouts_t *wheel = NULL;
	timeout_t to = TIMEOUT_INITIALIZER;

	UNUSED(state);

	timeouts_create(isc_g_mctx, &wheel);

	timeouts_add(wheel, &to, 1000);

	/* Update with same time - should be fast no-op */
	timeouts_update(wheel, 0);
	assert_true(timeouts_pending(wheel));
	assert_false(timeouts_expired(wheel));

	/* Update with same time again */
	timeouts_update(wheel, 0);
	assert_true(timeouts_pending(wheel));
	assert_false(timeouts_expired(wheel));

	timeouts_destroy(&wheel);
}

ISC_TEST_LIST_START

ISC_TEST_ENTRY(timeout_create_destroy)
ISC_TEST_ENTRY(timeout_add)
ISC_TEST_ENTRY(timeout_expire)
ISC_TEST_ENTRY(timeout_update)
ISC_TEST_ENTRY(timeout_delete)
ISC_TEST_ENTRY(timeout_reschedule_same_slot)
ISC_TEST_ENTRY(timeout_reschedule_same_time)
ISC_TEST_ENTRY(timeout_multiple)
ISC_TEST_ENTRY(timeout_interval)
ISC_TEST_ENTRY(timeout_delete_unlinked)
ISC_TEST_ENTRY(timeout_step)
ISC_TEST_ENTRY(timeout_large_values)
ISC_TEST_ENTRY(timeout_update_same_time)

ISC_TEST_LIST_END

ISC_TEST_MAIN
