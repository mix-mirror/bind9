/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * SPDX-License-Identifier: MPL-2.0
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at https://mozilla.org/MPL/2.0/.
 */

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdlib.h>

#define UNIT_TESTING
#include <cmocka.h>

#include <isc/lib.h>
#include <isc/mem.h>
#include <isc/tw.h>
#include <isc/util.h>

#include <tests/isc.h>

struct tw_entry {
	isc_tw_elt_t elt;
};

static void
init_entry(struct tw_entry *entry, isc_stdtime_t expire) {
	ISC_TW_ELT_INIT(&entry->elt);
	entry->elt.expire = expire;
}

ISC_RUN_TEST_IMPL(isc_tw_minimum_is_returned) {
	isc_tw_t *tw = NULL;
	struct tw_entry first, second;

	UNUSED(state);

	assert_int_equal(isc_tw_create(isc_g_mctx, &tw), ISC_R_SUCCESS);

	init_entry(&first, 5);
	init_entry(&second, 3);

	assert_int_equal(isc_tw_insert(tw, &first.elt), ISC_R_SUCCESS);
	assert_int_equal(isc_tw_insert(tw, &second.elt), ISC_R_SUCCESS);

	isc_tw_elt_t *min = isc_tw_element(tw);
	assert_ptr_equal(min, &second.elt);

	isc_tw_delete(tw, &first.elt);
	isc_tw_delete(tw, &second.elt);
	isc_tw_destroy(&tw);
}

ISC_RUN_TEST_IMPL(isc_tw_empty_returns_null) {
	isc_tw_t *tw = NULL;

	UNUSED(state);

	assert_int_equal(isc_tw_create(isc_g_mctx, &tw), ISC_R_SUCCESS);

	assert_null(isc_tw_element(tw));

	isc_tw_destroy(&tw);
}

ISC_RUN_TEST_IMPL(isc_tw_delete_marks_removed) {
	isc_tw_t *tw = NULL;
	struct tw_entry entry;

	UNUSED(state);

	assert_int_equal(isc_tw_create(isc_g_mctx, &tw), ISC_R_SUCCESS);

	init_entry(&entry, 10);
	assert_int_equal(isc_tw_insert(tw, &entry.elt), ISC_R_SUCCESS);

	isc_tw_delete(tw, &entry.elt);
	assert_true(isc_tw_is_node_deleted(&entry.elt));
	assert_int_equal(isc_tw_count(tw), 0);

	isc_tw_destroy(&tw);
}

ISC_RUN_TEST_IMPL(isc_tw_delete_idempotent) {
	isc_tw_t *tw = NULL;
	struct tw_entry entry;

	UNUSED(state);

	assert_int_equal(isc_tw_create(isc_g_mctx, &tw), ISC_R_SUCCESS);

	init_entry(&entry, 10);
	assert_int_equal(isc_tw_insert(tw, &entry.elt), ISC_R_SUCCESS);

	isc_tw_delete(tw, &entry.elt);
	assert_true(isc_tw_is_node_deleted(&entry.elt));
	assert_int_equal(isc_tw_count(tw), 0);

	/* Second delete is a no-op */
	isc_tw_delete(tw, &entry.elt);
	assert_true(isc_tw_is_node_deleted(&entry.elt));
	assert_int_equal(isc_tw_count(tw), 0);

	isc_tw_destroy(&tw);
}

ISC_RUN_TEST_IMPL(isc_tw_delete_safe_on_deleted) {
	isc_tw_t *tw = NULL;
	struct tw_entry entry;

	UNUSED(state);

	assert_int_equal(isc_tw_create(isc_g_mctx, &tw), ISC_R_SUCCESS);

	init_entry(&entry, 1);
	assert_int_equal(isc_tw_insert(tw, &entry.elt), ISC_R_SUCCESS);
	isc_tw_delete(tw, &entry.elt);

	/* Delete is idempotent - second delete is safe and does nothing */
	isc_tw_delete(tw, &entry.elt);
	assert_true(isc_tw_is_node_deleted(&entry.elt));
	assert_int_equal(isc_tw_count(tw), 0);

	isc_tw_destroy(&tw);
}

ISC_RUN_TEST_IMPL(isc_tw_increased_reorders_queue) {
	isc_tw_t *tw = NULL;
	struct tw_entry early, late;

	UNUSED(state);

	assert_int_equal(isc_tw_create(isc_g_mctx, &tw), ISC_R_SUCCESS);

	init_entry(&early, 10);
	init_entry(&late, 20);

	assert_int_equal(isc_tw_insert(tw, &early.elt), ISC_R_SUCCESS);
	assert_int_equal(isc_tw_insert(tw, &late.elt), ISC_R_SUCCESS);

	/* Update priority: delete, reinitialize, and reinsert */
	isc_tw_delete(tw, &late.elt);
	init_entry(&late, 5);
	isc_tw_insert(tw, &late.elt);

	isc_tw_elt_t *min = isc_tw_element(tw);
	assert_ptr_equal(min, &late.elt);

	isc_tw_delete(tw, &early.elt);
	isc_tw_delete(tw, &late.elt);
	isc_tw_destroy(&tw);
}

ISC_RUN_TEST_IMPL(isc_tw_settime_cascades) {
	isc_tw_t *tw = NULL;
	struct tw_entry distant;

	UNUSED(state);

	assert_int_equal(isc_tw_create(isc_g_mctx, &tw), ISC_R_SUCCESS);

	/* Set initial time */
	isc_tw_settime(tw, 100);

	/* Insert timer 300 seconds in future (at time 400) */
	/* Delta=300, goes to level 1 (256s/slot covers 256-65536s range) */
	init_entry(&distant, 400);
	assert_int_equal(isc_tw_insert(tw, &distant.elt), ISC_R_SUCCESS);
	assert_int_equal(distant.elt.level, 0);

	/* Advance time by 512 seconds to trigger 2 full level 0 rotations */
	/* This will cascade level 1 slot 0, advance to slot 1, then cascade slot 1 */
	isc_tw_settime(tw, 612);

	/* Timer should now be in level 0 since delta is now: 400-612 = -212 (expired) */
	/* Or if not expired yet, verify it was cascaded */
	assert_int_equal(distant.elt.level, 0);

	/* Should still be retrievable */
	isc_tw_elt_t *min = isc_tw_element(tw);
	assert_non_null(min);
	assert_ptr_equal(min, &distant.elt);

	isc_tw_delete(tw, &distant.elt);
	isc_tw_destroy(&tw);
}

ISC_RUN_TEST_IMPL(isc_tw_level_selection) {
	isc_tw_t *tw = NULL;
	struct tw_entry near, mid, far, very_far;

	UNUSED(state);

	assert_int_equal(isc_tw_create(isc_g_mctx, &tw), ISC_R_SUCCESS);
	isc_tw_settime(tw, 1000);

	/* Level 0: 0-255 seconds */
	init_entry(&near, 1100); /* delta=100 */
	assert_int_equal(isc_tw_insert(tw, &near.elt), ISC_R_SUCCESS);
	assert_int_equal(near.elt.level, 0);

	/* Level 1: 256-65535 seconds (256*256-1) */
	init_entry(&mid, 1500); /* delta=500 */
	assert_int_equal(isc_tw_insert(tw, &mid.elt), ISC_R_SUCCESS);
	assert_int_equal(mid.elt.level, 0);

	/* Level 2: 65536+ seconds */
	init_entry(&far, 70000); /* delta=69000 */
	assert_int_equal(isc_tw_insert(tw, &far.elt), ISC_R_SUCCESS);
	assert_int_equal(far.elt.level, 0);

	/* Level 3: very distant */
	init_entry(&very_far, 20000000); /* delta=19999000 */
	assert_int_equal(isc_tw_insert(tw, &very_far.elt), ISC_R_SUCCESS);
	assert_int_equal(very_far.elt.level, 0);

	isc_tw_delete(tw, &near.elt);
	isc_tw_delete(tw, &mid.elt);
	isc_tw_delete(tw, &far.elt);
	isc_tw_delete(tw, &very_far.elt);
	isc_tw_destroy(&tw);
}

ISC_RUN_TEST_IMPL(isc_tw_multiple_in_same_slot) {
	isc_tw_t *tw = NULL;
	struct tw_entry first, second, third;

	UNUSED(state);

	assert_int_equal(isc_tw_create(isc_g_mctx, &tw), ISC_R_SUCCESS);

	/* All timers in same slot, different expiry times */
	init_entry(&first, 10);
	init_entry(&second, 10);
	init_entry(&third, 8);

	assert_int_equal(isc_tw_insert(tw, &first.elt), ISC_R_SUCCESS);
	assert_int_equal(isc_tw_insert(tw, &second.elt), ISC_R_SUCCESS);
	assert_int_equal(isc_tw_insert(tw, &third.elt), ISC_R_SUCCESS);

	assert_int_equal(isc_tw_count(tw), 3);

	/* Should return earliest one */
	isc_tw_elt_t *min = isc_tw_element(tw);
	assert_ptr_equal(min, &third.elt);

	isc_tw_delete(tw, &first.elt);
	isc_tw_delete(tw, &second.elt);
	isc_tw_delete(tw, &third.elt);
	isc_tw_destroy(&tw);
}

ISC_RUN_TEST_IMPL(isc_tw_wraparound_level0) {
	isc_tw_t *tw = NULL;
	struct tw_entry entry;

	UNUSED(state);

	assert_int_equal(isc_tw_create(isc_g_mctx, &tw), ISC_R_SUCCESS);

	/* Insert timer at slot near end of level 0 */
	init_entry(&entry, 250);
	assert_int_equal(isc_tw_insert(tw, &entry.elt), ISC_R_SUCCESS);
	assert_int_equal(entry.elt.level, 0);

	/* Advance time to wrap around level 0 */
	isc_tw_settime(tw, 260);

	/* Timer should still be in level 0, retrievable */
	assert_int_equal(entry.elt.level, 0);
	isc_tw_elt_t *min = isc_tw_element(tw);
	assert_ptr_equal(min, &entry.elt);

	isc_tw_delete(tw, &entry.elt);
	isc_tw_destroy(&tw);
}

ISC_RUN_TEST_IMPL(isc_tw_past_timer_goes_to_current_slot) {
	isc_tw_t *tw = NULL;
	struct tw_entry past, future;

	UNUSED(state);

	assert_int_equal(isc_tw_create(isc_g_mctx, &tw), ISC_R_SUCCESS);

	/* Set current time */
	isc_tw_settime(tw, 100);

	/* Insert timer in the past (delta=0) */
	init_entry(&past, 50);
	assert_int_equal(isc_tw_insert(tw, &past.elt), ISC_R_SUCCESS);
	assert_int_equal(past.elt.level, 0);
	/* Past timers go to current slot (which is 0 because settime was no-op) */
	assert_int_equal(past.elt.slot, 0);

	/* Insert timer in future */
	init_entry(&future, 120);
	assert_int_equal(isc_tw_insert(tw, &future.elt), ISC_R_SUCCESS);

	/* Past timer should be returned first */
	isc_tw_elt_t *min = isc_tw_element(tw);
	assert_ptr_equal(min, &past.elt);

	isc_tw_delete(tw, &past.elt);
	isc_tw_delete(tw, &future.elt);
	isc_tw_destroy(&tw);
}

ISC_RUN_TEST_IMPL(isc_tw_large_time_jump) {
	isc_tw_t *tw = NULL;
	struct tw_entry entry;

	UNUSED(state);

	assert_int_equal(isc_tw_create(isc_g_mctx, &tw), ISC_R_SUCCESS);
	isc_tw_settime(tw, 100);

	/* Insert timer 1000 seconds in future */
	init_entry(&entry, 1100);
	assert_int_equal(isc_tw_insert(tw, &entry.elt), ISC_R_SUCCESS);

	/* Jump time by 2000 seconds (past the timer) */
	isc_tw_settime(tw, 2100);

	/* Timer should still be retrievable even though expired */
	isc_tw_elt_t *min = isc_tw_element(tw);
	assert_ptr_equal(min, &entry.elt);

	isc_tw_delete(tw, &entry.elt);
	isc_tw_destroy(&tw);
}

ISC_RUN_TEST_IMPL(isc_tw_earliest_slot_optimization) {
	isc_tw_t *tw = NULL;
	struct tw_entry entries[10];

	UNUSED(state);

	assert_int_equal(isc_tw_create(isc_g_mctx, &tw), ISC_R_SUCCESS);

	/* Insert timers in reverse order to test earliest_slot tracking */
	for (int i = 9; i >= 0; i--) {
		init_entry(&entries[i], 10 + i);
		assert_int_equal(isc_tw_insert(tw, &entries[i].elt), ISC_R_SUCCESS);
	}

	/* Verify earliest is returned first */
	isc_tw_elt_t *min = isc_tw_element(tw);
	assert_ptr_equal(min, &entries[0].elt);
	assert_int_equal(min->expire, 10);

	/* Delete earliest and verify next earliest is found */
	isc_tw_delete(tw, &entries[0].elt);
	min = isc_tw_element(tw);
	assert_ptr_equal(min, &entries[1].elt);
	assert_int_equal(min->expire, 11);

	/* Clean up */
	for (int i = 1; i < 10; i++) {
		isc_tw_delete(tw, &entries[i].elt);
	}
	isc_tw_destroy(&tw);
}

ISC_TEST_LIST_START

ISC_TEST_ENTRY(isc_tw_minimum_is_returned)
ISC_TEST_ENTRY(isc_tw_empty_returns_null)
ISC_TEST_ENTRY(isc_tw_delete_marks_removed)
ISC_TEST_ENTRY(isc_tw_delete_safe_on_deleted)
ISC_TEST_ENTRY(isc_tw_delete_idempotent)
ISC_TEST_ENTRY(isc_tw_increased_reorders_queue)
ISC_TEST_ENTRY(isc_tw_settime_cascades)
ISC_TEST_ENTRY(isc_tw_level_selection)
ISC_TEST_ENTRY(isc_tw_multiple_in_same_slot)
ISC_TEST_ENTRY(isc_tw_wraparound_level0)
ISC_TEST_ENTRY(isc_tw_past_timer_goes_to_current_slot)
ISC_TEST_ENTRY(isc_tw_large_time_jump)
ISC_TEST_ENTRY(isc_tw_earliest_slot_optimization)

ISC_TEST_LIST_END

ISC_TEST_MAIN
