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
#include <isc/urcu.h>
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

	rcu_read_lock();
	isc_tw_elt_t *min = isc_tw_element(tw);
	assert_ptr_equal(min, &second.elt);
	rcu_read_unlock();

	isc_tw_delete(tw, &first.elt);
	isc_tw_delete(tw, &second.elt);
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

ISC_RUN_TEST_IMPL(isc_tw_increased_reorders_queue) {
	isc_tw_t *tw = NULL;
	struct tw_entry early, late;

	UNUSED(state);

	assert_int_equal(isc_tw_create(isc_g_mctx, &tw), ISC_R_SUCCESS);

	init_entry(&early, 10);
	init_entry(&late, 20);

	assert_int_equal(isc_tw_insert(tw, &early.elt), ISC_R_SUCCESS);
	assert_int_equal(isc_tw_insert(tw, &late.elt), ISC_R_SUCCESS);

	late.elt.expire = 5;
	isc_tw_delete(tw, &late.elt);
	isc_tw_insert(tw, &late.elt);

	rcu_read_lock();
	isc_tw_elt_t *min = isc_tw_element(tw);
	assert_ptr_equal(min, &late.elt);
	rcu_read_unlock();

	isc_tw_delete(tw, &early.elt);
	isc_tw_delete(tw, &late.elt);
	isc_tw_destroy(&tw);
}

ISC_RUN_TEST_IMPL(isc_tw_settime_cascades) {
	isc_tw_t *tw = NULL;
	struct tw_entry distant;

	UNUSED(state);

	assert_int_equal(isc_tw_create(isc_g_mctx, &tw), ISC_R_SUCCESS);

	init_entry(&distant, 300);
	assert_int_equal(isc_tw_insert(tw, &distant.elt), ISC_R_SUCCESS);

	isc_tw_settime(tw, 400);

	rcu_read_lock();
	isc_tw_elt_t *min = isc_tw_element(tw);
	assert_non_null(min);
	assert_ptr_equal(min, &distant.elt);
	rcu_read_unlock();

	isc_tw_delete(tw, &distant.elt);
	isc_tw_destroy(&tw);
}

ISC_TEST_LIST_START

ISC_TEST_ENTRY(isc_tw_minimum_is_returned)
ISC_TEST_ENTRY(isc_tw_delete_marks_removed)
ISC_TEST_ENTRY(isc_tw_increased_reorders_queue)
ISC_TEST_ENTRY(isc_tw_settime_cascades)

ISC_TEST_LIST_END

ISC_TEST_MAIN
