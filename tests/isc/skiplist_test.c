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

#define UNIT_TESTING
#include <cmocka.h>

#include <isc/lib.h>
#include <isc/mem.h>
#include <isc/result.h>
#include <isc/skiplist.h>
#include <isc/urcu.h>

#include <tests/isc.h>

struct entry {
	uint64_t value;
	isc_skiplist_index_t index;
};

ISC_RUN_TEST_IMPL(isc_skiplist_empty) {
	isc_skiplist_iter_t *iter = NULL;
	isc_skiplist_t *skip = NULL;
	isc_result_t r;

	isc_skiplist_create(isc_g_mctx, &skip);

	r = isc_skiplist_iter_attach(skip, &iter);
	assert_int_equal(r, ISC_R_NOMORE);

	isc_skiplist_destroy(&skip);
}

ISC_RUN_TEST_IMPL(isc_skiplist_insert) {
	isc_skiplist_index_t *index = NULL;
	isc_skiplist_iter_t *iter = NULL;
	isc_skiplist_t *skip = NULL;
	struct entry *e;
	isc_result_t r;
	size_t i, j;

	struct entry data[] = {
		{ 10, ISC_SKIPLIST_INDEX_INITIALIZER },
		{ 15, ISC_SKIPLIST_INDEX_INITIALIZER },
		{ 1, ISC_SKIPLIST_INDEX_INITIALIZER },
		{ 0, ISC_SKIPLIST_INDEX_INITIALIZER },
		{ 10, ISC_SKIPLIST_INDEX_INITIALIZER },
	};

	uint32_t expected[][5] = {
		{ 10, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF },
		{ 10, 15, 0xFFFF, 0xFFFF, 0xFFFF },
		{ 1, 10, 15, 0xFFFF, 0xFFFF },
		{ 0, 1, 10, 15, 0xFFFF },
		{ 0, 1, 10, 10, 15 },
	};

	isc_skiplist_create(isc_g_mctx, &skip);

	for (i = 0; i < ARRAY_SIZE(data); i++) {
		isc_skiplist_insert(skip, data[i].value, &data[i].index);

		r = isc_skiplist_iter_attach(skip, &iter);
		assert_int_equal(r, ISC_R_SUCCESS);
		for (j = 0; j < i; j++) {
			index = NULL;
			isc_skiplist_iter_current(iter, &index);
			e = caa_container_of(index, struct entry, index);
			assert_int_equal(e->value, expected[i][j]);
			isc_skiplist_iter_next(iter);
		}

		r = isc_skiplist_iter_next(iter);
		assert_int_equal(r, ISC_R_NOMORE);

		isc_skiplist_iter_destroy(&iter);
	}

	isc_skiplist_destroy(&skip);
}

ISC_RUN_TEST_IMPL(isc_skiplist_delete) {
	isc_skiplist_index_t *index = NULL;
	isc_skiplist_iter_t *iter = NULL;
	isc_skiplist_t *skip = NULL;
	struct entry *e;
	isc_result_t r;
	size_t i, j;

	struct entry data[] = {
		{ 10, ISC_SKIPLIST_INDEX_INITIALIZER },
		{ 15, ISC_SKIPLIST_INDEX_INITIALIZER },
		{ 1, ISC_SKIPLIST_INDEX_INITIALIZER },
		{ 0, ISC_SKIPLIST_INDEX_INITIALIZER },
		{ 10, ISC_SKIPLIST_INDEX_INITIALIZER },
	};

	struct {
		isc_skiplist_index_t *index;
		uint32_t entries[5];
	} expected[] = {
		{ &data[2].index, { 0, 10, 10, 15, 0xFF } },
		{ &data[0].index, { 0, 10, 15, 0xFF, 0xFF } },
		{ &data[3].index, { 10, 15, 0xFF, 0xFF, 0xFF } },
		{ &data[1].index, { 10, 0xFF, 0xFF, 0xFF, 0xFF } },
		{ &data[4].index, { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF } },
	};

	isc_skiplist_create(isc_g_mctx, &skip);

	for (i = 0; i < ARRAY_SIZE(data); i++) {
		isc_skiplist_insert(skip, data[i].value, &data[i].index);
	}

	for (i = 0; i < ARRAY_SIZE(expected) - 1; i++) {
		isc_skiplist_remove(skip, expected[i].index);

		r = isc_skiplist_iter_attach(skip, &iter);
		assert_int_equal(r, ISC_R_SUCCESS);
		for (j = 0; j < ARRAY_SIZE(data) - i - 1; j++) {
			index = NULL;
			isc_skiplist_iter_current(iter, &index);
			e = caa_container_of(index, struct entry, index);
			assert_int_equal(e->value, expected[i].entries[j]);
			isc_skiplist_iter_next(iter);
		}

		r = isc_skiplist_iter_next(iter);
		assert_int_equal(r, ISC_R_NOMORE);

		isc_skiplist_iter_destroy(&iter);
	}

	isc_skiplist_remove(skip, expected[i].index);
	r = isc_skiplist_iter_attach(skip, &iter);
	assert_int_equal(r, ISC_R_NOMORE);

	isc_skiplist_destroy(&skip);
}

ISC_TEST_LIST_START
ISC_TEST_ENTRY(isc_skiplist_empty)
ISC_TEST_ENTRY(isc_skiplist_insert)
ISC_TEST_ENTRY(isc_skiplist_delete)
ISC_TEST_LIST_END

ISC_TEST_MAIN
