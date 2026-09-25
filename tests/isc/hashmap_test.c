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

#include <isc/hash.h>
#include <isc/hashmap.h>
#include <isc/lib.h>
#include <isc/mem.h>
#include <isc/string.h>
#include <isc/util.h>

#include <tests/isc.h>

/* INCLUDE LAST */

#include "hashmap.c"

typedef struct test_node {
	uint32_t hashval;
	char key[64];
} test_node_t;

static bool
nodes_match(void *node0, const void *key) {
	struct test_node *node = node0;

	return memcmp(node->key, key, 16) == 0;
}

static bool
long_nodes_match(void *node0, const void *key) {
	struct test_node *node = node0;
	size_t len = strlen(key);

	return memcmp(node->key, key, len) == 0;
}

static bool
upper_nodes_match(void *node0, const void *key) {
	struct test_node *node = node0;

	return isc_ascii_lowerequal((uint8_t *)node->key, key, 16);
}

static void
test_hashmap_full(uint8_t init_bits, uintptr_t count) {
	isc_hashmap_t *hashmap = NULL;
	isc_result_t result;
	test_node_t *nodes, *long_nodes, *upper_nodes;

	nodes = isc_mem_cget(isc_g_mctx, count, sizeof(nodes[0]));
	long_nodes = isc_mem_cget(isc_g_mctx, count, sizeof(nodes[0]));
	upper_nodes = isc_mem_cget(isc_g_mctx, count, sizeof(nodes[0]));

	isc_hashmap_create(isc_g_mctx, init_bits, &hashmap);
	assert_non_null(hashmap);

	/*
	 * Note: snprintf() is followed with strlcat()
	 * to ensure we are always filling the 16 byte key.
	 */
	for (size_t i = 0; i < count; i++) {
		/* short keys */
		snprintf((char *)nodes[i].key, 16, "%u", (unsigned int)i);
		strlcat((char *)nodes[i].key, " key of a raw hashmap!!", 16);
		nodes[i].hashval = isc_hash32(nodes[i].key, 16, true);

		/* long keys */
		snprintf((char *)long_nodes[i].key, sizeof(long_nodes[i].key),
			 "%u", (unsigned int)i);
		strlcat((char *)long_nodes[i].key, " key of a raw hashmap!!",
			sizeof(long_nodes[i].key));
		long_nodes[i].hashval = isc_hash32(
			long_nodes[i].key,
			strlen((const char *)long_nodes[i].key), true);

		/* (some) uppercase keys */
		snprintf((char *)upper_nodes[i].key, 16, "%u", (unsigned int)i);
		strlcat((char *)upper_nodes[i].key, " KEY of a raw hashmap!!",
			16);
		upper_nodes[i].hashval = isc_hash32(upper_nodes[i].key, 16,
						    false);
	}

	/* insert short nodes */
	for (size_t i = 0; i < count; i++) {
		void *f = NULL;
		result = isc_hashmap_add(hashmap, nodes[i].hashval, nodes_match,
					 nodes[i].key, &nodes[i], &f);
		assert_int_equal(result, ISC_R_SUCCESS);
		assert_ptr_equal(f, NULL);
	}

	/* check if the short nodes were insert */
	for (size_t i = 0; i < count; i++) {
		void *f = NULL;
		result = isc_hashmap_find(hashmap, nodes[i].hashval,
					  nodes_match, nodes[i].key, &f);
		assert_int_equal(result, ISC_R_SUCCESS);
		assert_ptr_equal(&nodes[i], f);
	}

	/* check for double inserts */
	for (size_t i = 0; i < count; i++) {
		void *f = NULL;
		result = isc_hashmap_add(hashmap, nodes[i].hashval, nodes_match,
					 nodes[i].key, &nodes[i], &f);
		assert_int_equal(result, ISC_R_EXISTS);
		assert_ptr_equal(f, &nodes[i]);
	}

	for (size_t i = 0; i < count; i++) {
		void *f = NULL;
		result = isc_hashmap_add(hashmap, long_nodes[i].hashval,
					 long_nodes_match, long_nodes[i].key,
					 &long_nodes[i], &f);
		assert_int_equal(result, ISC_R_SUCCESS);
		assert_ptr_equal(f, NULL);
	}

	for (size_t i = 0; i < count; i++) {
		void *f = NULL;
		result = isc_hashmap_find(hashmap, upper_nodes[i].hashval,
					  long_nodes_match, upper_nodes[i].key,
					  &f);
		assert_int_equal(result, ISC_R_NOTFOUND);
		assert_null(f);
	}

	for (size_t i = 0; i < count; i++) {
		void *f = NULL;
		result = isc_hashmap_find(hashmap, long_nodes[i].hashval,
					  long_nodes_match, long_nodes[i].key,
					  &f);
		assert_int_equal(result, ISC_R_SUCCESS);
		assert_ptr_equal(f, &long_nodes[i]);
	}

	for (size_t i = 0; i < count; i++) {
		void *f = NULL;
		result = isc_hashmap_delete(hashmap, nodes[i].hashval,
					    nodes_match, nodes[i].key);
		assert_int_equal(result, ISC_R_SUCCESS);
		result = isc_hashmap_find(hashmap, nodes[i].hashval,
					  nodes_match, nodes[i].key, &f);
		assert_int_equal(result, ISC_R_NOTFOUND);
		assert_null(f);
	}

	for (size_t i = 0; i < count; i++) {
		void *f = NULL;
		result = isc_hashmap_add(hashmap, upper_nodes[i].hashval,
					 upper_nodes_match, upper_nodes[i].key,
					 &upper_nodes[i], &f);
		assert_int_equal(result, ISC_R_SUCCESS);
		assert_ptr_equal(f, NULL);
	}

	for (size_t i = 0; i < count; i++) {
		void *f = NULL;
		result = isc_hashmap_delete(hashmap, long_nodes[i].hashval,
					    long_nodes_match,
					    long_nodes[i].key);
		assert_int_equal(result, ISC_R_SUCCESS);
		result = isc_hashmap_find(hashmap, long_nodes[i].hashval,
					  long_nodes_match, long_nodes[i].key,
					  &f);
		assert_int_equal(result, ISC_R_NOTFOUND);
		assert_null(f);
	}

	for (size_t i = 0; i < count; i++) {
		void *f = NULL;
		result = isc_hashmap_find(hashmap, upper_nodes[i].hashval,
					  upper_nodes_match, upper_nodes[i].key,
					  &f);
		assert_int_equal(result, ISC_R_SUCCESS);
		assert_ptr_equal(f, &upper_nodes[i]);
	}

	for (size_t i = 0; i < count; i++) {
		void *f = NULL;
		result = isc_hashmap_find(hashmap, nodes[i].hashval,
					  nodes_match, nodes[i].key, &f);
		assert_int_equal(result, ISC_R_NOTFOUND);
		assert_null(f);
	}

	isc_hashmap_destroy(&hashmap);
	assert_null(hashmap);

	isc_mem_cput(isc_g_mctx, nodes, count, sizeof(nodes[0]));
	isc_mem_cput(isc_g_mctx, long_nodes, count, sizeof(nodes[0]));
	isc_mem_cput(isc_g_mctx, upper_nodes, count, sizeof(nodes[0]));
}

#include "hashmap_nodes.h"

static void
test_hashmap_iterator(bool random_data) {
	isc_hashmap_t *hashmap = NULL;
	isc_result_t result;
	isc_hashmap_iter_t *iter = NULL;
	size_t count = 7600;
	test_node_t *nodes;
	bool *seen;

	nodes = isc_mem_cget(isc_g_mctx, count, sizeof(nodes[0]));
	seen = isc_mem_cget(isc_g_mctx, count, sizeof(seen[0]));

	isc_hashmap_create(isc_g_mctx, HASHMAP_MIN_BITS, &hashmap);
	assert_non_null(hashmap);

	for (size_t i = 0; i < count; i++) {
		/* short keys */
		snprintf((char *)nodes[i].key, 16, "%u", (unsigned int)i);
		strlcat((char *)nodes[i].key, " key of a raw hashmap!!", 16);
		if (random_data) {
			nodes[i].hashval = isc_hash32(nodes[i].key, 16, true);
		} else {
			nodes[i].hashval = test_hashvals[i];
		}
	}

	for (size_t i = 0; i < count; i++) {
		void *f = NULL;
		result = isc_hashmap_add(hashmap, nodes[i].hashval, nodes_match,
					 nodes[i].key, &nodes[i], &f);
		assert_int_equal(result, ISC_R_SUCCESS);
		assert_ptr_equal(f, NULL);
	}

	/* We want to iterate while rehashing is in progress */
	assert_true(rehashing_in_progress(hashmap));

	memset(seen, 0, count * sizeof(seen[0]));
	isc_hashmap_iter_create(hashmap, &iter);

	for (result = isc_hashmap_iter_first(iter); result == ISC_R_SUCCESS;
	     result = isc_hashmap_iter_next(iter))
	{
		char key[16] = { 0 };
		ptrdiff_t i;
		test_node_t *v = NULL;

		isc_hashmap_iter_current(iter, (void *)&v);

		i = v - &nodes[0];

		snprintf(key, 16, "%u", (unsigned int)i);
		strlcat(key, " key of a raw hashmap!!", 16);

		assert_memory_equal(key, v->key, 16);

		assert_false(seen[i]);
		seen[i] = true;
	}
	assert_int_equal(result, ISC_R_NOMORE);
	for (size_t i = 0; i < count; i++) {
		assert_true(seen[i]);
	}

	/* erase odd */
	memset(seen, 0, count * sizeof(seen[0]));
	result = isc_hashmap_iter_first(iter);
	while (result == ISC_R_SUCCESS) {
		char key[16] = { 0 };
		ptrdiff_t i;
		test_node_t *v = NULL;

		isc_hashmap_iter_current(iter, (void *)&v);

		i = v - nodes;
		snprintf(key, 16, "%u", (unsigned int)i);
		strlcat(key, " key of a raw hashmap!!", 16);
		assert_memory_equal(key, v->key, 16);

		if (i % 2 == 0) {
			result = isc_hashmap_iter_delcurrent_next(iter);
		} else {
			result = isc_hashmap_iter_next(iter);
		}

		assert_false(seen[i]);
		seen[i] = true;
	}
	assert_int_equal(result, ISC_R_NOMORE);
	for (size_t i = 0; i < count; i++) {
		assert_true(seen[i]);
	}

	/* erase even */
	memset(seen, 0, count * sizeof(seen[0]));
	result = isc_hashmap_iter_first(iter);
	while (result == ISC_R_SUCCESS) {
		char key[16] = { 0 };
		ptrdiff_t i;
		test_node_t *v = NULL;

		isc_hashmap_iter_current(iter, (void *)&v);

		i = v - nodes;
		snprintf(key, 16, "%u", (unsigned int)i);
		strlcat(key, " key of a raw hashmap!!", 16);
		assert_memory_equal(key, v->key, 16);

		if (i % 2 == 1) {
			result = isc_hashmap_iter_delcurrent_next(iter);
		} else {
			result = isc_hashmap_iter_next(iter);
		}
	}
	assert_int_equal(result, ISC_R_NOMORE);

	for (result = isc_hashmap_iter_first(iter); result == ISC_R_SUCCESS;
	     result = isc_hashmap_iter_next(iter))
	{
		assert_true(false);
	}
	assert_int_equal(result, ISC_R_NOMORE);

	/* Iterator doesn't progress rehashing */
	assert_true(rehashing_in_progress(hashmap));

	isc_hashmap_iter_destroy(&iter);
	assert_null(iter);

	isc_hashmap_destroy(&hashmap);
	assert_null(hashmap);

	isc_mem_cput(isc_g_mctx, seen, count, sizeof(seen[0]));
	isc_mem_cput(isc_g_mctx, nodes, count, sizeof(nodes[0]));
}

/* 1 bit, 120 elements test, full rehashing */
ISC_RUN_TEST_IMPL(isc_hashmap_1_120) {
	test_hashmap_full(1, 120);
	return;
}

/* 6 bit, 1000 elements test, full rehashing */
ISC_RUN_TEST_IMPL(isc_hashmap_6_1000) {
	test_hashmap_full(6, 1000);
	return;
}

/* 24 bit, 200K elements test, no rehashing */
ISC_RUN_TEST_IMPL(isc_hashmap_24_200000) {
	test_hashmap_full(24, 200000);
	return;
}

/* 15 bit, 45K elements test, full rehashing */
ISC_RUN_TEST_IMPL(isc_hashmap_1_48000) {
	test_hashmap_full(1, 48000);
	return;
}

/* 8 bit, 20k elements test, partial rehashing */
ISC_RUN_TEST_IMPL(isc_hashmap_8_20000) {
	test_hashmap_full(8, 20000);
	return;
}

/* test hashmap iterator */

ISC_RUN_TEST_IMPL(isc_hashmap_iterator) {
	test_hashmap_iterator(true);
	return;
}

ISC_RUN_TEST_IMPL(isc_hashmap_iterator_static) {
	test_hashmap_iterator(false);
	return;
}

ISC_RUN_TEST_IMPL(isc_hashmap_hash_zero_length) {
	isc_hashmap_t *hashmap = NULL;
	uint32_t hashval;
	bool again = false;

again:
	isc_hashmap_create(isc_g_mctx, 1, &hashmap);

	hashval = isc_hash32("", 0, true);

	isc_hashmap_destroy(&hashmap);

	if (hashval == 0 && !again) {
		/*
		 * We could be extremely unlucky and the siphash could hash the
		 * zero length string to 0, so try one more time.
		 */
		again = true;
		goto again;
	}

	assert_int_not_equal(hashval, 0);
}

static bool
case_match(void *node0, const void *key) {
	struct test_node *node = node0;
	size_t len = strlen(key);

	return memcmp(node->key, key, len) == 0;
}

static bool
nocase_match(void *node0, const void *key) {
	struct test_node *node = node0;
	size_t len = strlen(key);

	return isc_ascii_lowerequal((uint8_t *)node->key, key, len);
}

ISC_RUN_TEST_IMPL(isc_hashmap_case) {
	isc_result_t result;
	isc_hashmap_t *hashmap = NULL;
	test_node_t lower = { .key = "isc_hashmap_case" };
	test_node_t same = { .key = "isc_hashmap_case" };
	test_node_t upper = { .key = "ISC_HASHMAP_CASE" };
	test_node_t mixed = { .key = "IsC_hAsHmAp_CaSe" };
	void *f = NULL;

	isc_hashmap_create(isc_g_mctx, 1, &hashmap);

	result = isc_hashmap_add(hashmap,
				 isc_hash32(lower.key, strlen(lower.key), true),
				 case_match, lower.key, &lower, NULL);
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_hashmap_add(hashmap,
				 isc_hash32(same.key, strlen(same.key), true),
				 case_match, same.key, &same, NULL);
	assert_int_equal(result, ISC_R_EXISTS);

	result = isc_hashmap_add(hashmap,
				 isc_hash32(upper.key, strlen(upper.key), true),
				 case_match, upper.key, &upper, NULL);
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_hashmap_find(
		hashmap, isc_hash32(mixed.key, strlen(mixed.key), true),
		case_match, mixed.key, &f);
	assert_int_equal(result, ISC_R_NOTFOUND);
	assert_ptr_equal(f, NULL);

	isc_hashmap_destroy(&hashmap);

	isc_hashmap_create(isc_g_mctx, 1, &hashmap);

	result = isc_hashmap_add(
		hashmap, isc_hash32(lower.key, strlen(lower.key), false),
		nocase_match, lower.key, &lower, NULL);
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_hashmap_add(hashmap,
				 isc_hash32(same.key, strlen(same.key), false),
				 nocase_match, same.key, &same, NULL);
	assert_int_equal(result, ISC_R_EXISTS);

	result = isc_hashmap_add(
		hashmap, isc_hash32(upper.key, strlen(upper.key), false),
		nocase_match, upper.key, &upper, NULL);
	assert_int_equal(result, ISC_R_EXISTS);

	result = isc_hashmap_find(
		hashmap, isc_hash32(mixed.key, strlen(mixed.key), false),
		nocase_match, mixed.key, &f);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_ptr_equal(f, &lower);

	isc_hashmap_destroy(&hashmap);
}

static bool
nullable_match(void *value, const void *key) {
	return value == *(void *const *)key;
}

ISC_RUN_TEST_IMPL(isc_hashmap_null_value) {
	isc_hashmap_t *hashmap = NULL;
	isc_hashmap_iter_t *iter = NULL;
	int objects[64];
	void *values[64] = { NULL };
	bool seen_null = false;
	unsigned int count = 0;
	isc_result_t result;

	isc_hashmap_create(isc_g_mctx, 1, &hashmap);
	for (size_t i = 1; i < 64; i++) {
		values[i] = &objects[i];
	}

	/* Force collisions and growth, including a displaced NULL value. */
	for (size_t i = 64; i-- > 0;) {
		result = isc_hashmap_add(hashmap, 0, nullable_match, &values[i],
					 values[i], NULL);
		assert_int_equal(result, ISC_R_SUCCESS);
	}
	assert_int_equal(isc_hashmap_count(hashmap), 64);

	for (size_t i = 0; i < 64; i++) {
		void *found = NULL;
		result = isc_hashmap_find(hashmap, 0, nullable_match,
					  &values[i], &found);
		assert_int_equal(result, ISC_R_SUCCESS);
		assert_ptr_equal(found, values[i]);
		found = &objects[0];
		result = isc_hashmap_add(hashmap, 0, nullable_match, &values[i],
					 values[i], &found);
		assert_int_equal(result, ISC_R_EXISTS);
		assert_ptr_equal(found, values[i]);
	}

	/* Shift the collision chain and shrink while retaining NULL. */
	for (size_t i = 1; i < 64; i++) {
		result = isc_hashmap_delete(hashmap, 0, nullable_match,
					    &values[i]);
		assert_int_equal(result, ISC_R_SUCCESS);
		result = isc_hashmap_find(hashmap, 0, nullable_match,
					  &values[0], NULL);
		assert_int_equal(result, ISC_R_SUCCESS);
	}
	assert_int_equal(isc_hashmap_count(hashmap), 1);

	isc_hashmap_iter_create(hashmap, &iter);
	for (result = isc_hashmap_iter_first(iter); result == ISC_R_SUCCESS;
	     result = isc_hashmap_iter_delcurrent_next(iter))
	{
		void *value = NULL;
		isc_hashmap_iter_current(iter, &value);
		assert_null(value);
		seen_null = true;
		count++;
	}
	assert_int_equal(result, ISC_R_NOMORE);
	assert_true(seen_null);
	assert_int_equal(count, 1);
	isc_hashmap_iter_destroy(&iter);
	assert_int_equal(isc_hashmap_count(hashmap), 0);
	result = isc_hashmap_find(hashmap, 0, nullable_match, &values[0], NULL);
	assert_int_equal(result, ISC_R_NOTFOUND);

	/* Also remove a NULL value through the ordinary deletion API. */
	result = isc_hashmap_add(hashmap, 0, nullable_match, &values[0], NULL,
				 NULL);
	assert_int_equal(result, ISC_R_SUCCESS);
	result = isc_hashmap_delete(hashmap, 0, nullable_match, &values[0]);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_int_equal(isc_hashmap_count(hashmap), 0);
	isc_hashmap_destroy(&hashmap);
}

ISC_TEST_LIST_START
ISC_TEST_ENTRY(isc_hashmap_null_value)
ISC_TEST_ENTRY(isc_hashmap_hash_zero_length)
ISC_TEST_ENTRY(isc_hashmap_case)
ISC_TEST_ENTRY(isc_hashmap_1_120)
ISC_TEST_ENTRY(isc_hashmap_6_1000)
ISC_TEST_ENTRY(isc_hashmap_24_200000)
ISC_TEST_ENTRY(isc_hashmap_1_48000)
ISC_TEST_ENTRY(isc_hashmap_8_20000)
ISC_TEST_ENTRY(isc_hashmap_iterator)
ISC_TEST_ENTRY(isc_hashmap_iterator_static)
ISC_TEST_LIST_END

ISC_TEST_MAIN
