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
#include <stdint.h>
#include <stdlib.h>

#define UNIT_TESTING
#include <cmocka.h>

#include <isc/lib.h>

#include <dns/lib.h>

#include "qpzone/prio-treap.c"

#include <tests/dns.h>

/* The treap only uses node identity; it does not inspect node contents. */
struct qpznode {
	unsigned int released;
};

static void
release_node(qpznode_t *node) {
	node->released++;
}

/* Check search and heap order without recursion, including on a chain. */
static size_t
check_tree(qpz_prio_t *tree, prio_entry_t **stack, size_t capacity) {
	prio_entry_t *entry = tree->root, *previous = NULL;
	size_t depth = 0, count = 0;
	while (entry != NULL || depth != 0) {
		while (entry != NULL) {
			assert_true(depth < capacity);
			stack[depth++] = entry;
			if (entry->left != NULL) {
				assert_true(sooner(entry, entry->left));
			}
			if (entry->right != NULL) {
				assert_true(sooner(entry, entry->right));
			}
			entry = entry->left;
		}
		entry = stack[--depth];
		if (previous != NULL) {
			assert_true(search_compare(previous, entry) < 0);
		}
		previous = entry;
		assert_true(++count <= capacity);
		entry = entry->right;
	}
	return count;
}

ISC_RUN_TEST_IMPL(prio_schedule) {
	qpznode_t nodes[16] = { 0 };
	dns_typepair_t types[] = {
		DNS_SIGTYPEPAIR(dns_rdatatype_a),
		DNS_SIGTYPEPAIR(dns_rdatatype_aaaa),
		DNS_SIGTYPEPAIR(dns_rdatatype_soa),
		DNS_SIGTYPEPAIR(dns_rdatatype_mx),
	};
	qpz_resignstate_t schedule[64] = { 0 };
	prio_entry_t *stack[64];
	qpz_prio_t *tree = qpz_prio_create(isc_g_mctx);
	uint32_t random = 42;

	for (size_t step = 0; step < 4096; step++) {
		/* Deterministic trace, with an initial all-equal-time
		 * population. */
		random = random * 1664525U + 1013904223U;
		size_t i = step < 64 ? step : (random >> 16) % 64;
		qpznode_t *node = &nodes[i / 4];
		dns_typepair_t typepair = types[i % 4];
		bool remove = step >= 64 && (random & 7) == 0;
		int64_t time = step < 64 ? 100 : (int64_t)(random % 32) - 16;
		prio_entry_t key = make_key(tree, node, typepair);
		prio_entry_t *before = *find(tree, &key);
		qpz_resignstate_t old =
			remove ? qpz_prio_delete(tree, node, typepair)
			       : qpz_prio_set(tree, node, typepair, time);
		assert_int_equal(old.scheduled, schedule[i].scheduled);
		assert_int_equal(old.resign, schedule[i].resign);
		if (!remove && before != NULL) {
			/* Rescheduling must retain the allocation. */
			assert_ptr_equal(*find(tree, &key), before);
		}
		schedule[i] = (qpz_resignstate_t){
			.resign = remove ? 0 : time,
			.scheduled = !remove,
		};

		size_t count = 0, best = 64;
		for (size_t j = 0; j < 64; j++) {
			if (!schedule[j].scheduled) {
				continue;
			}
			count++;
			bool soa = j % 4 == 2, best_soa = best % 4 == 2;
			if (best == 64 ||
			    schedule[j].resign < schedule[best].resign ||
			    (schedule[j].resign == schedule[best].resign &&
			     (soa < best_soa ||
			      (soa == best_soa &&
			       (j / 4 < best / 4 ||
				(j / 4 == best / 4 &&
				 types[j % 4] < types[best % 4]))))))
			{
				best = j;
			}
		}
		assert_int_equal(check_tree(tree, stack, 64), count);
		qpznode_t *first = NULL;
		int64_t first_time;
		dns_typepair_t first_type;
		assert_int_equal(
			qpz_prio_first(tree, &first, &first_time, &first_type),
			best != 64);
		if (best != 64) {
			assert_ptr_equal(first, &nodes[best / 4]);
			assert_int_equal(first_time, schedule[best].resign);
			assert_int_equal(first_type, types[best % 4]);
		}
	}
	qpz_prio_destroy(&tree, release_node);
	assert_null(tree);
	for (size_t i = 0; i < 16; i++) {
		unsigned int count = 0;
		for (size_t j = 0; j < 4; j++) {
			count += schedule[i * 4 + j].scheduled;
		}
		assert_int_equal(nodes[i].released, count);
	}
}

ISC_RUN_TEST_IMPL(prio_collisions) {
	qpznode_t nodes[32] = { 0 };
	prio_entry_t *stack[64];
	qpz_prio_t *tree = qpz_prio_create(isc_g_mctx);
	for (size_t i = 0; i < 64; i++) {
		prio_entry_t *entry = isc_mem_get(isc_g_mctx, sizeof(*entry));
		*entry = (prio_entry_t){
			.node = &nodes[i / 2],
			.resign = (int64_t)(i * 17 % 31),
			.typepair = i % 2,
			.hash = 0,
		};
		insert(tree, entry);
		assert_int_equal(check_tree(tree, stack, 64), i + 1);
	}
	for (size_t i = 0; i < 64; i++) {
		prio_entry_t key = { .node = &nodes[i / 2], .typepair = i % 2 };
		prio_entry_t **link = find(tree, &key);
		prio_entry_t *entry = *link;
		assert_non_null(entry);
		assert_ptr_equal(entry->node, key.node);
		assert_int_equal(entry->typepair, key.typepair);
		*link = merge(entry->left, entry->right);
		isc_mem_put(isc_g_mctx, entry, sizeof(*entry));
		assert_null(*find(tree, &key));
		assert_int_equal(check_tree(tree, stack, 64), 63 - i);
	}
	qpz_prio_destroy(&tree, release_node);
}

ISC_RUN_TEST_IMPL(prio_deep_tree) {
	size_t count = 65536;
	qpznode_t node = { 0 };
	qpz_prio_t *tree = qpz_prio_create(isc_g_mctx);
	prio_entry_t **stack = isc_mem_cget(isc_g_mctx, count, sizeof(*stack));
	/* Build an intentionally degenerate, but valid, left chain. */
	for (size_t i = 0; i < count; i++) {
		prio_entry_t *entry = isc_mem_get(isc_g_mctx, sizeof(*entry));
		*entry = (prio_entry_t){
			.node = &node,
			.resign = -(int64_t)i,
			.left = tree->root,
			.typepair = i,
			.hash = i,
		};
		tree->root = entry;
	}
	assert_int_equal(check_tree(tree, stack, count), count);
	prio_entry_t key = { .node = &node, .typepair = 0, .hash = 0 };
	prio_entry_t **link = find(tree, &key);
	prio_entry_t *entry = *link;
	assert_non_null(entry);
	*link = merge(entry->left, entry->right);
	entry->resign = INT64_MIN;
	entry->left = entry->right = NULL;
	insert(tree, entry);
	assert_ptr_equal(tree->root, entry);
	assert_int_equal(check_tree(tree, stack, count), count);
	qpz_prio_destroy(&tree, release_node);
	assert_int_equal(node.released, count);
	isc_mem_cput(isc_g_mctx, stack, count, sizeof(*stack));
}

ISC_TEST_LIST_START
ISC_TEST_ENTRY(prio_schedule)
ISC_TEST_ENTRY(prio_collisions)
ISC_TEST_ENTRY(prio_deep_tree)
ISC_TEST_LIST_END

ISC_TEST_MAIN
