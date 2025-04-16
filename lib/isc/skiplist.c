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
#include <stdbool.h>

#include <isc/atomic.h>
#include <isc/bit.h>
#include <isc/magic.h>
#include <isc/mem.h>
#include <isc/random.h>
#include <isc/refcount.h>
#include <isc/skiplist.h>
#include <isc/urcu.h>
#include <isc/util.h>

#define SKIPLIST_MAGIC	    ISC_MAGIC('S', 'K', 'I', 'P')
#define SKIPLIST_ITER_MAGIC ISC_MAGIC('S', 'K', 'I', 't')

#define MAX_HEIGHT 32

#define TAG_NODE ((uintptr_t)0x01)

#define UNTAG_HALFINDEX(x) (x & ~TAG_NODE)

#define UPDATE_HALFINDEX(index, x) \
	index = ((uintptr_t)(void *)x) | ((index) & TAG_NODE)

#define HALFINDEX_TO_POINTER(x) \
	((isc_skiplist_index_t *)(void *)UNTAG_HALFINDEX(x))

#define POINTER_TO_UNTAGGED_HALFINDEX(x)                                  \
	({                                                                \
		STATIC_ASSERT(__builtin_types_compatible_p(               \
				      typeof(x), isc_skiplist_index_t *), \
			      "only index pointers can be half-indexes"); \
		((uintptr_t)(void *)(x));                                 \
	})

#define POINTER_TO_TAGGED_HALFINDEX(x)                                    \
	({                                                                \
		STATIC_ASSERT(__builtin_types_compatible_p(               \
				      typeof(x), isc_skiplist_index_t *), \
			      "only index pointers can be half-indexes"); \
		(((uintptr_t)(void *)(x)) | TAG_NODE);                    \
	})

typedef struct skipnode skipnode_t;

struct skipnode {
	uint32_t height;
	uint64_t value;
	isc_skiplist_index_t index;
	skipnode_t *next[];
};

struct isc_skiplist {
	uint32_t magic;
	uint32_t attached_iterators;
	isc_mem_t *mctx;
	skipnode_t *head;
};

struct isc_skiplist_iter {
	uint32_t magic;
	isc_skiplist_index_t *cursor;
	isc_skiplist_t *skip;
};

static void
remove_node(isc_mem_t *mctx, skipnode_t *head, skipnode_t *node) {
	skipnode_t *cursor, *next, *tower[MAX_HEIGHT];
	uint64_t value;
	int32_t level;
	size_t i;

	value = node->value;

	cursor = head;
	level = MAX_HEIGHT - 1;

	while (level >= 0) {
		next = cursor->next[level];

		if (value <= next->value) {
			tower[level] = cursor;
			level--;
			continue;
		}

		cursor = next;
	}

	for (i = 0; i < node->height; i++) {
		tower[i]->next[i] = node->next[i];
	}

	isc_mem_put(mctx, node, STRUCT_FLEX_SIZE(node, next, node->height));
}

void
isc_skiplist_create(isc_mem_t *mctx, isc_skiplist_t **skipp) {
	isc_skiplist_t *skip;
	skipnode_t *node;
	size_t i;

	REQUIRE(skipp != NULL && *skipp == NULL);

	node = isc_mem_get(mctx, STRUCT_FLEX_SIZE(node, next, MAX_HEIGHT));

	*node = (skipnode_t){
		.height = MAX_HEIGHT,
		.value = UINT64_MAX,
		.index = {
			.lo = POINTER_TO_UNTAGGED_HALFINDEX(&node->index),
			.hi = TAG_NODE,
		},
	};

	for (i = 0; i < MAX_HEIGHT; i++) {
		node->next[i] = node;
	}

	skip = isc_mem_get(mctx, sizeof(*skip));
	*skip = (isc_skiplist_t){
		.magic = SKIPLIST_MAGIC,
		.head = node,
	};

	isc_mem_attach(mctx, &skip->mctx);

	*skipp = skip;
}

void
isc_skiplist_destroy(isc_skiplist_t **skipp) {
	skipnode_t *cursor, *next;
	isc_skiplist_t *skip;

	REQUIRE(skipp != NULL && *skipp != NULL);
	REQUIRE((*skipp)->magic == SKIPLIST_MAGIC);

	skip = *skipp;
	*skipp = NULL;

	skip->magic = 0;

	for (cursor = skip->head->next[0]; cursor != skip->head; cursor = next)
	{
		next = cursor->next[0];

		isc_mem_put(skip->mctx, cursor,
			    STRUCT_FLEX_SIZE(cursor, next, cursor->height));
	}

	isc_mem_put(skip->mctx, skip->head,
		    STRUCT_FLEX_SIZE(skip->head, next, MAX_HEIGHT));

	isc_mem_putanddetach(&skip->mctx, skip, sizeof(*skip));
}

void
isc_skiplist_insert(isc_skiplist_t *skip, uint64_t value,
		    isc_skiplist_index_t *index) {
	skipnode_t *cursor, *next, *tower[MAX_HEIGHT];
	isc_skiplist_index_t *idx;
	uint32_t height;
	int32_t level;
	size_t i;

	REQUIRE(skip != NULL && skip->magic == SKIPLIST_MAGIC);
	REQUIRE(skip->attached_iterators == 0);
	REQUIRE(value != UINT64_MAX);
	REQUIRE(index != NULL);
	REQUIRE(index->lo == UINTPTR_MAX && index->hi == UINTPTR_MAX);

	cursor = skip->head;
	level = MAX_HEIGHT - 1;

	while (level >= 0) {
		next = cursor->next[level];

		if (value < next->value) {
			tower[level] = cursor;
			level--;
			continue;
		} else if (value == next->value) {
			*index = (isc_skiplist_index_t){
				.lo = POINTER_TO_TAGGED_HALFINDEX(&next->index),
				.hi = UNTAG_HALFINDEX(next->index.hi),
			};

			idx = HALFINDEX_TO_POINTER(next->index.hi);
			UPDATE_HALFINDEX(idx->lo, index);
			next->index.hi = POINTER_TO_TAGGED_HALFINDEX(index);

			return;
		}

		cursor = next;
	}

	idx = HALFINDEX_TO_POINTER(next->index.lo);

	height = stdc_trailing_zeros(isc_random32() | (1U << 31)) + 1;

	cursor = isc_mem_get(skip->mctx,
			     STRUCT_FLEX_SIZE(cursor, next, height));
	*cursor = (skipnode_t){
		.height = height,
		.value = value,
		.index = {
			.lo = POINTER_TO_UNTAGGED_HALFINDEX(idx),
			.hi = POINTER_TO_TAGGED_HALFINDEX(index),
		},
	};

	for (i = 0; i < cursor->height; i++) {
		cursor->next[i] = tower[i]->next[i];
		tower[i]->next[i] = cursor;
	}

	*index = (isc_skiplist_index_t){
		.lo = POINTER_TO_TAGGED_HALFINDEX(&cursor->index),
		.hi = UNTAG_HALFINDEX(idx->hi),
	};

	next->index.lo = POINTER_TO_UNTAGGED_HALFINDEX(index);

	idx->hi = ((uintptr_t)(void *)&cursor->index) | (idx->hi & TAG_NODE);
}

void
isc_skiplist_remove(isc_skiplist_t *skip, isc_skiplist_index_t *index) {
	isc_skiplist_index_t tmp, *prev, *next;
	skipnode_t *node;

	REQUIRE(skip != NULL && skip->magic == SKIPLIST_MAGIC);
	REQUIRE(skip->attached_iterators == 0);
	REQUIRE(index != NULL);
	REQUIRE(index->hi != UINTPTR_MAX && index->lo != UINTPTR_MAX);

	INSIST(!(index->lo & index->hi & TAG_NODE));

	tmp = *index;
	*index = (isc_skiplist_index_t)ISC_SKIPLIST_INDEX_INITIALIZER;

	prev = HALFINDEX_TO_POINTER(tmp.lo);
	next = HALFINDEX_TO_POINTER(tmp.hi);

	if (tmp.lo & TAG_NODE) {
		if (prev->hi & TAG_NODE) {
			node = caa_container_of(prev, skipnode_t, index);
			prev = HALFINDEX_TO_POINTER(prev->lo);
			remove_node(skip->mctx, skip->head, node);
		} else {
			prev->lo |= TAG_NODE;
		}
	}

	if (next != NULL) {
		UPDATE_HALFINDEX(next->lo, prev);
	}

	prev->hi = tmp.hi | (prev->hi & TAG_NODE);
}

isc_result_t
isc_skiplist_iter_attach(isc_skiplist_t *skip, isc_skiplist_iter_t **iterp) {
	isc_skiplist_index_t *index;
	isc_skiplist_iter_t *iter;

	REQUIRE(skip != NULL && skip->magic == SKIPLIST_MAGIC);
	REQUIRE(iterp != NULL && *iterp == NULL);

	index = &skip->head->index;
	while (index->hi & TAG_NODE) {
		if (UNTAG_HALFINDEX(index->hi) == 0x00) {
			return ISC_R_NOMORE;
		}
		index = HALFINDEX_TO_POINTER(index->hi);
	}

	iter = isc_mem_get(skip->mctx, sizeof(*iter));
	*iter = (isc_skiplist_iter_t){
		.magic = SKIPLIST_ITER_MAGIC,
		.cursor = index,
		.skip = skip,
	};

	skip->attached_iterators++;

	*iterp = iter;

	return ISC_R_SUCCESS;
}

void
isc_skiplist_iter_destroy(isc_skiplist_iter_t **iterp) {
	isc_skiplist_iter_t *iter;
	isc_skiplist_t *skip;

	REQUIRE(iterp != NULL && (*iterp)->magic == SKIPLIST_ITER_MAGIC);

	iter = *iterp;
	*iterp = NULL;

	iter->magic = 0;

	skip = iter->skip;

	skip->attached_iterators--;

	isc_mem_put(skip->mctx, iter, sizeof(*iter));
}

void
isc_skiplist_iter_current(isc_skiplist_iter_t *iter,
			  isc_skiplist_index_t **indexp) {
	REQUIRE(iter != NULL && iter->magic == SKIPLIST_ITER_MAGIC);
	REQUIRE(indexp != NULL && *indexp == NULL);

	INSIST((iter->cursor->hi & TAG_NODE) == 0x00);

	*indexp = iter->cursor;
}

isc_result_t
isc_skiplist_iter_next(isc_skiplist_iter_t *iter) {
	isc_skiplist_index_t *cursor;

	REQUIRE(iter != NULL && iter->magic == SKIPLIST_ITER_MAGIC);

	cursor = iter->cursor;
	do {
		if (HALFINDEX_TO_POINTER(cursor->hi) == NULL) {
			iter->cursor = cursor;
			return ISC_R_NOMORE;
		}

		cursor = HALFINDEX_TO_POINTER(cursor->hi);
	} while (cursor->hi & TAG_NODE);

	iter->cursor = cursor;
	return ISC_R_SUCCESS;
}
