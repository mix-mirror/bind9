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

#include <stdint.h>

#include <isc/hash.h>
#include <isc/mem.h>
#include <isc/util.h>

#include "../qpzone_p.h"

/*
 * Search order is (hash, node identity, typepair); priority order is
 * (signing time, is SOA, node identity, typepair). In particular, the hash
 * is NOT a priority tiebreaker: equal signing times must not form a chain.
 * Expected logarithmic height relies on search hashes being independent of
 * the scheduling workload. All traversals are iterative even for a chain.
 */
typedef struct prio_entry {
	qpznode_t *node;
	int64_t resign;
	struct prio_entry *left;
	struct prio_entry *right;
	dns_typepair_t typepair;
	uint32_t hash;
} prio_entry_t;

struct qpz_prio {
	isc_mem_t *mctx;
	prio_entry_t *root;
	/* Capture the randomized hash initializer for this tree's lifetime. */
	isc_hash32_t hashstate;
};

static int
identity_compare(const prio_entry_t *a, const prio_entry_t *b) {
	uintptr_t an = (uintptr_t)a->node, bn = (uintptr_t)b->node;
	if (an != bn) {
		return an < bn ? -1 : 1;
	}
	return (a->typepair > b->typepair) - (a->typepair < b->typepair);
}

static int
search_compare(const prio_entry_t *a, const prio_entry_t *b) {
	if (a->hash != b->hash) {
		return a->hash < b->hash ? -1 : 1;
	}
	return identity_compare(a, b);
}

static bool
sooner(const prio_entry_t *a, const prio_entry_t *b) {
	if (a->resign != b->resign) {
		return a->resign < b->resign;
	}
	bool a_soa = a->typepair == DNS_SIGTYPEPAIR(dns_rdatatype_soa);
	bool b_soa = b->typepair == DNS_SIGTYPEPAIR(dns_rdatatype_soa);
	if (a_soa != b_soa) {
		return !a_soa;
	}
	return identity_compare(a, b) < 0;
}

static prio_entry_t
make_key(qpz_prio_t *tree, qpznode_t *node, dns_typepair_t typepair) {
	uintptr_t identity = (uintptr_t)node;
	isc_hash32_t state = tree->hashstate;
	isc_hash32_hash(&state, &identity, sizeof(identity), true);
	isc_hash32_hash(&state, &typepair, sizeof(typepair), true);
	return (prio_entry_t){
		.node = node,
		.typepair = typepair,
		.hash = isc_hash32_finalize(&state),
	};
}

static prio_entry_t **
find(qpz_prio_t *tree, const prio_entry_t *key) {
	prio_entry_t **link = &tree->root;
	while (*link != NULL) {
		prio_entry_t *entry = *link;
		int order = search_compare(key, entry);
		if (order == 0) {
			break;
		}
		link = order < 0 ? &entry->left : &entry->right;
	}
	return link;
}

/* Merge adjacent search ranges by walking their adjoining boundary. */
static prio_entry_t *
merge(prio_entry_t *left, prio_entry_t *right) {
	prio_entry_t *root = NULL, **link = &root;
	while (left != NULL && right != NULL) {
		if (sooner(left, right)) {
			*link = left;
			link = &left->right;
			left = left->right;
		} else {
			*link = right;
			link = &right->left;
			right = right->left;
		}
	}
	*link = left != NULL ? left : right;
	return root;
}

/* Insert at the priority boundary, splitting the remaining search range. */
static void
insert(qpz_prio_t *tree, prio_entry_t *entry) {
	prio_entry_t **link = &tree->root;
	while (*link != NULL && sooner(*link, entry)) {
		prio_entry_t *current = *link;
		link = search_compare(entry, current) < 0 ? &current->left
							  : &current->right;
	}

	prio_entry_t *rest = *link;
	*link = entry;
	prio_entry_t **left = &entry->left, **right = &entry->right;
	while (rest != NULL) {
		if (search_compare(rest, entry) < 0) {
			*left = rest;
			left = &rest->right;
			rest = rest->right;
		} else {
			*right = rest;
			right = &rest->left;
			rest = rest->left;
		}
	}
	*left = *right = NULL;
}

qpz_prio_t *
qpz_prio_create(isc_mem_t *mctx) {
	qpz_prio_t *tree = isc_mem_get(mctx, sizeof(*tree));
	*tree = (qpz_prio_t){ 0 };
	isc_mem_attach(mctx, &tree->mctx);
	isc_hash32_init(&tree->hashstate);
	return tree;
}

void
qpz_prio_destroy(qpz_prio_t **treep, void (*release)(qpznode_t *)) {
	qpz_prio_t *tree = *treep;
	*treep = NULL;
	/* Rotate away left children, freeing the tree in linear time. */
	prio_entry_t *entry = tree->root;
	while (entry != NULL) {
		if (entry->left != NULL) {
			prio_entry_t *left = entry->left;
			entry->left = left->right;
			left->right = entry;
			entry = left;
		} else {
			prio_entry_t *next = entry->right;
			release(entry->node);
			isc_mem_put(tree->mctx, entry, sizeof(*entry));
			entry = next;
		}
	}
	isc_mem_putanddetach(&tree->mctx, tree, sizeof(*tree));
}

qpz_resignstate_t
qpz_prio_set(qpz_prio_t *tree, qpznode_t *node, dns_typepair_t typepair,
	     int64_t resign) {
	REQUIRE(node != NULL);
	prio_entry_t key = make_key(tree, node, typepair);
	qpz_resignstate_t previous = { 0 };
	prio_entry_t **link = find(tree, &key);
	prio_entry_t *entry = *link;
	if (entry != NULL) {
		previous = (qpz_resignstate_t){
			.resign = entry->resign,
			.scheduled = true,
		};
		if (entry->resign == resign) {
			return previous;
		}
		*link = merge(entry->left, entry->right);
	} else {
		entry = isc_mem_get(tree->mctx, sizeof(*entry));
	}
	key.resign = resign;
	*entry = key;
	insert(tree, entry);
	return previous;
}

qpz_resignstate_t
qpz_prio_delete(qpz_prio_t *tree, qpznode_t *node, dns_typepair_t typepair) {
	REQUIRE(node != NULL);
	prio_entry_t key = make_key(tree, node, typepair);
	qpz_resignstate_t previous = { 0 };
	prio_entry_t **link = find(tree, &key);
	prio_entry_t *entry = *link;
	if (entry != NULL) {
		previous = (qpz_resignstate_t){
			.resign = entry->resign,
			.scheduled = true,
		};
		*link = merge(entry->left, entry->right);
		isc_mem_put(tree->mctx, entry, sizeof(*entry));
	}
	return previous;
}

bool
qpz_prio_first(const qpz_prio_t *tree, qpznode_t **node, int64_t *resign,
	       dns_typepair_t *typepair) {
	const prio_entry_t *entry = tree->root;
	if (entry == NULL) {
		return false;
	}
	*node = entry->node;
	*resign = entry->resign;
	*typepair = entry->typepair;
	return true;
}
