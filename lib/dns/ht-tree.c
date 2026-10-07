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

#include <isc/hash.h>
#include <isc/urcu.h>
#include <isc/util.h>

#include <dns/name.h>

#include "ht_tree_p.h"

/* Must be powers of 2. */
#define DNS_HT_TREE_INIT_SIZE (1 << 16)
#define DNS_HT_TREE_MIN_SIZE  (1 << 10)

typedef struct ht_key {
	dns_ht_tree_t *tree;
	const dns_name_t *name;
} ht_key_t;

static uint32_t
ht_hash(const dns_name_t *name) {
	return isc_hash32(name->ndata, name->length, false);
}

static int
ht_match(struct cds_lfht_node *ht_node, const void *key0) {
	const ht_key_t *key = key0;
	const dns_name_t *name = key->tree->methods->name(key->tree->uctx,
							  ht_node);

	return dns_name_equal(name, key->name);
}

void
dns_ht_tree_init(const dns_htmethods_t *methods, void *uctx,
		 dns_ht_tree_t *tree) {
	REQUIRE(tree != NULL);
	REQUIRE(methods != NULL);
	REQUIRE(methods->detach != NULL);
	REQUIRE(methods->name != NULL);

	*tree = (dns_ht_tree_t){
		.methods = methods,
		.uctx = uctx,
	};

	tree->ht = cds_lfht_new(DNS_HT_TREE_INIT_SIZE, DNS_HT_TREE_MIN_SIZE, 0,
				CDS_LFHT_AUTO_RESIZE | CDS_LFHT_ACCOUNTING,
				NULL);
	INSIST(tree->ht != NULL);
}

void
dns_ht_tree_deinit(dns_ht_tree_t *tree) {
	REQUIRE(tree != NULL);

	struct cds_lfht_node *ht_node = NULL;
	struct cds_lfht_iter iter;
	cds_lfht_for_each(tree->ht, &iter, ht_node) {
		INSIST(cds_lfht_del(tree->ht, ht_node) == 0);
		tree->methods->detach(tree->uctx, ht_node);
	}
	RUNTIME_CHECK(cds_lfht_destroy(tree->ht, NULL) == 0);
}

isc_result_t
dns_ht_tree_getname(dns_ht_tree_t *tree, const dns_name_t *name,
		    dns_htnode_t **htnodep) {
	REQUIRE(tree != NULL);
	REQUIRE(htnodep != NULL && *htnodep == NULL);

	ht_key_t key = { .tree = tree, .name = name };
	struct cds_lfht_iter iter;

	cds_lfht_lookup(tree->ht, ht_hash(name), ht_match, &key, &iter);
	struct cds_lfht_node *ht_node = cds_lfht_iter_get_node(&iter);
	if (ht_node == NULL) {
		return ISC_R_NOTFOUND;
	}

	*htnodep = ht_node;
	return ISC_R_SUCCESS;
}

isc_result_t
dns_ht_tree_insert(dns_ht_tree_t *tree, dns_htnode_t *htnode,
		   dns_htnode_t **existingp) {
	REQUIRE(tree != NULL);
	REQUIRE(htnode != NULL);

	ht_key_t key = {
		.tree = tree,
		.name = tree->methods->name(tree->uctx, htnode),
	};

	cds_lfht_node_init(htnode);

	struct cds_lfht_node *ht_node = cds_lfht_add_unique(
		tree->ht, ht_hash(key.name), ht_match, &key, htnode);
	if (ht_node != htnode) {
		SET_IF_NOT_NULL(existingp, ht_node);
		return ISC_R_EXISTS;
	}

	return ISC_R_SUCCESS;
}

isc_result_t
dns_ht_tree_delete(dns_ht_tree_t *tree, dns_htnode_t *htnode) {
	REQUIRE(tree != NULL);
	REQUIRE(htnode != NULL);

	if (cds_lfht_del(tree->ht, htnode) != 0) {
		return ISC_R_NOTFOUND;
	}

	return ISC_R_SUCCESS;
}

bool
dns_ht_tree_isdeleted(dns_htnode_t *htnode) {
	REQUIRE(htnode != NULL);

	return cds_lfht_is_node_deleted(htnode);
}

size_t
dns_ht_tree_count(dns_ht_tree_t *tree) {
	long split_before, split_after;
	unsigned long count;

	REQUIRE(tree != NULL);

	cds_lfht_count_nodes(tree->ht, &split_before, &count, &split_after);

	return (size_t)count;
}
