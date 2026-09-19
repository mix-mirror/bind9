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
#include <isc/mem.h>
#include <isc/urcu.h>
#include <isc/util.h>

#include <dns/name.h>

#include "ht_tree_p.h"

/* Must be powers of 2. */
#define DNS_HT_TREE_INIT_SIZE (1 << 16)
#define DNS_HT_TREE_MIN_SIZE  (1 << 10)

typedef struct dns_ht_tree_entry {
	struct cds_lfht_node ht_node;
	struct rcu_head	     rcu_head;
	dns_ht_tree_t	    *tree;
	void		    *pval;
	uint32_t	     ival;
} dns_ht_tree_entry_t;

static uint32_t
ht_hash(const dns_name_t *name) {
	return isc_hash32(name->ndata, name->length, false);
}

static int
ht_match(struct cds_lfht_node *ht_node, const void *key) {
	const dns_name_t *name = key;
	dns_ht_tree_entry_t *entry =
		caa_container_of(ht_node, dns_ht_tree_entry_t, ht_node);
	const dns_name_t *entry_name = entry->tree->methods->name(
		entry->tree->uctx, entry->pval, entry->ival);

	return dns_name_equal(entry_name, name);
}

static void
entry_destroy(struct rcu_head *rcu_head) {
	dns_ht_tree_entry_t *entry =
		caa_container_of(rcu_head, dns_ht_tree_entry_t, rcu_head);
	dns_ht_tree_t *tree = entry->tree;

	tree->methods->detach(tree->uctx, entry->pval, entry->ival);
	isc_mem_put(tree->mctx, entry, sizeof(*entry));
}

void
dns_ht_tree_init(isc_mem_t *mctx, const dns_htmethods_t *methods, void *uctx,
		 dns_ht_tree_t *tree) {
	REQUIRE(tree != NULL);
	REQUIRE(methods != NULL);
	REQUIRE(methods->attach != NULL);
	REQUIRE(methods->detach != NULL);
	REQUIRE(methods->name != NULL);

	*tree = (dns_ht_tree_t){
		.methods = methods,
		.uctx = uctx,
	};
	isc_mem_attach(mctx, &tree->mctx);

	tree->ht = cds_lfht_new(DNS_HT_TREE_INIT_SIZE, DNS_HT_TREE_MIN_SIZE, 0,
				CDS_LFHT_AUTO_RESIZE | CDS_LFHT_ACCOUNTING,
				NULL);
	INSIST(tree->ht != NULL);
}

void
dns_ht_tree_deinit(dns_ht_tree_t *tree) {
	REQUIRE(tree != NULL);

	dns_ht_tree_entry_t *entry = NULL;
	struct cds_lfht_iter iter;
	cds_lfht_for_each_entry(tree->ht, &iter, entry, ht_node) {
		INSIST(cds_lfht_del(tree->ht, &entry->ht_node) == 0);
		entry_destroy(&entry->rcu_head);
	}
	RUNTIME_CHECK(cds_lfht_destroy(tree->ht, NULL) == 0);

	isc_mem_detach(&tree->mctx);
}

isc_result_t
dns_ht_tree_getname(dns_ht_tree_t *tree, const dns_name_t *name,
		    void **pval_r, uint32_t *ival_r) {
	REQUIRE(tree != NULL);

	uint32_t hashval = ht_hash(name);
	struct cds_lfht_iter iter;

	cds_lfht_lookup(tree->ht, hashval, ht_match, name, &iter);
	struct cds_lfht_node *ht_node = cds_lfht_iter_get_node(&iter);
	if (ht_node == NULL) {
		return ISC_R_NOTFOUND;
	}

	dns_ht_tree_entry_t *entry =
		caa_container_of(ht_node, dns_ht_tree_entry_t, ht_node);
	SET_IF_NOT_NULL(pval_r, entry->pval);
	SET_IF_NOT_NULL(ival_r, entry->ival);
	return ISC_R_SUCCESS;
}

isc_result_t
dns_ht_tree_insert(dns_ht_tree_t *tree, void *pval, uint32_t ival,
		   void **pval_r, uint32_t *ival_r) {
	REQUIRE(tree != NULL);
	REQUIRE(pval != NULL);

	const dns_name_t *name = tree->methods->name(tree->uctx, pval, ival);
	uint32_t hashval = ht_hash(name);

	dns_ht_tree_entry_t *entry = isc_mem_get(tree->mctx, sizeof(*entry));
	*entry = (dns_ht_tree_entry_t){
		.tree = tree,
		.pval = pval,
		.ival = ival,
	};
	cds_lfht_node_init(&entry->ht_node);

	tree->methods->attach(tree->uctx, pval, ival);

	struct cds_lfht_node *ht_node = cds_lfht_add_unique(
		tree->ht, hashval, ht_match, name, &entry->ht_node);

	if (ht_node != &entry->ht_node) {
		tree->methods->detach(tree->uctx, pval, ival);
		isc_mem_put(tree->mctx, entry, sizeof(*entry));

		dns_ht_tree_entry_t *existing = caa_container_of(
			ht_node, dns_ht_tree_entry_t, ht_node);
		SET_IF_NOT_NULL(pval_r, existing->pval);
		SET_IF_NOT_NULL(ival_r, existing->ival);
		return ISC_R_EXISTS;
	}

	return ISC_R_SUCCESS;
}

isc_result_t
dns_ht_tree_deletename(dns_ht_tree_t *tree, const dns_name_t *name,
		       void **pval_r, uint32_t *ival_r) {
	REQUIRE(tree != NULL);

	uint32_t hashval = ht_hash(name);
	struct cds_lfht_iter iter;

	cds_lfht_lookup(tree->ht, hashval, ht_match, name, &iter);
	struct cds_lfht_node *ht_node = cds_lfht_iter_get_node(&iter);
	if (ht_node == NULL) {
		return ISC_R_NOTFOUND;
	}
	if (cds_lfht_del(tree->ht, ht_node) != 0) {
		/* Lost a race with a concurrent deletion of this entry. */
		return ISC_R_NOTFOUND;
	}

	dns_ht_tree_entry_t *entry =
		caa_container_of(ht_node, dns_ht_tree_entry_t, ht_node);
	SET_IF_NOT_NULL(pval_r, entry->pval);
	SET_IF_NOT_NULL(ival_r, entry->ival);
	call_rcu(&entry->rcu_head, entry_destroy);
	return ISC_R_SUCCESS;
}

size_t
dns_ht_tree_count(dns_ht_tree_t *tree) {
	long split_before, split_after;
	unsigned long count;

	REQUIRE(tree != NULL);

	cds_lfht_count_nodes(tree->ht, &split_before, &count, &split_after);

	return (size_t)count;
}
