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

#include <isc/mem.h>
#include <isc/util.h>

#include <dns/qp.h>

#include "ht_tree_p.h"

void
dns_ht_tree_create(isc_mem_t *mctx, const dns_qpmethods_t *methods,
		   void *uctx, dns_ht_tree_t **treep) {
	dns_ht_tree_t *tree = NULL;

	REQUIRE(treep != NULL && *treep == NULL);

	tree = isc_mem_get(mctx, sizeof(*tree));
	*tree = (dns_ht_tree_t){ 0 };

	isc_mem_attach(mctx, &tree->mctx);
	dns_qp_create(mctx, methods, uctx, &tree->qp);

	*treep = tree;
}

void
dns_ht_tree_destroy(dns_ht_tree_t **treep) {
	dns_ht_tree_t *tree = NULL;
	isc_mem_t *mctx = NULL;

	REQUIRE(treep != NULL && *treep != NULL);

	tree = *treep;
	*treep = NULL;

	dns_qp_destroy(&tree->qp);

	mctx = tree->mctx;
	isc_mem_put(mctx, tree, sizeof(*tree));
	isc_mem_detach(&mctx);
}

isc_result_t
dns_ht_tree_getname(dns_ht_tree_t *tree, const dns_name_t *name,
		    dns_namespace_t space, void **pval_r, uint32_t *ival_r) {
	REQUIRE(tree != NULL);

	return dns_qp_getname(tree->qp, name, space, pval_r, ival_r);
}

isc_result_t
dns_ht_tree_lookup(dns_ht_tree_t *tree, const dns_name_t *name,
		   dns_namespace_t space, dns_qpiter_t *iter,
		   dns_qpchain_t *chain, void **pval_r, uint32_t *ival_r) {
	REQUIRE(tree != NULL);

	return dns_qp_lookup(tree->qp, name, space, iter, chain, pval_r,
			     ival_r);
}

isc_result_t
dns_ht_tree_insert(dns_ht_tree_t *tree, void *pval, uint32_t ival) {
	REQUIRE(tree != NULL);

	return dns_qp_insert(tree->qp, pval, ival);
}

isc_result_t
dns_ht_tree_deletename(dns_ht_tree_t *tree, const dns_name_t *name,
		       dns_namespace_t space, void **pval_r,
		       uint32_t *ival_r) {
	REQUIRE(tree != NULL);

	return dns_qp_deletename(tree->qp, name, space, pval_r, ival_r);
}

dns_qp_memusage_t
dns_ht_tree_memusage(dns_ht_tree_t *tree) {
	REQUIRE(tree != NULL);

	return dns_qp_memusage(tree->qp);
}

void
dns_ht_tree_iter_init(dns_ht_tree_t *tree, dns_qpiter_t *iter) {
	REQUIRE(tree != NULL);

	dns_qpiter_init(tree->qp, iter);
}
