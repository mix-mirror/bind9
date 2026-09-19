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

#pragma once

#include <dns/qp.h>
#include <dns/types.h>

/*! \file
 * \brief
 * `dns_ht_tree` is a thin wrapper around `dns_qp_t`, used for the
 * NAMESPACE_NORMAL half of the qpcache tree. It exists so that the
 * qp-trie backing NAMESPACE_NORMAL can later be swapped out for a
 * hashmap-based implementation without touching qpcache.c again -
 * for now, every operation is a straight passthrough to the
 * corresponding dns_qp_* function.
 */

typedef struct dns_ht_tree dns_ht_tree_t;

struct dns_ht_tree {
	isc_mem_t *mctx;
	dns_qp_t  *qp;
};

void
dns_ht_tree_create(isc_mem_t *mctx, const dns_qpmethods_t *methods,
		   void *uctx, dns_ht_tree_t **treep);
/*%<
 * Create a new dns_ht_tree, wrapping a freshly created dns_qp_t.
 *
 * Requires:
 * \li	'treep != NULL && *treep == NULL'
 */

void
dns_ht_tree_destroy(dns_ht_tree_t **treep);
/*%<
 * Destroy a dns_ht_tree created by dns_ht_tree_create(), and set
 * '*treep' to NULL.
 *
 * Requires:
 * \li	'treep != NULL && *treep != NULL'
 */

isc_result_t
dns_ht_tree_getname(dns_ht_tree_t *tree, const dns_name_t *name,
		    dns_namespace_t space, void **pval_r, uint32_t *ival_r);
/*%<
 * Equivalent to dns_qp_getname(), applied to 'tree'.
 */

isc_result_t
dns_ht_tree_lookup(dns_ht_tree_t *tree, const dns_name_t *name,
		   dns_namespace_t space, dns_qpiter_t *iter,
		   dns_qpchain_t *chain, void **pval_r, uint32_t *ival_r);
/*%<
 * Equivalent to dns_qp_lookup(), applied to 'tree'.
 */

isc_result_t
dns_ht_tree_insert(dns_ht_tree_t *tree, void *pval, uint32_t ival);
/*%<
 * Equivalent to dns_qp_insert(), applied to 'tree'.
 */

isc_result_t
dns_ht_tree_deletename(dns_ht_tree_t *tree, const dns_name_t *name,
		       dns_namespace_t space, void **pval_r,
		       uint32_t *ival_r);
/*%<
 * Equivalent to dns_qp_deletename(), applied to 'tree'.
 */

dns_qp_memusage_t
dns_ht_tree_memusage(dns_ht_tree_t *tree);
/*%<
 * Equivalent to dns_qp_memusage(), applied to 'tree'.
 */

void
dns_ht_tree_iter_init(dns_ht_tree_t *tree, dns_qpiter_t *iter);
/*%<
 * Equivalent to dns_qpiter_init(), applied to 'tree'.
 */
