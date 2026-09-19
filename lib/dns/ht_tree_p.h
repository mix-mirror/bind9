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
 *
 * A dns_ht_tree only ever holds DNS_DBNAMESPACE_NORMAL keys, so unlike
 * the dns_qp_* functions it wraps, it does not take a dns_namespace_t
 * argument - it's always NORMAL.
 *
 * There is currently no iterator support (no dns_qpiter_t equivalent):
 * qpcache's cache-iteration support (used by rndc dumpdb/flushtree) is
 * disabled for now, so nothing needs it. It will need to be added back
 * here when that support returns.
 */

typedef struct dns_ht_tree dns_ht_tree_t;

struct dns_ht_tree {
	isc_mem_t *mctx;
	dns_qp_t  *qp;
};

void
dns_ht_tree_init(isc_mem_t *mctx, const dns_qpmethods_t *methods, void *uctx,
		 dns_ht_tree_t *tree);
/*%<
 * Initialize 'tree', wrapping a freshly created dns_qp_t. The caller
 * owns the storage for 'tree' (typically embedded in another struct).
 *
 * Requires:
 * \li	'tree != NULL'
 */

void
dns_ht_tree_deinit(dns_ht_tree_t *tree);
/*%<
 * Release the resources owned by 'tree', which must have been
 * initialized by dns_ht_tree_init(). Does not free 'tree' itself.
 *
 * Requires:
 * \li	'tree != NULL'
 */

isc_result_t
dns_ht_tree_getname(dns_ht_tree_t *tree, const dns_name_t *name,
		    void **pval_r, uint32_t *ival_r);
/*%<
 * Equivalent to dns_qp_getname(), applied to 'tree' in the
 * DNS_DBNAMESPACE_NORMAL namespace.
 */

isc_result_t
dns_ht_tree_lookup(dns_ht_tree_t *tree, const dns_name_t *name,
		   void **pval_r, uint32_t *ival_r);
/*%<
 * Equivalent to dns_qp_lookup(), applied to 'tree' in the
 * DNS_DBNAMESPACE_NORMAL namespace, without iterator or chain support.
 */

isc_result_t
dns_ht_tree_insert(dns_ht_tree_t *tree, void *pval, uint32_t ival);
/*%<
 * Equivalent to dns_qp_insert(), applied to 'tree'.
 */

isc_result_t
dns_ht_tree_deletename(dns_ht_tree_t *tree, const dns_name_t *name,
		       void **pval_r, uint32_t *ival_r);
/*%<
 * Equivalent to dns_qp_deletename(), applied to 'tree' in the
 * DNS_DBNAMESPACE_NORMAL namespace.
 */

dns_qp_memusage_t
dns_ht_tree_memusage(dns_ht_tree_t *tree);
/*%<
 * Equivalent to dns_qp_memusage(), applied to 'tree'.
 */
