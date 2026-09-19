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

#include <isc/urcu.h>

#include <dns/name.h>
#include <dns/types.h>

/*! \file
 * \brief
 * `dns_ht_tree` is a lock-free hashmap (userspace-rcu's `cds_lfht`),
 * used for the NAMESPACE_NORMAL half of the qpcache tree. Exact-match
 * only: no partial-match/closest-encloser, no ordered iteration.
 *
 * Values are not stored directly in the table: each cds_lfht_node is
 * embedded in a dns_ht_tree_entry_t allocated by dns_ht_tree_insert(),
 * which holds a reference to the caller's value. That keeps the
 * hashmap's own RCU-deferred bookkeeping separate from the value's
 * lifetime.
 *
 * dns_ht_tree_getname/insert/deletename/count require the caller to
 * already hold the RCU read-side lock (rcu_read_lock()), same as
 * cds_lfht itself does. A value returned by dns_ht_tree_getname() is
 * only safe to dereference while still inside that same read-side
 * section, or after the caller has otherwise made it safe to use (e.g.
 * by acquiring its own reference) - once the section ends, nothing
 * stops the entry (and the reference it holds) from being reclaimed.
 */

typedef struct dns_ht_tree dns_ht_tree_t;

typedef struct dns_htmethods {
	void (*attach)(void *uctx, void *pval, uint32_t ival);
	void (*detach)(void *uctx, void *pval, uint32_t ival);
	const dns_name_t *(*name)(void *uctx, void *pval, uint32_t ival);
} dns_htmethods_t;

struct dns_ht_tree {
	isc_mem_t		 *mctx;
	const dns_htmethods_t	 *methods;
	void			 *uctx;
	struct cds_lfht		 *ht;
};

void
dns_ht_tree_init(isc_mem_t *mctx, const dns_htmethods_t *methods, void *uctx,
		 dns_ht_tree_t *tree);
/*%<
 * Initialize 'tree'. The caller owns the storage for 'tree' (typically
 * embedded in another struct).
 *
 * Requires:
 * \li	'tree != NULL'
 * \li	'methods->attach', 'methods->detach' and 'methods->name' are
 *	all non-NULL
 */

void
dns_ht_tree_deinit(dns_ht_tree_t *tree);
/*%<
 * Release the resources owned by 'tree', which must have been
 * initialized by dns_ht_tree_init(). Does not free 'tree' itself.
 *
 * There must be no concurrent access to 'tree' when this is called:
 * remaining entries are torn down immediately (not via an RCU grace
 * period), exactly as if each had been individually deleted then
 * the caller had waited for a grace period to elapse.
 *
 * Requires:
 * \li	'tree != NULL'
 */

isc_result_t
dns_ht_tree_getname(dns_ht_tree_t *tree, const dns_name_t *name,
		    void **pval_r, uint32_t *ival_r);
/*%<
 * Find the entry in 'tree' whose name is equal (case-insensitively)
 * to 'name'.
 *
 * The value is assigned to whichever of `*pval_r` and `*ival_r` are
 * not NULL, unless the return value is ISC_R_NOTFOUND.
 *
 * Requires:
 * \li	'tree != NULL'
 * \li	'name' is a pointer to a valid `dns_name_t`
 *
 * Returns:
 * \li	ISC_R_NOTFOUND if no entry with a matching name exists
 * \li	ISC_R_SUCCESS if the entry was found
 */

isc_result_t
dns_ht_tree_insert(dns_ht_tree_t *tree, void *pval, uint32_t ival,
		   void **pval_r, uint32_t *ival_r);
/*%<
 * Insert an entry into 'tree', keyed by the name that
 * methods->name(uctx, pval, ival) returns.
 *
 * If an entry with the same name already exists, 'pval'/'ival' are
 * not inserted, and the existing entry's value is assigned to
 * whichever of `*pval_r` and `*ival_r` are not NULL.
 *
 * Requires:
 * \li	'tree != NULL'
 * \li	'pval != NULL'
 *
 * Returns:
 * \li	ISC_R_EXISTS if the tree already has an entry with the same name
 * \li	ISC_R_SUCCESS if the entry was added to the tree
 */

isc_result_t
dns_ht_tree_deletename(dns_ht_tree_t *tree, const dns_name_t *name,
		       void **pval_r, uint32_t *ival_r);
/*%<
 * Delete the entry in 'tree' whose name is equal (case-insensitively)
 * to 'name'.
 *
 * The value is assigned to whichever of `*pval_r` and `*ival_r` are
 * not NULL, unless the return value is ISC_R_NOTFOUND.
 *
 * Requires:
 * \li	'tree != NULL'
 * \li	'name' is a pointer to a valid `dns_name_t`
 *
 * Returns:
 * \li	ISC_R_NOTFOUND if no entry with a matching name exists
 * \li	ISC_R_SUCCESS if the entry was deleted from the tree
 */

size_t
dns_ht_tree_count(dns_ht_tree_t *tree);
/*%<
 * Return the (approximate) number of entries in 'tree'.
 *
 * Requires:
 * \li	'tree != NULL'
 */
