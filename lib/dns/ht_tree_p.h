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
 * The hashmap is intrusive: each value embeds a `dns_htnode_t`, and the
 * methods map that back to the value's name. Inserting a node transfers
 * one reference held by the caller to the tree; dns_ht_tree_delete()
 * unlinks the node and hands that reference back. Concurrent readers
 * may still be looking at an unlinked node, so the caller must not
 * release the returned reference until an RCU grace period has elapsed
 * (e.g. by releasing it from a call_rcu() callback).
 *
 * dns_ht_tree_getname/insert/delete require the caller to
 * already hold the RCU read-side lock (rcu_read_lock()), same as
 * cds_lfht itself does. A node returned by dns_ht_tree_getname() is
 * only safe to dereference while still inside that same read-side
 * section, or after the caller has otherwise made it safe to use (e.g.
 * by acquiring its own reference). A reference acquired that way must
 * be checked against dns_ht_tree_isdeleted() under whatever lock
 * serializes the deletion, as the node may have been unlinked between
 * the lookup and the acquisition.
 */

typedef struct dns_ht_tree dns_ht_tree_t;
typedef struct cds_lfht_node dns_htnode_t;

typedef struct dns_htmethods {
	void (*detach)(void *uctx, dns_htnode_t *htnode);
	const dns_name_t *(*name)(void *uctx, dns_htnode_t *htnode);
} dns_htmethods_t;

struct dns_ht_tree {
	const dns_htmethods_t *methods;
	void *uctx;
	struct cds_lfht *ht;
};

void
dns_ht_tree_init(const dns_htmethods_t *methods, void *uctx,
		 dns_ht_tree_t *tree);
/*%<
 * Initialize 'tree'. The caller owns the storage for 'tree' (typically
 * embedded in another struct).
 *
 * Requires:
 * \li	'tree != NULL'
 * \li	'methods->detach' and 'methods->name' are both non-NULL
 */

void
dns_ht_tree_deinit(dns_ht_tree_t *tree);
/*%<
 * Release the resources owned by 'tree', which must have been
 * initialized by dns_ht_tree_init(). Does not free 'tree' itself.
 *
 * There must be no concurrent access to 'tree' when this is called:
 * the reference held by the tree on each remaining node is released
 * immediately with methods->detach (not via an RCU grace period).
 *
 * Requires:
 * \li	'tree != NULL'
 */

isc_result_t
dns_ht_tree_getname(dns_ht_tree_t *tree, const dns_name_t *name,
		    dns_htnode_t **htnodep);
/*%<
 * Find the node in 'tree' whose name is equal (case-insensitively)
 * to 'name'.
 *
 * The node is assigned to `*htnodep`, unless the return value is
 * ISC_R_NOTFOUND.
 *
 * Requires:
 * \li	'tree != NULL'
 * \li	'name' is a pointer to a valid `dns_name_t`
 * \li	'htnodep != NULL && *htnodep == NULL'
 *
 * Returns:
 * \li	ISC_R_NOTFOUND if no node with a matching name exists
 * \li	ISC_R_SUCCESS if the node was found
 */

isc_result_t
dns_ht_tree_insert(dns_ht_tree_t *tree, dns_htnode_t *htnode,
		   dns_htnode_t **existingp);
/*%<
 * Insert 'htnode' into 'tree', keyed by the name that
 * methods->name(uctx, htnode) returns. On success, the tree takes over
 * one reference to the node from the caller.
 *
 * If a node with the same name already exists, 'htnode' is not
 * inserted, the caller keeps its reference, and the existing node is
 * assigned to `*existingp` if 'existingp' is not NULL.
 *
 * Requires:
 * \li	'tree != NULL'
 * \li	'htnode != NULL'
 *
 * Returns:
 * \li	ISC_R_EXISTS if the tree already has a node with the same name
 * \li	ISC_R_SUCCESS if the node was added to the tree
 */

isc_result_t
dns_ht_tree_delete(dns_ht_tree_t *tree, dns_htnode_t *htnode);
/*%<
 * Unlink 'htnode' from 'tree'. On success, the reference the tree held
 * on the node is handed back to the caller, who must not release it
 * before an RCU grace period has elapsed.
 *
 * Requires:
 * \li	'tree != NULL'
 * \li	'htnode != NULL'
 *
 * Returns:
 * \li	ISC_R_NOTFOUND if the node had already been deleted
 * \li	ISC_R_SUCCESS if the node was deleted from the tree
 */

bool
dns_ht_tree_isdeleted(dns_htnode_t *htnode);
/*%<
 * Return true if 'htnode' has been unlinked by dns_ht_tree_delete().
 *
 * Requires:
 * \li	'htnode != NULL'
 */
