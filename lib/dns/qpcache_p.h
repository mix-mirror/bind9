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

#include <isc/atomic.h>
#include <isc/os.h>
#include <isc/queue.h>
#include <isc/refcount.h>
#include <isc/rwlock.h>
#include <isc/sieve.h>
#include <isc/urcu.h>

#include <dns/db.h>
#include <dns/nsec3.h>
#include <dns/qp.h>
#include <dns/rdataslab.h>
#include <dns/types.h>

/*****
***** Module Info
*****/

/*! \file
 * \brief
 * DNS QPDB Implementation (minimally adapted from RBTDB)
 */

isc_result_t
dns__qpcache_create(isc_mem_t *mctx, const dns_name_t *base, dns_dbtype_t type,
		    dns_rdataclass_t rdclass, unsigned int argc, char *argv[],
		    void *driverarg, dns_db_t **dbp);
/*%<
 * Create a new database of type "qpcache". Called via dns_db_create();
 * see documentation for that function for more details.
 *
 * Requires:
 *
 * \li argc == 0 and argv == NULL.
 */

/*%
 * Forward declarations
 */
typedef struct qpcache qpcache_t;

/*%
 * This is the structure that is used for each node in the qp trie of
 * trees.
 */
typedef struct qpcnode qpcnode_t;
struct qpcnode {
	DBNODE_FIELDS;

	qpcache_t *qpdb;

	uint8_t		      : 0;
	unsigned int nspace   : 2; /*%< range is 0..3 */
	unsigned int havensec : 1;
	uint8_t		      : 0;

	/*
	 * 'erefs' counts external references held by a caller: for
	 * example, it could be incremented by dns_db_findnode(),
	 * and decremented by dns_db_detachnode().
	 *
	 * 'references' counts internal references to the node object,
	 * including the one held by the QP trie so the node won't be
	 * deleted while it's quiescently stored in the database - even
	 * though 'erefs' may be zero because no external caller is
	 * using it at the time.
	 *
	 * Generally when 'erefs' is incremented or decremented,
	 * 'references' is too. When both go to zero (meaning callers
	 * and the database have both released the object) the object
	 * is freed.
	 *
	 * Whenever 'erefs' is incremented from zero, we also acquire a
	 * node use reference (see 'qpcache->references' below), and
	 * release it when 'erefs' goes back to zero. This prevents the
	 * database from being shut down until every caller has released
	 * all nodes.
	 */
	isc_refcount_t references;
	isc_refcount_t erefs;

	struct cds_list_head headers;

	/*%
	 * Used for dead nodes cleaning.  This linked list is used to mark nodes
	 * which have no data any longer, but we cannot unlink at that exact
	 * moment because we did not or could not obtain a write lock on the
	 * tree.
	 */
	isc_queue_node_t deadlink;
};

/*%
 * One bucket structure will be created for each loop, and
 * nodes in the database will evenly distributed among buckets
 * to reduce contention between threads.
 */
typedef struct qpcache_bucket {
	union {
		struct {
			/*%
			 * Temporary storage for stale cache nodes and
			 * dynamically deleted nodes that await being cleaned
			 * up.
			 */
			isc_queue_t deadnodes;

			/* Per-bucket lock. */
			isc_rwlock_t lock;

			/* SIEVE-LRU cache cleaning state. */
			ISC_SIEVE(dns_slabheader_t) sieve;
		};
		uint8_t __padding[ISC_OS_CACHELINE_SIZE];
	};
} qpcache_bucket_t;

struct qpcache {
	/* Unlocked. */
	dns_db_t common;
	/* Locks the data in this struct */
	isc_rwlock_t lock;
	/* Locks the tree structure (prevents nodes appearing/disappearing) */
	isc_rwlock_t tree_lock;

	/*
	 * NOTE: 'references' is NOT the global reference counter for
	 * the database object handled by dns_db_attach() and _detach();
	 * that one is 'common.references'.
	 *
	 * Instead, 'references' counts the number of nodes being used by
	 * at least one external caller. (It's called 'references' to
	 * leverage the ISC_REFCOUNT_STATIC macros, but 'nodes_in_use'
	 * might be a clearer name.)
	 *
	 * One additional reference to this counter is held by the database
	 * object itself. When 'common.references' goes to zero, that
	 * reference is released. When in turn 'references' goes to zero,
	 * the database is shut down and freed.
	 */
	isc_refcount_t references;

	dns_stats_t *rrsetstats;
	isc_stats_t *cachestats;

	uint32_t maxrrperset;	 /* Maximum RRs per RRset */
	uint32_t maxtypepername; /* Maximum number of RR types per owner */

	/*
	 * The time after a failed lookup, where stale answers from cache
	 * may be used directly in a DNS response without attempting a
	 * new iterative lookup.
	 */
	uint32_t serve_stale_refresh;

	/* Locked by tree_lock. */
	dns_qp_t *tree;

	isc_mem_t *hmctx; /* Memory context for the database structure. */

	struct {
		atomic_size_t size;
		atomic_size_t hiwater;
		atomic_size_t lowater;
		atomic_size_t inuse;
	} overmem;

	size_t buckets_count;
	qpcache_bucket_t buckets[]; /* attribute((counted_by(buckets_count))) */
};

typedef struct qpc_dbit qpc_dbit_t;

void
dns__qpcache_setcachesize(qpcache_t *qpdb, size_t size);

size_t
dns__qpcache_getcachesize(qpcache_t *qpdb);

size_t
dns__qpcache_getinuse(qpcache_t *qpdb);

unsigned int
dns__qpcache_nodecount(qpcache_t *qpdb);

/* These references share common.references with external dns_db users. */
void
dns__qpcache_attach(qpcache_t *source, qpcache_t **targetp);

void
dns__qpcache_detach(qpcache_t **dbp);

isc_result_t
dns__qpcache_findnode(qpcache_t *db, const dns_name_t *name, bool create,
		      qpcnode_t **nodep);

void
dns__qpcnode_detach(qpcnode_t **nodep);

void
dns__qpcache_createiterator(qpcache_t *db, qpc_dbit_t **iterp);

void
dns__qpc_dbit_destroy(qpc_dbit_t **iterp);

isc_result_t
dns__qpc_dbit_seek(qpc_dbit_t *iter, const dns_name_t *name);

isc_result_t
dns__qpc_dbit_next(qpc_dbit_t *iter);

isc_result_t
dns__qpc_dbit_current(qpc_dbit_t *iter, qpcnode_t **nodep);

void
dns__qpcache_new(isc_mem_t *mctx, const dns_name_t *origin,
		 dns_rdataclass_t rdclass, qpcache_t **dbp);

/* Caller holds the node's bucket write lock. */
size_t
dns__qpcache_header_delete(qpcnode_t *node, dns_slabheader_t *header);
