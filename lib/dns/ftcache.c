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

#include <inttypes.h>
#include <stdalign.h>
#include <stdbool.h>

#include <isc/ascii.h>
#include <isc/async.h>
#include <isc/atomic.h>
#include <isc/file.h>
#include <isc/hex.h>
#include <isc/list.h>
#include <isc/log.h>
#include <isc/loop.h>
#include <isc/mem.h>
#include <isc/mutex.h>
#include <isc/os.h>
#include <isc/queue.h>
#include <isc/random.h>
#include <isc/refcount.h>
#include <isc/result.h>
#include <isc/rwlock.h>
#include <isc/sieve.h>
#include <isc/stdio.h>
#include <isc/string.h>
#include <isc/time.h>
#include <isc/urcu.h>
#include <isc/util.h>

#include <dns/callbacks.h>
#include <dns/db.h>
#include <dns/dbiterator.h>
#include <dns/fixedname.h>
#include <dns/masterdump.h>
#include <dns/nsec.h>
#include <dns/qp.h>
#include <dns/rdata.h>
#include <dns/rdataset.h>
#include <dns/rdatasetiter.h>
#include <dns/rdataslab.h>
#include <dns/rdatastruct.h>
#include <dns/rdatatype.h>
#include <dns/stats.h>
#include <dns/time.h>
#include <dns/types.h>
#include <dns/view.h>

#include "db_p.h"
#include "ftcache_p.h"
#include "rdataslab_p.h"

/* after the RCU flavor is set up via <isc/urcu.h> in ftcache_p.h */
#include <urcu/fractal-trie.h>

#ifndef DNS_FTCACHE_LOG_STATS_LEVEL
#define DNS_FTCACHE_LOG_STATS_LEVEL 3
#endif

#define STALE_TTL(header, ftdb) \
	(NXDOMAIN(header) ? 0 : ftdb->common.serve_stale_ttl)

#define ACTIVE(header, now)            \
	(((header)->expire > (now)) || \
	 ((header)->expire == (now) && ZEROTTL(header)))

#define EXPIREDOK(iterator) \
	(((iterator)->common.options & DNS_DB_EXPIREDOK) != 0)

#define STALEOK(iterator) (((iterator)->common.options & DNS_DB_STALEOK) != 0)

#define KEEPSTALE(ftdb) ((ftdb)->common.serve_stale_ttl > 0)

/*%
 * Note that "impmagic" is not the first four bytes of the struct, so
 * ISC_MAGIC_VALID cannot be used.
 */
#define FTDB_MAGIC ISC_MAGIC('F', 'T', 'D', '4')
#define VALID_FTDB(ftdb) \
	((ftdb) != NULL && (ftdb)->common.impmagic == FTDB_MAGIC)

#define HEADERNODE(h) ((ftcnode_t *)((h)->node))

/*%
 * Forward declarations
 */
typedef struct ftcache ftcache_t;

/*%
 * This is the structure that is used for each node in the iter trie of
 * trees.
 */
typedef struct ftcnode ftcnode_t;
struct ftcnode {
	DBNODE_FIELDS;

	ftcache_t *ftdb;

	uint8_t		      : 0;
	unsigned int nspace   : 2; /*%< range is 0..3 */
	unsigned int havensec : 1;
	bool deleted	      : 1;
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
	 * node use reference (see 'ftcache->references' below), and
	 * release it when 'erefs' goes back to zero. This prevents the
	 * database from being shut down until every caller has released
	 * all nodes.
	 */
	isc_refcount_t references;
	isc_refcount_t erefs;

	struct cds_list_head headers;

	/*%
	 * Intrusive linkage into the cds_ft trie. The trie holds one
	 * internal reference to the node; it is dropped through 'rcu_head'
	 * (call_rcu) once the node has been removed from the trie.
	 */
	struct cds_ft_node ftnode;
	struct rcu_head	   rcu_head;

	/*%
	 * Used for dead nodes cleaning.  This linked list is used to mark nodes
	 * which have no data any longer, but we cannot unlink at that exact
	 * moment because we did not or could not obtain the tree write lock.
	 */
	isc_queue_node_t deadlink;
};

/*%
 * One bucket structure will be created for each loop, and
 * nodes in the database will evenly distributed among buckets
 * to reduce contention between threads.
 */
typedef struct ftcache_bucket {
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
} ftcache_bucket_t;

struct ftcache {
	/* Unlocked. */
	dns_db_t common;
	/* Locks the data in this struct */
	isc_rwlock_t lock;

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

	/*
	 * The cds_ft trie holding the cache nodes, its enclosing group,
	 * and the single-writer mutex serialising structural mutations.
	 * Reads run lock-free under the RCU read-side lock.
	 */
	struct cds_ft_group *ftgroup;
	struct cds_ft	    *ft;
	isc_mutex_t	     wmutex;

	struct rcu_head rcu_head;

	size_t buckets_count;
	ftcache_bucket_t buckets[]; /* attribute((counted_by(buckets_count))) */
};

#ifdef DNS_DB_NODETRACE
#define ftcache_ref(ptr)   ftcache__ref(ptr, __func__, __FILE__, __LINE__)
#define ftcache_unref(ptr) ftcache__unref(ptr, __func__, __FILE__, __LINE__)
#define ftcache_attach(ptr, ptrp) \
	ftcache__attach(ptr, ptrp, __func__, __FILE__, __LINE__)
#define ftcache_detach(ptrp) ftcache__detach(ptrp, __func__, __FILE__, __LINE__)
ISC_REFCOUNT_STATIC_TRACE_DECL(ftcache);
#else
ISC_REFCOUNT_STATIC_DECL(ftcache);
#endif

/*%
 * Search Context
 */
typedef struct {
	ftcache_t *ftdb;
	unsigned int options;
	bool need_cleanup;
	ftcnode_t *zonecut;
	dns_slabheader_t *zonecut_header;
	dns_slabheader_t *zonecut_sigheader;
	isc_stdtime_t now;
} ftc_search_t;

static isc_result_t
ftc_lookup(struct cds_ft *ft, const dns_name_t *name, dns_namespace_t space,
	   ftcnode_t **nodep);

#ifdef DNS_DB_NODETRACE
#define ftcnode_ref(ptr)   ftcnode__ref(ptr, __func__, __FILE__, __LINE__)
#define ftcnode_unref(ptr) ftcnode__unref(ptr, __func__, __FILE__, __LINE__)
#define ftcnode_attach(ptr, ptrp) \
	ftcnode__attach(ptr, ptrp, __func__, __FILE__, __LINE__)
#define ftcnode_detach(ptrp) ftcnode__detach(ptrp, __func__, __FILE__, __LINE__)
ISC_REFCOUNT_STATIC_TRACE_DECL(ftcnode);
#else
ISC_REFCOUNT_STATIC_DECL(ftcnode);
#endif

/*
 * Node methods forward declarations
 */
static void
ftcnode_attachnode(dns_dbnode_t *source, dns_dbnode_t **targetp DNS__DB_FLARG);
static void
ftcnode_detachnode(dns_dbnode_t **nodep DNS__DB_FLARG);
static void
ftcnode_expiredata(dns_dbnode_t *node, void *data);

static dns_dbnode_methods_t ftcnode_methods = (dns_dbnode_methods_t){
	.attachnode = ftcnode_attachnode,
	.detachnode = ftcnode_detachnode,
	.expiredata = ftcnode_expiredata,
};

static void
rdatasetiter_destroy(dns_rdatasetiter_t **iteratorp DNS__DB_FLARG);
static isc_result_t
rdatasetiter_first(dns_rdatasetiter_t *iterator DNS__DB_FLARG);
static isc_result_t
rdatasetiter_next(dns_rdatasetiter_t *iterator DNS__DB_FLARG);
static void
rdatasetiter_current(dns_rdatasetiter_t *iterator,
		     dns_rdataset_t *rdataset DNS__DB_FLARG);

static dns_rdatasetitermethods_t rdatasetiter_methods = {
	rdatasetiter_destroy, rdatasetiter_first, rdatasetiter_next,
	rdatasetiter_current
};

typedef struct ftc_rditer {
	dns_rdatasetiter_t common;
	dns_rdataset_t *current;
	ISC_LIST(dns_rdataset_t) rdatasets;
} ftc_rditer_t;

static void
dbiterator_destroy(dns_dbiterator_t **iteratorp DNS__DB_FLARG);
static isc_result_t
dbiterator_first(dns_dbiterator_t *iterator DNS__DB_FLARG);
static isc_result_t
dbiterator_last(dns_dbiterator_t *iterator DNS__DB_FLARG);
static isc_result_t
dbiterator_seek(dns_dbiterator_t *iterator,
		const dns_name_t *name DNS__DB_FLARG);
static isc_result_t
dbiterator_seek3(dns_dbiterator_t *iterator,
		 const dns_name_t *name DNS__DB_FLARG);
static isc_result_t
dbiterator_prev(dns_dbiterator_t *iterator DNS__DB_FLARG);
static isc_result_t
dbiterator_next(dns_dbiterator_t *iterator DNS__DB_FLARG);
static isc_result_t
dbiterator_current(dns_dbiterator_t *iterator, dns_dbnode_t **nodep,
		   dns_name_t *name DNS__DB_FLARG);
static isc_result_t
dbiterator_pause(dns_dbiterator_t *iterator);
static isc_result_t
dbiterator_origin(dns_dbiterator_t *iterator, dns_name_t *name);

static dns_dbiteratormethods_t dbiterator_methods = {
	dbiterator_destroy, dbiterator_first,	dbiterator_last,
	dbiterator_seek,    dbiterator_seek3,	dbiterator_prev,
	dbiterator_next,    dbiterator_current, dbiterator_pause,
	dbiterator_origin
};

/*
 * In the cache, NSEC3 records are currently stored in the NORMAL
 * namespace.  If we ever implement synth-from-dnssec using NSEC3 records,
 * they'll need be moved into the NSEC3 namespace for efficiency, and
 * the iterator implementation will need to be more complex, as in
 * qpzone.
 */
typedef struct ftc_dbit {
	dns_dbiterator_t common;
	bool paused;
	isc_result_t result;
	dns_fixedname_t fixed;
	dns_name_t *name;
	struct cds_ft_iter *iter;
	ftcnode_t *node;
} ftc_dbit_t;

static void
ftcache__destroy(ftcache_t *ftdb);

static dns_dbmethods_t ftdb_cachemethods;

static void
cleanup_deadnodes_cb(void *arg);

/*
 * Locking
 *
 * If a routine is going to lock more than one lock in this module, then
 * the locking must be done in the following order:
 *
 *      Tree Lock
 *
 *      Node Lock       (Only one from the set may be locked at one time by
 *                       any caller)
 *
 *      Database Lock
 *
 * Failure to follow this hierarchy can result in deadlock.
 */

/*
 * Cache-eviction routines.
 */

static size_t
header_delete(ftcnode_t *node, dns_slabheader_t *header);

static size_t
rdataset_size(dns_slabheader_t *header) {
	if (EXISTS(header)) {
		return dns_rdataslab_size(header);
	}

	return sizeof(*header);
}

static void
flush_node(ftcache_t *ftdb, ftcnode_t *node, isc_rwlocktype_t *nlocktypep,
	   struct cds_ft_iter *iter, dns_expire_t reason DNS__DB_FLARG);

static size_t
expire_header(ftcache_t *ftdb, ftcnode_t *node, dns_slabheader_t *header,
	      isc_rwlocktype_t *nlocktypep, struct cds_ft_iter *iter DNS__DB_FLARG) {
	size_t expired = 0;

	if (header->related != NULL) {
		expired += header_delete(node, header->related);
	}
	expired += header_delete(node, header);

	flush_node(ftdb, node, nlocktypep, iter,
		   dns_expire_lru DNS__DB_FLARG_PASS);

	return expired;
}

static void
expire_lru_headers(ftcache_t *ftdb, dns_slabheader_t *newheader, uint32_t idx,
		   size_t requested, isc_rwlocktype_t *nlocktypep,
		   struct cds_ft_iter *iter DNS__DB_FLARG) {
	size_t expired = 0;

	do {
		dns_slabheader_t *header = ISC_SIEVE_NEXT(
			ftdb->buckets[idx].sieve, visited, lrulink);
		if (header == NULL) {
			return;
		}

		/* newheader is protected from removal */
		if (header == newheader || header->related == newheader) {
			return;
		}

		ftcnode_t *node = HEADERNODE(header);

		expired += expire_header(ftdb, node, header, nlocktypep,
					 iter DNS__DB_FLARG_PASS);

	} while (expired < requested);
}

static void
ftcache_miss(ftcache_t *ftdb, dns_slabheader_t *newheader,
	     isc_rwlocktype_t *nlocktypep, struct cds_ft_iter *iter DNS__DB_FLARG) {
	uint32_t idx = HEADERNODE(newheader)->locknum;

	if (isc_mem_isovermem(ftdb->common.mctx)) {
		/*
		 * Maximum estimated size of the data being added: The size
		 * of the rdataset, plus a new QP database node and nodename,
		 * and a possible additional NSEC node and nodename. Also add
		 * a 12k margin for a possible QP-trie chunk allocation.
		 * (It's okay to overestimate, we want to get cache memory
		 * down quickly.)
		 */

		size_t purgesize =
			2 * (sizeof(ftcnode_t) +
			     dns_name_size(&HEADERNODE(newheader)->name)) +
			rdataset_size(newheader) + QP_SAFETY_MARGIN;

		expire_lru_headers(ftdb, newheader, idx, purgesize, nlocktypep,
				   iter DNS__DB_FLARG_PASS);
	}

	ISC_SIEVE_INSERT(ftdb->buckets[idx].sieve, newheader, lrulink);
}

static void
ftcache_hit(ftcache_t *ftdb ISC_ATTR_UNUSED, dns_slabheader_t *header) {
	/*
	 * On cache hit, we only mark the header as seen.
	 */
	ISC_SIEVE_MARK(header, visited);
}

/*
 * DB Routines
 */

/*
 * Write transaction must be open.
 */
/* RCU callback: drop the trie's reference once readers have drained. */
static void
ftc_drop_tree_ref(struct rcu_head *rcu_head) {
	ftcnode_t *node = caa_container_of(rcu_head, ftcnode_t, rcu_head);
	ftcnode_detach(&node);
}

static void
delete_node(ftcache_t *ftdb, struct cds_ft_iter *iter, ftcnode_t *node) {
	INSIST(!node->deleted);
	node->deleted = true;

	if (isc_log_wouldlog(ISC_LOG_DEBUG(DNS_FTCACHE_LOG_STATS_LEVEL))) {
		char printname[DNS_NAME_FORMATSIZE];
		dns_name_format(&node->name, printname, sizeof(printname));
		isc_log_write(DNS_LOGCATEGORY_DATABASE, DNS_LOGMODULE_CACHE,
			      ISC_LOG_DEBUG(DNS_FTCACHE_LOG_STATS_LEVEL),
			      "delete_node(): %p %s (bucket %d)", node,
			      printname, node->locknum);
	}

	/*
	 * TODO: a havensec NORMAL node also has an NSEC auxiliary node; for
	 * now that node is reclaimed independently on its own eviction
	 * rather than being co-deleted here.
	 */
	RUNTIME_CHECK(cds_ft_remove(ftdb->ft, iter, &node->ftnode) ==
		      CDS_FT_STATUS_OK);

	call_rcu(&node->rcu_head, ftc_drop_tree_ref);
}

/*
 * The caller must specify its currect node and tree lock status.
 * It's okay for neither lock to be held if there are existing external
 * references to the node, but if this is the first external reference,
 * then the caller must be holding at least one lock.
 *
 * If incrementing erefs from zero, we also increment the node use counter
 * in the ftcache object.
 *
 * This function is called from ftcnode_acquire(), so that internal
 * and external references are acquired at the same time, and from
 * ftcnode_release() when we only need to increase the internal references.
 */
static void
ftcnode_erefs_increment(ftcache_t *ftdb, ftcnode_t *node,
			isc_rwlocktype_t nlocktype DNS__DB_FLARG) {
	uint_fast32_t refs = isc_refcount_increment0(&node->erefs);

#if DNS_DB_NODETRACE
	fprintf(stderr, "incr:node:%s:%s:%u:%p->erefs = %" PRIuFAST32 "\n",
		func, file, line, node, refs + 1);
#endif

	if (refs > 0) {
		return;
	}

	/*
	 * this is the first external reference to the node.
	 *
	 * we need to hold the node to avoid incrementing the reference count
	 * while also deleting the node. delete_node() is always protected by
	 * both tree and node locks being write-locked.
	 */
	INSIST(nlocktype != isc_rwlocktype_none);

	ftcache_ref(ftdb);
}

static void
ftcnode_acquire(ftcache_t *ftdb, ftcnode_t *node,
		isc_rwlocktype_t nlocktype DNS__DB_FLARG) {
	ftcnode_ref(node);
	ftcnode_erefs_increment(ftdb, node, nlocktype DNS__DB_FLARG_PASS);
}

/*
 * Decrement the external references to a node. If the counter
 * goes to zero, decrement the node use counter in the ftcache object
 * as well, and return true. Otherwise return false.
 */
static bool
ftcnode_erefs_decrement(ftcache_t *ftdb, ftcnode_t *node DNS__DB_FLARG) {
	uint_fast32_t refs = isc_refcount_decrement(&node->erefs);

#if DNS_DB_NODETRACE
	fprintf(stderr, "decr:node:%s:%s:%u:%p->erefs = %" PRIuFAST32 "\n",
		func, file, line, node, refs - 1);
#endif
	if (refs > 1) {
		return false;
	}

	ftcache_unref(ftdb);
	return true;
}

/*
 * Caller must be holding a node lock, either read or write.
 *
 * Note that the lock must be held even when node references are
 * atomically modified; in that case the decrement operation itself does not
 * have to be protected, but we must avoid a race condition where multiple
 * threads are decreasing the reference to zero simultaneously and at least
 * one of them is going to free the node.
 *
 * This calls dec_erefs() to decrement the external node reference counter,
 * (and possibly the node use counter), cleans up and deletes the node
 * if necessary, then decrements the internal reference counter as well.
 */
static void
ftcnode_release(ftcache_t *ftdb, ftcnode_t *node, isc_rwlocktype_t *nlocktypep,
		struct cds_ft_iter *iter DNS__DB_FLARG) {
	REQUIRE(*nlocktypep != isc_rwlocktype_none);

	if (!ftcnode_erefs_decrement(ftdb, node DNS__DB_FLARG_PASS)) {
		goto unref;
	}

	/* Handle easy and typical case first. */
	if (!cds_list_empty(&node->headers)) {
		goto unref;
	}

	if (*nlocktypep == isc_rwlocktype_read) {
		/*
		 * The external reference count went to zero and the node
		 * is dirty or has no data, so we might want to delete it.
		 * To do that, we'll need a write lock. If we don't already
		 * have one, we have to make sure nobody else has
		 * acquired a reference in the meantime, so we increment
		 * erefs (but NOT references!), upgrade the node lock,
		 * decrement erefs again, and see if it's still zero.
		 *
		 * We can't really assume anything about the result code of
		 * erefs_increment.  If another thread acquires reference it
		 * will be larger than 0, if it doesn't it is going to be 0.
		 */
		isc_rwlock_t *nlock = &ftdb->buckets[node->locknum].lock;
		ftcnode_erefs_increment(ftdb, node,
					*nlocktypep DNS__DB_FLARG_PASS);
		NODE_FORCEUPGRADE(nlock, nlocktypep);
		if (!ftcnode_erefs_decrement(ftdb, node DNS__DB_FLARG_PASS)) {
			goto unref;
		}
	}

	if (!cds_list_empty(&node->headers)) {
		goto unref;
	}

	if (iter != NULL) {
		/*
		 * We can delete the node if we hold the writer mutex (carried
		 * as a removal iterator).
		 */
		delete_node(ftdb, iter, node);
	} else if (!node->deleted) {
		/*
		 * If we don't have the tree lock, we will add this node to a
		 * linked list of nodes in this locking bucket which we will
		 * free later.
		 */
		ftcnode_acquire(ftdb, node, *nlocktypep DNS__DB_FLARG_PASS);

		isc_queue_node_init(&node->deadlink);
		if (!isc_queue_enqueue_entry(
			    &ftdb->buckets[node->locknum].deadnodes, node,
			    deadlink))
		{
			/* Queue was empty, trigger new cleaning */
			isc_loop_t *loop = isc_loop_get(node->locknum);

			ftcache_ref(ftdb);
			isc_async_run(loop, cleanup_deadnodes_cb, ftdb);
		}
	}
	/* else: already removed from the trie; reclaimed with its chunk */
unref:
	ftcnode_unref(node);
}

static void
update_rrsetstats(dns_stats_t *stats, const dns_typepair_t typepair,
		  const uint_least16_t hattributes, const bool increment) {
	dns_rdatastatstype_t statattributes = 0;
	dns_rdatastatstype_t base = 0;
	dns_rdatastatstype_t type;
	dns_slabheader_t *header = &(dns_slabheader_t){
		.typepair = typepair,
		.attributes = hattributes,
	};

	if (!EXISTS(header) || !STATCOUNT(header)) {
		return;
	}

	if (NEGATIVE(header)) {
		if (NXDOMAIN(header)) {
			statattributes = DNS_RDATASTATSTYPE_ATTR_NXDOMAIN;
		} else {
			statattributes = DNS_RDATASTATSTYPE_ATTR_NXRRSET;
			base = DNS_TYPEPAIR_TYPE(header->typepair);
		}
	} else {
		base = DNS_TYPEPAIR_TYPE(header->typepair);
	}

	if (STALE(header)) {
		statattributes |= DNS_RDATASTATSTYPE_ATTR_STALE;
	}

	type = DNS_RDATASTATSTYPE_VALUE(base, statattributes);
	if (increment) {
		dns_rdatasetstats_increment(stats, type);
	} else {
		dns_rdatasetstats_decrement(stats, type);
	}
}

static void
mark(dns_slabheader_t *header, uint_least16_t flag) {
	uint_least16_t attributes = atomic_load_acquire(&header->attributes);
	uint_least16_t newattributes = 0;
	ftcache_t *ftdb = HEADERNODE(header)->ftdb;

	/*
	 * If we are already ancient there is nothing to do.
	 */
	do {
		if ((attributes & flag) != 0) {
			return;
		}
		newattributes = attributes | flag;
	} while (!atomic_compare_exchange_weak_acq_rel(
		&header->attributes, &attributes, newattributes));

	/*
	 * Decrement and increment the stats counter for the appropriate
	 * RRtype.
	 */
	update_rrsetstats(ftdb->rrsetstats, header->typepair, attributes,
			  false);
	update_rrsetstats(ftdb->rrsetstats, header->typepair, newattributes,
			  true);
}

static void
setttl(dns_slabheader_t *header, isc_stdtime_t newts) {
	header->expire = newts;
}

static size_t
header_delete(ftcnode_t *node, dns_slabheader_t *header) {
	/* The slabheader has already been removed from the node headers */
	if (cds_list_empty(&header->headers_link)) {
		return 0;
	}

	size_t expired = rdataset_size(header);
	ftcache_t *ftdb = node->ftdb;

	cds_list_del_init(&header->headers_link);

	/*
	 * This place is the only place where we actually need header->typepair.
	 */
	update_rrsetstats(ftdb->rrsetstats, header->typepair,
			  atomic_load_acquire(&header->attributes), false);

	ISC_SIEVE_UNLINK(ftdb->buckets[node->locknum].sieve, header, lrulink);

	if (header->related != NULL) {
		INSIST(header->related->related == header);
		dns_slabheader_detach(&header->related->related);
		dns_slabheader_detach(&header->related);
	}

	dns_slabheader_detach(&header);

	return expired;
}

/*
 * Caller must hold the node (write) lock.
 */

static void
flush_node(ftcache_t *ftdb, ftcnode_t *node, isc_rwlocktype_t *nlocktypep,
	   struct cds_ft_iter *iter, dns_expire_t reason DNS__DB_FLARG) {
	if (isc_refcount_current(&node->erefs) != 0) {
		return;
	}

	/*
	 * If no one else is using the node, we can clean it up now.
	 * We first need to gain a new reference to the node to meet a
	 * requirement of ftcnode_release().
	 */
	ftcnode_acquire(ftdb, node, *nlocktypep DNS__DB_FLARG_PASS);
	ftcnode_release(ftdb, node, nlocktypep, iter DNS__DB_FLARG_PASS);

	if (ftdb->cachestats == NULL) {
		return;
	}

	switch (reason) {
	case dns_expire_lru:
		isc_stats_increment(ftdb->cachestats,
				    dns_cachestatscounter_deletelru);
		break;
	default:
		break;
	}
}

static void
update_cachestats(ftcache_t *ftdb, isc_result_t result) {
	if (ftdb->cachestats == NULL) {
		return;
	}

	switch (result) {
	case DNS_R_COVERINGNSEC:
		isc_stats_increment(ftdb->cachestats,
				    dns_cachestatscounter_coveringnsec);
		FALLTHROUGH;
	case ISC_R_SUCCESS:
	case DNS_R_CNAME:
	case DNS_R_DNAME:
	case DNS_R_DELEGATION:
	case DNS_R_NCACHENXDOMAIN:
	case DNS_R_NCACHENXRRSET:
		isc_stats_increment(ftdb->cachestats,
				    dns_cachestatscounter_hits);
		break;
	default:
		isc_stats_increment(ftdb->cachestats,
				    dns_cachestatscounter_misses);
	}
}

static void
bindrdataset(ftcache_t *ftdb, ftcnode_t *node, dns_slabheader_t *header,
	     isc_stdtime_t now, isc_rwlocktype_t nlocktype,
	     dns_rdataset_t *rdataset DNS__DB_FLARG) {
	bool stale = STALE(header);

	/*
	 * Caller must be holding the node reader lock.
	 * XXXJT: technically, we need a writer lock, since we'll increment
	 * the header count below.  However, since the actual counter value
	 * doesn't matter, we prioritize performance here.  (We may want to
	 * use atomic increment when available).
	 */

	if (rdataset == NULL) {
		return;
	}

	dns_slabheader_ref(header);

	ftcnode_acquire(ftdb, node, nlocktype DNS__DB_FLARG_PASS);

	INSIST(rdataset->methods == NULL); /* We must be disassociated. */

	/*
	 * Mark header stale if the RRset is no longer active.
	 */
	if (!ACTIVE(header, now)) {
		dns_ttl_t stale_ttl = header->expire + STALE_TTL(header, ftdb);
		/*
		 * If this data is in the stale window keep it and if
		 * DNS_DBFIND_STALEOK is not set we tell the caller to
		 * skip this record.  We skip the records with ZEROTTL
		 * (these records should not be cached anyway).
		 */

		if (!ZEROTTL(header) && KEEPSTALE(ftdb) && stale_ttl > now) {
			stale = true;
		}
	}

	rdataset->methods = &dns_rdataslab_rdatasetmethods;
	rdataset->rdclass = ftdb->common.rdclass;
	if (NEGATIVE(header)) {
		rdataset->type = dns_rdatatype_none;
		rdataset->covers = DNS_TYPEPAIR_TYPE(header->typepair);
		INSIST(DNS_TYPEPAIR_COVERS(header->typepair) ==
		       dns_rdatatype_none);
	} else {
		rdataset->type = DNS_TYPEPAIR_TYPE(header->typepair);
		rdataset->covers = DNS_TYPEPAIR_COVERS(header->typepair);
	}
	rdataset->ttl = !ZEROTTL(header) ? header->expire - now : 0;
	rdataset->trust = atomic_load(&header->trust);
	rdataset->resign = 0;

	if (NEGATIVE(header)) {
		rdataset->attributes.negative = true;
	}
	if (NXDOMAIN(header)) {
		rdataset->attributes.nxdomain = true;
	}
	if (OPTOUT(header)) {
		rdataset->attributes.optout = true;
	}
	if (PREFETCH(header)) {
		rdataset->attributes.prefetch = true;
	}

	if (stale) {
		dns_ttl_t stale_ttl = header->expire + STALE_TTL(header, ftdb);
		if (stale_ttl > now) {
			rdataset->ttl = stale_ttl - now;
		} else {
			rdataset->ttl = 0;
		}
		if (STALE_WINDOW(header)) {
			rdataset->attributes.stale_window = true;
		}
		rdataset->attributes.stale = true;
		rdataset->expire = header->expire;
	} else if (!ACTIVE(header, now)) {
		/*
		 * The entry is expired but still present in the cache (it has
		 * not yet been removed); flag it so that, e.g., a cache dump
		 * including expired entries can mark it.
		 */
		rdataset->attributes.ancient = true;
		rdataset->ttl = 0;
	}

	rdataset->slab.node = (dns_dbnode_t *)node;
	rdataset->slab.raw = header->raw;
	rdataset->slab.iter_pos = NULL;
	rdataset->slab.iter_count = 0;

	/*
	 * Add noqname proof.
	 */
	rdataset->slab.noqname = header->noqname;
	if (header->noqname != NULL) {
		rdataset->attributes.noqname = true;
	}
	rdataset->slab.closest = header->closest;
	if (header->closest != NULL) {
		rdataset->attributes.closest = true;
	}
}

static void
bindrdatasets(ftcache_t *ftdb, ftcnode_t *qpnode, dns_slabheader_t *found,
	      dns_slabheader_t *foundsig, isc_stdtime_t now,
	      isc_rwlocktype_t nlocktype, dns_rdataset_t *rdataset,
	      dns_rdataset_t *sigrdataset DNS__DB_FLARG) {
	bindrdataset(ftdb, qpnode, found, now, nlocktype,
		     rdataset DNS__DB_FLARG_PASS);
	ftcache_hit(ftdb, found);
	if (!NEGATIVE(found) && foundsig != NULL) {
		bindrdataset(ftdb, qpnode, foundsig, now, nlocktype,
			     sigrdataset DNS__DB_FLARG_PASS);
		ftcache_hit(ftdb, foundsig);
	}
}

static isc_result_t
setup_delegation(ftc_search_t *search, dns_dbnode_t **nodep,
		 dns_rdataset_t *rdataset,
		 dns_rdataset_t *sigrdataset DNS__DB_FLARG) {
	dns_typepair_t typepair;
	ftcnode_t *node = NULL;

	REQUIRE(search != NULL);
	REQUIRE(search->zonecut != NULL);
	REQUIRE(search->zonecut_header != NULL);

	/*
	 * The caller MUST NOT be holding any node locks.
	 */

	node = search->zonecut;
	typepair = search->zonecut_header->typepair;

	if (nodep != NULL) {
		/*
		 * Note that we don't have to increment the node's reference
		 * count here because we're going to use the reference we
		 * already have in the search block.
		 */
		*nodep = (dns_dbnode_t *)node;
		search->need_cleanup = false;
	}
	if (rdataset != NULL) {
		isc_rwlocktype_t nlocktype = isc_rwlocktype_none;
		isc_rwlock_t *nlock =
			&search->ftdb->buckets[node->locknum].lock;
		NODE_RDLOCK(nlock, &nlocktype);
		bindrdatasets(search->ftdb, node, search->zonecut_header,
			      search->zonecut_sigheader, search->now, nlocktype,
			      rdataset, sigrdataset DNS__DB_FLARG_PASS);
		NODE_UNLOCK(nlock, &nlocktype);
	}

	if (typepair == DNS_TYPEPAIR_VALUE(dns_rdatatype_dname, 0)) {
		return DNS_R_DNAME;
	}
	return DNS_R_DELEGATION;
}

static bool
check_stale_header(dns_slabheader_t *header, ftc_search_t *search) {
	if (ACTIVE(header, search->now)) {
		return false;
	}

	isc_stdtime_t stale = header->expire + STALE_TTL(header, search->ftdb);
	/*
	 * If this data is in the stale window keep it and if
	 * DNS_DBFIND_STALEOK is not set we tell the caller to
	 * skip this record.  We skip the records with ZEROTTL
	 * (these records should not be cached anyway).
	 */

	DNS_SLABHEADER_CLRATTR(header, DNS_SLABHEADERATTR_STALE_WINDOW);
	if (!ZEROTTL(header) && KEEPSTALE(search->ftdb) && stale > search->now)
	{
		mark(header, DNS_SLABHEADERATTR_STALE);
		/*
		 * If DNS_DBFIND_STALESTART is set then it means we
		 * failed to resolve the name during recursion, in
		 * this case we mark the time in which the refresh
		 * failed.
		 */
		if ((search->options & DNS_DBFIND_STALESTART) != 0) {
			atomic_store_release(&header->last_refresh_fail_ts,
					     search->now);
		} else if ((search->options & DNS_DBFIND_STALEENABLED) != 0 &&
			   search->now <
				   (atomic_load_acquire(
					    &header->last_refresh_fail_ts) +
				    search->ftdb->serve_stale_refresh))
		{
			/*
			 * If we are within interval between last
			 * refresh failure time + 'stale-refresh-time',
			 * then don't skip this stale entry but use it
			 * instead.
			 */
			DNS_SLABHEADER_SETATTR(header,
					       DNS_SLABHEADERATTR_STALE_WINDOW);
			return false;
		} else if ((search->options & DNS_DBFIND_STALETIMEOUT) != 0) {
			/*
			 * We want stale RRset due to timeout, so we
			 * don't skip it.
			 */
			return false;
		}
		return (search->options & DNS_DBFIND_STALEOK) == 0;
	}

	return true;
}

static bool
invalid_header(dns_slabheader_t *header, ftc_search_t *search) {
	return header == NULL || check_stale_header(header, search) ||
	       !EXISTS(header);
}

/*
 * Return true if we've found headers for both 'type' and RRSIG('type'),
 * or (optionally, if 'negtype' is nonzero) if we've found a single
 * negative header covering either 'negtype' or ANY.
 */
static bool
related_headers(dns_slabheader_t *header, dns_slabheader_t *sigheader,
		dns_typepair_t typepair, dns_slabheader_t **foundp,
		dns_slabheader_t **foundsigp) {
	if (header != NULL) {
		REQUIRE(DNS_TYPEPAIR_TYPE(header->typepair) !=
			dns_rdatatype_rrsig);
		REQUIRE(DNS_TYPEPAIR_COVERS(header->typepair) ==
			dns_rdatatype_none);
	}
	if (sigheader != NULL) {
		REQUIRE(DNS_TYPEPAIR_TYPE(sigheader->typepair) ==
			dns_rdatatype_rrsig);
		REQUIRE(DNS_TYPEPAIR_COVERS(sigheader->typepair) !=
				dns_rdatatype_none ||
			NEGATIVE(sigheader));
	}

	/*
	 * Nothing exists if there's a NEGATIVE(dns_typepair_any).
	 */
	if (header != NULL && header->typepair == dns_typepair_any) {
		INSIST(NEGATIVE(header));
		INSIST(sigheader == NULL);
		*foundp = header;
		*foundsigp = NULL;
		return true;
	}

	/*
	 * Use the sigheader if we are looking for RRSIG.
	 */
	if (DNS_TYPEPAIR_TYPE(typepair) == dns_rdatatype_rrsig) {
		if (sigheader == NULL) {
			return false;
		}

		REQUIRE(EXISTS(sigheader));
		if (sigheader->typepair == typepair) {
			*foundp = sigheader;
			*foundsigp = NULL;
			return true;
		}
		return false;
	} else {
		if (header == NULL) {
			return false;
		}

		REQUIRE(EXISTS(header));
		REQUIRE(!NEGATIVE(header) || sigheader == NULL);

		if (header->typepair == typepair) {
			*foundp = header;
			*foundsigp = sigheader;
			return true;
		}
	}

	return false;
}

static void
store_headers(dns_slabheader_t *tmp, dns_slabheader_t **headerp,
	      dns_slabheader_t **sigheaderp, ftc_search_t *search) {
	dns_slabheader_t *header = NULL, *sigheader = NULL;
	if (DNS_TYPEPAIR_TYPE(tmp->typepair) == dns_rdatatype_rrsig) {
		header = tmp->related;
		sigheader = tmp;
	} else {
		header = tmp;
		sigheader = tmp->related;
	}

	if (invalid_header(header, search)) {
		return;
	}

	*headerp = header;

	if (invalid_header(sigheader, search)) {
		return;
	}
	*sigheaderp = sigheader;
}

static void
find_headers(ftcnode_t *node, ftc_search_t *search, dns_rdatatype_t type,
	     dns_slabheader_t **foundp, dns_slabheader_t **foundsigp) {
	DNS_SLABHEADER_FOREACH(tmp, &node->headers) {
		dns_slabheader_t *header = NULL, *sigheader = NULL;

		if (tmp->typepair == dns_typepair_any) {
			INSIST(tmp->related == NULL);
			INSIST(NEGATIVE(tmp));
			if (invalid_header(tmp, search)) {
				/*
				 * NEGATIVE(ANY), but it is no longer valid.
				 */
				continue;
			}
			*foundp = NULL;
			*foundsigp = NULL;
			return;
		}

		if (tmp->typepair != DNS_TYPEPAIR(type) &&
		    tmp->typepair != DNS_SIGTYPEPAIR(type))
		{
			/* Not our type; continue with next slabtop */
			continue;
		}

		store_headers(tmp, &header, &sigheader, search);

		/*
		 * This function only sets positive headers.
		 */
		if (header != NULL && !NEGATIVE(header)) {
			*foundp = header;
			*foundsigp = sigheader;
		}

		return;
	}
}

static isc_result_t
check_dname(ftcnode_t *node, void *arg DNS__DB_FLARG) {
	ftc_search_t *search = arg;
	dns_slabheader_t *found = NULL, *foundsig = NULL;
	isc_result_t result;
	isc_rwlock_t *nlock = NULL;
	isc_rwlocktype_t nlocktype = isc_rwlocktype_none;

	REQUIRE(search->zonecut == NULL);

	nlock = &search->ftdb->buckets[node->locknum].lock;
	NODE_RDLOCK(nlock, &nlocktype);

	/*
	 * Look for a DNAME or RRSIG DNAME rdataset.
	 */
	find_headers(node, search, dns_rdatatype_dname, &found, &foundsig);

	if (found != NULL && (!DNS_TRUST_PENDING(atomic_load(&found->trust)) ||
			      (search->options & DNS_DBFIND_PENDINGOK) != 0))
	{
		/*
		 * We increment the reference count on node to ensure that
		 * search->zonecut_header will still be valid later.
		 */
		ftcnode_acquire(search->ftdb, node,
				nlocktype DNS__DB_FLARG_PASS);
		search->zonecut = node;
		search->zonecut_header = found;
		search->zonecut_sigheader = foundsig;
		search->need_cleanup = true;
		result = DNS_R_PARTIALMATCH;
	} else {
		result = DNS_R_CONTINUE;
	}

	NODE_UNLOCK(nlock, &nlocktype);

	return result;
}

/*
 * Look for a potentially covering NSEC in the cache where `name`
 * is known not to exist.  This uses the auxiliary NSEC tree to find
 * the potential NSEC owner. If found, we update 'foundname', 'nodep',
 * 'rdataset' and 'sigrdataset', and return DNS_R_COVERINGNSEC.
 * Otherwise, return ISC_R_NOTFOUND.
 */
static isc_result_t
find_coveringnsec(ftc_search_t *search, const dns_name_t *name,
		  dns_dbnode_t **nodep, dns_name_t *foundname,
		  dns_rdataset_t *rdataset,
		  dns_rdataset_t *sigrdataset DNS__DB_FLARG) {
	dns_fixedname_t fpredecessor, fixed;
	dns_name_t *predecessor = NULL, *fname = NULL;
	ftcnode_t *node = NULL;
	ftcnode_t *exact = NULL;
	struct cds_ft_iter *iter = NULL;
	dns_qpkey_t key;
	size_t keylen;
	isc_result_t result;
	isc_rwlocktype_t nlocktype = isc_rwlocktype_none;
	isc_rwlock_t *nlock = NULL;
	dns_slabheader_t *found = NULL, *foundsig = NULL;

	/*
	 * An exact match in the NSEC namespace is not a covering NSEC.
	 */
	if (ftc_lookup(search->ftdb->ft, name, DNS_DBNAMESPACE_NSEC, &exact) ==
	    ISC_R_SUCCESS) {
		return ISC_R_NOTFOUND;
	}

	fname = dns_fixedname_initname(&fixed);
	predecessor = dns_fixedname_initname(&fpredecessor);

	/*
	 * Find the predecessor in the NSEC namespace: the largest NSEC owner
	 * strictly below the query name.
	 */
	keylen = dns_qpkey_fromname(key, name, DNS_DBNAMESPACE_NSEC);
	RUNTIME_CHECK(cds_ft_iter_create(search->ftdb->ft, &iter) ==
		      CDS_FT_STATUS_OK);
	cds_ft_iter_set_key(iter, key, keylen);
	if (cds_ft_lookup_lt(search->ftdb->ft, iter) != CDS_FT_STATUS_OK) {
		cds_ft_iter_destroy(iter);
		return ISC_R_NOTFOUND;
	}
	node = caa_container_of(cds_ft_iter_node(iter), ftcnode_t, ftnode);
	cds_ft_iter_destroy(iter);

	/* The predecessor must itself be in the NSEC namespace. */
	if (node->nspace != DNS_DBNAMESPACE_NSEC) {
		return ISC_R_NOTFOUND;
	}
	dns_name_copy(&node->name, predecessor);

	/*
	 * Lookup the predecessor in the normal namespace.
	 */
	node = NULL;
	RETERR(ftc_lookup(search->ftdb->ft, predecessor, DNS_DBNAMESPACE_NORMAL,
			  &node));
	dns_name_copy(&node->name, fname);

	nlock = &search->ftdb->buckets[node->locknum].lock;
	NODE_RDLOCK(nlock, &nlocktype);

	find_headers(node, search, dns_rdatatype_nsec, &found, &foundsig);

	if (found != NULL) {
		if (nodep != NULL) {
			ftcnode_acquire(search->ftdb, node,
					nlocktype DNS__DB_FLARG_PASS);
			*nodep = (dns_dbnode_t *)node;
		}
		bindrdatasets(search->ftdb, node, found, foundsig, search->now,
			      nlocktype, rdataset,
			      sigrdataset DNS__DB_FLARG_PASS);
		dns_name_copy(fname, foundname);

		result = DNS_R_COVERINGNSEC;
	} else {
		result = ISC_R_NOTFOUND;
	}
	NODE_UNLOCK(nlock, &nlocktype);
	return result;
}

static inline bool
missing_answer(dns_slabheader_t *found, unsigned int options) {
	if (found == NULL) {
		return true;
	}

	dns_trust_t trust = atomic_load(&found->trust);
	return (DNS_TRUST_ADDITIONAL(trust) &&
		(options & DNS_DBFIND_ADDITIONALOK) == 0) ||
	       (DNS_TRUST_GLUE(trust) && (options & DNS_DBFIND_GLUEOK) == 0) ||
	       (DNS_TRUST_PENDING(trust) &&
		(options & DNS_DBFIND_PENDINGOK) == 0);
}

static void
ftc_search_init(ftc_search_t *search, ftcache_t *db, unsigned int options,
		isc_stdtime_t now) {
	*search = (ftc_search_t){
		.ftdb = (ftcache_t *)db,
		.options = options,
		.now = now ? now : isc_stdtime_now(),
	};

	/* Reads run under the RCU read-side lock for the whole search. */
	rcu_read_lock();
}

static void
ftc_search_deinit(ftc_search_t *search DNS__DB_FLARG) {
	rcu_read_unlock();

	if (!search->need_cleanup) {
		return;
	}

	ftcnode_t *node = search->zonecut;
	INSIST(node != NULL);

	isc_rwlock_t *nlock = &search->ftdb->buckets[node->locknum].lock;
	isc_rwlocktype_t nlocktype = isc_rwlocktype_none;

	NODE_RDLOCK(nlock, &nlocktype);
	ftcnode_release(search->ftdb, node, &nlocktype,
			NULL DNS__DB_FLARG_PASS);
	NODE_UNLOCK(nlock, &nlocktype);
}

static isc_result_t
ftcache_find(dns_db_t *db, const dns_name_t *name, dns_dbversion_t *version,
	     dns_rdatatype_t type, unsigned int options, isc_stdtime_t __now,
	     dns_dbnode_t **nodep, dns_name_t *foundname,
	     dns_clientinfomethods_t *methods ISC_ATTR_UNUSED,
	     dns_clientinfo_t *clientinfo ISC_ATTR_UNUSED,
	     dns_rdataset_t *rdataset,
	     dns_rdataset_t *sigrdataset DNS__DB_FLARG) {
	ftcnode_t *node = NULL;
	isc_result_t result;
	bool cname_ok = true;
	bool found_noqname = false;
	bool all_negative = true;
	bool empty_node = true;
	isc_rwlock_t *nlock = NULL;
	isc_rwlocktype_t nlocktype = isc_rwlocktype_none;
	dns_slabheader_t *found = NULL, *foundsig = NULL;
	dns_slabheader_t *nsecheader = NULL, *nsecsig = NULL;
	dns_typepair_t typepair = DNS_TYPEPAIR(type);

	if (type == dns_rdatatype_none) {
		/* We can't search negative cache directly */
		return ISC_R_NOTFOUND;
	}

	ftc_search_t search;
	ftc_search_init(&search, (ftcache_t *)db, options, __now);

	REQUIRE(VALID_FTDB((ftcache_t *)db));
	REQUIRE(version == NULL);

	/*
	 * Search down from the root of the tree. cds_ft has no search chain,
	 * so we take the exact match if present, otherwise the closest
	 * enclosing ancestor (longest prefix match).
	 */
	result = ftc_lookup(search.ftdb->ft, name, DNS_DBNAMESPACE_NORMAL,
			    &node);
	if (result != ISC_R_SUCCESS) {
		dns_qpkey_t key;
		size_t keylen = dns_qpkey_fromname(key, name,
						   DNS_DBNAMESPACE_NORMAL);
		size_t match_len;
		struct cds_ft_node *ftn = NULL;

		if (cds_ft_lookup_longest_match_key(search.ftdb->ft, key, keylen,
						    &match_len,
						    &ftn) == CDS_FT_STATUS_OK) {
			node = caa_container_of(ftn, ftcnode_t, ftnode);
			result = DNS_R_PARTIALMATCH;
		} else {
			node = NULL;
			result = ISC_R_NOTFOUND;
		}
	}
	if (result != ISC_R_NOTFOUND && foundname != NULL) {
		dns_name_copy(&node->name, foundname);
	}

	/*
	 * Walk the ancestors of QNAME, shallowest first, looking for a node
	 * above us with an active DNAME rdataset. We consider only nodes
	 * strictly above QNAME.
	 *
	 * TODO: this does one trie lookup per ancestor label, whereas the qp
	 * version got the whole chain for free from a single descent.
	 */
	unsigned int nlabels = dns_name_countlabels(name);
	for (unsigned int k = 2; k < nlabels; k++) {
		isc_result_t tresult;
		ftcnode_t *encloser = NULL;
		dns_fixedname_t fanc;
		dns_name_t *anc = dns_fixedname_initname(&fanc);

		dns_name_getlabelsequence(name, nlabels - k, k, anc);

		if (ftc_lookup(search.ftdb->ft, anc, DNS_DBNAMESPACE_NORMAL,
			       &encloser) != ISC_R_SUCCESS) {
			continue;
		}

		tresult = check_dname(encloser,
				      (void *)&search DNS__DB_FLARG_PASS);
		if (tresult != DNS_R_CONTINUE) {
			result = DNS_R_PARTIALMATCH;
			node = encloser;
			if (foundname != NULL) {
				dns_name_copy(&node->name, foundname);
			}
			break;
		}
	}

	if (result == DNS_R_PARTIALMATCH) {
		/*
		 * If we discovered a covering DNAME skip looking for a covering
		 * NSEC.
		 */
		if ((search.options & DNS_DBFIND_COVERINGNSEC) != 0 &&
		    (search.zonecut_header == NULL ||
		     search.zonecut_header->typepair != dns_rdatatype_dname))
		{
			result = find_coveringnsec(
				&search, name, nodep, foundname, rdataset,
				sigrdataset DNS__DB_FLARG_PASS);
			if (result == DNS_R_COVERINGNSEC) {
				goto tree_exit;
			}
		}
		if (search.zonecut != NULL) {
			result = setup_delegation(
				&search, nodep, rdataset,
				sigrdataset DNS__DB_FLARG_PASS);
			goto tree_exit;
		} else {
			result = ISC_R_NOTFOUND;
			goto tree_exit;
		}
	} else if (result != ISC_R_SUCCESS) {
		goto tree_exit;
	}

	/*
	 * Certain DNSSEC types are not subject to CNAME matching
	 * (RFC4035, section 2.5).
	 */
	if (type == dns_rdatatype_nsec || type == dns_rdatatype_rrsig) {
		cname_ok = false;
	}

	/*
	 * We now go looking for rdata...
	 */

	nlock = &search.ftdb->buckets[node->locknum].lock;
	NODE_RDLOCK(nlock, &nlocktype);

	DNS_SLABHEADER_FOREACH(tmp, &node->headers) {
		dns_slabheader_t *header = NULL, *sigheader = NULL;

		store_headers(tmp, &header, &sigheader, &search);

		if (header == NULL && sigheader == NULL) {
			continue;
		}

		/*
		 * We now know that there is at least one active
		 * rdataset at this node.
		 */
		empty_node = false;

		if (header != NULL && header->noqname != NULL &&
		    atomic_load(&header->trust) == dns_trust_secure)
		{
			found_noqname = true;
		}

		if (header != NULL && !NEGATIVE(header)) {
			all_negative = false;
		}

		if (sigheader != NULL && !NEGATIVE(sigheader)) {
			all_negative = false;
		}

		if (related_headers(header, sigheader, typepair, &found,
				    &foundsig))
		{
			/*
			 * We can't exit early until we have an answer with
			 * sufficient trust level - see missing_answer()
			 * for details - because we might need NS or NSEC
			 * records.
			 */
			if (missing_answer(found, options) || STALE(found)) {
				continue;
			}

			/* We found something, continue with next header */
			break;
		}

		if (header == NULL || NEGATIVE(header)) {
			/*
			 * We are not interested in the negative headers for the
			 * auxiliary types, only for the main type we are
			 * looking for.
			 */
			continue;
		}

		switch (tmp->typepair) {
		case dns_rdatatype_cname:
		case DNS_SIGTYPEPAIR(dns_rdatatype_cname):
			if (cname_ok) {
				found = header;
				foundsig = sigheader;
			}
			break;

		case dns_rdatatype_nsec:
		case DNS_SIGTYPEPAIR(dns_rdatatype_nsec):
			nsecheader = header;
			nsecsig = sigheader;
			break;

		default:
			if (typepair == dns_typepair_any) {
				/* QTYPE==ANY, so any anwers will do */
				found = header;
				break;
			}
		}

		if (!missing_answer(found, options) && !STALE(found)) {
			break;
		}
	}

	if (empty_node) {
		/*
		 * We have an exact match for the name, but there are no
		 * extant rdatasets.  That means that this node doesn't
		 * meaningfully exist, and that we really have a partial match.
		 */
		NODE_UNLOCK(nlock, &nlocktype);
		if ((search.options & DNS_DBFIND_COVERINGNSEC) != 0) {
			result = find_coveringnsec(
				&search, name, nodep, foundname, rdataset,
				sigrdataset DNS__DB_FLARG_PASS);
			if (result == DNS_R_COVERINGNSEC) {
				goto tree_exit;
			}
		}

		result = ISC_R_NOTFOUND;
		goto tree_exit;
	}

	/*
	 * If we didn't find what we were looking for...
	 */
	if (missing_answer(found, options)) {
		/*
		 * Return covering NODATA NSEC record.
		 */
		if ((search.options & DNS_DBFIND_COVERINGNSEC) != 0 &&
		    nsecheader != NULL)
		{
			if (nodep != NULL) {
				ftcnode_acquire(search.ftdb, node,
						nlocktype DNS__DB_FLARG_PASS);
				*nodep = (dns_dbnode_t *)node;
			}
			bindrdatasets(search.ftdb, node, nsecheader, nsecsig,
				      search.now, nlocktype, rdataset,
				      sigrdataset DNS__DB_FLARG_PASS);
			result = DNS_R_COVERINGNSEC;
			goto node_exit;
		}

		/*
		 * This name was from a wild card.  Look for a covering NSEC.
		 */
		if (found == NULL && (found_noqname || all_negative) &&
		    (search.options & DNS_DBFIND_COVERINGNSEC) != 0)
		{
			NODE_UNLOCK(nlock, &nlocktype);
			result = find_coveringnsec(
				&search, name, nodep, foundname, rdataset,
				sigrdataset DNS__DB_FLARG_PASS);
			if (result != DNS_R_COVERINGNSEC) {
				result = ISC_R_NOTFOUND;
			}
			goto tree_exit;
		}

		result = ISC_R_NOTFOUND;
		goto node_exit;
	}

	/*
	 * We found what we were looking for, or we found a CNAME.
	 */

	if (nodep != NULL) {
		ftcnode_acquire(search.ftdb, node,
				nlocktype DNS__DB_FLARG_PASS);
		*nodep = (dns_dbnode_t *)node;
	}

	if (NEGATIVE(found)) {
		/*
		 * We found a negative cache entry.
		 */
		if (NXDOMAIN(found)) {
			result = DNS_R_NCACHENXDOMAIN;
		} else {
			result = DNS_R_NCACHENXRRSET;
		}
	} else if (typepair != found->typepair &&
		   typepair != dns_typepair_any &&
		   found->typepair == DNS_TYPEPAIR(dns_rdatatype_cname))
	{
		/*
		 * We weren't doing an ANY query and we found a CNAME instead
		 * of the type we were looking for, so we need to indicate
		 * that result to the caller.
		 */
		result = DNS_R_CNAME;
	} else {
		/*
		 * An ordinary successful query!
		 */
		result = ISC_R_SUCCESS;
	}

	if (typepair != dns_typepair_any || result == DNS_R_NCACHENXDOMAIN ||
	    result == DNS_R_NCACHENXRRSET)
	{
		bindrdatasets(search.ftdb, node, found, foundsig, search.now,
			      nlocktype, rdataset,
			      sigrdataset DNS__DB_FLARG_PASS);
	}

node_exit:
	NODE_UNLOCK(nlock, &nlocktype);

tree_exit:
	/*
	 * If we found a zonecut but aren't going to use it, we have to
	 * let go of it.
	 */
	ftc_search_deinit(&search DNS__DB_FLARG_PASS);

	update_cachestats(search.ftdb, result);
	return result;
}

static isc_result_t
ftcache_findrdataset(dns_db_t *db, dns_dbnode_t *node, dns_dbversion_t *version,
		     dns_rdatatype_t type, dns_rdatatype_t covers,
		     isc_stdtime_t __now, dns_rdataset_t *rdataset,
		     dns_rdataset_t *sigrdataset DNS__DB_FLARG) {
	ftcache_t *ftdb = (ftcache_t *)db;
	ftcnode_t *qpnode = (ftcnode_t *)node;
	dns_slabheader_t *found = NULL, *foundsig = NULL;
	dns_typepair_t typepair, sigpair;
	isc_result_t result = ISC_R_SUCCESS;
	isc_rwlock_t *nlock = NULL;
	isc_rwlocktype_t nlocktype = isc_rwlocktype_none;
	ftc_search_t search = (ftc_search_t){
		.ftdb = (ftcache_t *)db,
		.now = __now ? __now : isc_stdtime_now(),
	};

	REQUIRE(VALID_FTDB(ftdb));
	REQUIRE(version == NULL);
	REQUIRE(type != dns_rdatatype_any);

	if (type == dns_rdatatype_none) {
		/* We can't search negative cache directly */
		return ISC_R_NOTFOUND;
	}

	nlock = &ftdb->buckets[qpnode->locknum].lock;
	NODE_RDLOCK(nlock, &nlocktype);

	typepair = DNS_TYPEPAIR_VALUE(type, covers);
	sigpair = (type != dns_rdatatype_rrsig) ? DNS_SIGTYPEPAIR(type)
						: dns_typepair_none;

	DNS_SLABHEADER_FOREACH(tmp, &qpnode->headers) {
		dns_slabheader_t *header = NULL, *sigheader = NULL;

		if (tmp->typepair != typepair && tmp->typepair != sigpair &&
		    tmp->typepair != dns_typepair_any)
		{
			continue;
		}

		store_headers(tmp, &header, &sigheader, &search);

		(void)related_headers(header, sigheader, typepair, &found,
				      &foundsig);
		break;
	}

	if (found != NULL) {
		bindrdatasets(ftdb, qpnode, found, foundsig, search.now,
			      nlocktype, rdataset,
			      sigrdataset DNS__DB_FLARG_PASS);
	}

	NODE_UNLOCK(nlock, &nlocktype);

	if (found == NULL) {
		return ISC_R_NOTFOUND;
	}

	if (NEGATIVE(found)) {
		/*
		 * We found a negative cache entry.
		 */
		if (NXDOMAIN(found)) {
			result = DNS_R_NCACHENXDOMAIN;
		} else {
			result = DNS_R_NCACHENXRRSET;
		}
	}

	update_cachestats(ftdb, result);

	return result;
}

static isc_result_t
setcachestats(dns_db_t *db, isc_stats_t *stats) {
	ftcache_t *ftdb = (ftcache_t *)db;

	REQUIRE(VALID_FTDB(ftdb));
	REQUIRE(stats != NULL);

	isc_stats_attach(stats, &ftdb->cachestats);
	return ISC_R_SUCCESS;
}

static dns_stats_t *
getrrsetstats(dns_db_t *db) {
	ftcache_t *ftdb = (ftcache_t *)db;

	REQUIRE(VALID_FTDB(ftdb));

	return ftdb->rrsetstats;
}

static isc_result_t
setservestalettl(dns_db_t *db, dns_ttl_t ttl) {
	ftcache_t *ftdb = (ftcache_t *)db;

	REQUIRE(VALID_FTDB(ftdb));

	/* currently no bounds checking.  0 means disable. */
	ftdb->common.serve_stale_ttl = ttl;
	return ISC_R_SUCCESS;
}

static isc_result_t
getservestalettl(dns_db_t *db, dns_ttl_t *ttl) {
	ftcache_t *ftdb = (ftcache_t *)db;

	REQUIRE(VALID_FTDB(ftdb));

	*ttl = ftdb->common.serve_stale_ttl;
	return ISC_R_SUCCESS;
}

static isc_result_t
setservestalerefresh(dns_db_t *db, uint32_t interval) {
	ftcache_t *ftdb = (ftcache_t *)db;

	REQUIRE(VALID_FTDB(ftdb));

	/* currently no bounds checking.  0 means disable. */
	ftdb->serve_stale_refresh = interval;
	return ISC_R_SUCCESS;
}

static isc_result_t
getservestalerefresh(dns_db_t *db, uint32_t *interval) {
	ftcache_t *ftdb = (ftcache_t *)db;

	REQUIRE(VALID_FTDB(ftdb));

	*interval = ftdb->serve_stale_refresh;
	return ISC_R_SUCCESS;
}

static void
ftcnode_expiredata(dns_dbnode_t *node, void *data) {
	ftcnode_t *qpnode = (ftcnode_t *)node;
	ftcache_t *ftdb = (ftcache_t *)qpnode->ftdb;

	dns_slabheader_t *header = data;
	isc_rwlocktype_t nlocktype = isc_rwlocktype_none;

	isc_rwlock_t *nlock = &ftdb->buckets[qpnode->locknum].lock;
	NODE_WRLOCK(nlock, &nlocktype);
	(void)expire_header(ftdb, qpnode, header, &nlocktype,
			    NULL DNS__DB_FILELINE);
	NODE_UNLOCK(nlock, &nlocktype);
}

static void
ftcache__destroy_rcu(struct rcu_head *rcu_head) {
	ftcache_t *ftdb = caa_container_of(rcu_head, ftcache_t, rcu_head);
	char buf[DNS_NAME_FORMATSIZE];

	if (dns_name_dynamic(&ftdb->common.origin)) {
		dns_name_format(&ftdb->common.origin, buf, sizeof(buf));
	} else {
		strlcpy(buf, "<UNKNOWN>", sizeof(buf));
	}
	isc_log_write(DNS_LOGCATEGORY_DATABASE, DNS_LOGMODULE_CACHE,
		      ISC_LOG_DEBUG(DNS_FTCACHE_LOG_STATS_LEVEL), "done %s(%s)",
		      __func__, buf);

	if (dns_name_dynamic(&ftdb->common.origin)) {
		dns_name_free(&ftdb->common.origin, ftdb->common.mctx);
	}

	for (size_t i = 0; i < ftdb->buckets_count; i++) {
		NODE_DESTROYLOCK(&ftdb->buckets[i].lock);

		INSIST(ISC_SIEVE_EMPTY(ftdb->buckets[i].sieve));

		INSIST(isc_queue_empty(&ftdb->buckets[i].deadnodes));
		isc_queue_destroy(&ftdb->buckets[i].deadnodes);
	}

	dns_stats_detach(&ftdb->rrsetstats);

	if (ftdb->cachestats != NULL) {
		isc_stats_detach(&ftdb->cachestats);
	}

	isc_refcount_destroy(&ftdb->references);
	isc_refcount_destroy(&ftdb->common.references);

	isc_rwlock_destroy(&ftdb->lock);
	ftdb->common.magic = 0;
	ftdb->common.impmagic = 0;

	isc_mem_putanddetach(&ftdb->common.mctx, ftdb,
			     sizeof(*ftdb) + ftdb->buckets_count *
						     sizeof(ftdb->buckets[0]));
}

static void
ftcache__destroy(ftcache_t *ftdb) {
	/*
	 * TODO: drain the trie first -- remove every external node, wait
	 * one grace period, and drop the trie's reference -- once the
	 * remove path and iterator exist. cds_ft_destroy() does not reclaim
	 * a populated trie's external nodes.
	 */
	cds_ft_destroy(ftdb->ft);
	RUNTIME_CHECK(cds_ft_group_destroy(ftdb->ftgroup) == CDS_FT_STATUS_OK);
	isc_mutex_destroy(&ftdb->wmutex);

	call_rcu(&ftdb->rcu_head, ftcache__destroy_rcu);
}

static void
ftcache_destroy(dns_db_t *arg) {
	ftcache_t *ftdb = (ftcache_t *)arg;

	ftcache_detach(&ftdb);
}

/*%
 * Clean up dead nodes.  These are nodes which have no references, and
 * have no data.  They are dead but we could not or chose not to delete
 * them when we deleted all the data at that node because we did not want
 * to wait for the tree write lock.
 */
static void
cleanup_deadnodes(ftcache_t *ftdb, uint16_t locknum) {
	isc_rwlocktype_t nlocktype = isc_rwlocktype_none;
	isc_rwlock_t *nlock = &ftdb->buckets[locknum].lock;
	ftcnode_t *qpnode = NULL, *qpnext = NULL;
	isc_queue_t deadnodes;
	struct cds_ft_iter *iter = NULL;

	INSIST(locknum < ftdb->buckets_count);

	isc_queue_init(&deadnodes);

	LOCK(&ftdb->wmutex);
	RUNTIME_CHECK(cds_ft_iter_create(ftdb->ft, &iter) == CDS_FT_STATUS_OK);

	NODE_WRLOCK(nlock, &nlocktype);

	isc_queue_splice(&deadnodes, &ftdb->buckets[locknum].deadnodes);

	isc_queue_for_each_entry_safe(&deadnodes, qpnode, qpnext, deadlink) {
		ftcnode_release(ftdb, qpnode, &nlocktype, iter DNS__DB_FILELINE);
	}

	NODE_UNLOCK(nlock, &nlocktype);

	cds_ft_iter_destroy(iter);
	UNLOCK(&ftdb->wmutex);
}

static void
cleanup_deadnodes_cb(void *arg) {
	ftcache_t *ftdb = arg;
	uint16_t locknum = isc_tid();

	cleanup_deadnodes(ftdb, locknum);
	ftcache_unref(ftdb);
}
/*
 * This function is assumed to be called when a node is newly referenced
 * and can be in the deadnode list.  In that case the node will be references
 * and cleanup_deadnodes() will remove it from the list when the cleaning
 * happens.
 * Note: while a new reference is gained in multiple places, there are only very
 * few cases where the node can be in the deadnode list (only empty nodes can
 * have been added to the list).
 */
static isc_result_t
reactivate_node(ftcache_t *ftdb, ftcnode_t *node DNS__DB_FLARG) {
	isc_rwlocktype_t nlocktype = isc_rwlocktype_none;
	isc_rwlock_t *nlock = &ftdb->buckets[node->locknum].lock;
	isc_result_t result = ISC_R_SUCCESS;

	NODE_RDLOCK(nlock, &nlocktype);
	if (!node->deleted) {
		ftcnode_acquire(ftdb, node, nlocktype DNS__DB_FLARG_PASS);
	} else {
		result = ISC_R_NOTFOUND;
	}
	NODE_UNLOCK(nlock, &nlocktype);

	return result;
}

static ftcnode_t *
new_ftcnode(ftcache_t *ftdb, const dns_name_t *name, dns_namespace_t nspace) {
	ftcnode_t *newdata = isc_mem_get(ftdb->common.mctx, sizeof(*newdata));
	*newdata = (ftcnode_t){
		.headers = CDS_LIST_HEAD_INIT(newdata->headers),
		.methods = &ftcnode_methods,
		.ftdb = ftdb,
		.name = DNS_NAME_INITEMPTY,
		.nspace = nspace,
		.references = ISC_REFCOUNT_INITIALIZER(1),
		.locknum = isc_random_uniform(ftdb->buckets_count),
	};

	isc_mem_attach(ftdb->common.mctx, &newdata->mctx);
	dns_name_dup(name, newdata->mctx, &newdata->name);

#ifdef DNS_DB_NODETRACE
	fprintf(stderr, "new_ftcnode:%s:%s:%d:%p->references = 1\n", __func__,
		__FILE__, __LINE__ + 1, name);
#endif
	return newdata;
}

/*
 * Exact lookup of 'name' in namespace 'space'. cds_ft's candidate descent
 * may land on a near-miss, so the result is verified by name. The caller
 * must hold the RCU read-side lock, or exclude concurrent writers.
 */
static isc_result_t
ftc_lookup(struct cds_ft *ft, const dns_name_t *name, dns_namespace_t space,
	   ftcnode_t **nodep) {
	dns_qpkey_t key;
	size_t keylen = dns_qpkey_fromname(key, name, space);
	struct cds_ft_node *ftn = NULL;

	if (cds_ft_lookup_candidate_key(ft, key, keylen, 0, &ftn) !=
	    CDS_FT_STATUS_OK) {
		return ISC_R_NOTFOUND;
	}

	ftcnode_t *node = caa_container_of(ftn, ftcnode_t, ftnode);
	if (!dns_name_equal(name, &node->name)) {
		return ISC_R_NOTFOUND;
	}

	*nodep = node;
	return ISC_R_SUCCESS;
}

static isc_result_t
ftcache_findnode(dns_db_t *db, const dns_name_t *name, bool create,
		 dns_clientinfomethods_t *methods ISC_ATTR_UNUSED,
		 dns_clientinfo_t *clientinfo ISC_ATTR_UNUSED,
		 dns_dbnode_t **nodep DNS__DB_FLARG) {
	ftcache_t *ftdb = (ftcache_t *)db;
	ftcnode_t *node = NULL;
	isc_result_t result;
	dns_namespace_t nspace = DNS_DBNAMESPACE_NORMAL;

	/* lookup the node */
	rcu_read_lock();
	result = ftc_lookup(ftdb->ft, name, nspace, &node);
	if (result == ISC_R_SUCCESS) {
		/* maybe we found an already deleted node */
		result = reactivate_node(ftdb, node DNS__DB_FLARG_PASS);
	}
	rcu_read_unlock();

	if (result == ISC_R_SUCCESS) {
		*nodep = (dns_dbnode_t *)node;
		return ISC_R_SUCCESS;
	}
	if (!create) {
		return ISC_R_NOTFOUND;
	}

	/*
	 * Create the new node under the single-writer mutex. Re-check first:
	 * another writer may have created it since the lock-free lookup.
	 */
	LOCK(&ftdb->wmutex);
	rcu_read_lock();
	result = ftc_lookup(ftdb->ft, name, nspace, &node);
	rcu_read_unlock();
	if (result != ISC_R_SUCCESS) {
		dns_qpkey_t key;
		size_t keylen = dns_qpkey_fromname(key, name, nspace);

		node = new_ftcnode(ftdb, name, nspace);
		RUNTIME_CHECK(cds_ft_insert_unique(ftdb->ft, key, keylen,
						   &node->ftnode, NULL) ==
			      CDS_FT_STATUS_OK);
		/*
		 * The node's initial reference becomes the trie's reference;
		 * it is dropped via call_rcu once the node is removed.
		 */
	}
	RUNTIME_CHECK(reactivate_node(ftdb, node DNS__DB_FLARG_PASS) ==
		      ISC_R_SUCCESS);
	*nodep = (dns_dbnode_t *)node;
	UNLOCK(&ftdb->wmutex);
	return ISC_R_SUCCESS;
}

static isc_result_t
ftcache_createiterator(dns_db_t *db, unsigned int options ISC_ATTR_UNUSED,
		       dns_dbiterator_t **iteratorp) {
	ftcache_t *ftdb = (ftcache_t *)db;
	ftc_dbit_t *ftdbiter = NULL;

	REQUIRE(VALID_FTDB(ftdb));

	ftdbiter = isc_mem_get(ftdb->common.mctx, sizeof(*ftdbiter));
	*ftdbiter = (ftc_dbit_t){
		.common.methods = &dbiterator_methods,
		.common.magic = DNS_DBITERATOR_MAGIC,
		.paused = true,
	};

	ftdbiter->name = dns_fixedname_initname(&ftdbiter->fixed);
	dns_db_attach(db, &ftdbiter->common.db);
	RUNTIME_CHECK(cds_ft_iter_create(ftdb->ft, &ftdbiter->iter) ==
		      CDS_FT_STATUS_OK);

	*iteratorp = (dns_dbiterator_t *)ftdbiter;
	return ISC_R_SUCCESS;
}

static bool
iterator_active(ftcache_t *ftdb, ftc_rditer_t *iterator,
		dns_slabheader_t *header) {
	dns_ttl_t stale_ttl = header->expire + STALE_TTL(header, ftdb);

	/*
	 * If this header is still active then return it.
	 */
	if (ACTIVE(header, iterator->common.now)) {
		return true;
	}

	/*
	 * If we are not returning stale records or the rdataset is
	 * too old don't return it.
	 */
	if (!STALEOK(iterator) || (iterator->common.now > stale_ttl)) {
		return false;
	}
	return true;
}

static isc_result_t
ftcache_allrdatasets(dns_db_t *db, dns_dbnode_t *node, dns_dbversion_t *version,
		     unsigned int options, isc_stdtime_t __now,
		     dns_rdatasetiter_t **iteratorp DNS__DB_FLARG) {
	ftcache_t *ftdb = (ftcache_t *)db;
	ftcnode_t *qpnode = (ftcnode_t *)node;
	ftc_rditer_t *iterator = NULL;
	isc_rwlocktype_t nlocktype = isc_rwlocktype_none;
	isc_rwlock_t *nlock = &ftdb->buckets[qpnode->locknum].lock;

	REQUIRE(VALID_FTDB(ftdb));
	REQUIRE(version == NULL);

	iterator = isc_mem_get(ftdb->common.mctx, sizeof(*iterator));
	*iterator = (ftc_rditer_t){
		.common.magic = DNS_RDATASETITER_MAGIC,
		.common.methods = &rdatasetiter_methods,
		.common.db = db,
		.common.node = node,
		.common.options = options,
		.common.now = __now ? __now : isc_stdtime_now(),
		.rdatasets = ISC_LIST_INITIALIZER,
	};

	ftcnode_acquire(ftdb, qpnode, isc_rwlocktype_none DNS__DB_FLARG_PASS);

	NODE_RDLOCK(nlock, &nlocktype);

	DNS_SLABHEADER_FOREACH(header, &qpnode->headers) {
		if (EXPIREDOK(iterator) ||
		    iterator_active(ftdb, iterator, header))
		{
			dns_rdataset_t *rdataset =
				isc_mem_get(qpnode->mctx, sizeof(*rdataset));
			dns_rdataset_init(rdataset);

			bindrdataset(ftdb, qpnode, header, iterator->common.now,
				     nlocktype, rdataset DNS__DB_FLARG_PASS);

			ISC_LIST_APPEND(iterator->rdatasets, rdataset, link);
		}
	}

	NODE_UNLOCK(nlock, &nlocktype);

	*iteratorp = (dns_rdatasetiter_t *)iterator;

	return ISC_R_SUCCESS;
}

static bool
overmaxtype(ftcache_t *ftdb, uint32_t ntypes) {
	if (ftdb->maxtypepername == 0) {
		return false;
	}

	return ntypes >= ftdb->maxtypepername;
}

static bool
prio_header(dns_slabheader_t *header) {
	return prio_type(header->typepair);
}

static void
ftcnode_attachnode(dns_dbnode_t *source, dns_dbnode_t **targetp DNS__DB_FLARG) {
	REQUIRE(targetp != NULL && *targetp == NULL);

	ftcnode_t *node = (ftcnode_t *)source;
	ftcache_t *ftdb = (ftcache_t *)node->ftdb;

	ftcnode_acquire(ftdb, node, isc_rwlocktype_none DNS__DB_FLARG_PASS);

	*targetp = source;
}

static void
ftcnode_detachnode(dns_dbnode_t **nodep DNS__DB_FLARG) {
	ftcnode_t *node = NULL;
	isc_rwlocktype_t nlocktype = isc_rwlocktype_none;
	isc_rwlock_t *nlock = NULL;

	REQUIRE(nodep != NULL && *nodep != NULL);

	node = (ftcnode_t *)(*nodep);
	ftcache_t *ftdb = (ftcache_t *)node->ftdb;
	*nodep = NULL;
	nlock = &ftdb->buckets[node->locknum].lock;

	REQUIRE(VALID_FTDB(ftdb));

	/*
	 * We can't destroy ftcache while holding a nodelock, so we need to
	 * reference it before acquiring the lock and release it afterward.
	 * Additionally, we must ensure that we don't destroy the database while
	 * the NODE_LOCK is locked.
	 */
	ftcache_ref(ftdb);

	rcu_read_lock();
	NODE_RDLOCK(nlock, &nlocktype);
	ftcnode_release(ftdb, node, &nlocktype, NULL DNS__DB_FLARG_PASS);
	NODE_UNLOCK(nlock, &nlocktype);
	rcu_read_unlock();

	ftcache_detach(&ftdb);
}

static isc_result_t
check_ncache_block(ftcache_t *ftdb, ftcnode_t *qpnode, dns_slabheader_t *header,
		   dns_slabheader_t *newheader, dns_trust_t trust,
		   dns_rdataset_t *addedrdataset, isc_stdtime_t now,
		   isc_rwlocktype_t nlocktype DNS__DB_FLARG) {
	bool block = false;

	/*
	 * 1. If we have a cached NXDOMAIN, we won't cache
	 *    anything else here (dns_typepair_any).
	 * 2. If we have a cached NODATA for a given type,
	 *    we won't cache an RRSIG covering the same type.
	 */
	if (header->typepair == dns_typepair_any) {
		block = true;
	} else if (DNS_TYPEPAIR_TYPE(newheader->typepair) ==
			   dns_rdatatype_rrsig &&
		   DNS_TYPEPAIR_COVERS(newheader->typepair) ==
			   DNS_TYPEPAIR_TYPE(header->typepair))
	{
		block = true;
	}

	if (block) {
		/*
		 * If the ncache entry causing the block is less trusted
		 * than the new data, evict it from the cache. Otherwise,
		 * bind to it and leave the cache unchanged.
		 */
		if (trust >= header->trust) {
			header_delete(qpnode, header);
			return DNS_R_CONTINUE;
		} else {
			ftcache_hit(ftdb, header);
			bindrdataset(ftdb, qpnode, header, now, nlocktype,
				     addedrdataset DNS__DB_FLARG_PASS);
			return DNS_R_UNCHANGED;
		}
	}
	return ISC_R_SUCCESS;
}

static isc_result_t
add(ftcache_t *ftdb, ftcnode_t *qpnode, dns_slabheader_t *newheader,
    unsigned int options, dns_rdataset_t *addedrdataset, isc_stdtime_t now,
    isc_rwlocktype_t nlocktype, struct cds_ft_iter *iter DNS__DB_FLARG) {
	dns_slabheader_t *prioheader = NULL, *evictheader = NULL;
	dns_slabheader_t *oldheader = NULL, *related = NULL;
	dns_trust_t trust;
	uint32_t ntypes = 0;
	dns_rdatatype_t rdtype = DNS_TYPEPAIR_TYPE(newheader->typepair);
	dns_rdatatype_t covers = DNS_TYPEPAIR_COVERS(newheader->typepair);
	ftc_search_t search = (ftc_search_t){
		.ftdb = ftdb,
		.now = now,
	};

	REQUIRE(rdtype != dns_rdatatype_none);
	if (dns_rdatatype_issig(rdtype)) {
		/* signature must be either negative or cover something */
		REQUIRE(NEGATIVE(newheader) || covers != dns_rdatatype_none);
	} else {
		/* non-signature it must cover nothing */
		REQUIRE(covers == dns_rdatatype_none);
	}
	/* positive header can't be for type ANY */
	REQUIRE(rdtype != dns_rdatatype_any || NEGATIVE(newheader));

	if ((options & DNS_DBADD_FORCE) != 0) {
		trust = dns_trust_ultimate;
	} else {
		trust = newheader->trust;
	}

	DNS_SLABHEADER_FOREACH(header, &qpnode->headers) {
		if (EXISTS(newheader) && NEGATIVE(newheader)) {
			if (rdtype == dns_rdatatype_any) {
				/*
				 * We're adding a negative cache entry which
				 * covers all types (NXDOMAIN,
				 * NODATA(QTYPE=ANY)).
				 *
				 * Delete all other data so that the only
				 * rdataset that can be found at this node is
				 * the negative cache entry.
				 */
				header_delete(qpnode, header);
				continue;
			} else if (rdtype == dns_rdatatype_rrsig) {
				/*
				 * We're adding a proof that a signature doesn't
				 * exist.
				 *
				 * Delete all existing signatures.
				 */
				if (DNS_TYPEPAIR_TYPE(header->typepair) ==
				    dns_rdatatype_rrsig)
				{
					header_delete(qpnode, header);
					continue;
				}
			}
		}
		if (EXISTS(header) && EXISTS(newheader) && NEGATIVE(header) &&
		    !NEGATIVE(newheader) && ACTIVE(header, now))
		{
			/*
			 * There's an existing NXDOMAIN or negative
			 * covered type in the cache. If it's more
			 * trusted than the new data, keep it, but
			 * if not, purge and replace it.
			 */
			isc_result_t result = check_ncache_block(
				ftdb, qpnode, header, newheader, trust,
				addedrdataset, now, nlocktype);
			if (result == DNS_R_UNCHANGED) {
				return result;
			}
			if (result == DNS_R_CONTINUE) {
				/* the header has been invalidated */
				continue;
			}
			INSIST(result == ISC_R_SUCCESS);
		}

		if (check_stale_header(header, &search)) {
			header_delete(qpnode, header);
			continue;
		}

		++ntypes;

		if (prio_header(header)) {
			prioheader = header;
		}

		if (header->typepair == newheader->typepair) {
			INSIST(oldheader == NULL);
			oldheader = header;
		}

		if ((rdtype == dns_rdatatype_rrsig &&
		     DNS_TYPEPAIR_TYPE(header->typepair) == covers) ||
		    header->typepair == DNS_SIGTYPEPAIR(rdtype))
		{
			INSIST(related == NULL);
			related = header;
		}

		/*
		 * This simple condition works here because:
		 *
		 * 1. if related is the last header then we won't progress
		 * evictheader
		 *
		 * 2. if related is not the last header then we progress
		 * evictheader.
		 */
		if (header != related) {
			evictheader = header;
		}
	}

	if (oldheader != NULL) {
		/*
		 * Deleting an already non-existent rdataset has no effect.
		 */
		if (!EXISTS(oldheader) && !EXISTS(newheader)) {
			return DNS_R_UNCHANGED;
		}

		/*
		 * Trying to add an rdataset with lower trust to a cache
		 * DB has no effect, provided that the cache data isn't
		 * stale. If the cache data is stale, new lower trust
		 * data will supersede it below. Unclear what the best
		 * policy is here.
		 */
		dns_trust_t oldtrust = atomic_load(&oldheader->trust);
		if (trust < oldtrust &&
		    (ACTIVE(oldheader, now) || !EXISTS(oldheader)))
		{
			ftcache_hit(ftdb, oldheader);
			bindrdataset(ftdb, qpnode, oldheader, now, nlocktype,
				     addedrdataset DNS__DB_FLARG_PASS);
			if (ACTIVE(oldheader, now) &&
			    (options & DNS_DBADD_EQUALOK) != 0 &&
			    dns_rdataslab_equalx(
				    oldheader, newheader, ftdb->common.rdclass,
				    DNS_TYPEPAIR_TYPE(oldheader->typepair)))
			{
				/*
				 * Updated by caller to ISC_R_SUCCESS after
				 * cleaning up newheader.
				 */
				return ISC_R_EXISTS;
			}
			return DNS_R_UNCHANGED;
		}

		/*
		 * Don't replace existing NS in the cache if they already exist
		 * and replacing the existing one would increase the TTL. This
		 * prevents named being locked to old servers. Don't lower trust
		 * of existing record if the update is forced. Nothing special
		 * to be done w.r.t stale data; it gets replaced normally
		 * further down.
		 */
		if (ACTIVE(oldheader, now) &&
		    oldheader->typepair == DNS_TYPEPAIR(dns_rdatatype_ns) &&
		    EXISTS(oldheader) && EXISTS(newheader) &&
		    newheader->trust < oldtrust &&
		    oldheader->expire < newheader->expire &&
		    dns_rdataslab_equalx(
			    oldheader, newheader, ftdb->common.rdclass,
			    DNS_TYPEPAIR_TYPE(oldheader->typepair)))
		{
			if (oldheader->noqname == NULL &&
			    newheader->noqname != NULL)
			{
				oldheader->noqname = newheader->noqname;
				newheader->noqname = NULL;
			}
			if (oldheader->closest == NULL &&
			    newheader->closest != NULL)
			{
				oldheader->closest = newheader->closest;
				newheader->closest = NULL;
			}

			ftcache_hit(ftdb, oldheader);
			bindrdataset(ftdb, qpnode, oldheader, now, nlocktype,
				     addedrdataset DNS__DB_FLARG_PASS);
			if ((options & DNS_DBADD_EQUALOK) != 0) {
				/*
				 * Updated by caller to ISC_R_SUCCESS after
				 * cleaning up newheader.
				 */
				return ISC_R_EXISTS;
			}
			return DNS_R_UNCHANGED;
		}

		/*
		 * If we will be replacing an NS RRset, force its TTL
		 * to be no more than the current NS RRset's TTL.  This
		 * ensures the delegations that are withdrawn are honoured.
		 */
		if (ACTIVE(oldheader, now) &&
		    oldheader->typepair == DNS_TYPEPAIR(dns_rdatatype_ns) &&
		    EXISTS(oldheader) && EXISTS(newheader) &&
		    newheader->trust > oldtrust)
		{
			if (newheader->expire > oldheader->expire) {
				if (ZEROTTL(oldheader)) {
					DNS_SLABHEADER_SETATTR(
						newheader,
						DNS_SLABHEADERATTR_ZEROTTL);
				}
				newheader->expire = oldheader->expire;
			}
		}
		if (ACTIVE(oldheader, now) &&
		    (options & DNS_DBADD_PREFETCH) == 0 &&
		    (oldheader->typepair == DNS_TYPEPAIR(dns_rdatatype_a) ||
		     oldheader->typepair == DNS_TYPEPAIR(dns_rdatatype_aaaa) ||
		     oldheader->typepair == DNS_TYPEPAIR(dns_rdatatype_ds) ||
		     oldheader->typepair ==
			     DNS_SIGTYPEPAIR(dns_rdatatype_ds)) &&
		    EXISTS(oldheader) && EXISTS(newheader) &&
		    newheader->trust < oldtrust &&
		    oldheader->expire < newheader->expire &&
		    dns_rdataslab_equal(oldheader, newheader))
		{
			if (oldheader->noqname == NULL &&
			    newheader->noqname != NULL)
			{
				oldheader->noqname = newheader->noqname;
				newheader->noqname = NULL;
			}
			if (oldheader->closest == NULL &&
			    newheader->closest != NULL)
			{
				oldheader->closest = newheader->closest;
				newheader->closest = NULL;
			}

			ftcache_hit(ftdb, oldheader);
			bindrdataset(ftdb, qpnode, oldheader, now, nlocktype,
				     addedrdataset DNS__DB_FLARG_PASS);
			if ((options & DNS_DBADD_EQUALOK) != 0) {
				/*
				 * Updated by caller to ISC_R_SUCCESS after
				 * cleaning up newheader.
				 */
				return ISC_R_EXISTS;
			}
			return DNS_R_UNCHANGED;
		}

		INSIST(oldheader->related == related);
		header_delete(qpnode, oldheader);

	} else if (!EXISTS(newheader)) {
		/*
		 * The type already doesn't exist; no point trying
		 * to delete it.
		 */
		return DNS_R_UNCHANGED;
	}

	/*
	 * No rdatasets of the given type exist at the node or we removed the
	 * oldheader.
	 */

	if (prio_header(newheader)) {
		/* This is a priority type, prepend it */
		cds_list_add(&newheader->headers_link, &qpnode->headers);
	} else if (prioheader != NULL) {
		/* Append after the priority headers */
		cds_list_add(&newheader->headers_link,
			     &prioheader->headers_link);
	} else {
		/* There were no priority headers */
		cds_list_add(&newheader->headers_link, &qpnode->headers);
	}

	if (related != NULL) {
		INSIST(related->related == NULL);
		/* protect the related from LRU eviction */
		ftcache_hit(ftdb, related);
		related->related = dns_slabheader_ref(newheader);
		newheader->related = dns_slabheader_ref(related);
	}

	bindrdataset(ftdb, qpnode, newheader, now, nlocktype,
		     addedrdataset DNS__DB_FLARG_PASS);

	if (oldheader == NULL && overmaxtype(ftdb, ntypes)) {
		INSIST(evictheader != newheader);

		if (evictheader != NULL) {
			INSIST(evictheader->related != newheader);
			if (evictheader->related != NULL) {
				header_delete(qpnode, evictheader->related);
			}
			header_delete(qpnode, evictheader);
		}
	}

	ftcache_miss(ftdb, newheader, &nlocktype, iter DNS__DB_FLARG_PASS);

	/*
	 * We've added a proof that a rdtype doesn't exist.
	 *
	 * Delete the related rrsig in the cache.
	 */
	if (EXISTS(newheader) && NEGATIVE(newheader) &&
	    !dns_rdatatype_issig(rdtype) && related != NULL)
	{
		header_delete(qpnode, related);
	}

	return ISC_R_SUCCESS;
}

static isc_result_t
addnoqname(isc_mem_t *mctx, dns_slabheader_t *newheader, uint32_t maxrrperset,
	   dns_rdataset_t *rdataset) {
	isc_result_t result;
	dns_slabheader_proof_t *noqname = NULL;
	dns_name_t name = DNS_NAME_INITEMPTY;
	dns_rdataset_t neg = DNS_RDATASET_INIT, negsig = DNS_RDATASET_INIT;
	isc_region_t r1 = { .base = NULL }, r2 = { .base = NULL };

	result = dns_rdataset_getnoqname(rdataset, &name, &neg, &negsig);
	RUNTIME_CHECK(result == ISC_R_SUCCESS);

	CHECK(dns_rdataslab_fromrdataset(&neg, mctx, &r1, maxrrperset));

	CHECK(dns_rdataslab_fromrdataset(&negsig, mctx, &r2, maxrrperset));

	noqname = isc_mem_get(mctx, sizeof(*noqname));
	*noqname = (dns_slabheader_proof_t){
		.neg = ((dns_slabheader_t *)r1.base)->raw,
		.negsig = ((dns_slabheader_t *)r2.base)->raw,
		.type = neg.type,
		.name = DNS_NAME_INITEMPTY,
	};
	dns_name_dup(&name, mctx, &noqname->name);
	newheader->noqname = noqname;

cleanup:
	if (result != ISC_R_SUCCESS) {
		if (r1.base != NULL) {
			dns_slabheader_t *header = (dns_slabheader_t *)r1.base;
			dns_slabheader_detach(&header);
		}
		if (r2.base != NULL) {
			dns_slabheader_t *header = (dns_slabheader_t *)r2.base;
			dns_slabheader_detach(&header);
		}
	}
	dns_rdataset_disassociate(&neg);
	dns_rdataset_disassociate(&negsig);

	return result;
}

static isc_result_t
addclosest(isc_mem_t *mctx, dns_slabheader_t *newheader, uint32_t maxrrperset,
	   dns_rdataset_t *rdataset) {
	isc_result_t result;
	dns_slabheader_proof_t *closest = NULL;
	dns_name_t name = DNS_NAME_INITEMPTY;
	dns_rdataset_t neg = DNS_RDATASET_INIT, negsig = DNS_RDATASET_INIT;
	isc_region_t r1 = { .base = NULL }, r2 = { .base = NULL };

	result = dns_rdataset_getclosest(rdataset, &name, &neg, &negsig);
	RUNTIME_CHECK(result == ISC_R_SUCCESS);

	CHECK(dns_rdataslab_fromrdataset(&neg, mctx, &r1, maxrrperset));

	CHECK(dns_rdataslab_fromrdataset(&negsig, mctx, &r2, maxrrperset));

	closest = isc_mem_get(mctx, sizeof(*closest));
	*closest = (dns_slabheader_proof_t){
		.neg = ((dns_slabheader_t *)r1.base)->raw,
		.negsig = ((dns_slabheader_t *)r2.base)->raw,
		.name = DNS_NAME_INITEMPTY,
		.type = neg.type,
	};
	dns_name_dup(&name, mctx, &closest->name);
	newheader->closest = closest;

cleanup:
	if (result != ISC_R_SUCCESS) {
		if (r1.base != NULL) {
			dns_slabheader_t *header = (dns_slabheader_t *)r1.base;
			dns_slabheader_detach(&header);
		}
		if (r2.base != NULL) {
			dns_slabheader_t *header = (dns_slabheader_t *)r2.base;
			dns_slabheader_detach(&header);
		}
	}
	dns_rdataset_disassociate(&neg);
	dns_rdataset_disassociate(&negsig);
	return result;
}

static isc_result_t
ftcache_addrdataset(dns_db_t *db, dns_dbnode_t *node, dns_dbversion_t *version,
		    isc_stdtime_t __now, dns_rdataset_t *rdataset,
		    unsigned int options,
		    dns_rdataset_t *addedrdataset DNS__DB_FLARG) {
	ftcache_t *ftdb = (ftcache_t *)db;
	ftcnode_t *qpnode = (ftcnode_t *)node;
	isc_region_t region;
	dns_slabheader_t *newheader = NULL;
	isc_result_t result;
	bool newnsec = false;
	isc_rwlocktype_t nlocktype = isc_rwlocktype_none;
	isc_rwlock_t *nlock = NULL;
	dns_fixedname_t fixed;
	dns_name_t *name = NULL;
	isc_stdtime_t now = __now ? __now : isc_stdtime_now();

	REQUIRE(VALID_FTDB(ftdb));
	REQUIRE(version == NULL);

	result = dns_rdataslab_fromrdataset(rdataset, qpnode->mctx, &region,
					    ftdb->maxrrperset);
	if (result != ISC_R_SUCCESS) {
		if (result == DNS_R_TOOMANYRECORDS) {
			dns__db_logtoomanyrecords((dns_db_t *)ftdb,
						  &qpnode->name, rdataset->type,
						  "adding", ftdb->maxrrperset);
		}
		return result;
	}

	name = dns_fixedname_initname(&fixed);
	dns_name_copy(&qpnode->name, name);
	dns_rdataset_getownercase(rdataset, name);

	newheader = (dns_slabheader_t *)region.base;
	dns_slabheader_reset(newheader, node);

	/*
	 * Set the correct expire time.
	 */
	setttl(newheader, now + rdataset->ttl);
	if (rdataset->ttl == 0U) {
		DNS_SLABHEADER_SETATTR(newheader, DNS_SLABHEADERATTR_ZEROTTL);
	}

	if (rdataset->attributes.prefetch) {
		DNS_SLABHEADER_SETATTR(newheader, DNS_SLABHEADERATTR_PREFETCH);
	}
	if (rdataset->attributes.negative) {
		DNS_SLABHEADER_SETATTR(newheader, DNS_SLABHEADERATTR_NEGATIVE);
	}
	if (rdataset->attributes.nxdomain) {
		DNS_SLABHEADER_SETATTR(newheader, DNS_SLABHEADERATTR_NXDOMAIN);
	}
	if (rdataset->attributes.optout) {
		DNS_SLABHEADER_SETATTR(newheader, DNS_SLABHEADERATTR_OPTOUT);
	}
	if (rdataset->attributes.noqname) {
		CHECK(addnoqname(newheader->mctx, newheader, ftdb->maxrrperset,
				 rdataset));
	}
	if (rdataset->attributes.closest) {
		CHECK(addclosest(newheader->mctx, newheader, ftdb->maxrrperset,
				 rdataset));
	}

	nlock = &ftdb->buckets[qpnode->locknum].lock;

	/*
	 * Add to the auxiliary NSEC tree if we're adding an NSEC record.
	 */
	if (rdataset->type == dns_rdatatype_nsec) {
		NODE_RDLOCK(nlock, &nlocktype);
		if (!qpnode->havensec) {
			newnsec = true;
		}
		NODE_UNLOCK(nlock, &nlocktype);
	}

	struct cds_ft_iter *iter = NULL;
	if (newnsec) {
		LOCK(&ftdb->wmutex);
		RUNTIME_CHECK(cds_ft_iter_create(ftdb->ft, &iter) ==
			      CDS_FT_STATUS_OK);
	}

	NODE_WRLOCK(nlock, &nlocktype);

	if (newnsec && !qpnode->havensec) {
		ftcnode_t *nsecnode = NULL;

		if (ftc_lookup(ftdb->ft, name, DNS_DBNAMESPACE_NSEC,
			       &nsecnode) != ISC_R_SUCCESS) {
			dns_qpkey_t key;
			size_t keylen = dns_qpkey_fromname(
				key, name, DNS_DBNAMESPACE_NSEC);

			nsecnode = new_ftcnode(ftdb, name,
					       DNS_DBNAMESPACE_NSEC);
			RUNTIME_CHECK(cds_ft_insert_unique(
					      ftdb->ft, key, keylen,
					      &nsecnode->ftnode, NULL) ==
				      CDS_FT_STATUS_OK);
			/* the creation reference becomes the trie's */
		}
		qpnode->havensec = true;
	}

	result = add(ftdb, qpnode, newheader, options, addedrdataset, now,
		     nlocktype, iter DNS__DB_FLARG_PASS);

	if (result == ISC_R_SUCCESS) {
		DNS_SLABHEADER_SETATTR(newheader, DNS_SLABHEADERATTR_STATCOUNT);
		update_rrsetstats(ftdb->rrsetstats, newheader->typepair,
				  newheader->attributes, true);
	} else {
		dns_slabheader_detach(&newheader);
	}

	NODE_UNLOCK(nlock, &nlocktype);

	if (newnsec) {
		cds_ft_iter_destroy(iter);
		UNLOCK(&ftdb->wmutex);
	}

	if (result == ISC_R_EXISTS) {
		result = ISC_R_SUCCESS;
	}

	return result;
cleanup:
	dns_slabheader_detach(&newheader);
	return result;
}

static isc_result_t
ftcache_deleterdataset(dns_db_t *db, dns_dbnode_t *node,
		       dns_dbversion_t *version, dns_rdatatype_t type,
		       dns_rdatatype_t covers DNS__DB_FLARG) {
	ftcache_t *ftdb = (ftcache_t *)db;
	ftcnode_t *qpnode = (ftcnode_t *)node;
	isc_result_t result;
	dns_slabheader_t *newheader = NULL;
	isc_rwlocktype_t nlocktype = isc_rwlocktype_none;
	isc_rwlock_t *nlock = NULL;
	uint16_t attributes = DNS_SLABHEADERATTR_NONEXISTENT;

	REQUIRE(VALID_FTDB(ftdb));
	REQUIRE(version == NULL);

	/* Positive ANY type can't be in the cache. */
	if (type == dns_rdatatype_any) {
		return ISC_R_NOTIMPLEMENTED;
	}

	/* Convert the negative type into positive type. */
	if (type == dns_rdatatype_none && covers != dns_rdatatype_none) {
		type = covers;
		covers = dns_rdatatype_none;
		attributes |= DNS_SLABHEADERATTR_NEGATIVE;
	}

	newheader = dns_slabheader_new(db->mctx, node);
	newheader->typepair = DNS_TYPEPAIR_VALUE(type, covers);
	setttl(newheader, 0);
	atomic_init(&newheader->attributes, attributes);

	nlock = &ftdb->buckets[qpnode->locknum].lock;
	NODE_WRLOCK(nlock, &nlocktype);
	result = add(ftdb, qpnode, newheader, DNS_DBADD_FORCE, NULL, 0,
		     nlocktype, NULL DNS__DB_FLARG_PASS);
	if (result != ISC_R_SUCCESS) {
		dns_slabheader_detach(&newheader);
	}
	NODE_UNLOCK(nlock, &nlocktype);

	return result;
}

static unsigned int
nodecount(dns_db_t *db) {
	ftcache_t *ftdb = (ftcache_t *)db;
	unsigned int count;

	REQUIRE(VALID_FTDB(ftdb));

	rcu_read_lock();
	count = (unsigned int)cds_ft_count_keys(ftdb->ft);
	rcu_read_unlock();

	return count;
}

isc_result_t
dns__ftcache_create(isc_mem_t *mctx, const dns_name_t *origin,
		    dns_dbtype_t type, dns_rdataclass_t rdclass,
		    unsigned int argc, char *argv[],
		    void *driverarg ISC_ATTR_UNUSED, dns_db_t **dbp) {
	ftcache_t *ftdb = NULL;
	isc_loop_t *loop = isc_loop();
	int i;
	size_t nloops = isc_loopmgr_nloops();

	/* This database implementation only supports cache semantics */
	REQUIRE(type == dns_dbtype_cache);
	REQUIRE(loop != NULL);
	REQUIRE(argc == 0);
	REQUIRE(argv == NULL);

	ftdb = isc_mem_get(mctx,
			   sizeof(*ftdb) + nloops * sizeof(ftdb->buckets[0]));
	*ftdb = (ftcache_t){
		.common.methods = &ftdb_cachemethods,
		.common.origin = DNS_NAME_INITEMPTY,
		.common.rdclass = rdclass,
		.common.attributes = DNS_DBATTR_CACHE,
		.common.references = 1,
		.references = 1,
		.buckets_count = nloops,
	};

	isc_rwlock_init(&ftdb->lock);

	ftdb->buckets_count = isc_loopmgr_nloops();

	dns_rdatasetstats_create(mctx, &ftdb->rrsetstats);
	for (i = 0; i < (int)ftdb->buckets_count; i++) {
		ISC_SIEVE_INIT(ftdb->buckets[i].sieve);

		isc_queue_init(&ftdb->buckets[i].deadnodes);

		NODE_INITLOCK(&ftdb->buckets[i].lock);
	}

	/*
	 * Attach to the mctx.  The database will persist so long as there
	 * are references to it, and attaching to the mctx ensures that our
	 * mctx won't disappear out from under us.
	 */
	isc_mem_attach(mctx, &ftdb->common.mctx);

	/*
	 * Make a copy of the origin name.
	 */
	dns_name_dup(origin, mctx, &ftdb->common.origin);

	/*
	 * Make the cds_ft trie: a single variable-length-key trie in its
	 * own group, with a mutex serialising structural writes.
	 */
	isc_mutex_init(&ftdb->wmutex);
	{
		struct cds_ft_group_attr *attr = NULL;
		RUNTIME_CHECK(cds_ft_group_attr_create(&attr) ==
			      CDS_FT_STATUS_OK);
		RUNTIME_CHECK(cds_ft_group_attr_set_key_len(
				      attr, CDS_FT_LEN_VARIABLE) ==
			      CDS_FT_STATUS_OK);
		RUNTIME_CHECK(cds_ft_group_attr_set_max_key_len(
				      attr, DNS_QP_MAXKEY) == CDS_FT_STATUS_OK);
		RUNTIME_CHECK(cds_ft_group_create(attr, &ftdb->ftgroup) ==
			      CDS_FT_STATUS_OK);
		cds_ft_group_attr_destroy(attr);
	}
	RUNTIME_CHECK(cds_ft_create(ftdb->ftgroup, NULL, &ftdb->ft) ==
		      CDS_FT_STATUS_OK);

	ftdb->common.magic = DNS_DB_MAGIC;
	ftdb->common.impmagic = FTDB_MAGIC;

	*dbp = (dns_db_t *)ftdb;

	return ISC_R_SUCCESS;
}

/*
 * Rdataset Iterator Methods
 */

static void
rdatasetiter_destroy(dns_rdatasetiter_t **iteratorp DNS__DB_FLARG) {
	ftc_rditer_t *iterator = NULL;

	iterator = (ftc_rditer_t *)(*iteratorp);

	ISC_LIST_FOREACH(iterator->rdatasets, rdataset, link) {
		dns_rdataset_disassociate(rdataset);
		isc_mem_put(iterator->common.db->mctx, rdataset,
			    sizeof(*rdataset));
	}

	dns__db_detachnode(&iterator->common.node DNS__DB_FLARG_PASS);
	isc_mem_put(iterator->common.db->mctx, iterator, sizeof(*iterator));

	*iteratorp = NULL;
}

static isc_result_t
rdatasetiter_first(dns_rdatasetiter_t *it DNS__DB_FLARG) {
	ftc_rditer_t *iterator = (ftc_rditer_t *)it;

	iterator->current = ISC_LIST_HEAD(iterator->rdatasets);

	if (iterator->current == NULL) {
		return ISC_R_NOMORE;
	}

	return ISC_R_SUCCESS;
}

static isc_result_t
rdatasetiter_next(dns_rdatasetiter_t *it DNS__DB_FLARG) {
	ftc_rditer_t *iterator = (ftc_rditer_t *)it;

	if (iterator->current == NULL) {
		return ISC_R_NOMORE;
	}

	iterator->current = ISC_LIST_NEXT(iterator->current, link);

	if (iterator->current == NULL) {
		return ISC_R_NOMORE;
	}

	return ISC_R_SUCCESS;
}

static void
rdatasetiter_current(dns_rdatasetiter_t *it,
		     dns_rdataset_t *rdataset DNS__DB_FLARG) {
	ftc_rditer_t *iterator = (ftc_rditer_t *)it;

	REQUIRE(iterator->current != NULL);

	dns_rdataset_clone(iterator->current, rdataset);
}

/*
 * Database Iterator Methods
 */

static ftcnode_t *
ftc_iter_node(struct cds_ft_iter *iter) {
	struct cds_ft_node *ftn = cds_ft_iter_node(iter);
	return (ftn == NULL) ? NULL : caa_container_of(ftn, ftcnode_t, ftnode);
}

static void
reference_iter_node(ftc_dbit_t *ftdbiter DNS__DB_FLARG) {
	ftcache_t *ftdb = (ftcache_t *)ftdbiter->common.db;
	ftcnode_t *node = ftdbiter->node;

	if (node == NULL) {
		return;
	}

	isc_rwlocktype_t nlocktype = isc_rwlocktype_none;
	isc_rwlock_t *nlock = &ftdb->buckets[node->locknum].lock;

	NODE_RDLOCK(nlock, &nlocktype);
	ftcnode_acquire(ftdb, node, nlocktype DNS__DB_FLARG_PASS);
	NODE_UNLOCK(nlock, &nlocktype);
}

static void
dereference_iter_node(ftc_dbit_t *ftdbiter DNS__DB_FLARG) {
	ftcache_t *ftdb = (ftcache_t *)ftdbiter->common.db;
	ftcnode_t *node = ftdbiter->node;
	isc_rwlock_t *nlock = NULL;
	isc_rwlocktype_t nlocktype = isc_rwlocktype_none;

	if (node == NULL) {
		return;
	}

	nlock = &ftdb->buckets[node->locknum].lock;
	NODE_RDLOCK(nlock, &nlocktype);
	ftcnode_release(ftdb, node, &nlocktype, NULL DNS__DB_FLARG_PASS);
	NODE_UNLOCK(nlock, &nlocktype);

	ftdbiter->node = NULL;
}

static void
resume_iteration(ftc_dbit_t *ftdbiter, bool continuing) {
	REQUIRE(ftdbiter->paused);

	/*
	 * If we're being called from dbiterator_next, we may need
	 * to reinitialize the iterator to the current name. The
	 * tree could have changed while it was unlocked, which
	 * would make the iterator traversal inconsistent.
	 *
	 * As long as the iterator is holding a reference to
	 * ftdbiter->node, the node won't be removed from the tree,
	 * so the lookup should always succeed.
	 */
	if (continuing && ftdbiter->node != NULL) {
		ftcache_t *ftdb = (ftcache_t *)ftdbiter->common.db;
		dns_qpkey_t key;
		size_t keylen = dns_qpkey_fromname(key, ftdbiter->name,
						   DNS_DBNAMESPACE_NORMAL);
		rcu_read_lock();
		cds_ft_iter_set_key(ftdbiter->iter, key, keylen);
		RUNTIME_CHECK(cds_ft_lookup_ge(ftdb->ft, ftdbiter->iter) ==
			      CDS_FT_STATUS_OK);
		rcu_read_unlock();
	}

	ftdbiter->paused = false;
}

static void
dbiterator_destroy(dns_dbiterator_t **iteratorp DNS__DB_FLARG) {
	ftc_dbit_t *ftdbiter = (ftc_dbit_t *)(*iteratorp);
	dns_db_t *db = NULL;

	cds_ft_iter_destroy(ftdbiter->iter);

	dereference_iter_node(ftdbiter DNS__DB_FLARG_PASS);

	dns_db_attach(ftdbiter->common.db, &db);
	dns_db_detach(&ftdbiter->common.db);

	isc_mem_put(db->mctx, ftdbiter, sizeof(*ftdbiter));
	dns_db_detach(&db);

	*iteratorp = NULL;
}

static isc_result_t
dbiterator_first(dns_dbiterator_t *iterator DNS__DB_FLARG) {
	isc_result_t result;
	ftc_dbit_t *ftdbiter = (ftc_dbit_t *)iterator;

	if (ftdbiter->result != ISC_R_SUCCESS &&
	    ftdbiter->result != ISC_R_NOTFOUND &&
	    ftdbiter->result != DNS_R_PARTIALMATCH &&
	    ftdbiter->result != ISC_R_NOMORE)
	{
		return ftdbiter->result;
	}

	if (ftdbiter->paused) {
		resume_iteration(ftdbiter, false);
	}

	dereference_iter_node(ftdbiter DNS__DB_FLARG_PASS);

	ftcache_t *ftdb = (ftcache_t *)ftdbiter->common.db;

	rcu_read_lock();
	if (cds_ft_lookup_first(ftdb->ft, ftdbiter->iter) == CDS_FT_STATUS_OK) {
		ftdbiter->node = ftc_iter_node(ftdbiter->iter);
	} else {
		ftdbiter->node = NULL;
	}

	if (ftdbiter->node != NULL &&
	    ftdbiter->node->nspace == DNS_DBNAMESPACE_NORMAL)
	{
		dns_name_copy(&ftdbiter->node->name, ftdbiter->name);
		reference_iter_node(ftdbiter DNS__DB_FLARG_PASS);
		result = ISC_R_SUCCESS;
	} else if (ftdbiter->node != NULL) {
		/* Crossed out of the normal namespace. */
		result = ISC_R_NOMORE;
		ftdbiter->node = NULL;
	} else {
		/* The tree is empty. */
		result = ISC_R_NOMORE;
		ftdbiter->node = NULL;
	}
	rcu_read_unlock();

	ftdbiter->result = result;

	if (result != ISC_R_SUCCESS) {
		ENSURE(!ftdbiter->paused);
	}

	return result;
}

static isc_result_t
dbiterator_last(dns_dbiterator_t *iterator ISC_ATTR_UNUSED DNS__DB_FLARG) {
	return ISC_R_NOTIMPLEMENTED;
}

static isc_result_t
dbiterator_seek(dns_dbiterator_t *iterator,
		const dns_name_t *name DNS__DB_FLARG) {
	isc_result_t result;
	ftc_dbit_t *ftdbiter = (ftc_dbit_t *)iterator;

	if (ftdbiter->result != ISC_R_SUCCESS &&
	    ftdbiter->result != ISC_R_NOTFOUND &&
	    ftdbiter->result != DNS_R_PARTIALMATCH &&
	    ftdbiter->result != ISC_R_NOMORE)
	{
		return ftdbiter->result;
	}

	if (ftdbiter->paused) {
		resume_iteration(ftdbiter, false);
	}

	dereference_iter_node(ftdbiter DNS__DB_FLARG_PASS);

	ftcache_t *ftdb = (ftcache_t *)ftdbiter->common.db;
	dns_qpkey_t key;
	size_t keylen = dns_qpkey_fromname(key, name, DNS_DBNAMESPACE_NORMAL);

	rcu_read_lock();
	cds_ft_iter_set_key(ftdbiter->iter, key, keylen);
	if (cds_ft_lookup_ge(ftdb->ft, ftdbiter->iter) == CDS_FT_STATUS_OK) {
		ftdbiter->node = ftc_iter_node(ftdbiter->iter);
	} else {
		ftdbiter->node = NULL;
	}

	if (ftdbiter->node != NULL &&
	    ftdbiter->node->nspace == DNS_DBNAMESPACE_NORMAL)
	{
		bool exact = dns_name_equal(name, &ftdbiter->node->name);
		dns_name_copy(&ftdbiter->node->name, ftdbiter->name);
		reference_iter_node(ftdbiter DNS__DB_FLARG_PASS);
		result = exact ? ISC_R_SUCCESS : DNS_R_PARTIALMATCH;
	} else {
		result = ISC_R_NOMORE;
		ftdbiter->node = NULL;
	}
	rcu_read_unlock();

	ftdbiter->result = (result == DNS_R_PARTIALMATCH) ? ISC_R_SUCCESS
							  : result;
	return result;
}

static isc_result_t
dbiterator_seek3(dns_dbiterator_t *iterator ISC_ATTR_UNUSED,
		 const dns_name_t *name ISC_ATTR_UNUSED DNS__DB_FLARG) {
	return ISC_R_NOTIMPLEMENTED;
}

static isc_result_t
dbiterator_prev(dns_dbiterator_t *iterator ISC_ATTR_UNUSED DNS__DB_FLARG) {
	return ISC_R_NOTIMPLEMENTED;
}

static isc_result_t
dbiterator_next(dns_dbiterator_t *iterator DNS__DB_FLARG) {
	isc_result_t result;
	ftc_dbit_t *ftdbiter = (ftc_dbit_t *)iterator;

	REQUIRE(ftdbiter->node != NULL);

	if (ftdbiter->result != ISC_R_SUCCESS) {
		return ftdbiter->result;
	}

	if (ftdbiter->paused) {
		resume_iteration(ftdbiter, true);
	}

	dereference_iter_node(ftdbiter DNS__DB_FLARG_PASS);

	ftcache_t *ftdb = (ftcache_t *)ftdbiter->common.db;

	rcu_read_lock();
	if (cds_ft_next(ftdb->ft, ftdbiter->iter) == CDS_FT_STATUS_OK) {
		ftdbiter->node = ftc_iter_node(ftdbiter->iter);
	} else {
		ftdbiter->node = NULL;
	}

	if (ftdbiter->node != NULL &&
	    ftdbiter->node->nspace == DNS_DBNAMESPACE_NORMAL)
	{
		dns_name_copy(&ftdbiter->node->name, ftdbiter->name);
		reference_iter_node(ftdbiter DNS__DB_FLARG_PASS);
		result = ISC_R_SUCCESS;
	} else if (ftdbiter->node != NULL) {
		/* Crossed out of the normal namespace. */
		result = ISC_R_NOMORE;
		ftdbiter->node = NULL;
	} else {
		result = ISC_R_NOMORE;
		ftdbiter->node = NULL;
	}
	rcu_read_unlock();

	ftdbiter->result = result;
	return result;
}

static isc_result_t
dbiterator_current(dns_dbiterator_t *iterator, dns_dbnode_t **nodep,
		   dns_name_t *name DNS__DB_FLARG) {
	ftcache_t *ftdb = (ftcache_t *)iterator->db;
	ftc_dbit_t *ftdbiter = (ftc_dbit_t *)iterator;
	ftcnode_t *node = ftdbiter->node;

	REQUIRE(ftdbiter->result == ISC_R_SUCCESS);
	REQUIRE(node != NULL);

	if (ftdbiter->paused) {
		resume_iteration(ftdbiter, false);
	}

	if (name != NULL) {
		dns_name_copy(&node->name, name);
	}

	ftcnode_acquire(ftdb, node, isc_rwlocktype_none DNS__DB_FLARG_PASS);

	*nodep = (dns_dbnode_t *)ftdbiter->node;
	return ISC_R_SUCCESS;
}

static isc_result_t
dbiterator_pause(dns_dbiterator_t *iterator) {
	ftc_dbit_t *ftdbiter = (ftc_dbit_t *)iterator;

	if (ftdbiter->result != ISC_R_SUCCESS &&
	    ftdbiter->result != ISC_R_NOTFOUND &&
	    ftdbiter->result != DNS_R_PARTIALMATCH &&
	    ftdbiter->result != ISC_R_NOMORE)
	{
		return ftdbiter->result;
	}

	if (ftdbiter->paused) {
		return ISC_R_SUCCESS;
	}

	ftdbiter->paused = true;

	return ISC_R_SUCCESS;
}

static isc_result_t
dbiterator_origin(dns_dbiterator_t *iterator, dns_name_t *name) {
	ftc_dbit_t *ftdbiter = (ftc_dbit_t *)iterator;

	if (ftdbiter->result != ISC_R_SUCCESS) {
		return ftdbiter->result;
	}

	dns_name_copy(dns_rootname, name);
	return ISC_R_SUCCESS;
}

static void
setmaxrrperset(dns_db_t *db, uint32_t value) {
	ftcache_t *ftdb = (ftcache_t *)db;

	REQUIRE(VALID_FTDB(ftdb));

	ftdb->maxrrperset = value;
}

static void
setmaxtypepername(dns_db_t *db, uint32_t value) {
	ftcache_t *ftdb = (ftcache_t *)db;

	REQUIRE(VALID_FTDB(ftdb));

	ftdb->maxtypepername = value;
}

static dns_dbmethods_t ftdb_cachemethods = {
	.destroy = ftcache_destroy,
	.findnode = ftcache_findnode,
	.find = ftcache_find,
	.createiterator = ftcache_createiterator,
	.findrdataset = ftcache_findrdataset,
	.allrdatasets = ftcache_allrdatasets,
	.addrdataset = ftcache_addrdataset,
	.deleterdataset = ftcache_deleterdataset,
	.nodecount = nodecount,
	.getrrsetstats = getrrsetstats,
	.setcachestats = setcachestats,
	.setservestalettl = setservestalettl,
	.getservestalettl = getservestalettl,
	.setservestalerefresh = setservestalerefresh,
	.getservestalerefresh = getservestalerefresh,
	.setmaxrrperset = setmaxrrperset,
	.setmaxtypepername = setmaxtypepername,
};

static void
ftcnode_destroy(ftcnode_t *qpnode) {
	dns_slabheader_t *header = NULL, *header_next = NULL;
	cds_list_for_each_entry_safe(header, header_next, &qpnode->headers,
				     headers_link)
	{
		header_delete(qpnode, header);
	}

	dns_name_free(&qpnode->name, qpnode->mctx);
	isc_mem_putanddetach(&qpnode->mctx, qpnode, sizeof(ftcnode_t));
}

#ifdef DNS_DB_NODETRACE
ISC_REFCOUNT_STATIC_TRACE_IMPL(ftcnode, ftcnode_destroy);
#else
ISC_REFCOUNT_STATIC_IMPL(ftcnode, ftcnode_destroy);
#endif

#ifdef DNS_DB_NODETRACE
ISC_REFCOUNT_STATIC_TRACE_IMPL(ftcache, ftcache__destroy);
#else
ISC_REFCOUNT_STATIC_IMPL(ftcache, ftcache__destroy);
#endif
