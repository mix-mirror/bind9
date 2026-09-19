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
#include "lmdb-cache_p.h"
#include "qpcache_p.h"
#include "rdataslab_p.h"

#ifndef DNS_QPCACHE_LOG_STATS_LEVEL
#define DNS_QPCACHE_LOG_STATS_LEVEL 3
#endif

#define STALE_TTL(header, qpdb) \
	(NXDOMAIN(header) ? 0 : qpdb->common.serve_stale_ttl)

#define ACTIVE(header, now)            \
	(((header)->expire > (now)) || \
	 ((header)->expire == (now) && ZEROTTL(header)))

#define EXPIREDOK(iterator) \
	(((iterator)->common.options & DNS_DB_EXPIREDOK) != 0)

#define STALEOK(iterator) (((iterator)->common.options & DNS_DB_STALEOK) != 0)

#define KEEPSTALE(qpdb) ((qpdb)->common.serve_stale_ttl > 0)

#define QPC_RECORD_MAGIC   ISC_MAGIC('Q', 'C', 'R', '1')
#define QPC_RECORD_VERSION 1

#define QPC_CLOCK_BITS  16
#define QPC_CLOCK_SIZE  (1U << QPC_CLOCK_BITS)
#define QPC_CLOCK_MASK  (QPC_CLOCK_SIZE - 1)
#define QPC_CLOCK_REFERENCED UINT64_C(1)

/* A deliberately approximate, process-wide CLOCK sketch.  It is not an
 * LMDB membership index: collisions merely give an entry another chance. */
static _Atomic(uint64_t) qpc_clock[QPC_CLOCK_SIZE];

typedef struct qpc_record {
	uint32_t magic;
	uint16_t version;
	uint16_t attributes;
	uint32_t trust;
	uint32_t expire;
	uint32_t last_refresh_fail;
	uint16_t count;
	uint16_t proof_type;
	uint16_t proof_count;
	uint16_t proof_sig_count;
	uint32_t cache_order;
	uint32_t raw_length;
	uint32_t proof_name_length;
	uint32_t proof_length;
	uint32_t proof_sig_length;
	unsigned char data[];
} qpc_record_t;

static uint64_t
clock_fingerprint(const dns_name_t *name, dns_typepair_t typepair) {
	return dns_lmdb_rrsethash(name, DNS_DBNAMESPACE_NORMAL, typepair);
}

static void
clock_touch(const dns_name_t *name, dns_typepair_t typepair) {
	uint64_t fingerprint = clock_fingerprint(name, typepair);
	atomic_store_relaxed(&qpc_clock[(fingerprint >> 1) & QPC_CLOCK_MASK],
			     fingerprint | QPC_CLOCK_REFERENCED);
}

typedef struct clock_sweep_arg {
	isc_stdtime_t now;
	dns_ttl_t stale_ttl;
} clock_sweep_arg_t;

static bool
clock_evict(uint64_t fingerprint, const isc_region_t *value, void *arg) {
	clock_sweep_arg_t *sweep = arg;
	qpc_record_t record;
	if (value->length >= sizeof(record)) {
		memmove(&record, value->base, sizeof(record));
		dns_ttl_t stale_ttl =
			(record.attributes & DNS_SLABHEADERATTR_NXDOMAIN) != 0
				? 0
				: sweep->stale_ttl;
		if (record.magic == QPC_RECORD_MAGIC &&
		    record.version == QPC_RECORD_VERSION &&
		    record.expire + stale_ttl < sweep->now)
		{
			return true;
		}
	}

	_Atomic(uint64_t) *slot =
		&qpc_clock[(fingerprint >> 1) & QPC_CLOCK_MASK];
	uint64_t current = atomic_load_relaxed(slot);
	if ((current & ~QPC_CLOCK_REFERENCED) != fingerprint) {
		return true;
	}
	if ((current & QPC_CLOCK_REFERENCED) != 0) {
		atomic_store_relaxed(slot, fingerprint);
		return false;
	}
	return true;
}

/*%
 * Note that "impmagic" is not the first four bytes of the struct, so
 * ISC_MAGIC_VALID cannot be used.
 */
#define QPDB_MAGIC ISC_MAGIC('Q', 'P', 'D', '4')
#define VALID_QPDB(qpdb) \
	((qpdb) != NULL && (qpdb)->common.impmagic == QPDB_MAGIC)

#define HEADERNODE(h) ((qpcnode_t *)((h)->node))

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
	bool deleted	      : 1;
	bool transient       : 1;
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
	size_t max_bytes;	 /* LMDB high-level size target */

	/*
	 * The time after a failed lookup, where stale answers from cache
	 * may be used directly in a DNS response without attempting a
	 * new iterative lookup.
	 */
	uint32_t serve_stale_refresh;

	dns_lmdbcache_t *tree; /* LMDB-backed ordered node index */

	struct rcu_head rcu_head;

	size_t buckets_count;
	qpcache_bucket_t buckets[]; /* attribute((counted_by(buckets_count))) */
};

#ifdef DNS_DB_NODETRACE
#define qpcache_ref(ptr)   qpcache__ref(ptr, __func__, __FILE__, __LINE__)
#define qpcache_unref(ptr) qpcache__unref(ptr, __func__, __FILE__, __LINE__)
#define qpcache_attach(ptr, ptrp) \
	qpcache__attach(ptr, ptrp, __func__, __FILE__, __LINE__)
#define qpcache_detach(ptrp) qpcache__detach(ptrp, __func__, __FILE__, __LINE__)
ISC_REFCOUNT_STATIC_TRACE_DECL(qpcache);
#else
ISC_REFCOUNT_STATIC_DECL(qpcache);
#endif

/*%
 * Search Context
 */
typedef struct {
	qpcache_t *qpdb;
	dns_lmdbtxn_t *txn;
	unsigned int options;
	dns_lmdbchain_t chain;
	dns_lmdbiter_t iter;
	qpcnode_t *zonecut;
	dns_slabheader_t *zonecut_header;
	dns_slabheader_t *zonecut_sigheader;
	isc_stdtime_t now;
} qpc_search_t;

#ifdef DNS_DB_NODETRACE
#define qpcnode_ref(ptr)   qpcnode__ref(ptr, __func__, __FILE__, __LINE__)
#define qpcnode_unref(ptr) qpcnode__unref(ptr, __func__, __FILE__, __LINE__)
#define qpcnode_attach(ptr, ptrp) \
	qpcnode__attach(ptr, ptrp, __func__, __FILE__, __LINE__)
#define qpcnode_detach(ptrp) qpcnode__detach(ptrp, __func__, __FILE__, __LINE__)
ISC_REFCOUNT_STATIC_TRACE_DECL(qpcnode);
#else
ISC_REFCOUNT_STATIC_DECL(qpcnode);
#endif

/*
 * Node methods forward declarations
 */
static void
qpcnode_attachnode(dns_dbnode_t *source, dns_dbnode_t **targetp DNS__DB_FLARG);
static void
qpcnode_detachnode(dns_dbnode_t **nodep DNS__DB_FLARG);
static void
qpcnode_expiredata(dns_dbnode_t *node, void *data);
static void
qpcnode_settrust(dns_dbnode_t *node, dns_typepair_t typepair,
		 dns_trust_t trust);
static void
qpcnode_updateraw(dns_dbnode_t *node, dns_typepair_t typepair,
		  const isc_region_t *raw);
static void
qpcnode_expirerdataset(dns_dbnode_t *node, dns_typepair_t typepair);
static void
qpcnode_clearprefetch(dns_dbnode_t *node, dns_typepair_t typepair);
static qpcnode_t *
new_qpcnode(qpcache_t *qpdb, const dns_name_t *name,
	    dns_namespace_t nspace);
static qpcnode_t *
new_locator(qpcache_t *qpdb, const dns_name_t *name);

static dns_dbnode_methods_t qpcnode_methods = (dns_dbnode_methods_t){
	.attachnode = qpcnode_attachnode,
	.detachnode = qpcnode_detachnode,
	.expiredata = qpcnode_expiredata,
	.settrust = qpcnode_settrust,
	.updateraw = qpcnode_updateraw,
	.expirerdataset = qpcnode_expirerdataset,
	.clearprefetch = qpcnode_clearprefetch,
};

/* QP methods */
static void
qp_attach(void *uctx, void *pval, uint32_t ival);
static void
qp_detach(void *uctx, void *pval, uint32_t ival);
static size_t
qp_makekey(dns_qpkey_t key, void *uctx, void *pval, uint32_t ival);
static void
qp_triename(void *uctx, char *buf, size_t size);

static dns_qpmethods_t qpmethods = {
	qp_attach,
	qp_detach,
	qp_makekey,
	qp_triename,
};

static void
qp_attach(void *uctx ISC_ATTR_UNUSED, void *pval,
	  uint32_t ival ISC_ATTR_UNUSED) {
	qpcnode_t *data = pval;
	qpcnode_ref(data);
}

static void
qp_detach(void *uctx ISC_ATTR_UNUSED, void *pval,
	  uint32_t ival ISC_ATTR_UNUSED) {
	qpcnode_t *data = pval;
	qpcnode_detach(&data);
}

static size_t
qp_makekey(dns_qpkey_t key, void *uctx ISC_ATTR_UNUSED, void *pval,
	   uint32_t ival ISC_ATTR_UNUSED) {
	qpcnode_t *data = pval;
	return dns_qpkey_fromname(key, &data->name, data->nspace);
}

static void
qp_triename(void *uctx ISC_ATTR_UNUSED, char *buf, size_t size) {
	snprintf(buf, size, "qpdb-lite");
}

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

typedef struct qpc_rditer {
	dns_rdatasetiter_t common;
	dns_rdataset_t *current;
	ISC_LIST(dns_rdataset_t) rdatasets;
} qpc_rditer_t;

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
typedef struct qpc_dbit {
	dns_dbiterator_t common;
	bool paused;
	isc_result_t result;
	dns_fixedname_t fixed;
	dns_name_t *name;
	dns_lmdbsnap_t *snap;
	dns_lmdbiter_t iter;
	qpcnode_t *node;
} qpc_dbit_t;

static void
qpcache__destroy(qpcache_t *qpdb);

static dns_dbmethods_t qpdb_cachemethods;

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
header_delete(qpcnode_t *node, dns_slabheader_t *header);

static void
flush_node(qpcache_t *qpdb, qpcnode_t *node, isc_rwlocktype_t *nlocktypep,
	   dns_lmdbtxn_t *txn, dns_expire_t reason DNS__DB_FLARG);

static size_t
expire_header(qpcache_t *qpdb, qpcnode_t *node, dns_slabheader_t *header,
	      isc_rwlocktype_t *nlocktypep, dns_lmdbtxn_t *txn DNS__DB_FLARG) {
	size_t expired = 0;

	if (header->related != NULL) {
		expired += header_delete(node, header->related);
	}
	expired += header_delete(node, header);

	flush_node(qpdb, node, nlocktypep, txn,
		   dns_expire_lru DNS__DB_FLARG_PASS);

	return expired;
}

static void
expire_lru_headers(qpcache_t *qpdb, dns_slabheader_t *newheader, uint32_t idx,
		   size_t requested, isc_rwlocktype_t *nlocktypep,
		   dns_lmdbtxn_t *txn DNS__DB_FLARG) {
	size_t expired = 0;

	do {
		dns_slabheader_t *header = ISC_SIEVE_NEXT(
			qpdb->buckets[idx].sieve, visited, lrulink);
		if (header == NULL) {
			return;
		}

		/* newheader is protected from removal */
		if (header == newheader || header->related == newheader) {
			return;
		}

		qpcnode_t *node = HEADERNODE(header);

		expired += expire_header(qpdb, node, header, nlocktypep,
					 txn DNS__DB_FLARG_PASS);

	} while (expired < requested);
}

static void
qpcache_miss(qpcache_t *qpdb, dns_slabheader_t *newheader,
	     isc_rwlocktype_t *nlocktypep, dns_lmdbtxn_t *txn DNS__DB_FLARG) {
	uint32_t idx = HEADERNODE(newheader)->locknum;

	dns_qp_memusage_t usage = dns_lmdbtxn_memusage(txn);
	bool lmdb_over = qpdb->max_bytes != 0 &&
			 usage.bytes >= qpdb->max_bytes - (qpdb->max_bytes >> 3);
	if (isc_mem_isovermem(qpdb->common.mctx) || lmdb_over) {
		clock_sweep_arg_t sweep = {
			.now = isc_stdtime_now(),
			.stale_ttl = qpdb->common.serve_stale_ttl,
		};
		RUNTIME_CHECK(dns_lmdb_sweeprrsets(txn, 256, clock_evict,
						   &sweep, NULL) ==
			      ISC_R_SUCCESS);
		if (HEADERNODE(newheader)->transient) {
			return;
		}
		/*
		 * Maximum estimated size of the data being added: The size
		 * of the rdataset, plus a new QP database node and nodename,
		 * and a possible additional NSEC node and nodename. Also add
		 * a 12k margin for a possible QP-trie chunk allocation.
		 * (It's okay to overestimate, we want to get cache memory
		 * down quickly.)
		 */

		size_t purgesize =
			2 * (sizeof(qpcnode_t) +
			     dns_name_size(&HEADERNODE(newheader)->name)) +
			dns_rdataslab_size(newheader) + QP_SAFETY_MARGIN;

		expire_lru_headers(qpdb, newheader, idx, purgesize, nlocktypep,
				   txn DNS__DB_FLARG_PASS);
	}
	if (HEADERNODE(newheader)->transient) {
		return;
	}

	ISC_SIEVE_INSERT(qpdb->buckets[idx].sieve, newheader, lrulink);
}

static void
qpcache_hit(qpcache_t *qpdb ISC_ATTR_UNUSED, dns_slabheader_t *header) {
	ISC_SIEVE_MARK(header, visited);
	if (header->related) {
		ISC_SIEVE_MARK(header->related, visited);
	}
}

/*
 * DB Routines
 */

/*
 * Write transaction must be open.
 */
static void
delete_node(dns_lmdbtxn_t *txn, qpcnode_t *node) {
	isc_result_t result = ISC_R_UNEXPECTED;

	INSIST(!node->deleted);
	node->deleted = true;

	if (isc_log_wouldlog(ISC_LOG_DEBUG(DNS_QPCACHE_LOG_STATS_LEVEL))) {
		char printname[DNS_NAME_FORMATSIZE];
		dns_name_format(&node->name, printname, sizeof(printname));
		isc_log_write(DNS_LOGCATEGORY_DATABASE, DNS_LOGMODULE_CACHE,
			      ISC_LOG_DEBUG(DNS_QPCACHE_LOG_STATS_LEVEL),
			      "delete_node(): %p %s (bucket %d)", node,
			      printname, node->locknum);
	}

	switch (node->nspace) {
	case DNS_DBNAMESPACE_NORMAL:
		if (node->havensec) {
			/*
			 * Delete the corresponding node from the auxiliary NSEC
			 * tree before deleting from the main tree.
			 */
			result = dns_lmdb_deletename(txn, &node->name,
						   DNS_DBNAMESPACE_NSEC, NULL,
						   NULL);
			if (result != ISC_R_SUCCESS) {
				isc_log_write(DNS_LOGCATEGORY_DATABASE,
					      DNS_LOGMODULE_CACHE,
					      ISC_LOG_WARNING,
					      "delete_node(): "
					      "dns_qp_deletename: %s",
					      isc_result_totext(result));
			}
		}
		result = dns_lmdb_deletename(txn, &node->name, node->nspace, NULL,
					   NULL);
		break;
	case DNS_DBNAMESPACE_NSEC:
		result = dns_lmdb_deletename(txn, &node->name, node->nspace, NULL,
					   NULL);
		break;
	}
	if (result != ISC_R_SUCCESS) {
		isc_log_write(DNS_LOGCATEGORY_DATABASE, DNS_LOGMODULE_CACHE,
			      ISC_LOG_WARNING,
			      "delete_node(): "
			      "dns_qp_deletename: %s",
			      isc_result_totext(result));
	}
}

/*
 * The caller must specify its currect node and tree lock status.
 * It's okay for neither lock to be held if there are existing external
 * references to the node, but if this is the first external reference,
 * then the caller must be holding at least one lock.
 *
 * If incrementing erefs from zero, we also increment the node use counter
 * in the qpcache object.
 *
 * This function is called from qpcnode_acquire(), so that internal
 * and external references are acquired at the same time, and from
 * qpcnode_release() when we only need to increase the internal references.
 */
static void
qpcnode_erefs_increment(qpcache_t *qpdb, qpcnode_t *node,
			isc_rwlocktype_t nlocktype DNS__DB_FLARG) {
	UNUSED(nlocktype);
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
	/* LMDB read transactions protect a node pointer while a lock-free cache
	 * hit promotes it to an external reference. */

	qpcache_ref(qpdb);
}

static void
qpcnode_acquire(qpcache_t *qpdb, qpcnode_t *node,
		isc_rwlocktype_t nlocktype DNS__DB_FLARG) {
	qpcnode_ref(node);
	qpcnode_erefs_increment(qpdb, node, nlocktype DNS__DB_FLARG_PASS);
}

/*
 * Decrement the external references to a node. If the counter
 * goes to zero, decrement the node use counter in the qpcache object
 * as well, and return true. Otherwise return false.
 */
static bool
qpcnode_erefs_decrement(qpcache_t *qpdb, qpcnode_t *node DNS__DB_FLARG) {
	uint_fast32_t refs = isc_refcount_decrement(&node->erefs);

#if DNS_DB_NODETRACE
	fprintf(stderr, "decr:node:%s:%s:%u:%p->erefs = %" PRIuFAST32 "\n",
		func, file, line, node, refs - 1);
#endif
	if (refs > 1) {
		return false;
	}

	qpcache_unref(qpdb);
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
qpcnode_release(qpcache_t *qpdb, qpcnode_t *node, isc_rwlocktype_t *nlocktypep,
		dns_lmdbtxn_t *txn DNS__DB_FLARG) {
	REQUIRE(*nlocktypep != isc_rwlocktype_none);

	if (!qpcnode_erefs_decrement(qpdb, node DNS__DB_FLARG_PASS)) {
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
		isc_rwlock_t *nlock = &qpdb->buckets[node->locknum].lock;
		qpcnode_erefs_increment(qpdb, node,
					*nlocktypep DNS__DB_FLARG_PASS);
		NODE_FORCEUPGRADE(nlock, nlocktypep);
		if (!qpcnode_erefs_decrement(qpdb, node DNS__DB_FLARG_PASS)) {
			goto unref;
		}
	}

	if (!cds_list_empty(&node->headers)) {
		goto unref;
	}

	if (txn != NULL) {
		/*
		 * We can delete the node if we have the tree write lock.
		 */
		delete_node(txn, node);
	} else if (!node->deleted) {
		/*
		 * If we don't have the tree lock, we will add this node to a
		 * linked list of nodes in this locking bucket which we will
		 * free later.
		 */
		qpcnode_acquire(qpdb, node, *nlocktypep DNS__DB_FLARG_PASS);

		isc_queue_node_init(&node->deadlink);
		if (!isc_queue_enqueue_entry(
			    &qpdb->buckets[node->locknum].deadnodes, node,
			    deadlink))
		{
			/* Queue was empty, trigger new cleaning */
			isc_loop_t *loop = isc_loop_get(node->locknum);

			qpcache_ref(qpdb);
			isc_async_run(loop, cleanup_deadnodes_cb, qpdb);
		}
	}
	/* else: already removed from the trie; reclaimed with its chunk */
unref:
	qpcnode_unref(node);
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

	if (!STATCOUNT(header)) {
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
	qpcache_t *qpdb = HEADERNODE(header)->qpdb;

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
	update_rrsetstats(qpdb->rrsetstats, header->typepair, attributes,
			  false);
	update_rrsetstats(qpdb->rrsetstats, header->typepair, newattributes,
			  true);
}

static void
setttl(dns_slabheader_t *header, isc_stdtime_t newts) {
	header->expire = newts;
}

static size_t
header_delete(qpcnode_t *node, dns_slabheader_t *header) {
	/* The slabheader has already been removed from the node headers */
	if (cds_list_empty(&header->headers_link)) {
		return 0;
	}

	size_t expired = dns_rdataslab_size(header);
	qpcache_t *qpdb = node->qpdb;

	cds_list_del_init(&header->headers_link);

	/*
	 * This place is the only place where we actually need header->typepair.
	 */
	update_rrsetstats(qpdb->rrsetstats, header->typepair,
			  atomic_load_acquire(&header->attributes), false);

	if (ISC_SIEVE_LINKED(header, lrulink)) {
		ISC_SIEVE_UNLINK(qpdb->buckets[node->locknum].sieve, header,
				 lrulink);
	}

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
flush_node(qpcache_t *qpdb, qpcnode_t *node, isc_rwlocktype_t *nlocktypep,
	   dns_lmdbtxn_t *txn, dns_expire_t reason DNS__DB_FLARG) {
	if (isc_refcount_current(&node->erefs) != 0) {
		return;
	}

	/*
	 * If no one else is using the node, we can clean it up now.
	 * We first need to gain a new reference to the node to meet a
	 * requirement of qpcnode_release().
	 */
	qpcnode_acquire(qpdb, node, *nlocktypep DNS__DB_FLARG_PASS);
	qpcnode_release(qpdb, node, nlocktypep, txn DNS__DB_FLARG_PASS);

	if (qpdb->cachestats == NULL) {
		return;
	}

	switch (reason) {
	case dns_expire_lru:
		isc_stats_increment(qpdb->cachestats,
				    dns_cachestatscounter_deletelru);
		break;
	default:
		break;
	}
}

static void
update_cachestats(qpcache_t *qpdb, isc_result_t result) {
	if (qpdb->cachestats == NULL) {
		return;
	}

	switch (result) {
	case DNS_R_COVERINGNSEC:
		isc_stats_increment(qpdb->cachestats,
				    dns_cachestatscounter_coveringnsec);
		FALLTHROUGH;
	case ISC_R_SUCCESS:
	case DNS_R_CNAME:
	case DNS_R_DNAME:
	case DNS_R_DELEGATION:
	case DNS_R_NCACHENXDOMAIN:
	case DNS_R_NCACHENXRRSET:
		isc_stats_increment(qpdb->cachestats,
				    dns_cachestatscounter_hits);
		break;
	default:
		isc_stats_increment(qpdb->cachestats,
				    dns_cachestatscounter_misses);
	}
}

static dns_trust_t
header_trust(dns_slabheader_t *header) {
	if (header == NULL) {
		return dns_trust_none;
	}
	return atomic_load_acquire(&header->trust);
}

static isc_result_t
store_header_record(qpcache_t *qpdb, dns_lmdbtxn_t *txn,
		    const dns_name_t *name, dns_namespace_t nspace,
		    dns_slabheader_t *header) {
	isc_region_t proof_name = { 0 };
	dns_slabheader_t *proof = NULL, *proofsig = NULL;
	uint32_t raw_length = dns_rdataslab_size(header) - sizeof(*header);
	uint32_t proof_length = 0, proof_sig_length = 0;

	if (header->noqname != NULL) {
		dns_name_toregion(&header->noqname->name, &proof_name);
		proof = (dns_slabheader_t *)(
			(unsigned char *)header->noqname->neg - sizeof(*proof));
		proofsig = (dns_slabheader_t *)(
			(unsigned char *)header->noqname->negsig -
			sizeof(*proofsig));
		proof_length = dns_rdataslab_size(proof) - sizeof(*proof);
		proof_sig_length = dns_rdataslab_size(proofsig) -
				   sizeof(*proofsig);
	}

	size_t data_length = (size_t)raw_length + proof_name.length +
			     proof_length + proof_sig_length;
	size_t size = sizeof(qpc_record_t) + data_length;
	qpc_record_t *record = isc_mem_get(qpdb->common.mctx, size);
	*record = (qpc_record_t){
		.magic = QPC_RECORD_MAGIC,
		.version = QPC_RECORD_VERSION,
		.attributes = atomic_load_acquire(&header->attributes),
		.trust = header_trust(header),
		.expire = header->expire,
		.last_refresh_fail =
			atomic_load_acquire(&header->last_refresh_fail_ts),
		.count = header->nitems,
		.proof_type = header->noqname != NULL
				      ? header->noqname->type
				      : dns_rdatatype_none,
		.proof_count = proof != NULL ? proof->nitems : 0,
		.proof_sig_count = proofsig != NULL ? proofsig->nitems : 0,
		.cache_order = header->cache_order,
		.raw_length = raw_length,
		.proof_name_length = proof_name.length,
		.proof_length = proof_length,
		.proof_sig_length = proof_sig_length,
	};
	unsigned char *cursor = record->data;
	memmove(cursor, header->raw, raw_length);
	cursor += raw_length;
	if (header->noqname != NULL) {
		memmove(cursor, proof_name.base, proof_name.length);
		cursor += proof_name.length;
		memmove(cursor, proof->raw, proof_length);
		cursor += proof_length;
		memmove(cursor, proofsig->raw, proof_sig_length);
	}
	isc_region_t value = {
		.base = (unsigned char *)record,
		.length = size,
	};
	isc_result_t result = dns_lmdb_putrrset(
		txn, name, nspace, header->typepair, &value, true);
	isc_mem_put(qpdb->common.mctx, record, size);
	return result;
}

static isc_result_t
sync_node_records(qpcache_t *qpdb, dns_lmdbtxn_t *txn, qpcnode_t *node) {
	isc_result_t result = dns_lmdb_deleteallrrsets(
		txn, &node->name, DNS_DBNAMESPACE_NORMAL);
	if (result != ISC_R_SUCCESS && result != ISC_R_NOTFOUND) {
		return result;
	}
	result = dns_lmdb_deleteallrrsets(txn, &node->name,
					 DNS_DBNAMESPACE_NSEC);
	if (result != ISC_R_SUCCESS && result != ISC_R_NOTFOUND) {
		return result;
	}

	uint32_t cache_order = 0;
	DNS_SLABHEADER_FOREACH(header, &node->headers) {
		header->cache_order = cache_order++;
		result = store_header_record(qpdb, txn, &node->name,
					     DNS_DBNAMESPACE_NORMAL, header);
		if (result != ISC_R_SUCCESS) {
			return result;
		}
		if (header->typepair == DNS_TYPEPAIR(dns_rdatatype_nsec)) {
			result = store_header_record(qpdb, txn, &node->name,
						     DNS_DBNAMESPACE_NSEC,
						     header);
			if (result != ISC_R_SUCCESS) {
				return result;
			}
		}
	}
	return ISC_R_SUCCESS;
}

static bool
parse_record(const isc_region_t *value, qpc_record_t *record,
	     const unsigned char **datap) {
	if (value->length < sizeof(*record)) {
		return false;
	}
	memmove(record, value->base, sizeof(*record));
	if (record->magic != QPC_RECORD_MAGIC ||
	    record->version != QPC_RECORD_VERSION)
	{
		return false;
	}
	size_t data_length = (size_t)record->raw_length +
			     record->proof_name_length + record->proof_length +
			     record->proof_sig_length;
	if (data_length != value->length - sizeof(*record)) {
		return false;
	}
	if ((record->proof_name_length == 0) !=
	    (record->proof_length == 0 || record->proof_sig_length == 0))
	{
		return false;
	}
	*datap = value->base + sizeof(*record);
	return true;
}

typedef struct load_node_arg {
	qpcache_t *qpdb;
	qpcnode_t *node;
} load_node_arg_t;

static dns_slabheader_t *
new_bare_header(qpcache_t *qpdb, qpcnode_t *node,
		dns_typepair_t typepair, uint16_t count,
		const unsigned char *raw, uint32_t raw_length) {
	size_t size = sizeof(dns_slabheader_t) + raw_length;
	dns_slabheader_t *header = isc_mem_get(qpdb->common.mctx, size);
	*header = (dns_slabheader_t){
		.references = ISC_REFCOUNT_INITIALIZER(1),
		.mctx = isc_mem_ref(qpdb->common.mctx),
		.typepair = typepair,
		.headers_link = CDS_LIST_HEAD_INIT(header->headers_link),
		.node = (dns_dbnode_t *)node,
		.nitems = count,
		.lrulink = ISC_LINK_INITIALIZER,
	};
	memmove(header->raw, raw, raw_length);
	return header;
}

static isc_result_t
load_node_record(dns_typepair_t typepair, const isc_region_t *value,
		 void *arg) {
	load_node_arg_t *load = arg;
	qpc_record_t record;
	const unsigned char *data = NULL;
	if (!parse_record(value, &record, &data)) {
		return ISC_R_INVALIDFILE;
	}
	dns_slabheader_t *header = new_bare_header(
		load->qpdb, load->node, typepair, record.count, data,
		record.raw_length);
	atomic_store_relaxed(&header->attributes,
			     record.attributes & ~DNS_SLABHEADERATTR_STATCOUNT);
	atomic_store_relaxed(&header->trust, record.trust);
	header->expire = record.expire;
	header->cache_order = record.cache_order;
	atomic_store_relaxed(&header->last_refresh_fail_ts,
			     record.last_refresh_fail);

	if (record.proof_name_length != 0) {
		const unsigned char *name_raw = data + record.raw_length;
		const unsigned char *proof_raw =
			name_raw + record.proof_name_length;
		const unsigned char *proof_sig_raw =
			proof_raw + record.proof_length;
		dns_slabheader_t *proof = new_bare_header(
			load->qpdb, load->node, DNS_TYPEPAIR(record.proof_type),
			record.proof_count, proof_raw, record.proof_length);
		dns_slabheader_t *proofsig = new_bare_header(
			load->qpdb, load->node,
			DNS_SIGTYPEPAIR(record.proof_type),
			record.proof_sig_count, proof_sig_raw,
			record.proof_sig_length);
		dns_name_t proof_name = DNS_NAME_INITEMPTY;
		isc_region_t region = {
			.base = (unsigned char *)name_raw,
			.length = record.proof_name_length,
		};
		dns_name_fromregion(&proof_name, &region);
		header->noqname = isc_mem_get(load->qpdb->common.mctx,
						 sizeof(*header->noqname));
		*header->noqname = (dns_slabheader_proof_t){
			.name = DNS_NAME_INITEMPTY,
			.neg = proof->raw,
			.negsig = proofsig->raw,
			.type = record.proof_type,
		};
		dns_name_dup(&proof_name, load->qpdb->common.mctx,
			     &header->noqname->name);
	}
	DNS_SLABHEADER_FOREACH(existing, &load->node->headers) {
		if (header->cache_order < existing->cache_order) {
			cds_list_add_tail(&header->headers_link,
					  &existing->headers_link);
			return ISC_R_SUCCESS;
		}
	}
	cds_list_add_tail(&header->headers_link, &load->node->headers);
	return ISC_R_SUCCESS;
}

static isc_result_t
load_node_records(qpcache_t *qpdb, dns_lmdbtxn_t *txn, qpcnode_t *node) {
	load_node_arg_t load = { .qpdb = qpdb, .node = node };
	isc_result_t result = dns_lmdb_foreachrrset(
		txn, &node->name, DNS_DBNAMESPACE_NORMAL, load_node_record, &load);
	if (result == ISC_R_NOTFOUND) {
		return ISC_R_SUCCESS;
	}
	if (result != ISC_R_SUCCESS) {
		return result;
	}
	DNS_SLABHEADER_FOREACH(header, &node->headers) {
		if (dns_rdatatype_issig(DNS_TYPEPAIR_TYPE(header->typepair)) ||
		    NEGATIVE(header))
		{
			continue;
		}
		dns_typepair_t sigpair =
			DNS_SIGTYPEPAIR(DNS_TYPEPAIR_TYPE(header->typepair));
		DNS_SLABHEADER_FOREACH(sig, &node->headers) {
			if (sig->typepair == sigpair && !NEGATIVE(sig)) {
				header->related = dns_slabheader_ref(sig);
				sig->related = dns_slabheader_ref(header);
				break;
			}
		}
	}
	return ISC_R_SUCCESS;
}

static isc_result_t
bind_record(qpcache_t *qpdb, qpcnode_t *node, dns_typepair_t typepair,
	    const isc_region_t *value, isc_stdtime_t now,
	    dns_rdataset_t *rdataset DNS__DB_FLARG) {
	qpc_record_t record;
	const unsigned char *data = NULL;
	if (!parse_record(value, &record, &data)) {
		return ISC_R_INVALIDFILE;
	}

	rdataset->rdclass = qpdb->common.rdclass;
	rdataset->type = DNS_TYPEPAIR_TYPE(typepair);
	rdataset->covers = DNS_TYPEPAIR_COVERS(typepair);
	rdataset->ttl = record.expire > now ? record.expire - now : 0;
	rdataset->trust = record.trust;
	rdataset->resign = 0;
	rdataset->attributes.negative =
		(record.attributes & DNS_SLABHEADERATTR_NEGATIVE) != 0;
	rdataset->attributes.nxdomain =
		(record.attributes & DNS_SLABHEADERATTR_NXDOMAIN) != 0;
	rdataset->attributes.optout =
		(record.attributes & DNS_SLABHEADERATTR_OPTOUT) != 0;
	rdataset->attributes.prefetch =
		(record.attributes & DNS_SLABHEADERATTR_PREFETCH) != 0;

	bool zerottl =
		(record.attributes & DNS_SLABHEADERATTR_ZEROTTL) != 0;
	bool stale = (record.attributes & DNS_SLABHEADERATTR_STALE) != 0;
	if (!zerottl && record.expire <= now && KEEPSTALE(qpdb) &&
	    record.expire + (rdataset->attributes.nxdomain
			       ? 0
			       : qpdb->common.serve_stale_ttl) >
		    now)
	{
		stale = true;
	}
	if (stale) {
		dns_ttl_t stale_expire = record.expire +
					 (rdataset->attributes.nxdomain
						  ? 0
						  : qpdb->common.serve_stale_ttl);
		rdataset->ttl = stale_expire > now ? stale_expire - now : 0;
		rdataset->attributes.stale = true;
		rdataset->attributes.stale_window =
			(record.attributes &
			 DNS_SLABHEADERATTR_STALE_WINDOW) != 0;
		rdataset->expire = record.expire;
	} else if (record.expire <= now) {
		rdataset->attributes.ancient = true;
	}

	isc_region_t raw = {
		.base = (unsigned char *)data,
		.length = record.raw_length,
	};
	if (record.proof_name_length == 0) {
		dns_rdataset_makeallocated(rdataset, qpdb->common.mctx,
					  (dns_dbnode_t *)node, record.count,
					  &raw);
	} else {
		isc_region_t proof_name = {
			.base = (unsigned char *)data + record.raw_length,
			.length = record.proof_name_length,
		};
		isc_region_t proof = {
			.base = proof_name.base + proof_name.length,
			.length = record.proof_length,
		};
		isc_region_t proof_sig = {
			.base = proof.base + proof.length,
			.length = record.proof_sig_length,
		};
		dns_rdataset_makeallocatedproof(
			rdataset, qpdb->common.mctx, (dns_dbnode_t *)node,
			record.count, &raw, &proof_name, record.proof_type,
			record.proof_count, &proof, record.proof_sig_count,
			&proof_sig);
		rdataset->attributes.noqname = true;
	}
	rdataset->allocated.cache_order = record.cache_order;
	clock_touch(&node->name, typepair);
	return ISC_R_SUCCESS;
}

static bool
record_usable(qpcache_t *qpdb, const qpc_record_t *record, isc_stdtime_t now,
	      unsigned int options) {
	if (record->expire > now ||
	    (record->expire == now &&
	     (record->attributes & DNS_SLABHEADERATTR_ZEROTTL) != 0))
	{
		return true;
	}
	if ((record->attributes & DNS_SLABHEADERATTR_ZEROTTL) != 0 ||
	    !KEEPSTALE(qpdb) ||
	    (record->attributes & DNS_SLABHEADERATTR_NXDOMAIN) != 0 ||
	    record->expire + qpdb->common.serve_stale_ttl <= now)
	{
		return false;
	}
	if ((options & DNS_DBFIND_STALEENABLED) != 0 &&
	    now < record->last_refresh_fail + qpdb->serve_stale_refresh)
	{
		return true;
	}
	return (options & (DNS_DBFIND_STALEOK | DNS_DBFIND_STALETIMEOUT)) != 0;
}

static bool
record_missing(const qpc_record_t *record, unsigned int options) {
	dns_trust_t trust = record->trust;
	return (DNS_TRUST_ADDITIONAL(trust) &&
		(options & DNS_DBFIND_ADDITIONALOK) == 0) ||
	       (DNS_TRUST_GLUE(trust) &&
		(options & DNS_DBFIND_GLUEOK) == 0) ||
	       (DNS_TRUST_PENDING(trust) &&
		(options & DNS_DBFIND_PENDINGOK) == 0);
}

typedef struct direct_find {
	qpcache_t *qpdb;
	dns_typepair_t wanted;
	unsigned int options;
	isc_stdtime_t now;
	bool any_active;
	bool all_negative;
	bool found_noqname;
	bool have_answer;
	bool answer_stale;
	bool have_sig;
	bool have_cname;
	bool cname_stale;
	bool have_cnamesig;
	bool have_nsec;
	bool have_nsecsig;
	dns_typepair_t answer_typepair;
	isc_region_t answer;
	isc_region_t sig;
	isc_region_t cname;
	isc_region_t cnamesig;
	isc_region_t nsec;
	isc_region_t nsecsig;
} direct_find_t;

static isc_result_t
collect_direct_record(dns_typepair_t typepair, const isc_region_t *value,
		      void *arg) {
	direct_find_t *find = arg;
	qpc_record_t record;
	const unsigned char *data = NULL;
	if (!parse_record(value, &record, &data)) {
		return ISC_R_INVALIDFILE;
	}
	if (!record_usable(find->qpdb, &record, find->now, find->options)) {
		return ISC_R_SUCCESS;
	}
	find->any_active = true;
	bool negative =
		(record.attributes & DNS_SLABHEADERATTR_NEGATIVE) != 0;
	bool stale = record.expire < find->now ||
		     (record.expire == find->now &&
		      (record.attributes & DNS_SLABHEADERATTR_ZEROTTL) == 0);
	if (!negative) {
		find->all_negative = false;
	}
	if (record.proof_name_length != 0 &&
	    record.trust == dns_trust_secure)
	{
		find->found_noqname = true;
	}

	if (typepair == find->wanted ||
	    (typepair == dns_typepair_any && negative))
	{
		if (!record_missing(&record, find->options)) {
			find->answer_typepair = typepair;
			find->answer = *value;
			find->have_answer = true;
			find->answer_stale = stale;
		}
	} else if (typepair == DNS_SIGTYPEPAIR(
				       DNS_TYPEPAIR_TYPE(find->wanted)))
	{
		find->sig = *value;
		find->have_sig = true;
	} else if (typepair == DNS_TYPEPAIR(dns_rdatatype_cname) &&
		   !record_missing(&record, find->options))
	{
		find->cname = *value;
		find->have_cname = true;
		find->cname_stale = stale;
	} else if (typepair == DNS_SIGTYPEPAIR(dns_rdatatype_cname)) {
		find->cnamesig = *value;
		find->have_cnamesig = true;
	} else if (typepair == DNS_TYPEPAIR(dns_rdatatype_nsec)) {
		find->nsec = *value;
		find->have_nsec = true;
	} else if (typepair == DNS_SIGTYPEPAIR(dns_rdatatype_nsec)) {
		find->nsecsig = *value;
		find->have_nsecsig = true;
	} else if (find->wanted == dns_typepair_any && !negative &&
		   !find->have_answer && !record_missing(&record, find->options))
	{
		find->answer_typepair = typepair;
		find->answer = *value;
		find->have_answer = true;
		find->answer_stale = stale;
	}
	return ISC_R_SUCCESS;
}

static isc_result_t
find_records_at_name(qpcache_t *qpdb, dns_lmdbtxn_t *txn, qpcnode_t *node,
		     dns_rdatatype_t type, unsigned int options,
		     isc_stdtime_t now, dns_rdataset_t *rdataset,
		     dns_rdataset_t *sigrdataset DNS__DB_FLARG) {
	direct_find_t find = {
		.qpdb = qpdb,
		.wanted = DNS_TYPEPAIR(type),
		.options = options,
		.now = now,
		.all_negative = true,
	};
	isc_result_t result = dns_lmdb_foreachrrset(
		txn, &node->name, DNS_DBNAMESPACE_NORMAL, collect_direct_record,
		&find);
	if (result != ISC_R_SUCCESS) {
		return result == ISC_R_NOTFOUND ? ISC_R_NOTFOUND : result;
	}
	if (!find.any_active) {
		return ISC_R_NOTFOUND;
	}

	bool cname_ok = type != dns_rdatatype_nsec &&
			type != dns_rdatatype_rrsig;
	isc_region_t *answer = NULL, *sig = NULL;
	dns_typepair_t answer_typepair = find.answer_typepair;
	if (find.have_answer &&
	    (!find.answer_stale || !find.have_cname || find.cname_stale))
	{
		answer = &find.answer;
		sig = find.have_sig ? &find.sig : NULL;
	} else if (cname_ok && find.have_cname) {
		answer = &find.cname;
		sig = find.have_cnamesig ? &find.cnamesig : NULL;
		answer_typepair = DNS_TYPEPAIR(dns_rdatatype_cname);
	} else if ((options & DNS_DBFIND_COVERINGNSEC) != 0 &&
		   find.have_nsec)
	{
		answer = &find.nsec;
		sig = find.have_nsecsig ? &find.nsecsig : NULL;
		answer_typepair = DNS_TYPEPAIR(dns_rdatatype_nsec);
		result = DNS_R_COVERINGNSEC;
	} else {
		return ISC_R_NOTFOUND;
	}

	qpc_record_t record;
	const unsigned char *data = NULL;
	if (!parse_record(answer, &record, &data)) {
		return ISC_R_INVALIDFILE;
	}
	if (find.wanted != dns_typepair_any ||
	    (record.attributes & DNS_SLABHEADERATTR_NEGATIVE) != 0)
	{
		RETERR(bind_record(qpdb, node, answer_typepair, answer, now,
				     rdataset DNS__DB_FLARG_PASS));
		if ((record.attributes & DNS_SLABHEADERATTR_NEGATIVE) == 0 &&
		    sig != NULL && sigrdataset != NULL)
		{
			dns_typepair_t sigpair =
				DNS_SIGTYPEPAIR(DNS_TYPEPAIR_TYPE(answer_typepair));
			RETERR(bind_record(qpdb, node, sigpair, sig, now,
					     sigrdataset DNS__DB_FLARG_PASS));
		}
	}
	if (result == DNS_R_COVERINGNSEC) {
		return result;
	}
	if ((record.attributes & DNS_SLABHEADERATTR_NEGATIVE) != 0) {
		return (record.attributes & DNS_SLABHEADERATTR_NXDOMAIN) != 0
			       ? DNS_R_NCACHENXDOMAIN
			       : DNS_R_NCACHENXRRSET;
	}
	return answer_typepair == DNS_TYPEPAIR(dns_rdatatype_cname) &&
		       find.wanted != answer_typepair
		       ? DNS_R_CNAME
		       : ISC_R_SUCCESS;
}

static isc_result_t
find_dname_at(qpcache_t *qpdb, dns_lmdbtxn_t *txn, const dns_name_t *name,
	      unsigned int options, isc_stdtime_t now, dns_rdataset_t *rdataset,
	      dns_rdataset_t *sigrdataset DNS__DB_FLARG) {
	isc_region_t value;
	isc_result_t result = dns_lmdb_getrrset(
		txn, name, DNS_DBNAMESPACE_NORMAL,
		DNS_TYPEPAIR(dns_rdatatype_dname), &value);
	if (result != ISC_R_SUCCESS) {
		return ISC_R_NOTFOUND;
	}
	qpc_record_t record;
	const unsigned char *data = NULL;
	if (!parse_record(&value, &record, &data)) {
		return ISC_R_INVALIDFILE;
	}
	if (!record_usable(qpdb, &record, now, options) ||
	    record_missing(&record, options))
	{
		return ISC_R_NOTFOUND;
	}

	qpcnode_t *locator = new_locator(qpdb, name);
	result = bind_record(qpdb, locator,
			     DNS_TYPEPAIR(dns_rdatatype_dname), &value, now,
			     rdataset DNS__DB_FLARG_PASS);
	if (result == ISC_R_SUCCESS && sigrdataset != NULL) {
		isc_region_t sig;
		if (dns_lmdb_getrrset(txn, name, DNS_DBNAMESPACE_NORMAL,
					 DNS_SIGTYPEPAIR(dns_rdatatype_dname),
					 &sig) == ISC_R_SUCCESS)
		{
			result = bind_record(
				qpdb, locator,
				DNS_SIGTYPEPAIR(dns_rdatatype_dname), &sig, now,
				sigrdataset DNS__DB_FLARG_PASS);
		}
	}
	qpcnode_unref(locator);
	return result == ISC_R_SUCCESS ? DNS_R_DNAME : result;
}

static void
bindrdataset(qpcache_t *qpdb, qpcnode_t *node, dns_slabheader_t *header,
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

	INSIST(rdataset->methods == NULL); /* We must be disassociated. */

	/*
	 * Mark header stale if the RRset is no longer active.
	 */
	if (!ACTIVE(header, now)) {
		dns_ttl_t stale_ttl = header->expire + STALE_TTL(header, qpdb);
		/*
		 * If this data is in the stale window keep it and if
		 * DNS_DBFIND_STALEOK is not set we tell the caller to
		 * skip this record.  We skip the records with ZEROTTL
		 * (these records should not be cached anyway).
		 */

		if (!ZEROTTL(header) && KEEPSTALE(qpdb) && stale_ttl > now) {
			stale = true;
		}
	}

	rdataset->rdclass = qpdb->common.rdclass;
	rdataset->type = DNS_TYPEPAIR_TYPE(header->typepair);
	rdataset->covers = DNS_TYPEPAIR_COVERS(header->typepair);
	rdataset->ttl = !ZEROTTL(header) ? header->expire - now : 0;
	rdataset->trust = header_trust(header);
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
		dns_ttl_t stale_ttl = header->expire + STALE_TTL(header, qpdb);
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

	isc_region_t raw = {
		.base = header->raw,
		.length = dns_rdataslab_size(header) - sizeof(*header),
	};
	qpcnode_t *locator = HEADERNODE(header);
	if (header->noqname == NULL) {
		dns_rdataset_makeallocated(rdataset, qpdb->common.mctx,
					  NULL, header->nitems, &raw);
	} else {
		dns_slabheader_t *proof =
			(dns_slabheader_t *)((unsigned char *)header->noqname->neg -
					     sizeof(dns_slabheader_t));
		dns_slabheader_t *proofsig =
			(dns_slabheader_t *)((unsigned char *)header->noqname->negsig -
					     sizeof(dns_slabheader_t));
		isc_region_t proof_name, proof_raw, proof_sig_raw;
		dns_name_toregion(&header->noqname->name, &proof_name);
		proof_raw = (isc_region_t){
			.base = proof->raw,
			.length = dns_rdataslab_size(proof) - sizeof(*proof),
		};
		proof_sig_raw = (isc_region_t){
			.base = proofsig->raw,
			.length = dns_rdataslab_size(proofsig) - sizeof(*proofsig),
		};
		dns_rdataset_makeallocatedproof(
			rdataset, qpdb->common.mctx, NULL,
			header->nitems, &raw, &proof_name, header->noqname->type,
			proof->nitems, &proof_raw, proofsig->nitems,
			&proof_sig_raw);
		rdataset->attributes.noqname = true;
	}
	qpcnode_acquire(qpdb, locator, nlocktype DNS__DB_FLARG_PASS);
	rdataset->allocated.node = (dns_dbnode_t *)locator;
	UNUSED(node);
}

static void
bindrdatasets(qpcache_t *qpdb, qpcnode_t *qpnode, dns_slabheader_t *found,
	      dns_slabheader_t *foundsig, isc_stdtime_t now,
	      isc_rwlocktype_t nlocktype, dns_rdataset_t *rdataset,
	      dns_rdataset_t *sigrdataset DNS__DB_FLARG) {
	bindrdataset(qpdb, qpnode, found, now, nlocktype,
		     rdataset DNS__DB_FLARG_PASS);
	qpcache_hit(qpdb, found);
	if (!NEGATIVE(found) && foundsig != NULL) {
		bindrdataset(qpdb, qpnode, foundsig, now, nlocktype,
			     sigrdataset DNS__DB_FLARG_PASS);
		qpcache_hit(qpdb, foundsig);
	}
}

static bool
check_stale_header(dns_slabheader_t *header, qpc_search_t *search) {
	if (ACTIVE(header, search->now)) {
		return false;
	}

	isc_stdtime_t stale = header->expire + STALE_TTL(header, search->qpdb);
	/*
	 * If this data is in the stale window keep it and if
	 * DNS_DBFIND_STALEOK is not set we tell the caller to
	 * skip this record.  We skip the records with ZEROTTL
	 * (these records should not be cached anyway).
	 */

	DNS_SLABHEADER_CLRATTR(header, DNS_SLABHEADERATTR_STALE_WINDOW);
	if (!ZEROTTL(header) && KEEPSTALE(search->qpdb) && stale > search->now)
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
				    search->qpdb->serve_stale_refresh))
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
invalid_header(dns_slabheader_t *header, qpc_search_t *search) {
	return header == NULL || check_stale_header(header, search);
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
	      dns_slabheader_t **sigheaderp, qpc_search_t *search) {
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
find_headers(qpcnode_t *node, qpc_search_t *search, dns_rdatatype_t type,
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
check_dname(qpcnode_t *node, void *arg DNS__DB_FLARG) {
	qpc_search_t *search = arg;
	dns_slabheader_t *found = NULL, *foundsig = NULL;
	isc_result_t result;
	isc_rwlocktype_t nlocktype = isc_rwlocktype_none;
	isc_rwlock_t *nlock = NULL;

	REQUIRE(search->zonecut == NULL);

	nlock = &search->qpdb->buckets[node->locknum].lock;
	NODE_RDLOCK(nlock, &nlocktype);

	/*
	 * Look for a DNAME or RRSIG DNAME rdataset.
	 */
	find_headers(node, search, dns_rdatatype_dname, &found, &foundsig);

	if (found != NULL && (!DNS_TRUST_PENDING(header_trust(found)) ||
			      (search->options & DNS_DBFIND_PENDINGOK) != 0))
	{
		/*
		 * We increment the reference count on the node to keep it
		 * alive, and we attach to the DNAME header (and its signature)
		 * so that they stay valid after the node lock is released.
		 */
		qpcnode_acquire(search->qpdb, node,
				nlocktype DNS__DB_FLARG_PASS);
		search->zonecut = node;
		search->zonecut_header = dns_slabheader_ref(found);
		if (foundsig != NULL) {
			search->zonecut_sigheader =
				dns_slabheader_ref(foundsig);
		}
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
 * the potential NSEC owner. If found, we update 'foundname', 'rdataset', and
 * 'sigrdataset', and return DNS_R_COVERINGNSEC.
 * Otherwise, return ISC_R_NOTFOUND.
 */
static isc_result_t
find_coveringnsec(qpc_search_t *search, const dns_name_t *name,
		  dns_name_t *foundname, dns_rdataset_t *rdataset,
		  dns_rdataset_t *sigrdataset DNS__DB_FLARG) {
	dns_fixedname_t fixed;
	dns_name_t *predecessor = dns_fixedname_initname(&fixed);
	isc_region_t value;
	isc_result_t result = dns_lmdb_predecessor(
		search->txn, name, DNS_DBNAMESPACE_NSEC,
		DNS_TYPEPAIR(dns_rdatatype_nsec), predecessor, &value);
	if (result != ISC_R_SUCCESS) {
		return ISC_R_NOTFOUND;
	}
	qpc_record_t record;
	const unsigned char *data = NULL;
	if (!parse_record(&value, &record, &data) ||
	    !record_usable(search->qpdb, &record, search->now,
			   search->options) ||
	    record.trust != dns_trust_secure)
	{
		return ISC_R_NOTFOUND;
	}

	qpcnode_t *locator = new_locator(search->qpdb, predecessor);
	result = bind_record(search->qpdb, locator,
			     DNS_TYPEPAIR(dns_rdatatype_nsec), &value,
			     search->now, rdataset DNS__DB_FLARG_PASS);
	if (result == ISC_R_SUCCESS && sigrdataset != NULL) {
		isc_region_t sigvalue;
		if (dns_lmdb_getrrset(search->txn, predecessor,
					 DNS_DBNAMESPACE_NORMAL,
					 DNS_SIGTYPEPAIR(dns_rdatatype_nsec),
					 &sigvalue) == ISC_R_SUCCESS)
		{
			qpc_record_t sigrecord;
			if (!parse_record(&sigvalue, &sigrecord, &data) ||
			    sigrecord.trust != dns_trust_secure)
			{
				result = ISC_R_NOTFOUND;
			} else {
				result = bind_record(
					search->qpdb, locator,
					DNS_SIGTYPEPAIR(dns_rdatatype_nsec),
					&sigvalue, search->now, sigrdataset
					DNS__DB_FLARG_PASS);
			}
		}
	}
	qpcnode_unref(locator);
	if (result != ISC_R_SUCCESS) {
		return result;
	}
	if (foundname != NULL) {
		dns_name_copy(predecessor, foundname);
	}
	return DNS_R_COVERINGNSEC;
}

static inline bool
missing_answer(dns_slabheader_t *found, unsigned int options) {
	if (found == NULL) {
		return true;
	}

	dns_trust_t trust = header_trust(found);
	return (DNS_TRUST_ADDITIONAL(trust) &&
		(options & DNS_DBFIND_ADDITIONALOK) == 0) ||
	       (DNS_TRUST_GLUE(trust) && (options & DNS_DBFIND_GLUEOK) == 0) ||
	       (DNS_TRUST_PENDING(trust) &&
		(options & DNS_DBFIND_PENDINGOK) == 0);
}

static void
qpc_search_init(qpc_search_t *search, qpcache_t *db, unsigned int options,
		isc_stdtime_t now) {
	/*
	 * qpc_search_t contains two structures with large buffers (dns_qpiter_t
	 * and dns_qpchain_t). Those two structures will be initialized later by
	 * dns_qp_lookup anyway.
	 * To avoid the overhead of zero initialization, we avoid designated
	 * initializers and initialize all "small" fields manually.
	 */
	search->qpdb = (qpcache_t *)db;
	search->txn = NULL;
	search->options = options;
	/*
	 * qpch->in - Init by dns_qp_lookup
	 * qpiter - Init by dns_qp_lookup
	 */
	search->now = now ? now : isc_stdtime_now();
	search->zonecut = NULL;
	search->zonecut_header = NULL;
	search->zonecut_sigheader = NULL;

	dns_lmdbcache_query(search->qpdb->tree, &search->txn);
}

static void
qpc_search_deinit(qpc_search_t *search DNS__DB_FLARG) {
	dns_lmdbtxn_destroy(search->qpdb->tree, &search->txn);
	if (search->zonecut != NULL) {
		qpcnode_t *node = search->zonecut;
		isc_rwlock_t *nlock =
			&search->qpdb->buckets[node->locknum].lock;
		isc_rwlocktype_t nlocktype = isc_rwlocktype_none;

		NODE_RDLOCK(nlock, &nlocktype);
		qpcnode_release(search->qpdb, node, &nlocktype,
				NULL DNS__DB_FLARG_PASS);
		NODE_UNLOCK(nlock, &nlocktype);
	}

	if (search->zonecut_sigheader != NULL) {
		dns_slabheader_detach(&search->zonecut_sigheader);
	}
	if (search->zonecut_header != NULL) {
		dns_slabheader_detach(&search->zonecut_header);
	}
}

static isc_result_t
qpcache_find(dns_db_t *db, const dns_name_t *name, dns_dbversion_t *version,
	     dns_rdatatype_t type, unsigned int options, isc_stdtime_t __now,
	     dns_name_t *foundname,
	     dns_clientinfomethods_t *methods ISC_ATTR_UNUSED,
	     dns_clientinfo_t *clientinfo ISC_ATTR_UNUSED,
	     dns_rdataset_t *rdataset,
	     dns_rdataset_t *sigrdataset DNS__DB_FLARG) {
	qpcnode_t *node = NULL;
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

	/*
	 * Meta-types can't exist in the cache, with the sole exception
	 * of ANY, which matches any type at the node (both ANY and
	 * RRSIG queries are looked up as ANY).
	 */
	if (type == dns_rdatatype_none ||
	    (dns_rdatatype_ismeta(type) && type != dns_rdatatype_any))
	{
		return ISC_R_NOTFOUND;
	}

	qpc_search_t search;
	qpc_search_init(&search, (qpcache_t *)db, options, __now);

	REQUIRE(VALID_QPDB((qpcache_t *)db));
	REQUIRE(version == NULL);

	/* Fast path: probe serialized ancestor DNAMEs and the exact owner
	 * directly.  All selected bytes are copied before the LMDB transaction
	 * ends, so this path has neither a resident-node lock nor a long-lived
	 * reader transaction. */
	unsigned int labels = dns_name_countlabels(name);
	for (unsigned int first = 1; first < labels; first++) {
		dns_name_t ancestor = DNS_NAME_INITEMPTY;
		dns_name_getlabelsequence(name, first, labels - first,
					  &ancestor);
		result = find_dname_at(search.qpdb, search.txn, &ancestor,
					options, search.now, rdataset,
					sigrdataset DNS__DB_FLARG_PASS);
		if (result == DNS_R_DNAME) {
			if (foundname != NULL) {
				dns_name_copy(&ancestor, foundname);
			}
			goto tree_exit;
		}
		if (result != ISC_R_NOTFOUND) {
			goto tree_exit;
		}
	}

	qpcnode_t *locator = new_locator(search.qpdb, name);
	result = find_records_at_name(search.qpdb, search.txn, locator, type,
				      options, search.now, rdataset,
				      sigrdataset DNS__DB_FLARG_PASS);
	qpcnode_unref(locator);
	if (result != ISC_R_NOTFOUND) {
		if (foundname != NULL) {
			dns_name_copy(name, foundname);
		}
		goto tree_exit;
	}
	if ((options & DNS_DBFIND_COVERINGNSEC) != 0) {
		result = find_coveringnsec(&search, name, foundname, rdataset,
					   sigrdataset DNS__DB_FLARG_PASS);
		if (result == DNS_R_COVERINGNSEC) {
			goto tree_exit;
		}
	}
	result = ISC_R_NOTFOUND;
	goto tree_exit;

	/*
	 * Search down from the root of the tree.
	 */
	result = dns_lmdb_lookup(search.txn, name, DNS_DBNAMESPACE_NORMAL, NULL,
			       &search.chain, (void **)&node, NULL);
	if (result != ISC_R_NOTFOUND && foundname != NULL) {
		dns_name_copy(&node->name, foundname);
	}

	/*
	 * Check the QP chain to see if there's a node above us with an
	 * active DNAME rdataset.
	 *
	 * We're only interested in nodes above QNAME, so if the result
	 * was success, then we skip the last item in the chain.
	 */
	unsigned int len = dns_lmdbchain_length(&search.chain);
	if (result == ISC_R_SUCCESS) {
		len--;
	}

	for (unsigned int i = 0; i < len; i++) {
		isc_result_t tresult;
		qpcnode_t *encloser = NULL;

		dns_lmdbchain_node(&search.chain, i, (void **)&encloser, NULL);

		tresult = check_dname(encloser,
				      (void *)&search DNS__DB_FLARG_PASS);
		if (tresult != DNS_R_CONTINUE) {
			result = DNS_R_PARTIALMATCH;
			search.chain.len = i - 1;
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
				&search, name, foundname, rdataset,
				sigrdataset DNS__DB_FLARG_PASS);
			if (result == DNS_R_COVERINGNSEC) {
				goto tree_exit;
			}
		}
		result = ISC_R_NOTFOUND;
		goto tree_exit;
	} else if (result != ISC_R_SUCCESS) {
		goto tree_exit;
	}

	/* The serialized RRset is authoritative.  Materialize the answer while
	 * the short LMDB read transaction is open, then return without taking the
	 * node's slab-list lock.  The legacy list path remains as a fallback for
	 * records created before the typed store was populated. */
	isc_result_t direct_result = find_records_at_name(
		search.qpdb, search.txn, node, type, options, search.now,
		rdataset, sigrdataset DNS__DB_FLARG_PASS);
	if (direct_result != DNS_R_CONTINUE) {
		result = direct_result;
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

	nlock = &search.qpdb->buckets[node->locknum].lock;
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
		    header_trust(header) == dns_trust_secure)
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
				&search, name, foundname, rdataset,
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
			bindrdatasets(search.qpdb, node, nsecheader, nsecsig,
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
				&search, name, foundname, rdataset,
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
		bindrdatasets(search.qpdb, node, found, foundsig, search.now,
			      nlocktype, rdataset,
			      sigrdataset DNS__DB_FLARG_PASS);
	}

node_exit:
	NODE_UNLOCK(nlock, &nlocktype);

tree_exit:
	qpc_search_deinit(&search DNS__DB_FLARG_PASS);

	update_cachestats(search.qpdb, result);
	return result;
}

static isc_result_t
qpcache_findrdataset(dns_db_t *db, dns_dbnode_t *node, dns_dbversion_t *version,
		     dns_rdatatype_t type, dns_rdatatype_t covers,
		     isc_stdtime_t __now, dns_rdataset_t *rdataset,
		     dns_rdataset_t *sigrdataset DNS__DB_FLARG) {
	qpcache_t *qpdb = (qpcache_t *)db;
	qpcnode_t *qpnode = (qpcnode_t *)node;
	dns_typepair_t typepair = DNS_TYPEPAIR_VALUE(type, covers);
	isc_stdtime_t now = __now ? __now : isc_stdtime_now();
	isc_result_t result;

	REQUIRE(VALID_QPDB(qpdb));
	REQUIRE(version == NULL);
	REQUIRE(type != dns_rdatatype_any);

	/*
	 * Meta-types can't exist in the cache, with the sole
	 * exception of ANY, which records the nonexistence of all
	 * types at the node (NXDOMAIN or NODATA(QTYPE=ANY) proof),
	 * but can't be looked up using this function.
	 */
	if (type == dns_rdatatype_none || dns_rdatatype_ismeta(type)) {
		return ISC_R_NOTFOUND;
	}

	dns_lmdbtxn_t *txn = NULL;
	dns_lmdbcache_query(qpdb->tree, &txn);
	isc_region_t value;
	result = dns_lmdb_getrrset(txn, &qpnode->name,
				   DNS_DBNAMESPACE_NORMAL, typepair, &value);
	if (result != ISC_R_SUCCESS && !dns_rdatatype_issig(type)) {
		typepair = dns_typepair_any;
		result = dns_lmdb_getrrset(txn, &qpnode->name,
					   DNS_DBNAMESPACE_NORMAL, typepair,
					   &value);
	}
	if (result != ISC_R_SUCCESS) {
		dns_lmdbtxn_destroy(qpdb->tree, &txn);
		return ISC_R_NOTFOUND;
	}

	qpc_record_t record;
	const unsigned char *data = NULL;
	if (!parse_record(&value, &record, &data)) {
		dns_lmdbtxn_destroy(qpdb->tree, &txn);
		return ISC_R_INVALIDFILE;
	}
	bool active = record.expire > now ||
		      (record.expire == now &&
		       (record.attributes & DNS_SLABHEADERATTR_ZEROTTL) != 0);
	if (!active) {
		dns_lmdbtxn_destroy(qpdb->tree, &txn);
		return ISC_R_NOTFOUND;
	}

	result = bind_record(qpdb, qpnode, typepair, &value, now,
			     rdataset DNS__DB_FLARG_PASS);
	if (result != ISC_R_SUCCESS) {
		dns_lmdbtxn_destroy(qpdb->tree, &txn);
		return result;
	}

	bool negative =
		(record.attributes & DNS_SLABHEADERATTR_NEGATIVE) != 0;
	bool nxdomain =
		(record.attributes & DNS_SLABHEADERATTR_NXDOMAIN) != 0;
	if (!negative && !dns_rdatatype_issig(type) && sigrdataset != NULL) {
		isc_region_t sigvalue;
		dns_typepair_t sigpair = DNS_SIGTYPEPAIR(type);
		if (dns_lmdb_getrrset(txn, &qpnode->name,
					 DNS_DBNAMESPACE_NORMAL, sigpair,
					 &sigvalue) == ISC_R_SUCCESS)
		{
			qpc_record_t sigrecord;
			if (parse_record(&sigvalue, &sigrecord, &data) &&
			    (sigrecord.expire > now ||
			     (sigrecord.expire == now &&
			      (sigrecord.attributes &
			       DNS_SLABHEADERATTR_ZEROTTL) != 0)))
			{
				result = bind_record(qpdb, qpnode, sigpair,
						     &sigvalue, now, sigrdataset
						     DNS__DB_FLARG_PASS);
			}
		}
	}
	dns_lmdbtxn_destroy(qpdb->tree, &txn);

	if (result != ISC_R_SUCCESS) {
		return result;
	}
	if (negative) {
		result = nxdomain ? DNS_R_NCACHENXDOMAIN
				  : DNS_R_NCACHENXRRSET;
	}

	update_cachestats(qpdb, result);

	return result;
}

static isc_result_t
setcachestats(dns_db_t *db, isc_stats_t *stats) {
	qpcache_t *qpdb = (qpcache_t *)db;

	REQUIRE(VALID_QPDB(qpdb));
	REQUIRE(stats != NULL);

	isc_stats_attach(stats, &qpdb->cachestats);
	return ISC_R_SUCCESS;
}

static dns_stats_t *
getrrsetstats(dns_db_t *db) {
	qpcache_t *qpdb = (qpcache_t *)db;

	REQUIRE(VALID_QPDB(qpdb));

	return qpdb->rrsetstats;
}

static isc_result_t
setservestalettl(dns_db_t *db, dns_ttl_t ttl) {
	qpcache_t *qpdb = (qpcache_t *)db;

	REQUIRE(VALID_QPDB(qpdb));

	/* currently no bounds checking.  0 means disable. */
	qpdb->common.serve_stale_ttl = ttl;
	return ISC_R_SUCCESS;
}

static isc_result_t
getservestalettl(dns_db_t *db, dns_ttl_t *ttl) {
	qpcache_t *qpdb = (qpcache_t *)db;

	REQUIRE(VALID_QPDB(qpdb));

	*ttl = qpdb->common.serve_stale_ttl;
	return ISC_R_SUCCESS;
}

static isc_result_t
setservestalerefresh(dns_db_t *db, uint32_t interval) {
	qpcache_t *qpdb = (qpcache_t *)db;

	REQUIRE(VALID_QPDB(qpdb));

	/* currently no bounds checking.  0 means disable. */
	qpdb->serve_stale_refresh = interval;
	return ISC_R_SUCCESS;
}

static isc_result_t
getservestalerefresh(dns_db_t *db, uint32_t *interval) {
	qpcache_t *qpdb = (qpcache_t *)db;

	REQUIRE(VALID_QPDB(qpdb));

	*interval = qpdb->serve_stale_refresh;
	return ISC_R_SUCCESS;
}

static void
qpcnode_expiredata(dns_dbnode_t *node, void *data) {
	qpcnode_t *qpnode = (qpcnode_t *)node;
	qpcache_t *qpdb = (qpcache_t *)qpnode->qpdb;

	dns_slabheader_t *header = data;
	isc_rwlocktype_t nlocktype = isc_rwlocktype_none;

	isc_rwlock_t *nlock = &qpdb->buckets[qpnode->locknum].lock;
	NODE_WRLOCK(nlock, &nlocktype);
	(void)expire_header(qpdb, qpnode, header, &nlocktype,
			    NULL DNS__DB_FILELINE);
	NODE_UNLOCK(nlock, &nlocktype);
}

static void
locator_update(qpcnode_t *node, dns_typepair_t typepair,
	       const dns_trust_t *trust, bool clearprefetch) {
	qpcache_t *qpdb = node->qpdb;
	dns_lmdbtxn_t *txn = NULL;
	dns_lmdbcache_write(qpdb->tree, &txn);
	isc_region_t value;
	if (dns_lmdb_getrrset(txn, &node->name, DNS_DBNAMESPACE_NORMAL,
				 typepair, &value) == ISC_R_SUCCESS)
	{
		qpc_record_t parsed;
		const unsigned char *data = NULL;
		if (parse_record(&value, &parsed, &data)) {
			unsigned char *copy =
				isc_mem_get(qpdb->common.mctx, value.length);
			memmove(copy, value.base, value.length);
			qpc_record_t *record = (qpc_record_t *)copy;
			if (trust != NULL) {
				record->trust = *trust;
			}
			if (clearprefetch) {
				record->attributes &=
					~DNS_SLABHEADERATTR_PREFETCH;
			}
			isc_region_t replacement = {
				.base = copy,
				.length = value.length,
			};
			RUNTIME_CHECK(dns_lmdb_putrrset(
				txn, &node->name, DNS_DBNAMESPACE_NORMAL,
				typepair, &replacement, true) == ISC_R_SUCCESS);
			isc_mem_put(qpdb->common.mctx, copy, value.length);
		}
	}
	dns_lmdbcache_commit(qpdb->tree, &txn);
}

static void
qpcnode_settrust(dns_dbnode_t *node, dns_typepair_t typepair,
		 dns_trust_t trust) {
	qpcnode_t *qpnode = (qpcnode_t *)node;
	qpcache_t *qpdb = qpnode->qpdb;
	if (qpnode->transient) {
		locator_update(qpnode, typepair, &trust, false);
		return;
	}
	isc_rwlocktype_t nlocktype = isc_rwlocktype_none;
	isc_rwlock_t *nlock = &qpdb->buckets[qpnode->locknum].lock;
	dns_lmdbtxn_t *txn = NULL;
	dns_lmdbcache_write(qpdb->tree, &txn);

	NODE_RDLOCK(nlock, &nlocktype);
	DNS_SLABHEADER_FOREACH(header, &qpnode->headers) {
		if (header->typepair == typepair) {
			atomic_store_release(&header->trust, trust);
			break;
		}
	}
	RUNTIME_CHECK(sync_node_records(qpdb, txn, qpnode) == ISC_R_SUCCESS);
	NODE_UNLOCK(nlock, &nlocktype);
	dns_lmdbcache_commit(qpdb->tree, &txn);
}

static void
qpcnode_updateraw(dns_dbnode_t *node, dns_typepair_t typepair,
		  const isc_region_t *raw) {
	qpcnode_t *qpnode = (qpcnode_t *)node;
	qpcache_t *qpdb = qpnode->qpdb;
	INSIST(qpnode->transient);

	dns_lmdbtxn_t *txn = NULL;
	dns_lmdbcache_write(qpdb->tree, &txn);
	isc_region_t value;
	if (dns_lmdb_getrrset(txn, &qpnode->name, DNS_DBNAMESPACE_NORMAL,
				 typepair, &value) == ISC_R_SUCCESS)
	{
		qpc_record_t parsed;
		const unsigned char *data = NULL;
		if (parse_record(&value, &parsed, &data) &&
		    parsed.raw_length == raw->length)
		{
			unsigned char *copy =
				isc_mem_get(qpdb->common.mctx, value.length);
			memmove(copy, value.base, value.length);
			qpc_record_t *record = (qpc_record_t *)copy;
			memmove(record->data, raw->base, raw->length);
			isc_region_t replacement = {
				.base = copy,
				.length = value.length,
			};
			RUNTIME_CHECK(dns_lmdb_putrrset(
				txn, &qpnode->name, DNS_DBNAMESPACE_NORMAL,
				typepair, &replacement, true) == ISC_R_SUCCESS);
			isc_mem_put(qpdb->common.mctx, copy, value.length);
		}
	}
	dns_lmdbcache_commit(qpdb->tree, &txn);
}

static void
qpcnode_expirerdataset(dns_dbnode_t *node, dns_typepair_t typepair) {
	qpcnode_t *qpnode = (qpcnode_t *)node;
	qpcache_t *qpdb = qpnode->qpdb;
	if (qpnode->transient) {
		dns_lmdbtxn_t *txn = NULL;
		dns_lmdbcache_write(qpdb->tree, &txn);
		isc_result_t result = dns_lmdb_deleterrset(
			txn, &qpnode->name, DNS_DBNAMESPACE_NORMAL, typepair);
		RUNTIME_CHECK(result == ISC_R_SUCCESS ||
			      result == ISC_R_NOTFOUND);
		dns_lmdbcache_commit(qpdb->tree, &txn);
		return;
	}
	isc_rwlocktype_t nlocktype = isc_rwlocktype_none;
	isc_rwlock_t *nlock = &qpdb->buckets[qpnode->locknum].lock;
	dns_lmdbtxn_t *txn = NULL;
	dns_lmdbcache_write(qpdb->tree, &txn);

	NODE_WRLOCK(nlock, &nlocktype);
	DNS_SLABHEADER_FOREACH(header, &qpnode->headers) {
		if (header->typepair == typepair) {
			(void)expire_header(qpdb, qpnode, header, &nlocktype,
					    NULL DNS__DB_FILELINE);
			break;
		}
	}
	RUNTIME_CHECK(sync_node_records(qpdb, txn, qpnode) == ISC_R_SUCCESS);
	NODE_UNLOCK(nlock, &nlocktype);
	dns_lmdbcache_commit(qpdb->tree, &txn);
}

static void
qpcnode_clearprefetch(dns_dbnode_t *node, dns_typepair_t typepair) {
	qpcnode_t *qpnode = (qpcnode_t *)node;
	qpcache_t *qpdb = qpnode->qpdb;
	if (qpnode->transient) {
		locator_update(qpnode, typepair, NULL, true);
		return;
	}
	isc_rwlocktype_t nlocktype = isc_rwlocktype_none;
	isc_rwlock_t *nlock = &qpdb->buckets[qpnode->locknum].lock;
	dns_lmdbtxn_t *txn = NULL;
	dns_lmdbcache_write(qpdb->tree, &txn);

	NODE_RDLOCK(nlock, &nlocktype);
	DNS_SLABHEADER_FOREACH(header, &qpnode->headers) {
		if (header->typepair == typepair) {
			DNS_SLABHEADER_CLRATTR(
				header, DNS_SLABHEADERATTR_PREFETCH);
			break;
		}
	}
	RUNTIME_CHECK(sync_node_records(qpdb, txn, qpnode) == ISC_R_SUCCESS);
	NODE_UNLOCK(nlock, &nlocktype);
	dns_lmdbcache_commit(qpdb->tree, &txn);
}

static void
qpcache__destroy_rcu(struct rcu_head *rcu_head) {
	qpcache_t *qpdb = caa_container_of(rcu_head, qpcache_t, rcu_head);
	char buf[DNS_NAME_FORMATSIZE];

	if (dns_name_dynamic(&qpdb->common.origin)) {
		dns_name_format(&qpdb->common.origin, buf, sizeof(buf));
	} else {
		strlcpy(buf, "<UNKNOWN>", sizeof(buf));
	}
	isc_log_write(DNS_LOGCATEGORY_DATABASE, DNS_LOGMODULE_CACHE,
		      ISC_LOG_DEBUG(DNS_QPCACHE_LOG_STATS_LEVEL), "done %s(%s)",
		      __func__, buf);

	if (dns_name_dynamic(&qpdb->common.origin)) {
		dns_name_free(&qpdb->common.origin, qpdb->common.mctx);
	}

	for (size_t i = 0; i < qpdb->buckets_count; i++) {
		NODE_DESTROYLOCK(&qpdb->buckets[i].lock);

		INSIST(ISC_SIEVE_EMPTY(qpdb->buckets[i].sieve));

		INSIST(isc_queue_empty(&qpdb->buckets[i].deadnodes));
		isc_queue_destroy(&qpdb->buckets[i].deadnodes);
	}

	dns_stats_detach(&qpdb->rrsetstats);

	if (qpdb->cachestats != NULL) {
		isc_stats_detach(&qpdb->cachestats);
	}

	isc_refcount_destroy(&qpdb->references);
	isc_refcount_destroy(&qpdb->common.references);

	isc_rwlock_destroy(&qpdb->lock);
	qpdb->common.magic = 0;
	qpdb->common.impmagic = 0;

	isc_mem_putanddetach(&qpdb->common.mctx, qpdb,
			     sizeof(*qpdb) + qpdb->buckets_count *
						     sizeof(qpdb->buckets[0]));
}

static void
qpcache__destroy(qpcache_t *qpdb) {
	dns_lmdbcache_destroy(&qpdb->tree);

	call_rcu(&qpdb->rcu_head, qpcache__destroy_rcu);
}

static void
qpcache_destroy(dns_db_t *arg) {
	qpcache_t *qpdb = (qpcache_t *)arg;

	qpcache_detach(&qpdb);
}

/*%
 * Clean up dead nodes.  These are nodes which have no references, and
 * have no data.  They are dead but we could not or chose not to delete
 * them when we deleted all the data at that node because we did not want
 * to wait for the tree write lock.
 */
static void
cleanup_deadnodes(qpcache_t *qpdb, uint16_t locknum) {
	isc_rwlocktype_t nlocktype = isc_rwlocktype_none;
	isc_rwlock_t *nlock = &qpdb->buckets[locknum].lock;
	qpcnode_t *qpnode = NULL, *qpnext = NULL;
	isc_queue_t deadnodes;
	dns_lmdbtxn_t *txn = NULL;

	INSIST(locknum < qpdb->buckets_count);

	isc_queue_init(&deadnodes);

	dns_lmdbcache_write(qpdb->tree, &txn);

	NODE_WRLOCK(nlock, &nlocktype);

	isc_queue_splice(&deadnodes, &qpdb->buckets[locknum].deadnodes);

	isc_queue_for_each_entry_safe(&deadnodes, qpnode, qpnext, deadlink) {
		qpcnode_release(qpdb, qpnode, &nlocktype, txn DNS__DB_FILELINE);
	}

	NODE_UNLOCK(nlock, &nlocktype);

	dns_lmdbcache_commit(qpdb->tree, &txn);
}

static void
cleanup_deadnodes_cb(void *arg) {
	qpcache_t *qpdb = arg;
	uint16_t locknum = isc_tid();

	cleanup_deadnodes(qpdb, locknum);
	qpcache_unref(qpdb);
}
static qpcnode_t *
new_qpcnode(qpcache_t *qpdb, const dns_name_t *name, dns_namespace_t nspace) {
	qpcnode_t *newdata = isc_mem_get(qpdb->common.mctx, sizeof(*newdata));
	*newdata = (qpcnode_t){
		.headers = CDS_LIST_HEAD_INIT(newdata->headers),
		.methods = &qpcnode_methods,
		.qpdb = qpdb,
		.name = DNS_NAME_INITEMPTY,
		.nspace = nspace,
		.references = ISC_REFCOUNT_INITIALIZER(1),
		.locknum = isc_random_uniform(qpdb->buckets_count),
	};

	isc_mem_attach(qpdb->common.mctx, &newdata->mctx);
	dns_name_dup(name, newdata->mctx, &newdata->name);

#ifdef DNS_DB_NODETRACE
	fprintf(stderr, "new_qpcnode:%s:%s:%d:%p->references = 1\n", __func__,
		__FILE__, __LINE__ + 1, name);
#endif
	return newdata;
}

static qpcnode_t *
new_locator(qpcache_t *qpdb, const dns_name_t *name) {
	qpcnode_t *node =
		new_qpcnode(qpdb, name, DNS_DBNAMESPACE_NORMAL);
	node->transient = true;
	return node;
}

static isc_result_t
qpcache_findnode(dns_db_t *db, const dns_name_t *name, bool create,
		 dns_clientinfomethods_t *methods ISC_ATTR_UNUSED,
		 dns_clientinfo_t *clientinfo ISC_ATTR_UNUSED,
		 dns_dbnode_t **nodep DNS__DB_FLARG) {
	qpcache_t *qpdb = (qpcache_t *)db;
	if (!create) {
		dns_lmdbtxn_t *txn = NULL;
		dns_lmdbcache_query(qpdb->tree, &txn);
		bool found = dns_lmdb_hasrrsets(
			txn, name, DNS_DBNAMESPACE_NORMAL);
		dns_lmdbtxn_destroy(qpdb->tree, &txn);
		if (!found) {
			return ISC_R_NOTFOUND;
		}
	}

	qpcnode_t *node = new_locator(qpdb, name);
	qpcnode_acquire(qpdb, node,
			isc_rwlocktype_none DNS__DB_FLARG_PASS);
	qpcnode_unref(node);
	*nodep = (dns_dbnode_t *)node;
	return ISC_R_SUCCESS;
}

static isc_result_t
qpcache_createiterator(dns_db_t *db, unsigned int options ISC_ATTR_UNUSED,
		       dns_dbiterator_t **iteratorp) {
	qpcache_t *qpdb = (qpcache_t *)db;
	qpc_dbit_t *qpdbiter = NULL;

	REQUIRE(VALID_QPDB(qpdb));

	qpdbiter = isc_mem_get(qpdb->common.mctx, sizeof(*qpdbiter));
	*qpdbiter = (qpc_dbit_t){
		.common.methods = &dbiterator_methods,
		.common.magic = DNS_DBITERATOR_MAGIC,
		.paused = true,
	};

	qpdbiter->name = dns_fixedname_initname(&qpdbiter->fixed);
	dns_db_attach(db, &qpdbiter->common.db);
	dns_lmdbcache_snapshot(qpdb->tree, &qpdbiter->snap);
	dns_lmdbiter_init(dns_lmdbsnap_txn(qpdbiter->snap), &qpdbiter->iter);

	*iteratorp = (dns_dbiterator_t *)qpdbiter;
	return ISC_R_SUCCESS;
}

static bool
iterator_active(qpcache_t *qpdb, qpc_rditer_t *iterator,
		dns_slabheader_t *header) {
	/*
	 * If this header is still active then return it.
	 */
	if (ACTIVE(header, iterator->common.now)) {
		return true;
	}

	dns_ttl_t stale_ttl = header->expire + STALE_TTL(header, qpdb);

	/*
	 * If we are not returning stale records or the rdataset is
	 * too old don't return it.
	 */
	if (!STALEOK(iterator) || (iterator->common.now > stale_ttl)) {
		return false;
	}
	return true;
}

typedef struct all_records_arg {
	qpcache_t *qpdb;
	qpcnode_t *node;
	qpc_rditer_t *iterator;
} all_records_arg_t;

static isc_result_t
collect_all_record(dns_typepair_t typepair, const isc_region_t *value,
		   void *arg) {
	all_records_arg_t *all = arg;
	qpc_record_t record;
	const unsigned char *data = NULL;
	if (!parse_record(value, &record, &data)) {
		return ISC_R_INVALIDFILE;
	}
	bool active = record.expire > all->iterator->common.now ||
		      (record.expire == all->iterator->common.now &&
		       (record.attributes & DNS_SLABHEADERATTR_ZEROTTL) != 0);
	if (!active && !EXPIREDOK(all->iterator)) {
		dns_ttl_t stale_ttl =
			(record.attributes & DNS_SLABHEADERATTR_NXDOMAIN) != 0
				? 0
				: all->qpdb->common.serve_stale_ttl;
		if ((all->iterator->common.options & DNS_DB_STALEOK) == 0 ||
		    (record.attributes & DNS_SLABHEADERATTR_ZEROTTL) != 0 ||
		    record.expire + stale_ttl <= all->iterator->common.now)
		{
			return ISC_R_SUCCESS;
		}
	}
	dns_rdataset_t *rdataset =
		isc_mem_get(all->qpdb->common.mctx, sizeof(*rdataset));
	dns_rdataset_init(rdataset);
	isc_result_t result = bind_record(
		all->qpdb, all->node, typepair, value,
		all->iterator->common.now, rdataset DNS__DB_FILELINE);
	if (result != ISC_R_SUCCESS) {
		isc_mem_put(all->qpdb->common.mctx, rdataset,
			    sizeof(*rdataset));
		return result;
	}
	ISC_LIST_FOREACH(all->iterator->rdatasets, existing, link) {
		if (rdataset->allocated.cache_order <
		    existing->allocated.cache_order)
		{
			ISC_LIST_INSERTBEFORE(all->iterator->rdatasets, existing,
					      rdataset, link);
			return ISC_R_SUCCESS;
		}
	}
	ISC_LIST_APPEND(all->iterator->rdatasets, rdataset, link);
	return ISC_R_SUCCESS;
}

static isc_result_t
qpcache_allrdatasets(dns_db_t *db, dns_dbnode_t *node, dns_dbversion_t *version,
		     unsigned int options, isc_stdtime_t __now,
		     dns_rdatasetiter_t **iteratorp DNS__DB_FLARG) {
	qpcache_t *qpdb = (qpcache_t *)db;
	qpcnode_t *qpnode = (qpcnode_t *)node;
	qpc_rditer_t *iterator = NULL;
	isc_rwlocktype_t nlocktype = isc_rwlocktype_none;
	isc_rwlock_t *nlock = &qpdb->buckets[qpnode->locknum].lock;

	REQUIRE(VALID_QPDB(qpdb));
	REQUIRE(version == NULL);

	iterator = isc_mem_get(qpdb->common.mctx, sizeof(*iterator));
	*iterator = (qpc_rditer_t){
		.common.magic = DNS_RDATASETITER_MAGIC,
		.common.methods = &rdatasetiter_methods,
		.common.db = db,
		.common.node = node,
		.common.options = options,
		.common.now = __now ? __now : isc_stdtime_now(),
		.rdatasets = ISC_LIST_INITIALIZER,
	};

	qpcnode_acquire(qpdb, qpnode, isc_rwlocktype_none DNS__DB_FLARG_PASS);
	if (qpnode->transient) {
		dns_lmdbtxn_t *txn = NULL;
		dns_lmdbcache_query(qpdb->tree, &txn);
		all_records_arg_t all = {
			.qpdb = qpdb,
			.node = qpnode,
			.iterator = iterator,
		};
		isc_result_t result = dns_lmdb_foreachrrset(
			txn, &qpnode->name, DNS_DBNAMESPACE_NORMAL,
			collect_all_record, &all);
		dns_lmdbtxn_destroy(qpdb->tree, &txn);
		if (result != ISC_R_SUCCESS && result != ISC_R_NOTFOUND) {
			dns_rdatasetiter_t *it =
				(dns_rdatasetiter_t *)iterator;
			rdatasetiter_destroy(&it DNS__DB_FLARG_PASS);
			return result;
		}
		*iteratorp = (dns_rdatasetiter_t *)iterator;
		return ISC_R_SUCCESS;
	}

	NODE_RDLOCK(nlock, &nlocktype);

	DNS_SLABHEADER_FOREACH(header, &qpnode->headers) {
		if (EXPIREDOK(iterator) ||
		    iterator_active(qpdb, iterator, header))
		{
			dns_rdataset_t *rdataset =
				isc_mem_get(qpnode->mctx, sizeof(*rdataset));
			dns_rdataset_init(rdataset);

			bindrdataset(qpdb, qpnode, header, iterator->common.now,
				     nlocktype, rdataset DNS__DB_FLARG_PASS);

			ISC_LIST_APPEND(iterator->rdatasets, rdataset, link);
		}
	}

	NODE_UNLOCK(nlock, &nlocktype);

	*iteratorp = (dns_rdatasetiter_t *)iterator;

	return ISC_R_SUCCESS;
}

static bool
overmaxtype(qpcache_t *qpdb, uint32_t ntypes) {
	if (qpdb->maxtypepername == 0) {
		return false;
	}

	return ntypes >= qpdb->maxtypepername;
}

static bool
prio_header(dns_slabheader_t *header) {
	return prio_type(header->typepair);
}

static void
qpcnode_attachnode(dns_dbnode_t *source, dns_dbnode_t **targetp DNS__DB_FLARG) {
	REQUIRE(targetp != NULL && *targetp == NULL);

	qpcnode_t *node = (qpcnode_t *)source;
	qpcache_t *qpdb = (qpcache_t *)node->qpdb;

	qpcnode_acquire(qpdb, node, isc_rwlocktype_none DNS__DB_FLARG_PASS);

	*targetp = source;
}

static void
qpcnode_detachnode(dns_dbnode_t **nodep DNS__DB_FLARG) {
	qpcnode_t *node = NULL;
	isc_rwlocktype_t nlocktype = isc_rwlocktype_none;
	isc_rwlock_t *nlock = NULL;

	REQUIRE(nodep != NULL && *nodep != NULL);

	node = (qpcnode_t *)(*nodep);
	qpcache_t *qpdb = (qpcache_t *)node->qpdb;
	*nodep = NULL;
	if (node->transient) {
		/* Transient LMDB locators are never reachable through an index or
		 * shared slab list, so their final reference needs no node lock. */
		qpcache_ref(qpdb);
		(void)qpcnode_erefs_decrement(qpdb, node DNS__DB_FLARG_PASS);
		qpcnode_unref(node);
		qpcache_unref(qpdb);
		return;
	}
	nlock = &qpdb->buckets[node->locknum].lock;

	REQUIRE(VALID_QPDB(qpdb));

	/*
	 * We can't destroy qpcache while holding a nodelock, so we need to
	 * reference it before acquiring the lock and release it afterward.
	 * Additionally, we must ensure that we don't destroy the database while
	 * the NODE_LOCK is locked.
	 */
	qpcache_ref(qpdb);

	rcu_read_lock();
	NODE_RDLOCK(nlock, &nlocktype);
	qpcnode_release(qpdb, node, &nlocktype, NULL DNS__DB_FLARG_PASS);
	NODE_UNLOCK(nlock, &nlocktype);
	rcu_read_unlock();

	qpcache_detach(&qpdb);
}

static isc_result_t
check_ncache_block(qpcache_t *qpdb, qpcnode_t *qpnode, dns_slabheader_t *header,
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
		if (trust >= header_trust(header)) {
			header_delete(qpnode, header);
			return DNS_R_CONTINUE;
		} else {
			qpcache_hit(qpdb, header);
			bindrdataset(qpdb, qpnode, header, now, nlocktype,
				     addedrdataset DNS__DB_FLARG_PASS);
			return DNS_R_UNCHANGED;
		}
	}
	return ISC_R_SUCCESS;
}

static isc_result_t
add(qpcache_t *qpdb, qpcnode_t *qpnode, dns_slabheader_t *newheader,
    unsigned int options, dns_rdataset_t *addedrdataset, isc_stdtime_t now,
    isc_rwlocktype_t nlocktype, dns_lmdbtxn_t *txn DNS__DB_FLARG) {
	dns_slabheader_t *prioheader = NULL, *evictheader = NULL;
	dns_slabheader_t *oldheader = NULL, *related = NULL;
	dns_trust_t trust;
	uint32_t ntypes = 0;
	dns_rdatatype_t rdtype = DNS_TYPEPAIR_TYPE(newheader->typepair);
	dns_rdatatype_t covers = DNS_TYPEPAIR_COVERS(newheader->typepair);
	qpc_search_t search = (qpc_search_t){
		.qpdb = qpdb,
		.now = now,
	};

	REQUIRE(rdtype != dns_rdatatype_none);
	if (dns_rdatatype_issig(rdtype)) {
		/*
		 * signature must be either negative or cover something
		 * that's not a signature
		 */
		REQUIRE(NEGATIVE(newheader) || (covers != dns_rdatatype_none &&
						!dns_rdatatype_issig(covers)));
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

	/*
	 * An unvalidated negative entry covering all types (NXDOMAIN or
	 * NODATA(QTYPE=ANY)) must not purge secure data. Check for it in a
	 * separate pass first: evicting as we go and bailing out later would
	 * destroy lower-trust siblings before we found the secure header.
	 */
	if (NEGATIVE(newheader) && rdtype == dns_rdatatype_any &&
	    trust < dns_trust_secure)
	{
		DNS_SLABHEADER_FOREACH(header, &qpnode->headers) {
			if (ACTIVE(header, now) &&
			    header_trust(header) >= dns_trust_secure)
			{
				qpcache_hit(qpdb, header);
				bindrdataset(qpdb, qpnode, header, now,
					     nlocktype,
					     addedrdataset DNS__DB_FLARG_PASS);
				return DNS_R_UNCHANGED;
			}
		}
	}

	DNS_SLABHEADER_FOREACH(header, &qpnode->headers) {
		if (NEGATIVE(newheader)) {
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
		if (NEGATIVE(header) && !NEGATIVE(newheader) &&
		    ACTIVE(header, now))
		{
			/*
			 * There's an existing NXDOMAIN or negative
			 * covered type in the cache. If it's more
			 * trusted than the new data, keep it, but
			 * if not, purge and replace it.
			 */
			isc_result_t result = check_ncache_block(
				qpdb, qpnode, header, newheader, trust,
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
		 * Trying to add an rdataset with lower trust to a cache
		 * DB has no effect, provided that the cache data isn't
		 * stale. If the cache data is stale, new lower trust
		 * data will supersede it below. Unclear what the best
		 * policy is here.
		 */
		dns_trust_t oldtrust = header_trust(oldheader);
		if (trust < oldtrust && ACTIVE(oldheader, now)) {
			qpcache_hit(qpdb, oldheader);
			bindrdataset(qpdb, qpnode, oldheader, now, nlocktype,
				     addedrdataset DNS__DB_FLARG_PASS);
			if (ACTIVE(oldheader, now) &&
			    (options & DNS_DBADD_EQUALOK) != 0 &&
			    dns_rdataslab_equalx(
				    oldheader, newheader, qpdb->common.rdclass,
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
		    newheader->trust < oldtrust &&
		    oldheader->expire < newheader->expire &&
		    dns_rdataslab_equalx(
			    oldheader, newheader, qpdb->common.rdclass,
			    DNS_TYPEPAIR_TYPE(oldheader->typepair)))
		{
			if (oldheader->noqname == NULL &&
			    newheader->noqname != NULL)
			{
				oldheader->noqname = newheader->noqname;
				newheader->noqname = NULL;
			}
			qpcache_hit(qpdb, oldheader);
			bindrdataset(qpdb, qpnode, oldheader, now, nlocktype,
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
			qpcache_hit(qpdb, oldheader);
			bindrdataset(qpdb, qpnode, oldheader, now, nlocktype,
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
		qpcache_hit(qpdb, related);
		related->related = dns_slabheader_ref(newheader);
		newheader->related = dns_slabheader_ref(related);
	}

	bindrdataset(qpdb, qpnode, newheader, now, nlocktype,
		     addedrdataset DNS__DB_FLARG_PASS);

	if (oldheader == NULL && overmaxtype(qpdb, ntypes)) {
		INSIST(evictheader != newheader);

		if (evictheader != NULL) {
			INSIST(evictheader->related != newheader);
			if (evictheader->related != NULL) {
				header_delete(qpnode, evictheader->related);
			}
			header_delete(qpnode, evictheader);
		}
	}

	qpcache_miss(qpdb, newheader, &nlocktype, txn DNS__DB_FLARG_PASS);

	/*
	 * We've added a proof that a rdtype doesn't exist.
	 *
	 * Delete the related rrsig in the cache.
	 */
	if (NEGATIVE(newheader) && !dns_rdatatype_issig(rdtype) &&
	    related != NULL)
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

	CHECK(dns_rdataset_getnoqname(rdataset, &name, &neg, &negsig));

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
	dns_rdataset_cleanup(&neg);
	dns_rdataset_cleanup(&negsig);

	return result;
}

static isc_result_t
qpcache_addrdataset(dns_db_t *db, dns_dbnode_t *node, dns_dbversion_t *version,
		    isc_stdtime_t __now, dns_rdataset_t *rdataset,
		    unsigned int options,
		    dns_rdataset_t *addedrdataset DNS__DB_FLARG) {
	qpcache_t *qpdb = (qpcache_t *)db;
	qpcnode_t *qpnode = (qpcnode_t *)node;
	isc_region_t region;
	dns_slabheader_t *newheader = NULL;
	isc_result_t result;
	isc_rwlocktype_t nlocktype = isc_rwlocktype_none;
	isc_stdtime_t now = __now ? __now : isc_stdtime_now();

	REQUIRE(VALID_QPDB(qpdb));
	REQUIRE(version == NULL);

	/*
	 * Meta-types can't be added to the cache, with the sole
	 * exception of a negative ANY entry, which records the
	 * nonexistence of all types at the node (NXDOMAIN or
	 * NODATA(QTYPE=ANY) proof).
	 */
	if (rdataset->type == dns_rdatatype_none ||
	    (dns_rdatatype_ismeta(rdataset->type) &&
	     !(rdataset->type == dns_rdatatype_any &&
	       rdataset->attributes.negative)))
	{
		return ISC_R_NOTIMPLEMENTED;
	}

	result = dns_rdataslab_fromrdataset(rdataset, qpnode->mctx, &region,
					    qpdb->maxrrperset);
	if (result != ISC_R_SUCCESS) {
		if (result == DNS_R_TOOMANYRECORDS) {
			dns__db_logtoomanyrecords((dns_db_t *)qpdb,
						  &qpnode->name, rdataset->type,
						  "adding", qpdb->maxrrperset);
		}
		return result;
	}

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
		CHECK(addnoqname(newheader->mctx, newheader, qpdb->maxrrperset,
				 rdataset));
	}

	dns_lmdbtxn_t *txn = NULL;
	dns_lmdbcache_write(qpdb->tree, &txn);
	qpcnode_t *worknode = new_locator(qpdb, &qpnode->name);
	RUNTIME_CHECK(load_node_records(qpdb, txn, worknode) == ISC_R_SUCCESS);
	DNS_SLABHEADER_FOREACH(header, &worknode->headers) {
		header->node = node;
	}
	nlocktype = isc_rwlocktype_write;

	result = add(qpdb, worknode, newheader, options, addedrdataset, now,
		     nlocktype, txn DNS__DB_FLARG_PASS);
	isc_result_t sync_result = sync_node_records(qpdb, txn, worknode);
	RUNTIME_CHECK(sync_result == ISC_R_SUCCESS);

	if (result == ISC_R_SUCCESS) {
		DNS_SLABHEADER_SETATTR(newheader, DNS_SLABHEADERATTR_STATCOUNT);
		update_rrsetstats(qpdb->rrsetstats, newheader->typepair,
				  newheader->attributes, true);
	} else {
		dns_slabheader_detach(&newheader);
	}

	dns_lmdbcache_commit(qpdb->tree, &txn);
	DNS_SLABHEADER_FOREACH(header2, &worknode->headers) {
		DNS_SLABHEADER_CLRATTR(header2,
				       DNS_SLABHEADERATTR_STATCOUNT);
	}
	qpcnode_unref(worknode);

	if (result == ISC_R_EXISTS) {
		result = ISC_R_SUCCESS;
	}

	return result;
cleanup:
	dns_slabheader_detach(&newheader);
	return result;
}

static isc_result_t
qpcache_deleterdataset(dns_db_t *db, dns_dbnode_t *node,
		       dns_dbversion_t *version, dns_rdatatype_t type,
		       dns_rdatatype_t covers DNS__DB_FLARG) {
	qpcache_t *qpdb = (qpcache_t *)db;
	qpcnode_t *qpnode = (qpcnode_t *)node;
	isc_result_t result = DNS_R_UNCHANGED;
	isc_rwlocktype_t nlocktype = isc_rwlocktype_none;
	isc_rwlock_t *nlock = NULL;
	dns_typepair_t typepair;

	REQUIRE(VALID_QPDB(qpdb));
	REQUIRE(version == NULL);

	/*
	 * Type none can't exist in the cache; note that type ANY is
	 * a valid argument here because it matches the negative cache
	 * entry left behind by an NXDOMAIN or NODATA(QTYPE=ANY) response.
	 */
	if (type == dns_rdatatype_none ||
	    (dns_rdatatype_ismeta(type) && type != dns_rdatatype_any))
	{
		return ISC_R_NOTIMPLEMENTED;
	}

	typepair = DNS_TYPEPAIR_VALUE(type, covers);
	if (qpnode->transient) {
		dns_lmdbtxn_t *txn = NULL;
		dns_lmdbcache_write(qpdb->tree, &txn);
		result = dns_lmdb_deleterrset(txn, &qpnode->name,
					       DNS_DBNAMESPACE_NORMAL, typepair);
		if (typepair == DNS_TYPEPAIR(dns_rdatatype_nsec)) {
			isc_result_t nsec_result = dns_lmdb_deleterrset(
				txn, &qpnode->name, DNS_DBNAMESPACE_NSEC,
				typepair);
			RUNTIME_CHECK(nsec_result == ISC_R_SUCCESS ||
				      nsec_result == ISC_R_NOTFOUND);
		}
		dns_lmdbcache_commit(qpdb->tree, &txn);
		return result == ISC_R_NOTFOUND ? DNS_R_UNCHANGED : result;
	}

	dns_lmdbtxn_t *txn = NULL;
	dns_lmdbcache_write(qpdb->tree, &txn);
	nlock = &qpdb->buckets[qpnode->locknum].lock;
	NODE_WRLOCK(nlock, &nlocktype);
	DNS_SLABHEADER_FOREACH(header, &qpnode->headers) {
		if (header->typepair == typepair) {
			header_delete(qpnode, header);
			result = ISC_R_SUCCESS;
			break;
		}
	}
	RUNTIME_CHECK(sync_node_records(qpdb, txn, qpnode) == ISC_R_SUCCESS);
	NODE_UNLOCK(nlock, &nlocktype);
	dns_lmdbcache_commit(qpdb->tree, &txn);

	return result;
}

static unsigned int
nodecount(dns_db_t *db) {
	qpcache_t *qpdb = (qpcache_t *)db;
	dns_qp_memusage_t mu;

	REQUIRE(VALID_QPDB(qpdb));

	mu = dns_lmdbcache_memusage(qpdb->tree);

	return mu.leaves;
}

isc_result_t
dns__qpcache_create(isc_mem_t *mctx, const dns_name_t *origin,
		    dns_dbtype_t type, dns_rdataclass_t rdclass,
		    unsigned int argc, char *argv[],
		    void *driverarg ISC_ATTR_UNUSED, dns_db_t **dbp) {
	qpcache_t *qpdb = NULL;
	isc_loop_t *loop = isc_loop();
	int i;
	size_t nloops = isc_loopmgr_nloops();

	/* This database implementation only supports cache semantics */
	REQUIRE(type == dns_dbtype_cache);
	REQUIRE(loop != NULL);
	REQUIRE(argc == 0);
	REQUIRE(argv == NULL);

	qpdb = isc_mem_get(mctx,
			   sizeof(*qpdb) + nloops * sizeof(qpdb->buckets[0]));
	*qpdb = (qpcache_t){
		.common.methods = &qpdb_cachemethods,
		.common.origin = DNS_NAME_INITEMPTY,
		.common.rdclass = rdclass,
		.common.attributes = DNS_DBATTR_CACHE,
		.common.references = 1,
		.references = 1,
		.buckets_count = nloops,
	};

	isc_rwlock_init(&qpdb->lock);

	qpdb->buckets_count = isc_loopmgr_nloops();

	dns_rdatasetstats_create(mctx, &qpdb->rrsetstats);
	for (i = 0; i < (int)qpdb->buckets_count; i++) {
		ISC_SIEVE_INIT(qpdb->buckets[i].sieve);

		isc_queue_init(&qpdb->buckets[i].deadnodes);

		NODE_INITLOCK(&qpdb->buckets[i].lock);
	}

	/*
	 * Attach to the mctx.  The database will persist so long as there
	 * are references to it, and attaching to the mctx ensures that our
	 * mctx won't disappear out from under us.
	 */
	isc_mem_attach(mctx, &qpdb->common.mctx);

	/*
	 * Make a copy of the origin name.
	 */
	dns_name_dup(origin, mctx, &qpdb->common.origin);

	/*
	 * Make the qp trie.
	 */
	dns_lmdbcache_create(mctx, &qpmethods, qpdb, &qpdb->tree);

	qpdb->common.magic = DNS_DB_MAGIC;
	qpdb->common.impmagic = QPDB_MAGIC;

	*dbp = (dns_db_t *)qpdb;

	return ISC_R_SUCCESS;
}

/*
 * Rdataset Iterator Methods
 */

static void
rdatasetiter_destroy(dns_rdatasetiter_t **iteratorp DNS__DB_FLARG) {
	qpc_rditer_t *iterator = NULL;

	iterator = (qpc_rditer_t *)(*iteratorp);

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
	qpc_rditer_t *iterator = (qpc_rditer_t *)it;

	iterator->current = ISC_LIST_HEAD(iterator->rdatasets);

	if (iterator->current == NULL) {
		return ISC_R_NOMORE;
	}

	return ISC_R_SUCCESS;
}

static isc_result_t
rdatasetiter_next(dns_rdatasetiter_t *it DNS__DB_FLARG) {
	qpc_rditer_t *iterator = (qpc_rditer_t *)it;

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
	qpc_rditer_t *iterator = (qpc_rditer_t *)it;

	REQUIRE(iterator->current != NULL);

	dns_rdataset_clone(iterator->current, rdataset);
}

/*
 * Database Iterator Methods
 */

static void
reference_iter_node(qpc_dbit_t *qpdbiter DNS__DB_FLARG) {
	qpcache_t *qpdb = (qpcache_t *)qpdbiter->common.db;
	qpcnode_t *node = qpdbiter->node;

	if (node == NULL) {
		return;
	}

	isc_rwlocktype_t nlocktype = isc_rwlocktype_none;
	isc_rwlock_t *nlock = &qpdb->buckets[node->locknum].lock;

	NODE_RDLOCK(nlock, &nlocktype);
	qpcnode_acquire(qpdb, node, nlocktype DNS__DB_FLARG_PASS);
	NODE_UNLOCK(nlock, &nlocktype);
}

static void
dereference_iter_node(qpc_dbit_t *qpdbiter DNS__DB_FLARG) {
	qpcache_t *qpdb = (qpcache_t *)qpdbiter->common.db;
	qpcnode_t *node = qpdbiter->node;
	isc_rwlock_t *nlock = NULL;
	isc_rwlocktype_t nlocktype = isc_rwlocktype_none;

	if (node == NULL) {
		return;
	}

	nlock = &qpdb->buckets[node->locknum].lock;
	NODE_RDLOCK(nlock, &nlocktype);
	qpcnode_release(qpdb, node, &nlocktype, NULL DNS__DB_FLARG_PASS);
	NODE_UNLOCK(nlock, &nlocktype);

	qpdbiter->node = NULL;
}

static void
resume_iteration(qpc_dbit_t *qpdbiter, bool continuing) {
	REQUIRE(qpdbiter->paused);

	/*
	 * If we're being called from dbiterator_next, we may need
	 * to reinitialize the iterator to the current name. The
	 * tree could have changed while it was unlocked, which
	 * would make the iterator traversal inconsistent.
	 *
	 * As long as the iterator is holding a reference to
	 * qpdbiter->node, the node won't be removed from the tree,
	 * so the lookup should always succeed.
	 */
	if (continuing && qpdbiter->node != NULL) {
		isc_result_t result;
		result = dns_lmdb_lookup(dns_lmdbsnap_txn(qpdbiter->snap),
				       qpdbiter->name,
				       DNS_DBNAMESPACE_NORMAL, &qpdbiter->iter,
				       NULL, NULL, NULL);
		INSIST(result == ISC_R_SUCCESS);
	}

	qpdbiter->paused = false;
}

static void
dbiterator_destroy(dns_dbiterator_t **iteratorp DNS__DB_FLARG) {
	qpc_dbit_t *qpdbiter = (qpc_dbit_t *)(*iteratorp);
	qpcache_t *qpdb = (qpcache_t *)qpdbiter->common.db;
	dns_db_t *db = NULL;

	dns_lmdbsnap_destroy(qpdb->tree, &qpdbiter->snap);

	dereference_iter_node(qpdbiter DNS__DB_FLARG_PASS);

	dns_db_attach(qpdbiter->common.db, &db);
	dns_db_detach(&qpdbiter->common.db);

	isc_mem_put(db->mctx, qpdbiter, sizeof(*qpdbiter));
	dns_db_detach(&db);

	*iteratorp = NULL;
}

static isc_result_t
dbiterator_first(dns_dbiterator_t *iterator DNS__DB_FLARG) {
	isc_result_t result;
	qpc_dbit_t *qpdbiter = (qpc_dbit_t *)iterator;

	if (qpdbiter->result != ISC_R_SUCCESS &&
	    qpdbiter->result != ISC_R_NOTFOUND &&
	    qpdbiter->result != DNS_R_PARTIALMATCH &&
	    qpdbiter->result != ISC_R_NOMORE)
	{
		return qpdbiter->result;
	}

	if (qpdbiter->paused) {
		resume_iteration(qpdbiter, false);
	}

	dereference_iter_node(qpdbiter DNS__DB_FLARG_PASS);

	dns_lmdbiter_init(dns_lmdbsnap_txn(qpdbiter->snap), &qpdbiter->iter);
	result = dns_lmdbiter_next(&qpdbiter->iter, (void **)&qpdbiter->node,
				 NULL);

	if (result == ISC_R_SUCCESS &&
	    qpdbiter->node->nspace == DNS_DBNAMESPACE_NORMAL)
	{
		dns_name_copy(&qpdbiter->node->name, qpdbiter->name);
		reference_iter_node(qpdbiter DNS__DB_FLARG_PASS);
	} else if (result == ISC_R_SUCCESS) {
		result = ISC_R_NOMORE;
		qpdbiter->node = NULL;
	} else {
		/* The tree is empty. */
		INSIST(result == ISC_R_NOMORE);
		qpdbiter->node = NULL;
	}

	qpdbiter->result = result;

	if (result != ISC_R_SUCCESS) {
		ENSURE(!qpdbiter->paused);
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
	qpc_dbit_t *qpdbiter = (qpc_dbit_t *)iterator;

	if (qpdbiter->result != ISC_R_SUCCESS &&
	    qpdbiter->result != ISC_R_NOTFOUND &&
	    qpdbiter->result != DNS_R_PARTIALMATCH &&
	    qpdbiter->result != ISC_R_NOMORE)
	{
		return qpdbiter->result;
	}

	if (qpdbiter->paused) {
		resume_iteration(qpdbiter, false);
	}

	dereference_iter_node(qpdbiter DNS__DB_FLARG_PASS);

	result = dns_lmdb_lookup(dns_lmdbsnap_txn(qpdbiter->snap), name,
			       DNS_DBNAMESPACE_NORMAL,
			       &qpdbiter->iter, NULL, (void **)&qpdbiter->node,
			       NULL);

	if (result == ISC_R_SUCCESS || result == DNS_R_PARTIALMATCH) {
		dns_name_copy(&qpdbiter->node->name, qpdbiter->name);
		reference_iter_node(qpdbiter DNS__DB_FLARG_PASS);
	} else {
		qpdbiter->node = NULL;
	}

	qpdbiter->result = (result == DNS_R_PARTIALMATCH) ? ISC_R_SUCCESS
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
	qpc_dbit_t *qpdbiter = (qpc_dbit_t *)iterator;

	REQUIRE(qpdbiter->node != NULL);

	if (qpdbiter->result != ISC_R_SUCCESS) {
		return qpdbiter->result;
	}

	if (qpdbiter->paused) {
		resume_iteration(qpdbiter, true);
	}

	dereference_iter_node(qpdbiter DNS__DB_FLARG_PASS);

	result = dns_lmdbiter_next(&qpdbiter->iter, (void **)&qpdbiter->node,
				 NULL);

	if (result == ISC_R_SUCCESS &&
	    qpdbiter->node->nspace == DNS_DBNAMESPACE_NORMAL)
	{
		dns_name_copy(&qpdbiter->node->name, qpdbiter->name);
		reference_iter_node(qpdbiter DNS__DB_FLARG_PASS);
	} else if (result == ISC_R_SUCCESS) {
		result = ISC_R_NOMORE;
		qpdbiter->node = NULL;
	} else {
		INSIST(result == ISC_R_NOMORE);
		qpdbiter->node = NULL;
	}

	qpdbiter->result = result;
	return result;
}

static isc_result_t
dbiterator_current(dns_dbiterator_t *iterator, dns_dbnode_t **nodep,
		   dns_name_t *name DNS__DB_FLARG) {
	qpcache_t *qpdb = (qpcache_t *)iterator->db;
	qpc_dbit_t *qpdbiter = (qpc_dbit_t *)iterator;
	qpcnode_t *node = qpdbiter->node;

	REQUIRE(qpdbiter->result == ISC_R_SUCCESS);
	REQUIRE(node != NULL);

	if (qpdbiter->paused) {
		resume_iteration(qpdbiter, false);
	}

	if (name != NULL) {
		dns_name_copy(&node->name, name);
	}

	qpcnode_acquire(qpdb, node, isc_rwlocktype_none DNS__DB_FLARG_PASS);

	*nodep = (dns_dbnode_t *)qpdbiter->node;
	return ISC_R_SUCCESS;
}

static isc_result_t
dbiterator_pause(dns_dbiterator_t *iterator) {
	qpc_dbit_t *qpdbiter = (qpc_dbit_t *)iterator;

	if (qpdbiter->result != ISC_R_SUCCESS &&
	    qpdbiter->result != ISC_R_NOTFOUND &&
	    qpdbiter->result != DNS_R_PARTIALMATCH &&
	    qpdbiter->result != ISC_R_NOMORE)
	{
		return qpdbiter->result;
	}

	if (qpdbiter->paused) {
		return ISC_R_SUCCESS;
	}

	qpdbiter->paused = true;

	return ISC_R_SUCCESS;
}

static isc_result_t
dbiterator_origin(dns_dbiterator_t *iterator, dns_name_t *name) {
	qpc_dbit_t *qpdbiter = (qpc_dbit_t *)iterator;

	if (qpdbiter->result != ISC_R_SUCCESS) {
		return qpdbiter->result;
	}

	dns_name_copy(dns_rootname, name);
	return ISC_R_SUCCESS;
}

static void
setmaxrrperset(dns_db_t *db, uint32_t value) {
	qpcache_t *qpdb = (qpcache_t *)db;

	REQUIRE(VALID_QPDB(qpdb));

	qpdb->maxrrperset = value;
}

static void
setmaxtypepername(dns_db_t *db, uint32_t value) {
	qpcache_t *qpdb = (qpcache_t *)db;

	REQUIRE(VALID_QPDB(qpdb));

	qpdb->maxtypepername = value;
}

static void
setcachesize(dns_db_t *db, size_t value) {
	qpcache_t *qpdb = (qpcache_t *)db;

	REQUIRE(VALID_QPDB(qpdb));
	qpdb->max_bytes = value;
}

static isc_result_t
qpcache_clear(dns_db_t *db) {
	qpcache_t *qpdb = (qpcache_t *)db;
	dns_lmdbtxn_t *txn = NULL;

	REQUIRE(VALID_QPDB(qpdb));
	dns_lmdbcache_write(qpdb->tree, &txn);
	isc_result_t result = dns_lmdbcache_clear(txn);
	dns_lmdbcache_commit(qpdb->tree, &txn);
	return result;
}

static dns_dbmethods_t qpdb_cachemethods = {
	.destroy = qpcache_destroy,
	.findnode = qpcache_findnode,
	.find = qpcache_find,
	.createiterator = qpcache_createiterator,
	.findrdataset = qpcache_findrdataset,
	.allrdatasets = qpcache_allrdatasets,
	.addrdataset = qpcache_addrdataset,
	.deleterdataset = qpcache_deleterdataset,
	.nodecount = nodecount,
	.getrrsetstats = getrrsetstats,
	.setcachestats = setcachestats,
	.setservestalettl = setservestalettl,
	.getservestalettl = getservestalettl,
	.setservestalerefresh = setservestalerefresh,
	.getservestalerefresh = getservestalerefresh,
	.setmaxrrperset = setmaxrrperset,
	.setmaxtypepername = setmaxtypepername,
	.setcachesize = setcachesize,
	.clear = qpcache_clear,
};

static void
qpcnode_destroy(qpcnode_t *qpnode) {
	dns_slabheader_t *header = NULL, *header_next = NULL;
	cds_list_for_each_entry_safe(header, header_next, &qpnode->headers,
				     headers_link)
	{
		header_delete(qpnode, header);
	}

	dns_name_free(&qpnode->name, qpnode->mctx);
	isc_mem_putanddetach(&qpnode->mctx, qpnode, sizeof(qpcnode_t));
}

#ifdef DNS_DB_NODETRACE
ISC_REFCOUNT_STATIC_TRACE_IMPL(qpcnode, qpcnode_destroy);
#else
ISC_REFCOUNT_STATIC_IMPL(qpcnode, qpcnode_destroy);
#endif

#ifdef DNS_DB_NODETRACE
ISC_REFCOUNT_STATIC_TRACE_IMPL(qpcache, qpcache__destroy);
#else
ISC_REFCOUNT_STATIC_IMPL(qpcache, qpcache__destroy);
#endif
