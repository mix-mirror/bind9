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
#include <stdbool.h>

#include <isc/log.h>
#include <isc/loop.h>
#include <isc/mem.h>
#include <isc/refcount.h>
#include <isc/result.h>
#include <isc/stats.h>
#include <isc/string.h>
#include <isc/time.h>
#include <isc/timer.h>
#include <isc/util.h>

#include <dns/cache.h>
#include <dns/db.h>
#include <dns/stats.h>

#include "qpcache_p.h"

#ifdef HAVE_JSON_C
#include <json_object.h>
#endif /* HAVE_JSON_C */

#ifdef HAVE_LIBXML2
#include <libxml/xmlwriter.h>
#define ISC_XMLCHAR (const xmlChar *)
#endif /* HAVE_LIBXML2 */

#define CACHE_MAGIC	   ISC_MAGIC('$', '$', '$', '$')
#define VALID_CACHE(cache) ISC_MAGIC_VALID(cache, CACHE_MAGIC)

/***
 ***	Types
 ***/

/*%
 * The actual cache object.
 */

struct dns_cache {
	/* Unlocked. */
	unsigned int magic;
	isc_mutex_t lock;
	isc_mem_t *mctx;  /* Memory context for the dns_cache object */
	isc_mem_t *tmctx; /* Tree memory */
	char *name;
	isc_refcount_t references;

	/* Locked by 'lock'. */
	dns_rdataclass_t rdclass;
	qpcache_t *db;
	dns_ttl_t serve_stale_ttl;
	dns_ttl_t serve_stale_refresh;
	isc_stats_t *stats;
	uint32_t maxrrperset;
	uint32_t maxtypepername;
};

/***
 ***	Functions
 ***/

static void
cache_create_db(dns_cache_t *cache, qpcache_t **dbp, isc_mem_t **tmctxp) {
	qpcache_t *db = NULL;
	isc_mem_t *tmctx = NULL;

	isc_mem_create("cache", &tmctx);
	dns__qpcache_new(tmctx, dns_rootname, cache->rdclass, &db);
	isc_stats_attach(cache->stats, &db->cachestats);
	db->common.serve_stale_ttl = cache->serve_stale_ttl;
	db->serve_stale_refresh = cache->serve_stale_refresh;
	db->maxrrperset = cache->maxrrperset;
	db->maxtypepername = cache->maxtypepername;
	*dbp = db;
	*tmctxp = tmctx;
}

static void
cache_destroy(dns_cache_t *cache) {
	isc_stats_detach(&cache->stats);
	isc_mutex_destroy(&cache->lock);
	isc_mem_free(cache->mctx, cache->name);
	if (cache->tmctx != NULL) {
		isc_mem_detach(&cache->tmctx);
	}
	isc_mem_putanddetach(&cache->mctx, cache, sizeof(*cache));
}

isc_result_t
dns_cache_create(dns_rdataclass_t rdclass, const char *cachename,
		 isc_mem_t *mctx, dns_cache_t **cachep) {
	dns_cache_t *cache = NULL;

	REQUIRE(cachename != NULL);
	REQUIRE(cachep != NULL && *cachep == NULL);

	cache = isc_mem_get(mctx, sizeof(*cache));
	*cache = (dns_cache_t){
		.rdclass = rdclass,
		.name = isc_mem_strdup(mctx, cachename),
		.references = ISC_REFCOUNT_INITIALIZER(1),
		.magic = CACHE_MAGIC,
	};

	isc_mutex_init(&cache->lock);
	isc_mem_attach(mctx, &cache->mctx);

	isc_stats_create(mctx, &cache->stats, dns_cachestatscounter_max);

	/*
	 * Create the database
	 */
	cache_create_db(cache, &cache->db, &cache->tmctx);

	*cachep = cache;
	return ISC_R_SUCCESS;
}

static void
cache_cleanup(dns_cache_t *cache) {
	REQUIRE(VALID_CACHE(cache));

	isc_refcount_destroy(&cache->references);
	cache->magic = 0;

	dns__qpcache_detach(&cache->db);

	cache_destroy(cache);
}

#if DNS_CACHE_TRACE
ISC_REFCOUNT_TRACE_IMPL(dns_cache, cache_cleanup);
#else
ISC_REFCOUNT_IMPL(dns_cache, cache_cleanup);
#endif

void
dns_cache_attachdb(dns_cache_t *cache, dns_db_t **dbp) {
	REQUIRE(VALID_CACHE(cache));
	REQUIRE(dbp != NULL && *dbp == NULL);
	REQUIRE(cache->db != NULL);

	LOCK(&cache->lock);
	dns_db_attach(&cache->db->common, dbp);
	UNLOCK(&cache->lock);
}

const char *
dns_cache_getname(dns_cache_t *cache) {
	REQUIRE(VALID_CACHE(cache));

	return cache->name;
}

void
dns_cache_setcachesize(dns_cache_t *cache, size_t size) {
	REQUIRE(VALID_CACHE(cache));

	/*
	 * Impose a minimum cache size; pathological things happen if there
	 * is too little room.
	 */
	if (size < DNS_CACHE_MINSIZE) {
		size = DNS_CACHE_MINSIZE;
	}

	LOCK(&cache->lock);
	dns__qpcache_setcachesize(cache->db, size);
	UNLOCK(&cache->lock);
}

size_t
dns_cache_getcachesize(dns_cache_t *cache) {
	REQUIRE(VALID_CACHE(cache));

	LOCK(&cache->lock);
	size_t size = dns__qpcache_getcachesize(cache->db);
	UNLOCK(&cache->lock);
	return size;
}

void
dns_cache_setservestalettl(dns_cache_t *cache, dns_ttl_t ttl) {
	REQUIRE(VALID_CACHE(cache));

	LOCK(&cache->lock);
	cache->serve_stale_ttl = ttl;
	UNLOCK(&cache->lock);

	cache->db->common.serve_stale_ttl = ttl;
}

dns_ttl_t
dns_cache_getservestalettl(dns_cache_t *cache) {
	REQUIRE(VALID_CACHE(cache));
	return cache->db->common.serve_stale_ttl;
}

void
dns_cache_setservestalerefresh(dns_cache_t *cache, dns_ttl_t interval) {
	REQUIRE(VALID_CACHE(cache));

	LOCK(&cache->lock);
	cache->serve_stale_refresh = interval;
	UNLOCK(&cache->lock);

	cache->db->serve_stale_refresh = interval;
}

dns_ttl_t
dns_cache_getservestalerefresh(dns_cache_t *cache) {
	REQUIRE(VALID_CACHE(cache));
	return cache->db->serve_stale_refresh;
}

isc_result_t
dns_cache_flush(dns_cache_t *cache) {
	qpcache_t *db = NULL, *olddb = NULL;
	isc_mem_t *tmctx = NULL, *oldtmctx = NULL;

	cache_create_db(cache, &db, &tmctx);

	LOCK(&cache->lock);
	size_t size = dns__qpcache_getcachesize(cache->db);
	oldtmctx = cache->tmctx;
	cache->tmctx = tmctx;
	olddb = cache->db;
	dns__qpcache_setcachesize(olddb, 0);
	cache->db = db;
	dns__qpcache_setcachesize(cache->db, size);
	UNLOCK(&cache->lock);

	dns__qpcache_detach(&olddb);
	isc_mem_detach(&oldtmctx);

	return ISC_R_SUCCESS;
}

static void
clearnode(qpcache_t *db, qpcnode_t *node) {
	isc_rwlock_t *lock = &db->buckets[node->locknum].lock;

	RWLOCK(lock, isc_rwlocktype_write);
	DNS_SLABHEADER_FOREACH(header, &node->headers) {
		dns__qpcache_header_delete(node, header);
	}
	RWUNLOCK(lock, isc_rwlocktype_write);
}

static isc_result_t
cleartree(qpcache_t *db, const dns_name_t *name) {
	isc_result_t result;
	qpc_dbit_t *iter = NULL;
	qpcnode_t *node = NULL, *top = NULL;

	/*
	 * Create the node if it doesn't exist so dns__qpc_dbit_seek()
	 * can find it.  We will continue even if this fails.
	 */
	(void)dns__qpcache_findnode(db, name, true, &top);

	dns__qpcache_createiterator(db, &iter);

	result = dns__qpc_dbit_seek(iter, name);
	if (result == DNS_R_PARTIALMATCH) {
		result = dns__qpc_dbit_next(iter);
	}
	if (result != ISC_R_SUCCESS) {
		goto cleanup;
	}

	while (result == ISC_R_SUCCESS) {
		result = dns__qpc_dbit_current(iter, &node);
		if (result != ISC_R_SUCCESS) {
			goto cleanup;
		}
		/*
		 * Are we done?
		 */
		if (!dns_name_issubdomain(&node->name, name)) {
			goto cleanup;
		}

		clearnode(db, node);
		dns__qpcnode_detach(&node);
		result = dns__qpc_dbit_next(iter);
	}

cleanup:
	if (result == ISC_R_NOMORE || result == ISC_R_NOTFOUND) {
		result = ISC_R_SUCCESS;
	}
	if (node != NULL) {
		dns__qpcnode_detach(&node);
	}
	if (iter != NULL) {
		dns__qpc_dbit_destroy(&iter);
	}
	if (top != NULL) {
		dns__qpcnode_detach(&top);
	}

	return result;
}

isc_result_t
dns_cache_flushname(dns_cache_t *cache, const dns_name_t *name) {
	return dns_cache_flushnode(cache, name, false);
}

isc_result_t
dns_cache_flushnode(dns_cache_t *cache, const dns_name_t *name, bool tree) {
	isc_result_t result;
	qpcnode_t *node = NULL;
	qpcache_t *db = NULL;

	REQUIRE(!(tree && dns_name_isroot(name)));

	LOCK(&cache->lock);
	if (cache->db != NULL) {
		dns__qpcache_attach(cache->db, &db);
	}
	UNLOCK(&cache->lock);
	if (db == NULL) {
		return ISC_R_SUCCESS;
	}

	if (tree) {
		result = cleartree(db, name);
	} else {
		result = dns__qpcache_findnode(db, name, false, &node);
		if (result == ISC_R_NOTFOUND) {
			result = ISC_R_SUCCESS;
			goto cleanup_db;
		}
		if (result != ISC_R_SUCCESS) {
			goto cleanup_db;
		}
		clearnode(db, node);
		dns__qpcnode_detach(&node);
	}

cleanup_db:
	dns__qpcache_detach(&db);
	return result;
}

isc_stats_t *
dns_cache_getstats(dns_cache_t *cache) {
	REQUIRE(VALID_CACHE(cache));
	return cache->stats;
}

void
dns_cache_updatestats(dns_cache_t *cache, isc_result_t result) {
	REQUIRE(VALID_CACHE(cache));
	if (cache->stats == NULL) {
		return;
	}

	switch (result) {
	case ISC_R_SUCCESS:
	case DNS_R_NCACHENXDOMAIN:
	case DNS_R_NCACHENXRRSET:
	case DNS_R_CNAME:
	case DNS_R_DNAME:
	case DNS_R_GLUE:
	case DNS_R_ZONECUT:
	case DNS_R_COVERINGNSEC:
		isc_stats_increment(cache->stats,
				    dns_cachestatscounter_queryhits);
		break;
	default:
		isc_stats_increment(cache->stats,
				    dns_cachestatscounter_querymisses);
	}
}

void
dns_cache_setmaxrrperset(dns_cache_t *cache, uint32_t value) {
	REQUIRE(VALID_CACHE(cache));

	cache->maxrrperset = value;
	if (cache->db != NULL) {
		cache->db->maxrrperset = value;
	}
}

void
dns_cache_setmaxtypepername(dns_cache_t *cache, uint32_t value) {
	REQUIRE(VALID_CACHE(cache));

	cache->maxtypepername = value;
	if (cache->db != NULL) {
		cache->db->maxtypepername = value;
	}
}

/*
 * XXX: Much of the following code has been copied in from statschannel.c.
 * We should refactor this into a generic function in stats.c that can be
 * called from both places.
 */
typedef struct cache_dumparg {
	isc_statsformat_t type;
	void *arg;		 /* type dependent argument */
	int ncounters;		 /* for general statistics */
	int *counterindices;	 /* for general statistics */
	uint64_t *countervalues; /* for general statistics */
	isc_result_t result;
} cache_dumparg_t;

static void
getcounter(isc_statscounter_t counter, uint64_t val, void *arg) {
	cache_dumparg_t *dumparg = arg;

	REQUIRE(counter < dumparg->ncounters);
	dumparg->countervalues[counter] = val;
}

static void
getcounters(isc_stats_t *stats, isc_statsformat_t type, int ncounters,
	    int *indices, uint64_t *values) {
	cache_dumparg_t dumparg;

	memset(values, 0, sizeof(values[0]) * ncounters);

	dumparg.type = type;
	dumparg.ncounters = ncounters;
	dumparg.counterindices = indices;
	dumparg.countervalues = values;

	isc_stats_dump(stats, getcounter, &dumparg, ISC_STATSDUMP_VERBOSE);
}

void
dns_cache_dumpstats(dns_cache_t *cache, FILE *fp) {
	int indices[dns_cachestatscounter_max];
	uint64_t values[dns_cachestatscounter_max];

	REQUIRE(VALID_CACHE(cache));

	getcounters(cache->stats, isc_statsformat_file,
		    dns_cachestatscounter_max, indices, values);

	fprintf(fp, "%20" PRIu64 " %s\n", values[dns_cachestatscounter_hits],
		"cache hits");
	fprintf(fp, "%20" PRIu64 " %s\n", values[dns_cachestatscounter_misses],
		"cache misses");
	fprintf(fp, "%20" PRIu64 " %s\n",
		values[dns_cachestatscounter_queryhits],
		"cache hits (from query)");
	fprintf(fp, "%20" PRIu64 " %s\n",
		values[dns_cachestatscounter_querymisses],
		"cache misses (from query)");
	fprintf(fp, "%20" PRIu64 " %s\n",
		values[dns_cachestatscounter_deletelru],
		"cache records deleted due to memory exhaustion");
	fprintf(fp, "%20" PRIu64 " %s\n",
		values[dns_cachestatscounter_coveringnsec],
		"covering nsec returned");
	fprintf(fp, "%20u %s\n", dns__qpcache_nodecount(cache->db),
		"cache database nodes");

	fprintf(fp, "%20" PRIu64 " %s\n",
		(uint64_t)dns__qpcache_getinuse(cache->db),
		"cache tree memory in use");
}

#ifdef HAVE_LIBXML2
#define TRY0(a)                     \
	do {                        \
		xmlrc = (a);        \
		if (xmlrc < 0)      \
			goto error; \
	} while (0)
static int
renderstat(const char *name, uint64_t value, xmlTextWriterPtr writer) {
	int xmlrc;

	TRY0(xmlTextWriterStartElement(writer, ISC_XMLCHAR "counter"));
	TRY0(xmlTextWriterWriteAttribute(writer, ISC_XMLCHAR "name",
					 ISC_XMLCHAR name));
	TRY0(xmlTextWriterWriteFormatString(writer, "%" PRIu64 "", value));
	TRY0(xmlTextWriterEndElement(writer)); /* counter */

error:
	return xmlrc;
}

int
dns_cache_renderxml(dns_cache_t *cache, void *writer0) {
	int indices[dns_cachestatscounter_max];
	uint64_t values[dns_cachestatscounter_max];
	int xmlrc;
	xmlTextWriterPtr writer = (xmlTextWriterPtr)writer0;

	REQUIRE(VALID_CACHE(cache));

	getcounters(cache->stats, isc_statsformat_file,
		    dns_cachestatscounter_max, indices, values);
	TRY0(renderstat("CacheHits", values[dns_cachestatscounter_hits],
			writer));
	TRY0(renderstat("CacheMisses", values[dns_cachestatscounter_misses],
			writer));
	TRY0(renderstat("QueryHits", values[dns_cachestatscounter_queryhits],
			writer));
	TRY0(renderstat("QueryMisses",
			values[dns_cachestatscounter_querymisses], writer));
	TRY0(renderstat("DeleteLRU", values[dns_cachestatscounter_deletelru],
			writer));
	TRY0(renderstat("CoveringNSEC",
			values[dns_cachestatscounter_coveringnsec], writer));

	TRY0(renderstat("CacheNodes", dns__qpcache_nodecount(cache->db),
			writer));

	TRY0(renderstat("TreeMemInUse", dns__qpcache_getinuse(cache->db),
			writer));
error:
	return xmlrc;
}
#endif /* ifdef HAVE_LIBXML2 */

#ifdef HAVE_JSON_C
#define CHECKMEM(m)                              \
	do {                                     \
		if (m == NULL) {                 \
			result = ISC_R_NOMEMORY; \
			goto error;              \
		}                                \
	} while (0)

isc_result_t
dns_cache_renderjson(dns_cache_t *cache, void *cstats0) {
	isc_result_t result = ISC_R_SUCCESS;
	int indices[dns_cachestatscounter_max];
	uint64_t values[dns_cachestatscounter_max];
	json_object *obj;
	json_object *cstats = (json_object *)cstats0;

	REQUIRE(VALID_CACHE(cache));

	getcounters(cache->stats, isc_statsformat_file,
		    dns_cachestatscounter_max, indices, values);

	obj = json_object_new_int64(values[dns_cachestatscounter_hits]);
	CHECKMEM(obj);
	json_object_object_add(cstats, "CacheHits", obj);

	obj = json_object_new_int64(values[dns_cachestatscounter_misses]);
	CHECKMEM(obj);
	json_object_object_add(cstats, "CacheMisses", obj);

	obj = json_object_new_int64(values[dns_cachestatscounter_queryhits]);
	CHECKMEM(obj);
	json_object_object_add(cstats, "QueryHits", obj);

	obj = json_object_new_int64(values[dns_cachestatscounter_querymisses]);
	CHECKMEM(obj);
	json_object_object_add(cstats, "QueryMisses", obj);

	obj = json_object_new_int64(values[dns_cachestatscounter_deletelru]);
	CHECKMEM(obj);
	json_object_object_add(cstats, "DeleteLRU", obj);

	obj = json_object_new_int64(values[dns_cachestatscounter_coveringnsec]);
	CHECKMEM(obj);
	json_object_object_add(cstats, "CoveringNSEC", obj);

	obj = json_object_new_int64(dns__qpcache_nodecount(cache->db));
	CHECKMEM(obj);
	json_object_object_add(cstats, "CacheNodes", obj);

	obj = json_object_new_int64(isc_mem_inuse(cache->tmctx));
	CHECKMEM(obj);
	json_object_object_add(cstats, "TreeMemInUse", obj);

	result = ISC_R_SUCCESS;
error:
	return result;
}
#endif /* ifdef HAVE_JSON_C */
