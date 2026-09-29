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
#include <isc/hash.h>
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
#include "qpcache_p.h"
#include "rdataslab_p.h"

#define STALE_TTL(header, qpdb) \
	(NXDOMAIN(header) ? 0 : qpdb->common.serve_stale_ttl)

#define ACTIVE(header, now)            \
	(((header)->expire > (now)) || \
	 ((header)->expire == (now) && ZEROTTL(header)))

#define KEEPSTALE(qpdb) ((qpdb)->common.serve_stale_ttl > 0)

/*%
 * Note that "impmagic" is not the first four bytes of the struct, so
 * ISC_MAGIC_VALID cannot be used.
 */
#define QPDB_MAGIC ISC_MAGIC('Q', 'P', 'D', '4')
#define VALID_QPDB(qpdb) \
	((qpdb) != NULL && (qpdb)->common.impmagic == QPDB_MAGIC)

typedef struct qpcache {
	dns_db_t common;
	struct cds_lfht *ht;
	isc_rwlock_t tree_lock;
	dns_qp_t *tree_nsec;
	dns_stats_t *rrsetstats;
	isc_stats_t *cachestats;
	uint32_t maxrrperset;
	uint32_t serve_stale_refresh;
	_Atomic(uint64_t) serial;
} qpcache_t;

typedef struct {
	dns_cacheitem_t item;
	isc_mem_t *mctx;
} qpcache_marker_t;

typedef struct {
	const dns_name_t *name;
	dns_typepair_t type;
} cache_key_t;

typedef struct {
	qpcache_t *qpdb;
	unsigned int options;
	isc_stdtime_t now;
} qpc_search_t;

static dns_dbmethods_t qpdb_cachemethods;

static dns_slabheader_t *
item_header(dns_cacheitem_t *item) {
	return item->marker ? NULL
			    : caa_container_of(item, dns_slabheader_t, item);
}

static uint32_t
key_hash(const cache_key_t *key) {
	return isc_hash32(key->name->ndata, key->name->length, false) ^
	       isc_hash32(&key->type, sizeof(key->type), true);
}

static int
item_match(struct cds_lfht_node *ht_node, const void *arg) {
	const cache_key_t *key = arg;
	dns_cacheitem_t *item = caa_container_of(ht_node, dns_cacheitem_t,
						 ht_node);
	dns_slabheader_t *header = item_header(item);
	return header != NULL && header->typepair == key->type &&
	       dns_name_equal(&header->name, key->name);
}

static dns_slabheader_t *
table_find(qpcache_t *db, const dns_name_t *name, dns_typepair_t type) {
	cache_key_t key = { name, type };
	struct cds_lfht_iter iter;
	cds_lfht_lookup(db->ht, key_hash(&key), item_match, &key, &iter);
	struct cds_lfht_node *node = cds_lfht_iter_get_node(&iter);
	if (node == NULL) {
		return NULL;
	}
	return item_header(caa_container_of(node, dns_cacheitem_t, ht_node));
}

/* The callback touches only storage owned by the retired object. */
static void
item_destroy(struct rcu_head *head) {
	dns_cacheitem_t *item = caa_container_of(head, dns_cacheitem_t,
						 rcu_head);
	dns_slabheader_t *header = item_header(item);
	if (header != NULL) {
		dns_slabheader_detach(&header);
	} else {
		qpcache_marker_t *marker =
			caa_container_of(item, qpcache_marker_t, item);
		isc_mem_putanddetach(&marker->mctx, marker, sizeof(*marker));
	}
}

static void
qp_attach(void *arg ISC_ATTR_UNUSED, void *pval,
	  uint32_t ival ISC_ATTR_UNUSED) {
	dns_slabheader_ref(pval);
}
static void
qp_detach(void *arg ISC_ATTR_UNUSED, void *pval,
	  uint32_t ival ISC_ATTR_UNUSED) {
	dns_slabheader_t *header = pval;
	dns_slabheader_detach(&header);
}
static size_t
qp_makekey(dns_qpkey_t key, void *arg ISC_ATTR_UNUSED, void *pval,
	   uint32_t ival ISC_ATTR_UNUSED) {
	dns_slabheader_t *header = pval;
	return dns_qpkey_fromname(key, &header->name, DNS_DBNAMESPACE_NSEC);
}
static void
qp_triename(void *arg ISC_ATTR_UNUSED, char *buf, size_t size) {
	snprintf(buf, size, "cache-nsec");
}
static dns_qpmethods_t qpmethods = {
	.attach = qp_attach,
	.detach = qp_detach,
	.makekey = qp_makekey,
	.triename = qp_triename,
};

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
	qpcache_t *qpdb = (qpcache_t *)header->db;

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

/* NSEC mutation holds tree_lock(write), including hash publication/removal. */
static void
retire_header(qpcache_t *db, dns_slabheader_t *header) {
	uint16_t attrs = atomic_fetch_and_release(
		&header->attributes, ~DNS_SLABHEADERATTR_STATCOUNT);
	update_rrsetstats(db->rrsetstats, header->typepair, attrs, false);
	call_rcu(&header->item.rcu_head, item_destroy);
}

static size_t
header_delete(qpcache_t *db, dns_slabheader_t *header) {
	bool nsec = header->typepair == DNS_TYPEPAIR(dns_rdatatype_nsec);
	if (nsec) {
		RWLOCK(&db->tree_lock, isc_rwlocktype_write);
	}
	size_t size = 0;
	if (cds_lfht_del(db->ht, &header->item.ht_node) == 0) {
		size = dns_rdataslab_size(header) +
		       dns_name_size(&header->name);
		if (nsec) {
			dns_slabheader_t *indexed = NULL;
			if (dns_qp_getname(db->tree_nsec, &header->name,
					   DNS_DBNAMESPACE_NSEC,
					   (void **)&indexed,
					   NULL) == ISC_R_SUCCESS &&
			    indexed == header)
			{
				RUNTIME_CHECK(
					dns_qp_deletename(
						db->tree_nsec, &header->name,
						DNS_DBNAMESPACE_NSEC, NULL,
						NULL) == ISC_R_SUCCESS);
			}
		}
		retire_header(db, header);
	}
	if (nsec) {
		RWUNLOCK(&db->tree_lock, isc_rwlocktype_write);
	}
	return size;
}

static int
marker_match(struct cds_lfht_node *node, const void *key) {
	return node == key;
}

static void
expire_clock_headers(qpcache_t *db, dns_slabheader_t *newheader,
		     size_t requested) {
	struct cds_lfht_iter iter;
	unsigned int rounds = 0;
	size_t expired = 0;
	qpcache_marker_t *marker = isc_mem_get(db->common.mctx,
					       sizeof(*marker));
	*marker = (qpcache_marker_t){ .item.marker = true };
	isc_mem_attach(db->common.mctx, &marker->mctx);
	cds_lfht_node_init(&marker->item.ht_node);
	uint32_t hash = isc_random32();
	rcu_read_lock();
	cds_lfht_add(db->ht, hash, &marker->item.ht_node);
	cds_lfht_lookup(db->ht, hash, marker_match, &marker->item.ht_node,
			&iter);
	while (expired < requested) {
		cds_lfht_next(db->ht, &iter);
		if (cds_lfht_iter_get_node(&iter) == NULL) {
			cds_lfht_first(db->ht, &iter);
		}
		struct cds_lfht_node *node = cds_lfht_iter_get_node(&iter);
		INSIST(node != NULL);
		if (node == &marker->item.ht_node) {
			if (++rounds == 2) {
				break;
			}
			continue;
		}
		dns_slabheader_t *header = item_header(
			caa_container_of(node, dns_cacheitem_t, ht_node));
		if (header == NULL || header == newheader ||
		    atomic_exchange_relaxed(&header->visited, false))
		{
			continue;
		}
		size_t size = header_delete(db, header);
		expired += size;
		if (size != 0 && db->cachestats != NULL) {
			isc_stats_increment(db->cachestats,
					    dns_cachestatscounter_deletelru);
		}
	}
	INSIST(cds_lfht_del(db->ht, &marker->item.ht_node) == 0);
	call_rcu(&marker->item.rcu_head, item_destroy);
	rcu_read_unlock();
}

static void
qpcache_hit(qpcache_t *db ISC_ATTR_UNUSED, dns_slabheader_t *header) {
	if (!atomic_load_relaxed(&header->visited)) {
		atomic_store_relaxed(&header->visited, true);
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

static void
bindrdataset(qpcache_t *qpdb, dns_slabheader_t *header, isc_stdtime_t now,
	     dns_rdataset_t *rdataset) {
	bool stale = STALE(header);

	if (rdataset == NULL) {
		return;
	}

	dns_slabheader_ref(header);

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

	rdataset->methods = &dns_rdataslab_rdatasetmethods;
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

	dns_db_attach(&qpdb->common, &rdataset->slab.db);
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

typedef enum { ANSWER_MISSING, ANSWER_STALE, ANSWER_OK } answer_rank_t;

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

static inline answer_rank_t
answer_rank(dns_slabheader_t *header, unsigned int options) {
	if (missing_answer(header, options)) {
		return ANSWER_MISSING;
	}

	if (STALE(header)) {
		return ANSWER_STALE;
	}

	return ANSWER_OK;
}

static dns_slabheader_t *
lookup(qpc_search_t *search, const dns_name_t *name, dns_typepair_t type) {
	dns_slabheader_t *header = table_find(search->qpdb, name, type);
	return invalid_header(header, search) ? NULL : header;
}

/* Name-wide negatives coexist with positives. Trust takes precedence over
 * insertion order; freshness takes precedence over both. */
static dns_slabheader_t *
negative_answer(qpc_search_t *search, const dns_name_t *name,
		dns_slabheader_t *answer) {
	dns_slabheader_t *negative = lookup(search, name, dns_typepair_any);
	if (missing_answer(negative, search->options)) {
		return answer;
	}
	if (missing_answer(answer, search->options)) {
		return negative;
	}
	answer_rank_t nrank = answer_rank(negative, search->options);
	answer_rank_t arank = answer_rank(answer, search->options);
	if (nrank != arank) {
		return nrank > arank ? negative : answer;
	}
	dns_trust_t nt = header_trust(negative), at = header_trust(answer);
	return nt > at || (nt == at && negative->serial > answer->serial)
		       ? negative
		       : answer;
}

static void
bind_answer(qpc_search_t *search, dns_slabheader_t *header,
	    dns_rdataset_t *rdataset, dns_rdataset_t *sigrdataset) {
	bindrdataset(search->qpdb, header, search->now, rdataset);
	qpcache_hit(search->qpdb, header);
	if (!NEGATIVE(header) && sigrdataset != NULL) {
		dns_slabheader_t *sig = lookup(
			search, &header->name,
			DNS_SIGTYPEPAIR(DNS_TYPEPAIR_TYPE(header->typepair)));
		if (!missing_answer(sig, search->options) && !NEGATIVE(sig)) {
			bindrdataset(search->qpdb, sig, search->now,
				     sigrdataset);
			qpcache_hit(search->qpdb, sig);
		}
	}
}

static isc_result_t
qpcache_findcache(dns_db_t *db, const dns_name_t *name, dns_rdatatype_t type,
		  unsigned int options, isc_stdtime_t now,
		  dns_rdataset_t *rdataset, dns_rdataset_t *sigrdataset) {
	qpc_search_t search = { (qpcache_t *)db, options,
				now != 0 ? now : isc_stdtime_now() };
	rcu_read_lock();
	dns_slabheader_t *header = lookup(&search, name, DNS_TYPEPAIR(type));
	header = negative_answer(&search, name, header);
	isc_result_t result = ISC_R_NOTFOUND;
	if (!missing_answer(header, options)) {
		bind_answer(&search, header, rdataset, sigrdataset);
		result = !NEGATIVE(header)  ? ISC_R_SUCCESS
			 : NXDOMAIN(header) ? DNS_R_NCACHENXDOMAIN
					    : DNS_R_NCACHENXRRSET;
	}
	rcu_read_unlock();
	return result;
}

static isc_result_t
find_coveringnsec(qpc_search_t *search, const dns_name_t *name,
		  dns_name_t *foundname, dns_rdataset_t *rdataset,
		  dns_rdataset_t *sigrdataset) {
	dns_qpiter_t iter;
	dns_slabheader_t *header = NULL;
	qpcache_t *db = search->qpdb;
	RWLOCK(&db->tree_lock, isc_rwlocktype_read);
	isc_result_t result = dns_qp_lookup(db->tree_nsec, name,
					    DNS_DBNAMESPACE_NSEC, &iter, NULL,
					    (void **)&header, NULL);
	if (result == DNS_R_PARTIALMATCH || result == ISC_R_NOTFOUND) {
		result = dns_qpiter_current(&iter, (void **)&header, NULL);
	}
	if (result == ISC_R_SUCCESS && !invalid_header(header, search) &&
	    !NEGATIVE(header) && header_trust(header) == dns_trust_secure)
	{
		dns_slabheader_t *sig =
			lookup(search, &header->name,
			       DNS_SIGTYPEPAIR(dns_rdatatype_nsec));
		if (sig == NULL || header_trust(sig) == dns_trust_secure) {
			bind_answer(search, header, rdataset, sigrdataset);
			if (foundname != NULL) {
				dns_name_copy(&header->name, foundname);
			}
			result = DNS_R_COVERINGNSEC;
		} else {
			result = ISC_R_NOTFOUND;
		}
	} else {
		result = ISC_R_NOTFOUND;
	}
	RWUNLOCK(&db->tree_lock, isc_rwlocktype_read);
	return result;
}

static isc_result_t
qpcache_find(dns_db_t *db, const dns_name_t *name, dns_dbversion_t *version,
	     dns_rdatatype_t type, unsigned int options, isc_stdtime_t now,
	     dns_name_t *foundname,
	     dns_clientinfomethods_t *methods ISC_ATTR_UNUSED,
	     dns_clientinfo_t *clientinfo ISC_ATTR_UNUSED,
	     dns_rdataset_t *rdataset,
	     dns_rdataset_t *sigrdataset DNS__DB_FLARG) {
	REQUIRE(version == NULL);
	qpc_search_t search = { (qpcache_t *)db, options,
				now != 0 ? now : isc_stdtime_now() };
	if (type == dns_rdatatype_none || dns_rdatatype_ismeta(type) ||
	    dns_rdatatype_issig(type))
	{
		return ISC_R_NOTFOUND;
	}
	isc_result_t result = ISC_R_NOTFOUND;
	dns_slabheader_t *found = NULL;
	rcu_read_lock();
	dns_fixedname_t fixed;
	dns_name_t *ancestor = dns_fixedname_initname(&fixed);
	unsigned int labels = dns_name_countlabels(name);
	for (unsigned int n = 1; n < labels; n++) {
		dns_name_getlabelsequence(name, labels - n, n, ancestor);
		dns_slabheader_t *dname = lookup(
			&search, ancestor, DNS_TYPEPAIR(dns_rdatatype_dname));
		if (!missing_answer(dname, options) && !NEGATIVE(dname) &&
		    negative_answer(&search, ancestor, dname) == dname)
		{
			found = dname;
			result = DNS_R_DNAME;
			goto answer;
		}
	}
	found = lookup(&search, name, DNS_TYPEPAIR(type));
	if (type != dns_rdatatype_nsec && !dns_rdatatype_atparent(type)) {
		dns_slabheader_t *cname = lookup(
			&search, name, DNS_TYPEPAIR(dns_rdatatype_cname));
		if (cname != NULL && !NEGATIVE(cname) &&
		    answer_rank(cname, options) > answer_rank(found, options))
		{
			found = cname;
		}
	}
	found = negative_answer(&search, name, found);
	if (!missing_answer(found, options)) {
		if (NEGATIVE(found)) {
			result = NXDOMAIN(found) ? DNS_R_NCACHENXDOMAIN
						 : DNS_R_NCACHENXRRSET;
		} else if (found->typepair ==
				   DNS_TYPEPAIR(dns_rdatatype_cname) &&
			   type != dns_rdatatype_cname)
		{
			result = DNS_R_CNAME;
		} else {
			result = ISC_R_SUCCESS;
		}
		goto answer;
	}
	if ((options & DNS_DBFIND_COVERINGNSEC) != 0) {
		result = find_coveringnsec(&search, name, foundname, rdataset,
					   sigrdataset);
	}
	goto done;
answer:
	if (foundname != NULL) {
		dns_name_copy(&found->name, foundname);
	}
	bind_answer(&search, found, rdataset, sigrdataset);
done:
	rcu_read_unlock();
	update_cachestats(search.qpdb, result);
	return result;
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
qpcache_addcache(dns_db_t *db, const dns_name_t *name, isc_stdtime_t now,
		 dns_rdataset_t *rdataset, unsigned int options,
		 dns_rdataset_t *added) {
	qpcache_t *qpdb = (qpcache_t *)db;
	isc_region_t region;
	if (rdataset->type == dns_rdatatype_none ||
	    (dns_rdatatype_ismeta(rdataset->type) &&
	     !(rdataset->type == dns_rdatatype_any &&
	       rdataset->attributes.negative)))
	{
		return ISC_R_NOTIMPLEMENTED;
	}
	if (now == 0) {
		now = isc_stdtime_now();
	}
	isc_result_t result = dns_rdataslab_fromrdataset(
		rdataset, db->mctx, &region, qpdb->maxrrperset);
	if (result != ISC_R_SUCCESS) {
		if (result == DNS_R_TOOMANYRECORDS) {
			dns__db_logtoomanyrecords(db, name, rdataset->type,
						  "adding", qpdb->maxrrperset);
		}
		return result;
	}
	dns_slabheader_t *newheader = (dns_slabheader_t *)region.base;
	newheader->db = db;
	newheader->expire = now + rdataset->ttl;
	dns_name_dup(name, db->mctx, &newheader->name);
	cds_lfht_node_init(&newheader->item.ht_node);
	atomic_init(&newheader->visited, false);
	if (rdataset->ttl == 0) {
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
		result = addnoqname(db->mctx, newheader, qpdb->maxrrperset,
				    rdataset);
		if (result != ISC_R_SUCCESS) {
			dns_slabheader_detach(&newheader);
			return result;
		}
	}
	bool nsec = rdataset->type == dns_rdatatype_nsec;
	if (nsec) {
		RWLOCK(&qpdb->tree_lock, isc_rwlocktype_write);
	}
	rcu_read_lock();
	cache_key_t key = { name, newheader->typepair };
	uint32_t hash = key_hash(&key);
	dns_trust_t trust = (options & DNS_DBADD_FORCE) != 0
				    ? dns_trust_ultimate
				    : header_trust(newheader);
	for (;;) {
		dns_slabheader_t *oldheader = table_find(qpdb, name,
							 newheader->typepair);
		if (oldheader != NULL && ACTIVE(oldheader, now)) {
			dns_trust_t oldtrust = header_trust(oldheader);
			if (trust < oldtrust) {
				qpcache_hit(qpdb, oldheader);
				bindrdataset(qpdb, oldheader, now, added);
				result = DNS_R_UNCHANGED;
				if ((options & DNS_DBADD_EQUALOK) != 0 &&
				    dns_rdataslab_equalx(oldheader, newheader,
							 db->rdclass,
							 rdataset->type))
				{
					result = ISC_R_SUCCESS;
				}
				goto unpublished;
			}
			/* Preserve TTL/trust when a forced refresh carries the
			 * same lower-trust delegation or address/key data. */
			bool preserve =
				rdataset->type == dns_rdatatype_ns ||
				((options & DNS_DBADD_PREFETCH) == 0 &&
				 (rdataset->type == dns_rdatatype_a ||
				  rdataset->type == dns_rdatatype_aaaa ||
				  rdataset->type == dns_rdatatype_ds ||
				  newheader->typepair ==
					  DNS_SIGTYPEPAIR(dns_rdatatype_ds)));
			if (preserve && header_trust(newheader) < oldtrust &&
			    newheader->expire > oldheader->expire &&
			    dns_rdataslab_equalx(oldheader, newheader,
						 db->rdclass, rdataset->type))
			{
				newheader->expire = oldheader->expire;
				atomic_store_release(&newheader->trust,
						     oldtrust);
				if (newheader->noqname == NULL &&
				    oldheader->noqname != NULL)
				{
					dns_rdataset_t source =
						DNS_RDATASET_INIT;
					bindrdataset(qpdb, oldheader, now,
						     &source);
					result = addnoqname(db->mctx, newheader,
							    qpdb->maxrrperset,
							    &source);
					dns_rdataset_disassociate(&source);
					if (result != ISC_R_SUCCESS) {
						goto unpublished;
					}
				}
			}
			if (rdataset->type == dns_rdatatype_ns &&
			    header_trust(newheader) > oldtrust &&
			    newheader->expire > oldheader->expire)
			{
				newheader->expire = oldheader->expire;
				if (ZEROTTL(oldheader)) {
					DNS_SLABHEADER_SETATTR(
						newheader,
						DNS_SLABHEADERATTR_ZEROTTL);
				}
			}
		}
		newheader->serial = atomic_fetch_add_relaxed(&qpdb->serial, 1) +
				    1;
		/* Account before publication so concurrent removal can
		 * subtract. */
		DNS_SLABHEADER_SETATTR(newheader, DNS_SLABHEADERATTR_STATCOUNT);
		update_rrsetstats(qpdb->rrsetstats, newheader->typepair,
				  newheader->attributes, true);
		bool published;
		if (oldheader == NULL) {
			published = cds_lfht_add_unique(
					    qpdb->ht, hash, item_match, &key,
					    &newheader->item.ht_node) ==
				    &newheader->item.ht_node;
		} else {
			struct cds_lfht_iter iter;
			cds_lfht_lookup(qpdb->ht, hash, item_match, &key,
					&iter);
			published =
				cds_lfht_iter_get_node(&iter) ==
					&oldheader->item.ht_node &&
				cds_lfht_replace(qpdb->ht, &iter, hash,
						 item_match, &key,
						 &newheader->item.ht_node) == 0;
		}
		if (!published) {
			update_rrsetstats(qpdb->rrsetstats, newheader->typepair,
					  newheader->attributes, false);
			DNS_SLABHEADER_CLRATTR(newheader,
					       DNS_SLABHEADERATTR_STATCOUNT);
			continue;
		}
		if (nsec) {
			(void)dns_qp_deletename(qpdb->tree_nsec, name,
						DNS_DBNAMESPACE_NSEC, NULL,
						NULL);
			RUNTIME_CHECK(dns_qp_insert(qpdb->tree_nsec, newheader,
						    0) == ISC_R_SUCCESS);
		}
		if (oldheader != NULL) {
			retire_header(qpdb, oldheader);
		}
		bindrdataset(qpdb, newheader, now, added);
		break;
	}
	if (nsec) {
		RWUNLOCK(&qpdb->tree_lock, isc_rwlocktype_write);
	}
	/* Keep RCU across publication and eviction: another writer can already
	 * have replaced newheader, even if no dataset was returned. */
	if (isc_mem_isovermem(db->mctx)) {
		expire_clock_headers(qpdb, newheader,
				     dns_rdataslab_size(newheader) +
					     dns_name_size(name) +
					     QP_SAFETY_MARGIN);
	}
	rcu_read_unlock();
	return ISC_R_SUCCESS;
unpublished:
	rcu_read_unlock();
	if (nsec) {
		RWUNLOCK(&qpdb->tree_lock, isc_rwlocktype_write);
	}
	dns_slabheader_detach(&newheader);
	return result;
}

static isc_result_t
qpcache_deletecache(dns_db_t *db, const dns_name_t *name, dns_rdatatype_t type,
		    dns_rdatatype_t covers) {
	qpcache_t *qpdb = (qpcache_t *)db;
	rcu_read_lock();
	dns_slabheader_t *header = table_find(qpdb, name,
					      DNS_TYPEPAIR_VALUE(type, covers));
	size_t size = header != NULL ? header_delete(qpdb, header) : 0;
	rcu_read_unlock();
	return size != 0 ? ISC_R_SUCCESS : DNS_R_UNCHANGED;
}

static void
qpcache_expirecache(dns_db_t *db, dns_slabheader_t *header) {
	REQUIRE(header->db == db);
	rcu_read_lock();
	(void)header_delete((qpcache_t *)db, header);
	rcu_read_unlock();
}

static isc_result_t
qpcache_flushcache(dns_db_t *db, const dns_name_t *name, bool subtree) {
	qpcache_t *qpdb = (qpcache_t *)db;
	struct cds_lfht_iter iter;
	dns_cacheitem_t *item;
	rcu_read_lock();
	cds_lfht_for_each_entry(qpdb->ht, &iter, item, ht_node) {
		dns_slabheader_t *header = item_header(item);
		if (header != NULL &&
		    (subtree ? dns_name_issubdomain(&header->name, name)
			     : dns_name_equal(&header->name, name)))
		{
			(void)header_delete(qpdb, header);
		}
	}
	rcu_read_unlock();
	return ISC_R_SUCCESS;
}

static unsigned int
nodecount(dns_db_t *db) {
	qpcache_t *qpdb = (qpcache_t *)db;
	struct cds_lfht_iter iter;
	dns_cacheitem_t *item;
	unsigned int count = 0;
	rcu_read_lock();
	cds_lfht_for_each_entry(qpdb->ht, &iter, item, ht_node) {
		count += !item->marker;
	}
	rcu_read_unlock();
	return count;
}

static void
qpcache_destroy(dns_db_t *db) {
	qpcache_t *qpdb = (qpcache_t *)db;
	struct cds_lfht_iter iter;
	dns_cacheitem_t *item;
	rcu_read_lock();
	cds_lfht_for_each_entry(qpdb->ht, &iter, item, ht_node) {
		INSIST(!item->marker);
		(void)header_delete(qpdb, item_header(item));
	}
	rcu_read_unlock();
	RUNTIME_CHECK(cds_lfht_destroy(qpdb->ht, NULL) == 0);
	dns_qp_destroy(&qpdb->tree_nsec);
	dns_stats_detach(&qpdb->rrsetstats);
	if (qpdb->cachestats != NULL) {
		isc_stats_detach(&qpdb->cachestats);
	}
	isc_rwlock_destroy(&qpdb->tree_lock);
	dns_name_free(&db->origin, db->mctx);
	isc_refcount_destroy(&db->references);
	isc_mem_putanddetach(&db->mctx, qpdb, sizeof(*qpdb));
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
setmaxrrperset(dns_db_t *db, uint32_t value) {
	qpcache_t *qpdb = (qpcache_t *)db;

	REQUIRE(VALID_QPDB(qpdb));

	qpdb->maxrrperset = value;
}

static isc_result_t
qpcache_createiterator(dns_db_t *db ISC_ATTR_UNUSED,
		       unsigned int options ISC_ATTR_UNUSED,
		       dns_dbiterator_t **iteratorp ISC_ATTR_UNUSED) {
	return ISC_R_NOTIMPLEMENTED;
}

static dns_dbmethods_t qpdb_cachemethods = {
	.destroy = qpcache_destroy,
	.find = qpcache_find,
	.findcache = qpcache_findcache,
	.createiterator = qpcache_createiterator,
	.addcache = qpcache_addcache,
	.deletecache = qpcache_deletecache,
	.expirecache = qpcache_expirecache,
	.flushcache = qpcache_flushcache,
	.nodecount = nodecount,
	.getrrsetstats = getrrsetstats,
	.setcachestats = setcachestats,
	.setservestalettl = setservestalettl,
	.getservestalettl = getservestalettl,
	.setservestalerefresh = setservestalerefresh,
	.getservestalerefresh = getservestalerefresh,
	.setmaxrrperset = setmaxrrperset,
};

isc_result_t
dns__qpcache_create(isc_mem_t *mctx, const dns_name_t *origin,
		    dns_dbtype_t type, dns_rdataclass_t rdclass,
		    unsigned int argc, char *argv[],
		    void *driverarg ISC_ATTR_UNUSED, dns_db_t **dbp) {
	REQUIRE(type == dns_dbtype_cache);
	REQUIRE(argc == 0 && argv == NULL);
	qpcache_t *db = isc_mem_get(mctx, sizeof(*db));
	*db = (qpcache_t){
		.common.methods = &qpdb_cachemethods,
		.common.origin = DNS_NAME_INITEMPTY,
		.common.rdclass = rdclass,
		.common.attributes = DNS_DBATTR_CACHE,
		.common.references = 1,
		.common.magic = DNS_DB_MAGIC,
		.common.impmagic = QPDB_MAGIC,
	};
	isc_mem_attach(mctx, &db->common.mctx);
	dns_name_dup(origin, mctx, &db->common.origin);
	isc_rwlock_init(&db->tree_lock);
	dns_rdatasetstats_create(mctx, &db->rrsetstats);
	db->ht = cds_lfht_new(1 << 16, 1 << 10, 0,
			      CDS_LFHT_AUTO_RESIZE | CDS_LFHT_ACCOUNTING, NULL);
	INSIST(db->ht != NULL);
	dns_qp_create(mctx, &qpmethods, db, &db->tree_nsec);
	*dbp = &db->common;
	return ISC_R_SUCCESS;
}
