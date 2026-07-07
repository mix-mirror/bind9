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

#include <inttypes.h>
#include <sched.h> /* IWYU pragma: keep */
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define UNIT_TESTING
#include <cmocka.h>

#include <isc/async.h>
#include <isc/atomic.h>
#include <isc/lib.h>
#include <isc/loop.h>
#include <isc/mem.h>
#include <isc/result.h>
#include <isc/stdtime.h>
#include <isc/util.h>

#include <dns/db.h>
#include <dns/fixedname.h>
#include <dns/lib.h>
#include <dns/name.h>
#include <dns/rdata.h>
#include <dns/rdatalist.h>
#include <dns/rdataset.h>
#include <dns/rdatasetiter.h>
#include <dns/rdatatype.h>

#include <tests/dns.h>

/*
 * Node lifecycle stress test.
 *
 * The cache node lifecycle is a lock-free trie lookup plus per-node
 * reference counting: a node whose last external reference drops is
 * queued for deferred cleanup, can be reactivated from the trie in the
 * meantime, released again, displaced by a concurrent creator, and
 * finally removed. The races between those transitions only appear
 * under real concurrency, with many threads hammering a small set of
 * names so that reactivations, releases and cleanups collide on the
 * same nodes.
 *
 * Every loop runs a worker that repeatedly creates and releases nodes
 * from a deliberately tiny name set, occasionally adding and deleting
 * data so nodes oscillate between empty and non-empty. The work is done
 * in short batches, re-posted through the async queue, so the deferred
 * deadnode cleanups interleave with the churn instead of running only
 * after it. The test passes when the churn completes and the database
 * shuts down cleanly: reference-count underflows, corrupted cleanup
 * queues, or a stuck deferred teardown all abort or hang it.
 */

#define STRESS_NAMES   13
#define STRESS_BATCHES 250
#define STRESS_OPS     200

typedef struct stress_worker {
	isc_loop_t *loop;
	unsigned int batches;
	unsigned int seq;
} stress_worker_t;

static dns_db_t *stress_db;
static dns_fixedname_t stress_fnames[STRESS_NAMES];
static dns_name_t *stress_names[STRESS_NAMES];
static stress_worker_t *stress_workers;
static atomic_uint_fast32_t stress_left;

static void
stress_add(dns_dbnode_t *node, isc_stdtime_t now) {
	isc_result_t result;
	dns_rdata_t rdata = DNS_RDATA_INIT;
	dns_rdatalist_t rdatalist;
	dns_rdataset_t rdataset;
	unsigned char rdatabuf[16];

	result = dns_test_rdatafromstring(&rdata, dns_rdataclass_in,
					  dns_rdatatype_a, rdatabuf,
					  sizeof(rdatabuf), "10.53.0.1",
					  false);
	INSIST(result == ISC_R_SUCCESS);

	dns_rdatalist_init(&rdatalist);
	rdatalist.rdclass = dns_rdataclass_in;
	rdatalist.type = dns_rdatatype_a;
	rdatalist.ttl = 1;
	ISC_LIST_APPEND(rdatalist.rdata, &rdata, link);

	dns_rdataset_init(&rdataset);
	dns_rdatalist_tordataset(&rdatalist, &rdataset);

	result = dns_db_addrdataset(stress_db, node, NULL, now, &rdataset, 0,
				    NULL);
	INSIST(result == ISC_R_SUCCESS || result == DNS_R_UNCHANGED);
}

static void
stress_batch(void *arg) {
	stress_worker_t *w = arg;
	isc_stdtime_t now = isc_stdtime_now();

	for (unsigned int i = 0; i < STRESS_OPS; i++) {
		unsigned int seq = w->seq++;
		dns_name_t *name = stress_names[seq % STRESS_NAMES];
		dns_dbnode_t *node = NULL;
		isc_result_t result;

		result = dns_db_findnode(stress_db, name, true, &node);
		INSIST(result == ISC_R_SUCCESS);

		if (seq % 7 == 0) {
			stress_add(node, now);
		}
		if (seq % 11 == 0) {
			(void)dns_db_deleterdataset(stress_db, node, NULL,
						    dns_rdatatype_a, 0);
		}

		dns_db_detachnode(&node);
	}

	if (--w->batches > 0) {
		/*
		 * Yield the loop between batches so the deferred deadnode
		 * cleanup jobs run interleaved with the churn.
		 */
		isc_async_run(w->loop, stress_batch, w);
		return;
	}

	if (atomic_fetch_sub(&stress_left, 1) == 1) {
		/* Last worker: tear everything down under churn debris. */
		isc_mem_cput(isc_g_mctx, stress_workers, workers,
			     sizeof(stress_workers[0]));
		dns_db_detach(&stress_db);
		isc_loopmgr_shutdown();
	}
}

ISC_LOOP_TEST_IMPL(node_lifecycle_stress) {
	isc_result_t result;

	result = dns_db_create(isc_g_mctx, "ftcache", dns_rootname,
			       dns_dbtype_cache, dns_rdataclass_in, 0, NULL,
			       &stress_db);
	assert_int_equal(result, ISC_R_SUCCESS);

	for (size_t i = 0; i < STRESS_NAMES; i++) {
		char namebuf[64];
		snprintf(namebuf, sizeof(namebuf), "name%zu.ftcache-stress.",
			 i);
		dns_test_namefromstring(namebuf, &stress_fnames[i]);
		stress_names[i] = dns_fixedname_name(&stress_fnames[i]);
	}

	stress_workers = isc_mem_cget(isc_g_mctx, workers,
				      sizeof(stress_workers[0]));
	atomic_init(&stress_left, workers);

	for (unsigned int i = 0; i < workers; i++) {
		stress_workers[i] = (stress_worker_t){
			.loop = isc_loop_get(i),
			.batches = STRESS_BATCHES,
			.seq = i, /* stagger the name sequences */
		};
		isc_async_run(stress_workers[i].loop, stress_batch,
			      &stress_workers[i]);
	}
}

/*
 * Read-path stress test.
 *
 * The read path is lock-free: finds walk a node's header list under
 * the RCU read-side lock only, binding headers with a
 * try-reference that can fail when a writer concurrently deletes the
 * header, in which case the reader retries its walk. Writers add and
 * delete A + RRSIG(A) pairs (exercising the related cross-links and
 * their repointing on supersede), NSEC records (exercising the
 * covering-NSEC search and the auxiliary NSEC nodes), and readers
 * hammer dns_db_find/findrdataset/allrdatasets on the same tiny name
 * set, iterating every bound rdataset so any use-after-free is
 * touched. A bound signature must always be an RRSIG covering the
 * bound answer's type -- the pair binds all-or-nothing.
 */

#define READ_BATCHES 150
#define READ_OPS     200

static void
read_add(dns_dbnode_t *node, dns_name_t *name, isc_stdtime_t now,
	 dns_rdatatype_t type, dns_rdatatype_t covers, dns_ttl_t ttl,
	 const char *text) {
	isc_result_t result;
	dns_rdata_t rdata = DNS_RDATA_INIT;
	dns_rdatalist_t rdatalist;
	dns_rdataset_t rdataset;
	unsigned char rdatabuf[512];

	UNUSED(name);

	result = dns_test_rdatafromstring(&rdata, dns_rdataclass_in, type,
					  rdatabuf, sizeof(rdatabuf), text,
					  false);
	INSIST(result == ISC_R_SUCCESS);

	dns_rdatalist_init(&rdatalist);
	rdatalist.rdclass = dns_rdataclass_in;
	rdatalist.type = type;
	rdatalist.covers = covers;
	rdatalist.ttl = ttl;
	ISC_LIST_APPEND(rdatalist.rdata, &rdata, link);

	dns_rdataset_init(&rdataset);
	dns_rdatalist_tordataset(&rdatalist, &rdataset);
	rdataset.trust = dns_trust_authanswer;

	result = dns_db_addrdataset(stress_db, node, NULL, now, &rdataset, 0,
				    NULL);
	INSIST(result == ISC_R_SUCCESS || result == DNS_R_UNCHANGED);
}

static void
read_find(dns_name_t *name, unsigned int options, isc_stdtime_t now) {
	dns_fixedname_t ffound;
	dns_name_t *foundname = dns_fixedname_initname(&ffound);
	dns_rdataset_t rdataset, sigrdataset;
	dns_dbnode_t *node = NULL;
	isc_result_t result;

	dns_rdataset_init(&rdataset);
	dns_rdataset_init(&sigrdataset);

	result = dns_db_find(stress_db, name, NULL, dns_rdatatype_a, options,
			     now, &node, foundname, &rdataset, &sigrdataset);

	if (dns_rdataset_isassociated(&rdataset)) {
		/* Touch the slab data of everything we bound. */
		for (result = dns_rdataset_first(&rdataset);
		     result == ISC_R_SUCCESS;
		     result = dns_rdataset_next(&rdataset))
		{
			dns_rdata_t rdata = DNS_RDATA_INIT;
			dns_rdataset_current(&rdataset, &rdata);
			INSIST(rdata.length > 0);
		}

		if (dns_rdataset_isassociated(&sigrdataset)) {
			/*
			 * The pair binds all-or-nothing: a bound
			 * signature always matches the bound answer.
			 */
			INSIST(sigrdataset.type == dns_rdatatype_rrsig);
			INSIST(sigrdataset.covers == rdataset.type);
		}

		dns_rdataset_disassociate(&rdataset);
	}
	if (dns_rdataset_isassociated(&sigrdataset)) {
		dns_rdataset_disassociate(&sigrdataset);
	}
	if (node != NULL) {
		dns_db_detachnode(&node);
	}
}

static void
read_allrdatasets(dns_name_t *name, isc_stdtime_t now) {
	dns_dbnode_t *node = NULL;
	dns_rdatasetiter_t *it = NULL;
	isc_result_t result;

	result = dns_db_findnode(stress_db, name, false, &node);
	if (result != ISC_R_SUCCESS) {
		return;
	}

	result = dns_db_allrdatasets(stress_db, node, NULL, 0, now, &it);
	INSIST(result == ISC_R_SUCCESS);

	for (result = dns_rdatasetiter_first(it); result == ISC_R_SUCCESS;
	     result = dns_rdatasetiter_next(it))
	{
		dns_rdataset_t rdataset;
		dns_rdataset_init(&rdataset);
		dns_rdatasetiter_current(it, &rdataset);
		dns_rdataset_disassociate(&rdataset);
	}

	dns_rdatasetiter_destroy(&it);
	dns_db_detachnode(&node);
}

static void
read_batch(void *arg) {
	stress_worker_t *w = arg;
	isc_stdtime_t now = isc_stdtime_now();

	for (unsigned int i = 0; i < READ_OPS; i++) {
		unsigned int seq = w->seq++;
		dns_name_t *name = stress_names[seq % STRESS_NAMES];

		switch (seq % 5) {
		case 0: {
			/* Writer: add an A + RRSIG(A) pair. */
			dns_dbnode_t *node = NULL;
			isc_result_t result = dns_db_findnode(stress_db, name,
							      true, &node);
			INSIST(result == ISC_R_SUCCESS);
			read_add(node, name, now, dns_rdatatype_a,
				 dns_rdatatype_none, (seq % 3 == 0) ? 1 : 300,
				 "10.53.0.2");
			read_add(node, name, now, dns_rdatatype_rrsig,
				 dns_rdatatype_a, (seq % 3 == 0) ? 1 : 300,
				 "A 5 3 300 20370101000000 20200101000000 "
				 "12345 ftcache-stress. aGVsbG8gd29ybGQgaGVs"
				 "bG8gd29ybGQgaGVsbG8gd29ybGQ=");
			if (seq % 13 == 0) {
				read_add(node, name, now, dns_rdatatype_nsec,
					 dns_rdatatype_none, 300,
					 "zzz.ftcache-stress. A RRSIG NSEC");
			}
			dns_db_detachnode(&node);
			break;
		}
		case 1: {
			/* Writer: delete the pair (in both orders). */
			dns_dbnode_t *node = NULL;
			isc_result_t result = dns_db_findnode(stress_db, name,
							      true, &node);
			INSIST(result == ISC_R_SUCCESS);
			if (seq % 2 == 0) {
				(void)dns_db_deleterdataset(stress_db, node,
							    NULL,
							    dns_rdatatype_a, 0);
			} else {
				(void)dns_db_deleterdataset(
					stress_db, node, NULL,
					dns_rdatatype_rrsig, dns_rdatatype_a);
			}
			dns_db_detachnode(&node);
			break;
		}
		case 2:
			read_find(name, 0, now);
			break;
		case 3:
			read_find(name,
				  (seq % 17 == 0) ? DNS_DBFIND_STALEOK
						  : DNS_DBFIND_COVERINGNSEC,
				  now);
			break;
		case 4:
			if (seq % 13 == 0) {
				read_allrdatasets(name, now);
			} else {
				read_find(name, 0, now);
			}
			break;
		}
	}

	if (--w->batches > 0) {
		isc_async_run(w->loop, read_batch, w);
		return;
	}

	if (atomic_fetch_sub(&stress_left, 1) == 1) {
		isc_mem_cput(isc_g_mctx, stress_workers, workers,
			     sizeof(stress_workers[0]));
		dns_db_detach(&stress_db);
		isc_loopmgr_shutdown();
	}
}

ISC_LOOP_TEST_IMPL(read_path_stress) {
	isc_result_t result;

	result = dns_db_create(isc_g_mctx, "ftcache", dns_rootname,
			       dns_dbtype_cache, dns_rdataclass_in, 0, NULL,
			       &stress_db);
	assert_int_equal(result, ISC_R_SUCCESS);

	for (size_t i = 0; i < STRESS_NAMES; i++) {
		char namebuf[64];
		snprintf(namebuf, sizeof(namebuf), "name%zu.ftcache-stress.",
			 i);
		dns_test_namefromstring(namebuf, &stress_fnames[i]);
		stress_names[i] = dns_fixedname_name(&stress_fnames[i]);
	}

	stress_workers = isc_mem_cget(isc_g_mctx, workers,
				      sizeof(stress_workers[0]));
	atomic_init(&stress_left, workers);

	for (unsigned int i = 0; i < workers; i++) {
		stress_workers[i] = (stress_worker_t){
			.loop = isc_loop_get(i),
			.batches = READ_BATCHES,
			.seq = i, /* stagger the name sequences */
		};
		isc_async_run(stress_workers[i].loop, read_batch,
			      &stress_workers[i]);
	}
}

/*
 * Overmem eviction stress test.
 *
 * The database lives on a memory context with a low water mark, so
 * every addition purges room up front via the per-loop SIEVE-LRU
 * eviction, which takes the victims' node spinlocks while readers on
 * other loops are binding the same headers lock-free. Writers keep
 * inserting unique names (so eviction always has victims) while every
 * worker also reads a small set of hot names.
 */

#define EVICT_BATCHES  50
#define EVICT_OPS      100
#define EVICT_MAXCACHE 2097152U /* 2MB - same as DNS_CACHE_MINSIZE */

static isc_mem_t *evict_mctx;

static void
evict_batch(void *arg) {
	stress_worker_t *w = arg;
	isc_stdtime_t now = isc_stdtime_now();

	for (unsigned int i = 0; i < EVICT_OPS; i++) {
		unsigned int seq = w->seq++;
		dns_name_t *hot = stress_names[seq % STRESS_NAMES];
		dns_fixedname_t funique;
		char namebuf[64];
		dns_dbnode_t *node = NULL;
		isc_result_t result;

		/* Insert a unique name so eviction always has victims. */
		snprintf(namebuf, sizeof(namebuf),
			 "n%u-%u.evict.ftcache-stress.", seq,
			 (unsigned int)(w - stress_workers));
		dns_test_namefromstring(namebuf, &funique);

		result = dns_db_findnode(
			stress_db, dns_fixedname_name(&funique), true, &node);
		INSIST(result == ISC_R_SUCCESS);
		read_add(node, dns_fixedname_name(&funique), now,
			 dns_rdatatype_txt, dns_rdatatype_none, 300,
			 "\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			 "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			 "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			 "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			 "aaaaaaaaaaaaaaaaaaaaaa\"");
		dns_db_detachnode(&node);

		/* And keep the hot names both written and read. */
		if (seq % 5 == 0) {
			node = NULL;
			result = dns_db_findnode(stress_db, hot, true, &node);
			INSIST(result == ISC_R_SUCCESS);
			read_add(node, hot, now, dns_rdatatype_a,
				 dns_rdatatype_none, 300, "10.53.0.3");
			dns_db_detachnode(&node);
		} else {
			read_find(hot, 0, now);
		}
	}

	if (--w->batches > 0) {
		isc_async_run(w->loop, evict_batch, w);
		return;
	}

	if (atomic_fetch_sub(&stress_left, 1) == 1) {
		isc_mem_cput(isc_g_mctx, stress_workers, workers,
			     sizeof(stress_workers[0]));
		dns_db_detach(&stress_db);
		isc_mem_detach(&evict_mctx);
		isc_loopmgr_shutdown();
	}
}

ISC_LOOP_TEST_IMPL(overmem_eviction_stress) {
	size_t hiwater = EVICT_MAXCACHE - (EVICT_MAXCACHE >> 3);
	size_t lowater = EVICT_MAXCACHE - (EVICT_MAXCACHE >> 2);
	isc_result_t result;

	isc_mem_create("evict", &evict_mctx);
	isc_mem_setwater(evict_mctx, hiwater, lowater);

	result = dns_db_create(evict_mctx, "ftcache", dns_rootname,
			       dns_dbtype_cache, dns_rdataclass_in, 0, NULL,
			       &stress_db);
	assert_int_equal(result, ISC_R_SUCCESS);

	for (size_t i = 0; i < STRESS_NAMES; i++) {
		char namebuf[64];
		snprintf(namebuf, sizeof(namebuf), "hot%zu.ftcache-stress.", i);
		dns_test_namefromstring(namebuf, &stress_fnames[i]);
		stress_names[i] = dns_fixedname_name(&stress_fnames[i]);
	}

	stress_workers = isc_mem_cget(isc_g_mctx, workers,
				      sizeof(stress_workers[0]));
	atomic_init(&stress_left, workers);

	for (unsigned int i = 0; i < workers; i++) {
		stress_workers[i] = (stress_worker_t){
			.loop = isc_loop_get(i),
			.batches = EVICT_BATCHES,
			.seq = i,
		};
		isc_async_run(stress_workers[i].loop, evict_batch,
			      &stress_workers[i]);
	}
}

ISC_TEST_LIST_START
ISC_TEST_ENTRY_CUSTOM(node_lifecycle_stress, setup_managers,
		      teardown_managers)
ISC_TEST_ENTRY_CUSTOM(read_path_stress, setup_managers, teardown_managers)
ISC_TEST_ENTRY_CUSTOM(overmem_eviction_stress, setup_managers,
		      teardown_managers)
ISC_TEST_LIST_END

ISC_TEST_MAIN
