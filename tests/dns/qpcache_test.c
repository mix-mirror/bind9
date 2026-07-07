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
#include <stdio.h>
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
#include <dns/rdatatype.h>

#include <tests/dns.h>

/*
 * Concurrency stress tests for the cache database.
 *
 * The interesting cache races -- node reactivation against release,
 * deferred deadnode cleanup against re-enqueueing, rdataset
 * supersession against concurrent readers, overmem eviction against
 * everything -- only appear under real concurrency, with many threads
 * hammering a small set of names so that the transitions collide on
 * the same nodes and headers.
 *
 * Every loop runs a worker that repeatedly executes a mix of database
 * operations over a deliberately tiny name set. The work is done in
 * short batches, re-posted through the async queue, so deferred
 * cleanup jobs interleave with the churn instead of running only
 * after it. The tests pass when the churn completes and the database
 * shuts down cleanly: reference-count underflows, corrupted cleanup
 * queues, use-after-free of superseded headers, or a stuck deferred
 * teardown all abort or hang them (or trip the sanitizers).
 */

#define STRESS_NAMES 13

#define LIFECYCLE_BATCHES 250
#define LIFECYCLE_OPS	  200

#define HAMMER_BATCHES 150
#define HAMMER_OPS     150
/* Names below this index sit outside the DNAME subtree. */
#define HAMMER_DIRECT 8

#define OVERMEM_BATCHES 100
#define OVERMEM_OPS	100
/* An arbitrary private type: the filler data can be anything. */
#define FILLER_TYPE 50053

typedef struct stress_worker stress_worker_t;
struct stress_worker {
	isc_loop_t *loop;
	unsigned int batches;
	unsigned int ops;
	unsigned int seq;
	unsigned int id;
	void (*op)(stress_worker_t *w, isc_stdtime_t now);
};

static dns_db_t *stress_db;
static isc_mem_t *stress_mctx; /* only used by the overmem variant */
static dns_fixedname_t stress_fnames[STRESS_NAMES];
static dns_name_t *stress_names[STRESS_NAMES];
static dns_fixedname_t stress_fdname;
static dns_name_t *stress_dname;
static stress_worker_t *stress_workers;
static atomic_uint_fast32_t stress_left;

static void
add_rdata(dns_dbnode_t *node, dns_rdatatype_t type, const char *rdatastr,
	  dns_ttl_t ttl, isc_stdtime_t now) {
	isc_result_t result;
	dns_rdata_t rdata = DNS_RDATA_INIT;
	dns_rdatalist_t rdatalist;
	dns_rdataset_t rdataset;
	unsigned char rdatabuf[64];

	result = dns_test_rdatafromstring(&rdata, dns_rdataclass_in, type,
					  rdatabuf, sizeof(rdatabuf), rdatastr,
					  false);
	INSIST(result == ISC_R_SUCCESS);

	dns_rdatalist_init(&rdatalist);
	rdatalist.rdclass = dns_rdataclass_in;
	rdatalist.type = type;
	rdatalist.ttl = ttl;
	ISC_LIST_APPEND(rdatalist.rdata, &rdata, link);

	dns_rdataset_init(&rdataset);
	dns_rdatalist_tordataset(&rdatalist, &rdataset);

	result = dns_db_addrdataset(stress_db, node, NULL, now, &rdataset, 0,
				    NULL);
	INSIST(result == ISC_R_SUCCESS || result == DNS_R_UNCHANGED);
}

static void
add_at_name(const dns_name_t *name, dns_rdatatype_t type, const char *rdatastr,
	    dns_ttl_t ttl, isc_stdtime_t now) {
	isc_result_t result;
	dns_dbnode_t *node = NULL;

	result = dns_db_findnode(stress_db, name, true, &node);
	INSIST(result == ISC_R_SUCCESS);
	add_rdata(node, type, rdatastr, ttl, now);
	dns_db_detachnode(&node);
}

/*
 * Read every rdata in the bound rdataset so that the slab memory
 * behind it is actually touched; a header freed under a concurrent
 * reader turns into a sanitizer report here.
 */
static void
read_rdataset(dns_rdataset_t *rdataset) {
	for (isc_result_t result = dns_rdataset_first(rdataset);
	     result == ISC_R_SUCCESS; result = dns_rdataset_next(rdataset))
	{
		dns_rdata_t rdata = DNS_RDATA_INIT;
		dns_rdataset_current(rdataset, &rdata);
		INSIST(rdata.length > 0);
	}
}

/*
 * Node lifecycle churn: create and release nodes so they oscillate
 * between empty and non-empty and bounce through the deadnodes queue.
 */
static void
lifecycle_op(stress_worker_t *w, isc_stdtime_t now) {
	unsigned int seq = w->seq++;
	dns_name_t *name = stress_names[seq % STRESS_NAMES];
	dns_dbnode_t *node = NULL;
	isc_result_t result;

	result = dns_db_findnode(stress_db, name, true, &node);
	INSIST(result == ISC_R_SUCCESS);

	if (seq % 7 == 0) {
		add_rdata(node, dns_rdatatype_a, "10.53.0.1", 1, now);
	}
	if (seq % 11 == 0) {
		(void)dns_db_deleterdataset(stress_db, node, NULL,
					    dns_rdatatype_a, 0);
	}

	dns_db_detachnode(&node);
}

/*
 * Rdataset churn: full find calls racing against rdataset addition
 * (with varying rdata, so existing headers keep getting superseded),
 * deletion and explicit expiry. Part of the name set lives under a
 * DNAME whose target flips between two values, so finds cross a
 * zonecut that is concurrently superseded and deleted.
 */
static void
hammer_one(unsigned int seq, isc_stdtime_t now) {
	dns_name_t *name = stress_names[seq % STRESS_NAMES];
	isc_result_t result;

	{
		dns_dbnode_t *node = NULL;
		dns_fixedname_t ffound;
		dns_name_t *foundname = dns_fixedname_initname(&ffound);
		dns_rdataset_t rdataset;
		unsigned int options = 0;

		if (seq % 5 == 0) {
			options = DNS_DBFIND_STALEOK | DNS_DBFIND_STALEENABLED;
		}

		dns_rdataset_init(&rdataset);
		(void)dns_db_find(stress_db, name, NULL, dns_rdatatype_a,
				  options, now, &node, foundname, &rdataset,
				  NULL);
		if (dns_rdataset_isassociated(&rdataset)) {
			INSIST(rdataset.type == dns_rdatatype_a ||
			       rdataset.type == dns_rdatatype_dname);
			read_rdataset(&rdataset);
			dns_rdataset_disassociate(&rdataset);
		}
		if (node != NULL) {
			dns_db_detachnode(&node);
		}
	}

	if (seq % 3 == 0) {
		char rdatastr[32];
		snprintf(rdatastr, sizeof(rdatastr), "10.53.%u.%u",
			 (seq >> 8) & 0xff, seq & 0xff);
		add_at_name(name, dns_rdatatype_a, rdatastr, 2, now);
	}
	if (seq % 7 == 0) {
		add_at_name(stress_dname, dns_rdatatype_dname,
			    ((seq / 7) % 2 == 0) ? "target-a." : "target-b.",
			    5, now);
	}
	if (seq % 11 == 0) {
		dns_dbnode_t *node = NULL;

		result = dns_db_findnode(stress_db, name, false, &node);
		if (result == ISC_R_SUCCESS) {
			(void)dns_db_deleterdataset(stress_db, node, NULL,
						    dns_rdatatype_a, 0);
			dns_db_detachnode(&node);
		}
	}
	if (seq % 13 == 0) {
		dns_dbnode_t *node = NULL;

		result = dns_db_findnode(stress_db, name, false, &node);
		if (result == ISC_R_SUCCESS) {
			dns_rdataset_t rdataset;

			dns_rdataset_init(&rdataset);
			result = dns_db_findrdataset(stress_db, node, NULL,
						     dns_rdatatype_a, 0, now,
						     &rdataset, NULL);
			if (result == ISC_R_SUCCESS) {
				dns_rdataset_expire(&rdataset);
				dns_rdataset_disassociate(&rdataset);
			}
			dns_db_detachnode(&node);
		}
	}
	if (seq % 17 == 0) {
		dns_dbnode_t *node = NULL;

		result = dns_db_findnode(stress_db, stress_dname, false,
					 &node);
		if (result == ISC_R_SUCCESS) {
			(void)dns_db_deleterdataset(stress_db, node, NULL,
						    dns_rdatatype_dname, 0);
			dns_db_detachnode(&node);
		}
	}
}

static void
hammer_op(stress_worker_t *w, isc_stdtime_t now) {
	unsigned int seq = w->seq++;

	hammer_one(seq, now);
}

/*
 * Add a large rdataset at a unique name to drive the memory context
 * over its high-water mark, so that overmem eviction runs against the
 * concurrent churn on the hot names.
 */
static void
overmem_fill(stress_worker_t *w, unsigned int seq, isc_stdtime_t now) {
	isc_result_t result;
	dns_fixedname_t fname;
	dns_name_t *name;
	dns_dbnode_t *node = NULL;
	dns_rdata_t rdata = DNS_RDATA_INIT;
	dns_rdatalist_t rdatalist;
	dns_rdataset_t rdataset;
	unsigned char rdatabuf[512] = { 0 };
	char namebuf[64];

	snprintf(namebuf, sizeof(namebuf), "f%u-%u.filler.qpcache-stress.",
		 w->id, seq);
	dns_test_namefromstring(namebuf, &fname);
	name = dns_fixedname_name(&fname);

	dns_rdata_init(&rdata);
	rdata.data = rdatabuf;
	rdata.length = sizeof(rdatabuf);
	rdata.rdclass = dns_rdataclass_in;
	rdata.type = FILLER_TYPE;

	dns_rdatalist_init(&rdatalist);
	rdatalist.rdclass = dns_rdataclass_in;
	rdatalist.type = FILLER_TYPE;
	rdatalist.ttl = 3600;
	ISC_LIST_APPEND(rdatalist.rdata, &rdata, link);

	dns_rdataset_init(&rdataset);
	dns_rdatalist_tordataset(&rdatalist, &rdataset);

	result = dns_db_findnode(stress_db, name, true, &node);
	INSIST(result == ISC_R_SUCCESS);
	result = dns_db_addrdataset(stress_db, node, NULL, now, &rdataset, 0,
				    NULL);
	INSIST(result == ISC_R_SUCCESS || result == DNS_R_UNCHANGED);
	dns_db_detachnode(&node);
}

static void
overmem_op(stress_worker_t *w, isc_stdtime_t now) {
	unsigned int seq = w->seq++;

	hammer_one(seq, now);
	if (seq % 2 == 0) {
		overmem_fill(w, seq, now);
	}
}

static void
stress_batch(void *arg) {
	stress_worker_t *w = arg;
	isc_stdtime_t now = isc_stdtime_now();

	for (unsigned int i = 0; i < w->ops; i++) {
		w->op(w, now);
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
		if (stress_mctx != NULL) {
			isc_mem_detach(&stress_mctx);
		}
		isc_loopmgr_shutdown();
	}
}

static void
stress_names_init(const char *suffix) {
	for (size_t i = 0; i < STRESS_NAMES; i++) {
		char namebuf[64];

		if (i < HAMMER_DIRECT) {
			snprintf(namebuf, sizeof(namebuf), "name%zu.%s", i,
				 suffix);
		} else {
			snprintf(namebuf, sizeof(namebuf),
				 "name%zu.sub.dname.%s", i, suffix);
		}
		dns_test_namefromstring(namebuf, &stress_fnames[i]);
		stress_names[i] = dns_fixedname_name(&stress_fnames[i]);
	}

	char dnamebuf[64];
	snprintf(dnamebuf, sizeof(dnamebuf), "dname.%s", suffix);
	dns_test_namefromstring(dnamebuf, &stress_fdname);
	stress_dname = dns_fixedname_name(&stress_fdname);
}

static void
stress_start(void (*op)(stress_worker_t *w, isc_stdtime_t now),
	     unsigned int batches, unsigned int ops) {
	stress_workers = isc_mem_cget(isc_g_mctx, workers,
				      sizeof(stress_workers[0]));
	atomic_init(&stress_left, workers);

	for (unsigned int i = 0; i < workers; i++) {
		stress_workers[i] = (stress_worker_t){
			.loop = isc_loop_get(i),
			.batches = batches,
			.ops = ops,
			.op = op,
			.seq = i, /* stagger the name sequences */
			.id = i,
		};
		isc_async_run(stress_workers[i].loop, stress_batch,
			      &stress_workers[i]);
	}
}

ISC_LOOP_TEST_IMPL(node_lifecycle_stress) {
	isc_result_t result;

	result = dns_db_create(isc_g_mctx, CACHEDB_DEFAULT, dns_rootname,
			       dns_dbtype_cache, dns_rdataclass_in, 0, NULL,
			       &stress_db);
	assert_int_equal(result, ISC_R_SUCCESS);

	stress_names_init("qpcache-stress.");
	stress_start(lifecycle_op, LIFECYCLE_BATCHES, LIFECYCLE_OPS);
}

ISC_LOOP_TEST_IMPL(rdataset_churn_stress) {
	isc_result_t result;

	result = dns_db_create(isc_g_mctx, CACHEDB_DEFAULT, dns_rootname,
			       dns_dbtype_cache, dns_rdataclass_in, 0, NULL,
			       &stress_db);
	assert_int_equal(result, ISC_R_SUCCESS);

	/*
	 * Keep expired entries around so finds also race against
	 * stale-marking of the headers instead of plain misses.
	 */
	dns_db_setservestalettl(stress_db, 3600);

	stress_names_init("qpcache-hammer.");
	stress_start(hammer_op, HAMMER_BATCHES, HAMMER_OPS);
}

ISC_LOOP_TEST_IMPL(overmem_churn_stress) {
	size_t hiwater = 1048576;	     /* 1MB */
	size_t lowater = hiwater - (hiwater >> 2);
	isc_result_t result;

	isc_mem_create("overmem-stress", &stress_mctx);

	result = dns_db_create(stress_mctx, CACHEDB_DEFAULT, dns_rootname,
			       dns_dbtype_cache, dns_rdataclass_in, 0, NULL,
			       &stress_db);
	assert_int_equal(result, ISC_R_SUCCESS);

	isc_mem_setwater(stress_mctx, hiwater, lowater);

	stress_names_init("qpcache-overmem.");
	stress_start(overmem_op, OVERMEM_BATCHES, OVERMEM_OPS);
}

ISC_TEST_LIST_START
ISC_TEST_ENTRY_CUSTOM(node_lifecycle_stress, setup_managers,
		      teardown_managers)
ISC_TEST_ENTRY_CUSTOM(rdataset_churn_stress, setup_managers,
		      teardown_managers)
ISC_TEST_ENTRY_CUSTOM(overmem_churn_stress, setup_managers,
		      teardown_managers)
ISC_TEST_LIST_END

ISC_TEST_MAIN
