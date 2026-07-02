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
#include <dns/rdatatype.h>

#include <tests/dns.h>

/*
 * Node lifecycle stress test.
 *
 * The cache node lifecycle is a lock-free trie lookup plus per-bucket
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

ISC_TEST_LIST_START
ISC_TEST_ENTRY_CUSTOM(node_lifecycle_stress, setup_managers,
		      teardown_managers)
ISC_TEST_LIST_END

ISC_TEST_MAIN
