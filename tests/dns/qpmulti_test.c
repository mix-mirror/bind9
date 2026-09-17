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

#include <assert.h>
#include <inttypes.h>
#include <sched.h> /* IWYU pragma: keep */
#include <setjmp.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdlib.h>

#define UNIT_TESTING
#include <cmocka.h>

#include <isc/assertions.h>
#include <isc/async.h>
#include <isc/atomic.h>
#include <isc/lib.h>
#include <isc/log.h>
#include <isc/loop.h>
#include <isc/magic.h>
#include <isc/mem.h>
#include <isc/random.h>
#include <isc/refcount.h>
#include <isc/rwlock.h>
#include <isc/urcu.h>
#include <isc/util.h>

#include <dns/lib.h>
#include <dns/qp.h>
#include <dns/types.h>

#include "qp_p.h"

#include <tests/isc.h>
#include <tests/qp.h>

#define VERBOSE		  0
#define ITEM_COUNT	  12345
#define TRANSACTION_SIZE  123
#define TRANSACTION_COUNT 1234

#if VERBOSE
#define TRACE(fmt, ...)                                               \
	isc_log_write(DNS_LOGCATEGORY_DATABASE, DNS_LOGMODULE_QP,     \
		      ISC_LOG_DEBUG(7), "%s:%d:%s(): " fmt, __FILE__, \
		      __LINE__, __func__, ##__VA_ARGS__)
#else
#define TRACE(...)
#endif

#if VERBOSE
#define ASSERT(p)                       \
	if (!(p)) {                     \
		TRACE("%s failed", #p); \
		ok = false;             \
	} else
#else
#define ASSERT(p) assert_true(p)
#endif

static void
setup_logging(void) {
#if VERBOSE
	isc_log_setdebuglevel(7);
#endif
	isc_logconfig_t *logconfig = isc_logconfig_get();
	isc_log_createandusechannel(
		logconfig, "default_stderr", ISC_LOG_TOFILEDESC,
		ISC_LOG_DYNAMIC, ISC_LOGDESTINATION_STDERR,
		ISC_LOG_PRINTPREFIX | ISC_LOG_PRINTTIME | ISC_LOG_ISO8601,
		ISC_LOGCATEGORY_DEFAULT, ISC_LOGMODULE_DEFAULT);
}

/*
 * Reference counts are changed by the RCU reclamation thread as well as
 * by the test's own transactions, so they must be atomic.
 */
static struct {
	atomic_uint_fast32_t refcount;
	bool in_ro;
	bool in_rw;
	uint8_t len;
	dns_qpkey_t key;
	dns_qpkey_t ascii;
} item[ITEM_COUNT];

static void
item_attach(void *ctx, void *pval, uint32_t ival) {
	INSIST(ctx == NULL);
	INSIST(pval == &item[ival]);
	atomic_fetch_add_relaxed(&item[ival].refcount, 1);
}

static void
item_detach(void *ctx, void *pval, uint32_t ival) {
	assert_null(ctx);
	assert_ptr_equal(pval, &item[ival]);
	assert_int_not_equal(atomic_fetch_sub_relaxed(&item[ival].refcount, 1),
			     0);
}

static size_t
item_makekey(dns_qpkey_t key, void *ctx, void *pval, uint32_t ival) {
	INSIST(ctx == NULL);
	uintptr_t ip = (uintptr_t)pval;
	uintptr_t lo = (uintptr_t)item;
	uintptr_t hi = sizeof(item) + lo;
	if (!(ival < ARRAY_SIZE(item) && lo <= ip && ip < hi &&
	      pval == &item[ival]))
	{
		ISC_INSIST(ival < ARRAY_SIZE(item));
		ISC_INSIST(pval != NULL);
		ISC_INSIST(ip >= lo);
		ISC_INSIST(ip < hi);
		ISC_INSIST(pval == &item[ival]);
	}
	memmove(key, item[ival].key, item[ival].len);
	return item[ival].len;
}

static void
testname(void *ctx, char *buf, size_t size) {
	REQUIRE(ctx == NULL);
	strlcpy(buf, "test", size);
}

const dns_qpmethods_t test_methods = {
	item_attach,
	item_detach,
	item_makekey,
	testname,
};

static uint8_t
random_byte(void) {
	return isc_random_uniform(SHIFT_OFFSET - SHIFT_NOBYTE) + SHIFT_NOBYTE;
}

static void
setup_items(void) {
	void *pval = NULL;
	dns_qp_t *qp = NULL;
	dns_qp_create(isc_g_mctx, &test_methods, NULL, &qp);
	for (size_t i = 0; i < ARRAY_SIZE(item); i++) {
		do {
			size_t len = isc_random_uniform(16) + 4;
			item[i].len = len;
			for (size_t off = 0; off < len; off++) {
				item[i].key[off] = random_byte();
			}
			memmove(item[i].ascii, item[i].key, len);
			qp_test_keytoascii(item[i].ascii, len);
		} while (dns_qp_getkey(qp, item[i].key, item[i].len, &pval,
				       NULL) == ISC_R_SUCCESS);
		assert_int_equal(dns_qp_insert(qp, &item[i], i), ISC_R_SUCCESS);
	}
	dns_qp_destroy(&qp);
}

static bool
checkkey(dns_qpreadable_t qpr, size_t i, bool exists, const char *rubric) {
	bool ok = true;
	void *pval = NULL;
	uint32_t ival = ~0U;
	isc_result_t result;
	result = dns_qp_getkey(qpr, item[i].key, item[i].len, &pval, &ival);
	if (result == ISC_R_SUCCESS) {
		assert_true(exists);
		assert_ptr_equal(pval, &item[i]);
		assert_int_equal(ival, i);
	} else if (result == ISC_R_NOTFOUND) {
		assert_false(exists);
		assert_null(pval);
		assert_int_equal(ival, ~0U);
	} else {
		UNREACHABLE();
	}
	if (!ok) {
		TRACE("checkkey %p %zu %s %s %s", qpr.qpr, i,
		      exists ? "exists" : "missing", isc_result_totext(result),
		      rubric);
		UNUSED(rubric);
	}
	return ok;
}

static bool
checkallro(dns_qpreadable_t qp) {
	bool ok = true;
	for (size_t i = 0; i < ARRAY_SIZE(item); i++) {
		ASSERT(checkkey(qp, i, item[i].in_ro, "checkall ro"));
	}
	if (!ok) {
		qp_test_dumptrie(qp);
		TRACE("checkallro failed");
	}
	return ok;
}

static bool
checkallrw(dns_qpreadable_t qp) {
	bool ok = true;
	for (size_t i = 0; i < ARRAY_SIZE(item); i++) {
		ASSERT(checkkey(qp, i, item[i].in_rw, "checkall rw"));
	}
	if (!ok) {
		qp_test_dumptrie(qp);
		TRACE("checkallrw failed");
	}
	return ok;
}

static void
one_transaction(dns_qpmulti_t *qpm) {
	isc_result_t result;
	bool ok = true;

	dns_qpreader_t *qpo = NULL;
	dns_qpsnap_t *qps = NULL;
	dns_qpread_t qpr = { 0 };
	dns_qp_t *qpw = NULL;

	bool snap = isc_random_uniform(2) == 0;
	bool update = isc_random_uniform(2) != 0;
	bool rollback = update && isc_random_uniform(4) == 0;
	size_t count = isc_random_uniform(TRANSACTION_SIZE);

	TRACE("transaction %s %s %s size %zu", snap ? "snapshot" : "query",
	      update ? "update" : "write", rollback ? "rollback" : "commit",
	      count);

	/*
	 * We need to take care to avoid lock order inversion:
	 * The write mutex must be the outermost lock if it is held.
	 * The mutex must not be taken while the rwlock is held.
	 */

	/* briefly take and drop mutex */
	if (snap) {
		dns_qpmulti_snapshot(qpm, &qps);
		qpo = (dns_qpreader_t *)qps;
	}

	/* take mutex */
	if (update) {
		dns_qpmulti_update(qpm, &qpw);
	} else {
		dns_qpmulti_write(qpm, &qpw);
	}

	if (!snap) {
		dns_qpmulti_query(qpm, &qpr);
		qpo = (dns_qpreader_t *)&qpr;
	}

	for (size_t n = 0; n < count; n++) {
		size_t i = isc_random_uniform(ARRAY_SIZE(item));

		ASSERT(checkkey(qpo, i, item[i].in_ro, "before ro"));
		ASSERT(checkkey(qpw, i, item[i].in_rw, "before rw"));

		if (item[i].in_rw) {
			/* TRACE("delete %zu %.*s", i,
				 item[i].len, item[i].ascii); */
			void *pvald = NULL;
			uint32_t ivald = 0;
			result = dns_qp_deletekey(qpw, item[i].key, item[i].len,
						  &pvald, &ivald);
			ASSERT(result == ISC_R_SUCCESS);
			ASSERT(pvald == &item[i]);
			ASSERT(ivald == i);
			item[i].in_rw = false;
		} else {
			/* TRACE("insert %zu %.*s", i,
				 item[i].len, item[i].ascii); */
			result = dns_qp_insert(qpw, &item[i], i);
			ASSERT(result == ISC_R_SUCCESS);
			item[i].in_rw = true;
		}

		ASSERT(checkkey(qpo, i, item[i].in_ro, "after ro"));
		ASSERT(checkkey(qpw, i, item[i].in_rw, "after rw"));

		if (!ok) {
			TRACE("mutate %zu/%zu failed", n, count);
			qp_test_dumptrie(qpo);
			qp_test_dumptrie(qpw);
		}
		assert_true(ok);
	}

	assert_true(checkallro(qpo));
	assert_true(checkallrw(qpw));

	if (!snap) {
		dns_qpread_destroy(qpm, &qpr);
	}

	if (rollback) {
		TRACE("transaction rollback");
		dns_qpmulti_rollback(qpm, &qpw);
		/* mutex is now dropped */
		dns_qpmulti_query(qpm, &qpr);
		for (size_t i = 0; i < ARRAY_SIZE(item); i++) {
			if (snap) {
				ASSERT(checkkey(qps, i, item[i].in_ro,
						"rollback ro"));
			}
			item[i].in_rw = item[i].in_ro;
			ASSERT(checkkey(&qpr, i, item[i].in_rw, "rollback rw"));
		}
		dns_qpread_destroy(qpm, &qpr);
	} else {
		TRACE("transaction commit");
		dns_qpmulti_commit(qpm, &qpw);
		/* mutex is now dropped */
		dns_qpmulti_query(qpm, &qpr);
		for (size_t i = 0; i < ARRAY_SIZE(item); i++) {
			if (snap) {
				ASSERT(checkkey(qps, i, item[i].in_ro,
						"commit ro"));
			}
			item[i].in_ro = item[i].in_rw;
			ASSERT(checkkey(&qpr, i, item[i].in_rw, "commit rw"));
		}
		dns_qpread_destroy(qpm, &qpr);
	}

	if (snap) {
		TRACE("snapshot destroy");
		/* takes mutex briefly */
		dns_qpsnap_destroy(qpm, &qps);
	}

	TRACE("completed %s %s %s size %zu", snap ? "snapshot" : "query",
	      update ? "update" : "write", rollback ? "rollback" : "commit",
	      count);

	if (!ok) {
		TRACE("transaction failed");
		dns_qpmulti_query(qpm, &qpr);
		qp_test_dumptrie(&qpr);
		dns_qpread_destroy(qpm, &qpr);
	}
	assert_true(ok);
}

/*
 * The writer's fields belong to whoever holds the mutex, and the RCU
 * thread that frees chunks takes it too, so even the test must.
 */
static void
set_budget(dns_qpmulti_t *qpm, dns_qpcell_t budget) {
	LOCK(&qpm->mutex);
	qpm->writer.compact_budget = budget;
	UNLOCK(&qpm->mutex);
}

/*
 * Every slot below the frontier that holds no chunk must be on the free
 * list exactly once, and nothing else may be.
 */
static void
check_free_slots(dns_qpmulti_t *qpm) {
	dns_qp_t *qp = &qpm->writer;
	unsigned int listed = 0, empty = 0;

	LOCK(&qpm->mutex);
	assert_true(qp->chunk_frontier <= qp->chunk_max);
	for (dns_qpchunk_t c = qp->free_slot; c != INVALID_CHUNK;
	     c = qp->usage[c].reclaim_next)
	{
		assert_true(c < qp->chunk_frontier);
		assert_false(qp->usage[c].exists);
		assert_true(++listed <= qp->chunk_frontier);
	}
	for (dns_qpchunk_t c = 0; c < qp->chunk_max; c++) {
		if (c < qp->chunk_frontier && !qp->usage[c].exists) {
			empty++;
		} else if (c >= qp->chunk_frontier) {
			assert_false(qp->usage[c].exists);
		}
	}
	assert_int_equal(listed, empty);
	UNLOCK(&qpm->mutex);
}

static void
force_cycle(dns_qpmulti_t *qpm) {
	LOCK(&qpm->mutex);
	qpm->writer.compact_all = true;
	UNLOCK(&qpm->mutex);
}

static void
many_transactions(void *arg) {
	UNUSED(arg);

	dns_qpmulti_t *qpm = NULL;
	dns_qpmulti_create(isc_g_mctx, &test_methods, NULL, &qpm);
	qpm->writer.write_protect = true;
	/* many small compaction steps among the random transactions */
	set_budget(qpm, 64);

	for (size_t n = 0; n < TRANSACTION_COUNT; n++) {
		TRACE("transaction %zu", n);
		if (n % 100 == 0) {
			force_cycle(qpm);
		}
		one_transaction(qpm);
		rcu_quiescent_state();
	}

	dns_qpmulti_destroy(&qpm);
	isc_loopmgr_shutdown();
}

ISC_RUN_TEST_IMPL(qpmulti) {
	setup_loopmgr(NULL);
	setup_logging();
	setup_items();
	isc_loop_setup(isc_loop_main(), many_transactions, NULL);
	isc_loopmgr_run();
	rcu_barrier();
	isc_loopmgr_destroy();
}

ISC_RUN_TEST_IMPL(qpmulti_memusage) {
	dns_qpmulti_t *qpm = NULL;
	dns_qp_memusage_t mu;

	dns_qpmulti_create(isc_g_mctx, &test_methods, NULL, &qpm);

	mu = dns_qpmulti_memusage(qpm);
	assert_int_equal(mu.leaves, 0);
	assert_int_equal(mu.used, 0);

	dns_qpmulti_destroy(&qpm);
}

/* Empty reader chunks must be reclaimed when the bump allocator moves on. */
ISC_RUN_TEST_IMPL(qpmulti_reclaim_bump) {
	dns_qpmulti_t *qpm = NULL;
	dns_qp_t *qp = NULL;

	dns_qpmulti_create(isc_g_mctx, &test_methods, NULL, &qpm);
	for (size_t i = 0; i < 4 * QP_CHUNK_SIZE; i++) {
		dns_qpmulti_write(qpm, &qp);
		dns_qpmulti_commit(qpm, &qp);
	}
	rcu_barrier();

	dns_qp_memusage_t mu = dns_qpmulti_memusage(qpm);
	dns_qpmulti_destroy(&qpm);
	rcu_barrier();

	assert_int_equal(mu.leaves, 0);
	assert_int_equal(mu.chunk_count, 1);
}

/* Leave empty mutable chunks below the automatic recycling threshold. */
static void
empty_mutable_chunks(dns_qp_t *qp, size_t i) {
	item[i].len = 1;
	item[i].key[0] = SHIFT_BITMAP + i;

	for (size_t n = 0; n < 3 * QP_CHUNK_SIZE; n++) {
		assert_int_equal(dns_qp_insert(qp, &item[i], i), ISC_R_SUCCESS);
		assert_int_equal(dns_qp_deletekey(qp, item[i].key, item[i].len,
						  NULL, NULL),
				 ISC_R_SUCCESS);
	}
}

ISC_RUN_TEST_IMPL(qpmulti_reclaim_mutable) {
	dns_qpmulti_t *qpm = NULL;
	dns_qp_t *qp = NULL;

	dns_qpmulti_create(isc_g_mctx, &test_methods, NULL, &qpm);
	dns_qpmulti_write(qpm, &qp);
	empty_mutable_chunks(qp, 0);
	dns_qpmulti_commit(qpm, &qp);
	dns_qpmulti_write(qpm, &qp);
	dns_qpmulti_commit(qpm, &qp);
	rcu_barrier();

	dns_qp_memusage_t mu = dns_qpmulti_memusage(qpm);
	dns_qpmulti_destroy(&qpm);
	rcu_barrier();

	assert_int_equal(mu.leaves, 0);
	assert_int_equal(mu.chunk_count, 1);
	assert_int_equal(atomic_load_relaxed(&item[0].refcount), 0);
}

/* Rollback must discard candidates while retaining the published version. */
ISC_RUN_TEST_IMPL(qpmulti_reclaim_rollback) {
	dns_qpmulti_t *qpm = NULL;
	dns_qp_t *qp = NULL;
	dns_qpsnap_t *snap = NULL;

	item[0].len = 1;
	item[0].key[0] = SHIFT_BITMAP;
	dns_qpmulti_create(isc_g_mctx, &test_methods, NULL, &qpm);
	dns_qpmulti_write(qpm, &qp);
	assert_int_equal(dns_qp_insert(qp, &item[0], 0), ISC_R_SUCCESS);
	dns_qpmulti_commit(qpm, &qp);
	dns_qpmulti_snapshot(qpm, &snap);

	dns_qpmulti_update(qpm, &qp);
	assert_int_equal(
		dns_qp_deletekey(qp, item[0].key, item[0].len, NULL, NULL),
		ISC_R_SUCCESS);
	empty_mutable_chunks(qp, 1);
	dns_qpmulti_rollback(qpm, &qp);
	check_free_slots(qpm);

	dns_qpmulti_write(qpm, &qp);
	assert_true(checkkey(qp, 0, true, "after rollback"));
	assert_int_equal(
		dns_qp_deletekey(qp, item[0].key, item[0].len, NULL, NULL),
		ISC_R_SUCCESS);
	dns_qpmulti_commit(qpm, &qp);
	rcu_barrier();
	assert_true(checkkey(snap, 0, true, "snapshot after delete"));
	dns_qpsnap_destroy(qpm, &snap);
	rcu_barrier();
	check_free_slots(qpm);

	dns_qp_memusage_t mu = dns_qpmulti_memusage(qpm);
	dns_qpmulti_destroy(&qpm);
	rcu_barrier();

	assert_int_equal(mu.leaves, 0);
	assert_int_equal(mu.chunk_count, 1);
	assert_int_equal(atomic_load_relaxed(&item[0].refcount), 0);
	assert_int_equal(atomic_load_relaxed(&item[1].refcount), 0);
}

static dns_qpcell_t
chunk_usage_of(dns_qpmulti_t *qpm, dns_qpchunk_t c) {
	return qpm->writer.usage[c].used - qpm->writer.usage[c].free;
}

/*
 * Insert every item in write transactions of `batch`, and mark them
 * present for checkallrw().
 */
static void
insert_all(dns_qpmulti_t *qpm, size_t batch) {
	dns_qp_t *qp = NULL;

	for (size_t i = 0; i < ITEM_COUNT; i++) {
		item[i].in_rw = false;
	}
	for (size_t i = 0; i < ITEM_COUNT; i += batch) {
		dns_qpmulti_write(qpm, &qp);
		for (size_t j = i; j < i + batch && j < ITEM_COUNT; j++) {
			assert_int_equal(dns_qp_insert(qp, &item[j], j),
					 ISC_R_SUCCESS);
			item[j].in_rw = true;
		}
		dns_qpmulti_commit(qpm, &qp);
	}
}

/*
 * Run empty write transactions until no compaction cycle is active,
 * checking the contents now and then. Returns the number of commits.
 */
static unsigned int
compact_to_completion(dns_qpmulti_t *qpm, unsigned int limit) {
	dns_qp_t *qp = NULL;
	unsigned int commits = 0;

	while (qpm->writer.compact_active) {
		assert_true(commits < limit);
		dns_qpmulti_write(qpm, &qp);
		if (commits % 16 == 0) {
			assert_true(checkallrw(qp));
		}
		dns_qpmulti_commit(qpm, &qp);
		commits++;
	}
	return commits;
}

/*
 * While the trie lives, a stale copy of a leaf in a chunk that has not
 * been freed yet holds a reference too, so all we can say is that every
 * present item is referenced. After the trie is destroyed every chunk
 * has been freed, so nothing is referenced any more.
 */
static void
check_refcounts(bool destroyed) {
	for (size_t i = 0; i < ITEM_COUNT; i++) {
		uint32_t refs = atomic_load_relaxed(&item[i].refcount);
		if (destroyed) {
			assert_int_equal(refs, 0);
		} else if (item[i].in_rw) {
			assert_true(refs >= 1);
		}
	}
}

/* A forced cycle copies the whole trie in bounded steps across commits. */
ISC_RUN_TEST_IMPL(qpmulti_compact_incremental) {
	dns_qpmulti_t *qpm = NULL;
	dns_qp_t *qp = NULL;
	dns_qp_memusage_t mu;
	dns_qpcell_t evacuated;
	unsigned int commits = 0, height;
	uint64_t gen;

	setup_items();
	dns_qpmulti_create(isc_g_mctx, &test_methods, NULL, &qpm);
	set_budget(qpm, 256);
	insert_all(qpm, 100);
	compact_to_completion(qpm, 10000);

	mu = dns_qpmulti_memusage(qpm);
	gen = qpm->writer.generation;
	height = qp_test_getheight(&qpm->writer);

	force_cycle(qpm);
	dns_qpmulti_write(qpm, &qp);
	dns_qpmulti_commit(qpm, &qp);
	assert_true(qpm->writer.compact_active);
	assert_non_null(qpm->writer.compact_key);
	evacuated = qpm->writer.compact_evacuated;

	while (qpm->writer.compact_active) {
		dns_qpcell_t delta;

		/* every vector is visited and copied at most once */
		assert_true(commits <= 2 * mu.live / 256 + 2);
		dns_qpmulti_write(qpm, &qp);
		if (commits % 16 == 0) {
			assert_true(checkallrw(qp));
		}
		dns_qpmulti_commit(qpm, &qp);
		/* bounded: budget, the last vector, and the resume path */
		delta = qpm->writer.compact_evacuated - evacuated;
		assert_true(delta <= 256 + 96 + 96 * height);
		evacuated = qpm->writer.compact_evacuated;
		commits++;
	}
	assert_true(commits > 1);
	assert_null(qpm->writer.compact_key);
	assert_false(qpm->writer.compact_all);

	/* everything still in use was written by the cycle */
	rcu_barrier();
	LOCK(&qpm->mutex);
	for (dns_qpchunk_t c = 0; c < qpm->writer.chunk_max; c++) {
		if (qpm->writer.usage[c].exists && chunk_usage_of(qpm, c) > 0) {
			assert_true(qpm->writer.usage[c].generation > gen);
		}
	}
	UNLOCK(&qpm->mutex);

	mu = dns_qpmulti_memusage(qpm);
	assert_int_equal(mu.leaves, ITEM_COUNT);
	/* the only garbage left is the resume path copied by each step */
	assert_true(mu.free <= (size_t)(commits + 2) * 48 * (height + 1));
	check_refcounts(false);
	check_free_slots(qpm);

	dns_qpmulti_destroy(&qpm);
	rcu_barrier();
	check_refcounts(true);
}

/* Commits collect garbage on their own; nothing calls dns_qp_compact(). */
ISC_RUN_TEST_IMPL(qpmulti_compact_needgc) {
	dns_qpmulti_t *qpm = NULL;
	dns_qp_t *qp = NULL;
	dns_qp_memusage_t mu;
	unsigned int commits = 0;

	setup_items();
	dns_qpmulti_create(isc_g_mctx, &test_methods, NULL, &qpm);
	set_budget(qpm, 1024);
	insert_all(qpm, 100);
	compact_to_completion(qpm, 10000);
	rcu_barrier();
	mu = dns_qpmulti_memusage(qpm);
	size_t chunks_full = mu.chunk_count;

	for (size_t i = 16; i < ITEM_COUNT; i += 100) {
		dns_qpmulti_write(qpm, &qp);
		for (size_t j = i; j < i + 100 && j < ITEM_COUNT; j++) {
			assert_int_equal(dns_qp_deletekey(qp, item[j].key,
							  item[j].len, NULL,
							  NULL),
					 ISC_R_SUCCESS);
			item[j].in_rw = false;
		}
		dns_qpmulti_commit(qpm, &qp);
	}

	while (qpm->writer.compact_active ||
	       dns_qpmulti_memusage(qpm).fragmented)
	{
		assert_true(commits < 10000);
		dns_qpmulti_write(qpm, &qp);
		dns_qpmulti_commit(qpm, &qp);
		commits++;
	}

	rcu_barrier();
	mu = dns_qpmulti_memusage(qpm);
	assert_int_equal(mu.leaves, 16);
	assert_false(mu.fragmented);
	/*
	 * The memory of the deleted items was collected along the way:
	 * what is left is the bump chunk and at most a couple of chunks
	 * that the last cycles left too tightly packed to bother with.
	 */
	assert_true(mu.chunk_count * 2 < chunks_full);
	check_refcounts(false);

	dns_qpmulti_destroy(&qpm);
	rcu_barrier();
	check_refcounts(true);
}

/* Emptying the trie in the middle of a cycle ends the cycle cleanly. */
ISC_RUN_TEST_IMPL(qpmulti_compact_empty) {
	dns_qpmulti_t *qpm = NULL;
	dns_qp_t *qp = NULL;
	dns_qp_memusage_t mu;

	setup_items();
	dns_qpmulti_create(isc_g_mctx, &test_methods, NULL, &qpm);
	set_budget(qpm, 64);
	insert_all(qpm, 100);
	compact_to_completion(qpm, 10000);

	force_cycle(qpm);
	dns_qpmulti_write(qpm, &qp);
	dns_qpmulti_commit(qpm, &qp);
	assert_true(qpm->writer.compact_active);

	dns_qpmulti_write(qpm, &qp);
	for (size_t i = 0; i < ITEM_COUNT; i++) {
		assert_int_equal(dns_qp_deletekey(qp, item[i].key, item[i].len,
						  NULL, NULL),
				 ISC_R_SUCCESS);
		item[i].in_rw = false;
	}
	dns_qpmulti_commit(qpm, &qp);
	compact_to_completion(qpm, 10);

	rcu_barrier();
	mu = dns_qpmulti_memusage(qpm);
	assert_int_equal(mu.leaves, 0);
	assert_null(qpm->writer.compact_key);
	check_refcounts(false);

	dns_qpmulti_destroy(&qpm);
	rcu_barrier();
	check_refcounts(true);
}

/*
 * Random inserts and deletes while cycles run, with explicit calls to
 * dns_qp_compact() that share the transaction's step, and with the
 * cursor's own key deleted from under the collector now and then.
 */
ISC_RUN_TEST_IMPL(qpmulti_compact_mutate) {
	dns_qpmulti_t *qpm = NULL;
	dns_qp_t *qp = NULL;
	dns_qp_memusage_t mu;
	unsigned int cursor_deleted = 0;

	setup_items();
	dns_qpmulti_create(isc_g_mctx, &test_methods, NULL, &qpm);
	set_budget(qpm, 128);
	insert_all(qpm, 100);

	for (unsigned int n = 0; n < 3000; n++) {
		size_t i = isc_random_uniform(ITEM_COUNT);

		if (n % 500 == 0) {
			force_cycle(qpm);
		}
		dns_qpmulti_write(qpm, &qp);
		if (item[i].in_rw) {
			assert_int_equal(dns_qp_deletekey(qp, item[i].key,
							  item[i].len, NULL,
							  NULL),
					 ISC_R_SUCCESS);
			item[i].in_rw = false;
		} else {
			assert_int_equal(dns_qp_insert(qp, &item[i], i),
					 ISC_R_SUCCESS);
			item[i].in_rw = true;
		}
		if (n % 7 == 0 && qp->compact_key != NULL) {
			void *pval = NULL;
			uint32_t ival = 0;
			if (dns_qp_getkey(qp, *qp->compact_key,
					  qp->compact_keylen, &pval,
					  &ival) == ISC_R_SUCCESS)
			{
				assert_int_equal(
					dns_qp_deletekey(qp, *qp->compact_key,
							 qp->compact_keylen,
							 NULL, NULL),
					ISC_R_SUCCESS);
				item[ival].in_rw = false;
				cursor_deleted++;
			}
		}
		if (n % 5 == 0) {
			dns_qp_compact(qp, DNS_QPGC_MAYBE);
		}
		if (n % 250 == 0) {
			assert_true(checkallrw(qp));
		}
		dns_qpmulti_commit(qpm, &qp);
	}
	assert_true(cursor_deleted > 0);
	compact_to_completion(qpm, 10000);

	rcu_barrier();
	mu = dns_qpmulti_memusage(qpm);
	size_t expected = 0;
	for (size_t i = 0; i < ITEM_COUNT; i++) {
		expected += item[i].in_rw;
	}
	assert_int_equal(mu.leaves, expected);
	check_refcounts(false);

	dns_qpmulti_destroy(&qpm);
	rcu_barrier();
	check_refcounts(true);
}

/* An update transaction abandons the cycle; rollback leaves no cursor. */
ISC_RUN_TEST_IMPL(qpmulti_compact_rollback) {
	dns_qpmulti_t *qpm = NULL;
	dns_qp_t *qp = NULL;
	dns_qp_memusage_t mu;

	setup_items();
	dns_qpmulti_create(isc_g_mctx, &test_methods, NULL, &qpm);
	set_budget(qpm, 64);
	insert_all(qpm, 100);
	compact_to_completion(qpm, 10000);

	force_cycle(qpm);
	dns_qpmulti_write(qpm, &qp);
	dns_qpmulti_commit(qpm, &qp);
	assert_true(qpm->writer.compact_active);
	assert_non_null(qpm->writer.compact_key);

	dns_qpmulti_update(qpm, &qp);
	assert_false(qpm->writer.compact_active);
	assert_null(qpm->writer.compact_key);
	assert_true(qpm->writer.compact_all);
	assert_int_equal(
		dns_qp_deletekey(qp, item[0].key, item[0].len, NULL, NULL),
		ISC_R_SUCCESS);
	dns_qp_compact(qp, DNS_QPGC_MAYBE);
	assert_true(qpm->writer.compact_active);
	assert_non_null(qpm->writer.compact_key);
	dns_qpmulti_rollback(qpm, &qp);
	assert_false(qpm->writer.compact_active);
	assert_null(qpm->writer.compact_key);
	assert_true(qpm->writer.compact_all);
	check_free_slots(qpm);

	dns_qpmulti_write(qpm, &qp);
	assert_true(checkallrw(qp));
	dns_qpmulti_commit(qpm, &qp);
	compact_to_completion(qpm, 10000);

	rcu_barrier();
	check_free_slots(qpm);
	mu = dns_qpmulti_memusage(qpm);
	assert_int_equal(mu.leaves, ITEM_COUNT);
	check_refcounts(false);

	dns_qpmulti_destroy(&qpm);
	rcu_barrier();
	check_refcounts(true);
}

/* A snapshot keeps its version readable across a whole cycle. */
ISC_RUN_TEST_IMPL(qpmulti_compact_snapshot) {
	dns_qpmulti_t *qpm = NULL;
	dns_qp_t *qp = NULL;
	dns_qpsnap_t *snap = NULL;
	dns_qp_memusage_t held, released;

	setup_items();
	dns_qpmulti_create(isc_g_mctx, &test_methods, NULL, &qpm);
	set_budget(qpm, 256);
	insert_all(qpm, 100);
	compact_to_completion(qpm, 10000);

	dns_qpmulti_snapshot(qpm, &snap);
	force_cycle(qpm);
	dns_qpmulti_write(qpm, &qp);
	dns_qpmulti_commit(qpm, &qp);
	compact_to_completion(qpm, 10000);
	assert_true(checkallrw(snap));

	rcu_barrier();
	held = dns_qpmulti_memusage(qpm);
	dns_qpsnap_destroy(qpm, &snap);
	rcu_barrier();
	released = dns_qpmulti_memusage(qpm);
	assert_true(released.chunk_count < held.chunk_count);
	check_refcounts(false);

	dns_qpmulti_destroy(&qpm);
	rcu_barrier();
	check_refcounts(true);
}

/*
 * Compaction steps taken from a job that runs whenever the loop gets
 * around to it, with no write transaction of our own in between:
 * dns_qpmulti_gcstep() does all the work and never blocks.
 */
static unsigned int gc_steps, gc_pumps;

static void
gc_pump(void *arg) {
	dns_qpmulti_t *qpm = arg;
	dns_qp_memusage_t mu;

	if (dns_qpmulti_gcpending(qpm)) {
		uint32_t before = qpm->writer.compact_steps;

		assert_true(++gc_pumps < 100000);
		(void)dns_qpmulti_gcstep(qpm);
		if (qpm->writer.compact_steps != before) {
			gc_steps++;
		}
		isc_async_current(gc_pump, qpm);
		return;
	}
	assert_false(qpm->writer.compact_active);
	assert_true(gc_steps > 1);
	/* the forced cycle's first step came from our commit, the rest here */
	assert_int_equal(qpm->writer.compact_steps, gc_steps + 1);
	assert_true(qpm->background_gc);

	/* while a writer holds the mutex, a step is refused, not awaited */
	LOCK(&qpm->mutex);
	uint32_t before = qpm->writer.compact_steps;
	assert_true(dns_qpmulti_gcstep(qpm));
	assert_int_equal(qpm->writer.compact_steps, before);
	UNLOCK(&qpm->mutex);

	rcu_barrier();
	mu = dns_qpmulti_memusage(qpm);
	assert_int_equal(mu.leaves, ITEM_COUNT);
	assert_false(mu.fragmented);
	check_refcounts(false);

	dns_qpmulti_destroy(&qpm);
	isc_loopmgr_shutdown();
}

static void
gc_start(void *arg ISC_ATTR_UNUSED) {
	dns_qpmulti_t *qpm = NULL;
	dns_qp_t *qp = NULL;

	dns_qpmulti_create(isc_g_mctx, &test_methods, NULL, &qpm);
	set_budget(qpm, 256);
	insert_all(qpm, 100);
	compact_to_completion(qpm, 10000);

	/* force a cycle; this commit takes its first step */
	force_cycle(qpm);
	dns_qpmulti_write(qpm, &qp);
	dns_qpmulti_commit(qpm, &qp);
	assert_true(qpm->writer.compact_active);
	assert_true(dns_qpmulti_gcpending(qpm));
	assert_int_equal(qpm->writer.compact_steps, 1);

	gc_steps = gc_pumps = 0;
	isc_async_current(gc_pump, qpm);
}

ISC_RUN_TEST_IMPL(qpmulti_gcstep) {
	setup_loopmgr(NULL);
	setup_items();
	isc_loop_setup(isc_loop_main(), gc_start, NULL);
	isc_loopmgr_run();
	rcu_barrier();
	isc_loopmgr_destroy();
	check_refcounts(true);
}

/* Destroying a trie with a saved cursor must not leak it. */
ISC_RUN_TEST_IMPL(qpmulti_compact_destroy) {
	dns_qpmulti_t *qpm = NULL;
	dns_qp_t *qp = NULL;

	setup_items();
	dns_qpmulti_create(isc_g_mctx, &test_methods, NULL, &qpm);
	set_budget(qpm, 64);
	insert_all(qpm, 100);
	compact_to_completion(qpm, 10000);

	force_cycle(qpm);
	dns_qpmulti_write(qpm, &qp);
	dns_qpmulti_commit(qpm, &qp);
	assert_non_null(qpm->writer.compact_key);

	dns_qpmulti_destroy(&qpm);
	rcu_barrier();
	check_refcounts(true);
}

/*
 * Build a single-threaded trie holding items [lo, hi).
 */
static dns_qp_t *
build_offline(size_t lo, size_t hi) {
	dns_qp_t *qp = NULL;

	dns_qp_create(isc_g_mctx, &test_methods, NULL, &qp);
	for (size_t i = lo; i < hi; i++) {
		assert_int_equal(dns_qp_insert(qp, &item[i], i), ISC_R_SUCCESS);
	}
	return qp;
}

static void
delete_all(dns_qpmulti_t *qpm) {
	dns_qp_t *qp = NULL;

	dns_qpmulti_write(qpm, &qp);
	for (size_t i = 0; i < ITEM_COUNT; i++) {
		assert_int_equal(dns_qp_deletekey(qp, item[i].key, item[i].len,
						  NULL, NULL),
				 ISC_R_SUCCESS);
	}
	dns_qpmulti_commit(qpm, &qp);
}

/*
 * An adopted trie replaces the published version in one step; a reader
 * of the old version keeps it until it is done, and only then are the
 * old leaves detached.
 */
ISC_RUN_TEST_IMPL(qpmulti_adopt) {
	dns_qpmulti_t *qpm = NULL;
	dns_qp_t *qp = NULL;
	dns_qpread_t old, new;
	dns_qp_memusage_t mu;
	uint64_t generation;

	setup_items();
	dns_qpmulti_create(isc_g_mctx, &test_methods, NULL, &qpm);
	insert_all(qpm, 100);
	compact_to_completion(qpm, 10000);
	LOCK(&qpm->mutex);
	generation = qpm->writer.generation;
	UNLOCK(&qpm->mutex);

	dns_qpmulti_query(qpm, &old);

	qp = build_offline(ITEM_COUNT / 2, ITEM_COUNT);
	dns_qpmulti_adopt(qpm, &qp);
	assert_null(qp);

	/* the old version is intact, the new one has the second half */
	assert_true(checkallrw(&old));
	dns_qpmulti_query(qpm, &new);
	for (size_t i = 0; i < ITEM_COUNT; i++) {
		assert_true(checkkey(&new, i, i >= ITEM_COUNT / 2, "adopted"));
	}
	dns_qpread_destroy(qpm, &new);
	dns_qpread_destroy(qpm, &old);
	rcu_barrier();

	/* the old version's leaves were detached, exactly once each */
	for (size_t i = 0; i < ITEM_COUNT; i++) {
		assert_int_equal(atomic_load_relaxed(&item[i].refcount),
				 i >= ITEM_COUNT / 2 ? 1 : 0);
		item[i].in_rw = i >= ITEM_COUNT / 2;
	}
	LOCK(&qpm->mutex);
	assert_int_equal(qpm->writer.generation, generation + 1);
	assert_true(ISC_LIST_EMPTY(qpm->reclaiming));
	UNLOCK(&qpm->mutex);
	check_free_slots(qpm);
	mu = dns_qpmulti_memusage(qpm);
	assert_int_equal(mu.leaves, ITEM_COUNT - ITEM_COUNT / 2);
	assert_false(mu.fragmented);

	/* ordinary transactions carry on from the adopted version */
	dns_qpmulti_write(qpm, &qp);
	for (size_t i = 0; i < ITEM_COUNT / 2; i++) {
		assert_int_equal(dns_qp_insert(qp, &item[i], i), ISC_R_SUCCESS);
		item[i].in_rw = true;
	}
	dns_qpmulti_commit(qpm, &qp);
	dns_qpmulti_query(qpm, &new);
	assert_true(checkallrw(&new));
	dns_qpread_destroy(qpm, &new);
	compact_to_completion(qpm, 10000);
	rcu_barrier();
	check_refcounts(false);
	check_free_slots(qpm);

	dns_qpmulti_destroy(&qpm);
	rcu_barrier();
	check_refcounts(true);
}

/*
 * Chunks that a queued reclamation callback has yet to free are
 * renumbered by adoption, so the callback frees the right memory and
 * leaves the adopted trie alone.
 */
ISC_RUN_TEST_IMPL(qpmulti_adopt_reclaiming) {
	dns_qpmulti_t *qpm = NULL;
	dns_qp_t *qp = NULL;
	dns_qpread_t hold, new;
	dns_qp_memusage_t mu;

	setup_items();
	dns_qpmulti_create(isc_g_mctx, &test_methods, NULL, &qpm);
	insert_all(qpm, 100);
	compact_to_completion(qpm, 10000);
	rcu_barrier();

	/* pin the grace period so the callbacks queued below cannot run */
	dns_qpmulti_query(qpm, &hold);
	delete_all(qpm);
	LOCK(&qpm->mutex);
	assert_false(ISC_LIST_EMPTY(qpm->reclaiming));
	UNLOCK(&qpm->mutex);

	qp = build_offline(0, ITEM_COUNT);
	dns_qpmulti_adopt(qpm, &qp);
	LOCK(&qpm->mutex);
	assert_false(ISC_LIST_EMPTY(qpm->reclaiming));
	UNLOCK(&qpm->mutex);

	dns_qpmulti_query(qpm, &new);
	assert_true(checkallrw(&new));
	dns_qpread_destroy(qpm, &new);

	/* let the callbacks run with their renumbered chunks */
	dns_qpread_destroy(qpm, &hold);
	rcu_barrier();
	LOCK(&qpm->mutex);
	assert_true(ISC_LIST_EMPTY(qpm->reclaiming));
	UNLOCK(&qpm->mutex);
	check_free_slots(qpm);

	dns_qpmulti_query(qpm, &new);
	assert_true(checkallrw(&new));
	dns_qpread_destroy(qpm, &new);
	for (size_t i = 0; i < ITEM_COUNT; i++) {
		assert_int_equal(atomic_load_relaxed(&item[i].refcount), 1);
	}
	mu = dns_qpmulti_memusage(qpm);
	assert_int_equal(mu.leaves, ITEM_COUNT);
	assert_false(mu.fragmented);

	dns_qpmulti_destroy(&qpm);
	rcu_barrier();
	check_refcounts(true);
}

/* A trie that was never committed to can adopt as well. */
ISC_RUN_TEST_IMPL(qpmulti_adopt_fresh) {
	dns_qpmulti_t *qpm = NULL;
	dns_qp_t *qp = NULL;
	dns_qpread_t new;

	setup_items();
	dns_qpmulti_create(isc_g_mctx, &test_methods, NULL, &qpm);
	qp = build_offline(0, ITEM_COUNT);
	dns_qpmulti_adopt(qpm, &qp);

	for (size_t i = 0; i < ITEM_COUNT; i++) {
		item[i].in_rw = true;
	}
	dns_qpmulti_query(qpm, &new);
	assert_true(checkallrw(&new));
	dns_qpread_destroy(qpm, &new);

	dns_qpmulti_write(qpm, &qp);
	assert_int_equal(
		dns_qp_deletekey(qp, item[0].key, item[0].len, NULL, NULL),
		ISC_R_SUCCESS);
	item[0].in_rw = false;
	dns_qpmulti_commit(qpm, &qp);
	dns_qpmulti_query(qpm, &new);
	assert_true(checkallrw(&new));
	dns_qpread_destroy(qpm, &new);
	rcu_barrier();
	check_refcounts(false);
	check_free_slots(qpm);

	dns_qpmulti_destroy(&qpm);
	rcu_barrier();
	check_refcounts(true);
}

ISC_TEST_LIST_START
ISC_TEST_ENTRY(qpmulti)
ISC_TEST_ENTRY(qpmulti_memusage)
ISC_TEST_ENTRY(qpmulti_reclaim_bump)
ISC_TEST_ENTRY(qpmulti_reclaim_mutable)
ISC_TEST_ENTRY(qpmulti_reclaim_rollback)
ISC_TEST_ENTRY(qpmulti_compact_incremental)
ISC_TEST_ENTRY(qpmulti_compact_needgc)
ISC_TEST_ENTRY(qpmulti_compact_empty)
ISC_TEST_ENTRY(qpmulti_compact_mutate)
ISC_TEST_ENTRY(qpmulti_compact_rollback)
ISC_TEST_ENTRY(qpmulti_compact_snapshot)
ISC_TEST_ENTRY(qpmulti_compact_destroy)
ISC_TEST_ENTRY(qpmulti_gcstep)
ISC_TEST_ENTRY(qpmulti_adopt)
ISC_TEST_ENTRY(qpmulti_adopt_reclaiming)
ISC_TEST_ENTRY(qpmulti_adopt_fresh)
ISC_TEST_LIST_END

ISC_TEST_MAIN
