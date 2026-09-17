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
	size_t count = isc_random_uniform(TRANSACTION_SIZE);

	TRACE("transaction %s size %zu", snap ? "snapshot" : "query", count);

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
	dns_qpmulti_write(qpm, &qpw);

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

	TRACE("transaction commit");
	dns_qpmulti_commit(qpm, &qpw);
	/* mutex is now dropped */
	dns_qpmulti_query(qpm, &qpr);
	for (size_t i = 0; i < ARRAY_SIZE(item); i++) {
		if (snap) {
			ASSERT(checkkey(qps, i, item[i].in_ro, "commit ro"));
		}
		item[i].in_ro = item[i].in_rw;
		ASSERT(checkkey(&qpr, i, item[i].in_rw, "commit rw"));
	}
	dns_qpread_destroy(qpm, &qpr);

	if (snap) {
		TRACE("snapshot destroy");
		/* takes mutex briefly */
		dns_qpsnap_destroy(qpm, &qps);
	}

	TRACE("completed %s size %zu", snap ? "snapshot" : "query", count);

	if (!ok) {
		TRACE("transaction failed");
		dns_qpmulti_query(qpm, &qpr);
		qp_test_dumptrie(&qpr);
		dns_qpread_destroy(qpm, &qpr);
	}
	assert_true(ok);
}

static void
many_transactions(void *arg) {
	UNUSED(arg);

	dns_qpmulti_t *qpm = NULL;
	dns_qpmulti_create(isc_g_mctx, &test_methods, NULL, &qpm);
	qpm->writer.write_protect = true;

	for (size_t n = 0; n < TRANSACTION_COUNT; n++) {
		TRACE("transaction %zu", n);
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
	check_free_slots(qpm);

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

ISC_TEST_LIST_START
ISC_TEST_ENTRY(qpmulti)
ISC_TEST_ENTRY(qpmulti_memusage)
ISC_TEST_ENTRY(qpmulti_reclaim_bump)
ISC_TEST_ENTRY(qpmulti_reclaim_mutable)
ISC_TEST_LIST_END

ISC_TEST_MAIN
