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
#include <isc/lib.h>
#include <isc/log.h>
#include <isc/loop.h>
#include <isc/magic.h>
#include <isc/mem.h>
#include <isc/random.h>
#include <isc/refcount.h>
#include <isc/rwlock.h>
#include <isc/thread.h>
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

static struct {
	atomic_uint refcount;
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
	INSIST(atomic_fetch_sub_relaxed(&item[ival].refcount, 1) != 0);
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

static void
many_transactions(void *arg) {
	UNUSED(arg);

	dns_qpmulti_t *qpm = NULL;
	dns_qpmulti_create(isc_g_mctx, &test_methods, NULL, &qpm);

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

/* Deterministic keys with separately observable physical leaf lifetimes. */
typedef struct lifetime_item {
	atomic_uint references;
} lifetime_item_t;

static void
lifetime_attach(void *ctx ISC_ATTR_UNUSED, void *pval,
		uint32_t ival ISC_ATTR_UNUSED) {
	lifetime_item_t *value = pval;
	atomic_fetch_add_relaxed(&value->references, 1);
}

static void
lifetime_detach(void *ctx ISC_ATTR_UNUSED, void *pval,
		uint32_t ival ISC_ATTR_UNUSED) {
	lifetime_item_t *value = pval;
	INSIST(atomic_fetch_sub_relaxed(&value->references, 1) != 0);
}

static size_t
lifetime_key(dns_qpkey_t key, void *ctx ISC_ATTR_UNUSED,
	     void *pval ISC_ATTR_UNUSED, uint32_t ival) {
	for (unsigned int i = 0; i < 4; i++) {
		key[i] = SHIFT_BITMAP + ((ival >> (4 * i)) & 15);
	}
	return 4;
}

static const dns_qpmethods_t lifetime_methods = {
	lifetime_attach,
	lifetime_detach,
	lifetime_key,
	testname,
};

static void
lifetime_check(dns_qpreadable_t qp, lifetime_item_t *values, uint32_t first,
	       uint32_t end, bool exists) {
	for (uint32_t i = first; i < end; i++) {
		dns_qpkey_t key;
		size_t len = lifetime_key(key, NULL, NULL, i);
		void *pval = NULL;
		isc_result_t result = dns_qp_getkey(qp, key, len, &pval, NULL);
		assert_int_equal(result,
				 exists ? ISC_R_SUCCESS : ISC_R_NOTFOUND);
		if (exists) {
			assert_ptr_equal(pval, &values[i]);
			assert_true(atomic_load_relaxed(&values[i].references) >
				    0);
		}
	}
}

static void
lifetime_delete(dns_qp_t *qp, uint32_t first, uint32_t end) {
	for (uint32_t i = first; i < end; i++) {
		dns_qpkey_t key;
		size_t len = lifetime_key(key, NULL, NULL, i);
		assert_int_equal(dns_qp_deletekey(qp, key, len, NULL, NULL),
				 ISC_R_SUCCESS);
	}
}

static void
drain_versions(void) {
	rcu_thread_offline();
	rcu_barrier();
	rcu_thread_online();
}

ISC_RUN_TEST_IMPL(qpmulti_versions) {
	lifetime_item_t values[64] = { 0 };
	dns_qpmulti_t *multi = NULL;
	dns_qp_t *qp = NULL;
	dns_qpsnap_t *empty = NULL, *snap1 = NULL, *snap2 = NULL;
	dns_qpread_t old = { 0 };
	dns_qpmulti_create(isc_g_mctx, &lifetime_methods, NULL, &multi);
	dns_qpmulti_snapshot(multi, &empty);

	dns_qpmulti_write(multi, &qp);
	for (uint32_t i = 0; i < 32; i++) {
		assert_int_equal(dns_qp_insert(qp, &values[i], i),
				 ISC_R_SUCCESS);
	}
	dns_qp_compact(qp, DNS_QPGC_ALL);
	/* The first pass frees the low indices; the second occupies one. */
	dns_qp_compact(qp, DNS_QPGC_ALL);
	dns_qpmulti_commit(multi, &qp);
	dns_qpmulti_snapshot(multi, &snap1);
	dns_qpmulti_snapshot(multi, &snap2);
	dns_qpmulti_query(multi, &old);
	assert_ptr_equal(snap1->base, old.base);
	assert_ptr_equal(snap2->base, old.base);
	lifetime_check(empty, values, 0, 64, false);
	dns_qpsnap_destroy(multi, &empty);

	size_t bytes = old.base->chunk_max * sizeof(old.base->ptr[0]);
	dns_qpnode_t **mapping = isc_mem_get(isc_g_mctx, bytes);
	memmove(mapping, old.base->ptr, bytes);

	dns_qpmulti_write(multi, &qp);
	assert_ptr_not_equal(qp->base, old.base);
	lifetime_delete(qp, 0, 32);
	for (uint32_t i = 32; i < 64; i++) {
		assert_int_equal(dns_qp_insert(qp, &values[i], i),
				 ISC_R_SUCCESS);
	}
	dns_qp_compact(qp, DNS_QPGC_ALL);
	dns_qpmulti_commit(multi, &qp);

	/* Reuse a retired index before the old RCU reader can depart. */
	bool reused = false;
	for (unsigned int round = 0; round < 8; round++) {
		dns_qpmulti_write(multi, &qp);
		dns_qp_compact(qp, DNS_QPGC_ALL);
		for (dns_qpchunk_t c = 0; c < old.base->chunk_max; c++) {
			if (mapping[c] != NULL && qp->base->ptr[c] != NULL &&
			    mapping[c] != qp->base->ptr[c])
			{
				reused = true;
			}
		}
		dns_qpmulti_commit(multi, &qp);
		assert_memory_equal(mapping, old.base->ptr, bytes);
		lifetime_check(&old, values, 0, 32, true);
		lifetime_check(&old, values, 32, 64, false);
	}
	assert_true(reused);
	isc_mem_put(isc_g_mctx, mapping, bytes);
	dns_qpread_destroy(multi, &old);
	drain_versions();

	/* Snapshots survive both index reuse and the RCU grace period. */
	lifetime_check(snap1, values, 0, 32, true);
	dns_qpsnap_destroy(multi, &snap1);
	lifetime_check(snap2, values, 0, 32, true);
	dns_qpsnap_destroy(multi, &snap2);
	for (uint32_t i = 0; i < 32; i++) {
		assert_int_equal(atomic_load_relaxed(&values[i].references), 0);
	}
	dns_qpmulti_query(multi, &old);
	lifetime_check(&old, values, 32, 64, true);
	dns_qpread_destroy(multi, &old);
	dns_qpmulti_destroy(&multi);
	drain_versions();
	for (uint32_t i = 0; i < 64; i++) {
		assert_int_equal(atomic_load_relaxed(&values[i].references), 0);
	}
}

ISC_RUN_TEST_IMPL(qpmulti_clone_rollback) {
	lifetime_item_t values[2048] = { 0 };
	dns_qpmulti_t *multi = NULL;
	dns_qp_t *qp = NULL;
	dns_qpread_t read = { 0 };
	dns_qpmulti_create(isc_g_mctx, &lifetime_methods, NULL, &multi);

	/* Roll back the very first update, including its initial allocation. */
	dns_qpmulti_update(multi, &qp);
	assert_int_equal(dns_qp_insert(qp, &values[0], 0), ISC_R_SUCCESS);
	dns_qpmulti_rollback(multi, &qp);
	assert_int_equal(atomic_load_relaxed(&values[0].references), 0);
	dns_qpmulti_query(multi, &read);
	lifetime_check(&read, values, 0, 1, false);
	dns_qpread_destroy(multi, &read);

	dns_qpmulti_update(multi, &qp);
	assert_int_equal(dns_qp_insert(qp, &values[0], 0), ISC_R_SUCCESS);
	dns_qpmulti_commit(multi, &qp);
	dns_qpmulti_query(multi, &read);
	dns_qpchunk_t oldmax = read.base->chunk_max;
	dns_qp_memusage_t before = dns_qpmulti_memusage(multi);

	dns_qpmulti_update(multi, &qp);
	lifetime_delete(qp, 0, 1);
	for (uint32_t i = 1; i < ARRAY_SIZE(values); i++) {
		assert_int_equal(dns_qp_insert(qp, &values[i], i),
				 ISC_R_SUCCESS);
	}
	assert_true(qp->chunk_max > oldmax);
	dns_qp_compact(qp, DNS_QPGC_ALL);
	lifetime_check(&read, values, 0, 1, true);
	lifetime_check(&read, values, 1, ARRAY_SIZE(values), false);
	dns_qpmulti_rollback(multi, &qp);
	assert_ptr_equal(multi->writer.base, read.base);
	dns_qp_memusage_t after = dns_qpmulti_memusage(multi);
	assert_int_equal(before.used, after.used);
	assert_int_equal(before.free, after.free);
	assert_int_equal(before.bytes, after.bytes);
	for (uint32_t i = 1; i < ARRAY_SIZE(values); i++) {
		assert_int_equal(atomic_load_relaxed(&values[i].references), 0);
	}
	dns_qpread_destroy(multi, &read);

	/* Empty commits and write-after-update must handle a zero-sized bump.
	 */
	dns_qpmulti_update(multi, &qp);
	lifetime_delete(qp, 0, 1);
	dns_qpmulti_commit(multi, &qp);
	dns_qpmulti_write(multi, &qp);
	dns_qpmulti_commit(multi, &qp);
	dns_qpmulti_destroy(&multi);
	drain_versions();
	assert_int_equal(atomic_load_relaxed(&values[0].references), 0);
}

static void
check_base_layout(dns_qpbase_t *base) {
	size_t count = base->chunk_max;
	assert_true((char *)base->free >=
		    (char *)base->immutable + base_bitmap_size(count));
	assert_true((char *)base->ptr >= (char *)(base->free + count));
	assert_int_equal((uintptr_t)base->free % alignof(uint16_t), 0);
	assert_int_equal((uintptr_t)base->ptr % alignof(dns_qpnode_t *), 0);
	assert_ptr_equal(base->ptr + count, (char *)base + base_size(count));
}

ISC_RUN_TEST_IMPL(qpmulti_base_metadata) {
	lifetime_item_t values[32768] = { 0 };
	dns_qpmulti_t *multi = NULL;
	dns_qp_t *qp = NULL;
	dns_qpread_t read = { 0 };
	dns_qpmulti_create(isc_g_mctx, &lifetime_methods, NULL, &multi);
	dns_qpmulti_write(multi, &qp);
	for (uint32_t i = 0; i < 128; i++) {
		assert_int_equal(dns_qp_insert(qp, &values[i], i),
				 ISC_R_SUCCESS);
		check_base_layout(qp->base);
		/* Growth must not freeze chunks allocated in this transaction.
		 */
		for (dns_qpchunk_t c = 0; c < qp->chunk_max; c++) {
			if (qp->base->ptr[c] != NULL) {
				assert_false(chunk_immutable(qp->base, c));
			}
		}
	}
	dns_qpmulti_commit(multi, &qp);
	dns_qpmulti_query(multi, &read);
	dns_qpbase_t *old = read.base;
	size_t bitmap_bytes = base_bitmap_size(old->chunk_max);
	size_t free_bytes = old->chunk_max * sizeof(old->free[0]);
	uint8_t *bitmap = isc_mem_get(isc_g_mctx, bitmap_bytes);
	uint16_t *counters = isc_mem_get(isc_g_mctx, free_bytes);
	memmove(bitmap, old->immutable, bitmap_bytes);
	memmove(counters, old->free, free_bytes);

	dns_qpmulti_update(multi, &qp);
	lifetime_delete(qp, 0, 64);
	bool changed = false;
	for (dns_qpchunk_t c = 0; c < old->chunk_max; c++) {
		if (qp->base->free[c] != counters[c]) {
			changed = true;
		}
	}
	assert_true(changed);
	/* Cross bitmap-byte boundaries and grow a mixture of old/new chunks. */
	for (uint32_t i = 128; i < ARRAY_SIZE(values); i++) {
		assert_int_equal(dns_qp_insert(qp, &values[i], i),
				 ISC_R_SUCCESS);
		check_base_layout(qp->base);
		for (dns_qpchunk_t c = 0; c < qp->chunk_max; c++) {
			if (qp->base->ptr[c] != NULL) {
				assert_int_equal(chunk_immutable(qp->base, c),
						 c < old->chunk_max &&
							 old->ptr[c] != NULL);
			}
		}
		if (qp->chunk_max > old->chunk_max && qp->chunk_max > 8) {
			break;
		}
	}
	assert_true(qp->chunk_max > old->chunk_max);
	assert_true(qp->chunk_max > 8);
	assert_memory_equal(old->immutable, bitmap, bitmap_bytes);
	assert_memory_equal(old->free, counters, free_bytes);
	lifetime_check(&read, values, 0, 128, true);
	dns_qpmulti_rollback(multi, &qp);
	assert_ptr_equal(multi->writer.base, old);
	assert_memory_equal(old->immutable, bitmap, bitmap_bytes);
	assert_memory_equal(old->free, counters, free_bytes);

	/* A write after rollback must freeze the restored chunks anew. */
	dns_qpmulti_write(multi, &qp);
	for (dns_qpchunk_t c = 0; c < old->chunk_max; c++) {
		if (old->ptr[c] != NULL) {
			assert_true(chunk_immutable(qp->base, c));
		}
	}
	lifetime_delete(qp, 0, 128);
	dns_qpmulti_commit(multi, &qp);
	assert_memory_equal(old->immutable, bitmap, bitmap_bytes);
	assert_memory_equal(old->free, counters, free_bytes);
	lifetime_check(&read, values, 0, 128, true);
	isc_mem_put(isc_g_mctx, bitmap, bitmap_bytes);
	isc_mem_put(isc_g_mctx, counters, free_bytes);
	dns_qpread_destroy(multi, &read);
	dns_qpmulti_destroy(&multi);
	drain_versions();
	for (uint32_t i = 0; i < ARRAY_SIZE(values); i++) {
		assert_int_equal(atomic_load_relaxed(&values[i].references), 0);
	}
}

ISC_RUN_TEST_IMPL(qpmulti_reclaim_without_mutex) {
	lifetime_item_t values[32] = { 0 };
	dns_qpmulti_t *multi = NULL;
	dns_qp_t *qp = NULL;
	dns_qpread_t old = { 0 };
	dns_qpmulti_create(isc_g_mctx, &lifetime_methods, NULL, &multi);
	dns_qpmulti_write(multi, &qp);
	for (uint32_t i = 0; i < ARRAY_SIZE(values); i++) {
		assert_int_equal(dns_qp_insert(qp, &values[i], i),
				 ISC_R_SUCCESS);
	}
	dns_qpmulti_commit(multi, &qp);
	dns_qpmulti_query(multi, &old);
	dns_qpmulti_write(multi, &qp);
	lifetime_delete(qp, 0, ARRAY_SIZE(values));
	dns_qpmulti_commit(multi, &qp);
	dns_qpread_destroy(multi, &old);

	/* This barrier would deadlock if the callback acquired the writer
	 * mutex. */
	dns_qpmulti_write(multi, &qp);
	drain_versions();
	for (uint32_t i = 0; i < ARRAY_SIZE(values); i++) {
		assert_int_equal(atomic_load_relaxed(&values[i].references), 0);
	}
	dns_qpmulti_commit(multi, &qp);

	/* Destruction must wait for readers of already retired versions too. */
	dns_qpmulti_write(multi, &qp);
	assert_int_equal(dns_qp_insert(qp, &values[0], 0), ISC_R_SUCCESS);
	dns_qpmulti_commit(multi, &qp);
	dns_qpmulti_query(multi, &old);
	dns_qpmulti_write(multi, &qp);
	lifetime_delete(qp, 0, 1);
	dns_qpmulti_commit(multi, &qp);
	dns_qpmulti_t *whence = multi;
	dns_qpmulti_destroy(&multi);
	lifetime_check(&old, values, 0, 1, true);
	dns_qpread_destroy(whence, &old);
	drain_versions();
	assert_int_equal(atomic_load_relaxed(&values[0].references), 0);
}

typedef struct concurrent_readers {
	dns_qpmulti_t *multi;
	lifetime_item_t *values;
	atomic_bool stop;
	atomic_uint started;
	atomic_uint reads;
} concurrent_readers_t;

static void *
read_versions(void *arg) {
	concurrent_readers_t *ctx = arg;
	atomic_fetch_add_release(&ctx->started, 1);
	unsigned int round = 0;
	do {
		dns_qpread_t read = { 0 };
		dns_qpsnap_t *snap = NULL;
		dns_qpreader_t *qp;
		if (round++ % 2 == 0) {
			dns_qpmulti_query(ctx->multi, &read);
			qp = (dns_qpreader_t *)&read;
		} else {
			dns_qpmulti_snapshot(ctx->multi, &snap);
			qp = (dns_qpreader_t *)snap;
		}

		dns_qpkey_t key;
		size_t len = lifetime_key(key, NULL, NULL, 0);
		isc_result_t result = dns_qp_getkey(qp, key, len, NULL, NULL);
		INSIST(result == ISC_R_SUCCESS || result == ISC_R_NOTFOUND);
		bool first = result == ISC_R_SUCCESS;
		for (uint32_t i = 0; i < 128; i++) {
			len = lifetime_key(key, NULL, NULL, i);
			void *pval = NULL;
			result = dns_qp_getkey(qp, key, len, &pval, NULL);
			bool exists = (i < 64) == first;
			INSIST(result ==
			       (exists ? ISC_R_SUCCESS : ISC_R_NOTFOUND));
			if (exists) {
				INSIST(pval == &ctx->values[i]);
				INSIST(atomic_load_relaxed(
					       &ctx->values[i].references) > 0);
			}
			if (i == 32) {
				isc_thread_yield();
			}
		}
		if (snap != NULL) {
			dns_qpsnap_destroy(ctx->multi, &snap);
		} else {
			dns_qpread_destroy(ctx->multi, &read);
		}
		atomic_fetch_add_relaxed(&ctx->reads, 1);
		rcu_quiescent_state();
	} while (!atomic_load_acquire(&ctx->stop));
	return NULL;
}

ISC_RUN_TEST_IMPL(qpmulti_concurrent_versions) {
	lifetime_item_t values[128] = { 0 };
	dns_qpmulti_t *multi = NULL;
	dns_qp_t *qp = NULL;
	dns_qpmulti_create(isc_g_mctx, &lifetime_methods, NULL, &multi);
	dns_qpmulti_write(multi, &qp);
	for (uint32_t i = 0; i < 64; i++) {
		assert_int_equal(dns_qp_insert(qp, &values[i], i),
				 ISC_R_SUCCESS);
	}
	dns_qpmulti_commit(multi, &qp);

	concurrent_readers_t ctx = { .multi = multi, .values = values };
	isc_thread_t threads[2];
	for (unsigned int i = 0; i < ARRAY_SIZE(threads); i++) {
		isc_thread_create(read_versions, &ctx, &threads[i]);
	}
	while (atomic_load_acquire(&ctx.started) != ARRAY_SIZE(threads)) {
		isc_thread_yield();
	}
	for (unsigned int round = 0; round < 256; round++) {
		uint32_t old = round % 2 == 0 ? 0 : 64;
		uint32_t next = 64 - old;
		if (round % 7 == 0) {
			dns_qpmulti_update(multi, &qp);
			lifetime_delete(qp, old, old + 64);
			dns_qpmulti_rollback(multi, &qp);
		}
		bool update = round % 4 == 0;
		if (update) {
			dns_qpmulti_update(multi, &qp);
		} else {
			dns_qpmulti_write(multi, &qp);
		}
		lifetime_delete(qp, old, old + 64);
		for (uint32_t i = next; i < next + 64; i++) {
			assert_int_equal(dns_qp_insert(qp, &values[i], i),
					 ISC_R_SUCCESS);
		}
		if (round % 8 == 0) {
			dns_qp_compact(qp, DNS_QPGC_ALL);
		}
		dns_qpmulti_commit(multi, &qp);
		rcu_quiescent_state();
		isc_thread_yield();
	}
	atomic_store_release(&ctx.stop, true);
	rcu_thread_offline();
	for (unsigned int i = 0; i < ARRAY_SIZE(threads); i++) {
		isc_thread_join(threads[i], NULL);
	}
	rcu_thread_online();
	assert_true(atomic_load_relaxed(&ctx.reads) >= ARRAY_SIZE(threads));
	dns_qpmulti_destroy(&multi);
	drain_versions();
	for (uint32_t i = 0; i < ARRAY_SIZE(values); i++) {
		assert_int_equal(atomic_load_relaxed(&values[i].references), 0);
	}
}

ISC_TEST_LIST_START
ISC_TEST_ENTRY(qpmulti)
ISC_TEST_ENTRY(qpmulti_memusage)
ISC_TEST_ENTRY(qpmulti_versions)
ISC_TEST_ENTRY(qpmulti_clone_rollback)
ISC_TEST_ENTRY(qpmulti_base_metadata)
ISC_TEST_ENTRY(qpmulti_reclaim_without_mutex)
ISC_TEST_ENTRY(qpmulti_concurrent_versions)
ISC_TEST_LIST_END

ISC_TEST_MAIN
