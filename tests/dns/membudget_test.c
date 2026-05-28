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
#include <stdint.h>
#include <stdlib.h>

#define UNIT_TESTING
#include <cmocka.h>

#include <isc/lib.h>
#include <isc/mem.h>
#include <isc/util.h>

#include <dns/lib.h>
#include <dns/membudget.h>

#include <tests/isc.h>

#define BUDGET_MAX (8U * 1024 * 1024) /* 8 MiB */

/*
 * Allocate `bytes` from `mctx` and return the chunk so the caller can free
 * it.  We hold real allocations so isc_mem_inuse() reflects the test setup.
 */
static void *
hold(isc_mem_t *mctx, size_t bytes) {
	return isc_mem_allocate(mctx, bytes);
}

ISC_RUN_TEST_IMPL(below_lo_returns_zero) {
	isc_mem_t *m_a = NULL, *m_b = NULL, *m_c = NULL;
	dns_membudget_t *budget = NULL;
	dns_membudget_tenant_t t_a = { 0 }, t_b = { 0 }, t_c = { 0 };

	isc_mem_create("ta", &m_a);
	isc_mem_create("tb", &m_b);
	isc_mem_create("tc", &m_c);

	dns_membudget_create(isc_g_mctx, BUDGET_MAX, &budget);
	dns_membudget_register(budget, &t_a, "a", m_a);
	dns_membudget_register(budget, &t_b, "b", m_b);
	dns_membudget_register(budget, &t_c, "c", m_c);

	/* Each holds 1 MiB; global = 3 MiB, far below 75% of 8 MiB. */
	void *a = hold(m_a, 1 << 20);
	void *b = hold(m_b, 1 << 20);
	void *c = hold(m_c, 1 << 20);

	assert_int_equal(dns_membudget_cleaning_prob(&t_a, 0), 0);
	assert_int_equal(dns_membudget_cleaning_prob(&t_b, 0), 0);
	assert_int_equal(dns_membudget_cleaning_prob(&t_c, 0), 0);
	assert_int_equal(dns_membudget_tenant_count(budget), 3);
	assert_int_equal(dns_membudget_max(budget), BUDGET_MAX);

	isc_mem_free(m_a, a);
	isc_mem_free(m_b, b);
	isc_mem_free(m_c, c);

	dns_membudget_unregister(&t_a);
	dns_membudget_unregister(&t_b);
	dns_membudget_unregister(&t_c);
	dns_membudget_detach(&budget);
	isc_mem_detach(&m_a);
	isc_mem_detach(&m_b);
	isc_mem_detach(&m_c);
}

ISC_RUN_TEST_IMPL(equal_share_scales_to_global) {
	isc_mem_t *m_a = NULL, *m_b = NULL, *m_c = NULL;
	dns_membudget_t *budget = NULL;
	dns_membudget_tenant_t t_a = { 0 }, t_b = { 0 }, t_c = { 0 };

	isc_mem_create("ta", &m_a);
	isc_mem_create("tb", &m_b);
	isc_mem_create("tc", &m_c);

	dns_membudget_create(isc_g_mctx, BUDGET_MAX, &budget);
	dns_membudget_register(budget, &t_a, "a", m_a);
	dns_membudget_register(budget, &t_b, "b", m_b);
	dns_membudget_register(budget, &t_c, "c", m_c);

	/*
	 * Each tenant holds ~2.2 MiB; global = ~6.6 MiB, mid-ramp
	 * (75%-87.5% of 8 MiB = 6.0-7.0 MiB).  Equal shares mean each
	 * tenant's prob should equal the global prob.
	 */
	void *a = hold(m_a, (size_t)(2.2 * (1 << 20)));
	void *b = hold(m_b, (size_t)(2.2 * (1 << 20)));
	void *c = hold(m_c, (size_t)(2.2 * (1 << 20)));

	uint8_t pa = dns_membudget_cleaning_prob(&t_a, 0);
	uint8_t pb = dns_membudget_cleaning_prob(&t_b, 0);
	uint8_t pc = dns_membudget_cleaning_prob(&t_c, 0);

	assert_true(pa > 0);
	assert_true(pb > 0);
	assert_true(pc > 0);
	/* Equal shares give probs within a few units of each other. */
	int diff_ab = (int)pa - (int)pb;
	int diff_ac = (int)pa - (int)pc;
	assert_in_range(diff_ab + 32, 0, 64);
	assert_in_range(diff_ac + 32, 0, 64);

	isc_mem_free(m_a, a);
	isc_mem_free(m_b, b);
	isc_mem_free(m_c, c);

	dns_membudget_unregister(&t_a);
	dns_membudget_unregister(&t_b);
	dns_membudget_unregister(&t_c);
	dns_membudget_detach(&budget);
	isc_mem_detach(&m_a);
	isc_mem_detach(&m_b);
	isc_mem_detach(&m_c);
}

ISC_RUN_TEST_IMPL(asymmetric_share_cleans_biggest_hardest) {
	isc_mem_t *m_a = NULL, *m_b = NULL, *m_c = NULL;
	dns_membudget_t *budget = NULL;
	dns_membudget_tenant_t t_a = { 0 }, t_b = { 0 }, t_c = { 0 };

	isc_mem_create("ta", &m_a);
	isc_mem_create("tb", &m_b);
	isc_mem_create("tc", &m_c);

	dns_membudget_create(isc_g_mctx, BUDGET_MAX, &budget);
	dns_membudget_register(budget, &t_a, "a", m_a);
	dns_membudget_register(budget, &t_b, "b", m_b);
	dns_membudget_register(budget, &t_c, "c", m_c);

	/*
	 * a holds 5 MiB, b and c hold 0.75 MiB each; global 6.5 MiB,
	 * inside the ramp.  a's prob must dominate.
	 */
	void *a = hold(m_a, (size_t)(5 * (1 << 20)));
	void *b = hold(m_b, (size_t)((1 << 20) / 2 + (1 << 18)));
	void *c = hold(m_c, (size_t)((1 << 20) / 2 + (1 << 18)));

	uint8_t pa = dns_membudget_cleaning_prob(&t_a, 0);
	uint8_t pb = dns_membudget_cleaning_prob(&t_b, 0);
	uint8_t pc = dns_membudget_cleaning_prob(&t_c, 0);

	assert_true(pa > pb);
	assert_true(pa > pc);

	isc_mem_free(m_a, a);
	isc_mem_free(m_b, b);
	isc_mem_free(m_c, c);

	dns_membudget_unregister(&t_a);
	dns_membudget_unregister(&t_b);
	dns_membudget_unregister(&t_c);
	dns_membudget_detach(&budget);
	isc_mem_detach(&m_a);
	isc_mem_detach(&m_b);
	isc_mem_detach(&m_c);
}

ISC_RUN_TEST_IMPL(empty_tenant_does_not_clean) {
	isc_mem_t *m_a = NULL, *m_b = NULL;
	dns_membudget_t *budget = NULL;
	dns_membudget_tenant_t t_a = { 0 }, t_b = { 0 };

	isc_mem_create("ta", &m_a);
	isc_mem_create("tb", &m_b);

	dns_membudget_create(isc_g_mctx, BUDGET_MAX, &budget);
	dns_membudget_register(budget, &t_a, "a", m_a);
	dns_membudget_register(budget, &t_b, "b", m_b);

	/* a holds the whole pool; b is empty. */
	void *a = hold(m_a, BUDGET_MAX);
	uint8_t pa = dns_membudget_cleaning_prob(&t_a, 0);
	uint8_t pb = dns_membudget_cleaning_prob(&t_b, 0);

	assert_int_equal(pa, 255);
	assert_int_equal(pb, 0);

	isc_mem_free(m_a, a);
	dns_membudget_unregister(&t_a);
	dns_membudget_unregister(&t_b);
	dns_membudget_detach(&budget);
	isc_mem_detach(&m_a);
	isc_mem_detach(&m_b);
}

ISC_RUN_TEST_IMPL(resize_updates_ramp) {
	isc_mem_t *m_a = NULL;
	dns_membudget_t *budget = NULL;
	dns_membudget_tenant_t t_a = { 0 };

	isc_mem_create("ta", &m_a);

	dns_membudget_create(isc_g_mctx, BUDGET_MAX, &budget);
	dns_membudget_register(budget, &t_a, "a", m_a);

	void *a = hold(m_a, 4U * 1024 * 1024); /* 4 MiB */

	/* 4 MiB / 8 MiB = 50%; below ramp lo (75%). */
	assert_int_equal(dns_membudget_cleaning_prob(&t_a, 0), 0);

	/* Resize down so 4 MiB is now over the ramp's hi. */
	dns_membudget_resize(budget, 4U * 1024 * 1024);
	assert_int_equal(dns_membudget_max(budget), 4U * 1024 * 1024);
	assert_int_equal(dns_membudget_cleaning_prob(&t_a, 0), 255);

	/* Resize back up: pressure should drop. */
	dns_membudget_resize(budget, BUDGET_MAX);
	assert_int_equal(dns_membudget_cleaning_prob(&t_a, 0), 0);

	isc_mem_free(m_a, a);
	dns_membudget_unregister(&t_a);
	dns_membudget_detach(&budget);
	isc_mem_detach(&m_a);
}

ISC_TEST_LIST_START
ISC_TEST_ENTRY(below_lo_returns_zero)
ISC_TEST_ENTRY(equal_share_scales_to_global)
ISC_TEST_ENTRY(asymmetric_share_cleans_biggest_hardest)
ISC_TEST_ENTRY(empty_tenant_does_not_clean)
ISC_TEST_ENTRY(resize_updates_ramp)
ISC_TEST_LIST_END

ISC_TEST_MAIN
