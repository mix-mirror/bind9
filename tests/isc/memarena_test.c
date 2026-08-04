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
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#define UNIT_TESTING
#include <cmocka.h>

#include <isc/buffer.h>
#include <isc/lib.h>
#include <isc/loop.h>
#include <isc/mem.h>
#include <isc/memarena.h>
#include <isc/tid.h>
#include <isc/util.h>

#include <tests/isc.h>

/*
 * The isc_mem_get()/isc_mem_put() macros accept an arena only once the
 * transparent-union dispatch is in place; until then (and for direct
 * coverage of the native entry points) call them explicitly.
 */
#define arena_get(a, s) isc__memarena_get((a), (s), 0 _ISC_MEM_FILELINE)
#define arena_zget(a, s) \
	isc__memarena_get((a), (s), ISC__MEM_ZERO _ISC_MEM_FILELINE)
#define arena_put(a, p, s) isc__memarena_put((a), (p), (s), 0 _ISC_MEM_FILELINE)
#define arena_reget(a, p, o, n) \
	isc__memarena_reget((a), (p), (o), (n), 0 _ISC_MEM_FILELINE)
#define arena_zreget(a, p, o, n) \
	isc__memarena_reget((a), (p), (o), (n), ISC__MEM_ZERO _ISC_MEM_FILELINE)

ISC_RUN_TEST_IMPL(isc_memarena_basic) {
	isc_mem_t *mctx = NULL;
	isc_memarena_t *arena = NULL;
	void *ptr = NULL;

	isc_mem_create("memarena_basic", &mctx);

	isc_memarena_create(mctx, "test", &arena);

	/* Chunk allocation is lazy. */
	assert_int_equal(isc_memarena_capacity(arena), 0);
	assert_int_equal(isc_memarena_live(arena), 0);
	assert_int_equal(isc_memarena_used(arena), 0);

	ptr = arena_get(arena, 100);
	assert_non_null(ptr);
	memset(ptr, 0xa5, 100);
	assert_int_equal(isc_memarena_live(arena), 100);
	assert_true(isc_memarena_capacity(arena) >= 100);

	arena_put(arena, ptr, 100);
	assert_int_equal(isc_memarena_live(arena), 0);
	assert_int_equal(isc_memarena_dead(arena), 100);

	isc_memarena_destroy(&arena);
	assert_null(arena);

	/* The final detach asserts that nothing leaked from mctx. */
	isc_mem_detach(&mctx);
}

ISC_RUN_TEST_IMPL(isc_memarena_alignment) {
	isc_mem_t *mctx = NULL;
	isc_memarena_t *arena = NULL;

	isc_mem_create("memarena_alignment", &mctx);
	isc_memarena_create(mctx, "test", &arena);

	for (size_t size = 1; size <= 100; size++) {
		uint8_t *ptr = arena_get(arena, size);

		assert_non_null(ptr);
		assert_int_equal((uintptr_t)ptr % ISC_MEMARENA_ALIGNMENT, 0);
		memset(ptr, (int)size, size);
	}

	isc_memarena_destroy(&arena);
	isc_mem_detach(&mctx);
}

ISC_RUN_TEST_IMPL(isc_memarena_zero) {
	isc_mem_t *mctx = NULL;
	isc_memarena_t *arena = NULL;
	uint8_t *ptr = NULL;

	isc_mem_create("memarena_zero", &mctx);
	isc_memarena_create(mctx, "test", &arena);

	/* Zero-sized get/put must be symmetric. */
	ptr = arena_get(arena, 0);
	assert_non_null(ptr);
	arena_put(arena, ptr, 0);
	assert_int_equal(isc_memarena_live(arena), 0);

	/* ISC__MEM_ZERO must return zeroed memory. */
	ptr = arena_zget(arena, 512);
	for (size_t i = 0; i < 512; i++) {
		assert_int_equal(ptr[i], 0);
	}

	isc_memarena_destroy(&arena);
	isc_mem_detach(&mctx);
}

/*
 * Address stability: every allocation keeps its content across arbitrary
 * later allocations, including chunk rollovers and one oversize chunk.
 */
ISC_RUN_TEST_IMPL(isc_memarena_growth) {
	isc_mem_t *mctx = NULL;
	isc_memarena_t *arena = NULL;
	enum { NPTRS = 2048 };
	static uint8_t *ptrs[NPTRS];
	static size_t sizes[NPTRS];

	isc_mem_create("memarena_growth", &mctx);
	isc_memarena_create(mctx, "test", &arena);

	for (size_t i = 0; i < NPTRS; i++) {
		/* Mixed sizes, one oversize allocation in the middle. */
		sizes[i] = (i == NPTRS / 2) ? 100 * 1024 : (i % 200) + 1;
		ptrs[i] = arena_get(arena, sizes[i]);
		assert_non_null(ptrs[i]);
		memset(ptrs[i], (int)(i & 0xff), sizes[i]);
	}

	for (size_t i = 0; i < NPTRS; i++) {
		for (size_t j = 0; j < sizes[i]; j++) {
			assert_int_equal(ptrs[i][j], (uint8_t)(i & 0xff));
		}
	}

	assert_true(isc_memarena_live(arena) > 0);
	assert_true(isc_memarena_capacity(arena) >= isc_memarena_used(arena));

	/* Destroy with everything still live: leak-until-reset model. */
	isc_memarena_destroy(&arena);
	isc_mem_detach(&mctx);
}

ISC_RUN_TEST_IMPL(isc_memarena_shrink) {
	isc_mem_t *mctx = NULL;
	isc_memarena_t *arena = NULL;
	uint8_t *a = NULL, *b = NULL, *c = NULL;
	size_t used;

	isc_mem_create("memarena_shrink", &mctx);
	isc_memarena_create(mctx, "test", &arena);

	/*
	 * Shrinking the most recent allocation must roll the bump pointer
	 * back so the next allocation reuses the reclaimed space.
	 */
	a = arena_get(arena, 255);
	memset(a, 0xaa, 13);
	isc_memarena_shrink(arena, a, 255, 13);
	assert_int_equal(isc_memarena_live(arena), 13);

	used = isc_memarena_used(arena);
	b = arena_get(arena, 16);
	assert_true(b > a);
	assert_true((size_t)(b - a) <= 2 * ISC_MEMARENA_ALIGNMENT);
	assert_true(isc_memarena_used(arena) <=
		    used + 2 * ISC_MEMARENA_ALIGNMENT + 16);

	/*
	 * LIFO composition: a full rollback of the newest allocation makes
	 * the one before it the newest again.
	 */
	c = arena_get(arena, 64);
	isc_memarena_shrink(arena, c, 64, 0);
	isc_memarena_shrink(arena, b, 16, 8);
	assert_int_equal(isc_memarena_live(arena), 13 + 8);
	assert_int_equal(isc_memarena_dead(arena), 0);

	/*
	 * Shrinking an older allocation only marks the tail dead.
	 */
	c = arena_get(arena, 64);
	UNUSED(c);
	isc_memarena_shrink(arena, a, 13, 3);
	assert_int_equal(isc_memarena_dead(arena), 10);
	assert_int_equal(isc_memarena_live(arena), 3 + 8 + 64);

	isc_memarena_destroy(&arena);
	isc_mem_detach(&mctx);
}

ISC_RUN_TEST_IMPL(isc_memarena_reget) {
	isc_mem_t *mctx = NULL;
	isc_memarena_t *arena = NULL;
	uint8_t *a = NULL, *b = NULL, *c = NULL;

	isc_mem_create("memarena_reget", &mctx);
	isc_memarena_create(mctx, "test", &arena);

	/* NULL/0 corner cases mirror isc_mem_reget(). */
	a = arena_reget(arena, NULL, 0, 32);
	assert_non_null(a);
	memset(a, 0x11, 32);

	/* Growing the most recent allocation happens in place. */
	b = arena_reget(arena, a, 32, 200);
	assert_ptr_equal(a, b);
	for (size_t i = 0; i < 32; i++) {
		assert_int_equal(b[i], 0x11);
	}

	/* The grown part of a zeroing reget is zeroed. */
	b = arena_zreget(arena, b, 200, 300);
	assert_ptr_equal(a, b);
	for (size_t i = 200; i < 300; i++) {
		assert_int_equal(b[i], 0);
	}

	/* A non-top allocation relocates and copies. */
	c = arena_get(arena, 8);
	memset(c, 0x22, 8);
	b = arena_reget(arena, b, 300, 400);
	assert_ptr_not_equal(a, b);
	for (size_t i = 0; i < 32; i++) {
		assert_int_equal(b[i], 0x11);
	}
	assert_int_equal(isc_memarena_dead(arena), 300);

	/* Shrinking reget keeps the pointer. */
	c = arena_reget(arena, b, 400, 100);
	assert_ptr_equal(b, c);

	/* reget to zero size frees. */
	c = arena_reget(arena, c, 100, 0);
	assert_null(c);

	isc_memarena_destroy(&arena);
	isc_mem_detach(&mctx);
}

/*
 * The sized isc_mem_* macros must accept both handle kinds through the
 * transparent union and dispatch on the magic number.
 */
ISC_RUN_TEST_IMPL(isc_memarena_allocator_union) {
	isc_mem_t *mctx = NULL;
	isc_memarena_t *arena = NULL;
	uint8_t *ptr = NULL;

	isc_mem_create("memarena_union", &mctx);
	isc_memarena_create(mctx, "test", &arena);

	ptr = isc_mem_get(arena, 100);
	assert_non_null(ptr);
	memset(ptr, 0x5a, 100);
	isc_mem_put(arena, ptr, 100);
	assert_null(ptr);
	assert_int_equal(isc_memarena_dead(arena), 100);

	ptr = isc_mem_cget(arena, 4, 32);
	for (size_t i = 0; i < 4 * 32; i++) {
		assert_int_equal(ptr[i], 0);
	}
	ptr = isc_mem_reget(arena, ptr, 128, 256);
	assert_non_null(ptr);
	isc_mem_cput(arena, ptr, 8, 32);
	assert_null(ptr);
	assert_int_equal(isc_memarena_live(arena), 0);

	/* The same call sites keep working with a memory context. */
	ptr = isc_mem_get(mctx, 100);
	assert_non_null(ptr);
	isc_mem_put(mctx, ptr, 100);

	isc_memarena_destroy(&arena);
	isc_mem_detach(&mctx);
}

ISC_RUN_TEST_IMPL(isc_memarena_reset) {
	isc_mem_t *mctx = NULL;
	isc_memarena_t *arena = NULL;
	size_t inuse[10];

	isc_mem_create("memarena_reset", &mctx);
	isc_memarena_create(mctx, "test", &arena);

	for (size_t cycle = 0; cycle < 10; cycle++) {
		for (size_t i = 0; i < 64; i++) {
			uint8_t *ptr = arena_get(arena, 200);
			memset(ptr, (int)i, 200);
		}
		assert_true(isc_memarena_live(arena) > 0);

		isc_memarena_reset(arena);

		assert_int_equal(isc_memarena_live(arena), 0);
		assert_int_equal(isc_memarena_dead(arena), 0);
		assert_int_equal(isc_memarena_used(arena), 0);
#if __SANITIZE_ADDRESS__
		/* Under ASan nothing is retained. */
		assert_int_equal(isc_memarena_capacity(arena), 0);
#else
		/* At most one chunk stays warm. */
		assert_true(isc_memarena_capacity(arena) > 0);
#endif
		inuse[cycle] = isc_mem_inuse(mctx);
	}

	/* Retention must reach a steady state, not accrete. */
	for (size_t cycle = 3; cycle < 10; cycle++) {
		assert_int_equal(inuse[cycle], inuse[3]);
	}

	/* An arena must be reusable after reset. */
	for (size_t i = 0; i < 64; i++) {
		uint8_t *ptr = arena_get(arena, 200);
		memset(ptr, (int)i, 200);
	}

	isc_memarena_destroy(&arena);
	isc_mem_detach(&mctx);
}

/*
 * The retention target follows the workload: heavy cycles grow the warm
 * chunk, light cycles decay it.
 */
ISC_RUN_TEST_IMPL(isc_memarena_retention) {
	isc_mem_t *mctx = NULL;
	isc_memarena_t *arena = NULL;

	isc_mem_create("memarena_retention", &mctx);
	isc_memarena_create(mctx, "test", &arena);

	/* Heavy phase: ~25 KB per cycle. */
	for (size_t cycle = 0; cycle < 16; cycle++) {
		for (size_t i = 0; i < 120; i++) {
			(void)arena_get(arena, 200);
		}
		isc_memarena_reset(arena);
	}
#if __SANITIZE_ADDRESS__
	/* Retention is disabled under ASan. */
	assert_int_equal(isc_memarena_capacity(arena), 0);
#else
	/* The warm chunk converges to the power-of-two usage cover. */
	assert_true(isc_memarena_capacity(arena) >= 16 * 1024);
	assert_true(isc_memarena_capacity(arena) <= 64 * 1024);

	/* Light phase: the moving average decays the warm chunk. */
	for (size_t cycle = 0; cycle < 64; cycle++) {
		(void)arena_get(arena, 64);
		isc_memarena_reset(arena);
	}
	assert_true(isc_memarena_capacity(arena) <= 4096);
#endif

	/* The arena stays usable in either mode. */
	(void)arena_get(arena, 512);

	isc_memarena_destroy(&arena);
	isc_mem_detach(&mctx);
}

/*
 * The dns_message fromwire pattern: allocate an upper bound, parse into
 * a stack buffer over it (no attached mctx, so the base can never move),
 * then shrink to the actually-used length.
 */
ISC_RUN_TEST_IMPL(isc_memarena_buffer) {
	isc_mem_t *mctx = NULL;
	isc_memarena_t *arena = NULL;
	isc_buffer_t b;
	uint8_t *store = NULL;
	uint8_t *next = NULL;
	static const unsigned char data[] = "\x03isc\x03org";

	isc_mem_create("memarena_buffer", &mctx);
	isc_memarena_create(mctx, "test", &arena);

	store = arena_get(arena, 255);
	isc_buffer_init(&b, store, 255);
	isc_buffer_putmem(&b, data, sizeof(data));
	assert_ptr_equal(isc_buffer_base(&b), store);

	isc_memarena_shrink(arena, store, 255, isc_buffer_usedlength(&b));
	assert_int_equal(isc_memarena_live(arena), sizeof(data));

	/* The rolled-back tail is reused by the next allocation. */
	next = arena_get(arena, 16);
	assert_true((size_t)(next - store) <= 2 * ISC_MEMARENA_ALIGNMENT);
	assert_int_equal(memcmp(store, data, sizeof(data)), 0);

	isc_memarena_destroy(&arena);
	isc_mem_detach(&mctx);
}

/*
 * On a thread without a loop the cache degrades to plain create/destroy
 * backed by the fallback context.  This test must run before any loop
 * test: isc_loopmgr_run() permanently assigns a tid to the main thread.
 */
ISC_RUN_TEST_IMPL(isc_memarena_cache_noloop) {
	isc_mem_t *mctx = NULL;
	isc_memarena_t *arena = NULL;

	assert_int_equal(isc_tid(), ISC_TID_UNKNOWN);

	isc_mem_create("memarena_cache_noloop", &mctx);

	isc_memarena_getcached(mctx, "test", &arena);
	assert_non_null(arena);
	(void)arena_get(arena, 1000);
	isc_memarena_putcached(&arena);
	assert_null(arena);

	/* putcached also pairs with a plain create. */
	isc_memarena_create(mctx, "test", &arena);
	isc_memarena_putcached(&arena);

	isc_mem_detach(&mctx);
}

ISC_LOOP_TEST_IMPL(isc_memarena_cache) {
	isc_memarena_t *arena = NULL;
	isc_memarena_t *first = NULL;

	assert_true(isc_tid() != ISC_TID_UNKNOWN);

	isc_memarena_getcached(isc_g_mctx, "test", &arena);
	assert_non_null(arena);
	(void)arena_get(arena, 1000);

	first = arena;
	isc_memarena_putcached(&arena);
	assert_null(arena);

	isc_memarena_getcached(isc_g_mctx, "test", &arena);
#if !__SANITIZE_ADDRESS__
	/* Warm reuse: the same arena comes back from the cache. */
	assert_ptr_equal(arena, first);
#else
	UNUSED(first);
#endif
	isc_memarena_putcached(&arena);

	/* Loopmgr teardown flushes the cache (leak check in teardown). */
	isc_loopmgr_shutdown();
}

ISC_TEST_LIST_START

ISC_TEST_ENTRY(isc_memarena_cache_noloop)
ISC_TEST_ENTRY(isc_memarena_basic)
ISC_TEST_ENTRY(isc_memarena_alignment)
ISC_TEST_ENTRY(isc_memarena_zero)
ISC_TEST_ENTRY(isc_memarena_growth)
ISC_TEST_ENTRY(isc_memarena_shrink)
ISC_TEST_ENTRY(isc_memarena_reget)
ISC_TEST_ENTRY(isc_memarena_allocator_union)
ISC_TEST_ENTRY(isc_memarena_reset)
ISC_TEST_ENTRY(isc_memarena_retention)
ISC_TEST_ENTRY(isc_memarena_buffer)
ISC_TEST_ENTRY_CUSTOM(isc_memarena_cache, setup_loopmgr, teardown_loopmgr)

ISC_TEST_LIST_END

ISC_TEST_MAIN
