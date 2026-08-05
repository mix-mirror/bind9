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

#include <stdbool.h>
#include <string.h>

#include <isc/bit.h>
#include <isc/loop.h>
#include <isc/magic.h>
#include <isc/mem.h>
#include <isc/memarena.h>
#include <isc/os.h>
#include <isc/overflow.h>
#include <isc/tid.h>
#include <isc/util.h>

#include "memarena_p.h"

#if __SANITIZE_ADDRESS__
#include <sanitizer/asan_interface.h>
#define MEMARENA_POISON(p, s)	ASAN_POISON_MEMORY_REGION((p), (s))
#define MEMARENA_UNPOISON(p, s) ASAN_UNPOISON_MEMORY_REGION((p), (s))
#else
#define MEMARENA_POISON(p, s)
#define MEMARENA_UNPOISON(p, s)
#endif

#if ISC_MEM_TRACKLINES
#define FLARG_PASS , func, file, line
#define FLARG	   , const char *func, const char *file, unsigned int line
#define FLARG_IGNORE  \
	UNUSED(func); \
	UNUSED(file); \
	UNUSED(line)
#else /* if ISC_MEM_TRACKLINES */
#define FLARG_PASS
#define FLARG
#define FLARG_IGNORE
#endif /* if ISC_MEM_TRACKLINES */

/*
 * Mirrors the same rule in mem.c: zero-sized allocations are rounded up
 * so that every allocation has a distinct, poisonable address range.
 */
#define ZERO_ALLOCATION_SIZE sizeof(void *)
#define ADJUST_ZERO_ALLOCATION_SIZE(s)    \
	if (s == 0) {                     \
		s = ZERO_ALLOCATION_SIZE; \
	}

/*
 * Chunk totals are powers of two so they map onto jemalloc size classes;
 * the usable capacity is the total minus the (alignment-rounded) header.
 * Requests too large for ISC_MEMARENA_MAX_CHUNK get a dedicated,
 * exactly-sized chunk that is never retained across a reset.
 */
#define MEMARENA_MIN_CHUNK 2048
#define MEMARENA_MAX_CHUNK 65536

/*
 * Weight of one cycle in the usage moving average: 1/8.
 */
#define MEMARENA_EWMA_SHIFT 3

/*
 * Single-writer updates of the statistics counters: a relaxed
 * load-modify-store is race-free because only the owning thread writes,
 * and it compiles to plain memory accesses; cross-thread readers
 * (isc_mem_stats()) see a best-effort snapshot.
 */
#define COUNTER_ADD(c, delta) \
	atomic_store_relaxed(&(c), atomic_load_relaxed(&(c)) + (delta))
#define COUNTER_SUB(c, delta) \
	atomic_store_relaxed(&(c), atomic_load_relaxed(&(c)) - (delta))

/*
 * Per-thread cache of warm arenas.  Each slot is only ever touched by
 * its owning thread while the loops are running; the flush hooks run
 * single-threaded during shutdown after the loop threads have been
 * joined.  With every cached arena retaining at most one
 * MEMARENA_MAX_CHUNK chunk, a full slot holds about 4 MiB.
 */
#define MEMARENA_CACHE_MAX 64

typedef union {
	struct {
		isc_memarena_t *head;
		size_t count;
	};
	char padding[ISC_OS_CACHELINE_SIZE];
} memarena_cacheslot_t;

static memarena_cacheslot_t cacheslots[ISC_TID_MAX];

struct memarena_chunk {
	struct memarena_chunk *prev; /*%< older chunk, NULL for the oldest */
	size_t total;		     /*%< allocation size, for sized free */
	size_t used;		     /*%< committed bytes when sealed */
};

#define CHUNK_HDRSIZE \
	ISC_ALIGN(sizeof(memarena_chunk_t), ISC_MEMARENA_ALIGNMENT)
#define CHUNK_DATA(chunk)     ((uintptr_t)(chunk) + CHUNK_HDRSIZE)
#define CHUNK_CAPACITY(chunk) ((chunk)->total - CHUNK_HDRSIZE)

static void
chunk_free(isc_memarena_t *arena, memarena_chunk_t *chunk) {
	MEMARENA_UNPOISON((void *)CHUNK_DATA(chunk), CHUNK_CAPACITY(chunk));
	isc_mem_put(arena->mctx, chunk, chunk->total);
}

static void
chunk_free_chain(isc_memarena_t *arena, memarena_chunk_t *chunk) {
	while (chunk != NULL) {
		memarena_chunk_t *prev = chunk->prev;

		chunk_free(arena, chunk);
		chunk = prev;
	}
}

static size_t
pow2_ceil(size_t value) {
	if ((value & (value - 1)) == 0) {
		return value;
	}
	return (size_t)1
	       << (sizeof(size_t) * CHAR_BIT - stdc_leading_zeros(value));
}

/*
 * Seal the current chunk (if any), allocate a new one large enough for
 * 'size' bytes, and make it current.
 */
static void
memarena_grow(isc_memarena_t *arena, size_t size) {
	memarena_chunk_t *chunk = NULL;
	size_t total;

	if (arena->current != NULL) {
		arena->current->used = arena->pos - CHUNK_DATA(arena->current);
		COUNTER_ADD(arena->used_sealed, arena->current->used);
		COUNTER_ADD(arena->waste, arena->end - arena->pos);
	}

	if (size > MEMARENA_MAX_CHUNK - CHUNK_HDRSIZE) {
		/* Oversize request: dedicated, exactly-sized chunk. */
		total = ISC_CHECKED_ADD(CHUNK_HDRSIZE, size);
	} else {
		total = arena->next_chunk;
		while (total - CHUNK_HDRSIZE < size) {
			total <<= 1;
		}
		arena->next_chunk = ISC_MIN(total << 1, MEMARENA_MAX_CHUNK);
	}

	chunk = isc_mem_get(arena->mctx, total);
	*chunk = (memarena_chunk_t){
		.prev = arena->current,
		.total = total,
	};

	arena->current = chunk;
	COUNTER_ADD(arena->nchunks, 1);
	COUNTER_ADD(arena->capacity, total - CHUNK_HDRSIZE);
	arena->pos = CHUNK_DATA(chunk);
	arena->end = arena->pos + (total - CHUNK_HDRSIZE);
	MEMARENA_POISON((void *)arena->pos, arena->end - arena->pos);
}

void *
isc__memarena_get(isc_memarena_t *arena, size_t size, int flags FLARG) {
	uintptr_t ptr;

	REQUIRE(VALID_MEMARENA(arena));

	FLARG_IGNORE;

	ADJUST_ZERO_ALLOCATION_SIZE(size);

	ptr = ISC_ALIGN(arena->pos, ISC_MEMARENA_ALIGNMENT);
	if (ptr > arena->end || size > (size_t)(arena->end - ptr)) {
		memarena_grow(arena, size);
		ptr = arena->pos;
	} else {
		COUNTER_ADD(arena->waste, ptr - arena->pos);
	}

	arena->pos = ptr + size;
	COUNTER_ADD(arena->live, size);

	MEMARENA_UNPOISON((void *)ptr, size);
	if ((flags & ISC__MEM_ZERO) != 0) {
		memset((void *)ptr, 0, size);
	}

	return (void *)ptr;
}

void
isc__memarena_put(isc_memarena_t *arena, void *ptr, size_t size,
		  int flags FLARG) {
	REQUIRE(VALID_MEMARENA(arena));
	REQUIRE(ptr != NULL);
	UNUSED(flags);

	FLARG_IGNORE;

	ADJUST_ZERO_ALLOCATION_SIZE(size);

	REQUIRE(atomic_load_relaxed(&arena->live) >= size);
	COUNTER_SUB(arena->live, size);
	COUNTER_ADD(arena->dead, size);

	MEMARENA_POISON(ptr, size);
}

/*
 * True iff [p, p + size) is the most recent live allocation: it must lie
 * in the current chunk and end exactly at the bump cursor.  Containment
 * must be checked first: the one-past-end of an allocation in an OLDER
 * chunk may legally compare equal to the cursor if the chunks happen to
 * be adjacent in memory.
 */
static bool
memarena_is_top(isc_memarena_t *arena, uintptr_t p, size_t size) {
	return arena->current != NULL && p >= CHUNK_DATA(arena->current) &&
	       p < arena->end && p + size == arena->pos;
}

void
isc__memarena_shrink(isc_memarena_t *arena, void *ptr, size_t old_size,
		     size_t new_size FLARG) {
	uintptr_t p = (uintptr_t)ptr;
	size_t delta;

	REQUIRE(VALID_MEMARENA(arena));
	REQUIRE(ptr != NULL);
	REQUIRE(new_size <= old_size);

	FLARG_IGNORE;

	ADJUST_ZERO_ALLOCATION_SIZE(old_size);

	delta = old_size - new_size;
	if (delta == 0) {
		return;
	}

	REQUIRE(atomic_load_relaxed(&arena->live) >= delta);
	COUNTER_SUB(arena->live, delta);

	if (memarena_is_top(arena, p, old_size)) {
		/* Most recent allocation: exact bump-pointer rollback. */
		arena->pos = p + new_size;
		MEMARENA_POISON((void *)arena->pos, delta);
	} else {
		COUNTER_ADD(arena->dead, delta);
		MEMARENA_POISON((uint8_t *)ptr + new_size, delta);
	}
}

void *
isc__memarena_reget(isc_memarena_t *arena, void *old_ptr, size_t old_size,
		    size_t new_size, int flags FLARG) {
	void *new_ptr = NULL;
	uintptr_t p = (uintptr_t)old_ptr;

	REQUIRE(VALID_MEMARENA(arena));

	if (old_ptr == NULL) {
		REQUIRE(old_size == 0);
		return isc__memarena_get(arena, new_size, flags FLARG_PASS);
	}
	if (new_size == 0) {
		isc__memarena_put(arena, old_ptr, old_size, flags FLARG_PASS);
		return NULL;
	}
	if (new_size <= old_size) {
		isc__memarena_shrink(arena, old_ptr, old_size,
				     new_size FLARG_PASS);
		return old_ptr;
	}

	if (memarena_is_top(arena, p, old_size) &&
	    new_size <= (size_t)(arena->end - p))
	{
		/* Most recent allocation: grow in place. */
		arena->pos = p + new_size;
		COUNTER_ADD(arena->live, new_size - old_size);
		MEMARENA_UNPOISON((uint8_t *)old_ptr + old_size,
				  new_size - old_size);
		if ((flags & ISC__MEM_ZERO) != 0) {
			memset((uint8_t *)old_ptr + old_size, 0,
			       new_size - old_size);
		}
		return old_ptr;
	}

	new_ptr = isc__memarena_get(arena, new_size,
				    flags & ~ISC__MEM_ZERO FLARG_PASS);
	memmove(new_ptr, old_ptr, old_size);
	if ((flags & ISC__MEM_ZERO) != 0) {
		memset((uint8_t *)new_ptr + old_size, 0, new_size - old_size);
	}
	isc__memarena_put(arena, old_ptr, old_size, flags FLARG_PASS);

	return new_ptr;
}

void
isc_memarena_create(isc_mem_t *mctx, const char *name,
		    isc_memarena_t **arenap) {
	isc_memarena_t *arena = NULL;

	REQUIRE(arenap != NULL && *arenap == NULL);

	arena = isc_mem_get(mctx, sizeof(*arena));
	*arena = (isc_memarena_t){
		.tid = isc_tid(),
		.next_chunk = MEMARENA_MIN_CHUNK,
		.link = ISC_LINK_INITIALIZER,
	};
	isc_mem_attach(mctx, &arena->mctx);
	if (name != NULL) {
		arena->name = isc_mem_strdup(arena->mctx, name);
	}
	arena->magic = MEMARENA_MAGIC;

	isc__mem_registerarena(arena->mctx, arena);

	*arenap = arena;
}

void
isc_memarena_destroy(isc_memarena_t **arenap) {
	isc_memarena_t *arena = NULL;

	REQUIRE(arenap != NULL);
	REQUIRE(VALID_MEMARENA(*arenap));

	arena = *arenap;
	*arenap = NULL;

	arena->magic = 0;

	isc__mem_unregisterarena(arena->mctx, arena);

	chunk_free_chain(arena, arena->current);
	if (arena->name != NULL) {
		isc_mem_free(arena->mctx, arena->name);
	}
	isc_mem_putanddetach(&arena->mctx, arena, sizeof(*arena));
}

void
isc_memarena_reset(isc_memarena_t *arena) {
	memarena_chunk_t *keep = NULL;
	memarena_chunk_t *chunk = NULL;
	size_t cycle_used, target;

	REQUIRE(VALID_MEMARENA(arena));

	cycle_used = isc_memarena_used(arena);

	/*
	 * An exponentially weighted moving average of the per-cycle usage
	 * drives the retention target, so the warm capacity follows the
	 * recent workload both up and down.
	 */
	if (arena->usage_ewma == 0) {
		arena->usage_ewma = cycle_used;
	} else {
		arena->usage_ewma -= arena->usage_ewma >> MEMARENA_EWMA_SHIFT;
		arena->usage_ewma += cycle_used >> MEMARENA_EWMA_SHIFT;
	}

	/*
	 * The retained chunk is compared by its total allocation size,
	 * so the target must cover the usable bytes plus the chunk
	 * header; otherwise a workload just under a power of two would
	 * free and reallocate its chunk on every cycle.
	 */
	target = ISC_CLAMP(pow2_ceil(arena->usage_ewma + CHUNK_HDRSIZE),
			   MEMARENA_MIN_CHUNK, MEMARENA_MAX_CHUNK);
#if __SANITIZE_ADDRESS__
	/*
	 * Retention is disabled so that every cycle gets fresh, fully
	 * poisonable chunks; this mirrors the mempool behavior under
	 * AddressSanitizer.
	 */
	target = 0;
#endif

	/*
	 * Keep exactly one chunk warm for the next cycle: the newest one
	 * not exceeding the target.  Chunks are newest-first and, with
	 * geometric growth, mostly biggest-first, so this is the best fit;
	 * dedicated oversize chunks are always freed.
	 */
	chunk = arena->current;
	while (chunk != NULL) {
		memarena_chunk_t *prev = chunk->prev;

		if (keep == NULL && chunk->total <= target) {
			keep = chunk;
		} else {
			chunk_free(arena, chunk);
		}
		chunk = prev;
	}

	if (keep != NULL) {
		keep->prev = NULL;
		keep->used = 0;

		arena->current = keep;
		atomic_store_relaxed(&arena->nchunks, 1);
		atomic_store_relaxed(&arena->capacity, CHUNK_CAPACITY(keep));
		arena->pos = CHUNK_DATA(keep);
		arena->end = arena->pos + CHUNK_CAPACITY(keep);
		MEMARENA_POISON((void *)arena->pos, CHUNK_CAPACITY(keep));
	} else {
		arena->current = NULL;
		atomic_store_relaxed(&arena->nchunks, 0);
		atomic_store_relaxed(&arena->capacity, 0);
		arena->pos = 0;
		arena->end = 0;
	}

	/*
	 * Start the next cycle's chunk sizing from the target so a reused
	 * arena reaches its steady-state chunk in one allocation.
	 */
	arena->next_chunk = ISC_MAX(target, MEMARENA_MIN_CHUNK);

	atomic_store_relaxed(&arena->live, 0);
	atomic_store_relaxed(&arena->dead, 0);
	atomic_store_relaxed(&arena->waste, 0);
	atomic_store_relaxed(&arena->used_sealed, 0);
}

size_t
isc_memarena_live(isc_memarena_t *arena) {
	REQUIRE(VALID_MEMARENA(arena));

	return atomic_load_relaxed(&arena->live);
}

size_t
isc_memarena_dead(isc_memarena_t *arena) {
	REQUIRE(VALID_MEMARENA(arena));

	return atomic_load_relaxed(&arena->dead);
}

size_t
isc_memarena_used(isc_memarena_t *arena) {
	REQUIRE(VALID_MEMARENA(arena));

	if (arena->current == NULL) {
		return atomic_load_relaxed(&arena->used_sealed);
	}
	return atomic_load_relaxed(&arena->used_sealed) +
	       (arena->pos - CHUNK_DATA(arena->current));
}

size_t
isc_memarena_capacity(isc_memarena_t *arena) {
	REQUIRE(VALID_MEMARENA(arena));

	return atomic_load_relaxed(&arena->capacity);
}

void
isc_memarena_getcached(isc_mem_t *fallback_mctx, const char *name,
		       isc_memarena_t **arenap) {
	isc_tid_t tid = isc_tid();
	memarena_cacheslot_t *slot = NULL;

	REQUIRE(arenap != NULL && *arenap == NULL);

	/*
	 * A valid tid alone does not imply a live loop: the thread-local
	 * tid outlives the loop manager, but isc_loop() is reset to NULL
	 * as soon as the loop stops running.
	 */
	if (tid == ISC_TID_UNKNOWN || isc_loop() == NULL) {
		/* Thread without a running loop: degrade to a plain arena. */
		isc_memarena_create(fallback_mctx, name, arenap);
		return;
	}

	slot = &cacheslots[tid];
	if (slot->head != NULL) {
		isc_memarena_t *arena = slot->head;

		slot->head = arena->cache_next;
		slot->count--;
		arena->cache_next = NULL;
		arena->tid = tid;

		*arenap = arena;
		return;
	}

	isc_memarena_create(isc_loop_getmctx(isc_loop()), name, arenap);
}

void
isc_memarena_putcached(isc_memarena_t **arenap) {
	isc_tid_t tid = isc_tid();
	isc_memarena_t *arena = NULL;
	bool cache;

	REQUIRE(arenap != NULL);
	REQUIRE(VALID_MEMARENA(*arenap));

	arena = *arenap;
	*arenap = NULL;

	isc_memarena_reset(arena);

#if __SANITIZE_ADDRESS__
	/* No pooling under ASan, mirroring isc_mempool. */
	cache = false;
#else
	cache = (tid != ISC_TID_UNKNOWN && isc_loop() != NULL &&
		 cacheslots[tid].count < MEMARENA_CACHE_MAX);
#endif
	if (!cache) {
		isc_memarena_destroy(&arena);
		return;
	}

	arena->tid = tid;
	arena->cache_next = cacheslots[tid].head;
	cacheslots[tid].head = arena;
	cacheslots[tid].count++;
}

void
isc__memarena_cache_flush(isc_tid_t tid) {
	memarena_cacheslot_t *slot = NULL;

	if (tid == ISC_TID_UNKNOWN) {
		return;
	}

	slot = &cacheslots[tid];
	while (slot->head != NULL) {
		isc_memarena_t *arena = slot->head;

		slot->head = arena->cache_next;
		slot->count--;
		isc_memarena_destroy(&arena);
	}
	INSIST(slot->count == 0);
}

void
isc__memarena_cache_flushall(void) {
	for (isc_tid_t tid = 0; tid < ISC_TID_MAX; tid++) {
		isc__memarena_cache_flush(tid);
	}
}
