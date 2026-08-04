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

#include <isc/magic.h>
#include <isc/mem.h>
#include <isc/memarena.h>
#include <isc/tid.h>
#include <isc/util.h>

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

#define MEMARENA_MAGIC	  ISC_MAGIC('M', 'e', 'm', 'A')
#define VALID_MEMARENA(a) ISC_MAGIC_VALID(a, MEMARENA_MAGIC)

/*
 * Chunk totals are powers of two so they map onto jemalloc size classes;
 * the usable capacity is the total minus the (alignment-rounded) header.
 * Requests too large for ISC_MEMARENA_MAX_CHUNK get a dedicated,
 * exactly-sized chunk that is never retained across a reset.
 */
#define MEMARENA_MIN_CHUNK 2048
#define MEMARENA_MAX_CHUNK 65536

typedef struct memarena_chunk {
	struct memarena_chunk *prev; /*%< older chunk, NULL for the oldest */
	size_t total;		     /*%< allocation size, for sized free */
	size_t used;		     /*%< committed bytes when sealed */
} memarena_chunk_t;

#define CHUNK_HDRSIZE \
	ISC_ALIGN(sizeof(memarena_chunk_t), ISC_MEMARENA_ALIGNMENT)
#define CHUNK_DATA(chunk)     ((uintptr_t)(chunk) + CHUNK_HDRSIZE)
#define CHUNK_CAPACITY(chunk) ((chunk)->total - CHUNK_HDRSIZE)

struct isc_memarena {
	unsigned int magic;
	isc_tid_t tid; /*%< creator thread, for cache bookkeeping */
	isc_mem_t *mctx;
	char *name;

	/* bump state */
	memarena_chunk_t *current; /*%< newest chunk */
	uintptr_t pos;		   /*%< bump cursor in the current chunk */
	uintptr_t end;		   /*%< current chunk limit */

	/* per-cycle accounting */
	size_t live;	    /*%< allocated minus put/shrunk bytes */
	size_t dead;	    /*%< put/shrunk bytes awaiting reset */
	size_t waste;	    /*%< alignment padding and skipped tails */
	size_t used_sealed; /*%< committed bytes in sealed chunks */
	size_t nchunks;
	size_t capacity;

	size_t next_chunk; /*%< total size of the next chunk to allocate */
};

static void
chunk_free_chain(isc_memarena_t *arena, memarena_chunk_t *chunk) {
	while (chunk != NULL) {
		memarena_chunk_t *prev = chunk->prev;

		MEMARENA_UNPOISON((void *)CHUNK_DATA(chunk),
				  CHUNK_CAPACITY(chunk));
		isc_mem_put(arena->mctx, chunk, chunk->total);
		chunk = prev;
	}
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
		arena->used_sealed += arena->current->used;
		arena->waste += arena->end - arena->pos;
	}

	if (size > MEMARENA_MAX_CHUNK - CHUNK_HDRSIZE) {
		/* Oversize request: dedicated, exactly-sized chunk. */
		total = CHUNK_HDRSIZE + size;
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
	arena->nchunks++;
	arena->capacity += total - CHUNK_HDRSIZE;
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
	if (ptr + size > arena->end) {
		memarena_grow(arena, size);
		ptr = arena->pos;
	} else {
		arena->waste += ptr - arena->pos;
	}

	arena->pos = ptr + size;
	arena->live += size;

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

	REQUIRE(arena->live >= size);
	arena->live -= size;
	arena->dead += size;

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

	REQUIRE(arena->live >= delta);
	arena->live -= delta;

	if (memarena_is_top(arena, p, old_size)) {
		/* Most recent allocation: exact bump-pointer rollback. */
		arena->pos = p + new_size;
		MEMARENA_POISON((void *)arena->pos, delta);
	} else {
		arena->dead += delta;
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

	if (memarena_is_top(arena, p, old_size) && p + new_size <= arena->end) {
		/* Most recent allocation: grow in place. */
		arena->pos = p + new_size;
		arena->live += new_size - old_size;
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
	};
	isc_mem_attach(mctx, &arena->mctx);
	if (name != NULL) {
		arena->name = isc_mem_strdup(arena->mctx, name);
	}
	arena->magic = MEMARENA_MAGIC;

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

	chunk_free_chain(arena, arena->current);
	if (arena->name != NULL) {
		isc_mem_free(arena->mctx, arena->name);
	}
	isc_mem_putanddetach(&arena->mctx, arena, sizeof(*arena));
}

void
isc_memarena_reset(isc_memarena_t *arena) {
	memarena_chunk_t *keep = NULL;

	REQUIRE(VALID_MEMARENA(arena));

#if !__SANITIZE_ADDRESS__
	/*
	 * Keep the newest chunk warm for the next cycle, unless it is a
	 * dedicated oversize chunk.
	 */
	if (arena->current != NULL &&
	    arena->current->total <= MEMARENA_MAX_CHUNK)
	{
		keep = arena->current;
	}
#endif

	if (keep != NULL) {
		chunk_free_chain(arena, keep->prev);
		keep->prev = NULL;
		keep->used = 0;

		arena->current = keep;
		arena->nchunks = 1;
		arena->capacity = CHUNK_CAPACITY(keep);
		arena->pos = CHUNK_DATA(keep);
		arena->end = arena->pos + CHUNK_CAPACITY(keep);
		MEMARENA_POISON((void *)arena->pos, CHUNK_CAPACITY(keep));
	} else {
		chunk_free_chain(arena, arena->current);
		arena->current = NULL;
		arena->nchunks = 0;
		arena->capacity = 0;
		arena->pos = 0;
		arena->end = 0;
	}

	arena->live = 0;
	arena->dead = 0;
	arena->waste = 0;
	arena->used_sealed = 0;
}

size_t
isc_memarena_live(isc_memarena_t *arena) {
	REQUIRE(VALID_MEMARENA(arena));

	return arena->live;
}

size_t
isc_memarena_dead(isc_memarena_t *arena) {
	REQUIRE(VALID_MEMARENA(arena));

	return arena->dead;
}

size_t
isc_memarena_used(isc_memarena_t *arena) {
	REQUIRE(VALID_MEMARENA(arena));

	if (arena->current == NULL) {
		return arena->used_sealed;
	}
	return arena->used_sealed + (arena->pos - CHUNK_DATA(arena->current));
}

size_t
isc_memarena_capacity(isc_memarena_t *arena) {
	REQUIRE(VALID_MEMARENA(arena));

	return arena->capacity;
}
