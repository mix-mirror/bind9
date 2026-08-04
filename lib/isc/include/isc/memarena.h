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

#pragma once

/*! \file isc/memarena.h
 * \brief Region-based (arena) allocator.
 *
 * An isc_memarena_t hands out memory from a chain of chunks obtained
 * from a backing memory context using a bump-pointer.  Allocations are
 * address-stable until isc_memarena_reset() or isc_memarena_destroy();
 * there is no per-allocation free.  Returning memory with
 * isc__memarena_put() only marks the bytes dead for accounting; the
 * memory is reclaimed in bulk at reset/destroy time.
 *
 * The allocator is THREAD-UNSAFE by design, like isc_mempool: the
 * caller must confine an arena to a single thread (loop/tid affinity)
 * or serialize access externally.
 *
 * All allocations are aligned to ISC_MEMARENA_ALIGNMENT and never fail
 * (the backing context aborts on allocation failure).
 *
 * The isc__memarena_{get,put,reget} entry points intentionally mirror
 * the isc__mem_{get,put,reget} contract so that an arena can be used
 * wherever a memory context is expected via the isc_mem_get()/
 * isc_mem_put()/isc_mem_reget() macros (transparent union dispatch).
 */

#include <stdalign.h>
#include <stddef.h>

#include <isc/attributes.h>
#include <isc/mem.h>
#include <isc/types.h>

#define ISC_MEMARENA_ALIGNMENT alignof(max_align_t)

void
isc_memarena_create(isc_mem_t *mctx, const char *name, isc_memarena_t **arenap);
/*%<
 * Create an arena backed by 'mctx' (a reference is attached).  'name'
 * is copied and used in statistics reporting; it may be NULL.
 *
 * No chunk is allocated until the first allocation is requested.
 *
 * Requires:
 *\li	'mctx' is a valid memory context.
 *\li	arenap != NULL && *arenap == NULL
 */

void
isc_memarena_destroy(isc_memarena_t **arenap);
/*%<
 * Free all chunks and the arena itself.
 *
 * Outstanding allocations do NOT have to be returned first:
 * leak-until-reset is the ownership model.  The caller is responsible
 * for making sure no pointer into the arena is used afterwards.
 *
 * Requires:
 *\li	arenap != NULL && *arenap is a valid arena.
 */

void
isc_memarena_reset(isc_memarena_t *arena);
/*%<
 * Bulk truncate-to-empty: every allocation made from 'arena' becomes
 * invalid and its memory is reclaimed.  A retention policy decides how
 * much chunk capacity stays warm for the next use cycle; under
 * AddressSanitizer nothing is retained.
 *
 * Requires:
 *\li	'arena' is a valid arena.
 */

#define isc_memarena_shrink(a, p, o, n) \
	isc__memarena_shrink((a), (p), (o), (n)_ISC_MEM_FILELINE)
/*%<
 * Shrink the allocation 'p' from 'o' to 'n' bytes.  Always legal:
 *
 *\li	if 'p' is the MOST RECENT allocation, the tail is reclaimed
 *	exactly (bump-pointer rollback);
 *\li	otherwise the tail is only marked dead (accounting).
 *
 * Shrinking to 0 releases the allocation entirely; 'p' must not be
 * used (or put) afterwards.  After a shrink to n > 0 the allocation's
 * size IS n: a subsequent put or shrink must pass n as the old size.
 *
 * Requires:
 *\li	'a' is a valid arena.
 *\li	'p' points to a live allocation of size 'o' from 'a'.
 *\li	n <= o
 */

size_t
isc_memarena_live(isc_memarena_t *arena);
/*%<
 * Bytes currently allocated and not put back or shrunk away.
 */

size_t
isc_memarena_dead(isc_memarena_t *arena);
/*%<
 * Bytes returned with put or non-rollback shrink since the last reset;
 * they are reclaimed only at the next reset/destroy.
 */

size_t
isc_memarena_used(isc_memarena_t *arena);
/*%<
 * Bump-pointer high-water mark since the last reset, including
 * alignment padding and skipped chunk tails.
 */

size_t
isc_memarena_capacity(isc_memarena_t *arena);
/*%<
 * Total usable capacity of all chunks currently held by the arena.
 */

void
isc_memarena_getcached(isc_mem_t *fallback_mctx, const char *name,
		       isc_memarena_t **arenap);
/*%<
 * Obtain an arena from the current thread's cache of warm arenas, or
 * create a new one when the cache is empty.  Freshly created cached
 * arenas are backed by the current loop's memory context; on a thread
 * without a RUNNING loop the cache is bypassed and a plain arena
 * backed by 'fallback_mctx' is created instead.
 * 'name' is used only when a new arena has to be created; an arena
 * popped from the cache keeps the name of its original creator.
 *
 * Requires:
 *\li	'fallback_mctx' is a valid memory context.
 *\li	arenap != NULL && *arenap == NULL
 */

void
isc_memarena_putcached(isc_memarena_t **arenap);
/*%<
 * Reset 'arena' and return it to the current thread's cache; the arena
 * is destroyed instead when the cache is full, when the current thread
 * has no loop, or under AddressSanitizer (no pooling, mirroring
 * isc_mempool).  It is safe to pair isc_memarena_putcached() with a
 * plain isc_memarena_create().
 *
 * Requires:
 *\li	arenap != NULL && *arenap is a valid arena.
 */

#if defined(UNIT_TESTING) && defined(malloc)
/*
 * cmocka.h redefined malloc as a macro, we #undef it
 * to avoid replacing ISC_ATTR_MALLOC with garbage.
 */
#pragma push_macro("malloc")
#undef malloc
#define POP_MALLOC_MACRO 1
#endif

/*
 * Pseudo-private functions for use via macros.  Do not call directly.
 */
void
isc__memarena_put(isc_memarena_t *, void *, size_t, int _ISC_MEM_FLARG);

ISC_ATTR_MALLOC_DEALLOCATOR_IDX(isc__memarena_put, 2)
void *
isc__memarena_get(isc_memarena_t *, size_t, int _ISC_MEM_FLARG);

ISC_ATTR_DEALLOCATOR_IDX(isc__memarena_put, 2)
void *
isc__memarena_reget(isc_memarena_t *, void *, size_t, size_t,
		    int _ISC_MEM_FLARG);

void
isc__memarena_shrink(isc_memarena_t *, void *, size_t, size_t _ISC_MEM_FLARG);

#ifdef POP_MALLOC_MACRO
/*
 * Restore cmocka.h macro for malloc.
 */
#pragma pop_macro("malloc")
#endif
