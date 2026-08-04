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

/*! \file */

/*
 * Shared between memarena.c and mem.c: mem.c registers arenas on their
 * backing context (for isc_mem_stats()) and dispatches the sized
 * allocation entry points, so it needs the structure layout and the
 * magic number.
 */

#include <isc/list.h>
#include <isc/magic.h>
#include <isc/tid.h>
#include <isc/types.h>

#define MEMARENA_MAGIC	  ISC_MAGIC('M', 'e', 'm', 'A')
#define VALID_MEMARENA(a) ISC_MAGIC_VALID(a, MEMARENA_MAGIC)

typedef struct memarena_chunk memarena_chunk_t;

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
	size_t usage_ewma; /*%< moving average of per-cycle usage */

	ISC_LINK(isc_memarena_t) link; /*%< backing context's arena list */
	isc_memarena_t *cache_next;    /*%< per-tid cache free list */
};

void
isc__mem_registerarena(isc_mem_t *ctx, isc_memarena_t *arena);
void
isc__mem_unregisterarena(isc_mem_t *ctx, isc_memarena_t *arena);
/*%<
 * Add/remove 'arena' to/from the arena list of 'ctx' (implemented in
 * mem.c, under the context lock).  Used by isc_mem_stats() reporting.
 */

void
isc__memarena_cache_flush(isc_tid_t tid);
/*%<
 * Destroy all arenas cached for 'tid'.  Called from loop_close() before
 * the loop's memory context is detached; safe there because the loop
 * threads have already been joined.
 */

void
isc__memarena_cache_flushall(void);
/*%<
 * Destroy all cached arenas on all threads; backstop for non-loopmgr
 * users, called from isc__mem_shutdown() before the leak check.
 */
