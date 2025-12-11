/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * SPDX-License-Identifier: MPL-2.0
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at https://mozilla.org/MPL/2.0/.
 */

/*
 * Hierarchical Timing Wheels as Priority Queue
 * Based on "Hashed and Hierarchical Timing Wheels: Efficient Data Structures
 * for Implementing a Timer Facility" by George Varghese and Tony Lauck (1987)
 */

#pragma once

#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>

#include <isc/mem.h>
#include <isc/result.h>
#include <isc/stdtime.h>
#include <isc/types.h>
#include <isc/urcu.h>

/*
 * Configuration for timing wheel hierarchy
 * 4 levels × 256 slots with 1 second base resolution
 */
#define ISC_TW_LEVELS 4
#define ISC_TW_SLOTS  256

/*
 * Priority queue element - embedded in user structures
 */
typedef struct isc_tw_elt {
	struct cds_list_head list_node;
	isc_stdtime_t	     expire;
	uint32_t	     level;
	uint32_t	     slot;
} isc_tw_elt_t;

/*
 * Slot in timing wheel. Caller provides external synchronization for
 * concurrent access.
 */
typedef struct isc_tw_slot {
	struct cds_list_head head;
	size_t	       count;
} isc_tw_slot_t;

/*
 * Single level of hierarchical timing wheel
 */
typedef struct isc_tw_level {
	isc_tw_slot_t slots[ISC_TW_SLOTS];
	uint64_t      tick_size; /* Duration per slot in seconds */
	uint_fast32_t current;
} isc_tw_level_t;

/*
 * Main timing wheel structure. Caller must provide synchronization (e.g.
 * write lock) around mutation and iteration.
 */
typedef struct isc_tw {
	unsigned int   magic;
	isc_mem_t     *mctx;
	isc_tw_level_t levels[ISC_TW_LEVELS];
	size_t	       size;
	isc_stdtime_t  now;
} isc_tw_t;

#define ISC_TW_MAGIC	 ISC_MAGIC('T', 'W', 'h', 'l')
#define ISC_TW_VALID(tw) ISC_MAGIC_VALID(tw, ISC_TW_MAGIC)

/*
 * Initialize timing wheel element
 */
#define ISC_TW_ELT_INIT(elt)                           \
	{                                              \
		CDS_INIT_LIST_HEAD(&(elt)->list_node); \
		(elt)->expire = 0;                     \
		(elt)->level = (unsigned int)-1;       \
		(elt)->slot = (unsigned int)-1;        \
	}

/*
 * Create timing wheel priority queue. Caller handles synchronization.
 */
isc_result_t
isc_tw_create(isc_mem_t *mctx, isc_tw_t **twp);

/*
 * Destroy timing wheel. Elements must already be quiesced by caller.
 */
void
isc_tw_destroy(isc_tw_t **twp);

/*
 * Insert element into timing wheel.
 */
isc_result_t
isc_tw_insert(isc_tw_t *tw, isc_tw_elt_t *elt);

/*
 * Delete element from timing wheel.
 */
void
isc_tw_delete(isc_tw_t *tw, isc_tw_elt_t *elt);

/*
 * Return whether the node has been deleted.
 */
bool
isc_tw_is_node_deleted(isc_tw_elt_t *elt);

/*
 * Get element with minimum priority (earliest time)
 * Returns NULL if empty
 */
isc_tw_elt_t *
isc_tw_element(isc_tw_t *tw);

/*
 * Set current time for timing wheel (in seconds since epoch)
 * Triggers cascading - writer must serialize calls
 */
void
isc_tw_settime(isc_tw_t *tw, isc_stdtime_t now);

/*
 * Get approximate number of elements
 * May be slightly stale due to concurrent operations
 */
static inline size_t
isc_tw_count(isc_tw_t *tw) {
	return tw->size;
}

static inline isc_stdtime_t
isc_tw_getexpire(isc_tw_elt_t *elt) {
	return elt->expire;
}

static inline void
isc_tw_setexpire(isc_tw_elt_t *elt, isc_stdtime_t now) {
	elt->expire = now;
}
