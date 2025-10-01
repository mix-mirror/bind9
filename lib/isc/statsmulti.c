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

#include <inttypes.h>
#include <string.h>

#include <isc/atomic.h>
#include <isc/buffer.h>
#include <isc/magic.h>
#include <isc/mem.h>
#include <isc/os.h>
#include <isc/refcount.h>
#include <isc/stats.h>
#include <isc/statsmulti.h>
#include <isc/tid.h>
#include <isc/util.h>

#define ISC_STATSMULTI_MAGIC	   ISC_MAGIC('S', 'M', 'u', 'l')
#define ISC_STATSMULTI_VALID(x) ISC_MAGIC_VALID(x, ISC_STATSMULTI_MAGIC)

/*
 * Same constraint as stats.c
 */
STATIC_ASSERT(sizeof(isc_statscounter_t) <= sizeof(uint64_t),
	      "Exported statistics must fit into the statistic counter size");

enum {
	COUNTERS_PER_CACHELINE = 64 / sizeof(isc_statscounter_t),
};

struct isc_statsmulti {
	unsigned int magic;
	isc_mem_t *mctx;
	isc_refcount_t references;
	int n_counters;
	int n_additive;
	int n_highwater;
	int per_thread_capacity;
	int num_threads_plus_one;
	char *counters;
};

static isc_statscounter_t
additive_counter(isc_statsmulti_t *stats, isc_statscounter_t counter) {
	REQUIRE(counter < stats->n_additive);
	return counter;
}

static isc_statscounter_t
highwater_counter(isc_statsmulti_t *stats, isc_statscounter_t counter) {
	REQUIRE(counter >= stats->n_additive);
	REQUIRE(counter < stats->n_counters);

	/* Map counter to internal highwater position */
	return counter;
}

static int
to_index(isc_statsmulti_t *stats, isc_tid_t tid, isc_statscounter_t internal_counter) {
	int thread_id = tid + 1;
	if (thread_id >= stats->num_threads_plus_one) {
		thread_id = 0;
	}
	return thread_id * stats->per_thread_capacity + internal_counter;
}

static isc_atomic_statscounter_t *
get_atomic_counter_from_index(isc_statsmulti_t *stats, int index) {
	return (isc_atomic_statscounter_t *)&stats->counters[index * sizeof(isc_atomic_statscounter_t)];
}

static void
atomic_update_if_greater(isc_atomic_statscounter_t *counter, isc_statscounter_t value) {
	/* Atomically update if the new value is greater than current */
	isc_statscounter_t current = atomic_load_relaxed(counter);
	while (value > current) {
		if (atomic_compare_exchange_weak_relaxed(counter, &current, value)) {
			break;
		}
		/* current was updated by the failed compare_exchange, try again */
	}
}

void
isc_statsmulti_create(isc_mem_t *mctx, isc_statsmulti_t **statsp, int n_additive, int n_highwater) {
	REQUIRE(statsp != NULL && *statsp == NULL);

	int ncounters = n_additive + n_highwater;
	
	size_t size_in_bytes = sizeof(isc_atomic_statscounter_t) * ncounters;
	size_t rounded_up = (size_in_bytes + 63) & ~63; /* Round up to next multiple of 64 */
	int per_thread_capacity = rounded_up / sizeof(isc_atomic_statscounter_t);
	int num_threads_plus_one = isc_tid_count() + 1;
	REQUIRE(num_threads_plus_one >= 1);
	
	/* Allocate per_thread_capacity * num_threads total counters */
	size_t alloc_size = rounded_up * num_threads_plus_one;
	isc_statsmulti_t *stats = isc_mem_get(mctx, sizeof(*stats));
	stats->counters = isc_mem_get(mctx, alloc_size);
	isc_refcount_init(&stats->references, 1);
	for (int i = 0; i < per_thread_capacity * num_threads_plus_one; i++) {
		atomic_init(get_atomic_counter_from_index(stats, i), 0);
	}

	stats->mctx = NULL;
	isc_mem_attach(mctx, &stats->mctx);
	stats->n_counters = ncounters;
	stats->n_additive = n_additive;
	stats->n_highwater = n_highwater;
	stats->per_thread_capacity = per_thread_capacity;
	stats->num_threads_plus_one = num_threads_plus_one;
	stats->magic = ISC_STATSMULTI_MAGIC;
	*statsp = stats;
}

void
isc_statsmulti_attach(isc_statsmulti_t *stats, isc_statsmulti_t **statsp) {
	REQUIRE(ISC_STATSMULTI_VALID(stats));
	REQUIRE(statsp != NULL && *statsp == NULL);

	isc_refcount_increment(&stats->references);
	*statsp = stats;
}

void
isc_statsmulti_detach(isc_statsmulti_t **statsp) {
	isc_statsmulti_t *stats;

	REQUIRE(statsp != NULL && ISC_STATSMULTI_VALID(*statsp));

	stats = *statsp;
	*statsp = NULL;

	if (isc_refcount_decrement(&stats->references) == 1) {
		isc_refcount_destroy(&stats->references);
		size_t alloc_size = stats->per_thread_capacity * stats->num_threads_plus_one * sizeof(isc_atomic_statscounter_t);
		isc_mem_put(stats->mctx, stats->counters, alloc_size);
		isc_mem_putanddetach(&stats->mctx, stats, sizeof(*stats));
	}
}

isc_statscounter_t
isc_statsmulti_increment(isc_statsmulti_t *stats, isc_statscounter_t counter) {
	REQUIRE(ISC_STATSMULTI_VALID(stats));
	counter = additive_counter(stats, counter);

	int index = to_index(stats, isc_tid(), counter);
	if (isc_tid() == 0) {
		return atomic_fetch_add_relaxed(get_atomic_counter_from_index(stats, index), 1);
	} else {
		isc_atomic_statscounter_t *ptr = get_atomic_counter_from_index(stats, index);
		int_fast64_t tmp = atomic_load_relaxed(ptr);
		atomic_store_relaxed(ptr, tmp + 1);
		return tmp;
	}
}

void
isc_statsmulti_decrement(isc_statsmulti_t *stats, isc_statscounter_t counter) {
	REQUIRE(ISC_STATSMULTI_VALID(stats));
	counter = additive_counter(stats, counter);

	int index = to_index(stats, isc_tid(), counter);
	if (isc_tid() == 0) {
		atomic_fetch_sub_relaxed(get_atomic_counter_from_index(stats, index), 1);
	} else {
		isc_atomic_statscounter_t *ptr = get_atomic_counter_from_index(stats, index);
		int_fast64_t tmp = atomic_load_relaxed(ptr);
		atomic_store_relaxed(ptr, tmp - 1);
	}
}

void
isc_statsmulti_dump(isc_statsmulti_t *stats, isc_statsmulti_dumper_t dump_fn, void *arg,
		    unsigned int options) {
	int i;

	REQUIRE(ISC_STATSMULTI_VALID(stats));

	for (i = 0; i < stats->n_counters; i++) {
		/* Accumulate across all threads */
		/* First thread (tid 0) uses atomic operations */
		int index0 = to_index(stats, 0, i);
		isc_statscounter_t total = atomic_load_acquire(get_atomic_counter_from_index(stats, index0));
		/* Other threads (tid >= 1) use normal operations */
		for (int thread = 1; thread < stats->num_threads_plus_one; thread++) {
			int index = to_index(stats, thread, i);
			total += atomic_load_relaxed(get_atomic_counter_from_index(stats, index));
		}
		if ((options & ISC_STATSMULTIDUMP_VERBOSE) == 0 && total == 0) {
			continue;
		}
		dump_fn((isc_statscounter_t)i, total, arg);
	}
}

isc_statscounter_t
isc_statsmulti_get_counter(isc_statsmulti_t *stats, isc_statscounter_t counter) {
	REQUIRE(ISC_STATSMULTI_VALID(stats));
	counter = additive_counter(stats, counter);

	/* Accumulate across all threads */
	/* First thread (tid 0) uses atomic operations */
	int index0 = to_index(stats, 0, counter);
	isc_statscounter_t total = atomic_load_acquire(get_atomic_counter_from_index(stats, index0));
	/* Other threads (tid >= 1) use normal operations */
	for (int thread = 1; thread < stats->num_threads_plus_one; thread++) {
		int index = to_index(stats, thread, counter);
		total += atomic_load_relaxed(get_atomic_counter_from_index(stats, index));
	}
	return total;
}

void
isc_statsmulti_clear(isc_statsmulti_t *stats) {
	REQUIRE(ISC_STATSMULTI_VALID(stats));

	/* Clear all counters across all threads */
	for (int i = 0; i < stats->per_thread_capacity * stats->num_threads_plus_one; i++) {
		atomic_store_relaxed(get_atomic_counter_from_index(stats, i), 0);
	}
}

void
isc_statsmulti_update_if_greater(isc_statsmulti_t *stats, isc_statscounter_t counter, isc_statscounter_t value) {
	REQUIRE(ISC_STATSMULTI_VALID(stats));

	isc_statscounter_t internal_counter = highwater_counter(stats, counter);

	int index = to_index(stats, isc_tid(), internal_counter);
	
	atomic_update_if_greater(get_atomic_counter_from_index(stats, index), value);
}

isc_statscounter_t
isc_statsmulti_get_highwater(isc_statsmulti_t *stats, isc_statscounter_t counter) {
	REQUIRE(ISC_STATSMULTI_VALID(stats));

	isc_statscounter_t internal_counter = highwater_counter(stats, counter);

	/* Find maximum value across all threads */
	/* First thread (tid 0) uses atomic operations */
	int index0 = to_index(stats, 0, internal_counter);
	isc_statscounter_t max_value = atomic_load_acquire(get_atomic_counter_from_index(stats, index0));
	/* Other threads (tid >= 1) can use atomic operations for now */
	for (int thread = 1; thread < stats->num_threads_plus_one; thread++) {
		int index = to_index(stats, thread, internal_counter);
		isc_statscounter_t value = atomic_load_acquire(get_atomic_counter_from_index(stats, index));
		if (value > max_value) {
			max_value = value;
		}
	}
	return max_value;
}

void
isc_statsmulti_reset_highwater(isc_statsmulti_t *stats, isc_statscounter_t counter) {
	REQUIRE(ISC_STATSMULTI_VALID(stats));

	isc_statscounter_t internal_counter = highwater_counter(stats, counter);

	/* Reset highwater counter to 0 across all threads */
	for (int thread = 0; thread < stats->num_threads_plus_one; thread++) {
		int index = to_index(stats, thread, internal_counter);
		atomic_store_relaxed(get_atomic_counter_from_index(stats, index), 0);
	}
}
