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
#include <isc/util.h>

#define ISC_STATSMULTI_MAGIC	   ISC_MAGIC('S', 'M', 'u', 'l')
#define ISC_STATSMULTI_VALID(x) ISC_MAGIC_VALID(x, ISC_STATSMULTI_MAGIC)

/*
 * Same constraint as stats.c
 */
STATIC_ASSERT(sizeof(isc_statscounter_t) <= sizeof(uint64_t),
	      "Exported statistics must fit into the statistic counter size");

struct isc_statsmulti {
	unsigned int magic;
	isc_mem_t *mctx;
	isc_refcount_t references;
	int ncounters;
	int per_thread_capacity;
	int num_threads;
	isc_atomic_statscounter_t *counters;
};

void
isc_statsmulti_create(isc_mem_t *mctx, isc_statsmulti_t **statsp, int ncounters) {
	REQUIRE(statsp != NULL && *statsp == NULL);

	isc_statsmulti_t *stats = isc_mem_get(mctx, sizeof(*stats));
	
	size_t counters_size = sizeof(isc_atomic_statscounter_t) * ncounters;
	size_t counters_alloc_size = (counters_size + 63) & ~63; /* Round up to next multiple of 64 */
	int per_thread_capacity = counters_alloc_size / sizeof(isc_atomic_statscounter_t);
	int num_threads = isc_os_ncpus();
	
	/* Allocate per_thread_capacity * num_threads total counters */
	size_t total_alloc_size = counters_alloc_size * num_threads;
	stats->counters = isc_mem_get(mctx, total_alloc_size);
	isc_refcount_init(&stats->references, 1);
	for (int i = 0; i < per_thread_capacity * num_threads; i++) {
		atomic_init(&stats->counters[i], 0);
	}
	stats->mctx = NULL;
	isc_mem_attach(mctx, &stats->mctx);
	stats->ncounters = ncounters;
	stats->per_thread_capacity = per_thread_capacity;
	stats->num_threads = num_threads;
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
		isc_mem_cput(stats->mctx, stats->counters, stats->per_thread_capacity * stats->num_threads,
			     sizeof(isc_atomic_statscounter_t));
		isc_mem_putanddetach(&stats->mctx, stats, sizeof(*stats));
	}
}

isc_statscounter_t
isc_statsmulti_increment(isc_statsmulti_t *stats, isc_statscounter_t counter) {
	REQUIRE(ISC_STATSMULTI_VALID(stats));
	REQUIRE(counter < stats->ncounters);

	return atomic_fetch_add_relaxed(&stats->counters[counter], 1);
}

void
isc_statsmulti_decrement(isc_statsmulti_t *stats, isc_statscounter_t counter) {
	REQUIRE(ISC_STATSMULTI_VALID(stats));
	REQUIRE(counter < stats->ncounters);
#if ISC_STATS_CHECKUNDERFLOW
	REQUIRE(atomic_fetch_sub_release(&stats->counters[counter], 1) > 0);
#else
	atomic_fetch_sub_release(&stats->counters[counter], 1);
#endif
}

void
isc_statsmulti_dump(isc_statsmulti_t *stats, isc_statsmulti_dumper_t dump_fn, void *arg,
		    unsigned int options) {
	int i;

	REQUIRE(ISC_STATSMULTI_VALID(stats));

	for (i = 0; i < stats->ncounters; i++) {
		isc_statscounter_t total = 0;
		/* Accumulate across all threads */
		for (int thread = 0; thread < stats->num_threads; thread++) {
			int index = thread * stats->per_thread_capacity + i;
			total += atomic_load_acquire(&stats->counters[index]);
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
	REQUIRE(counter < stats->ncounters);

	isc_statscounter_t total = 0;
	/* Accumulate across all threads */
	for (int thread = 0; thread < stats->num_threads; thread++) {
		int index = thread * stats->per_thread_capacity + counter;
		total += atomic_load_acquire(&stats->counters[index]);
	}
	return total;
}
