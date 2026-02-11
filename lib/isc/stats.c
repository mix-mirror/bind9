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

#include <isc/atomic.h>
#include <isc/buffer.h>
#include <isc/magic.h>
#include <isc/mem.h>
#include <isc/refcount.h>
#include <isc/stats.h>
#include <isc/tid.h>
#include <isc/util.h>

#define ISC_STATS_MAGIC	   ISC_MAGIC('S', 't', 'a', 't')
#define ISC_STATS_VALID(x) ISC_MAGIC_VALID(x, ISC_STATS_MAGIC)

/*
 * Statistics are counted with an atomic int_fast64_t but exported to functions
 * taking uint64_t (isc_stats_dumper_t). A 128-bit native and fast architecture
 * doesn't exist in reality so these two are the same thing in practise.
 * However, a silent truncation happening silently in the future is still not
 * acceptable.
 */
STATIC_ASSERT(sizeof(isc_statscounter_t) <= sizeof(uint64_t),
	      "Exported statistics must fit into the statistic counter size");

struct isc_stats {
	unsigned int magic;
	isc_mem_t *mctx;
	isc_refcount_t references;
	ssize_t ncounters;
	ssize_t tid_count;
	isc_atomic_statscounter_t **counters;
};

void
isc_stats_attach(isc_stats_t *stats, isc_stats_t **statsp) {
	REQUIRE(ISC_STATS_VALID(stats));
	REQUIRE(statsp != NULL && *statsp == NULL);

	isc_refcount_increment(&stats->references);
	*statsp = stats;
}

void
isc_stats_detach(isc_stats_t **statsp) {
	isc_stats_t *stats;

	REQUIRE(statsp != NULL && ISC_STATS_VALID(*statsp));

	stats = *statsp;
	*statsp = NULL;

	if (isc_refcount_decrement(&stats->references) == 1) {
		isc_refcount_destroy(&stats->references);

		for (ssize_t j = -1; j < stats->tid_count; j++) {
			isc_mem_cput(stats->mctx, stats->counters[j],
				     stats->ncounters,
				     sizeof(stats->counters[j][0]));
		}
		uint8_t *counters = (uint8_t *)stats->counters;
		counters -= sizeof(stats->counters[0]);

		isc_mem_cput(stats->mctx, counters, stats->tid_count + 1,
			     sizeof(stats->counters[0]));
		isc_mem_putanddetach(&stats->mctx, stats, sizeof(*stats));
	}
}

int
isc_stats_ncounters(isc_stats_t *stats) {
	REQUIRE(ISC_STATS_VALID(stats));

	return stats->ncounters;
}

void
isc_stats_create(isc_mem_t *mctx, isc_stats_t **statsp, int ncounters) {
	REQUIRE(statsp != NULL && *statsp == NULL);

	isc_stats_t *stats = isc_mem_get(mctx, sizeof(*stats));
	*stats = (isc_stats_t){
		.magic = ISC_STATS_MAGIC,
		.mctx = isc_mem_ref(mctx),
		.ncounters = ncounters,
		.tid_count = ISC_TID_MAX,
		.references = 1,
	};
	uint8_t *counters = isc_mem_cget(stats->mctx, stats->tid_count + 1,
					 sizeof(stats->counters[0]));

	stats->counters =
		(isc_atomic_statscounter_t **)(counters +
					       sizeof(stats->counters[0]));

	for (ssize_t j = -1; j < stats->tid_count; j++) {
		stats->counters[j] =
			isc_mem_cget(stats->mctx, stats->ncounters,
				     sizeof(stats->counters[j][0]));
	}

	*statsp = stats;
}

isc_statscounter_t
isc_stats_increment(isc_stats_t *stats, isc_statscounter_t counter) {
	REQUIRE(ISC_STATS_VALID(stats));
	REQUIRE(counter < stats->ncounters);

	return atomic_fetch_add_relaxed(&stats->counters[isc_tid()][counter],
					1);
}

void
isc_stats_decrement(isc_stats_t *stats, isc_statscounter_t counter) {
	REQUIRE(ISC_STATS_VALID(stats));
	REQUIRE(counter < stats->ncounters);

	atomic_fetch_sub_release(&stats->counters[isc_tid()][counter], 1);
}

void
isc_stats_dump(isc_stats_t *stats, isc_stats_dumper_t dump_fn, void *arg,
	       unsigned int options) {
	int i;

	REQUIRE(ISC_STATS_VALID(stats));

	for (i = 0; i < stats->ncounters; i++) {
		isc_statscounter_t counter = 0;
		for (ssize_t j = -1; j < stats->tid_count; j++) {
			counter += atomic_load_acquire(&stats->counters[j][i]);
		}
		if ((options & ISC_STATSDUMP_VERBOSE) == 0 && counter == 0) {
			continue;
		}
		dump_fn((isc_statscounter_t)i, counter, arg);
	}
}

void
isc_stats_set(isc_stats_t *stats, uint64_t val, isc_statscounter_t counter) {
	REQUIRE(ISC_STATS_VALID(stats));
	REQUIRE(counter < stats->ncounters);

	atomic_store_release(&stats->counters[-1][counter], val);
	for (ssize_t j = 0; j < stats->tid_count; j++) {
		atomic_store_release(&stats->counters[j][counter], 0);
	}
}

void
isc_stats_update_if_greater(isc_stats_t *stats, isc_statscounter_t counter,
			    isc_statscounter_t value) {
	REQUIRE(ISC_STATS_VALID(stats));
	REQUIRE(counter < stats->ncounters);

	/*
	 * FIXME: This is definitely wrong, we will probably need more counter
	 * types or smth. :)
	 */

	isc_statscounter_t curr_value = isc_stats_get_counter(stats, counter);
	if (curr_value >= value) {
		return;
	}
	atomic_fetch_add_release(&stats->counters[isc_tid()][counter],
				 value - curr_value);
}

isc_statscounter_t
isc_stats_get_counter(isc_stats_t *stats, isc_statscounter_t counter) {
	REQUIRE(ISC_STATS_VALID(stats));
	REQUIRE(counter < stats->ncounters);

	isc_statscounter_t value = 0;

	for (ssize_t j = -1; j < stats->tid_count; j++) {
		value += atomic_load_acquire(&stats->counters[j][counter]);
	}

	return value;
}

void
isc_stats_resize(isc_stats_t **statsp, int ncounters) {
	isc_stats_t *stats;
	isc_atomic_statscounter_t *newcounters;

	REQUIRE(statsp != NULL && *statsp != NULL);
	REQUIRE(ISC_STATS_VALID(*statsp));
	REQUIRE(ncounters > 0);

	stats = *statsp;
	if (stats->ncounters >= ncounters) {
		/* We already have enough counters. */
		return;
	}

	/* Grow number of counters. */
	for (ssize_t j = -1; j < stats->tid_count; j++) {
		newcounters = isc_mem_cget(stats->mctx, ncounters,
					   sizeof(stats->counters[j][0]));
		for (int i = 0; i < stats->ncounters; i++) {
			atomic_init(&newcounters[i], stats->counters[j][i]);
		}

		isc_mem_cput(stats->mctx, stats->counters[j], stats->ncounters,
			     sizeof(stats->counters[j][0]));
		stats->counters[j] = newcounters;
	}
	stats->ncounters = ncounters;
}
