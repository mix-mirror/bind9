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
	int capacity;
	isc_atomic_statscounter_t *counters;
};

void
isc_statsmulti_create(isc_mem_t *mctx, isc_statsmulti_t **statsp, int ncounters) {
	REQUIRE(statsp != NULL && *statsp == NULL);

	isc_statsmulti_t *stats = isc_mem_get(mctx, sizeof(*stats));
	
	size_t counters_size = sizeof(isc_atomic_statscounter_t) * ncounters;
	size_t counters_alloc_size = (counters_size + 63) & ~63; /* Round up to next multiple of 64 */
	int capacity = counters_alloc_size / sizeof(isc_atomic_statscounter_t);
	
	stats->counters = isc_mem_get(mctx, counters_alloc_size);
	isc_refcount_init(&stats->references, 1);
	for (int i = 0; i < capacity; i++) {
		atomic_init(&stats->counters[i], 0);
	}
	stats->mctx = NULL;
	isc_mem_attach(mctx, &stats->mctx);
	stats->ncounters = ncounters;
	stats->capacity = capacity;
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
		isc_mem_cput(stats->mctx, stats->counters, stats->capacity,
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
		isc_statscounter_t counter =
			atomic_load_acquire(&stats->counters[i]);
		if ((options & ISC_STATSMULTIDUMP_VERBOSE) == 0 && counter == 0) {
			continue;
		}
		dump_fn((isc_statscounter_t)i, counter, arg);
	}
}

isc_statscounter_t
isc_statsmulti_get_counter(isc_statsmulti_t *stats, isc_statscounter_t counter) {
	REQUIRE(ISC_STATSMULTI_VALID(stats));
	REQUIRE(counter < stats->ncounters);

	return atomic_load_acquire(&stats->counters[counter]);
}
