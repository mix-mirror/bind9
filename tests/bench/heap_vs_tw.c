/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * SPDX-License-Identifier: MPL-2.0
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at https://mozilla.org/MPL/2.0/.
 */

#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include <isc/heap.h>
#include <isc/lib.h>
#include <isc/mem.h>
#include <isc/random.h>
#include <isc/timeout.h>
#include <isc/util.h>

isc_mem_t *isc_g_mctx = NULL;

/*
 * Benchmark parameters - simulate DNS cache workload
 */
#define BENCH_ENTRIES	     100000  /* Number of cache entries */
#define BENCH_OPS_PER_UPDATE 10000   /* Add/del ops between updates */
#define BENCH_UPDATES	     100     /* Number of update cycles */
#define BENCH_TTL_MIN	     30	     /* Minimum TTL in seconds */
#define BENCH_TTL_MAX	     86400   /* Maximum TTL (24 hours) */
#define BENCH_TIME_STEP	     10	     /* Seconds to advance per update */

typedef struct bench_entry {
	union {
		struct {
			unsigned int index;  /* Heap index */
		} heapnode;
		timeout_t timeout;
	};
	isc_stdtime_t expire;
	uint32_t id;
} bench_entry_t;

static isc_stdtime_t
get_random_ttl(void) {
	/* Generate TTL with realistic distribution:
	 * - 60% short (30-300 seconds)
	 * - 30% medium (5-60 minutes)
	 * - 10% long (1-24 hours)
	 */
	uint32_t r = isc_random_uniform(100);
	if (r < 60) {
		return BENCH_TTL_MIN + isc_random_uniform(270);
	} else if (r < 90) {
		return 300 + isc_random_uniform(3300);
	} else {
		return 3600 + isc_random_uniform(82800);
	}
}

static uint64_t
get_time_ns(void) {
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

/*
 * Heap-based implementation benchmark
 */

static bool
heap_compare(void *p1, void *p2) {
	bench_entry_t *e1 = p1;
	bench_entry_t *e2 = p2;
	return (e1->expire < e2->expire);
}

static void
heap_index(void *p, unsigned int i) {
	bench_entry_t *e = p;
	e->heapnode.index = i;
}

static void
bench_heap(void) {
	isc_heap_t *heap = NULL;
	bench_entry_t *entries = NULL;
	isc_stdtime_t now = 1000000;
	uint64_t start_ns, end_ns;
	uint64_t add_time = 0, del_time = 0, update_time = 0;
	size_t total_adds = 0, total_dels = 0, total_updates = 0;
	size_t expired_count = 0;

	isc_heap_create(isc_g_mctx, heap_compare, heap_index, 0, &heap);

	entries = isc_mem_cget(isc_g_mctx, BENCH_ENTRIES, sizeof(*entries));
	for (size_t i = 0; i < BENCH_ENTRIES; i++) {
		entries[i].id = i;
		entries[i].expire = 0;
	}

	printf("\n=== Heap-based Implementation ===\n");
	printf("Initial population: %d entries\n", BENCH_ENTRIES);

	/* Initial population */
	start_ns = get_time_ns();
	for (size_t i = 0; i < BENCH_ENTRIES; i++) {
		entries[i].expire = now + get_random_ttl();
		isc_heap_insert(heap, &entries[i]);
		total_adds++;
	}
	end_ns = get_time_ns();
	add_time += (end_ns - start_ns);

	/* Simulate workload: many add/del operations, occasional updates */
	printf("Running workload: %d updates, %d ops/update\n", BENCH_UPDATES,
	       BENCH_OPS_PER_UPDATE);

	for (size_t update = 0; update < BENCH_UPDATES; update++) {
		/* Perform many add/del operations */
		for (size_t op = 0; op < BENCH_OPS_PER_UPDATE; op++) {
			size_t idx = isc_random_uniform(BENCH_ENTRIES);
			bench_entry_t *entry = &entries[idx];

			if (entry->expire == 0) {
				/* Entry not in heap, add it */
				start_ns = get_time_ns();
				entry->expire = now + get_random_ttl();
				isc_heap_insert(heap, entry);
				end_ns = get_time_ns();
				add_time += (end_ns - start_ns);
				total_adds++;
			} else {
				/* Entry in heap, delete it */
				start_ns = get_time_ns();
				isc_heap_delete(heap, entry->heapnode.index);
				end_ns = get_time_ns();
				del_time += (end_ns - start_ns);
				entry->expire = 0;
				total_dels++;
			}
		}

		/* Advance time and process expirations */
		now += BENCH_TIME_STEP;
		start_ns = get_time_ns();

		while (true) {
			bench_entry_t *entry = isc_heap_element(heap, 1);
			if (entry == NULL || entry->expire > now) {
				break;
			}
			isc_heap_delete(heap, 1);
			entry->expire = 0;
			expired_count++;
		}

		end_ns = get_time_ns();
		update_time += (end_ns - start_ns);
		total_updates++;
	}

	printf("\nResults:\n");
	printf("  Total operations:\n");
	printf("    Adds:    %zu (%.2f ns/op)\n", total_adds,
	       (double)add_time / total_adds);
	printf("    Deletes: %zu (%.2f ns/op)\n", total_dels,
	       (double)del_time / total_dels);
	printf("    Updates: %zu (%.2f ns/op)\n", total_updates,
	       (double)update_time / total_updates);
	printf("    Expired: %zu\n", expired_count);
	printf("  Total time: %.3f ms\n",
	       (double)(add_time + del_time + update_time) / 1000000.0);
	printf("  Ops/sec: %.0f\n",
	       (double)(total_adds + total_dels) * 1000000000.0 /
		       (add_time + del_time));

	/* Cleanup */
	while (isc_heap_element(heap, 1) != NULL) {
		isc_heap_delete(heap, 1);
	}
	isc_heap_destroy(&heap);
	isc_mem_cput(isc_g_mctx, entries, BENCH_ENTRIES, sizeof(*entries));
}

/*
 * Timing wheel implementation benchmark
 */

static void
bench_timewheel(void) {
	timeouts_t *wheel = NULL;
	bench_entry_t *entries = NULL;
	isc_stdtime_t now = 1000000;
	uint64_t start_ns, end_ns;
	uint64_t add_time = 0, del_time = 0, update_time = 0;
	size_t total_adds = 0, total_dels = 0, total_updates = 0;
	size_t expired_count = 0;

	timeouts_create(isc_g_mctx, &wheel);

	entries = isc_mem_cget(isc_g_mctx, BENCH_ENTRIES, sizeof(*entries));
	for (size_t i = 0; i < BENCH_ENTRIES; i++) {
		entries[i].timeout = (timeout_t)TIMEOUT_INITIALIZER;
		entries[i].id = i;
		entries[i].expire = 0;
	}

	printf("\n=== Timing Wheel Implementation ===\n");
	printf("Initial population: %d entries\n", BENCH_ENTRIES);

	/* Initial population */
	start_ns = get_time_ns();
	for (size_t i = 0; i < BENCH_ENTRIES; i++) {
		entries[i].expire = now + get_random_ttl();
		timeouts_add(wheel, &entries[i].timeout, entries[i].expire);
		total_adds++;
	}
	end_ns = get_time_ns();
	add_time += (end_ns - start_ns);

	/* Simulate workload: many add/del operations, occasional updates */
	printf("Running workload: %d updates, %d ops/update\n", BENCH_UPDATES,
	       BENCH_OPS_PER_UPDATE);

	for (size_t update = 0; update < BENCH_UPDATES; update++) {
		/* Perform many add/del operations */
		for (size_t op = 0; op < BENCH_OPS_PER_UPDATE; op++) {
			size_t idx = isc_random_uniform(BENCH_ENTRIES);
			bench_entry_t *entry = &entries[idx];

			if (entry->expire == 0) {
				/* Entry not scheduled, add it */
				start_ns = get_time_ns();
				entry->expire = now + get_random_ttl();
				timeouts_add(wheel, &entry->timeout,
					     entry->expire);
				end_ns = get_time_ns();
				add_time += (end_ns - start_ns);
				total_adds++;
			} else {
				/* Entry scheduled, delete it */
				start_ns = get_time_ns();
				timeouts_del(wheel, &entry->timeout);
				end_ns = get_time_ns();
				del_time += (end_ns - start_ns);
				entry->expire = 0;
				total_dels++;
			}
		}

		/* Advance time and process expirations */
		now += BENCH_TIME_STEP;
		start_ns = get_time_ns();

		timeouts_update(wheel, now);
		while (timeouts_expired(wheel)) {
			timeout_t *timeout = timeouts_get(wheel);
			if (timeout == NULL) {
				break;
			}
			bench_entry_t *entry = (bench_entry_t *)timeout;
			entry->expire = 0;
			expired_count++;
		}

		end_ns = get_time_ns();
		update_time += (end_ns - start_ns);
		total_updates++;
	}

	printf("\nResults:\n");
	printf("  Total operations:\n");
	printf("    Adds:    %zu (%.2f ns/op)\n", total_adds,
	       (double)add_time / total_adds);
	printf("    Deletes: %zu (%.2f ns/op)\n", total_dels,
	       (double)del_time / total_dels);
	printf("    Updates: %zu (%.2f ns/op)\n", total_updates,
	       (double)update_time / total_updates);
	printf("    Expired: %zu\n", expired_count);
	printf("  Total time: %.3f ms\n",
	       (double)(add_time + del_time + update_time) / 1000000.0);
	printf("  Ops/sec: %.0f\n",
	       (double)(total_adds + total_dels) * 1000000000.0 /
		       (add_time + del_time));

	/* Cleanup */
	timeouts_destroy(&wheel);
	isc_mem_cput(isc_g_mctx, entries, BENCH_ENTRIES, sizeof(*entries));
}

int
main(void) {
	isc_mem_t *mctx = NULL;

	isc_mem_create("heap_vs_tw", &mctx);

	/* Make isc_g_mctx available for benchmark functions */
	isc_g_mctx = mctx;

	printf("\n");
	printf("========================================\n");
	printf("Timeout Data Structure Benchmark\n");
	printf("========================================\n");
	printf("Simulating DNS cache workload:\n");
	printf("  - %d cache entries\n", BENCH_ENTRIES);
	printf("  - %d add/del ops between updates\n", BENCH_OPS_PER_UPDATE);
	printf("  - %d update cycles\n", BENCH_UPDATES);
	printf("  - Time advances %d seconds per update\n", BENCH_TIME_STEP);
	printf("  - TTL range: %d-%d seconds\n", BENCH_TTL_MIN, BENCH_TTL_MAX);
	printf("\n");

	bench_heap();
	bench_timewheel();

	printf("\n");
	printf("========================================\n");
	printf("Benchmark Complete\n");
	printf("========================================\n");

	return (0);
}
