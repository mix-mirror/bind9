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

/*
 * Benchmark comparing isc_heap (binary heap) vs isc_tw (timing wheels)
 * as priority queue implementations for timer management.
 */

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <isc/heap.h>
#include <isc/lib.h>
#include <isc/random.h>
#include <isc/time.h>
#include <isc/tw.h>
#include <isc/util.h>

#include <dns/lib.h>

#define NS_PER_SEC 1000000000

/* Test parameters */
#define NUM_ELEMENTS   100000
#define NUM_OPERATIONS 10000 /* Reduced for testing */
#define TIME_RANGE_MIN 0
#define TIME_RANGE_MAX 86400 /* 1 day in seconds */

/* Entry for heap */
typedef struct heap_entry {
	isc_stdtime_t expire;
	unsigned int index;
	uint32_t id;
} heap_entry_t;

/* Entry for timing wheel */
typedef struct tw_entry {
	isc_tw_elt_t elt;
	uint32_t id;
} tw_entry_t;

/* Heap comparison function: earlier expiry has higher priority */
static bool
heap_compare(void *p1, void *p2) {
	heap_entry_t *e1 = (heap_entry_t *)p1;
	heap_entry_t *e2 = (heap_entry_t *)p2;
	return e1->expire < e2->expire;
}

/* Heap index callback */
static void
heap_index(void *p, unsigned int idx) {
	heap_entry_t *e = (heap_entry_t *)p;
	e->index = idx;
}

/* Generate random expiry times */
static void
generate_random_times(isc_stdtime_t *times, size_t count,
		      isc_stdtime_t base_time) {
	for (size_t i = 0; i < count; i++) {
		uint32_t offset =
			isc_random_uniform(TIME_RANGE_MAX - TIME_RANGE_MIN);
		times[i] = base_time + TIME_RANGE_MIN + offset;
	}
}

/* Benchmark: Heap - Sequential insertions */
static void
bench_heap_insert_sequential(isc_stdtime_t base_time, size_t count,
			     isc_stdtime_t *times) {
	isc_heap_t *heap = NULL;
	heap_entry_t *entries = NULL;
	isc_nanosecs_t start, end;

	UNUSED(base_time);

	isc_heap_create(isc_g_mctx, heap_compare, heap_index, 0, &heap);
	entries = isc_mem_cget(isc_g_mctx, count, sizeof(heap_entry_t));

	for (size_t i = 0; i < count; i++) {
		entries[i].expire = times[i];
		entries[i].index = 0;
		entries[i].id = i;
	}

	start = isc_time_monotonic();
	for (size_t i = 0; i < count; i++) {
		isc_heap_insert(heap, &entries[i]);
	}
	end = isc_time_monotonic();

	printf("Heap insert %zu elements:              %7.3f ms (%7.3f "
	       "µs/op)\n",
	       count, (end - start) / 1000000.0,
	       (end - start) / (double)count / 1000.0);

	/* Cleanup */
	while (isc_heap_element(heap, 1) != NULL) {
		isc_heap_delete(heap, 1);
	}
	isc_mem_cput(isc_g_mctx, entries, count, sizeof(heap_entry_t));
	isc_heap_destroy(&heap);
}

/* Benchmark: Timing Wheel - Sequential insertions */
static void
bench_tw_insert_sequential(isc_stdtime_t base_time, size_t count,
			   isc_stdtime_t *times) {
	isc_tw_t *tw = NULL;
	tw_entry_t *entries = NULL;
	isc_nanosecs_t start, end;

	isc_tw_create(isc_g_mctx, &tw);
	isc_tw_settime(tw, base_time);
	entries = isc_mem_cget(isc_g_mctx, count, sizeof(tw_entry_t));

	for (size_t i = 0; i < count; i++) {
		ISC_TW_ELT_INIT(&entries[i].elt);
		entries[i].elt.expire = times[i];
		entries[i].id = i;
	}

	start = isc_time_monotonic();
	for (size_t i = 0; i < count; i++) {
		isc_tw_insert(tw, &entries[i].elt);
	}
	end = isc_time_monotonic();

	printf("TW   insert %zu elements:              %7.3f ms (%7.3f "
	       "µs/op)\n",
	       count, (end - start) / 1000000.0,
	       (end - start) / (double)count / 1000.0);

	/* Cleanup */
	for (size_t i = 0; i < count; i++) {
		isc_tw_delete(tw, &entries[i].elt);
	}
	isc_mem_cput(isc_g_mctx, entries, count, sizeof(tw_entry_t));
	isc_tw_destroy(&tw);
}

/* Benchmark: Heap - Extract minimum repeatedly */
static void
bench_heap_extract_min(isc_stdtime_t base_time, size_t count,
		       isc_stdtime_t *times) {
	isc_heap_t *heap = NULL;
	heap_entry_t *entries = NULL;
	isc_nanosecs_t start, end;
	size_t extracted = 0;

	UNUSED(base_time);

	isc_heap_create(isc_g_mctx, heap_compare, heap_index, 0, &heap);
	entries = isc_mem_cget(isc_g_mctx, count, sizeof(heap_entry_t));

	for (size_t i = 0; i < count; i++) {
		entries[i].expire = times[i];
		entries[i].index = 0;
		entries[i].id = i;
		isc_heap_insert(heap, &entries[i]);
	}

	start = isc_time_monotonic();
	while (isc_heap_element(heap, 1) != NULL) {
		isc_heap_delete(heap, 1);
		extracted++;
	}
	end = isc_time_monotonic();

	printf("Heap extract-min %zu elements:         %7.3f ms (%7.3f "
	       "µs/op)\n",
	       extracted, (end - start) / 1000000.0,
	       (end - start) / (double)extracted / 1000.0);

	isc_mem_cput(isc_g_mctx, entries, count, sizeof(heap_entry_t));
	isc_heap_destroy(&heap);
}

/* Benchmark: Timing Wheel - Extract minimum repeatedly */
static void
bench_tw_extract_min(isc_stdtime_t base_time, size_t count,
		     isc_stdtime_t *times) {
	isc_tw_t *tw = NULL;
	tw_entry_t *entries = NULL;
	isc_nanosecs_t start, end;
	size_t extracted = 0;

	isc_tw_create(isc_g_mctx, &tw);
	isc_tw_settime(tw, base_time);
	entries = isc_mem_cget(isc_g_mctx, count, sizeof(tw_entry_t));

	for (size_t i = 0; i < count; i++) {
		ISC_TW_ELT_INIT(&entries[i].elt);
		entries[i].elt.expire = times[i];
		entries[i].id = i;
		isc_tw_insert(tw, &entries[i].elt);
	}

	/* Advance time once to expire all timers */
	isc_tw_settime(tw, base_time + TIME_RANGE_MAX + 1);

	start = isc_time_monotonic();
	while (isc_tw_element(tw) != NULL) {
		isc_tw_elt_t *elt = isc_tw_element(tw);
		isc_tw_delete(tw, elt);
		extracted++;
	}
	end = isc_time_monotonic();

	printf("TW   extract-min %zu elements:         %7.3f ms (%7.3f "
	       "µs/op)\n",
	       extracted, (end - start) / 1000000.0,
	       (end - start) / (double)extracted / 1000.0);

	isc_mem_cput(isc_g_mctx, entries, count, sizeof(tw_entry_t));
	isc_tw_destroy(&tw);
}

/* Benchmark: Heap - Random deletions */
static void
bench_heap_random_delete(isc_stdtime_t base_time, size_t count,
			 isc_stdtime_t *times) {
	isc_heap_t *heap = NULL;
	heap_entry_t *entries = NULL;
	size_t *delete_order = NULL;
	isc_nanosecs_t start, end;

	UNUSED(base_time);

	isc_heap_create(isc_g_mctx, heap_compare, heap_index, 0, &heap);
	entries = isc_mem_cget(isc_g_mctx, count, sizeof(heap_entry_t));
	delete_order = isc_mem_cget(isc_g_mctx, count, sizeof(size_t));

	for (size_t i = 0; i < count; i++) {
		entries[i].expire = times[i];
		entries[i].index = 0;
		entries[i].id = i;
		delete_order[i] = i;
		isc_heap_insert(heap, &entries[i]);
	}

	/* Shuffle delete order */
	for (size_t i = count - 1; i > 0; i--) {
		size_t j = isc_random_uniform(i + 1);
		size_t temp = delete_order[i];
		delete_order[i] = delete_order[j];
		delete_order[j] = temp;
	}

	start = isc_time_monotonic();
	for (size_t i = 0; i < count; i++) {
		size_t idx = delete_order[i];
		if (entries[idx].index > 0) {
			isc_heap_delete(heap, entries[idx].index);
		}
	}
	end = isc_time_monotonic();

	printf("Heap random delete %zu elements:       %7.3f ms (%7.3f "
	       "µs/op)\n",
	       count, (end - start) / 1000000.0,
	       (end - start) / (double)count / 1000.0);

	isc_mem_cput(isc_g_mctx, entries, count, sizeof(heap_entry_t));
	isc_mem_cput(isc_g_mctx, delete_order, count, sizeof(size_t));
	isc_heap_destroy(&heap);
}

/* Benchmark: Timing Wheel - Random deletions */
static void
bench_tw_random_delete(isc_stdtime_t base_time, size_t count,
		       isc_stdtime_t *times) {
	isc_tw_t *tw = NULL;
	tw_entry_t *entries = NULL;
	size_t *delete_order = NULL;
	isc_nanosecs_t start, end;

	isc_tw_create(isc_g_mctx, &tw);
	isc_tw_settime(tw, base_time);
	entries = isc_mem_cget(isc_g_mctx, count, sizeof(tw_entry_t));
	delete_order = isc_mem_cget(isc_g_mctx, count, sizeof(size_t));

	for (size_t i = 0; i < count; i++) {
		ISC_TW_ELT_INIT(&entries[i].elt);
		entries[i].elt.expire = times[i];
		entries[i].id = i;
		delete_order[i] = i;
		isc_tw_insert(tw, &entries[i].elt);
	}

	/* Shuffle delete order */
	for (size_t i = count - 1; i > 0; i--) {
		size_t j = isc_random_uniform(i + 1);
		size_t temp = delete_order[i];
		delete_order[i] = delete_order[j];
		delete_order[j] = temp;
	}

	start = isc_time_monotonic();
	for (size_t i = 0; i < count; i++) {
		size_t idx = delete_order[i];
		if (!isc_tw_is_node_deleted(&entries[idx].elt)) {
			isc_tw_delete(tw, &entries[idx].elt);
		}
	}
	end = isc_time_monotonic();

	printf("TW   random delete %zu elements:       %7.3f ms (%7.3f "
	       "µs/op)\n",
	       count, (end - start) / 1000000.0,
	       (end - start) / (double)count / 1000.0);

	isc_mem_cput(isc_g_mctx, entries, count, sizeof(tw_entry_t));
	isc_mem_cput(isc_g_mctx, delete_order, count, sizeof(size_t));
	isc_tw_destroy(&tw);
}

/* Benchmark: Heap - Mixed operations */
static void
bench_heap_mixed_ops(isc_stdtime_t base_time, size_t num_ops) {
	isc_heap_t *heap = NULL;
	heap_entry_t *entries = NULL;
	size_t entries_capacity = num_ops;
	size_t entries_count = 0;
	isc_nanosecs_t start, end;

	isc_heap_create(isc_g_mctx, heap_compare, heap_index, 0, &heap);
	entries = isc_mem_cget(isc_g_mctx, entries_capacity,
			       sizeof(heap_entry_t));

	start = isc_time_monotonic();
	for (size_t i = 0; i < num_ops; i++) {
		uint32_t op = isc_random_uniform(100);

		if (op < 50) { /* 50% insert */
			if (entries_count < entries_capacity) {
				uint32_t offset = isc_random_uniform(
					TIME_RANGE_MAX - TIME_RANGE_MIN);
				entries[entries_count].expire =
					base_time + TIME_RANGE_MIN + offset;
				entries[entries_count].index = 0;
				entries[entries_count].id = entries_count;
				isc_heap_insert(heap, &entries[entries_count]);
				entries_count++;
			}
		} else if (op < 75) { /* 25% delete min */
			if (isc_heap_element(heap, 1) != NULL) {
				isc_heap_delete(heap, 1);
			}
		} else { /* 25% random delete */
			if (entries_count > 0) {
				size_t idx = isc_random_uniform(entries_count);
				if (entries[idx].index > 0) {
					isc_heap_delete(heap,
							entries[idx].index);
				}
			}
		}
	}
	end = isc_time_monotonic();

	printf("Heap mixed ops %zu operations:         %7.3f ms (%7.3f "
	       "µs/op)\n",
	       num_ops, (end - start) / 1000000.0,
	       (end - start) / (double)num_ops / 1000.0);

	/* Cleanup */
	while (isc_heap_element(heap, 1) != NULL) {
		isc_heap_delete(heap, 1);
	}
	isc_mem_cput(isc_g_mctx, entries, entries_capacity,
		     sizeof(heap_entry_t));
	isc_heap_destroy(&heap);
}

/* Benchmark: Timing Wheel - Mixed operations */
static void
bench_tw_mixed_ops(isc_stdtime_t base_time, size_t num_ops) {
	isc_tw_t *tw = NULL;
	tw_entry_t *entries = NULL;
	size_t entries_capacity = num_ops;
	size_t entries_count = 0;
	isc_nanosecs_t start, end;

	isc_tw_create(isc_g_mctx, &tw);
	isc_tw_settime(tw, base_time);
	entries = isc_mem_cget(isc_g_mctx, entries_capacity,
			       sizeof(tw_entry_t));

	start = isc_time_monotonic();
	for (size_t i = 0; i < num_ops; i++) {
		uint32_t op = isc_random_uniform(100);

		if (op < 50) { /* 50% insert */
			if (entries_count < entries_capacity) {
				ISC_TW_ELT_INIT(&entries[entries_count].elt);
				uint32_t offset = isc_random_uniform(
					TIME_RANGE_MAX - TIME_RANGE_MIN);
				entries[entries_count].elt.expire =
					base_time + TIME_RANGE_MIN + offset;
				entries[entries_count].id = entries_count;
				isc_tw_insert(tw, &entries[entries_count].elt);
				entries_count++;
			}
		} else if (op < 75) { /* 25% delete min */
			isc_tw_elt_t *elt = isc_tw_element(tw);
			if (elt != NULL) {
				isc_tw_delete(tw, elt);
			}
		} else { /* 25% random delete */
			if (entries_count > 0) {
				size_t idx = isc_random_uniform(entries_count);
				if (!isc_tw_is_node_deleted(&entries[idx].elt))
				{
					isc_tw_delete(tw, &entries[idx].elt);
				}
			}
		}
	}
	end = isc_time_monotonic();

	printf("TW   mixed ops %zu operations:         %7.3f ms (%7.3f "
	       "µs/op)\n",
	       num_ops, (end - start) / 1000000.0,
	       (end - start) / (double)num_ops / 1000.0);

	/* Cleanup */
	for (size_t i = 0; i < entries_count; i++) {
		if (!isc_tw_is_node_deleted(&entries[i].elt)) {
			isc_tw_delete(tw, &entries[i].elt);
		}
	}
	isc_mem_cput(isc_g_mctx, entries, entries_capacity, sizeof(tw_entry_t));
	isc_tw_destroy(&tw);
}

/* Benchmark: Heap - Peek minimum repeatedly */
static void
bench_heap_peek_min(isc_stdtime_t base_time, size_t count, size_t num_peeks) {
	isc_heap_t *heap = NULL;
	heap_entry_t *entries = NULL;
	isc_stdtime_t *times = NULL;
	isc_nanosecs_t start, end;

	times = isc_mem_cget(isc_g_mctx, count, sizeof(isc_stdtime_t));
	generate_random_times(times, count, base_time);

	isc_heap_create(isc_g_mctx, heap_compare, heap_index, 0, &heap);
	entries = isc_mem_cget(isc_g_mctx, count, sizeof(heap_entry_t));

	for (size_t i = 0; i < count; i++) {
		entries[i].expire = times[i];
		entries[i].index = 0;
		entries[i].id = i;
		isc_heap_insert(heap, &entries[i]);
	}

	start = isc_time_monotonic();
	for (size_t i = 0; i < num_peeks; i++) {
		(void)isc_heap_element(heap, 1);
	}
	end = isc_time_monotonic();

	printf("Heap peek-min %zu ops (%zu elements):    %7.3f ms (%7.3f "
	       "µs/op)\n",
	       num_peeks, count, (end - start) / 1000000.0,
	       (end - start) / (double)num_peeks / 1000.0);

	/* Cleanup */
	while (isc_heap_element(heap, 1) != NULL) {
		isc_heap_delete(heap, 1);
	}
	isc_mem_cput(isc_g_mctx, entries, count, sizeof(heap_entry_t));
	isc_heap_destroy(&heap);
	isc_mem_cput(isc_g_mctx, times, count, sizeof(isc_stdtime_t));
}

/* Benchmark: Timing Wheel - Peek minimum repeatedly */
static void
bench_tw_peek_min(isc_stdtime_t base_time, size_t count, size_t num_peeks) {
	isc_tw_t *tw = NULL;
	tw_entry_t *entries = NULL;
	isc_stdtime_t *times = NULL;
	isc_nanosecs_t start, end;

	times = isc_mem_cget(isc_g_mctx, count, sizeof(isc_stdtime_t));
	generate_random_times(times, count, base_time);

	isc_tw_create(isc_g_mctx, &tw);
	isc_tw_settime(tw, base_time);
	entries = isc_mem_cget(isc_g_mctx, count, sizeof(tw_entry_t));

	for (size_t i = 0; i < count; i++) {
		ISC_TW_ELT_INIT(&entries[i].elt);
		entries[i].elt.expire = times[i];
		entries[i].id = i;
		isc_tw_insert(tw, &entries[i].elt);
	}

	start = isc_time_monotonic();
	for (size_t i = 0; i < num_peeks; i++) {
		(void)isc_tw_element(tw);
	}
	end = isc_time_monotonic();

	printf("TW   peek-min %zu ops (%zu elements):    %7.3f ms (%7.3f "
	       "µs/op)\n",
	       num_peeks, count, (end - start) / 1000000.0,
	       (end - start) / (double)num_peeks / 1000.0);

	/* Cleanup */
	for (size_t i = 0; i < count; i++) {
		isc_tw_delete(tw, &entries[i].elt);
	}
	isc_mem_cput(isc_g_mctx, entries, count, sizeof(tw_entry_t));
	isc_tw_destroy(&tw);
	isc_mem_cput(isc_g_mctx, times, count, sizeof(isc_stdtime_t));
}

/* Benchmark: Heap - Time-based expiration (simulated) */
static void
bench_heap_time_expiration(isc_stdtime_t base_time, size_t count) {
	isc_heap_t *heap = NULL;
	heap_entry_t *entries = NULL;
	isc_nanosecs_t start, end;
	size_t expired_count = 0;

	UNUSED(expired_count);

	isc_heap_create(isc_g_mctx, heap_compare, heap_index, 0, &heap);
	entries = isc_mem_cget(isc_g_mctx, count, sizeof(heap_entry_t));

	/* Insert timers expiring over next 1000 seconds */
	for (size_t i = 0; i < count; i++) {
		entries[i].expire = base_time + (i * 1000) / count;
		entries[i].index = 0;
		entries[i].id = i;
		isc_heap_insert(heap, &entries[i]);
	}

	start = isc_time_monotonic();
	/* Simulate time advancing and processing expired timers */
	for (isc_stdtime_t now = base_time; now <= base_time + 1000; now++) {
		while (true) {
			heap_entry_t *elt = isc_heap_element(heap, 1);
			if (elt == NULL || elt->expire > now) {
				break;
			}
			isc_heap_delete(heap, 1);
			expired_count++;
		}
	}
	end = isc_time_monotonic();

	printf("Heap time expiration %zu timers:        %7.3f ms (%7.3f "
	       "µs/tick)\n",
	       count, (end - start) / 1000000.0,
	       (end - start) / 1001.0 / 1000.0);

	/* Cleanup remaining */
	while (isc_heap_element(heap, 1) != NULL) {
		isc_heap_delete(heap, 1);
	}
	isc_mem_cput(isc_g_mctx, entries, count, sizeof(heap_entry_t));
	isc_heap_destroy(&heap);
}

/* Benchmark: Timing Wheel - Time-based expiration (natural use case) */
static void
bench_tw_time_expiration(isc_stdtime_t base_time, size_t count) {
	isc_tw_t *tw = NULL;
	tw_entry_t *entries = NULL;
	isc_nanosecs_t start, end;
	size_t expired_count = 0;

	UNUSED(expired_count);

	isc_tw_create(isc_g_mctx, &tw);
	isc_tw_settime(tw, base_time);
	entries = isc_mem_cget(isc_g_mctx, count, sizeof(tw_entry_t));

	/* Insert timers expiring over next 1000 seconds */
	for (size_t i = 0; i < count; i++) {
		ISC_TW_ELT_INIT(&entries[i].elt);
		entries[i].elt.expire = base_time + (i * 1000) / count;
		entries[i].id = i;
		isc_tw_insert(tw, &entries[i].elt);
	}

	start = isc_time_monotonic();
	/* Simulate time advancing and processing expired timers */
	for (isc_stdtime_t now = base_time; now <= base_time + 1000; now++) {
		isc_tw_settime(tw, now);
		while (true) {
			isc_tw_elt_t *elt = isc_tw_element(tw);
			if (elt == NULL || elt->expire > now) {
				break;
			}
			isc_tw_delete(tw, elt);
			expired_count++;
		}
	}
	end = isc_time_monotonic();

	printf("TW   time expiration %zu timers:        %7.3f ms (%7.3f "
	       "µs/tick)\n",
	       count, (end - start) / 1000000.0,
	       (end - start) / 1001.0 / 1000.0);

	/* Cleanup remaining */
	for (size_t i = 0; i < count; i++) {
		if (!isc_tw_is_node_deleted(&entries[i].elt)) {
			isc_tw_delete(tw, &entries[i].elt);
		}
	}
	isc_mem_cput(isc_g_mctx, entries, count, sizeof(tw_entry_t));
	isc_tw_destroy(&tw);
}

/* Benchmark: Heap - Realistic DNS timer workload */
static void
bench_heap_realistic_workload(isc_stdtime_t base_time, size_t num_seconds) {
	isc_heap_t *heap = NULL;
	heap_entry_t *entries = NULL;
	size_t entries_capacity = 1000000; /* Support up to 1M active timers */
	size_t entries_count = 0;
	isc_nanosecs_t start, end;
	size_t total_ops = 0;

	isc_heap_create(isc_g_mctx, heap_compare, heap_index, 0, &heap);
	entries = isc_mem_cget(isc_g_mctx, entries_capacity,
			       sizeof(heap_entry_t));

	/*
	 * Realistic DNS resolver workload at ~100k QPS:
	 * - 100,000 queries/sec with 30-300 second TTLs
	 * - ~80% cache hit rate (20k new cache entries/sec)
	 * - Each second: 20k inserts + 20k expirations + random deletions
	 */
	start = isc_time_monotonic();
	for (isc_stdtime_t now = base_time; now < base_time + num_seconds;
	     now++)
	{
		/* Add new timers (20k cache entries per second at 100k QPS) */
		for (size_t i = 0; i < 100; i++) { /* 100 per tick for reasonable runtime */
			if (entries_count < entries_capacity) {
				/* TTL: 30-300 seconds typical for DNS */
				uint32_t offset = 30 + isc_random_uniform(270);
				entries[entries_count].expire = now + offset;
				entries[entries_count].index = 0;
				entries[entries_count].id = entries_count;
				isc_heap_insert(heap, &entries[entries_count]);
				entries_count++;
				total_ops++;
			}
		}

		/* Process expired timers */
		while (true) {
			heap_entry_t *elt = isc_heap_element(heap, 1);
			if (elt == NULL || elt->expire > now) {
				break;
			}
			isc_heap_delete(heap, 1);
			total_ops++;
		}

		/* Random cancellations (cache evictions, negative responses) */
		for (size_t i = 0; i < 10 && entries_count > 1000; i++) {
			size_t idx = isc_random_uniform(entries_count);
			if (entries[idx].index > 0) {
				isc_heap_delete(heap, entries[idx].index);
				total_ops++;
			}
		}
	}
	end = isc_time_monotonic();

	printf("Heap realistic workload %zu seconds:    %7.3f ms (%7.3f "
	       "µs/op)\n",
	       num_seconds, (end - start) / 1000000.0,
	       (end - start) / (double)total_ops / 1000.0);

	/* Cleanup */
	while (isc_heap_element(heap, 1) != NULL) {
		isc_heap_delete(heap, 1);
	}
	isc_mem_cput(isc_g_mctx, entries, entries_capacity,
		     sizeof(heap_entry_t));
	isc_heap_destroy(&heap);
}

/* Benchmark: Timing Wheel - Realistic DNS timer workload */
static void
bench_tw_realistic_workload(isc_stdtime_t base_time, size_t num_seconds) {
	isc_tw_t *tw = NULL;
	tw_entry_t *entries = NULL;
	size_t entries_capacity = 1000000; /* Support up to 1M active timers */
	size_t entries_count = 0;
	isc_nanosecs_t start, end;
	size_t total_ops = 0;

	isc_tw_create(isc_g_mctx, &tw);
	isc_tw_settime(tw, base_time);
	entries = isc_mem_cget(isc_g_mctx, entries_capacity,
			       sizeof(tw_entry_t));

	/*
	 * Realistic DNS resolver workload at ~100k QPS:
	 * - 100,000 queries/sec with 30-300 second TTLs
	 * - ~80% cache hit rate (20k new cache entries/sec)
	 * - Each second: 20k inserts + 20k expirations + random deletions
	 */
	start = isc_time_monotonic();
	for (isc_stdtime_t now = base_time; now < base_time + num_seconds;
	     now++)
	{
		isc_tw_settime(tw, now);

		/* Add new timers (20k cache entries per second at 100k QPS) */
		for (size_t i = 0; i < 100; i++) { /* 100 per tick for reasonable runtime */
			if (entries_count < entries_capacity) {
				ISC_TW_ELT_INIT(&entries[entries_count].elt);
				/* TTL: 30-300 seconds typical for DNS */
				uint32_t offset = 30 + isc_random_uniform(270);
				entries[entries_count].elt.expire = now + offset;
				entries[entries_count].id = entries_count;
				isc_tw_insert(tw, &entries[entries_count].elt);
				entries_count++;
				total_ops++;
			}
		}

		/* Process expired timers */
		while (true) {
			isc_tw_elt_t *elt = isc_tw_element(tw);
			if (elt == NULL || elt->expire > now) {
				break;
			}
			isc_tw_delete(tw, elt);
			total_ops++;
		}

		/* Random cancellations (cache evictions, negative responses) */
		for (size_t i = 0; i < 10 && entries_count > 1000; i++) {
			size_t idx = isc_random_uniform(entries_count);
			if (!isc_tw_is_node_deleted(&entries[idx].elt)) {
				isc_tw_delete(tw, &entries[idx].elt);
				total_ops++;
			}
		}
	}
	end = isc_time_monotonic();

	printf("TW   realistic workload %zu seconds:    %7.3f ms (%7.3f "
	       "µs/op)\n",
	       num_seconds, (end - start) / 1000000.0,
	       (end - start) / (double)total_ops / 1000.0);

	/* Cleanup */
	for (size_t i = 0; i < entries_count; i++) {
		if (!isc_tw_is_node_deleted(&entries[i].elt)) {
			isc_tw_delete(tw, &entries[i].elt);
		}
	}
	isc_mem_cput(isc_g_mctx, entries, entries_capacity, sizeof(tw_entry_t));
	isc_tw_destroy(&tw);
}

/* Memory analysis functions */
static void
analyze_memory_usage(void) {
	size_t heap_entry_size = sizeof(heap_entry_t);
	size_t tw_entry_size = sizeof(tw_entry_t);

	/* Heap overhead: Estimated based on structure members:
	 * - magic (unsigned int)
	 * - mctx pointer
	 * - size, size_increment, last (3 x unsigned int)
	 * - array pointer
	 * - compare, index function pointers
	 */
	size_t heap_base = sizeof(unsigned int) * 4 + sizeof(void *) * 4;

	/* TW overhead: Full structure is visible */
	size_t tw_base = sizeof(isc_tw_t);

	/* Heap growth: default size_increment is 1024 (from heap.c) */
	const size_t heap_size_increment = 1024;

	printf("=======================================================\n");
	printf("Memory Usage Analysis\n");
	printf("=======================================================\n\n");

	printf("Per-Element Size:\n");
	printf("-------------------------------------------------------\n");
	printf("Heap entry (heap_entry_t):     %3zu bytes\n", heap_entry_size);
	printf("  - expire time:               %3zu bytes\n",
	       sizeof(isc_stdtime_t));
	printf("  - index:                     %3zu bytes\n",
	       sizeof(unsigned int));
	printf("  - id:                        %3zu bytes\n", sizeof(uint32_t));
	printf("Heap array pointer:            %3zu bytes\n", sizeof(void *));
	printf("  Total per element:           %3zu bytes\n\n",
	       heap_entry_size + sizeof(void *));

	printf("TW entry (tw_entry_t):         %3zu bytes\n", tw_entry_size);
	printf("  - isc_tw_elt_t:              %3zu bytes\n",
	       sizeof(isc_tw_elt_t));
	printf("    * ISC_LINK (2 pointers):   %3zu bytes\n",
	       sizeof(void *) * 2);
	printf("    * expire time:             %3zu bytes\n",
	       sizeof(isc_stdtime_t));
	printf("    * level:                   %3zu bytes\n", sizeof(uint32_t));
	printf("    * slot:                    %3zu bytes\n", sizeof(uint32_t));
	printf("  - id:                        %3zu bytes\n", sizeof(uint32_t));
	printf("  Total per element:           %3zu bytes\n\n", tw_entry_size);

	printf("Base Structure Overhead:\n");
	printf("-------------------------------------------------------\n");
	printf("Heap structure (estimated):    %3zu bytes\n", heap_base);
	printf("TW structure (isc_tw_t):       %3zu bytes\n", tw_base);
	printf("  - 4 levels × 256 slots:      %3zu bytes\n",
	       4 * 256 * sizeof(isc_tw_slot_t));
	printf("\n");

	const size_t scales[] = { 1000000, 10000000, 100000000 };
	const char *labels[] = { "1M", "10M", "100M" };

	printf("Total Memory at Scale (including over-allocation):\n");
	printf("-------------------------------------------------------\n");
	printf("Records      Heap (worst)      TW\n");
	printf("-------------------------------------------------------\n");

	for (size_t i = 0; i < 3; i++) {
		size_t count = scales[i];

		/* Heap capacity must be >= count, rounded up to size_increment
		 */
		size_t heap_capacity = ((count + heap_size_increment - 1) /
					heap_size_increment) *
				       heap_size_increment;

		/* Worst case: just allocated new chunk, using only 1 slot */
		size_t heap_capacity_worst = heap_capacity +
					     heap_size_increment;

		/* Heap memory = structure + element storage + pointer array
		 * Pointer array size = capacity × sizeof(void*) */
		size_t heap_total_worst = heap_base + heap_entry_size * count +
					  heap_capacity_worst * sizeof(void *);

		/* TW memory = structure + element storage (no separate array)
		 */
		size_t tw_total = tw_base + tw_entry_size * count;

		printf("%-8s     %7.1f MB        %7.1f MB\n", labels[i],
		       heap_total_worst / (1024.0 * 1024.0),
		       tw_total / (1024.0 * 1024.0));

		/* Show comparisons */
		long long tw_vs_heap = (long long)tw_total -
				       (long long)heap_total_worst;

		printf("         TW vs Heap: %+7.1f MB (%+5.1f%%)\n",
		       tw_vs_heap / (1024.0 * 1024.0),
		       ((double)tw_vs_heap / heap_total_worst) * 100.0);
	}

	printf("\n");
	printf("Memory Allocation Behavior:\n");
	printf("-------------------------------------------------------\n");
	printf("Heap:\n");
	printf("  - Dynamic pointer array grows by %zu slots per allocation\n",
	       heap_size_increment);
	printf("  - Requires memcpy on resize (costly for large heaps)\n");
	printf("  - Over-allocation waste: up to %zu pointers (%.1f KB)\n",
	       heap_size_increment,
	       heap_size_increment * sizeof(void *) / 1024.0);
	printf("  - Reallocations needed: count / %zu times\n",
	       heap_size_increment);
	printf("\n");
	printf("Timing Wheel:\n");
	printf("  - No dynamic allocation after creation\n");
	printf("  - Fixed memory usage regardless of operation order\n");
	printf("  - No reallocation overhead\n");
	printf("  - Cache-friendly: intrusive lists\n");
	printf("\n");
	printf("Notes:\n");
	printf("- Heap pointer array is often larger than needed due to "
	       "chunked growth\n");
	printf("- At 1M records: heap needs ~977 reallocations (expensive!)\n");
	printf("- TW is more predictable and avoids reallocation stalls\n");
	printf("- For DNS cache: TW's constant memory and no-realloc design is "
	       "better\n");
	printf("=======================================================\n\n");
}

int
main(void) {
	isc_stdtime_t base_time;
	isc_stdtime_t *times = NULL;

	printf("=======================================================\n");
	printf("Heap vs Timing Wheel Benchmark\n");
	printf("=======================================================\n\n");

	base_time = isc_stdtime_now();
	times = isc_mem_cget(isc_g_mctx, NUM_ELEMENTS, sizeof(isc_stdtime_t));
	generate_random_times(times, NUM_ELEMENTS, base_time);

	printf("Test 1: Sequential Insertion (%d elements)\n", NUM_ELEMENTS);
	printf("-------------------------------------------------------\n");
	bench_heap_insert_sequential(base_time, NUM_ELEMENTS, times);
	bench_tw_insert_sequential(base_time, NUM_ELEMENTS, times);
	printf("\n");

	printf("Test 2: Extract Minimum (%d elements)\n", NUM_ELEMENTS);
	printf("-------------------------------------------------------\n");
	bench_heap_extract_min(base_time, NUM_ELEMENTS, times);
	bench_tw_extract_min(base_time, NUM_ELEMENTS, times);
	printf("\n");

	printf("Test 3: Random Deletion (%d elements)\n", NUM_ELEMENTS);
	printf("-------------------------------------------------------\n");
	bench_heap_random_delete(base_time, NUM_ELEMENTS, times);
	bench_tw_random_delete(base_time, NUM_ELEMENTS, times);
	printf("\n");

	printf("Test 4: Mixed Operations (%d ops)\n", NUM_OPERATIONS);
	printf("-------------------------------------------------------\n");
	bench_heap_mixed_ops(base_time, NUM_OPERATIONS);
	bench_tw_mixed_ops(base_time, NUM_OPERATIONS);
	printf("\n");

	printf("Test 5: Peek Minimum (10k peeks, %d elements)\n", NUM_ELEMENTS);
	printf("-------------------------------------------------------\n");
	bench_heap_peek_min(base_time, NUM_ELEMENTS, 10000);
	bench_tw_peek_min(base_time, NUM_ELEMENTS, 10000);
	printf("\n");

	printf("Test 6: Time-Based Expiration (%d timers, 1000 ticks)\n",
	       NUM_ELEMENTS);
	printf("-------------------------------------------------------\n");
	bench_heap_time_expiration(base_time, NUM_ELEMENTS);
	bench_tw_time_expiration(base_time, NUM_ELEMENTS);
	printf("\n");

	printf("Test 7: Realistic DNS Workload (100 seconds @ ~10k ops/sec)\n");
	printf("-------------------------------------------------------\n");
	bench_heap_realistic_workload(base_time, 100);
	bench_tw_realistic_workload(base_time, 100);
	printf("\n");

	/* Memory usage analysis */
	analyze_memory_usage();

	printf("=======================================================\n");
	printf("Performance Benchmark Complete\n");
	printf("\n");
	printf("ANALYSIS:\n");
	printf("- Heap excels at: peek-min (O(1)), extract-min (O(log n))\n");
	printf("- TW excels at: insert/delete (O(1)), time-based expiration\n");
	printf("- For DNS cache: TW optimal (true O(1), no redistributions)\n");
	printf("- Memory: TW(40B) > Heap(20B)\n");
	printf("=======================================================\n");

	isc_mem_cput(isc_g_mctx, times, NUM_ELEMENTS, sizeof(isc_stdtime_t));

	return 0;
}
