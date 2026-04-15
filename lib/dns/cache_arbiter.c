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

#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <isc/async.h>
#include <isc/atomic.h>
#include <isc/log.h>
#include <isc/loop.h>
#include <isc/magic.h>
#include <isc/mem.h>
#include <isc/timer.h>
#include <isc/urcu.h>
#include <isc/util.h>

#include <dns/adb.h>
#include <dns/cache.h>
#include <dns/cache_arbiter.h>
#include <dns/deleg.h>
#include <dns/view.h>

#define DNS_CACHE_ARBITER_MAGIC	       ISC_MAGIC('C', 'A', 'r', 'b')
#define VALID_CACHE_ARBITER(a)	       ISC_MAGIC_VALID(a, DNS_CACHE_ARBITER_MAGIC)

enum { POOL_QPCACHE = 0, POOL_ADB = 1, POOL_DELEGDB = 2, POOL_COUNT = 3 };

#define ARBITER_TICK_INTERVAL_S 5

/*
 * Hysteresis: only apply a change if |new - current| > (1/8) of current.
 * Prevents small oscillations from thrashing the pool sizes.
 */
#define HYSTERESIS_DEN 8

struct dns_cache_arbiter {
	unsigned int magic;
	isc_mem_t *mctx;
	/*
	 * View is a weak pointer; the view owns the arbiter's lifetime and
	 * must stop + destroy it before detaching its pools.
	 */
	dns_view_t *view;

	size_t total_budget;
	size_t floor[POOL_COUNT];
	size_t ceiling[POOL_COUNT];
	size_t current_size[POOL_COUNT];
	uint64_t last_pressure[POOL_COUNT];

	bool apply_mode;
	uint64_t rebalance_count;

	isc_timer_t *timer;
};

static const char *pool_names[POOL_COUNT] = {
	"qpcache",
	"adb",
	"delegdb",
};

static void
sample(dns_cache_arbiter_t *a, size_t usage[POOL_COUNT],
       uint64_t pressure_delta[POOL_COUNT]) {
	uint64_t curr[POOL_COUNT] = { 0 };
	dns_adb_t *adb = NULL;

	curr[POOL_QPCACHE] = dns_cache_getevictions(a->view->cache);
	usage[POOL_QPCACHE] = dns_cache_getinuse(a->view->cache);

	if (a->view->deleg != NULL) {
		curr[POOL_DELEGDB] = dns_delegdb_getevictions(a->view->deleg);
		usage[POOL_DELEGDB] = dns_delegdb_getinuse(a->view->deleg);
	}

	dns_view_getadb(a->view, &adb);
	if (adb != NULL) {
		curr[POOL_ADB] = dns_adb_getevictions(adb);
		usage[POOL_ADB] = dns_adb_getinuse(adb);
		dns_adb_detach(&adb);
	}

	for (int i = 0; i < POOL_COUNT; i++) {
		pressure_delta[i] = curr[i] - a->last_pressure[i];
		a->last_pressure[i] = curr[i];
	}
}

static void
compute(dns_cache_arbiter_t *a, size_t usage[POOL_COUNT],
	uint64_t pressure_delta[POOL_COUNT],
	size_t new_size[POOL_COUNT]) {
	double weight[POOL_COUNT];
	double total_weight = 0;
	size_t elastic;
	bool was_clipped[POOL_COUNT] = { false };
	size_t clipped = 0;

	/*
	 * Demand weight: pools that are BOTH evicting heavily AND near
	 * their current cap want more budget.  Pools that are idle or
	 * under-filled carry near-zero weight.
	 */
	for (int i = 0; i < POOL_COUNT; i++) {
		double pressured = (double)(pressure_delta[i] + 1);
		double filled = a->current_size[i] > 0
					? (double)usage[i] /
						  (double)a->current_size[i]
					: 0.0;
		weight[i] = pressured * filled;
		total_weight += weight[i];
	}

	/*
	 * Elastic pool = total - Σ floor[i].  Floors are guaranteed
	 * regardless of demand; the elastic fraction is distributed
	 * according to demand weight.
	 */
	elastic = a->total_budget;
	for (int i = 0; i < POOL_COUNT; i++) {
		elastic -= a->floor[i];
	}

	for (int i = 0; i < POOL_COUNT; i++) {
		double share = total_weight > 0
				       ? weight[i] / total_weight
				       : 1.0 / POOL_COUNT;
		size_t proposed = a->floor[i] + (size_t)(elastic * share);
		if (proposed > a->ceiling[i]) {
			clipped += proposed - a->ceiling[i];
			proposed = a->ceiling[i];
			was_clipped[i] = true;
		}
		new_size[i] = proposed;
	}

	/*
	 * Redistribute ceiling-clipped excess to non-clipped pools in
	 * proportion to their demand weight.  Maintains Σ new_size ==
	 * total_budget in the common case.
	 */
	if (clipped > 0) {
		double uncapped = 0;
		for (int i = 0; i < POOL_COUNT; i++) {
			if (!was_clipped[i]) {
				uncapped += weight[i];
			}
		}
		if (uncapped > 0) {
			for (int i = 0; i < POOL_COUNT; i++) {
				if (was_clipped[i]) {
					continue;
				}
				size_t extra = (size_t)((double)clipped *
							weight[i] / uncapped);
				new_size[i] += extra;
				if (new_size[i] > a->ceiling[i]) {
					new_size[i] = a->ceiling[i];
				}
			}
		}
	}

	/*
	 * Hysteresis: small moves are noise; only apply large changes.
	 */
	for (int i = 0; i < POOL_COUNT; i++) {
		size_t diff = new_size[i] > a->current_size[i]
				      ? new_size[i] - a->current_size[i]
				      : a->current_size[i] - new_size[i];
		if (diff * HYSTERESIS_DEN < a->current_size[i]) {
			new_size[i] = a->current_size[i];
		}
	}
}

static void
log_proposal(dns_cache_arbiter_t *a, size_t new_size[POOL_COUNT],
	     size_t usage[POOL_COUNT],
	     uint64_t pressure_delta[POOL_COUNT]) {
	int level = a->apply_mode ? ISC_LOG_INFO : ISC_LOG_DEBUG(3);

	for (int i = 0; i < POOL_COUNT; i++) {
		isc_log_write(DNS_LOGCATEGORY_DATABASE, DNS_LOGMODULE_CACHE,
			      level,
			      "cache-arbiter: view=%s pool=%s usage=%zu "
			      "budget=%zu proposed=%zu pressure=%" PRIu64
			      " %s",
			      a->view->name, pool_names[i], usage[i],
			      a->current_size[i], new_size[i],
			      pressure_delta[i],
			      a->apply_mode ? "applying" : "(observe-only)");
	}
}

static void
apply(dns_cache_arbiter_t *a, size_t new_size[POOL_COUNT]) {
	dns_adb_t *adb = NULL;

	for (int i = 0; i < POOL_COUNT; i++) {
		a->current_size[i] = new_size[i];
	}

	dns_cache_setcachesize(a->view->cache, new_size[POOL_QPCACHE]);
	if (a->view->deleg != NULL) {
		dns_delegdb_setsize(a->view->deleg, new_size[POOL_DELEGDB]);
	}

	dns_view_getadb(a->view, &adb);
	if (adb != NULL) {
		dns_adb_setadbsize(adb, new_size[POOL_ADB]);
		dns_adb_detach(&adb);
	}
}

/*
 * Sweep fan-out.  One sweep_arg_t is allocated per loop; the target
 * byte counts say how much each loop's SIEVE(s) should try to evict.
 *
 * The view is held by weak reference so the view's memory and pool
 * pointers remain valid until every queued sweep_cb has run, even if
 * the view's strong references hit zero meanwhile.  After shutdown the
 * pools' sweep helpers become no-ops (delegdb's QP nodes=NULL, adb's
 * view->adb=NULL, etc.), so late sweeps are safe.
 */
typedef struct sweep_arg {
	dns_view_t *view;
	isc_mem_t *mctx;
	size_t target[POOL_COUNT];
} sweep_arg_t;

static void
sweep_cb(void *arg) {
	sweep_arg_t *sa = arg;
	dns_view_t *view = sa->view;
	isc_mem_t *mctx = sa->mctx;

	if (sa->target[POOL_QPCACHE] > 0 && view->cache != NULL) {
		dns_cache_sweep(view->cache, sa->target[POOL_QPCACHE]);
	}
	if (sa->target[POOL_DELEGDB] > 0 && view->deleg != NULL) {
		dns_delegdb_sweep(view->deleg, sa->target[POOL_DELEGDB]);
	}
	if (sa->target[POOL_ADB] > 0) {
		dns_adb_t *adb = NULL;
		dns_view_getadb(view, &adb);
		if (adb != NULL) {
			dns_adb_sweep(adb, sa->target[POOL_ADB]);
			dns_adb_detach(&adb);
		}
	}

	isc_mem_put(mctx, sa, sizeof(*sa));
	dns_view_weakdetach(&view);
	isc_mem_detach(&mctx);
}

static void
fanout_sweeps(dns_cache_arbiter_t *a, size_t usage[POOL_COUNT]) {
	uint32_t nloops = isc_loopmgr_nloops();
	size_t target[POOL_COUNT] = { 0 };
	bool any = false;

	/*
	 * Pick a per-pool target equal to the overshoot above the pool's
	 * low-water line (87.5% of current_size), spread evenly across
	 * loops.  Pools under lo_water get no sweep.
	 */
	for (int i = 0; i < POOL_COUNT; i++) {
		size_t lo = a->current_size[i] - (a->current_size[i] >> 3);
		if (usage[i] > lo) {
			size_t excess = usage[i] - lo;
			target[i] = nloops > 0 ? excess / nloops : excess;
			if (target[i] == 0) {
				target[i] = 4096;
			}
			any = true;
		}
	}
	if (!any) {
		return;
	}

	for (uint32_t i = 0; i < nloops; i++) {
		sweep_arg_t *sa = isc_mem_get(a->mctx, sizeof(*sa));
		*sa = (sweep_arg_t){ 0 };
		dns_view_weakattach(a->view, &sa->view);
		isc_mem_attach(a->mctx, &sa->mctx);
		memcpy(sa->target, target, sizeof(target));
		isc_async_run(isc_loop_get(i), sweep_cb, sa);
	}
}

void
dns_cache_arbiter_tick(dns_cache_arbiter_t *a) {
	size_t usage[POOL_COUNT] = { 0 };
	uint64_t pressure_delta[POOL_COUNT] = { 0 };
	size_t new_size[POOL_COUNT] = { 0 };

	REQUIRE(VALID_CACHE_ARBITER(a));

	sample(a, usage, pressure_delta);
	compute(a, usage, pressure_delta, new_size);
	log_proposal(a, new_size, usage, pressure_delta);

	if (a->apply_mode) {
		apply(a, new_size);
	}

	fanout_sweeps(a, usage);

	a->rebalance_count++;
}

static void
timer_cb(void *arg) {
	dns_cache_arbiter_tick(arg);
}

void
dns_cache_arbiter_create(dns_view_t *view, size_t max_cache_size,
			 dns_cache_arbiter_t **arbiterp) {
	dns_cache_arbiter_t *a = NULL;

	REQUIRE(view != NULL);
	REQUIRE(max_cache_size > 0);
	REQUIRE(arbiterp != NULL && *arbiterp == NULL);

	a = isc_mem_get(view->mctx, sizeof(*a));
	*a = (dns_cache_arbiter_t){
		.magic = DNS_CACHE_ARBITER_MAGIC,
		.view = view,
		.total_budget = max_cache_size,
		.apply_mode = false,
	};
	isc_mem_attach(view->mctx, &a->mctx);

	/*
	 * Default floor / ceiling policy.  Floors sum to 62.5% of budget
	 * so 37.5% is elastic.  Ceilings sum to >100% intentionally —
	 * they cap per-pool growth under contention but the arbiter
	 * enforces Σ current_size == total_budget.
	 */
	a->floor[POOL_QPCACHE] = max_cache_size / 2;	    /* 50.00% */
	a->floor[POOL_ADB] = max_cache_size / 16;	    /* 6.25% */
	a->floor[POOL_DELEGDB] = max_cache_size / 16;	    /* 6.25% */

	a->ceiling[POOL_QPCACHE] = max_cache_size * 7 / 8;  /* 87.50% */
	a->ceiling[POOL_ADB] = max_cache_size / 4;	    /* 25.00% */
	a->ceiling[POOL_DELEGDB] = max_cache_size / 4;	    /* 25.00% */

	/*
	 * Initial sizes match the historic static 6/8 1/8 1/8 split so
	 * the first tick has a stable baseline to rebalance from.
	 */
	a->current_size[POOL_QPCACHE] = max_cache_size * 6 / 8;
	a->current_size[POOL_ADB] = max_cache_size / 8;
	a->current_size[POOL_DELEGDB] = max_cache_size / 8;

	*arbiterp = a;
}

void
dns_cache_arbiter_start(dns_cache_arbiter_t *a) {
	isc_interval_t interval;

	REQUIRE(VALID_CACHE_ARBITER(a));
	REQUIRE(a->timer == NULL);

	isc_interval_set(&interval, ARBITER_TICK_INTERVAL_S, 0);

	isc_timer_create(isc_loop_main(), timer_cb, a, &a->timer);
	isc_timer_start(a->timer, isc_timertype_ticker, &interval);
}

void
dns_cache_arbiter_stop(dns_cache_arbiter_t *a) {
	REQUIRE(VALID_CACHE_ARBITER(a));

	if (a->timer != NULL) {
		/*
		 * The timer lives on the main loop.  Stop and destroy may be
		 * called from any thread (e.g. view teardown), so dispatch
		 * the destroy to the timer's own loop.
		 */
		isc_timer_async_destroy(&a->timer);
	}
}

void
dns_cache_arbiter_setapply(dns_cache_arbiter_t *a, bool apply) {
	REQUIRE(VALID_CACHE_ARBITER(a));

	a->apply_mode = apply;
}

static void
free_arbiter_cb(void *arg) {
	dns_cache_arbiter_t *a = arg;

	REQUIRE(VALID_CACHE_ARBITER(a));

	a->magic = 0;
	isc_mem_putanddetach(&a->mctx, a, sizeof(*a));
}

void
dns_cache_arbiter_destroy(dns_cache_arbiter_t **arbiterp) {
	dns_cache_arbiter_t *a;

	REQUIRE(arbiterp != NULL);
	a = *arbiterp;
	REQUIRE(VALID_CACHE_ARBITER(a));
	*arbiterp = NULL;

	/*
	 * Stop the timer (running=false; any in-flight tick continues to
	 * completion but no new tick starts).  Dispatch the struct free
	 * to the main loop so it runs strictly after any in-flight or
	 * queued timer callback, which is also on the main loop.  This
	 * makes dns_cache_arbiter_destroy() safe to call from any thread.
	 */
	dns_cache_arbiter_stop(a);
	isc_async_run(isc_loop_main(), free_arbiter_cb, a);
}
