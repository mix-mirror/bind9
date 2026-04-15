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

#include <stdbool.h>
#include <stddef.h>

#include <dns/types.h>

/*%
 * The cache-budget arbiter dynamically rebalances the per-pool memory
 * budget of a view's three caches (qpcache, adb, delegdb) based on
 * observed eviction pressure.  Each pool has a guaranteed floor and a
 * hard ceiling; the elastic middle is distributed proportionally to
 * demand.  Attacker-driven skew toward one pool is contained by the
 * ceilings; a quiet pool is held above its floor.
 *
 * In observe-only mode (the default) the arbiter logs proposed budget
 * changes but does not apply them; this lets operators validate the
 * decisions on real workloads before any behavior change takes effect.
 *
 * Per-tick the arbiter also fans out a lightweight sweep() call to
 * every loop's SIEVE for any pool above its low-water threshold,
 * making idle pools shed stale / least-recently-used entries even
 * when insert traffic is concentrated elsewhere.
 */

void
dns_cache_arbiter_create(dns_view_t *view, size_t max_cache_size,
			 dns_cache_arbiter_t **arbiterp);
/*%<
 * Create a new arbiter for 'view' with total budget 'max_cache_size'.
 * The arbiter is created in observe-only mode; call
 * dns_cache_arbiter_setapply() to enable budget changes.  The timer is
 * not started until dns_cache_arbiter_start() is called.
 *
 * Requires:
 *\li	'view' is a valid view with cache and delegdb already attached.
 *\li	'max_cache_size' is non-zero.
 *\li	'arbiterp' is non-NULL and '*arbiterp' is NULL.
 */

void
dns_cache_arbiter_destroy(dns_cache_arbiter_t **arbiterp);
/*%<
 * Stop the arbiter timer (if running) and free the arbiter.  Must be
 * called before the view's pools are detached.
 */

void
dns_cache_arbiter_start(dns_cache_arbiter_t *arbiter);
/*%<
 * Start the periodic rebalance timer on the main loop.
 */

void
dns_cache_arbiter_stop(dns_cache_arbiter_t *arbiter);
/*%<
 * Stop the periodic rebalance timer.  Safe to call more than once or
 * before start.
 */

void
dns_cache_arbiter_tick(dns_cache_arbiter_t *arbiter);
/*%<
 * Run one rebalance cycle synchronously.  Samples per-pool usage and
 * pressure, computes new sizes, logs the proposal, and (if in apply
 * mode) applies the change and fans out sweeps.  Intended for the
 * periodic timer and for tests.
 *
 * Requires:
 *\li	Called from the main loop.
 */

void
dns_cache_arbiter_setapply(dns_cache_arbiter_t *arbiter, bool apply);
/*%<
 * Toggle between observe-only (false) and apply (true) mode.  In apply
 * mode the arbiter calls dns_cache_setcachesize / dns_adb_setadbsize /
 * dns_delegdb_setsize with the computed new budgets.
 */
