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

#include <isc/mem.h>
#include <isc/stats.h>
#include <isc/statsmulti.h>
#include <isc/util.h>

#include <ns/stats.h>

void
ns_stats_create(isc_mem_t *mctx, isc_statsmulti_t **statsp,
		isc_stats_t **hwstatsp) {
	REQUIRE(statsp != NULL && *statsp == NULL);
	REQUIRE(hwstatsp != NULL && *hwstatsp == NULL);

	isc_statsmulti_create(mctx, statsp, ns_statscounter_max);
	isc_stats_create(mctx, hwstatsp, ns_highwater_max);
}

/*%
 * Increment/Decrement methods
 */
void
ns_stats_increment(isc_statsmulti_t *stats, isc_statscounter_t counter) {
	REQUIRE(stats != NULL);

	isc_statsmulti_increment(stats, counter);
}

void
ns_stats_update_if_greater(isc_stats_t *hwstats, isc_statscounter_t counter,
			   isc_statscounter_t value) {
	REQUIRE(hwstats != NULL);

	isc_stats_update_if_greater(hwstats, counter, value);
}

isc_statscounter_t
ns_stats_get_counter(isc_statsmulti_t *stats, isc_statscounter_t counter) {
	REQUIRE(stats != NULL);

	return isc_statsmulti_get_counter(stats, counter);
}

isc_statscounter_t
ns_stats_get_highwater(isc_stats_t *hwstats, isc_statscounter_t counter) {
	REQUIRE(hwstats != NULL);

	return isc_stats_get_counter(hwstats, counter);
}

void
ns_stats_reset_highwater(isc_stats_t *hwstats, isc_statscounter_t counter) {
	REQUIRE(hwstats != NULL);

	isc_stats_set(hwstats, 0, counter);
}
