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
#include <isc/statsmulti.h>
#include <isc/util.h>

#include <ns/stats.h>

void
ns_stats_create(isc_mem_t *mctx, isc_statsmulti_t **statsp) {
	REQUIRE(statsp != NULL && *statsp == NULL);

	isc_statsmulti_create(mctx, statsp, ns_additive_count, ns_highwater_count);
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
ns_stats_decrement(isc_statsmulti_t *stats, isc_statscounter_t counter) {
	REQUIRE(stats != NULL);

	isc_statsmulti_decrement(stats, counter);
}

void
ns_stats_update_if_greater(isc_statsmulti_t *stats, isc_statscounter_t counter,
			   isc_statscounter_t value) {
	REQUIRE(stats != NULL);

	isc_statsmulti_update_if_greater(stats, counter, value);
}

isc_statscounter_t
ns_stats_get_counter(isc_statsmulti_t *stats, isc_statscounter_t counter) {
	REQUIRE(stats != NULL);

	/* Check if this is a highwater counter */
	if (counter == ns_statscounter_tcphighwater || counter == ns_statscounter_recurshighwater) {
		return ns_stats_get_highwater(stats, counter);
	}

	return isc_statsmulti_get_counter(stats, counter);
}

isc_statscounter_t
ns_stats_get_highwater(isc_statsmulti_t *stats, isc_statscounter_t counter) {
	REQUIRE(stats != NULL);

	return isc_statsmulti_get_highwater(stats, counter);
}

void
ns_stats_reset_highwater(isc_statsmulti_t *stats, isc_statscounter_t counter) {
	REQUIRE(stats != NULL);

	isc_statsmulti_reset_highwater(stats, counter);
}
