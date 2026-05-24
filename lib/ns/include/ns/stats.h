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

/*! \file include/ns/stats.h */

#include <isc/mem.h>
#include <isc/stats.h>
#include <isc/statsmulti.h>

#include <ns/types.h>

/*%
 * Server statistics counters.  Used as isc_statscounter_t values.
 */
enum {
	ns_statscounter_requestv4 = 0,
	ns_statscounter_requestv6 = 1,
	ns_statscounter_edns0in = 2,
	ns_statscounter_badednsver = 3,
	ns_statscounter_tsigin = 4,
	ns_statscounter_sig0in = 5,
	ns_statscounter_invalidsig = 6,
	ns_statscounter_requesttcp = 7,

	ns_statscounter_authrej = 8,
	ns_statscounter_recurserej = 9,
	ns_statscounter_xfrrej = 10,
	ns_statscounter_updaterej = 11,

	ns_statscounter_response = 12,
	ns_statscounter_truncatedresp = 13,
	ns_statscounter_edns0out = 14,
	ns_statscounter_tsigout = 15,
	ns_statscounter_sig0out = 16,

	ns_statscounter_success = 17,
	ns_statscounter_authans = 18,
	ns_statscounter_nonauthans = 19,
	ns_statscounter_referral = 20,
	ns_statscounter_nxrrset = 21,
	ns_statscounter_servfail = 22,
	ns_statscounter_formerr = 23,
	ns_statscounter_nxdomain = 24,
	ns_statscounter_recursion = 25,
	ns_statscounter_duplicate = 26,
	ns_statscounter_dropped = 27,
	ns_statscounter_failure = 28,

	ns_statscounter_xfrdone = 29,

	ns_statscounter_updatereqfwd = 30,
	ns_statscounter_updaterespfwd = 31,
	ns_statscounter_updatefwdfail = 32,
	ns_statscounter_updatedone = 33,
	ns_statscounter_updatefail = 34,
	ns_statscounter_updatebadprereq = 35,

	ns_statscounter_dns64 = 36,

	ns_statscounter_ratedropped = 37,
	ns_statscounter_rateslipped = 38,

	ns_statscounter_rpz_rewrites = 39,

	ns_statscounter_udp = 40,
	ns_statscounter_tcp = 41,

	ns_statscounter_nsidopt = 42,
	ns_statscounter_expireopt = 43,
	ns_statscounter_otheropt = 44,
	ns_statscounter_ecsopt = 45,
	ns_statscounter_padopt = 46,
	ns_statscounter_keepaliveopt = 47,
	ns_statscounter_zoneversionopt = 48,

	ns_statscounter_nxdomainredirect = 49,
	ns_statscounter_nxdomainredirect_rlookup = 50,

	ns_statscounter_cookiein = 51,
	ns_statscounter_cookiebadsize = 52,
	ns_statscounter_cookiebadtime = 53,
	ns_statscounter_cookienomatch = 54,
	ns_statscounter_cookiematch = 55,
	ns_statscounter_cookienew = 56,
	ns_statscounter_badcookie = 57,

	ns_statscounter_nxdomainsynth = 58,
	ns_statscounter_nodatasynth = 59,
	ns_statscounter_wildcardsynth = 60,

	ns_statscounter_trystale = 61,
	ns_statscounter_usedstale = 62,

	ns_statscounter_prefetch = 63,
	ns_statscounter_keytagopt = 64,

	ns_statscounter_reclimitdropped = 65,

	ns_statscounter_updatequota = 66,
	ns_statscounter_dot = 67,
	ns_statscounter_doh = 68,
	ns_statscounter_dohplain = 69,

	ns_statscounter_proxyudp = 70,
	ns_statscounter_proxytcp = 71,
	ns_statscounter_proxydot = 72,
	ns_statscounter_proxydoh = 73,
	ns_statscounter_proxydohplain = 74,
	ns_statscounter_encryptedproxydot = 75,
	ns_statscounter_encryptedproxydoh = 76,

	ns_statscounter_max = 77,
};

/*%
 * Highwater statistics counters. Used as isc_statscounter_t values
 * for the separate highwater stats structure.
 */
enum {
	ns_highwater_tcp = 0,
	ns_highwater_recursive = 1,
	ns_highwater_recursclients = 2,

	ns_highwater_max = 3,
};

void
ns_stats_create(isc_mem_t *mctx, isc_statsmulti_t **statsp,
		isc_stats_t **hwstatsp);

void
ns_stats_increment(isc_statsmulti_t *stats, isc_statscounter_t counter);

void
ns_stats_update_if_greater(isc_stats_t *hwstats, isc_statscounter_t counter,
			   isc_statscounter_t value);

isc_statscounter_t
ns_stats_get_counter(isc_statsmulti_t *stats, isc_statscounter_t counter);

isc_statscounter_t
ns_stats_get_highwater(isc_stats_t *hwstats, isc_statscounter_t counter);

void
ns_stats_reset_highwater(isc_stats_t *hwstats, isc_statscounter_t counter);
