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

/*! \file */

/*%
 *	Types and functions below meant to be used for internal zone
 *	modules only, and associated unit tests.
 */

#define UDP_REQUEST_TIMEOUT 5 /*%< 5 seconds */
#define UDP_REQUEST_RETRIES 2
#define TCP_REQUEST_TIMEOUT \
	(UDP_REQUEST_TIMEOUT * (UDP_REQUEST_RETRIES + 1) + 1)

typedef struct {
	dns_diff_t *diff;
	bool offline;
} dns__zonediff_t;

isc_result_t
dns__zone_updatesigs(dns_diff_t *diff, dns_db_t *db, dns_dbversion_t *version,
		     dst_key_t *zone_keys[], unsigned int nkeys,
		     dns_zone_t *zone, isc_stdtime_t inception,
		     isc_stdtime_t expire, isc_stdtime_t keyxpire,
		     isc_stdtime_t now, dns__zonediff_t *zonediff);

isc_result_t
dns__zone_lookup_nsec3param(dns_zone_t *zone, dns_rdata_nsec3param_t *lookup,
			    dns_rdata_nsec3param_t *param,
			    unsigned char saltbuf[255], bool resalt);

void
dns__zone_lock(dns_zone_t *zone);
/*%<
 *      Locks the zone.
 *
 * Requires:
 *\li   'zone' to be a valid zone.
 */

void
dns__zone_unlock(dns_zone_t *zone);
/*%<
 *      Unlocks the zone.
 *
 * Requires:
 *\li   'zone' to be a valid zone.
 */

bool
dns__zone_locked(dns_zone_t *zone);
/*%<
 *      Checks if the zone is locked.
 *
 * Requires:
 *\li   'zone' to be a valid zone.
 *
 * Returns:
 *\li   true if the zone is locked, false otherwise.
 */

bool
dns__zone_loaded(dns_zone_t *zone);
/*%<
 *      Checks if the zone is loaded.
 *
 * Requires:
 *\li   'zone' to be a valid zone.
 *
 * Returns:
 *\li   true if the zone is loaded, false otherwise.
 */

bool
dns__zone_exiting(dns_zone_t *zone);
/*%<
 *      Checks if the zone is exiting.
 *
 * Requires:
 *\li   'zone' to be a valid zone.
 *
 * Returns:
 *\li   true if the zone is exiting, false otherwise.
 */

void
dns__zone_stats_increment(dns_zone_t *zone, isc_statscounter_t counter);
/*%
 *      Increment resolver-related statistics counters
 *
 * Requires:
 *\li   'zone' to be a valid zone, and locked.
 */

dns_notifyctx_t *
dns__zone_getnotifyctx(dns_zone_t *zone, dns_rdatatype_t type);
/*%<
 *	Returns the notify context.
 *
 * Require:
 *\li	'zone' to be a valid zone.
 */

void
dns__zonemgr_getnotifyrl(dns_zonemgr_t *zmgr, isc_ratelimiter_t **prl);
/*%<
 *	Get the NOTIFY requests rate limiter
 *
 * Requires:
 *\li	'zmgr' to be a valid zone manager
 */

void
dns__zonemgr_getstartupnotifyrl(dns_zonemgr_t *zmgr, isc_ratelimiter_t **prl);
/*%<
 *	Get the startup NOTIFY requests rate limiter
 *
 * Requires:
 *\li	'zmgr' to be a valid zone manager
 */

void
dns__zonemgr_tlsctx_attach(dns_zonemgr_t *zmgr,
			   isc_tlsctx_cache_t **ptlsctx_cache);
/*%<
 *	Attach to TLS client context cache used for zone transfers via
 * 	encrypted transports (e.g. XoT).
 *
 *	The obtained reference needs to be detached by a call to
 *	'isc_tlsctx_cache_detach()' when not needed anymore.
 *
 * Requires:
 *\li	'zmgr' is a valid zone manager.
 *\li	'ptlsctx_cache' is not 'NULL' and points to 'NULL'.
 */

void
dns__zone_getisself(dns_zone_t *zone, dns_isselffunc_t *isself, void **arg);
/*%<
 *	Returns the isself callback function and argument.
 *
 * Require:
 *\li	'zone' to be a valid zone.
 *\li	'isself' is not NULL.
 *\li	'arg' is not NULL and '*arg' is NULL.
 */

void
dns__zone_iattach_locked(dns_zone_t *source, dns_zone_t **target);
/*%<
 *      Attach '*target' to 'source' incrementing its internal
 *      reference count.  This is intended for use by operations
 *      such as zone transfers that need to prevent the zone
 *      object from being freed but not from shutting down.
 *
 * Require:
 *\li   The caller is running in the context of the zone's loop.
 *\li   'zone' to be a valid zone, already locked.
 *\li   'target' to be non NULL and '*target' to be NULL.
 */

void
dns__zone_idetach_locked(dns_zone_t **zonep);
/*%<
 *      Detach from a zone decrementing its internal reference count.
 *      If there are no more internal or external references to the
 *      zone, it will be freed.
 *
 * Require:
 *\li   The caller is running in the context of the zone's loop.
 *\li   'zonep' to point to a valid zone, already locked.
 */

isc_refcount_t *
dns__zone_irefs(dns_zone_t *zone);
/*%<
 *	Get the reference count of a zone.
 *
 *	Requires:
 *	\li 'zone' to be a valid zone.
 */

void
dns__zone_free(dns_zone_t *zone);
/*
 *	Free a zone.  Because we require that there be no more
 *	outstanding events or references, no locking is necessary.
 *
 *	Requires:
 *	\li 'zone' to be a valid zone, unlocked.
 */

bool
dns__zone_free_check(dns_zone_t *zone);
/*
 *	Check if a zone is ready to be freed.
 *
 *	Requires:
 *	\li 'zone' to be a valid zone, locked.
 */
