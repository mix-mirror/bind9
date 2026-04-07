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

/*! \file dns/zonemgr.h */

#include <dns/zone.h>

void
dns_zonemgr_create(isc_mem_t *mctx, dns_zonemgr_t **zmgrp);
/*%<
 * Create a zone manager.
 *
 * Requires:
 *\li	'mctx' to be a valid memory context.
 *\li	'zmgrp'	to point to a NULL pointer.
 */

isc_result_t
dns_zonemgr_createzone(dns_zonemgr_t *zmgr, dns_zone_t **zonep);
/*%<
 *	Allocate a new zone using a memory context from the
 *	zone manager's memory context pool.
 *
 * Require:
 *\li	'zmgr' to be a valid zone manager.
 *\li	'zonep' != NULL and '*zonep' == NULL.
 */

isc_result_t
dns_zonemgr_managezone(dns_zonemgr_t *zmgr, dns_zone_t *zone);
/*%<
 *	Bring the zone under control of a zone manager.
 *
 * Require:
 *\li	'zmgr' to be a valid zone manager.
 *\li	'zone' to be a valid zone.
 */

isc_result_t
dns_zonemgr_forcemaint(dns_zonemgr_t *zmgr);
/*%<
 * Force zone maintenance of all loaded zones managed by 'zmgr'
 * to take place at the system's earliest convenience.
 */

void
dns_zonemgr_shutdown(dns_zonemgr_t *zmgr);
/*%<
 *	Shut down the zone manager.
 *
 * Requires:
 *\li	'zmgr' to be a valid zone manager.
 */

void
dns_zonemgr_attach(dns_zonemgr_t *source, dns_zonemgr_t **target);
/*%<
 *	Attach '*target' to 'source' incrementing its external
 * 	reference count.
 *
 * Require:
 *\li	'zone' to be a valid zone.
 *\li	'target' to be non NULL and '*target' to be NULL.
 */

void
dns_zonemgr_detach(dns_zonemgr_t **zmgrp);
/*%<
 *	 Detach from a zone manager.
 *
 * Requires:
 *\li	'*zmgrp' is a valid, non-NULL zone manager pointer.
 *
 * Ensures:
 *\li	'*zmgrp' is NULL.
 */

void
dns_zonemgr_releasezone(dns_zonemgr_t *zmgr, dns_zone_t *zone);
/*%<
 *	Release 'zone' from the managed by 'zmgr'.  'zmgr' is implicitly
 *	detached from 'zone'.
 *
 * Requires:
 *\li	'zmgr' to be a valid zone manager.
 *\li	'zone' to be a valid zone.
 *\li	'zmgr' == 'zone->zmgr'
 *
 * Ensures:
 *\li	'zone->zmgr' == NULL;
 */

void
dns_zonemgr_settransfersin(dns_zonemgr_t *zmgr, uint32_t value);
/*%<
 *	Set the maximum number of simultaneous transfers in allowed by
 *	the zone manager.
 *
 * Requires:
 *\li	'zmgr' to be a valid zone manager.
 */

uint32_t
dns_zonemgr_gettransfersin(dns_zonemgr_t *zmgr);
/*%<
 *	Return the maximum number of simultaneous transfers in allowed.
 *
 * Requires:
 *\li	'zmgr' to be a valid zone manager.
 */

void
dns_zonemgr_settransfersperns(dns_zonemgr_t *zmgr, uint32_t value);
/*%<
 *	Set the number of zone transfers allowed per nameserver.
 *
 * Requires:
 *\li	'zmgr' to be a valid zone manager
 */

uint32_t
dns_zonemgr_gettransfersperns(dns_zonemgr_t *zmgr);
/*%<
 *	Return the number of transfers allowed per nameserver.
 *
 * Requires:
 *\li	'zmgr' to be a valid zone manager.
 */

void
dns_zonemgr_setcheckdsrate(dns_zonemgr_t *zmgr, unsigned int value);
/*%<
 *	Set the number of parental DS queries sent per second.
 *
 * Requires:
 *\li	'zmgr' to be a valid zone manager
 */

void
dns_zonemgr_setnotifyrate(dns_zonemgr_t *zmgr, unsigned int value);
/*%<
 *	Set the number of NOTIFY requests sent per second.
 *
 * Requires:
 *\li	'zmgr' to be a valid zone manager
 */

void
dns_zonemgr_setstartupnotifyrate(dns_zonemgr_t *zmgr, unsigned int value);
/*%<
 *	Set the number of startup NOTIFY requests sent per second.
 *
 * Requires:
 *\li	'zmgr' to be a valid zone manager
 */

void
dns_zonemgr_setserialqueryrate(dns_zonemgr_t *zmgr, unsigned int value);
/*%<
 *	Set the number of SOA queries sent per second.
 *
 * Requires:
 *\li	'zmgr' to be a valid zone manager
 */

unsigned int
dns_zonemgr_getnotifyrate(dns_zonemgr_t *zmgr);
/*%<
 *	Return the number of NOTIFY requests sent per second.
 *
 * Requires:
 *\li	'zmgr' to be a valid zone manager.
 */

unsigned int
dns_zonemgr_getstartupnotifyrate(dns_zonemgr_t *zmgr);
/*%<
 *	Return the number of startup NOTIFY requests sent per second.
 *
 * Requires:
 *\li	'zmgr' to be a valid zone manager.
 */

unsigned int
dns_zonemgr_getserialqueryrate(dns_zonemgr_t *zmgr);
/*%<
 *	Return the number of SOA queries sent per second.
 *
 * Requires:
 *\li	'zmgr' to be a valid zone manager.
 */

unsigned int
dns_zonemgr_getcount(dns_zonemgr_t *zmgr, dns_zonestate_t state);
/*%<
 *	Returns the number of zones in the specified state.
 *
 * Requires:
 *\li	'zmgr' to be a valid zone manager.
 *\li	'state' to be a valid DNS_ZONESTATE_ enum.
 */

void
dns_zonemgr_set_tlsctx_cache(dns_zonemgr_t	*zmgr,
			     isc_tlsctx_cache_t *tlsctx_cache);
/*%<
 *	Set the TLS client context cache used for zone transfers via
 *	encrypted transports (e.g. XoT).
 *
 * Requires:
 *\li	'zmgr' is a valid zone manager.
 *\li	'tlsctx_cache' is a valid TLS context cache.
 */

isc_result_t
dns_zonemgr_next_zone(dns_zone_t *zone, dns_zone_t **next);
/*%<
 * Find the next zone in the list of managed zones.
 *
 * Requires:
 *\li	'zone' to be valid
 *\li	The zone manager for the indicated zone MUST be locked
 *	by the caller.  This is not checked.
 *\li	'next' be non-NULL, and '*next' be NULL.
 *
 * Ensures:
 *\li	'next' points to a valid zone (result ISC_R_SUCCESS) or to NULL
 *	(result ISC_R_NOMORE).
 */

isc_result_t
dns_zonemgr_first_zone(dns_zonemgr_t *zmgr, dns_zone_t **first);
/*%<
 * Find the first zone in the list of managed zones.
 *
 * Requires:
 *\li	'zonemgr' to be valid
 *\li	The zone manager for the indicated zone MUST be locked
 *	by the caller.  This is not checked.
 *\li	'first' be non-NULL, and '*first' be NULL
 *
 * Ensures:
 *\li	'first' points to a valid zone (result ISC_R_SUCCESS) or to NULL
 *	(result ISC_R_NOMORE).
 */
