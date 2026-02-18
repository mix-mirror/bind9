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

#include <isc/refcount.h>
#include <isc/stdtime.h>

#include <dns/types.h>

/*
 * Represents either:
 *
 * - a DELEG-based delegation, with associated IPv4/IPv6 addresses,
 *   include-delegi names as well as name server names.
 *
 * - an NS-based delegation, where associated server names and A/AAAA glues.
 *
 * Must not be used by the caller without an attached `dns_delegset_t` owner.
 *
 * TODO:
 *
 * because a `dns_deleg_t` can be of only one type, fields address, delegi and
 * nameserver must be a union as:
 *
 *   union { isc_netaddrlist_t addresses, dns_namelist_t names } data;
 *
 * and there must be a type:
 *
 *   enum short type { DNS_DELEGTYPE_ADDRESS,
 *                     DNS_DELEGTYPE_NS,
 *                     DNS_DELEGTYPE_DELEGI }
 *
 * this saves 4 pointers (well, 3 pointers, with padding) and also makes clearer
 * from the code the exclusivity of addresses, delegi and nameservers (which is
 * exclusive in the protocol).
 */
struct dns_deleg {
	isc_netaddrlist_t address;
	dns_namelist_t	  delegi;
	dns_namelist_t	  nameserver;

	ISC_LINK(dns_deleg_t) link;
};

/*
 * A delegation set. Once it's added to the delegation DB, it gets a
 * read-only object thus doesn't require any locking nor copying when the caller
 * gets it.
 *
 * The TTL is common to all the DELEG RR for the same zonecut
 * https://datatracker.ietf.org/doc/html/rfc2181#section-5.2
 *
 * When the delegation is NS-based, the TTL is the lowest TTL of the referral
 * (either of the NS, A or AAAA glues).
 *
 * If a zone contains NS and DELEG delegations, this delegation must only store
 * the DELEG ones. (This is resolver responsibility to ensure that.)
 */
struct dns_delegset {
	unsigned int   magic;
	isc_mem_t     *mctx;
	isc_refcount_t references;

	dns_deleglist_t deleg;
	dns_ttl_t	ttl;

	/*
	 * Used only when a delegation is built from a local zone.
	 */
	bool staticstub;
};
ISC_REFCOUNT_DECL(dns_delegset);

/*
 * A dns_delegset_t can be used as a delegation database (in which case, it is
 * attached to the DB), or independently (for instance, when building a
 * dns_delegset_t object from a non-cached RR delegation).
 */
#define DNS_DELEGSET_DBATTACHED_MAGIC ISC_MAGIC('D', 'e', 'G', 'S')
#define DNS_DELEGSET_DBATTACHED_VALID(delegset) \
	ISC_MAGIC_VALID(delegset, DNS_DELEGSET_DBATTACHED_MAGIC)

#define DNS_DELEGSET_DBDETACHED_MAGIC ISC_MAGIC('D', 'e', 'G', 's')
#define DNS_DELEGSET_DBDETACHED_VALID(delegset) \
	ISC_MAGIC_VALID(delegset, DNS_DELEGSET_DBDETACHED_MAGIC)

#define DNS_DELEGSET_VALID(delegset)                \
	(DNS_DELEGSET_DBATTACHED_VALID(delegset) || \
	 DNS_DELEGSET_DBDETACHED_VALID(delegset))

typedef struct dns_delegdb dns_delegdb_t;
ISC_REFCOUNT_DECL(dns_delegdb);

/*
 * Allocate and initialize the delegation database. `db` is attached to the
 * caller.
 */
void
dns_deleg_init(dns_delegdb_t **db);

/*
 * Shutdown and detach the delegation database. Allocated `dns_delegset_t`
 * still owned by callers will remain alive until they are detached.
 */
void
dns_deleg_shutdownanddetach(dns_delegdb_t **db);

/*
 * Lookup for delegations of a given name in the DB. If found, the zonecut is
 * written and the delegation set is attached to the caller, so it must be
 * detached once the caller is done with it. Even though `delegset` is not const
 * (for convenience with ISC_LIST_FOREACH macros, _attach, _detach functions,
 * etc.) the `delegset` _is_ a read-only object, and must not be modified.
 *
 * If only the zonecut is needed from the caller, `delegset` can be NULL, it
 * won't be attached.
 *
 * The zonecut must be a initialized and attached to a buffer.
 *
 * If `now` is 0, the actual expiration time is `isc_stdtime_now()`.
 */
isc_result_t
dns_deleg_lookup(dns_delegdb_t *db, const dns_name_t *name, isc_stdtime_t now,
		 unsigned int options, dns_name_t *zonecut,
		 dns_name_t *deepestzonecut, dns_delegset_t **delegset);

/*
 * Allocate and attach to the caller a new empty delegation set, but do not
 * attach it in the DB yet, so the following API can be used to set its various
 * properties.
 */
void
dns_deleg_allocset(dns_delegdb_t *db, dns_delegset_t **delegsetp);

/*
 * Allocate a new deleg struct and insert it into the delegation set. Can't be
 * used on delegation set already attached in the DB.
 */
void
dns_deleg_allocdeleg(dns_delegset_t *delegset, dns_deleg_t **delegp);

/*
 * Add a new IP into a delegation. Can't be used on a delegation from a
 * delegation set already attached in the DB.
 */
void
dns_deleg_addaddr(dns_delegset_t *delegset, dns_deleg_t *deleg,
		  const isc_netaddr_t *addr);

/*
 * Add a new DELEGI name into a delegation. Can't be used on a delegation from
 * a delegation set already attached in the DB.
 */
void
dns_deleg_adddelegi(dns_delegset_t *delegset, dns_deleg_t *deleg,
		    const dns_name_t *name);

/*
 * Add a new nameserver name into a delegation. Can't be used on a delegation
 * from a delegation set already attached in the DB.
 */
void
dns_deleg_addns(dns_delegset_t *delegset, dns_deleg_t *deleg,
		const dns_name_t *name);

/*
 * Attach a delegation set into the DB for the given zonecut and expiration
 * time. Then detach it from the caller. The delegation node is now read-only.
 */
void
dns_deleg_writeset(dns_delegdb_t *db, const dns_name_t *zonecut,
		   dns_ttl_t expire, dns_delegset_t **node);

/*
 * Dump the database in a textual format for a given name. If a closest zonecut
 * matching the name is found, its delegation data is dumped. If the name is
 * NULL, the whole database is dumped.
 *
 * Only the non expired entries will be dumped. If `now` is 0, the actual
 * expiration time is `isc_stdtime_now()`.
 */
void
dns_deleg_dump(dns_delegdb_t *db, const dns_name_t *name, isc_stdtime_t now,
	       isc_buffer_t *b);

/*
 * Convert an NS rdataset into a delegset containing a single delegation (with
 * possibly multiple nameserver).
 */
void
dns_deleg_fromrdataset(dns_rdataset_t *rdataset, dns_delegset_t **delegsetp);

/*
 * Delete all the delegations.
 */
void
dns_deleg_flush(dns_delegdb_t *db);

/*
 * Delete a delegation matching a name. If `tree` is true, this will also delete
 * all names below `name`.
 */
isc_result_t
dns_deleg_delete(dns_delegdb_t *db, const dns_name_t *name, bool tree);
