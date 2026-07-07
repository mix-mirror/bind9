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

/*! \file dns/rdataslab.h
 * \brief
 * Implements storage of rdatasets into slabs of memory.
 *
 * MP:
 *\li	Clients of this module must impose any required synchronization.
 *
 * Reliability:
 *\li	This module deals with low-level byte streams.  Errors in any of
 *	the functions are likely to crash the server or corrupt memory.
 *
 *\li	If the caller passes invalid memory references, these functions are
 *	likely to crash the server or corrupt memory.
 *
 * Resources:
 *\li	None.
 *
 * Security:
 *\li	None.
 *
 * Standards:
 *\li	None.
 */

/***
 *** Imports
 ***/

/* Add -DDNS_SLABHEADER_TRACE=1 to CFLAGS for detailed reference tracing */

#include <stdalign.h>
#include <stdbool.h>

#include <isc/atomic.h>
#include <isc/stdtime.h>
#include <isc/urcu.h>

#include <dns/name.h>
#include <dns/rdataset.h>
#include <dns/types.h>

#define DNS_RDATASLAB_FORCE 0x1
#define DNS_RDATASLAB_EXACT 0x2

#define DNS_RDATASLAB_OFFLINE 0x01 /* RRSIG is for offline DNSKEY */

struct dns_slabheader_proof {
	dns_name_t	name;
	void	       *neg;
	void	       *negsig;
	dns_rdatatype_t type;
};

#define DNS_SLABHEADER_FOREACH(pos, head)                 \
	dns_slabheader_t *pos = NULL, *pos##_next = NULL; \
	cds_list_for_each_entry_safe(pos, pos##_next, head, headers_link)

/*
 * RCU-safe traversal for lock-free readers; the writers must mutate
 * the list with cds_list_add_rcu()/cds_list_del_rcu() only.
 */
#define DNS_SLABHEADER_FOREACH_RCU(pos, head) \
	dns_slabheader_t *pos = NULL;         \
	cds_list_for_each_entry_rcu(pos, head, headers_link)

struct dns_slabheader {
	_Atomic(uint16_t)    attributes;
	_Atomic(dns_trust_t) trust;

	/*%
	 * The tid of the loop whose SIEVE-LRU holds this header (see
	 * ftcache.c).  Written before the header is linked into the
	 * sieve and read by deleting threads to find the owner's
	 * zombie stack; both happen under the owning node's lock.
	 */
	uint16_t sieve_tid;

	struct urcu_ref references;

	isc_mem_t *mctx;

	/*%
	 * Locked by the owning node's lock.
	 */
	isc_stdtime_t  expire;
	dns_typepair_t typepair;

	dns_slabheader_proof_t *noqname;
	dns_slabheader_proof_t *closest;

	dns_slabheader_t *related;

	struct cds_list_head headers_link;

	/*%
	 * The database node objects containing this rdataset, if any.
	 */
	dns_dbnode_t *node;

	/*%
	 * Case vector.  If the bit is set then the corresponding
	 * character in the owner name needs to be AND'd with 0x20,
	 * rendering that character upper case.
	 *
	 * The deferred-destruction state shares this storage: it is
	 * written only after the last reference has been dropped (see
	 * slabheader_release() in rdataslab.c), while upper[] is only
	 * ever read while a reference is held.  'wfs_node' links the
	 * dead header on the graveyard stack; 'rcu_head' is used by
	 * the batch carrier only.
	 */
	union {
		unsigned char upper[32];
		struct {
			struct rcu_head	    rcu_head;
			struct cds_wfs_node wfs_node;
		};
	};

	/* Used for stale refresh */
	_Atomic(isc_stdtime_t) last_refresh_fail_ts;

	uint16_t nitems;

	/*% Used for SIEVE-LRU (cache) */
	bool visited;
	ISC_LINK(struct dns_slabheader) lrulink;

	/*%
	 * Hands a dead header over to the sieve owner's zombie stack
	 * (see header_delete() in ftcache.c).  A dedicated field: the
	 * push happens while the sieve (and possibly readers) still
	 * hold references, so no reader-visible storage -- upper[],
	 * related, headers_link -- can be reused for it.
	 */
	struct cds_wfs_node zombie_link;

	/*%
	 * Flexible member indicates the address of the raw data
	 * following this header.  This needs to be aligned to the
	 * size of the pointer because we cast raw[] to slabheader
	 * in rdataset_getheader().
	 */
	alignas(sizeof(void *)) unsigned char raw[];
};

/*
 * The reference counting uses liburcu's urcu_ref so that lock-free
 * readers can acquire a reference with dns_slabheader_tryref()
 * (urcu_ref_get_unless_zero()); dropping the last reference defers
 * the actual destruction by an RCU grace period (see
 * slabheader_release() in rdataslab.c), which keeps the memory valid
 * for any reader still inspecting the header inside its RCU read-side
 * critical section.  dns_slabheader_tryref() returning false means
 * the header is dead and must be skipped.
 */
#define dns_slabheader_ref(ptr) \
	dns_slabheader__ref(ptr, __func__, __FILE__, __LINE__)
#define dns_slabheader_unref(ptr) \
	dns_slabheader__unref(ptr, __func__, __FILE__, __LINE__)
#define dns_slabheader_attach(ptr, ptrp) \
	dns_slabheader__attach(ptr, ptrp, __func__, __FILE__, __LINE__)
#define dns_slabheader_detach(ptrp) \
	dns_slabheader__detach(ptrp, __func__, __FILE__, __LINE__)
#define dns_slabheader_tryref(ptr) \
	dns_slabheader__tryref(ptr, __func__, __FILE__, __LINE__)

dns_slabheader_t *
dns_slabheader__ref(dns_slabheader_t *header, const char *func,
		    const char *file, unsigned int line);
void
dns_slabheader__unref(dns_slabheader_t *header, const char *func,
		      const char *file, unsigned int line);
void
dns_slabheader__attach(dns_slabheader_t *header, dns_slabheader_t **headerp,
		       const char *func, const char *file, unsigned int line);
void
dns_slabheader__detach(dns_slabheader_t **headerp, const char *func,
		       const char *file, unsigned int line);
bool
dns_slabheader__tryref(dns_slabheader_t *header, const char *func,
		       const char *file, unsigned int line);

enum {
	DNS_SLABHEADERATTR_NONEXISTENT = 1 << 0,
	DNS_SLABHEADERATTR_STALE = 1 << 1,
	DNS_SLABHEADERATTR_IGNORE = 1 << 2,
	DNS_SLABHEADERATTR_NXDOMAIN = 1 << 3,
	DNS_SLABHEADERATTR_RESIGN = 1 << 4,
	DNS_SLABHEADERATTR_STATCOUNT = 1 << 5,
	DNS_SLABHEADERATTR_OPTOUT = 1 << 6,
	DNS_SLABHEADERATTR_NEGATIVE = 1 << 7,
	DNS_SLABHEADERATTR_PREFETCH = 1 << 8,
	DNS_SLABHEADERATTR_CASESET = 1 << 9,
	DNS_SLABHEADERATTR_ZEROTTL = 1 << 10,
	DNS_SLABHEADERATTR_CASEFULLYLOWER = 1 << 11,
	DNS_SLABHEADERATTR_STALE_WINDOW = 1 << 12,
	/*%
	 * The header has been removed from its node's header list but
	 * may still be linked in an LRU structure owned by another
	 * thread, which will reap it lazily (see ftcache.c).
	 */
	DNS_SLABHEADERATTR_DEAD = 1 << 13,
	/*%
	 * Dropping the last reference must defer the destruction by an
	 * RCU grace period because lock-free readers can still be
	 * inspecting the header (see ftcache.c, which sets this on
	 * every header it publishes).  Headers without this attribute
	 * are destroyed synchronously (qpcache holds node locks, so it
	 * must not pay the deferral in delayed overmem accounting).
	 */
	DNS_SLABHEADERATTR_RCUFREE = 1 << 14,
};

/* clang-format off : RemoveParentheses */
#define DNS_SLABHEADER_GETATTR(header, attribute) \
	(atomic_load_acquire(&(header)->attributes) & (attribute))
/* clang-format on */
#define DNS_SLABHEADER_SETATTR(header, attribute) \
	atomic_fetch_or_release(&(header)->attributes, attribute)
#define DNS_SLABHEADER_CLRATTR(header, attribute) \
	atomic_fetch_and_release(&(header)->attributes, ~(attribute))

extern dns_rdatasetmethods_t dns_rdataslab_rdatasetmethods;

/***
 *** Functions
 ***/

#define dns_rdataslab_fromrdataset(rdataset, mctx, region, limit)            \
	dns_rdataslab__fromrdataset(rdataset, mctx, region, limit, __func__, \
				    __FILE__, __LINE__)
isc_result_t
dns_rdataslab__fromrdataset(dns_rdataset_t *rdataset, isc_mem_t *mctx,
			    isc_region_t *region, uint32_t limit,
			    const char *func, const char *file,
			    const unsigned int line);
/*%<
 * Allocate space for a slab to hold the data in rdataset, and copy the
 * data into it.  The resulting slab will be returned in 'region'.
 *
 * dns_rdataslab_fromrdataset() allocates space for a dns_slabheader object
 * and the memory needed for a raw slab, and partially initializes
 * it, setting the type, and trust fields to match rdataset->type,
 * rdataset->covers, and rdataset->trust.
 *
 * Requires:
 *\li	'rdataset' is valid.
 *
 * Ensures:
 *\li	'region' will have base pointing to the start of allocated memory,
 *	with the slabified region beginning at region->base + reservelen.
 *	region->length contains the total length allocated.
 *
 * Returns:
 *\li	ISC_R_SUCCESS		- successful completion
 *\li	ISC_R_NOSPACE		- more than 64k RRs
 *\li	DNS_R_TOOMANYRECORDS	- more than max-records-per-rrset RRs
 *\li	DNS_R_SINGLETON		- singleton type has more than one RR
 */

unsigned int
dns_rdataslab_size(dns_slabheader_t *header);
/*%<
 * Return the total size of the rdataslab following 'header'.
 *
 * Requires:
 *\li	'header' points to a slabheader with an rdataslab following it.
 *
 * Returns:
 *\li	The number of bytes in the slab, plus the header.
 */

unsigned int
dns_rdataslab_count(dns_slabheader_t *header);
/*%<
 * Return the number of records in the rdataslab following 'header'.
 *
 * Requires:
 *\li	'header' points to a slabheader with an rdataslab following it.
 *
 * Returns:
 *\li	The number of records in the slab.
 */

bool
dns_rdataslab_equal(dns_slabheader_t *header1, dns_slabheader_t *header2);
/*%<
 * Compare two rdataslabs for equality.  This does _not_ do a full
 * DNSSEC comparison.
 *
 * Requires:
 *\li	'header1' and 'header1' point to slab headers followed by slabs.
 *
 * Returns:
 *\li	true if the slabs are equal, false otherwise.
 */
bool
dns_rdataslab_equalx(dns_slabheader_t *header1, dns_slabheader_t *header2,
		     dns_rdataclass_t rdclass, dns_rdatatype_t type);
/*%<
 * Compare two rdataslabs for DNSSEC equality.
 *
 * Requires:
 *\li	'header1' and 'header2' point to slab headers followed by slabs.
 *
 * Returns:
 *\li	true if the slabs are equal, #false otherwise.
 */

#define dns_slabheader_reset(header, node) \
	dns_slabheader__reset(header, node, __func__, __FILE__, __LINE__)
void
dns_slabheader__reset(dns_slabheader_t *h, dns_dbnode_t *node, const char *func,
		      const char *file, const unsigned int line);
/*%<
 * Reset an rdataslab header 'h' so it can be used to store data in
 * database node 'node'.
 */

#define dns_slabheader_new(mctx, node) \
	dns_slabheader__new(mctx, node, __func__, __FILE__, __LINE__)
dns_slabheader_t *
dns_slabheader__new(isc_mem_t *mctx, dns_dbnode_t *node, const char *func,
		    const char *file, const unsigned int line);
/*%<
 * Allocate memory for an rdataslab header and initialize it for use
 * in database node 'node'.
 */

void
dns_slabheader_freeproof(isc_mem_t *mctx, dns_slabheader_proof_t **proof);
/*%<
 * Free all memory associated with a nonexistence proof.
 */
