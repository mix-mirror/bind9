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

/*
 * Private header for the rdata vtable dispatch system.
 *
 * Each rdata type implementation exports a dns_rdata_typedesc_t
 * descriptor containing method pointers and type metadata.  The
 * registry (rdata_registry.c) collects these into a lookup table
 * used by the dispatch functions in rdata.c.
 */

#include <stdbool.h>

#include <isc/buffer.h>
#include <isc/lex.h>
#include <isc/mem.h>
#include <isc/region.h>
#include <isc/result.h>

#include <dns/name.h>
#include <dns/types.h>

/*
 * Context structure for the totext_ functions.
 * Contains formatting options for rdata-to-text conversion.
 */
typedef struct dns_rdata_textctx {
	const dns_name_t *origin;      /*%< Current origin, or NULL. */
	dns_masterstyle_flags_t flags; /*%< DNS_STYLEFLAG_*  */
	unsigned int width;	       /*%< Width of rdata column. */
	const char *linebreak;	       /*%< Line break string. */
} dns_rdata_textctx_t;

/*
 * Method table for an rdata type implementation.
 *
 * NULL pointers mean "use default behavior" (binary copy/compare
 * for wire operations, RFC 3597 unknown format for text, etc.).
 */
typedef struct dns_rdata_methods {
	isc_result_t (*fromtext)(int rdclass, dns_rdatatype_t type,
				 isc_lex_t *lexer, const dns_name_t *origin,
				 unsigned int options, isc_buffer_t *target,
				 dns_rdatacallbacks_t *callbacks);

	isc_result_t (*totext)(dns_rdata_t *rdata, dns_rdata_textctx_t *tctx,
			       isc_buffer_t *target);

	isc_result_t (*fromwire)(int rdclass, dns_rdatatype_t type,
				 isc_buffer_t *source, dns_decompress_t dctx,
				 isc_buffer_t *target);

	isc_result_t (*towire)(dns_rdata_t *rdata, dns_compress_t *cctx,
			       isc_buffer_t *target);

	int (*compare)(const dns_rdata_t *rdata1, const dns_rdata_t *rdata2);

	int (*casecompare)(const dns_rdata_t *rdata1,
			   const dns_rdata_t *rdata2);

	isc_result_t (*fromstruct)(int rdclass, dns_rdatatype_t type,
				   void *source, isc_buffer_t *target);

	isc_result_t (*tostruct)(const dns_rdata_t *rdata, void *target,
				 isc_mem_t *mctx);

	void (*freestruct)(void *source);

	isc_result_t (*additionaldata)(dns_rdata_t *rdata,
				       const dns_name_t *owner,
				       dns_additionaldatafunc_t add, void *arg);

	isc_result_t (*digest)(dns_rdata_t *rdata, dns_digestfunc_t digest,
			       void *arg);

	bool (*checkowner)(const dns_name_t *name, dns_rdataclass_t rdclass,
			   dns_rdatatype_t type, bool wildcard);

	bool (*checknames)(dns_rdata_t *rdata, const dns_name_t *owner,
			   dns_name_t *bad);
} dns_rdata_methods_t;

/*
 * Type descriptor combining identity, metadata, and methods.
 *
 * Entries with methods==NULL are meta-types (IXFR, AXFR, etc.)
 * that have names and attributes but no rdata operations.
 */
typedef struct dns_rdata_typedesc {
	dns_rdatatype_t type;
	dns_rdataclass_t rdclass; /* 0 = class-independent */
	const char *name;	  /* "MX", "A", etc. */
	unsigned int attributes;
	const dns_rdata_methods_t *methods;
} dns_rdata_typedesc_t;

/*
 * Direct-indexed type descriptor table for types 0..262, defined in
 * rdata_registry.c.  Types above 262 (TA, DLV, KEYDATA) are handled
 * by explicit checks in the lookup functions.
 */
#define DNS_RDATA_TYPEDESC_TABLE_SIZE 263

extern const dns_rdata_typedesc_t *const
	dns__rdata_typedesc_table[DNS_RDATA_TYPEDESC_TABLE_SIZE];

/* Outlier type descriptors (sparse, above the dense table range) */
extern const dns_rdata_typedesc_t dns__rdata_ta_typedesc;
extern const dns_rdata_typedesc_t dns__rdata_dlv_typedesc;
extern const dns_rdata_typedesc_t dns__rdata_keydata_typedesc;

/*
 * Look up a type descriptor by type code only (ignoring class).
 * Dense table for 0..262, explicit checks for outliers.
 */
static inline const dns_rdata_typedesc_t *
dns__rdata_typedesc_bytype(dns_rdatatype_t type) {
	if (type < DNS_RDATA_TYPEDESC_TABLE_SIZE) {
		return dns__rdata_typedesc_table[type];
	}
	if (type == 32768) {
		return &dns__rdata_ta_typedesc;
	}
	if (type == 32769) {
		return &dns__rdata_dlv_typedesc;
	}
	if (type == 65533) {
		return &dns__rdata_keydata_typedesc;
	}
	return NULL;
}

/*
 * Look up the type descriptor for a given (rdclass, type) pair.
 * Returns NULL for class mismatches on class-specific types.
 */
static inline const dns_rdata_typedesc_t *
dns__rdata_typedesc_lookup(dns_rdataclass_t rdclass, dns_rdatatype_t type) {
	const dns_rdata_typedesc_t *td = dns__rdata_typedesc_bytype(type);

	/*
	 * Class-specific types (rdclass != 0) are only valid for their
	 * own class.  Return NULL for mismatches so the caller falls
	 * through to default (unknown-type) handling.
	 */
	if (td != NULL && td->rdclass != 0 && td->rdclass != rdclass) {
		return NULL;
	}

	return td;
}

/*
 * Look up a type descriptor by type name (case-insensitive).
 * Uses first-character switch dispatch.
 *
 * Returns NULL if the name is not recognized.
 */
const dns_rdata_typedesc_t *
dns__rdata_typedesc_fromtext(const char *name, unsigned int length);
