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

/*****
***** Module Info
*****/

/*! \file dns/fixedname.h
 * \brief
 * Fixed-size Names
 *
 * dns_fixedname_t is a convenience type containing a name and a byte array big
 * enough for the longest possible name. This is typically used for
 * stack-allocated names.
 *
 * MP:
 *\li	The caller must ensure any required synchronization.
 *
 * Reliability:
 *\li	No anticipated impact.
 *
 * Resources:
 *\li	Per dns_fixedname_t:
 *\code
 *		sizeof(dns_name_t) + 255 bytes + structure padding
 *\endcode
 *
 * Security:
 *\li	No anticipated impact.
 *
 * Standards:
 *\li	None.
 */

/*****
***** Imports
*****/

#include <isc/buffer.h>

#include <dns/name.h>

/*****
***** Types
*****/

struct dns_fixedname {
	dns_name_t    name;
	unsigned char data[DNS_NAME_MAXWIRE];
};

dns_fixedname_t *
dns_fixedname_init(dns_fixedname_t *fixed);
/*%<
 * Initialize the fixedname and return it. */

void
dns_fixedname_invalidate(dns_fixedname_t *fixed);

dns_name_t *
dns_fixedname_name(dns_fixedname_t *fixed);
/*%<
 * Return the name view, or NULL if fixed is NULL. The view may reference
 * external data; writing APIs always use the fixedname's own storage.
 */

dns_name_t *
dns_fixedname_initname(dns_fixedname_t *fixed);

void
dns_fixedname_reset(dns_fixedname_t *fixed);
/*%<
 * Reset the name, retaining non-absolute attributes. */

void
dns_fixedname_copy(const dns_name_t *source, dns_fixedname_t *fixed);
/*%<
 * Copy a valid name into an initialized fixedname, retaining destination
 * attributes except for the absolute flag. Source may alias the destination.
 */

void
dns_fixedname_fromregion(dns_fixedname_t *fixed, const isc_region_t *region);
/*%<
 * Copy the name at the beginning of a region into an initialized fixedname.
 * The region must contain valid labels, as for dns_name_fromregion().
 */

isc_result_t
dns_fixedname_fromtext(dns_fixedname_t *fixed, isc_buffer_t *source,
		       const dns_name_t *origin, unsigned int options);
/*%<
 * Parse text into an initialized fixedname. Relative names have origin
 * appended when non-NULL. DNS_NAME_DOWNCASE requests lowercase output.
 * On success, advance source past the consumed text.
 * Return ISC_R_SUCCESS, DNS_R_EMPTYLABEL, DNS_R_LABELTOOLONG,
 * DNS_R_BADESCAPE, DNS_R_BADDOTTEDQUAD, ISC_R_NOSPACE, or
 * ISC_R_UNEXPECTEDEND.
 */

isc_result_t
dns_fixedname_fromstring(dns_fixedname_t *fixed, const char *source,
			 const dns_name_t *origin, unsigned int options);
/*%<
 * Parse a string into an initialized fixedname without allocating storage.
 * Origin and options have the same meaning as dns_fixedname_fromtext().
 */

isc_result_t
dns_fixedname_fromwire(dns_fixedname_t *fixed, isc_buffer_t *source,
		       dns_decompress_t dctx);
/*%<
 * Decompress a wire name into an initialized fixedname, advancing source
 * on success. See dns_name_fromwire() for decompression rules and errors.
 */

isc_result_t
dns_fixedname_concatenate(const dns_name_t *prefix, const dns_name_t *suffix,
			  dns_fixedname_t *fixed);
/*%<
 * Concatenate names into an initialized fixedname. Either input may be NULL
 * or alias the destination. An absolute prefix requires an empty suffix.
 * Return DNS_R_NAMETOOLONG if the result exceeds DNS_NAME_MAXWIRE.
 */

isc_result_t
dns_fixedname_downcase(const dns_name_t *source, dns_fixedname_t *fixed);
/*%<
 * Copy and lowercase a name into an initialized fixedname. Inputs may alias.
 * Retain only the absolute attribute in the result.
 */
