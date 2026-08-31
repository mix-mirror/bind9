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

#include <isc/base32.h>
#include <isc/util.h>

#include <dns/fixedname.h>

void
dns_fixedname_init(dns_fixedname_t *fixed) {
	dns_name_init(&fixed->name);
	isc_buffer_init(&fixed->buffer, fixed->data, DNS_NAME_MAXWIRE);
	dns_name_setbuffer(&fixed->name, &fixed->buffer);
}

void
dns_fixedname_invalidate(dns_fixedname_t *fixed) {
	dns_name_invalidate(&fixed->name);
}

dns_name_t *
dns_fixedname_name(dns_fixedname_t *fixed) {
	return &fixed->name;
}

dns_name_t *
dns_fixedname_initname(dns_fixedname_t *fixed) {
	dns_fixedname_init(fixed);
	return dns_fixedname_name(fixed);
}

isc_result_t
dns_fixedname_fromnsec3hash(dns_fixedname_t *fixed, const unsigned char *hash,
			    size_t hash_length, const dns_name_t *origin) {
	isc_region_t source = {
		.base = UNCONST(hash),
		.length = (unsigned int)hash_length,
	};
	size_t encoded_length;
	size_t origin_length = (origin != NULL) ? origin->length : 0;

	REQUIRE(fixed != NULL);
	REQUIRE(hash != NULL);
	REQUIRE(origin == NULL || DNS_NAME_VALID(origin));

	/* The encoded hash has to fit in a single DNS label. */
	if (hash_length > (DNS_NAME_LABELLEN * 5U) / 8U) {
		return DNS_R_LABELTOOLONG;
	}
	encoded_length = (hash_length * 8U + 4U) / 5U;
	if (encoded_length + 1U + origin_length > DNS_NAME_MAXWIRE) {
		return DNS_R_NAMETOOLONG;
	}

	dns_fixedname_init(fixed);
	isc_buffer_putuint8(&fixed->buffer, (uint8_t)encoded_length);
	RETERR(isc_base32hexnp_totext(&source, -1, "", &fixed->buffer));
	if (origin != NULL) {
		isc_buffer_putmem(&fixed->buffer, origin->ndata,
				  origin->length);
	}

	fixed->name.ndata = fixed->data;
	fixed->name.length = (uint8_t)isc_buffer_usedlength(&fixed->buffer);
	if (origin != NULL) {
		fixed->name.attributes.absolute = origin->attributes.absolute;
	}

	return ISC_R_SUCCESS;
}
