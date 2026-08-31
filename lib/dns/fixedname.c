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
	dns_name_t *name;
	isc_region_t origin_region;
	isc_region_t source = {
		.base = UNCONST(hash),
		.length = (unsigned int)hash_length,
	};

	REQUIRE(fixed != NULL);
	REQUIRE(hash != NULL);
	REQUIRE(DNS_NAME_VALID(origin));

	name = dns_fixedname_name(fixed);
	dns_name_reset(name);
	name->ndata = isc_buffer_used(&fixed->buffer);
	isc_buffer_putuint8(&fixed->buffer, 0);
	RETERR(isc_base32hexnp_totext(&source, -1, "", &fixed->buffer));
	name->ndata[0] = (uint8_t)(isc_buffer_usedlength(&fixed->buffer) - 1U);

	dns_name_toregion(origin, &origin_region);
	RETERR(isc_buffer_copyregion(&fixed->buffer, &origin_region));

	name->length = (uint8_t)isc_buffer_usedlength(&fixed->buffer);
	name->attributes = (struct dns_name_attrs){ .absolute = true };

	return ISC_R_SUCCESS;
}
