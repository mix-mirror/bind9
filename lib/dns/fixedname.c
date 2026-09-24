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

#include <string.h>

#include <isc/ascii.h>
#include <isc/util.h>

#include <dns/compress.h>
#include <dns/fixedname.h>

dns_fixedname_t *
dns_fixedname_init(dns_fixedname_t *fixed) {
	dns_name_init(&fixed->name);
	return fixed;
}

void
dns_fixedname_invalidate(dns_fixedname_t *fixed) {
	dns_name_invalidate(&fixed->name);
}

dns_name_t *
dns_fixedname_name(dns_fixedname_t *fixed) {
	return fixed != NULL ? &fixed->name : NULL;
}

dns_name_t *
dns_fixedname_initname(dns_fixedname_t *fixed) {
	dns_fixedname_init(fixed);
	return dns_fixedname_name(fixed);
}

void
dns_fixedname_fromregion(dns_fixedname_t *fixed, const isc_region_t *region) {
	dns_name_t name = DNS_NAME_INITEMPTY;
	dns_name_fromregion(&name, region);
	dns_fixedname_copy(&name, fixed);
}

isc_result_t
dns_fixedname_fromwire(dns_fixedname_t *fixed, isc_buffer_t *source,
		       dns_decompress_t dctx) {
	isc_buffer_t target;
	isc_buffer_init(&target, fixed->data, sizeof(fixed->data));
	return dns_name_fromwire(&fixed->name, source, dctx, &target);
}

void
dns_fixedname_reset(dns_fixedname_t *fixed) {
	dns_name_reset(&fixed->name);
}

void
dns_fixedname_copy(const dns_name_t *source, dns_fixedname_t *fixed) {
	dns_name_t *dest = &fixed->name;
	unsigned char *ndata = fixed->data;

	REQUIRE(DNS_NAME_VALID(source));
	REQUIRE(DNS_NAME_VALID(dest));
	REQUIRE(DNS_NAME_BINDABLE(dest));

	REQUIRE(sizeof(fixed->data) >= source->length);

	if (source->length != 0) {
		memmove(ndata, source->ndata, source->length);
	}

	dest->ndata = ndata;
	dest->length = source->length;
	dest->attributes.absolute = source->attributes.absolute;
}

isc_result_t
dns_fixedname_concatenate(const dns_name_t *prefix, const dns_name_t *suffix,
			  dns_fixedname_t *fixed) {
	dns_name_t *name = &fixed->name;
	unsigned char *ndata = fixed->data;
	unsigned int prefix_length, length;
	bool copy_prefix = true;
	bool copy_suffix = true;
	bool absolute = false;

	/*
	 * Concatenate 'prefix' and 'suffix'.
	 */

	REQUIRE(prefix == NULL || DNS_NAME_VALID(prefix));
	REQUIRE(suffix == NULL || DNS_NAME_VALID(suffix));
	REQUIRE(DNS_NAME_VALID(name));
	REQUIRE(DNS_NAME_BINDABLE(name));

	if (prefix == NULL || prefix->length == 0) {
		copy_prefix = false;
	}
	if (suffix == NULL || suffix->length == 0) {
		copy_suffix = false;
	}
	if (copy_prefix && prefix->attributes.absolute) {
		absolute = true;
		REQUIRE(!copy_suffix);
	}
	length = 0;
	prefix_length = 0;
	if (copy_prefix) {
		prefix_length = prefix->length;
		length += prefix_length;
	}
	if (copy_suffix) {
		length += suffix->length;
	}
	if (length > DNS_NAME_MAXWIRE) {
		return DNS_R_NAMETOOLONG;
	}

	unsigned char data[DNS_NAME_MAXWIRE];
	if (copy_prefix) {
		memmove(data, prefix->ndata, prefix_length);
	}
	if (copy_suffix) {
		memmove(data + prefix_length, suffix->ndata, suffix->length);
		absolute = suffix->attributes.absolute;
	}
	memmove(ndata, data, length);

	name->ndata = ndata;
	name->length = length;
	name->attributes.absolute = absolute;

	return ISC_R_SUCCESS;
}

isc_result_t
dns_fixedname_downcase(const dns_name_t *source, dns_fixedname_t *fixed) {
	dns_name_t *name = &fixed->name;
	REQUIRE(DNS_NAME_VALID(source));
	REQUIRE(DNS_NAME_VALID(name));
	REQUIRE(DNS_NAME_BINDABLE(name));
	dns_fixedname_copy(source, fixed);
	name->attributes = (struct dns_name_attrs){
		.absolute = source->attributes.absolute,
	};
	return dns_name_downcase(name);
}

isc_result_t
dns_fixedname_fromstring(dns_fixedname_t *fixed, const char *src,
			 const dns_name_t *origin, unsigned int options) {
	isc_buffer_t buf;
	REQUIRE(src != NULL);
	isc_buffer_constinit(&buf, src, strlen(src));
	isc_buffer_add(&buf, strlen(src));
	return dns_fixedname_fromtext(fixed, &buf, origin, options);
}
