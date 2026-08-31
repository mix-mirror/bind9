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

#include <isc/endian.h>
#include <isc/util.h>

#include <dns/fixedname.h>

static const unsigned char base32hex[] = "0123456789ABCDEFGHIJKLMNOPQRSTUV";

static inline void
base32hexnp_encode_block(uint64_t block, unsigned char *dst) {
	dst[0] = base32hex[(block >> 59) & 0x1fU];
	dst[1] = base32hex[(block >> 54) & 0x1fU];
	dst[2] = base32hex[(block >> 49) & 0x1fU];
	dst[3] = base32hex[(block >> 44) & 0x1fU];
	dst[4] = base32hex[(block >> 39) & 0x1fU];
	dst[5] = base32hex[(block >> 34) & 0x1fU];
	dst[6] = base32hex[(block >> 29) & 0x1fU];
	dst[7] = base32hex[(block >> 24) & 0x1fU];
}

static isc_result_t
base32hexnp_encode(const unsigned char *src, size_t length,
		   isc_buffer_t *target) {
	unsigned int encoded_length;
	unsigned char *dst;
	uint64_t tail = 0;

	if (length > (isc_buffer_availablelength(target) * 5U) / 8U) {
		return ISC_R_NOSPACE;
	}
	encoded_length = (unsigned int)((length * 8U + 4U) / 5U);
	dst = isc_buffer_used(target);

	while (length >= 8U) {
		uint64_t block;

		memcpy(&block, src, sizeof(block));
		base32hexnp_encode_block(be64toh(block), dst);

		src += 5;
		dst += 8;
		length -= 5;
	}

	switch (length) {
	case 7:
		tail |= (uint64_t)src[6] << 8;
		dst[11] = base32hex[(tail >> 4) & 0x1fU];
		dst[10] = base32hex[(tail >> 9) & 0x1fU];
		FALLTHROUGH;
	case 6:
		tail |= (uint64_t)src[5] << 16;
		dst[9] = base32hex[(tail >> 14) & 0x1fU];
		dst[8] = base32hex[(tail >> 19) & 0x1fU];
		FALLTHROUGH;
	case 5:
		tail |= (uint64_t)src[4] << 24;
		dst[7] = base32hex[(tail >> 24) & 0x1fU];
		FALLTHROUGH;
	case 4:
		tail |= (uint64_t)src[3] << 32;
		dst[6] = base32hex[(tail >> 29) & 0x1fU];
		dst[5] = base32hex[(tail >> 34) & 0x1fU];
		FALLTHROUGH;
	case 3:
		tail |= (uint64_t)src[2] << 40;
		dst[4] = base32hex[(tail >> 39) & 0x1fU];
		FALLTHROUGH;
	case 2:
		tail |= (uint64_t)src[1] << 48;
		dst[3] = base32hex[(tail >> 44) & 0x1fU];
		dst[2] = base32hex[(tail >> 49) & 0x1fU];
		FALLTHROUGH;
	case 1:
		tail |= (uint64_t)src[0] << 56;
		dst[1] = base32hex[(tail >> 54) & 0x1fU];
		dst[0] = base32hex[tail >> 59];
		break;
	case 0:
		goto done;
	default:
		UNREACHABLE();
	}

done:
	isc_buffer_add(target, encoded_length);
	return ISC_R_SUCCESS;
}

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
	isc_region_t origin_region;

	REQUIRE(fixed != NULL);
	REQUIRE(hash != NULL);
	REQUIRE(DNS_NAME_VALID(origin));

	isc_buffer_clear(&fixed->buffer);
	isc_buffer_putuint8(&fixed->buffer, 0);
	RETERR(base32hexnp_encode(hash, hash_length, &fixed->buffer));
	fixed->data[0] = (uint8_t)(isc_buffer_usedlength(&fixed->buffer) - 1U);

	dns_name_toregion(origin, &origin_region);
	RETERR(isc_buffer_copyregion(&fixed->buffer, &origin_region));

	fixed->name = (dns_name_t){
		.magic = DNS_NAME_MAGIC,
		.attributes = { .absolute = true },
		.ndata = fixed->data,
		.length = (uint8_t)isc_buffer_usedlength(&fixed->buffer),
		.buffer = &fixed->buffer,
		.link = ISC_LINK_INITIALIZER,
		.list = ISC_LIST_INITIALIZER,
	};

	return ISC_R_SUCCESS;
}
