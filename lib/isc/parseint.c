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

#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stdbool.h>
#include <stdlib.h>

#include <isc/parseint.h>
#include <isc/result.h>

isc_result_t
isc_parse_uint32_region(uint32_t *uip, const isc_textregion_t *source,
			int base) {
	uint32_t value = 0;
	unsigned int i = 0;
	bool saw_digit = false;

	if (source->length == 0 || base < 0 || base == 1 || base > 36) {
		return ISC_R_BADNUMBER;
	}

	if (base == 0) {
		if (source->base[0] == '0') {
			base = 8;
			if (source->length > 1 &&
			    (source->base[1] == 'x' || source->base[1] == 'X'))
			{
				base = 16;
				i = 2;
			}
		} else {
			base = 10;
		}
	} else if (base == 16 && source->length > 1 &&
		   source->base[0] == '0' &&
		   (source->base[1] == 'x' || source->base[1] == 'X'))
	{
		i = 2;
	}

	for (; i < source->length; i++) {
		unsigned char c = (unsigned char)source->base[i];
		unsigned int digit;

		if (c >= '0' && c <= '9') {
			digit = c - '0';
		} else if (c >= 'a' && c <= 'z') {
			digit = c - 'a' + 10;
		} else if (c >= 'A' && c <= 'Z') {
			digit = c - 'A' + 10;
		} else {
			return ISC_R_BADNUMBER;
		}
		if (digit >= (unsigned int)base) {
			return ISC_R_BADNUMBER;
		}
		if (value > (UINT32_MAX - digit) / (unsigned int)base) {
			return ISC_R_RANGE;
		}
		value = value * (unsigned int)base + digit;
		saw_digit = true;
	}

	if (!saw_digit) {
		return ISC_R_BADNUMBER;
	}
	*uip = value;
	return ISC_R_SUCCESS;
}

isc_result_t
isc_parse_uint32(uint32_t *uip, const char *string, int base) {
	unsigned long n;
	uint32_t r;
	char *e;
	if (!isalnum((unsigned char)(string[0]))) {
		return ISC_R_BADNUMBER;
	}
	errno = 0;
	n = strtoul(string, &e, base);
	if (*e != '\0') {
		return ISC_R_BADNUMBER;
	}
	/*
	 * Where long is 64 bits we need to convert to 32 bits then test for
	 * equality.  This is a no-op on 32 bit machines and a good compiler
	 * will optimise it away.
	 */
	r = (uint32_t)n;
	if ((n == ULONG_MAX && errno == ERANGE) || (n != (unsigned long)r)) {
		return ISC_R_RANGE;
	}
	*uip = r;
	return ISC_R_SUCCESS;
}

isc_result_t
isc_parse_uint16(uint16_t *uip, const char *string, int base) {
	uint32_t val;

	RETERR(isc_parse_uint32(&val, string, base));
	if (val > 0xFFFF) {
		return ISC_R_RANGE;
	}
	*uip = (uint16_t)val;
	return ISC_R_SUCCESS;
}

isc_result_t
isc_parse_uint8(uint8_t *uip, const char *string, int base) {
	uint32_t val;

	RETERR(isc_parse_uint32(&val, string, base));
	if (val > 0xFF) {
		return ISC_R_RANGE;
	}
	*uip = (uint8_t)val;
	return ISC_R_SUCCESS;
}
