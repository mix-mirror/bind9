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

#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>

#include <isc/ascii.h>
#include <isc/buffer.h>
#include <isc/region.h>
#include <isc/result.h>
#include <isc/string.h>
#include <isc/util.h>

#include <dns/ttl.h>

static isc_result_t
bind_ttl(isc_textregion_t *source, uint32_t *ttl);

/*
 * Helper for dns_ttl_totext().
 */
static isc_result_t
ttlfmt(unsigned int t, const char *s, bool verbose, bool space,
       isc_buffer_t *target) {
	char tmp[60];
	unsigned int len;
	isc_region_t region;

	if (verbose) {
		len = snprintf(tmp, sizeof(tmp), "%s%u %s%s", space ? " " : "",
			       t, s, t == 1 ? "" : "s");
	} else {
		len = snprintf(tmp, sizeof(tmp), "%u%c", t, s[0]);
	}

	INSIST(len + 1 <= sizeof(tmp));
	isc_buffer_availableregion(target, &region);
	if (len > region.length) {
		return ISC_R_NOSPACE;
	}
	memmove(region.base, tmp, len);
	isc_buffer_add(target, len);

	return ISC_R_SUCCESS;
}

/*
 * Derived from bind8 ns_format_ttl().
 */
isc_result_t
dns_ttl_totext(uint32_t src, bool verbose, bool upcase, isc_buffer_t *target) {
	unsigned int secs, mins, hours, days, weeks, x;

	secs = src % 60;
	src /= 60;
	mins = src % 60;
	src /= 60;
	hours = src % 24;
	src /= 24;
	days = src % 7;
	src /= 7;
	weeks = src;
	src = 0;
	POST(src);

	x = 0;
	if (weeks != 0) {
		RETERR(ttlfmt(weeks, "week", verbose, x > 0, target));
		x++;
	}
	if (days != 0) {
		RETERR(ttlfmt(days, "day", verbose, x > 0, target));
		x++;
	}
	if (hours != 0) {
		RETERR(ttlfmt(hours, "hour", verbose, x > 0, target));
		x++;
	}
	if (mins != 0) {
		RETERR(ttlfmt(mins, "minute", verbose, x > 0, target));
		x++;
	}
	if (secs != 0 || (weeks == 0 && days == 0 && hours == 0 && mins == 0)) {
		RETERR(ttlfmt(secs, "second", verbose, x > 0, target));
		x++;
	}
	INSIST(x > 0);
	/*
	 * If only a single unit letter is printed, print it
	 * in upper case. (Why?  Because BIND 8 does that.
	 * Presumably it has a reason.)
	 */
	if (x == 1 && upcase && !verbose) {
		isc_region_t region;
		/*
		 * The unit letter is the last character in the
		 * used region of the buffer.
		 */
		isc_buffer_usedregion(target, &region);
		region.base[region.length - 1] =
			isc_ascii_toupper(region.base[region.length - 1]);
	}
	return ISC_R_SUCCESS;
}

isc_result_t
dns_counter_fromtext(isc_textregion_t *source, uint32_t *ttl) {
	return bind_ttl(source, ttl);
}

isc_result_t
dns_ttl_fromtext(isc_textregion_t *source, uint32_t *ttl) {
	isc_result_t result;

	result = bind_ttl(source, ttl);
	if (result != ISC_R_SUCCESS && result != ISC_R_RANGE) {
		result = DNS_R_BADTTL;
	}
	return result;
}

static isc_result_t
bind_ttl(isc_textregion_t *source, uint32_t *ttl) {
	uint64_t tmp = 0ULL;
	uint64_t n = 0;
	bool digits = false;

	/*
	 * No legal counter / ttl is longer than 63 characters.
	 */
	if (source->length == 0 || source->length > 63) {
		return DNS_R_SYNTAX;
	}

	for (size_t i = 0; i < source->length; i++) {
		switch (source->base[i]) {
		case '0' ... '9':
			n = n * 10 + (source->base[i] - '0');
			if (n > UINT32_MAX) {
				return DNS_R_SYNTAX;
			}
			digits = true;
			continue;
		case 'w':
		case 'W':
			tmp += n * 7 * 24 * 3600;
			break;
		case 'd':
		case 'D':
			tmp += n * 24 * 3600;
			break;
		case 'h':
		case 'H':
			tmp += n * 3600;
			break;
		case 'm':
		case 'M':
			tmp += n * 60;
			break;
		case 's':
		case 'S':
			tmp += n;
			break;
		default:
			return DNS_R_SYNTAX;
		}
		if (!digits) {
			return DNS_R_SYNTAX;
		}
		n = 0;
		digits = false;
	}

	if (digits) {
		/* Plain number? */
		if (tmp != 0ULL) {
			return DNS_R_SYNTAX;
		}
		tmp = n;
	}

	if (tmp > UINT32_MAX) {
		return ISC_R_RANGE;
	}

	*ttl = (uint32_t)tmp;
	return ISC_R_SUCCESS;
}
