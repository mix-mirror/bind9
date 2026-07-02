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

#include <isc/bit.h>
#include <isc/u16bitmap.h>

typedef uint8_t isc__window_t[32];

static uint8_t
window_mask(unsigned int bit) {
	return (uint8_t)(1U << (7U - (bit % 8U)));
}

static void
window_reinit(isc__window_t *window) {
	memset(*window, 0, sizeof(*window));
}

static void
window_set(isc__window_t *window, uint8_t value) {
	(*window)[value / 8U] |= window_mask(value);
}

static bool
window_isset(const isc__window_t *window, uint8_t value) {
	return ((*window)[value / 8U] & window_mask(value)) != 0;
}

static void
window_unset(isc__window_t *window, uint8_t value) {
	(*window)[value / 8U] &= (uint8_t)~window_mask(value);
}

static uint32_t
window_count(const isc__window_t *window) {
	uint32_t count = 0;

	for (uint_fast8_t i = 0; i < 32; i++) {
		count += stdc_count_ones((unsigned int)(*window)[i]);
	}

	return count;
}

static uint8_t
window_length(const isc__window_t *window) {
	for (ssize_t length = 32; length > 0; length--) {
		if ((*window)[length - 1] != 0) {
			return (uint8_t)length;
		}
	}

	return 0;
}

static ssize_t
window_firstfrom(const isc__window_t *window, ssize_t value) {
	for (; value < 256; value++) {
		if (window_isset(window, (uint8_t)value)) {
			return (ssize_t)value;
		}
	}

	return ISC_U16BITMAP_END;
}

#define WINDOW_FOREACH_FROM(windowp, value, first)                    \
	for (ssize_t value = window_firstfrom((windowp), (first));    \
	     value != ISC_U16BITMAP_END;                              \
	     value = window_firstfrom((windowp), value + 1))

#define WINDOW_FOREACH(windowp, value) WINDOW_FOREACH_FROM(windowp, value, 0)

void
isc_u16bitmap_reinit(isc_u16bitmap_t *bitmap) {
	window_reinit(&bitmap->active);
}

void
isc_u16bitmap_set(isc_u16bitmap_t *bitmap, uint16_t value) {
	uint8_t window = (uint8_t)(value >> 8);

	if (!window_isset(&bitmap->active, window)) {
		window_reinit(&bitmap->bits[window]);
		window_set(&bitmap->active, window);
	}

	window_set(&bitmap->bits[window], (uint8_t)value);
}

void
isc_u16bitmap_setrange(isc_u16bitmap_t *bitmap, uint16_t lo, uint16_t hi) {
	uint16_t value = lo;

	REQUIRE(lo <= hi);

	do {
		isc_u16bitmap_set(bitmap, value);
	} while (value++ < hi);
}

void
isc_u16bitmap_unset(isc_u16bitmap_t *bitmap, uint16_t value) {
	uint8_t window = (uint8_t)(value >> 8);

	if (!window_isset(&bitmap->active, window)) {
		return;
	}

	window_unset(&bitmap->bits[window], (uint8_t)value);
}

bool
isc_u16bitmap_isset(const isc_u16bitmap_t *bitmap, uint16_t value) {
	uint8_t window = (uint8_t)(value >> 8);

	if (!window_isset(&bitmap->active, window)) {
		return false;
	}

	return window_isset(&bitmap->bits[window], (uint8_t)value);
}

ssize_t
isc_u16bitmap_next(const isc_u16bitmap_t *bitmap, ssize_t value) {
	int32_t start = (int32_t)value;
	uint_fast16_t offset = 0;
	ssize_t start_window = 0;

	start = start >= INT32_MAX ? INT32_MAX : start + 1;
	start_window = start >> 8;
	offset = (uint_fast16_t)(start & 0xffU);

	WINDOW_FOREACH_FROM(&bitmap->active, window, start_window) {
		offset = window == start_window ? offset : 0;

		WINDOW_FOREACH_FROM(&bitmap->bits[window], next, offset) {
			return (ssize_t)(((uint32_t)window << 8) |
					 (uint32_t)next);
		}

		offset = 0;
	}

	return ISC_U16BITMAP_END;
}

uint32_t
isc_u16bitmap_count(const isc_u16bitmap_t *bitmap) {
	uint32_t count = 0;

	WINDOW_FOREACH(&bitmap->active, window) {
		count += window_count(&bitmap->bits[window]);
	}

	return count;
}

size_t
isc_u16bitmap_compress(const isc_u16bitmap_t *bitmap, uint8_t *target,
		       uint16_t max_type) {
	uint8_t *start = target;
	uint8_t max_window = (uint8_t)(max_type >> 8);

	WINDOW_FOREACH(&bitmap->active, window) {
		uint8_t length = window_length(&bitmap->bits[window]);

		if (window > max_window) {
			break;
		}

		if (length == 0) {
			continue;
		}

		*target++ = (uint8_t)window;
		*target++ = length;
		memmove(target, &bitmap->bits[window], length);
		target += length;
	}

	return (size_t)(target - start);
}
