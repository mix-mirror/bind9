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

/*! \file isc/u16bitmap.h */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#define ISC_U16BITMAP_MAXCOMPRESSEDSIZE (256 * (2 + 32))

typedef enum isc_u16bitmap_iterator {
	ISC_U16BITMAP_BEGIN = -1,
	ISC_U16BITMAP_END = INT32_MAX,
} isc_u16bitmap_iterator_t;

_Static_assert(sizeof(ssize_t) >= 4, "ssize_t must be at least 32 bits");
_Static_assert(ISC_U16BITMAP_END > UINT16_MAX,
	       "iterator end sentinel must be outside the bitmap value range");

typedef struct isc_u16bitmap {
	uint8_t active[32];
	uint8_t bits[256][32];
} isc_u16bitmap_t;

/*%
 * Bits are stored most-significant-bit first within each byte, matching DNS
 * type bitmap wire order.
 *
 * Reinitializing only clears the active-window bitmap; second-level windows
 * are zeroed lazily before first use after reinitialization.
 */

void
isc_u16bitmap_reinit(isc_u16bitmap_t *bitmap);

void
isc_u16bitmap_set(isc_u16bitmap_t *bitmap, uint16_t value);

void
isc_u16bitmap_setrange(isc_u16bitmap_t *bitmap, uint16_t lo, uint16_t hi);

void
isc_u16bitmap_unset(isc_u16bitmap_t *bitmap, uint16_t value);

bool
isc_u16bitmap_isset(const isc_u16bitmap_t *bitmap, uint16_t value);

ssize_t
isc_u16bitmap_next(const isc_u16bitmap_t *bitmap, ssize_t value);

uint32_t
isc_u16bitmap_count(const isc_u16bitmap_t *bitmap);

size_t
isc_u16bitmap_compress(const isc_u16bitmap_t *bitmap, uint8_t *target);

#define ISC_U16BITMAP_FOREACH(bitmap, value)                         \
	for (ssize_t value = isc_u16bitmap_next(bitmap,                 \
						ISC_U16BITMAP_BEGIN); \
	     value != ISC_U16BITMAP_END;                               \
	     value = isc_u16bitmap_next(bitmap, value))
