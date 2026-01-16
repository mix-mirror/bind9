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

#include <stdint.h>

#include <isc/util.h>

typedef struct dns_size {
	uint64_t hi;
	uint64_t lo;
	uint64_t cached_size;

	uint64_t scale;
	int shift;
} dns_size_t;

static inline void
dns_size_init(dns_size_t *ctx, uint64_t size) {
	REQUIRE(size != 0);

	if (ctx->cached_size == size) {
		return;
	}

	ctx->cached_size = size;
	ctx->lo = size - (size >> 3); /* ~87.5% */
	ctx->hi = size;		      /* 100%  */

	uint64_t range = ctx->hi - ctx->lo;

#if defined(__SIZEOF_INT128__)
	if (sizeof(size_t) == 8) {
		ctx->shift = -1;
		unsigned __int128 num = (unsigned __int128)256 << 64;
		ctx->scale = (uint64_t)(num / range);
		return;
	}
#endif

	/* 32-bit fallback */
	ctx->shift = 0;
	uint64_t tmp = range;
	while (tmp > 0xFFFFFFFFU) {
		tmp >>= 1;
		ctx->shift++;
	}
	ctx->scale = ((uint64_t)1 << 32) * 256 / tmp;
}

/*
 * Calculates the cleaning probability (0..255) based on current memory usage.
 *
 * Parameters:
 * - current: The current memory in use (bytes).
 * - size: The max memory size (in bytes).
 *
 * Returns:
 * - 0-255
 */
static inline uint8_t
dns_size_cleaning_prob(dns_size_t *ctx, size_t current) {
	if (ctx->cached_size == 0) {
		return 0;
	}

	if (current < ctx->lo) {
		return 0;
	}
	if (current >= ctx->hi) {
		return 255;
	}

	uint64_t position = current - ctx->lo;
	uint64_t result;

#if defined(__SIZEOF_INT128__)
	if (ctx->shift == -1) {
		unsigned __int128 prod = (unsigned __int128)position *
					 ctx->scale;
		result = (uint64_t)(prod >> 64);
	} else
#endif
	{
		uint32_t pos_red = (uint32_t)(position >> ctx->shift);
		result = (uint64_t)((uint64_t)pos_red * ctx->scale) >> 32;
	}

	if (result > 255) {
		return 255;
	}

	return (uint8_t)result;
}
