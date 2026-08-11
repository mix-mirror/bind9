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

#include <limits.h>
#include <stdbool.h>
#include <stdint.h>

#include <isc/attributes.h>
#include <isc/util.h>

#if __has_header(<stdbit.h>)
#include <stdbit.h>
#else /* __has_header(<stdbit.h>) */

#define __STDC_VERSION_STDBIT_H__ 0L

#ifdef HAVE_BUILTIN_POPCOUNTG
#define stdc_count_ones(x) __builtin_popcountg(x)
#else /* HAVE_BUILTIN_POPCOUNTG */
#define stdc_count_ones(x)                          \
	_Generic((x),                               \
		unsigned int: __builtin_popcount,   \
		unsigned long: __builtin_popcountl, \
		unsigned long long: __builtin_popcountll)(x)
#endif /* HAVE_BUILTIN_POPCOUNTG */

#ifdef HAVE_BUILTIN_CLZG
#define stdc_leading_zeros(x) __builtin_clzg(x, (int)(sizeof(x) * 8))
#else /* HAVE_BUILTIN_CLZG */
#define stdc_leading_zeros(x)                           \
	(((x) == 0) ? (sizeof(x) * 8)                   \
		    : _Generic((x),                     \
			 unsigned int: __builtin_clz,   \
			 unsigned long: __builtin_clzl, \
			 unsigned long long: __builtin_clzll)(x))
#endif /* HAVE_BUILTIN_CLZG */

#ifdef HAVE_BUILTIN_CTZG
#define stdc_trailing_zeros(x) __builtin_ctzg(x, (int)sizeof(x) * 8)
#else /* HAVE_BUILTIN_CTZG */
#define stdc_trailing_zeros(x)                          \
	(((x) == 0) ? (sizeof(x) * 8)                   \
		    : _Generic((x),                     \
			 unsigned int: __builtin_ctz,   \
			 unsigned long: __builtin_ctzl, \
			 unsigned long long: __builtin_ctzll)(x))
#endif /* HAVE_BUILTIN_CTZG */

#define stdc_leading_ones(x)  stdc_leading_zeros(~(x))
#define stdc_trailing_ones(x) stdc_trailing_zeros(~(x))

#endif /* __has_header(<stdbit.h>) */

#if HAVE_BUILTIN_STD_ROTATE_LEFT && HAVE_BUILTIN_STD_ROTATE_RIGHT
#define ISC_ROTATE_LEFT(x, n)  __builtin_stdc_rotate_left(x, n)
#define ISC_ROTATE_RIGHT(x, n) __builtin_stdc_rotate_right(x, n)
#else /* HAVE_BUILTIN_STD_ROTATE_LEFT && HAVE_BUILTIN_STD_ROTATE_RIGHT */

static inline uint8_t
isc_rotate_left8(const uint8_t x, uint32_t n) {
	return (x << n) | (x >> (8 - n));
}

static inline uint16_t
isc_rotate_left16(const uint16_t x, uint32_t n) {
	return (x << n) | (x >> (16 - n));
}

static inline uint32_t
isc_rotate_left32(const uint32_t x, uint32_t n) {
	return (x << n) | (x >> (32 - n));
}

static inline uint64_t
isc_rotate_left64(const uint64_t x, uint32_t n) {
	return (x << n) | (x >> (64 - n));
}

static inline uint8_t
isc_rotate_right8(const uint8_t x, uint32_t n) {
	return (x >> n) | (x << (8 - n));
}

static inline uint16_t
isc_rotate_right16(const uint16_t x, uint32_t n) {
	return (x >> n) | (x << (16 - n));
}

static inline uint32_t
isc_rotate_right32(const uint32_t x, uint32_t n) {
	return (x >> n) | (x << (32 - n));
}

static inline uint64_t
isc_rotate_right64(const uint64_t x, uint32_t n) {
	return (x >> n) | (x << (64 - n));
}

#if __APPLE_CC__ || (defined(__OpenBSD__) && defined(__clang__))

/*
 * Apple compiler doesn't recognize size_t and uintXX_t types as same,
 * so we need to add kludges for size_t below.
 */

#if SIZE_MAX == UINT64_MAX
#define EXTRA_ROTATE_LEFT  , size_t : isc_rotate_left64
#define EXTRA_ROTATE_RIGHT , size_t : isc_rotate_right64
#elif SIZE_MAX == UINT32_MAX
#define EXTRA_ROTATE_LEFT  , size_t : isc_rotate_left32
#define EXTRA_ROTATE_RIGHT , size_t : isc_rotate_right32
#else
#error "size_t must be either 32 or 64-bits"
#endif
#else
#define EXTRA_ROTATE_LEFT
#define EXTRA_ROTATE_RIGHT
#endif

#define ISC_ROTATE_LEFT(x, n)                \
	_Generic((x),                        \
		uint8_t: isc_rotate_left8,   \
		uint16_t: isc_rotate_left16, \
		uint32_t: isc_rotate_left32, \
		uint64_t: isc_rotate_left64 EXTRA_ROTATE_LEFT)(x, n)

#define ISC_ROTATE_RIGHT(x, n)                \
	_Generic((x),                         \
		uint8_t: isc_rotate_right8,   \
		uint16_t: isc_rotate_right16, \
		uint32_t: isc_rotate_right32, \
		uint64_t: isc_rotate_right64 EXTRA_ROTATE_RIGHT)(x, n)

#endif /* HAVE_BUILTIN_STD_ROTATE_LEFT && HAVE_BUILTIN_STD_ROTATE_RIGHT */

/*
 * 48-bit BIND extensions to the C2y endian-aware 8-bit store/load functions.
 */

static inline uint_least64_t
isc_load8_leu48(const unsigned char ptr[static 6]) {
	return ((uint64_t)(ptr[0])) | ((uint64_t)(ptr[1]) << 8) |
	       ((uint64_t)(ptr[2]) << 16) | ((uint64_t)(ptr[3]) << 24) |
	       ((uint64_t)(ptr[4]) << 32) | ((uint64_t)(ptr[5]) << 40);
}

static inline uint_least64_t
isc_load8_beu48(const unsigned char ptr[static 6]) {
	return ((uint64_t)(ptr[0]) << 40) | ((uint64_t)(ptr[1]) << 32) |
	       ((uint64_t)(ptr[2]) << 24) | ((uint64_t)(ptr[3]) << 16) |
	       ((uint64_t)(ptr[4]) << 8) | ((uint64_t)(ptr[5]));
}

static inline void
isc_store8_leu48(uint_least64_t value, unsigned char ptr[static 6]) {
	ptr[0] = (uint8_t)(value);
	ptr[1] = (uint8_t)(value >> 8);
	ptr[2] = (uint8_t)(value >> 16);
	ptr[3] = (uint8_t)(value >> 24);
	ptr[4] = (uint8_t)(value >> 32);
	ptr[5] = (uint8_t)(value >> 40);
}

static inline void
isc_store8_beu48(uint_least64_t value, unsigned char ptr[static 6]) {
	ptr[0] = (uint8_t)(value >> 40);
	ptr[1] = (uint8_t)(value >> 32);
	ptr[2] = (uint8_t)(value >> 24);
	ptr[3] = (uint8_t)(value >> 16);
	ptr[4] = (uint8_t)(value >> 8);
	ptr[5] = (uint8_t)(value);
}

/*
 * Shims to the endian-aware bit operations.
 *
 * Since POSIX requires `CHAR_BIT == 8` these will always exist to us.
 */

#if __STDC_VERSION_STDBIT_H__ <= 202311L

static inline void
stdc_memreverse_u8(size_t n, unsigned char *ptr) {
	size_t i, j;

	if (n == 0) {
		return;
	}

	for (i = 0, j = n - 1; i < j; i++, j--) {
		ISC_SWAP(ptr[i], ptr[j]);
	}
}

static inline uint8_t
stdc_memreverse8u8(uint8_t x) {
	return x;
}

static inline uint16_t
stdc_memreverse8u16(uint16_t x) {
#if __has_builtin(__builtin_bswap16)
	return __builtin_bswap16(x);
#else
	return (uint16_t)((((uint16_t)(x) & 0xff00) >> 8) |
			  (((uint16_t)(x) & 0x00ff) << 8));
#endif
}

static inline uint32_t
stdc_memreverse8u32(uint32_t x) {
#if __has_builtin(__builtin_bswap32)
	return __builtin_bswap32(x);
#else
	return (uint32_t)((((uint32_t)(x) & 0xff000000) >> 24) |
			  (((uint32_t)(x) & 0x00ff0000) >> 8) |
			  (((uint32_t)(x) & 0x0000ff00) << 8) |
			  (((uint32_t)(x) & 0x000000ff) << 24));
#endif
}

static inline uint64_t
stdc_memreverse8u64(uint32_t x) {
#if __has_builtin(__builtin_bswap64)
	return __builtin_bswap64(x);
#else
	return (uint64_t)((((uint64_t)(x) & 0xff00000000000000ULL) >> 56) |
			  (((uint64_t)(x) & 0x00ff000000000000ULL) >> 40) |
			  (((uint64_t)(x) & 0x0000ff0000000000ULL) >> 24) |
			  (((uint64_t)(x) & 0x000000ff00000000ULL) >> 8) |
			  (((uint64_t)(x) & 0x00000000ff000000ULL) << 8) |
			  (((uint64_t)(x) & 0x0000000000ff0000ULL) << 24) |
			  (((uint64_t)(x) & 0x000000000000ff00ULL) << 40) |
			  (((uint64_t)(x) & 0x00000000000000ffULL) << 56));
#endif
}

static inline uint_least8_t
stdc_load8_leu8(const unsigned char ptr[static 1]) {
	return ptr[0];
}

static inline uint_least16_t
stdc_load8_leu16(const unsigned char ptr[static 2]) {
	return ((uint16_t)ptr[0]) | ((uint16_t)ptr[1] << 8);
}

static inline uint_least32_t
stdc_load8_leu32(const unsigned char ptr[static 4]) {
	return ((uint32_t)ptr[0]) | ((uint32_t)ptr[1] << 8) |
	       ((uint32_t)(ptr[2]) << 16) | ((uint32_t)(ptr[3]) << 24);
}

static inline uint_least64_t
stdc_load8_leu64(const unsigned char ptr[static 8]) {
	return ((uint64_t)(ptr[0])) | ((uint64_t)(ptr[1]) << 8) |
	       ((uint64_t)(ptr[2]) << 16) | ((uint64_t)(ptr[3]) << 24) |
	       ((uint64_t)(ptr[4]) << 32) | ((uint64_t)(ptr[5]) << 40) |
	       ((uint64_t)(ptr[6]) << 48) | ((uint64_t)(ptr[7]) << 56);
}

static inline uint_least8_t
stdc_load8_beu8(const unsigned char ptr[static 1]) {
	return ptr[0];
}

static inline uint_least16_t
stdc_load8_beu16(const unsigned char ptr[static 2]) {
	return ((uint16_t)ptr[0] << 8) | ((uint16_t)ptr[1]);
}

static inline uint_least32_t
stdc_load8_beu32(const unsigned char ptr[static 4]) {
	return ((uint32_t)ptr[0] << 24) | ((uint32_t)ptr[1] << 16) |
	       ((uint32_t)(ptr[2]) << 8) | ((uint32_t)(ptr[3]));
}

static inline uint_least64_t
stdc_load8_beu64(const unsigned char ptr[static 8]) {
	return ((uint64_t)(ptr[0]) << 56) | ((uint64_t)(ptr[1]) << 48) |
	       ((uint64_t)(ptr[2]) << 40) | ((uint64_t)(ptr[3]) << 32) |
	       ((uint64_t)(ptr[4]) << 24) | ((uint64_t)(ptr[5]) << 16) |
	       ((uint64_t)(ptr[6]) << 8) | ((uint64_t)(ptr[7]));
}

static inline void
stdc_store8_leu8(uint_least8_t value, unsigned char ptr[static 1]) {
	ptr[0] = value;
}

static inline void
stdc_store8_leu16(uint_least16_t value, unsigned char ptr[static 2]) {
	ptr[0] = (uint8_t)(value);
	ptr[1] = (uint8_t)(value >> 8);
}

static inline void
stdc_store8_leu32(uint_least32_t value, unsigned char ptr[static 4]) {
	ptr[0] = (uint8_t)(value);
	ptr[1] = (uint8_t)(value >> 8);
	ptr[2] = (uint8_t)(value >> 16);
	ptr[3] = (uint8_t)(value >> 24);
}

static inline void
stdc_store8_leu64(uint_least64_t value, unsigned char ptr[static 8]) {
	ptr[0] = (uint8_t)(value);
	ptr[1] = (uint8_t)(value >> 8);
	ptr[2] = (uint8_t)(value >> 16);
	ptr[3] = (uint8_t)(value >> 24);
	ptr[4] = (uint8_t)(value >> 32);
	ptr[5] = (uint8_t)(value >> 40);
	ptr[6] = (uint8_t)(value >> 48);
	ptr[7] = (uint8_t)(value >> 56);
}

static inline void
stdc_store8_beu8(uint_least8_t value, unsigned char ptr[static 1]) {
	ptr[0] = value;
}

static inline void
stdc_store8_beu16(uint_least16_t value, unsigned char ptr[static 2]) {
	ptr[0] = (uint8_t)(value >> 8);
	ptr[1] = (uint8_t)(value);
}

static inline void
stdc_store8_beu32(uint_least32_t value, unsigned char ptr[static 4]) {
	ptr[0] = (uint8_t)(value >> 24);
	ptr[1] = (uint8_t)(value >> 16);
	ptr[2] = (uint8_t)(value >> 8);
	ptr[3] = (uint8_t)(value);
}

static inline void
stdc_store8_beu64(uint_least64_t value, unsigned char ptr[static 8]) {
	ptr[0] = (uint8_t)(value >> 56);
	ptr[1] = (uint8_t)(value >> 48);
	ptr[2] = (uint8_t)(value >> 40);
	ptr[3] = (uint8_t)(value >> 32);
	ptr[4] = (uint8_t)(value >> 24);
	ptr[5] = (uint8_t)(value >> 16);
	ptr[6] = (uint8_t)(value >> 8);
	ptr[7] = (uint8_t)(value);
}

#endif /* __STDC_VERSION_STDBIT_H__ <= 202311L */
