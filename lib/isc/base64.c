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

#include <stdbool.h>
#include <stdint.h>

#include <isc/base64.h>
#include <isc/buffer.h>
#include <isc/lex.h>
#include <isc/string.h>
#include <isc/util.h>

/*@{*/
/*!
 * These static functions are also present in lib/dns/rdata.c.  I'm not
 * sure where they should go. -- bwelling
 */
static isc_result_t
str_totext(const char *source, isc_buffer_t *target);

static isc_result_t
mem_tobuffer(isc_buffer_t *target, void *base, unsigned int length);

static const char base64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvw"
			     "xyz0123456789+/=";
/*@}*/

/*
 * Use simdutf's scalar approach: four position-specific lookups contribute
 * one base64 digit each to a three-byte result.  The four high bits mark
 * which input positions held valid base64 characters.
 */
#define BASE64_DIGITS(X) \
	X('A', 0)        \
	X('B', 1)        \
	X('C', 2)        \
	X('D', 3)        \
	X('E', 4)        \
	X('F', 5)        \
	X('G', 6)        \
	X('H', 7)        \
	X('I', 8)        \
	X('J', 9)        \
	X('K', 10)       \
	X('L', 11)       \
	X('M', 12)       \
	X('N', 13)       \
	X('O', 14)       \
	X('P', 15)       \
	X('Q', 16)       \
	X('R', 17)       \
	X('S', 18)       \
	X('T', 19)       \
	X('U', 20)       \
	X('V', 21)       \
	X('W', 22)       \
	X('X', 23)       \
	X('Y', 24)       \
	X('Z', 25)       \
	X('a', 26)       \
	X('b', 27)       \
	X('c', 28)       \
	X('d', 29)       \
	X('e', 30)       \
	X('f', 31)       \
	X('g', 32)       \
	X('h', 33)       \
	X('i', 34)       \
	X('j', 35)       \
	X('k', 36)       \
	X('l', 37)       \
	X('m', 38)       \
	X('n', 39)       \
	X('o', 40)       \
	X('p', 41)       \
	X('q', 42)       \
	X('r', 43)       \
	X('s', 44)       \
	X('t', 45)       \
	X('u', 46)       \
	X('v', 47)       \
	X('w', 48)       \
	X('x', 49)       \
	X('y', 50)       \
	X('z', 51)       \
	X('0', 52)       \
	X('1', 53)       \
	X('2', 54)       \
	X('3', 55)       \
	X('4', 56)       \
	X('5', 57)       \
	X('6', 58)       \
	X('7', 59)       \
	X('8', 60)       \
	X('9', 61)       \
	X('+', 62)       \
	X('/', 63)

#define BASE64_D0(c, v) [c] = 0x01000000U | ((uint32_t)(v) << 2),
#define BASE64_D1(c, v)                            \
	[c] = 0x02000000U | ((uint32_t)(v) >> 4) | \
	      (((uint32_t)(v) & 0x0fU) << 12),
#define BASE64_D2(c, v)                                 \
	[c] = 0x04000000U | ((uint32_t)(v) >> 2 << 8) | \
	      (((uint32_t)(v) & 0x03U) << 22),
#define BASE64_D3(c, v) [c] = 0x08000000U | ((uint32_t)(v) << 16),

/*
 * The tables cover every byte value, so they can be indexed by any input
 * byte without a range check; bytes that are not base64 digits are zero.
 */
static const uint32_t base64_d0[256] = { BASE64_DIGITS(BASE64_D0) };
static const uint32_t base64_d1[256] = { BASE64_DIGITS(BASE64_D1) };
static const uint32_t base64_d2[256] = { BASE64_DIGITS(BASE64_D2) };
static const uint32_t base64_d3[256] = { BASE64_DIGITS(BASE64_D3) };

#undef BASE64_D0
#undef BASE64_D1
#undef BASE64_D2
#undef BASE64_D3
#undef BASE64_DIGITS

isc_result_t
isc_base64_totext(isc_region_t *source, int wordlength, const char *wordbreak,
		  isc_buffer_t *target) {
	char buf[5];
	unsigned int loops = 0;

	if (wordlength < 4) {
		wordlength = 4;
	}

	memset(buf, 0, sizeof(buf));
	while (source->length > 2) {
		buf[0] = base64[(source->base[0] >> 2) & 0x3f];
		buf[1] = base64[((source->base[0] << 4) & 0x30) |
				((source->base[1] >> 4) & 0x0f)];
		buf[2] = base64[((source->base[1] << 2) & 0x3c) |
				((source->base[2] >> 6) & 0x03)];
		buf[3] = base64[source->base[2] & 0x3f];
		RETERR(str_totext(buf, target));
		isc_region_consume(source, 3);

		loops++;
		if (source->length != 0 && (int)((loops + 1) * 4) >= wordlength)
		{
			loops = 0;
			RETERR(str_totext(wordbreak, target));
		}
	}
	if (source->length == 2) {
		buf[0] = base64[(source->base[0] >> 2) & 0x3f];
		buf[1] = base64[((source->base[0] << 4) & 0x30) |
				((source->base[1] >> 4) & 0x0f)];
		buf[2] = base64[((source->base[1] << 2) & 0x3c)];
		buf[3] = '=';
		RETERR(str_totext(buf, target));
		isc_region_consume(source, 2);
	} else if (source->length == 1) {
		buf[0] = base64[(source->base[0] >> 2) & 0x3f];
		buf[1] = base64[((source->base[0] << 4) & 0x30)];
		buf[2] = buf[3] = '=';
		RETERR(str_totext(buf, target));
		isc_region_consume(source, 1);
	}
	return ISC_R_SUCCESS;
}

/*%
 * State of a base64 decoding process in progress.
 */
typedef struct {
	int length;	      /*%< Desired length of binary data or -1 */
	isc_buffer_t *target; /*%< Buffer for resulting binary data */
	int digits;	      /*%< Number of buffered base64 digits */
	bool seen_end;	      /*%< True if "=" end marker seen */
	int val[4];
} base64_decode_ctx_t;

static void
base64_decode_init(base64_decode_ctx_t *ctx, int length, isc_buffer_t *target) {
	ctx->digits = 0;
	ctx->seen_end = false;
	ctx->length = length;
	ctx->target = target;
}

static isc_result_t
base64_decode_char(base64_decode_ctx_t *ctx, unsigned char c) {
	if (ctx->seen_end) {
		return ISC_R_BADBASE64;
	}
	if (c == '=') {
		ctx->val[ctx->digits++] = 64;
	} else if (base64_d0[c] != 0) {
		ctx->val[ctx->digits++] = (base64_d0[c] & 0xffU) >> 2;
	} else {
		return ISC_R_BADBASE64;
	}
	if (ctx->digits == 4) {
		int n;
		unsigned char buf[3];
		if (ctx->val[0] == 64 || ctx->val[1] == 64) {
			return ISC_R_BADBASE64;
		}
		if (ctx->val[2] == 64 && ctx->val[3] != 64) {
			return ISC_R_BADBASE64;
		}
		/*
		 * Check that bits that should be zero are.
		 */
		if (ctx->val[2] == 64 && (ctx->val[1] & 0xf) != 0) {
			return ISC_R_BADBASE64;
		}
		/*
		 * We don't need to test for ctx->val[2] != 64 as
		 * the bottom two bits of 64 are zero.
		 */
		if (ctx->val[3] == 64 && (ctx->val[2] & 0x3) != 0) {
			return ISC_R_BADBASE64;
		}
		n = (ctx->val[2] == 64) ? 1 : (ctx->val[3] == 64) ? 2 : 3;
		if (n != 3) {
			ctx->seen_end = true;
			if (ctx->val[2] == 64) {
				ctx->val[2] = 0;
			}
			if (ctx->val[3] == 64) {
				ctx->val[3] = 0;
			}
		}
		buf[0] = (ctx->val[0] << 2) | (ctx->val[1] >> 4);
		buf[1] = (ctx->val[1] << 4) | (ctx->val[2] >> 2);
		buf[2] = (ctx->val[2] << 6) | (ctx->val[3]);
		RETERR(mem_tobuffer(ctx->target, buf, n));
		if (ctx->length >= 0) {
			if (n > ctx->length) {
				return ISC_R_BADBASE64;
			} else {
				ctx->length -= n;
			}
		}
		ctx->digits = 0;
	}
	return ISC_R_SUCCESS;
}

static isc_result_t
base64_decode_chars(base64_decode_ctx_t *ctx, const unsigned char *input,
		    size_t length) {
	while (length > 0) {
		if (ctx->digits == 0 && !ctx->seen_end) {
			/*
			 * Fast path: decode whole quanta at once, as far as
			 * the input, the desired length, and the space in the
			 * target allow.  Padding, errors, and anything past
			 * those limits fall through to base64_decode_char().
			 */
			isc_region_t avail;
			unsigned char *dst;
			size_t n = length / 4;
			size_t i;

			isc_buffer_availableregion(ctx->target, &avail);
			if (n > avail.length / 3) {
				n = avail.length / 3;
			}
			if (ctx->length >= 0 && n > (size_t)ctx->length / 3) {
				n = (size_t)ctx->length / 3;
			}
			dst = avail.base;
			for (i = 0; i < n; i++, input += 4, dst += 3) {
				const uint32_t x = base64_d0[input[0]] |
						   base64_d1[input[1]] |
						   base64_d2[input[2]] |
						   base64_d3[input[3]];

				if ((x & 0x0f000000U) != 0x0f000000U) {
					break;
				}
				dst[0] = x;
				dst[1] = x >> 8;
				dst[2] = x >> 16;
			}
			isc_buffer_add(ctx->target, (unsigned int)(3 * i));
			length -= 4 * i;
			if (ctx->length >= 0) {
				ctx->length -= 3 * i;
			}
			if (length == 0) {
				break;
			}
		}
		RETERR(base64_decode_char(ctx, *input++));
		length--;
	}
	return ISC_R_SUCCESS;
}

static isc_result_t
base64_decode_finish(base64_decode_ctx_t *ctx) {
	if (ctx->length > 0) {
		return ISC_R_UNEXPECTEDEND;
	}
	if (ctx->digits != 0) {
		return ISC_R_BADBASE64;
	}
	return ISC_R_SUCCESS;
}

isc_result_t
isc_base64_tobuffer(isc_lex_t *lexer, isc_buffer_t *target, int length) {
	unsigned int before, after;
	base64_decode_ctx_t ctx;
	isc_textregion_t *tr;
	isc_token_t token;
	bool eol;

	REQUIRE(length >= isc_one_or_more);

	base64_decode_init(&ctx, length, target);

	before = isc_buffer_usedlength(target);
	while (!ctx.seen_end && (ctx.length != 0)) {
		if (length > 0) {
			eol = false;
		} else {
			eol = true;
		}
		RETERR(isc_lex_getmastertoken(lexer, &token,
					      isc_tokentype_string, eol));
		if (token.type != isc_tokentype_string) {
			break;
		}
		tr = &token.value.as_textregion;
		RETERR(base64_decode_chars(
			&ctx, (const unsigned char *)tr->base, tr->length));
	}
	after = isc_buffer_usedlength(target);
	if (ctx.length < 0 && !ctx.seen_end) {
		isc_lex_ungettoken(lexer, &token);
	}
	RETERR(base64_decode_finish(&ctx));
	if (length == isc_one_or_more && before == after) {
		return ISC_R_UNEXPECTEDEND;
	}
	return ISC_R_SUCCESS;
}

isc_result_t
isc_base64_decodestring(const char *cstr, isc_buffer_t *target) {
	base64_decode_ctx_t ctx;

	base64_decode_init(&ctx, isc_zero_or_more, target);
	for (;;) {
		int c = *cstr++;
		if (c == '\0') {
			break;
		}
		if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
			continue;
		}
		RETERR(base64_decode_char(&ctx, c));
	}
	RETERR(base64_decode_finish(&ctx));
	return ISC_R_SUCCESS;
}

static isc_result_t
str_totext(const char *source, isc_buffer_t *target) {
	unsigned int l;
	isc_region_t region;

	isc_buffer_availableregion(target, &region);
	l = strlen(source);

	if (l > region.length) {
		return ISC_R_NOSPACE;
	}

	memmove(region.base, source, l);
	isc_buffer_add(target, l);
	return ISC_R_SUCCESS;
}

static isc_result_t
mem_tobuffer(isc_buffer_t *target, void *base, unsigned int length) {
	isc_region_t tr;

	isc_buffer_availableregion(target, &tr);
	if (length > tr.length) {
		return ISC_R_NOSPACE;
	}
	memmove(tr.base, base, length);
	isc_buffer_add(target, length);
	return ISC_R_SUCCESS;
}
