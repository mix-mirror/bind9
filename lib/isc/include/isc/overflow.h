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

#include <stdbool.h>

#include <isc/util.h>

#if __has_include(<stdckdint.h>)
#include <stdckdint.h>
#else /* __has_include(<stdckdint.h>) */
#define ckd_mul(cp, a, b) __builtin_mul_overflow(a, b, cp)
#define ckd_add(cp, a, b) __builtin_add_overflow(a, b, cp)
#define ckd_sub(cp, a, b) __builtin_sub_overflow(a, b, cp)
#endif /* __has_include(<stdckdint.h>) */

#define ISC_CHECKED_MUL(a, b)                             \
	({                                                \
		typeof(a) _c;                             \
		bool	  _overflow = ckd_mul(&_c, a, b); \
		INSIST(!_overflow);                       \
		_c;                                       \
	})

#define ISC_CHECKED_ADD(a, b)                             \
	({                                                \
		typeof(a) _c;                             \
		bool	  _overflow = ckd_add(&_c, a, b); \
		INSIST(!_overflow);                       \
		_c;                                       \
	})

#define ISC_CHECKED_SUB(a, b)                             \
	({                                                \
		typeof(a) _c;                             \
		bool	  _overflow = ckd_sub(&_c, a, b); \
		INSIST(!_overflow);                       \
		_c;                                       \
	})

#define ISC_CHECKED_MUL_ADD(a, b, c)                                          \
	({                                                                    \
		size_t _d;                                                    \
		bool   _overflow = ckd_mul(&_d, a, b) || ckd_add(&_d, _d, c); \
		INSIST(!_overflow);                                           \
		_d;                                                           \
	})
