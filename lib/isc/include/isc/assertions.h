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

/*! \file isc/assertions.h
 */

#pragma once

#include <isc/attributes.h>
#include <isc/lang.h>

ISC_LANG_BEGINDECLS

/*% isc assertion type */
typedef enum {
	isc_assertiontype_require,
	isc_assertiontype_ensure,
	isc_assertiontype_insist,
	isc_assertiontype_invariant
} isc_assertiontype_t;

typedef void (*isc_assertioncallback_t)(const char *, int, isc_assertiontype_t,
					const char *);

/* coverity[+kill] */
ISC_NORETURN void
isc_assertion_failed(const char *, int, isc_assertiontype_t, const char *);

void isc_assertion_setcallback(isc_assertioncallback_t);

const char *
isc_assertion_typetotext(isc_assertiontype_t type);

#define ISC_REQUIRE(cond)                                                 \
	do {                                                              \
		if (__builtin_expect(!(cond), 0)) {                       \
			(isc_assertion_failed)(__FILE__, __LINE__,        \
					       isc_assertiontype_require, \
					       #cond);                    \
			__builtin_unreachable();                          \
		}                                                         \
	} while (0)

#define ISC_ENSURE(cond)                                                 \
	do {                                                             \
		if (__builtin_expect(!(cond), 0)) {                      \
			(isc_assertion_failed)(__FILE__, __LINE__,       \
					       isc_assertiontype_ensure, \
					       #cond);                   \
			__builtin_unreachable();                         \
		}                                                        \
	} while (0)

#define ISC_INSIST(cond)                                                 \
	do {                                                             \
		if (__builtin_expect(!(cond), 0)) {                      \
			(isc_assertion_failed)(__FILE__, __LINE__,       \
					       isc_assertiontype_insist, \
					       #cond);                   \
			__builtin_unreachable();                         \
		}                                                        \
	} while (0)

#define ISC_INVARIANT(cond)                                                 \
	do {                                                                \
		if (__builtin_expect(!(cond), 0)) {                         \
			(isc_assertion_failed)(__FILE__, __LINE__,          \
					       isc_assertiontype_invariant, \
					       #cond);                      \
			__builtin_unreachable();                            \
		}                                                           \
	} while (0)

#define ISC_UNREACHABLE()                                                   \
	(isc_assertion_failed(__FILE__, __LINE__, isc_assertiontype_insist, \
			      "unreachable"),                               \
	 __builtin_unreachable())

ISC_LANG_ENDDECLS
