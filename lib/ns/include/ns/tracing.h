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

#ifdef ENABLE_TRACING

#undef LTTNG_UST_TRACEPOINT_PROVIDER
#define LTTNG_UST_TRACEPOINT_PROVIDER libns

#undef LTTNG_UST_TRACEPOINT_INCLUDE
#define LTTNG_UST_TRACEPOINT_INCLUDE <ns/tracing.h>

#if !defined(NS_TRACING_H) || defined(LTTNG_UST_TRACEPOINT_HEADER_MULTI_READ)
#define NS_TRACING_H

#include <lttng/tracepoint.h>

/* clang-format off */

LTTNG_UST_TRACEPOINT_EVENT(
	libns,
	rrl_drop,
	LTTNG_UST_TP_ARGS(
		const char *, peerbuf,
		const char *, qnamebuf,
		const char *, fnamebuf,
		int, rrl_result
	),
	LTTNG_UST_TP_FIELDS(
		lttng_ust_field_string(peer, peerbuf)
		lttng_ust_field_string(qname, qnamebuf)
		lttng_ust_field_string(fname, fnamebuf)
		lttng_ust_field_integer(int, rrl_result, (int)rrl_result)
	)
)

/* clang-format on */

#endif /* NS_TRACING_H */

#include <lttng/tracepoint-event.h>

#else /* ENABLE_TRACING */

#define lttng_ust_tracepoint(...)
#define lttng_ust_tracepoint_enabled(...) 0

#endif /* ENABLE_TRACING */
