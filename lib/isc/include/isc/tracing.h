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
#define LTTNG_UST_TRACEPOINT_PROVIDER libisc

#undef LTTNG_UST_TRACEPOINT_INCLUDE
#define LTTNG_UST_TRACEPOINT_INCLUDE <isc/tracing.h>

#if !defined(ISC_TRACING_H) || defined(LTTNG_UST_TRACEPOINT_HEADER_MULTI_READ)
#define ISC_TRACING_H

#include <lttng/tracepoint.h>

/* clang-format off */

LTTNG_UST_TRACEPOINT_EVENT_CLASS(
	libisc,
	rwlock,
	LTTNG_UST_TP_ARGS(
		void *, rwl
	),
	LTTNG_UST_TP_FIELDS(
		lttng_ust_field_integer_hex(uintptr_t, rwl, (uintptr_t)rwl)
	)
)

LTTNG_UST_TRACEPOINT_EVENT_INSTANCE(
	libisc,
	rwlock,
	libisc,
	rwlock_init,
	LTTNG_UST_TP_ARGS(
		void *, rwl
	)
)

LTTNG_UST_TRACEPOINT_EVENT_INSTANCE(
	libisc,
	rwlock,
	libisc,
	rwlock_destroy,
	LTTNG_UST_TP_ARGS(
		void *, rwl
	)
)

LTTNG_UST_TRACEPOINT_EVENT_INSTANCE(
	libisc,
	rwlock,
	libisc,
	rwlock_rdlock_req,
	LTTNG_UST_TP_ARGS(
		void *, rwl
	)
)

LTTNG_UST_TRACEPOINT_EVENT_INSTANCE(
	libisc,
	rwlock,
	libisc,
	rwlock_rdlock_acq,
	LTTNG_UST_TP_ARGS(
		void *, rwl
	)
)

LTTNG_UST_TRACEPOINT_EVENT_INSTANCE(
	libisc,
	rwlock,
	libisc,
	rwlock_rdunlock,
	LTTNG_UST_TP_ARGS(
		void *, rwl
	)
)

LTTNG_UST_TRACEPOINT_EVENT_INSTANCE(
	libisc,
	rwlock,
	libisc,
	rwlock_wrlock_req,
	LTTNG_UST_TP_ARGS(
		void *, rwl
	)
)

LTTNG_UST_TRACEPOINT_EVENT_INSTANCE(
	libisc,
	rwlock,
	libisc,
	rwlock_wrlock_acq,
	LTTNG_UST_TP_ARGS(
		void *, rwl
	)
)

LTTNG_UST_TRACEPOINT_EVENT_INSTANCE(
	libisc,
	rwlock,
	libisc,
	rwlock_wrunlock,
	LTTNG_UST_TP_ARGS(
		void *, rwl
	)
)

LTTNG_UST_TRACEPOINT_EVENT_INSTANCE(
	libisc,
	rwlock,
	libisc,
	rwlock_downgrade,
	LTTNG_UST_TP_ARGS(
		void *, rwl
	)
)

LTTNG_UST_TRACEPOINT_EVENT_CLASS(
	libisc,
	rwlock_try,
	LTTNG_UST_TP_ARGS(
		void *, rwl,
		int, result
	),
	LTTNG_UST_TP_FIELDS(
		lttng_ust_field_integer_hex(uintptr_t, rwl, (uintptr_t)rwl)
		lttng_ust_field_integer(int, result, result)
	)
)

LTTNG_UST_TRACEPOINT_EVENT_INSTANCE(
	libisc,
	rwlock_try,
	libisc,
	rwlock_tryrdlock,
	LTTNG_UST_TP_ARGS(
		void *, rwl,
		int, result
	)
)

LTTNG_UST_TRACEPOINT_EVENT_INSTANCE(
	libisc,
	rwlock_try,
	libisc,
	rwlock_tryupgrade,
	LTTNG_UST_TP_ARGS(
		void *, rwl,
		int, result
	)
)

LTTNG_UST_TRACEPOINT_EVENT_INSTANCE(
	libisc,
	rwlock_try,
	libisc,
	rwlock_trywrlock,
	LTTNG_UST_TP_ARGS(
		void *, rwl,
		int, result
	)
)

/*
 * Job Callbacks
 */

LTTNG_UST_TRACEPOINT_EVENT_CLASS(
	libisc,
	job_cb_class,
	LTTNG_UST_TP_ARGS(
		void *, job,
		void *, cb,
		void *, cbarg
	),
	LTTNG_UST_TP_FIELDS(
		lttng_ust_field_integer_hex(uintptr_t, job, (uintptr_t)job)
		lttng_ust_field_integer_hex(uintptr_t, cb, (uintptr_t)cb)
		lttng_ust_field_integer_hex(uintptr_t, cbarg, (uintptr_t)cbarg)
	)
)

LTTNG_UST_TRACEPOINT_EVENT_INSTANCE(
	libisc,
	job_cb_class,
	libisc,
	job_cb_before,
	LTTNG_UST_TP_ARGS(
		void *, job,
		void *, cb,
		void *, cbarg
	)
)

LTTNG_UST_TRACEPOINT_EVENT_INSTANCE(
	libisc,
	job_cb_class,
	libisc,
	job_cb_after,
	LTTNG_UST_TP_ARGS(
		void *, job,
		void *, cb,
		void *, cbarg
	)
)

/* clang-format on */

#endif /* ISC_TRACING_H */

#include <lttng/tracepoint-event.h>

#else /* ENABLE_TRACING */

#define lttng_ust_tracepoint(...)
#define lttng_ust_tracepoint_enabled(...) 0

#endif /* ENABLE_TRACING */
