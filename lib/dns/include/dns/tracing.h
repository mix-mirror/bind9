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
#define LTTNG_UST_TRACEPOINT_PROVIDER libdns

#undef LTTNG_UST_TRACEPOINT_INCLUDE
#define LTTNG_UST_TRACEPOINT_INCLUDE <dns/tracing.h>

#if !defined(DNS_TRACING_H) || defined(LTTNG_UST_TRACEPOINT_HEADER_MULTI_READ)
#define DNS_TRACING_H

#include <lttng/tracepoint.h>

/* clang-format off */

LTTNG_UST_TRACEPOINT_EVENT_CLASS(
	libdns,
	delegdb_cleanup,
	LTTNG_UST_TP_ARGS(
		void *, delegdb,
		size_t, requested
	),
	LTTNG_UST_TP_FIELDS(
		lttng_ust_field_integer_hex(uintptr_t, delegdb, (uintptr_t)delegdb)
		lttng_ust_field_integer(size_t, requested, requested)
	)
)

LTTNG_UST_TRACEPOINT_EVENT_INSTANCE(
	libdns,
	delegdb_cleanup,
	libdns,
	delegdb_cleanup_done,
	LTTNG_UST_TP_ARGS(
		void *, delegdb,
		size_t, requested
	)
)

LTTNG_UST_TRACEPOINT_EVENT_INSTANCE(
	libdns,
	delegdb_cleanup,
	libdns,
	delegdb_cleanup_start,
	LTTNG_UST_TP_ARGS(void *, delegdb,
			  size_t, requested
	)
)

LTTNG_UST_TRACEPOINT_EVENT_CLASS(
	libdns,
	delegdb,
	LTTNG_UST_TP_ARGS(
		void *, delegdb
	),
	LTTNG_UST_TP_FIELDS(
		lttng_ust_field_integer_hex(uintptr_t, delegdb, (uintptr_t)delegdb)
	)
)

LTTNG_UST_TRACEPOINT_EVENT_INSTANCE(
	libdns,
	delegdb,
	libdns,
	delegdb_create,
	LTTNG_UST_TP_ARGS(
		void *, delegdb
	)
)

LTTNG_UST_TRACEPOINT_EVENT_INSTANCE(
	libdns,
	delegdb,
	libdns,
	delegdb_shutdown,
	LTTNG_UST_TP_ARGS(
		void *, delegdb
	)
)

LTTNG_UST_TRACEPOINT_EVENT(
	libdns,
	delegdb_delete,
	LTTNG_UST_TP_ARGS(
		void *, delegdb,
		const char *, namebuf,
		int, tree,
		int, result
	),
	LTTNG_UST_TP_FIELDS(
		lttng_ust_field_integer_hex(uintptr_t, delegdb, (uintptr_t)delegdb)
		lttng_ust_field_string(name, namebuf)
		lttng_ust_field_integer(int, tree, (int)tree)
		lttng_ust_field_integer(int, result, result)
	)
)

LTTNG_UST_TRACEPOINT_EVENT(
	libdns,
	delegdb_evict,
	LTTNG_UST_TP_ARGS(
		void *, delegdb,
		void *, node,
		const char *, namebuf
	),
	LTTNG_UST_TP_FIELDS(
		lttng_ust_field_integer_hex(uintptr_t, delegdb, (uintptr_t)delegdb)
		lttng_ust_field_integer_hex(uintptr_t, node, (uintptr_t)node)
		lttng_ust_field_string(name, namebuf)
	)
)


LTTNG_UST_TRACEPOINT_EVENT(
	libdns,
	delegdb_insert_start,
	LTTNG_UST_TP_ARGS(
		void *, delegdb,
		const char *, zonecutbuf
	),
	LTTNG_UST_TP_FIELDS(
		lttng_ust_field_integer_hex(uintptr_t, delegdb, (uintptr_t)delegdb)
		lttng_ust_field_string(zonecut, zonecutbuf)
	)
)

LTTNG_UST_TRACEPOINT_EVENT(
	libdns,
	delegdb_insert_done,
	LTTNG_UST_TP_ARGS(
		void *, delegdb,
		const char *, zonecutbuf,
		int, result
	),
	LTTNG_UST_TP_FIELDS(
		lttng_ust_field_integer_hex(uintptr_t, delegdb, (uintptr_t)delegdb)
		lttng_ust_field_string(zonecut, zonecutbuf)
		lttng_ust_field_integer(int, result, result)
	)
)

LTTNG_UST_TRACEPOINT_EVENT(
	libdns,
	delegdb_lookup_start,
	LTTNG_UST_TP_ARGS(
		void *, delegdb,
		const char *, namebuf
	),
	LTTNG_UST_TP_FIELDS(
		lttng_ust_field_integer_hex(uintptr_t, delegdb, (uintptr_t)delegdb)
		lttng_ust_field_string(name, namebuf)
	)
)

LTTNG_UST_TRACEPOINT_EVENT(
	libdns,
	delegdb_lookup_done,
	LTTNG_UST_TP_ARGS(
		void *, delegdb,
		const char *, namebuf,
		int, result
	),
	LTTNG_UST_TP_FIELDS(
		lttng_ust_field_integer_hex(uintptr_t, delegdb, (uintptr_t)delegdb)
		lttng_ust_field_string(name, namebuf)
		lttng_ust_field_integer(int, result, result)
	)
)

LTTNG_UST_TRACEPOINT_EVENT_CLASS(
	libdns,
	xfrin_info,
	LTTNG_UST_TP_ARGS(
		void *, xfr,
		const char *, info
	),
	LTTNG_UST_TP_FIELDS(
		lttng_ust_field_integer_hex(uintptr_t, xfr, (uintptr_t)xfr)
		lttng_ust_field_string(xfr_info, info)
	)
)

LTTNG_UST_TRACEPOINT_EVENT_INSTANCE(
	libdns,
	xfrin_info,
	libdns,
	xfrin_axfr_finalize_begin,
	LTTNG_UST_TP_ARGS(
		void *, xfr,
		const char *, info
	)
)

LTTNG_UST_TRACEPOINT_EVENT_INSTANCE(
	libdns,
	xfrin_info,
	libdns,
	xfrin_start,
	LTTNG_UST_TP_ARGS(
		void *, xfr,
		const char *, info
	)
)

LTTNG_UST_TRACEPOINT_EVENT_INSTANCE(
	libdns,
	xfrin_info,
	libdns,
	xfrin_recv_send_request,
	LTTNG_UST_TP_ARGS(
		void *, xfr,
		const char *, info
	)
)

LTTNG_UST_TRACEPOINT_EVENT_CLASS(
	libdns,
	xfrin_info_result,
	LTTNG_UST_TP_ARGS(
		void *, xfr,
		const char *, info,
		int, result
	),
	LTTNG_UST_TP_FIELDS(
		lttng_ust_field_integer_hex(uintptr_t, xfr, (uintptr_t)xfr)
		lttng_ust_field_string(xfr_info, info)
		lttng_ust_field_integer(int, result, (int)result)
	)
)

LTTNG_UST_TRACEPOINT_EVENT_INSTANCE(
	libdns,
	xfrin_info_result,
	libdns,
	xfrin_connected,
	LTTNG_UST_TP_ARGS(
		void *, xfr,
		const char *, info,
		int, result
	)
)


LTTNG_UST_TRACEPOINT_EVENT_INSTANCE(
	libdns,
	xfrin_info_result,
	libdns,
	xfrin_axfr_finalize_end,
	LTTNG_UST_TP_ARGS(
		void *, xfr,
		const char *, info,
		int, result
	)
)

LTTNG_UST_TRACEPOINT_EVENT_INSTANCE(
	libdns,
	xfrin_info_result,
	libdns,
	xfrin_sent,
	LTTNG_UST_TP_ARGS(
		void *, xfr,
		const char *, info,
		int, result
	)
)

LTTNG_UST_TRACEPOINT_EVENT_INSTANCE(
	libdns,
	xfrin_info_result,
	libdns,
	xfrin_done_callback_begin,
	LTTNG_UST_TP_ARGS(
		void *, xfr,
		const char *, info,
		int, result
	)
)

LTTNG_UST_TRACEPOINT_EVENT_INSTANCE(
	libdns,
	xfrin_info_result,
	libdns,
	xfrin_done_callback_end,
	LTTNG_UST_TP_ARGS(
		void *, xfr,
		const char *, info,
		int, result
	)
)

LTTNG_UST_TRACEPOINT_EVENT_INSTANCE(
	libdns,
	xfrin_info_result,
	libdns,
	xfrin_recv_start,
	LTTNG_UST_TP_ARGS(
		void *, xfr,
		const char *, info,
		int, result
	)
)

LTTNG_UST_TRACEPOINT_EVENT_INSTANCE(
	libdns,
	xfrin_info_result,
	libdns,
	xfrin_recv_parsed,
	LTTNG_UST_TP_ARGS(
		void *, xfr,
		const char *, info,
		int, result
	)
)

LTTNG_UST_TRACEPOINT_EVENT_INSTANCE(
	libdns,
	xfrin_info_result,
	libdns,
	xfrin_recv_try_axfr,
	LTTNG_UST_TP_ARGS(
		void *, xfr,
		const char *, info,
		int, result
	)
)

LTTNG_UST_TRACEPOINT_EVENT_INSTANCE(
	libdns,
	xfrin_info_result,
	libdns,
	xfrin_read,
	LTTNG_UST_TP_ARGS(
		void *, xfr,
		const char *, info,
		int, result
	)
)

LTTNG_UST_TRACEPOINT_EVENT_INSTANCE(
	libdns,
	xfrin_info_result,
	libdns,
	xfrin_recv_done,
	LTTNG_UST_TP_ARGS(
		void *, xfr,
		const char *, info,
		int, result
	)
)

LTTNG_UST_TRACEPOINT_EVENT_CLASS(
	libdns,
	xfrin_info_message,
	LTTNG_UST_TP_ARGS(
		void *, xfr,
		const char *, info,
		void *, msg
	),
	LTTNG_UST_TP_FIELDS(
		lttng_ust_field_integer_hex(uintptr_t, xfr, (uintptr_t)xfr)
		lttng_ust_field_string(xfr_info, info)
		lttng_ust_field_integer_hex(uintptr_t, msg, (uintptr_t)msg)
	)
)

LTTNG_UST_TRACEPOINT_EVENT_INSTANCE(
	libdns,
	xfrin_info_message,
	libdns,
	xfrin_recv_question,
	LTTNG_UST_TP_ARGS(
		void *, xfr,
		const char *, info,
		void *, msg
	)
)

LTTNG_UST_TRACEPOINT_EVENT_INSTANCE(
	libdns,
	xfrin_info_message,
	libdns,
	xfrin_recv_answer,
	LTTNG_UST_TP_ARGS(
		void *, xfr,
		const char *, info,
		void *, msg
	)
)

LTTNG_UST_TRACEPOINT_EVENT(
	libdns,
	resolver_query,
	LTTNG_UST_TP_ARGS(
		void *, fctx,
		const char *, addrstr,
		int, srtt
	),
	LTTNG_UST_TP_FIELDS(
		lttng_ust_field_integer_hex(uintptr_t, fctx, (uintptr_t)fctx)
		lttng_ust_field_string(sockaddr, addrstr)
		lttng_ust_field_integer(int, srtt, srtt)
	)
)

/* clang-format on */

#endif /* DNS_TRACING_H */

#include <lttng/tracepoint-event.h>

#else /* ENABLE_TRACING */

#define lttng_ust_tracepoint(...)
#define lttng_ust_tracepoint_enabled(...) 0

#endif /* ENABLE_TRACING */
