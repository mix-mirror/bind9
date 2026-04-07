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

/*! \file isc/quic.h */

#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <isc/list.h>
#include <isc/refcount.h>
#include <isc/region.h>
#include <isc/time.h>
#include <isc/tls.h>
#include <isc/types.h>

/**
 *
 */
typedef struct isc_quic_conn isc_quic_conn_t;

/**
 *
 */
typedef struct isc_quic_cid isc_quic_cid_t;

/**
 *
 */
typedef struct isc_quic_cid_map isc_quic_cid_map_t;

/**
 *
 */
typedef struct isc_quic_stream_data isc_quic_stream_data_t;

/**
 *
 */
typedef struct isc_quic_client_conn_options {
	isc_tlsctx_t	     *tlsctx;
	isc_quic_cid_t	     *dcid;
	isc_quic_cid_t	     *scid;
	const isc_sockaddr_t *local;
	const isc_sockaddr_t *peer;
	const char	     *sni;

	/**
	 *
	 */
	isc_constregion_t alpn;
} isc_quic_client_conn_options_t;

/**
 *
 */
typedef struct isc_quic_server_conn_options {
	isc_tlsctx_t	       *tlsctx;
	isc_quic_cid_t	       *dcid;
	isc_quic_cid_t	       *scid;
	const isc_sockaddr_t   *local;
	const isc_sockaddr_t   *peer;
	const isc_constregion_t initial_dcid;
	const isc_constregion_t initial_scid;

	/**
	 *
	 */
	isc_constregion_t alpn;
} isc_quic_server_conn_options_t;

/*
 *
 */
typedef struct isc_quic_conn_callbacks {
	/**
	 *
	 */
	isc_result_t (*stream_opened)(void *cbarg, int64_t stream_id);

	/**
	 *
	 */
	isc_result_t (*stream_closed)(void *cbarg, int64_t stream_id,
				      bool     has_application_error,
				      uint64_t application_error_code);
} isc_quic_conn_callbacks_t;

struct isc_quic_stream_data {
	bool	finish;
	bool	zerortt;
	int64_t stream_id;
	size_t	length;
	size_t	offset;
	ISC_LINK(isc_quic_stream_data_t) link;
	uint8_t bytes[];
};

constexpr isc_nanosecs_t isc_quic_timestamp_invalid = UINT64_MAX;

isc_quic_cid_t *
isc_quic_cid_random_new(size_t length, isc_mem_t *mctx);
/**
 *
 */

isc_constregion_t
isc_quic_cid_bytes(isc_quic_cid_t *cid);
/**
 *
 */

void
isc_quic_cid_destroy(isc_mem_t *mctx, isc_quic_cid_t **cidp);
/**
 *
 */

void
isc_quic_cid_map_create(isc_mem_t *mctx, isc_quic_cid_map_t **mapp);
/**
 *
 */

ISC_REFCOUNT_DECL(isc_quic_cid_map);

isc_result_t
isc_quic_cid_map_find(isc_quic_cid_map_t *map, isc_constregion_t cid_bytes,
		      isc_quic_conn_t **existsp, isc_tid_t *tidp);
/**
 * Returns:
 * - #ISC_R_SUCCESS on success
 * - #ISC_R_NOTFOUND if such a connection id doesn't exist
 */

isc_result_t
isc_quic_cid_map_add(isc_quic_cid_map_t *map, isc_quic_cid_t *cid,
		     isc_quic_conn_t *conn);
/**
 * Returns:
 * - #ISC_R_SUCCESS
 * - #ISC_R_EXISTS
 */

isc_result_t
isc_quic_cid_map_add_bytes(isc_quic_cid_map_t *map, isc_constregion_t cid_bytes,
			   isc_quic_conn_t *conn);
/**
 *
 */

isc_result_t
isc_quic_cid_map_remove(isc_quic_cid_map_t *map, isc_quic_cid_t *cid);
/**
 * Returns:
 * - #ISC_R_SUCCESS on success
 * - #ISC_R_NOTFOUND if such a connection id doesn't exist
 */

isc_result_t
isc_quic_packet_info_decode(isc_constregion_t *scid, isc_constregion_t *dcid,
			    isc_constregion_t data);
/**
 *
 */

void
isc_quic_stream_data_destroy(isc_quic_conn_t	     *conn,
			     isc_quic_stream_data_t **datap);
/**
 *
 */

isc_result_t
isc_quic_conn_client_create(isc_mem_t *mctx, isc_quic_cid_map_t *cidmap,
			    isc_quic_conn_callbacks_t		 *callbacks,
			    const isc_quic_client_conn_options_t *options,
			    isc_nanosecs_t timestamp, isc_quic_conn_t **connp);
/**
 *
 */

isc_result_t
isc_quic_conn_server_create(isc_mem_t *mctx, isc_quic_cid_map_t *cidmap,
			    isc_quic_conn_callbacks_t		 *callbacks,
			    const isc_quic_server_conn_options_t *options,
			    isc_nanosecs_t timestamp, isc_quic_conn_t **connp);
/**
 *
 */

void
isc_quic_conn_destroy(isc_quic_conn_t **connp);
/**
 *
 */

isc_nanosecs_t
isc_quic_conn_next_expiry_time(isc_quic_conn_t *conn);
/**
 *
 */

isc_result_t
isc_quic_conn_handle_expiry(isc_quic_conn_t *conn, isc_nanosecs_t timestamp);
/**
 *
 */

isc_result_t
isc_quic_conn_pull_packet(isc_quic_conn_t *conn, uint8_t *out, size_t len,
			  size_t *written,
			  isc_nanosecs_t (*timestamp_fn)(void));
/**
 *
 */

isc_result_t
isc_quic_conn_push_packet(isc_quic_conn_t *conn, isc_constregion_t packet,
			  isc_nanosecs_t timestamp_fn);
/**
 *
 */

isc_result_t
isc_quic_conn_shutdown_stream(isc_quic_conn_t *conn, int64_t stream_id,
			      uint64_t application_code);
/**
 *
 */

isc_result_t
isc_quic_conn_open_bidi_stream(isc_quic_conn_t *conn, int64_t *stream_idp,
			       void *user_data);
/**
 *
 */

isc_result_t
isc_quic_conn_pull_stream_data(isc_quic_conn_t	       *conn,
			       isc_quic_stream_data_t **datap);
/**
 *
 */

isc_result_t
isc_quic_conn_push_stream_data(isc_quic_conn_t *conn, int64_t stream_id,
			       uint8_t *data, size_t len);
/**
 *
 */

bool
isc_quic_conn_handshake_complete(isc_quic_conn_t *conn);
/**
 *
 */
