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

#include <isc/attributes.h>
#include <isc/refcount.h>
#include <isc/region.h>
#include <isc/time.h>
#include <isc/tls.h>
#include <isc/types.h>

/*! \file isc/quic.h */

/**
 * \brief
 * Minimum allowed length of a CID.
 *
 * Specified in RFC9000, Section 17.2.
 */
#define ISC_QUIC_CID_MIN_LENGTH 1

/**
 * \brief
 * Maximum allowed length of a CID.
 *
 * Specified in RFC9000, Section 17.2.
 */
#define ISC_QUIC_CID_MAX_LENGTH 20

/**
 * \brief
 * Length of the stateless reset token.
 *
 * Specified in RFC9000, Section 10.3.
 */
#define ISC_QUIC_STATELESS_TOKEN_LENGTH 16

/**
 * \brief
 * Infinite timeout or an invalid timestamp.
 */
constexpr isc_nanosecs_t isc_quic_timestamp_invalid = UINT64_MAX;

/**
 * \brief
 * Thread-safe data structure for associating CID's and stateless reset tokens
 * to QUIC connections.
 */
typedef struct isc_quic_router isc_quic_router_t;

struct isc_quic_stream_data_info {
	bool final;

	/**
	 * \brief
	 * True if the data is trasmitted during 0-RTT.
	 */
	bool zerortt;

	int64_t stream_id;
};

typedef struct isc_quic_server_options {
	isc_tlsctx_t	 *tlsctx;
	isc_constregion_t alpn;
	isc_nanosecs_t	  idle_timeout;
} isc_quic_server_options_t;

struct isc_quic_client_options {
	isc_tlsctx_t	 *tlsctx;
	isc_constregion_t alpn;
	isc_nanosecs_t	  idle_timeout;
};

/**
 * \brief
 * User-specified callbacks
 *
 * All callbacks are optional.
 */
struct isc_quic_conn_callbacks {
	/**
	 * \brief
	 * Handshake has been completed
	 *
	 * \param cbarg connection-specific callback argument.
	 */
	void (*handshake_completed)(void *cbarg);

	/**
	 * \brief
	 * Callback function for when the remote endpoint has opened a new
	 * stream.
	 *
	 * \param cbarg **connection**-specific callback argument
	 * \param stream_id ID of the newly opened stream.
	 */
	isc_result_t (*stream_opened)(void *cbarg, int64_t stream_id);

	/**
	 * \brief
	 * Callback function for when a stream has been closed.
	 *
	 * \param cbarg **connection**-specific callback argument
	 * \param stream_id ID of the closed stream
	 * \param has_application_error if the stream has closed with a failure
	 * \param application_error_code if `has_application_error` is true.
	 */
	isc_result_t (*stream_closed)(void *cbarg, int64_t stream_id,
				      bool     has_application_error,
				      uint64_t application_error_code);

	/**
	 * \brief
	 * Callback function for when there is data to be read in a stream.
	 *
	 * Called by #isc_quic_conn_push_packet when there is data to be read
	 * in a stream.
	 *
	 * \param cbarg User-specified callback argument.
	 * \param info Frame-relevant information.
	 * \param data Contents of the stream.
	 */
	isc_result_t (*data_read)(void *cbarg, isc_quic_stream_data_info_t info,
				  isc_constregion_t data);
};

typedef enum isc_quic_version {
	/** Invalid QUIC version */
	ISC_QUIC_VERSION_INVALID = 0,

	/** Unknown QUIC version */
	ISC_QUIC_VERSION_UNKNOWN = 1,

	/** RFC9000 */
	ISC_QUIC_VERSION_V1 = 2,

	/** RFC9369 */
	ISC_QUIC_VERSION_V2 = 3,

	ISC_QUIC_VERSION__MAX = 4,
} isc_quic_version_t;

struct isc_quic_stream_data {
	/**
	 *
	 */
	bool finish;

	/**
	 *
	 */
	bool zerortt;

	/**
	 * Stream ID of the given data.
	 */
	int64_t stream_id;

	size_t length;

	size_t offset;

	/**
	 * \warning
	 * Opaque. Don't touch.
	 */
	ISC_LINK(isc_quic_stream_data_t) link;

	/**
	 *
	 */
	uint8_t bytes[] ISC_ATTR_COUNTED_BY(length);
};

void
isc_quic_router_create(isc_mem_t *mctx, isc_quic_router_t **routerp);
/**<
 * \brief
 * Create a new QUIC CID router.
 *
 * \par Requires:
 * \li `mctx` is a valid memory context.
 * \li `routerp != NULL` and `*routerp == NULL`
 */

ISC_REFCOUNT_DECL(isc_quic_router);

isc_result_t
isc_quic_router_add_cid(isc_quic_router_t *router, isc_constregion_t cid,
			void *conn);
/**<
 * \brief
 * Associate a connection with the given CID.
 *
 * The CID will be copied and thus the parameter free from any lifetime
 * requirements.
 *
 * \par Requires:
 * \li `router` is a valid router.
 * \li `cid.base != NULL` and `cid.length` ∈ [1, 20]
 * \li `conn != NULL`
 *
 * \retval ISC_R_SUCCESS on success
 * \retval ISC_R_EXISTS if a connection exists for the given CID
 */

isc_result_t
isc_quic_router_get_cid(isc_quic_router_t *router, isc_constregion_t cid,
			void **connp);
/**<
 * \brief
 * Get the connection associated with a given CID.
 *
 * \par Requires:
 * \li `router` is a valid router.
 * \li `cid.base != NULL` and `cid.length` ∈ [1, 20]
 *
 * \retval ISC_R_SUCCESS on success
 * \retval ISC_R_NOTFOUND if no connection exists for the given CID.
 */

isc_result_t
isc_quic_router_del_cid(isc_quic_router_t *router, isc_constregion_t cid);
/**<
 * \brief
 * Remove the connection associated with the given CID.
 *
 * \par Requires:
 * \li `router` is a valid router.
 * \li `cid.base != NULL` and `cid.length` ∈ [1, 20]
 *
 * \retval ISC_R_SUCCESS on success
 * \retval ISC_R_NOTFOUND if no connection exists for the given CID.
 */

isc_result_t
isc_quic_router_add_stateless_reset(
	isc_quic_router_t *router,
	const uint8_t	   token[restrict ISC_QUIC_STATELESS_TOKEN_LENGTH],
	void		  *conn);
/**<
 * \brief
 * Associate a connection with the given stateless reset token.
 *
 * The token will be copied and thus the parameter free from any lifetime
 * requirements.
 *
 * \par Requires:
 * \li `router` is a valid router.
 * \li `token != NULL`
 * \li `conn != NULL`
 *
 * \retval ISC_R_SUCCESS on success
 * \retval ISC_R_EXISTS if a connection is already associated with the given
 * token.
 */

isc_result_t
isc_quic_router_get_stateless_reset(
	isc_quic_router_t *router,
	const uint8_t token[const restrict ISC_QUIC_STATELESS_TOKEN_LENGTH],
	void	    **connp);
/**<
 * \brief
 * Get the connection associated with the given stateless reset token.
 *
 * \par Requires:
 * \li `router` is a valid router.
 * \li `token` != NULL
 *
 * \retval ISC_R_SUCCESS on success
 * \retval ISC_R_NOTFOUND if no connection exists for the given token.
 */

isc_result_t
isc_quic_router_del_stateless_reset(
	isc_quic_router_t *router,
	const uint8_t token[const restrict ISC_QUIC_STATELESS_TOKEN_LENGTH]);
/**<
 * \brief
 * Remove the connection associated with the given stateless reset token.
 *
 * \par Requires:
 * \li `router` is a valid router.
 * \li `token != NULL`
 *
 * \retval ISC_R_SUCCESS on success
 * \retval ISC_R_NOTFOUND if no connection exists for the given token.
 */

isc_result_t
isc_quic_router_handle_packet(isc_quic_router_t	 *router,
			      isc_constregion_t	  packet,
			      isc_quic_version_t *versionp,
			      isc_constregion_t	 *dcidp,
			      isc_constregion_t *scidp, void **connp);
/**<
 * \brief
 * Extracts the associated value and relevant information of a given QUIC
 * packet.
 *
 * \par Requires:
 * \li `router` is a valid router.
 * \li `packet.base != NULL` and `packet.length != 0`
 * \li `dcidp != NULL`
 * \li `scidp != NULL`
 * \li `connp != NULL` and `*connp == NULL`
 *
 * It checks for the following
 * \li Check if the packet header is valid. If so, extract relevant information.
 * \li If the DCID is associated with a value, return it.
 * \li Otherwise, check if the packet version is unknown. If so, also check if
 * it has a stateless reset token.
 * \li Check if
 *
 * \warning
 * The router will **NOT** automatically remove the CID.
 *
 * \retval ISC_R_SUCCESS when an associated connection for the packet is found
 * \retval ISC_R_UNSET when a stateless reset packet for a session has been
 * found.
 * \retval ISC_R_NOTFOUND when the packet should be accepted as the handshake of
 * a new connection.
 * \retval ISC_R_INVALIDPROTO on packet misformat
 * \retval ISC_R_UNEXPECTED when the packet isn't associated with a connection
 * yet cannot be accepted as a handshake.
 * \retval ISC_R_IGNORE when the packet should be ignored silently.
 */

void
isc_quic_stream_data_destroy(isc_quic_conn_t	     *conn,
			     isc_quic_stream_data_t **datap);
/**<
 * \brief
 * Destroy stream data and its resources
 *
 * \par Requires:
 * \li `conn` is a valid QUIC connection state machine.
 * \li `datap != NULL` and `*datap` is a valid #isc_quic_stream_data_t produced
 * by `conn`.
 */

isc_result_t
isc_quic_conn_client_create(isc_mem_t *mctx, isc_quic_router_t *router,
			    const isc_quic_conn_callbacks_t *callbacks,
			    void			    *callback_arg,
			    const isc_quic_client_options_t *options,
			    const char *sni, const isc_sockaddr_t *local,
			    const isc_sockaddr_t *peer,
			    isc_quic_conn_t	**connp);

/**<
 * \brief
 * Create a new client state machine.
 *
 * \par Requires
 * \li `mctx` is a valid memory context
 * \li `cidmap` is a valid CID map
 * \li `connp != NULL` and `*connp == NULL`
 * \li `options != NULL`
 * \li `options.idle_timeout != isc_quic_timestamp_invalid`
 *
 * \retval #ISC_R_SUCCESS on success
 * \retval #ISC_R_NOMEMORY on memory failure
 * \retval #ISC_R_FAILURE on unknown failure
 */

isc_result_t
isc_quic_conn_server_create(isc_mem_t *mctx, isc_quic_router_t *router,
			    const isc_quic_conn_callbacks_t *callbacks,
			    void			    *callback_arg,
			    const isc_quic_server_options_t *options,
			    isc_constregion_t		     initial_dcid,
			    isc_constregion_t		     initial_scid,
			    const isc_sockaddr_t	    *local,
			    const isc_sockaddr_t	    *peer,
			    isc_quic_conn_t		   **connp);
/**<
 * \par Requires:
 * \li `connp != NULL` and `*connp == NULL`
 *
 */

void
isc_quic_conn_destroy(isc_quic_conn_t **connp);
/**<
 * \brief
 * Destroy the quic state machine.
 *
 * \par Requires:
 * \li `connp != NULL` and `*connp` is a valid state machine.
 */

isc_result_t
isc_quic_conn_pull_packet(isc_quic_conn_t *conn, isc_region_t out,
			  size_t *written, isc_sockaddr_t *from,
			  isc_sockaddr_t *to);
/**<
 * \brief
 * Consume a packet produced by the state machine if there is any.
 *
 * \retval ISC_R_SUCCESS on success
 * \retval ISC_R_TERMINATED if the connection has been terminated
 */

isc_result_t
isc_quic_conn_push_packet(isc_quic_conn_t *conn, isc_constregion_t packet,
			  isc_sockaddr_t *local, isc_sockaddr_t *peer);
/**<
 * \brief
 * Feed the incoming packet to the state machine.
 *
 * If provided, it might call the `data_read` callback.
 *
 * \par Requires
 * \li `conn` is a valid QUIC connection state machine.
 * \li `packet.base != NULL` and `packet` is a valid QUIC packet.
 *
 * \retval ISC_R_SUCCESS on success
 * \retval ISC_R_FAILURE on unknown failure
 */

isc_result_t
isc_quic_conn_handle_expiry(isc_quic_conn_t *conn);
/**<
 * \brief
 * Decides on the timeout action.
 *
 * This function is meant to be fired at a timeout after the duration specified
 * by #isc_quic_conn_next_expiry_time has passed.
 *
 * \retval ISC_R_SUCCESS when the a packet should be pulled from the connection
 * \retval ISC_R_TIMEDOUT when the connection should be dropped without further
 * interaction
 * \retval ISC_R_CANCELED when the connection is closed and yet it want to
 * transmit the connection to the endpoint
 */

isc_nanosecs_t
isc_quic_conn_next_expiry_time(isc_quic_conn_t *conn);
/**<
 * \brief
 * Get the next timeout duration.
 *
 * \par Requires:
 * \li `conn` is a valid QUIC connection state machine.
 *
 * \retval #isc_quic_timestamp_invalid if there are no timeouts to be handled
 */

isc_result_t
isc_quic_conn_shutdown_stream(isc_quic_conn_t *conn, int64_t stream_id,
			      uint64_t application_code);
/**
 * \brief
 * Abruptly shutdown a stream.
 *
 * \par Requires
 * \li `conn` is a valid QUIC connection state machine.
 * \li `stream_id` ≥ 0
 *
 * \retval ISC_R_SUCCESS on success
 * \retval ISC_R_NOMEMORY on memory context failure
 * \retval ISC_R_FAILURE on unknown failure
 */

isc_result_t
isc_quic_conn_open_bidi_stream(isc_quic_conn_t *conn, int64_t *stream_idp,
			       void *user_data);
/**<
 * \brief
 * Open a new bidrectional stream.
 *
 * \note
 * This does not trigger the `stream_opened` callback.
 *
 * \par Requires
 * \li `conn` is a valid QUIC connection state machine.
 * \li `stream_idp != NULL`
 * \li `user_data != NULL`
 *
 * \retval ISC_R_SUCCESS on success
 */

isc_result_t
isc_quic_conn_push_stream_data(isc_quic_conn_t *conn, int64_t stream_id,
			       uint8_t *data, size_t len);
/**<
 * \brief
 * Push stream data to the QUIC connection state machine.
 *
 * \par Requires
 * \li `conn` is a valid QUIC connection state machine.
 * \li `stream_id` ≥ 0
 * \li `data != NULL`
 *
 * \retval #ISC_R_SUCCESS on success
 * \retval #ISC_R_NOTFOUND if no such stream with the given ID exists
 */

void
isc__quic_initialize(void);

void
isc__quic_shutdown(void);
