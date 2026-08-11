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

#include <isc/refcount.h>
#include <isc/region.h>
#include <isc/result.h>
#include <isc/tid.h>
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
 * Thread-safe data structure for associating CID's and stateless reset tokens
 * to QUIC connections.
 */
typedef struct isc_quic_router isc_quic_router_t;

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
 * The current thread will be used for the TID of the connection.
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
			isc_tid_t *tidp, void **connp);
/**<
 * \brief
 * Get the connection associated with a given CID and its thread if `tidp` is
 * not NULL.
 *
 * \note
 * The router does not hold a reference on the returned connection; it only
 * keeps the routing entry alive for the duration of the lookup. The caller is
 * responsible for ensuring the connection is not torn down while the returned
 * pointer is in use (e.g. by only tearing it down on its owning `tid`).
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
 * The current thread will be used for the TID of the connection.
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
	isc_tid_t *tidp, void **connp);
/**<
 * \brief
 * Get the connection associated with the given stateless reset token and its
 * thread if `tidp` is not NULL.
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
			      isc_constregion_t *scidp, isc_tid_t *tidp,
			      void **connp);
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
 * \li Check if it can be accepted as a handshake.
 *
 * \warning
 * The router will **NOT** automatically remove the CID on stateless reset.
 *
 * \note
 * On return, `*dcidp` and `*scidp` alias into `packet.base`; they are only
 * valid for as long as `packet` is, and are left unset on the
 * ISC_R_INVALIDPROTO path (where the header could not be decoded).
 *
 * \note
 * When a connection is returned via `*connp`, the router holds no reference on
 * it; the caller is responsible for keeping it alive (see
 * isc_quic_router_get_cid()).
 *
 * \retval ISC_R_SUCCESS when an associated connection for the packet is found
 * \retval ISC_R_UNSET when a stateless reset packet for a session has been
 * found.
 * \retval ISC_R_NOTFOUND when the packet should be accepted as the handshake of
 * a new connection.
 * \retval ISC_R_FAILURE when the version is unsupported and a Version
 * Negotiation packet should be sent; `*dcidp` and `*scidp` are populated with
 * the peer's connection IDs (which may exceed ISC_QUIC_CID_MAX_LENGTH).
 * \retval ISC_R_INVALIDPROTO on packet misformat
 * \retval ISC_R_UNEXPECTED when the packet isn't associated with a connection
 * yet cannot be accepted as a handshake.
 * \retval ISC_R_IGNORE when the packet should be ignored silently.
 */
