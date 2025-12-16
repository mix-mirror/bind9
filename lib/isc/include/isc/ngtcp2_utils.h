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

#include <ngtcp2/ngtcp2.h>

#include <isc/region.h>
#include <isc/sockaddr.h>

#define ISC_NGTCP2_PROTO_VER_RESERVED ((uint32_t)0x1a2a3a4au)
/*%<
 * The versions in form of 0x?a?a?a?a are a reserved to test version
 * negotiation.
 */

#define ISC_NGTCP2_MAX_POSSIBLE_CID_LENGTH (255)
/*%<
 * Maximum theoretical size of a CID that is possible and supported
 * by 'ngtcp2_pkt_decode_version_cid()'. All currently used versions
 * of QUIC have smaller limit defined as 'NGTCP2_MAX_CIDLEN', but
 * future versions of QUIC might use larger CIDs.
 */

#define ISC_QUIC_SERVER_SCID_LEN (18)
/*%<
 * Server's SCID length.
 */

void
isc_ngtcp2_gen_cid(ngtcp2_cid *restrict cid, const size_t size);
/*%<
 * Generate a new connection ID data.
 *
 * Requires:
 *\li	'cid' != NULL;
 *\li	'size' >= NGTCP2_MIN_CIDLEN && 'size' <=
 * NGTCP2_MAX_CIDLEN.
 */

void
isc_ngtcp2_copy_cid(ngtcp2_cid *restrict dst, const ngtcp2_cid *restrict src);
/*%<
 * Copy a connection ID data.
 *
 * Requires:
 *\li	'dst' != NULL;
 *\li	'src' != NULL && 'src->datalen' > 0.
 */

void
isc_ngtcp2_copy_cid_region(ngtcp2_cid *restrict dst,
			   const isc_region_t *restrict src);
/*%<
 * Copy a connection ID data from the given 'isc_region_t' source
 * object.
 *
 * Requires:
 *\li	'dst' != NULL;
 *\li	'src' != NULL && 'src->base' != NULL && 'src->length' <=
 * NGTCP2_MAX_CIDLEN.
 */

static inline void
isc_ngtcp2_cid_region(ngtcp2_cid *restrict cid, isc_region_t *restrict region) {
	REQUIRE(cid != NULL);
	REQUIRE(region != NULL);

	region->base = &cid->data[0];
	region->length = cid->datalen;
}
/*%<
 * Initialize the given 'isc_region_t' object to point to data held
 * by the given 'ngtcp2_cid' object.
 *
 * Requires:
 *\li	'cid' != NULL;
 *\li	'region' != NULL.
 */

void
isc_ngtcp2_addr_init(ngtcp2_addr *restrict ngaddr,
		     const isc_sockaddr_t *restrict addr);
/*%<
 * Initialize the given 'ngtcp2_addr' object according the data from
 * the given 'isc_sockaddr_t' object.
 *
 * NOTE: Please keep in mind that no data is copied, only pointers are
 * set and they are valid for as long as the given isc_sockaddr_t'
 * object is valid.
 *
 * Requires:
 *\li	'ngaddr' != NULL;
 *\li	'addr' != NULL.
 */

void
isc_ngtcp2_path_init(ngtcp2_path *restrict path,
		     const isc_sockaddr_t *restrict local,
		     const isc_sockaddr_t *restrict peer);
/*%<
 * Initialize the given 'ngtcp2_path' according the data from the
 * given 'isc_sockaddr_t' objects.
 *
 * NOTE: Please keep in mind that no data is copied, only pointers are
 * set and they are valid for as long as the given isc_sockaddr_t'
 * objects are valid.
 *
 * Requires:
 *\li	'path' != NULL;
 *\li	'local' != NULL;
 *\li	'peer' != NULL.
 */

void
isc_ngtcp2_path_storage_init(ngtcp2_path_storage *restrict path_storage,
			     const isc_sockaddr_t *restrict local,
			     const isc_sockaddr_t *restrict peer);
/*%<
 * Initialize the given 'ngtcp2_path_storage' according the data
 * from the given 'isc_sockaddr_t' objects. The data from the provided
 * addresses is copied inside the path storage object.
 *
 * Requires:
 *\li	'path_storage' != NULL;
 *\li	'local' != NULL;
 *\li	'peer' != NULL.
 */

void
isc_ngtcp2_path_getaddrs(const ngtcp2_path *restrict path,
			 isc_sockaddr_t *restrict local,
			 isc_sockaddr_t *restrict peer);
/*%<
 * Return the individual components of the given QUIC path object,
 * if pointers are specified.
 *
 * Requires:
 *\li	'path' != NULL.
 */

static inline ngtcp2_duration
isc_ngtcp2_make_duration(const uint32_t seconds, const uint32_t millis) {
	const ngtcp2_duration duration =
		((NGTCP2_SECONDS * seconds) + (NGTCP2_MILLISECONDS * millis));

	/*
	 * UINT64_MAX is an invalid value in ngtcp2. Often used as the no-value
	 * marker.
	 */
	INSIST(duration <= UINT64_MAX);

	return duration;
}
/*%<
 * An utility to generate a duration/timestamp with nanosecond
 * accuracy that is suitable to use in ngtcp2.
 */

void
isc_ngtcp2_mem_init(ngtcp2_mem *restrict mem, isc_mem_t *mctx);
/*%<
 * Initialize an 'ngtcp2_mem' object so that it can be used to route
 * memory allocation operations to the given memory context.
 *
 * Requires:
 *\li	'mem' != NULL;
 *\li	'mctx' != NULL.
 */

bool
isc_ngtcp2_is_version_available(const uint32_t	version,
				const uint32_t *versions,
				const size_t	versions_len);
/*%<
 * Returns 'true' if the given QUIC version is available in the given
 * set of versions.
 *
 * Requires:
 *\li	'versions' != NULL.
 */

uint32_t
isc_ngtcp2_select_version(const uint32_t  client_original_chosen_version,
			  const uint32_t *client_preferred_versions,
			  const size_t	  client_preferred_versions_len,
			  const uint32_t *server_preferred_versions,
			  const size_t	  server_preferred_versions_len);
/*%<
 *
 * Get a negotiated QUIC version following the rules described in
 * RFC8999 and, especially, RFC9368.
 *
 * NOTE: Similar to 'ngtcp2_select_version()' but a bit more strict
 * according to the RFC9368.
 *
 * Requires:
 *\li	'client_preferred_versions' != NULL;
 *\li	'server_preferred_versions' != NULL.
 */

static inline bool
isc_ngtcp2_pkt_header_is_long(const uint8_t *pkt, const size_t pktlen) {
	REQUIRE(pkt != NULL);
	REQUIRE(pktlen >= 5);

	if (pkt[0] & 0x80) {
		return true;
	}

	return false;
}
/*%<
 * Check if the QUIC packet uses a long form. The function is
 * expected to be used after a successful call to
 * 'ngtcp2_pkt_decode_version_cid()' which does some initial sanity
 * checks on a packet.
 *
 * See RFC8999 for more details about this and other version-agnostic
 * characteristics of QUIC.
 *
 * Requires:
 *\li	'pkt' != NULL;
 *\li	'pktlen' >= 5.
 */

isc_result_t
isc_ngtcp2_decode_pkt_header(const isc_region_t *pkt,
			     const size_t short_pkt_dcidlen, bool *pkt_long,
			     isc_region_t *pkt_scid, isc_region_t *pkt_dcid,
			     uint32_t *pkt_version);
/*%<
 * Get the basic information about the given QUIC packet header. You
 * can pass 'NULL' to the argument you are not interested in.  NOTE:
 * It is a specialized thin wrapper on top of
 * ngtcp2_pkt_decode_version_cid() intended to be used as a first step
 * in processing an incoming QUIC packet/UDP-datagram.
 *
 * Requires:
 *\li	'pkt' != NULL && 'pkt->base' != NULL && 'pkt->length' > 0.
 */

isc_result_t
isc_ngtcp2_decode_pkt_header_data(const uint8_t *pkt_data, const size_t pkt_len,
				  const size_t short_pkt_dcidlen,
				  bool *pkt_long, isc_region_t *pkt_scid,
				  isc_region_t *pkt_dcid,
				  uint32_t     *pkt_version);
/*%<
 *
 * Mostly same as above, but accepts data directly rather than via a
 * pointer to `isc_region_t`.
 *
 * Requires:
 *\li	'pkt_data' != NULL && 'pkt_len' > 0.
 */

static inline size_t
isc_ngtcp2_get_short_pkt_dcidlen(const bool client) {
	return client ? NGTCP2_MAX_CIDLEN : ISC_QUIC_SERVER_SCID_LEN;
}
/*%<
 * Return the short header DCID length.
 */

void
isc_ngtcp2_get_default_quic_versions(const uint32_t **protocols,
				     size_t	     *protocols_len);
/*%<
 * Get the list of default (aka supported) QUIC protocol versions.
 *
 * Requires:
 *\li	'protocols' != NULL && '*protocols' == NULL;
 *\li	'protocols_len' != NULL && '*protocols_len' == 0.
 */
