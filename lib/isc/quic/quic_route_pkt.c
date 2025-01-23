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

#include <isc/ngtcp2_crypto.h>
#include <isc/ngtcp2_utils.h>
#include <isc/quic.h>
#include <isc/random.h>

/*
 * This function is the main entry point for routing an incoming QUIC
 * packet.  It first attempts to find an existing session using the
 * packet's destination CID. If a session is found, it returns it. If
 * not, its behavior differs based on whether it is running on a
 * server or a client.
 *
 * On a client, if no session is found, it simply returns
 * ISC_R_NOTFOUND.
 *
 * On a server, if no session is found and the packet is an initial
 * packet (long header), it starts address validation. It may issue a
 * Retry packet to the client to verify its source address or validate
 * a token provided by the client. It may also issue a Version
 * Negotiation packet.
 */
isc_result_t
isc_quic_route_pkt(const isc_region_t *restrict pkt,
		   const isc_quic_cid_map_t *map,
		   const isc_region_t *restrict server_secret,
		   const uint32_t *available_versions,
		   const size_t available_versions_len,
		   const isc_sockaddr_t *restrict local,
		   const isc_sockaddr_t *restrict peer,
		   const isc_region_t *restrict pkt_dcid,
		   const isc_region_t *restrict pkt_scid,
		   const uint32_t version, const bool is_server,
		   const uint64_t retry_token_timeout_ns,
		   const uint64_t timestamp, isc_quic_session_t **sessionp,
		   isc_tid_t *tidp, isc_buffer_t *token_odcid_buf,
		   isc_quic_out_pkt_t *restrict out_pkt) {
	REQUIRE(pkt != NULL && pkt->length > 0 && pkt->base != NULL);
	REQUIRE(map != NULL);
	REQUIRE(!is_server ||
		(server_secret != NULL && server_secret->base != NULL &&
		 server_secret->length > 0));
	REQUIRE(local != NULL);
	REQUIRE(peer != NULL);
	REQUIRE(pkt_dcid != NULL && pkt_dcid->length > 0 &&
		pkt_dcid->base != NULL);
	REQUIRE(is_server || retry_token_timeout_ns == 0);
	REQUIRE(sessionp != NULL && *sessionp == NULL);
	REQUIRE(!is_server || (token_odcid_buf != NULL &&
			       isc_buffer_availablelength(token_odcid_buf) >=
				       ISC_NGTCP2_MAX_POSSIBLE_CID_LENGTH));
	REQUIRE(!is_server ||
		(out_pkt != NULL && out_pkt->pktbuf.base != NULL &&
		 out_pkt->pktbuf.length >= NGTCP2_MAX_UDP_PAYLOAD_SIZE &&
		 out_pkt->pktsz == 0));

	isc_quic_session_t *found_session = NULL;
	isc_tid_t found_tid = -1;

	/*
	 * First, try to find an existing session associated with the
	 * destination CID of the incoming packet.
	 */
	isc_result_t result = isc_quic_cid_map_find(map, pkt_dcid,
						    &found_session, &found_tid);
	if (result == ISC_R_SUCCESS) {
		/* A session was found. We are done. */
		goto done;
	}

	/*
	 * If we are not a server or if the packet does not have a long
	 * header, there is nothing more to do. Only servers handle new
	 * connections, which must start with a long header packet.
	 */
	if (!is_server ||
	    !isc_ngtcp2_pkt_header_is_long(pkt->base, pkt->length))
	{
		goto done;
	}

	/* check for the supported version first */
	bool send_verneg = false;

	if (!ngtcp2_is_supported_version(version) ||
	    ngtcp2_is_reserved_version(version))
	{
		send_verneg = true;
	} else if (available_versions != NULL && available_versions_len > 0 &&
		   !isc_ngtcp2_is_version_available(version, available_versions,
						    available_versions_len))
	{
		send_verneg = true;
	}

	if (send_verneg) {
		ssize_t written = written = ngtcp2_pkt_write_version_negotiation(
			out_pkt->pktbuf.base, out_pkt->pktbuf.length,
			isc_random8(), pkt_scid->base, pkt_scid->length,
			pkt_dcid->base, pkt_dcid->length,
			(uint32_t *)available_versions, available_versions_len);
		if (written > 0) {
			out_pkt->pktsz = written;
			out_pkt->local = *local;
			out_pkt->peer = *peer;
			ISC_LINK_INIT(&out_pkt->local, link);
			ISC_LINK_INIT(&out_pkt->peer, link);
		}

		goto exit;
	}

	/*
	 * From this point on, we are a server handling a long header packet
	 * for which no session was found. This is likely a new connection
	 * attempt. We need to parse the QUIC packet header.
	 */
	ngtcp2_pkt_hd hd = { 0 };
	int ret = ngtcp2_accept(&hd, pkt->base, pkt->length);
	if (ret != 0) {
		/* The packet header is malformed. */
		result = ISC_R_FAILURE;
		goto exit;
	}

	ngtcp2_addr peeraddr = { 0 };
	ngtcp2_cid odcid = { 0 }, rcid = { 0 }, scid = { 0 }, dcid = { 0 };
	bool write_retry = false;

	/* Prepare ngtcp2 address and CID structures. */
	isc_ngtcp2_addr_init(&peeraddr, peer);
	isc_ngtcp2_copy_cid_region(&dcid, pkt_dcid);
	isc_ngtcp2_copy_cid_region(&scid, pkt_scid);

	/*
	 * Check for a token. The token is a critical part of QUIC's
	 * anti-spoofing mechanism.
	 */
	if (hd.tokenlen == 0) {
		/*
		 * No token provided. This is likely the client's first packet.
		 * We must send a Retry packet to validate the client's address.
		 */
		write_retry = true;
	} else if (hd.tokenlen > 0 &&
		   hd.token[0] == ISC_NGTCP2_CRYPTO_TOKEN_MAGIC_RETRY)
	{
		/* The client has provided a Retry token. We must verify it. */
		isc_result_t verification_result =
			isc_ngtcp2_crypto_verify_retry_token(
				&odcid, hd.token, hd.tokenlen,
				server_secret->base, server_secret->length,
				version, peeraddr.addr, peeraddr.addrlen, &dcid,
				retry_token_timeout_ns, timestamp);
		if (verification_result != ISC_R_SUCCESS) {
			/* The token is invalid or expired. Send a new Retry. */
			write_retry = true;
		} else {
			/*
			 * The token is valid. Extract the original DCID (odcid)
			 * that the client used in its first Initial packet.
			 * This is needed by the caller to create a new session
			 * that is correctly associated with the client's
			 * original intent.
			 */
			isc_buffer_putmem(token_odcid_buf, odcid.data,
					  odcid.datalen);
		}
	} else if (hd.tokenlen > 0 &&
		   hd.token[0] == ISC_NGTCP2_CRYPTO_TOKEN_MAGIC_REGULAR)
	{
		/*
		 * The client has provided a regular token from a previous
		 * connection. We must verify it.
		 */
		isc_result_t verification_result =
			isc_ngtcp2_crypto_verify_regular_token(
				hd.token, hd.tokenlen, server_secret->base,
				server_secret->length, peeraddr.addr,
				peeraddr.addrlen,
				ISC_QUIC_SESSION_REGULAR_TOKEN_VALIDITY_PERIOD,
				timestamp);
		if (verification_result != ISC_R_SUCCESS) {
			/* The token is invalid. Force a new Retry handshake. */
			write_retry = true;
		}
		/*
		 * If the regular token is valid, we do not need to send a
		 * Retry. The caller can proceed with creating a new session.
		 */
	}

	/*
	 * If we decided a Retry packet is necessary, we construct and
	 * send one now.
	 */
	if (write_retry) {
		uint8_t tokenbuf[ISC_NGTCP2_CRYPTO_MAX_RETRY_TOKEN_LEN] = { 0 };

		/*
		 * Generate a new, unique CID for the client to use in its
		 * next Initial packet. This is the "Retry CID".
		 */
		isc_quic_cid_map_gen_unique_buf(map, rcid.data,
						ISC_QUIC_SERVER_SCID_LEN);
		rcid.datalen = ISC_QUIC_SERVER_SCID_LEN;

		/*
		 * Generate the Retry token. This token securely binds the
		 * client's address, its original DCID, and our new Retry CID.
		 */
		size_t token_len = isc_ngtcp2_crypto_generate_retry_token(
			tokenbuf, sizeof(tokenbuf), server_secret->base,
			server_secret->length, version, peeraddr.addr,
			peeraddr.addrlen, &rcid, &dcid, timestamp);

		if (token_len == 0) {
			result = ISC_R_UNEXPECTED;
			goto exit;
		}

		/* Write the complete Retry packet into the output buffer. */
		ssize_t written = isc_ngtcp2_crypto_write_retry(
			out_pkt->pktbuf.base, out_pkt->pktbuf.length, version,
			&scid, &rcid, &dcid, tokenbuf, token_len);

		if (written < 0) {
			result = ISC_R_UNEXPECTED;
			goto exit;
		}

		/* Populate the outgoing packet metadata. */
		out_pkt->pktsz = written;
		out_pkt->local = *local;
		out_pkt->peer = *peer;
		ISC_LINK_INIT(&out_pkt->local, link);
		ISC_LINK_INIT(&out_pkt->peer, link);

		/* The Retry packet is ready to be sent, so we exit. */
		goto exit;
	}

done:
	/*
	 * If a session was found, assign it to the output parameter.
	 * The caller is responsible for attaching its own reference if needed.
	 */
	if (found_session != NULL) {
		*sessionp = found_session;
		/* Thread ID */
		*tidp = found_tid;
	}

exit:
	/*
	 * Return the result of the operation. This will be ISC_R_SUCCESS if
	 * a session was found, or ISC_R_NOTFOUND if no session was found
	 * (and no Retry was sent), or an error code.
	 */
	return result;
}
