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

#include <stdint.h>

#include <ngtcp2/ngtcp2.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/opensslv.h>
#include <openssl/ssl.h>

#include <isc/crypto.h>
#include <isc/quic.h>
#include <isc/util.h>

#include "quic_p.h"

static int quic_index;

static int
set_read_secret_cb(isc_tls_t *tls, enum ssl_encryption_level_t level,
		   const SSL_CIPHER *cipher, const uint8_t *secret, size_t len);

static int
set_write_secret_cb(isc_tls_t *tls, enum ssl_encryption_level_t level,
		    const SSL_CIPHER *cipher, const uint8_t *secret,
		    size_t len);

static int
add_handshake_data_cb(isc_tls_t *tls, enum ssl_encryption_level_t level,
		      const uint8_t *data, size_t len);

static int
flush_flight_cb(isc_tls_t *tls);

static int
send_alert_cb(isc_tls_t *ssl, enum ssl_encryption_level_t level, uint8_t alert);

static SSL_QUIC_METHOD method = {
	.set_read_secret = set_read_secret_cb,
	.set_write_secret = set_write_secret_cb,
	.add_handshake_data = add_handshake_data_cb,
	.flush_flight = flush_flight_cb,
	.send_alert = send_alert_cb,
};

static ngtcp2_encryption_level libssl_to_ngtcp2_level_lut[] = {
	[ssl_encryption_initial] = NGTCP2_ENCRYPTION_LEVEL_INITIAL,
	[ssl_encryption_early_data] = NGTCP2_ENCRYPTION_LEVEL_0RTT,
	[ssl_encryption_handshake] = NGTCP2_ENCRYPTION_LEVEL_HANDSHAKE,
	[ssl_encryption_application] = NGTCP2_ENCRYPTION_LEVEL_1RTT,
};

static enum ssl_encryption_level_t libngtcp2_to_ssl_level_lut[] = {
	[NGTCP2_ENCRYPTION_LEVEL_INITIAL] = ssl_encryption_initial,
	[NGTCP2_ENCRYPTION_LEVEL_0RTT] = ssl_encryption_early_data,
	[NGTCP2_ENCRYPTION_LEVEL_HANDSHAKE] = ssl_encryption_handshake,
	[NGTCP2_ENCRYPTION_LEVEL_1RTT] = ssl_encryption_application,
};

static int
set_read_secret_cb(isc_tls_t *tls, enum ssl_encryption_level_t level,
		   const SSL_CIPHER *cipher ISC_ATTR_UNUSED,
		   const uint8_t *secret, size_t len) {
	isc_quic_conn_t *conn = SSL_get_ex_data(tls, quic_index);
	bool is_server;

#if NGTCP2_VERSION_NUM >= 0x011700 /* 1.23.0 */
	is_server = ngtcp2_conn_is_server2(conn->inner);
#else  /* NGTCP2_VERSION_NUM >= 0x011700 */
	is_server = ngtcp2_conn_is_server(conn->inner);
#endif /* NGTCP2_VERSION_NUM >= 0x011700 */

	if (isc__quic_setup_read_key(
		    conn, is_server, libssl_to_ngtcp2_level_lut[level],
		    (isc_constregion_t){ secret, len }) != ISC_R_SUCCESS)
	{
		return 0;
	}

	return 1;
}

static int
set_write_secret_cb(isc_tls_t *tls, enum ssl_encryption_level_t level,
		    const SSL_CIPHER *cipher ISC_ATTR_UNUSED,
		    const uint8_t *secret, size_t len) {
	isc_quic_conn_t *conn = SSL_get_ex_data(tls, quic_index);
	bool is_server;

#if NGTCP2_VERSION_NUM >= 0x011700 /* 1.23.0 */
	is_server = ngtcp2_conn_is_server2(conn->inner);
#else  /* NGTCP2_VERSION_NUM >= 0x011700 */
	is_server = ngtcp2_conn_is_server(conn->inner);
#endif /* NGTCP2_VERSION_NUM >= 0x011700 */

	if (isc__quic_setup_write_key(
		    conn, is_server, libssl_to_ngtcp2_level_lut[level],
		    (isc_constregion_t){ secret, len }) != ISC_R_SUCCESS)
	{
		return 0;
	}

	return 1;
}

static int
add_handshake_data_cb(isc_tls_t *tls, enum ssl_encryption_level_t level,
		      const uint8_t *data, size_t len) {
	isc_quic_conn_t *conn;
	int r;

	REQUIRE(level < ARRAY_SIZE(libssl_to_ngtcp2_level_lut));

	conn = SSL_get_ex_data(tls, quic_index);

	r = ngtcp2_conn_submit_crypto_data(
		conn->inner, libssl_to_ngtcp2_level_lut[level], data, len);
	if (r != 0) {
		ngtcp2_conn_set_tls_error(conn->inner, r);
		return 0;
	}

	return 1;
}

static int
flush_flight_cb(isc_tls_t *tls ISC_ATTR_UNUSED) {
	return 1;
}

static int
send_alert_cb(isc_tls_t *tls, enum ssl_encryption_level_t level ISC_ATTR_UNUSED,
	      uint8_t alert) {
	isc_quic_conn_t *conn = SSL_get_ex_data(tls, quic_index);
	ngtcp2_conn_set_tls_alert(conn->inner, alert);
	return 1;
}

isc_result_t
isc__quic_set_remote_transport_params(isc_quic_conn_t *conn, isc_tls_t *tls) {
	const uint8_t *out_params;
	size_t out_params_len;
	int r;

	SSL_get_peer_quic_transport_params(tls, &out_params, &out_params_len);

	r = ngtcp2_conn_decode_and_set_remote_transport_params(
		conn->inner, out_params, out_params_len);
	if (r != 0) {
		ngtcp2_conn_set_tls_error(conn->inner, r);
		return ISC_R_TLSERROR;
	}

	return ISC_R_SUCCESS;
}

isc_result_t
isc__quic_set_local_transport_params(isc_quic_conn_t *conn ISC_ATTR_UNUSED,
				     isc_tls_t *tls) {
	uint8_t buffer[512];
	ngtcp2_ssize len;
	int r;

#if NGTCP2_VERSION_NUM >= 0x011700 /* 1.23.0 */
	len = ngtcp2_conn_encode_local_transport_params2(conn->inner, buffer,
							 sizeof(buffer));
#else
	len = ngtcp2_conn_encode_local_transport_params(conn->inner, buffer,
							sizeof(buffer));
#endif
	if (len < 0) {
		return ISC_R_NOSPACE;
	}

	ERR_set_mark();
	r = SSL_set_quic_transport_params(tls, buffer, len);
	ERR_pop_to_mark();
	if (r != 1) {
		return ISC_R_TLSERROR;
	}

	return ISC_R_SUCCESS;
}

isc_result_t
isc__quic_setup_tls(isc_tls_t *tls, isc_quic_conn_t *conn ISC_ATTR_UNUSED) {
	SSL_set_ex_data(tls, quic_index, conn);

	RUNTIME_CHECK(SSL_set_min_proto_version(tls, TLS1_3_VERSION) == 1);
	RUNTIME_CHECK(SSL_set_max_proto_version(tls, TLS1_3_VERSION) == 1);
	RUNTIME_CHECK(SSL_set_quic_method(tls, &method) == 1);

	return ISC_R_SUCCESS;
}

isc_result_t
isc__quic_do_tls(isc_quic_conn_t *conn, isc_tls_t *tls,
		 ngtcp2_encryption_level nglevel, isc_constregion_t data) {
	enum ssl_encryption_level_t level;
	isc_result_t result;
	ngtcp2_conn *ngconn;
	int r;

	REQUIRE(nglevel < ARRAY_SIZE(libngtcp2_to_ssl_level_lut));

	level = libngtcp2_to_ssl_level_lut[nglevel];
	ngconn = conn->inner;

	ERR_set_mark();

	if (data.length != 0 &&
	    SSL_provide_quic_data(tls, level, data.base, data.length) != 1)
	{
		CLEANUP(ISC_R_TLSERROR);
	}

	while (!ngtcp2_conn_get_handshake_completed(ngconn)) {
		r = SSL_do_handshake(tls);
		if (r != 1) {
			switch (SSL_get_error(tls, r)) {
			case SSL_ERROR_WANT_READ:
			case SSL_ERROR_WANT_WRITE:
			case SSL_ERROR_WANT_X509_LOOKUP:
#ifdef LIBRESSL_VERSION_NUMBER
			case SSL_ERROR_WANT_CLIENT_HELLO_CB:
				CLEANUP(ISC_R_SUCCESS);
#else
			case SSL_ERROR_WANT_PRIVATE_KEY_OPERATION:
			case SSL_ERROR_WANT_CERTIFICATE_VERIFY:
				CLEANUP(ISC_R_SUCCESS);
			case SSL_ERROR_EARLY_DATA_REJECTED:
#if NGTCP2_VERSION_NUM >= 0x011700 /* 1.23.0 */
				INSIST(!ngtcp2_conn_is_server2(ngconn));
#else
				INSIST(!ngtcp2_conn_is_server(ngconn));
#endif
				SSL_reset_early_data_reject(tls);
				if (ngtcp2_conn_tls_early_data_rejected(
					    ngconn) != 0)
				{
					CLEANUP(ISC_R_FAILURE);
				}
				continue;
#endif /* LIBRESSL_VERSION_NUMBER */
			default:
				CLEANUP(ISC_R_TLSERROR);
			}
		}

#ifndef LIBRESSL_VERSION_NUMBER
		if (SSL_in_early_data(tls) == 1) {
			CLEANUP(ISC_R_SUCCESS);
		}
#endif /* LIBRESSL_VERSION_NUMBER */

		ngtcp2_conn_tls_handshake_completed(ngconn);

		break;
	}

	r = SSL_process_quic_post_handshake(tls);
	if (r != 1) {
		switch (SSL_get_error(tls, r)) {
		case SSL_ERROR_WANT_READ:
		case SSL_ERROR_WANT_WRITE:
			break;
		default:
			CLEANUP(ISC_R_TLSERROR);
		}
	}

	result = ISC_R_SUCCESS;

cleanup:
	ERR_pop_to_mark();
	return result;
}

void
isc__quic_initialize(void) {
	quic_index = SSL_get_ex_new_index(0, NULL, NULL, NULL, NULL);
}

void
isc__quic_shutdown(void) {
	/* noop */
}
