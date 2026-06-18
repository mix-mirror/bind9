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
#include <ngtcp2/ngtcp2_crypto.h>

#include <isc/quic.h>

typedef struct quic_stream quic_stream_t;

typedef enum quic_conn_state {
	QUIC_CONN_STATE_INVALID = 0x00,
	QUIC_CONN_STATE_HANDSHAKE = 0x01,
	QUIC_CONN_STATE_CONNECTED = 0x02,
	QUIC_CONN_STATE_CLOSED = 0x03,
	QUIC_CONN_STATE_TERMINATED = 0x04,
} quic_conn_state_t;

struct isc_quic_conn {
	uint32_t magic;
	quic_conn_state_t state;
	isc_quic_cid_map_t *cidmap;
#ifdef HAVE_OPENSSL_3
	ngtcp2_crypto_ossl_ctx *ossl_ctx;
#else
	isc_tls_t *tls;
#endif
	ngtcp2_crypto_conn_ref crypto_ref;
	isc_quic_conn_callbacks_t *cb;
	void *cbarg;
	ISC_LIST(isc_quic_stream_data_t) incoming_stream_data;
	ISC_LIST(isc_quic_stream_data_t) outgoing_stream_data;
	ISC_LIST(quic_stream_t) streams;
	struct {
		uint8_t len;
		uint8_t buf[7];
	} alpn;
	/*
	 * isc_mem_t is stored inside `mem.user_data`
	 */
	ngtcp2_mem mem;
	ngtcp2_path path;
	ngtcp2_ccerr ccerr;
	ngtcp2_conn *inner;
};

#ifdef HAVE_OPENSSL_3
#define isc__quic_client_initial_cb ngtcp2_crypto_client_initial_cb
#define isc__quic_encrypt_cb	    ngtcp2_crypto_encrypt_cb
#define isc__quic_decrypt_cb	    ngtcp2_crypto_decrypt_cb
#else

int
isc__quic_client_initial_cb(ngtcp2_conn *ngconn, void *user_data);

int
isc__quic_encrypt_cb(uint8_t *dest, const ngtcp2_crypto_aead *ngaead,
		     const ngtcp2_crypto_aead_ctx *ngaeadctx,
		     const uint8_t *plaintext, size_t plaintextlen,
		     const uint8_t *nonce, size_t noncelen, const uint8_t *aad,
		     size_t aadlen);

int
isc__quic_decrypt_cb(uint8_t *dest, const ngtcp2_crypto_aead *ngaead,
		     const ngtcp2_crypto_aead_ctx *ngaeadctx,
		     const uint8_t *ciphertext, size_t ciphertextlen,
		     const uint8_t *nonce, size_t noncelen, const uint8_t *aad,
		     size_t aadlen);
#endif
