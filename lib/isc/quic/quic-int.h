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

#include <isc/tls.h>
#include <isc/types.h>

struct isc_tls_quic_interface {
	void (*tlsctx_configure)(isc_tlsctx_t *tlsctx);
	/* NOTE: the keylog callback will never be called on LibreSSL. */
	void (*tlsctx_keylog_callback)(const isc_tls_t *tls, const char *line);

	void (*tls_init)(isc_tls_t *tls, isc_mem_t *mctx);
	void (*tls_uninit)(isc_tls_t *tls);

	bool (*tls_calling_method_cb)(const isc_tls_t *tls);

	/* See SSL_set_quic_method() */
	int (*tls_set_quic_method)(isc_tls_t *tls,
				   const isc_tls_quic_method_t *method);

	/* See SSL_provide_quic_data() */
	int (*tls_provide_quic_data)(isc_tls_t *tls,
				     const isc_quic_encryption_level_t level,
				     const uint8_t *data, const size_t len);

	/* See SSL_do_handshake(). Internally it is a thin wrapper on top
	 * of it. It exists mostly to properly handle failed callbacks in
	 * a compatibility layer.
	 */
	int (*tls_do_quic_handshake)(isc_tls_t *tls);

	/*
	 * See SSL_process_quic_post_handshake(). In the worst case can
	 * be a dummy implementation (return 1) or a wrapper on top of
	 * SSL_read() in a compatibility layer.
	 */
	int (*tls_process_quic_post_handshake)(isc_tls_t *tls);

	/* See  SSL_set_quic_transport_params() */
	int (*tls_set_quic_transport_params)(isc_tls_t *tls,
					     const uint8_t *params,
					     const size_t params_len);

	/* See SSL_get_peer_quic_transport_params() */
	void (*tls_get_peer_quic_transport_params)(isc_tls_t *tls,
						   const uint8_t **out_params,
						   size_t *out_params_len);

	/* See SSL_quic_read_level() */
	isc_quic_encryption_level_t (*tls_quic_read_level)(const isc_tls_t *tls);

	/* See SSL_quic_read_level() */
	isc_quic_encryption_level_t (*tls_quic_write_level)(
		const isc_tls_t *tls);
};
/*%<
 * An interface used to implement functionality to access
 * QUIC-related TLS interfacing functionality of the used crypto
 * library (or a compatibility interface). It is based on the
 * interface used by LibreSSL/BoringSSL/QuicTLS so that it can be
 * easily implemented for these libraries.
 */

void *
isc__tls_get_quic_data(const isc_tls_t *tls);
/*%<
 * Returns opaque pointer referring to QUIC specific data associated with the
 * 'tls' object.
 */

void
isc__tls_set_quic_data(isc_tls_t *tls, void *data);
/*%<
 * Associates an opaque pointer referring to QUIC specific data with 'tls'
 * object.
 */

void
isc__tls_quic_init(isc_tls_t *tls);
/*%<
 * Initializes and configures the given TLS object to be used for QUIC.
 *
 * Requires:
 *\li	'tls' is a valid pointer to a TLS object.
 */

void
isc__tls_quic_uninit(isc_tls_t *tls);
/*%<
 * Deinitializes the given TLS object to be used for QUIC.
 *
 * Requires:
 *\li	'tls' is a valid pointer to a TLS object.
 */

bool
isc__tls_is_quic(isc_tls_t *tls);
/*%<
 * Returns 'true' if the given object is configured for QUIC.
 *
 * Requires:
 *\li	'tls' is a valid pointer to a TLS object.
 */
