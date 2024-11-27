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

/*
 * Native QUIC interface for OpenSSL forks implementing
 * BoringSSL/LibreSSL/QuicTLS QUIC API.
 *
 * See here:
 * https://github.com/quictls/openssl/blob/openssl-3.1.5%2Bquic/doc/man3/SSL_CTX_set_quic_method.pod
 * https://commondatastorage.googleapis.com/chromium-boringssl-docs/ssl.h.html#QUIC-integration
 *
 * LibreSSL's interface strives to be compatible with other
 * libraries. That being said, there are still differences in how
 * different libraries behave, in particular how they report current
 * read and write levels, but that should not matter much on practice.
 */

#include <stdbool.h>
#include <stdlib.h>

#include <openssl/ssl.h>

#include <isc/magic.h>
#include <isc/tls.h>
#include <isc/util.h>

#include "quic-int.h"

#define QUIC_NATIVE_DATA_MAGIC	  ISC_MAGIC('Q', 'n', 'C', 'd')
#define VALID_QUIC_NATIVE_DATA(t) ISC_MAGIC_VALID(t, QUIC_NATIVE_DATA_MAGIC)

static int
compat_encryption_level_to_native(const isc_quic_encryption_level_t level);

static void
quic_native_tlsctx_configure(isc_tlsctx_t *tlsctx);

static void
quic_native_tlsctx_keylog_callback(const isc_tls_t *tls, const char *line);

static void
quic_native_tls_init(isc_tls_t *tls, isc_mem_t *mctx);

static void
quic_native_tls_uninit(isc_tls_t *tls);

static bool
quic_native_tls_calling_method_cb(const isc_tls_t *tls);

static int
quic_native_tls_set_quic_method(isc_tls_t *tls,
				const isc_tls_quic_method_t *method);

static int
quic_native_tls_provide_quic_data(isc_tls_t *tls,
				  const isc_quic_encryption_level_t level,
				  const uint8_t *data, const size_t len);

static int
quic_native_tls_do_quic_handshake(isc_tls_t *tls);

static int
quic_native_tls_process_quic_post_handshake(isc_tls_t *tls);

static int
quic_native_tls_set_quic_transport_params(isc_tls_t *tls, const uint8_t *params,
					  const size_t params_len);
static void
quic_native_tls_get_peer_quic_transport_params(isc_tls_t *tls,
					       const uint8_t **out_params,
					       size_t *out_params_len);

static isc_quic_encryption_level_t
quic_native_read_level(const isc_tls_t *tls);

static isc_quic_encryption_level_t
quic_native_write_level(const isc_tls_t *tls);

static isc_tls_quic_interface_t native_quic_interface =
	(isc_tls_quic_interface_t){
		.tlsctx_configure = quic_native_tlsctx_configure,
		.tlsctx_keylog_callback = quic_native_tlsctx_keylog_callback,

		.tls_init = quic_native_tls_init,
		.tls_uninit = quic_native_tls_uninit,

		.tls_calling_method_cb = quic_native_tls_calling_method_cb,
		.tls_set_quic_method = quic_native_tls_set_quic_method,

		.tls_provide_quic_data = quic_native_tls_provide_quic_data,
		.tls_do_quic_handshake = quic_native_tls_do_quic_handshake,
		.tls_process_quic_post_handshake =
			quic_native_tls_process_quic_post_handshake,

		.tls_set_quic_transport_params =
			quic_native_tls_set_quic_transport_params,
		.tls_get_peer_quic_transport_params =
			quic_native_tls_get_peer_quic_transport_params,

		.tls_quic_read_level = quic_native_read_level,
		.tls_quic_write_level = quic_native_write_level
	};

static int
quic_native_method_set_read_secret(isc_tls_t *tls,
				   enum ssl_encryption_level_t level,
				   const isc_tls_cipher_t *cipher,
				   const uint8_t *secret, size_t secret_len);

static int
quic_native_method_set_write_secret(isc_tls_t *tls,
				    enum ssl_encryption_level_t level,
				    const isc_tls_cipher_t *cipher,
				    const uint8_t *secret, size_t secret_len);

#ifndef HAVE_QUIC_METHOD_SET_READ_WRITE_SECRET
static int
quic_native_method_set_encryption_secrets(isc_tls_t *tls,
					  enum ssl_encryption_level_t level,
					  const uint8_t *read_secret,
					  const uint8_t *write_secret,
					  size_t secret_len);
#endif /* HAVE_QUIC_METHOD_SET_READ_WRITE_SECRET */

static int
quic_native_method_add_handshake_data(isc_tls_t *tls,
				      enum ssl_encryption_level_t level,
				      const uint8_t *hs_data, size_t hs_len);

static int
quic_native_method_flush_flight(isc_tls_t *tls);

static int
quic_native_method_send_alert(isc_tls_t *tls, enum ssl_encryption_level_t level,
			      uint8_t alert);

static SSL_QUIC_METHOD native_quic_method = (SSL_QUIC_METHOD){
#ifdef HAVE_QUIC_METHOD_SET_READ_WRITE_SECRET
	.set_read_secret = quic_native_method_set_read_secret,
	.set_write_secret = quic_native_method_set_write_secret,
#else
	.set_encryption_secrets = quic_native_method_set_encryption_secrets,
#endif /* HAVE_QUIC_METHOD_SET_READ_WRITE_SECRET */
	.add_handshake_data = quic_native_method_add_handshake_data,
	.flush_flight = quic_native_method_flush_flight,
	.send_alert = quic_native_method_send_alert
};

typedef struct quic_native_data {
	uint32_t magic;
	isc_mem_t *mctx;
	const isc_tls_quic_method_t *method;
	bool calling_method_cb;
} quic_native_data_t;

static int
compat_encryption_level_to_native(const isc_quic_encryption_level_t level) {
	switch (level) {
	case ISC_QUIC_ENCRYPTION_INITIAL:
		return ssl_encryption_initial;
	case ISC_QUIC_ENCRYPTION_EARLY_DATA:
		return ssl_encryption_early_data;
	case ISC_QUIC_ENCRYPTION_HANDSHAKE:
		return ssl_encryption_handshake;
	case ISC_QUIC_ENCRYPTION_APPLICATION:
		return ssl_encryption_application;
	}

	UNREACHABLE();
}

static isc_quic_encryption_level_t
native_to_compat_encryption_level(int level) {
	switch (level) {
	case ssl_encryption_initial:
		return ISC_QUIC_ENCRYPTION_INITIAL;
	case ssl_encryption_early_data:
		return ISC_QUIC_ENCRYPTION_EARLY_DATA;
	case ssl_encryption_handshake:
		return ISC_QUIC_ENCRYPTION_HANDSHAKE;
	case ssl_encryption_application:
		return ISC_QUIC_ENCRYPTION_APPLICATION;
	}

	UNREACHABLE();
}

static void
quic_native_tlsctx_configure(isc_tlsctx_t *tlsctx) {
	/* dummy */
	UNUSED(tlsctx);
}

/* Will not be called on LibreSSL */
static void
quic_native_tlsctx_keylog_callback(const isc_tls_t *tls, const char *line) {
	/* dummy */
	UNUSED(tls);
	UNUSED(line);
}

static void
quic_native_tls_init(isc_tls_t *tls, isc_mem_t *mctx) {
	quic_native_data_t *data = isc_mem_cget(mctx, 1, sizeof(*data));

	isc_mem_attach(mctx, &data->mctx);

	data->magic = QUIC_NATIVE_DATA_MAGIC;

	INSIST(isc__tls_get_quic_data(tls) == NULL);
	isc__tls_set_quic_data(tls, data);
}

static void
quic_native_tls_uninit(isc_tls_t *tls) {
	isc_mem_t *mctx = NULL;
	quic_native_data_t *data = isc__tls_get_quic_data(tls);

	INSIST(VALID_QUIC_NATIVE_DATA(data));

	mctx = data->mctx;

	isc_mem_cput(mctx, data, 1, sizeof(*data));
	isc__tls_set_quic_data(tls, NULL);

	isc_mem_detach(&mctx);
}

static bool
quic_native_tls_calling_method_cb(const isc_tls_t *tls) {
	quic_native_data_t *data = isc__tls_get_quic_data(tls);

	INSIST(VALID_QUIC_NATIVE_DATA(data));

	return data->calling_method_cb;
}

static int
quic_native_tls_set_quic_method(isc_tls_t *tls,
				const isc_tls_quic_method_t *method) {
	int ret = 0;
	quic_native_data_t *data = isc__tls_get_quic_data(tls);

	INSIST(VALID_QUIC_NATIVE_DATA(data));

	ret = SSL_set_quic_method(tls, &native_quic_method);

	if (ret == 0) {
		return ret;
	}

	data->method = method;

	return ret;
}

static int
quic_native_tls_provide_quic_data(isc_tls_t *tls,
				  const isc_quic_encryption_level_t level,
				  const uint8_t *data, const size_t len) {
	int encryption_level = compat_encryption_level_to_native(level);

	return SSL_provide_quic_data(tls, encryption_level, data, len);
}

static int
quic_native_tls_do_quic_handshake(isc_tls_t *tls) {
	return SSL_do_handshake(tls);
}

static int
quic_native_tls_process_quic_post_handshake(isc_tls_t *tls) {
	return SSL_process_quic_post_handshake(tls);
}

static int
quic_native_tls_set_quic_transport_params(isc_tls_t *tls, const uint8_t *params,
					  const size_t params_len) {
	return SSL_set_quic_transport_params(tls, params, params_len);
}

static void
quic_native_tls_get_peer_quic_transport_params(isc_tls_t *tls,
					       const uint8_t **out_params,
					       size_t *out_params_len) {
	SSL_get_peer_quic_transport_params(tls, out_params, out_params_len);
}

static int
quic_native_method_set_read_secret(isc_tls_t *tls,
				   enum ssl_encryption_level_t level,
				   const isc_tls_cipher_t *cipher,
				   const uint8_t *secret, size_t secret_len) {
	quic_native_data_t *data = isc__tls_get_quic_data(tls);
	isc_quic_encryption_level_t compat_level =
		native_to_compat_encryption_level((int)level);
	bool ret = false;

	INSIST(VALID_QUIC_NATIVE_DATA(data));

	data->calling_method_cb = true;
	ret = data->method->set_read_secret(tls, compat_level, cipher, secret,
					    secret_len);
	data->calling_method_cb = false;

	if (!ret) {
		return 0;
	}

	return 1;
}

static int
quic_native_method_set_write_secret(isc_tls_t *tls,
				    enum ssl_encryption_level_t level,
				    const isc_tls_cipher_t *cipher,
				    const uint8_t *secret, size_t secret_len) {
	quic_native_data_t *data = isc__tls_get_quic_data(tls);
	isc_quic_encryption_level_t compat_level =
		native_to_compat_encryption_level((int)level);
	bool ret = false;

	INSIST(VALID_QUIC_NATIVE_DATA(data));

	data->calling_method_cb = true;
	ret = data->method->set_write_secret(tls, compat_level, cipher, secret,
					     secret_len);
	data->calling_method_cb = false;

	if (!ret) {
		return 0;
	}

	return 1;
}

#ifndef HAVE_QUIC_METHOD_SET_READ_WRITE_SECRET
static int
quic_native_method_set_encryption_secrets(isc_tls_t *tls,
					  enum ssl_encryption_level_t level,
					  const uint8_t *read_secret,
					  const uint8_t *write_secret,
					  size_t secret_len) {
	const isc_tls_cipher_t *cipher = SSL_get_current_cipher(tls);
	int ret = 1;

	RUNTIME_CHECK(cipher != NULL);

	if (read_secret != NULL) {
		ret = quic_native_method_set_read_secret(
			tls, level, cipher, read_secret, secret_len);
	}

	if (ret < 1) {
		return ret;
	}

	if (write_secret != NULL) {
		ret = quic_native_method_set_write_secret(
			tls, level, cipher, write_secret, secret_len);
	}

	return ret;
}
#endif /* HAVE_QUIC_METHOD_SET_READ_WRITE_SECRET */

static int
quic_native_method_add_handshake_data(isc_tls_t *tls,
				      enum ssl_encryption_level_t level,
				      const uint8_t *hs_data, size_t hs_len) {
	quic_native_data_t *data = isc__tls_get_quic_data(tls);
	isc_quic_encryption_level_t compat_level =
		native_to_compat_encryption_level((int)level);
	bool ret = false;

	INSIST(VALID_QUIC_NATIVE_DATA(data));

	data->calling_method_cb = true;
	ret = data->method->add_handshake_data(tls, compat_level, hs_data,
					       hs_len);
	data->calling_method_cb = false;

	if (!ret) {
		return 0;
	}

	return 1;
}

static int
quic_native_method_flush_flight(isc_tls_t *tls) {
	/* dummy */
	UNUSED(tls);

	return 1;
}

static int
quic_native_method_send_alert(isc_tls_t *tls, enum ssl_encryption_level_t level,
			      uint8_t alert) {
	quic_native_data_t *data = isc__tls_get_quic_data(tls);
	isc_quic_encryption_level_t compat_level =
		native_to_compat_encryption_level((int)level);
	bool ret = false;

	INSIST(VALID_QUIC_NATIVE_DATA(data));

	data->calling_method_cb = true;
	ret = data->method->send_alert(tls, compat_level, alert);
	data->calling_method_cb = false;

	if (!ret) {
		return 0;
	}

	return 1;
}

static isc_quic_encryption_level_t
quic_native_read_level(const isc_tls_t *tls) {
	quic_native_data_t *data = isc__tls_get_quic_data(tls);
	isc_quic_encryption_level_t compat_level;

	INSIST(VALID_QUIC_NATIVE_DATA(data));

	compat_level =
		native_to_compat_encryption_level(SSL_quic_read_level(tls));

	return compat_level;
}

static isc_quic_encryption_level_t
quic_native_write_level(const isc_tls_t *tls) {
	quic_native_data_t *data = isc__tls_get_quic_data(tls);
	isc_quic_encryption_level_t compat_level;

	INSIST(VALID_QUIC_NATIVE_DATA(data));

	compat_level =
		native_to_compat_encryption_level(SSL_quic_write_level(tls));

	return compat_level;
}

const isc_tls_quic_interface_t *
isc__tls_get_native_quic_interface(void) {
	return &native_quic_interface;
}
