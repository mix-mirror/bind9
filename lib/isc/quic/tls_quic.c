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
 * QUIC-related TLS functionality
 */

#include <stdbool.h>
#include <stdlib.h>

#include <isc/tls.h>
#include <isc/util.h>

#include "../openssl_shim.h"
#include "quic-int.h"
#include "quic_crypto.h"

static bool tls_quic_initialized = false;

static int tlsctx_quic_interface_index = 0;
static int tls_quic_interface_index = 0;
static int tls_quic_data_index = 0;
static int tls_quic_app_data_index = 0;
static int tls_quic_keylog_cb_index = 0;

static isc_mem_t *tls__quic_mctx = NULL;

void
isc__tls_quic_initialize(void) {
	if (tls_quic_initialized) {
		return;
	}

	tlsctx_quic_interface_index = CRYPTO_get_ex_new_index(
		CRYPTO_EX_INDEX_SSL_CTX, 0, NULL, NULL, NULL, NULL);
	tls_quic_interface_index = CRYPTO_get_ex_new_index(
		CRYPTO_EX_INDEX_SSL, 0, NULL, NULL, NULL, NULL);
	tls_quic_data_index = CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_SSL, 0,
						      NULL, NULL, NULL, NULL);
	tls_quic_app_data_index = CRYPTO_get_ex_new_index(
		CRYPTO_EX_INDEX_SSL, 0, NULL, NULL, NULL, NULL);
	tls_quic_keylog_cb_index = CRYPTO_get_ex_new_index(
		CRYPTO_EX_INDEX_SSL, 0, NULL, NULL, NULL, NULL);

	isc_mem_create("QUIC TLS", &tls__quic_mctx);
	isc_mem_setdestroycheck(tls__quic_mctx, false);

	tls_quic_initialized = true;
}

void
isc__tls_quic_shutdown(void) {
	if (!tls_quic_initialized) {
		return;
	}

#if HAVE_CRYPTO_FREE_EX_INDEX
	RUNTIME_CHECK(CRYPTO_free_ex_index(CRYPTO_EX_INDEX_SSL,
					   tls_quic_keylog_cb_index) == 1);
	RUNTIME_CHECK(CRYPTO_free_ex_index(CRYPTO_EX_INDEX_SSL,
					   tls_quic_app_data_index) == 1);
	RUNTIME_CHECK(CRYPTO_free_ex_index(CRYPTO_EX_INDEX_SSL,
					   tls_quic_data_index) == 1);
	RUNTIME_CHECK(CRYPTO_free_ex_index(CRYPTO_EX_INDEX_SSL,
					   tls_quic_interface_index) == 1);
	RUNTIME_CHECK(CRYPTO_free_ex_index(CRYPTO_EX_INDEX_SSL,
					   tlsctx_quic_interface_index) == 1);
	tlsctx_quic_interface_index = 0;
	tls_quic_interface_index = 0;
	tls_quic_data_index = 0;
	tls_quic_app_data_index = 0;
	tls_quic_keylog_cb_index = 0;
#endif /* HAVE_CRYPTO_FREE_EX_INDEX */

	if (tls__quic_mctx != NULL) {
		isc_mem_detach(&tls__quic_mctx);
	}

	tls_quic_initialized = false;
}

void
isc_tls_quic_crypto_initialize(void) {
	isc__quic_crypto_initialize();
}

void
isc_tls_quic_crypto_shutdown(void) {
	isc__quic_crypto_shutdown();
}

const char *
isc_tls_quic_encryption_level_text(const isc_quic_encryption_level_t level) {
	switch (level) {
	case ISC_QUIC_ENCRYPTION_INITIAL:
		return "initial";
	case ISC_QUIC_ENCRYPTION_EARLY_DATA:
		return "early data";
	case ISC_QUIC_ENCRYPTION_HANDSHAKE:
		return "handshake";
	case ISC_QUIC_ENCRYPTION_APPLICATION:
		return "application";
	};

	UNREACHABLE();
}

const isc_tls_quic_interface_t *
isc_tls_get_default_quic_interface(void) {
#ifdef HAVE_NATIVE_BORINGSSL_QUIC_API
	return isc__tls_get_native_quic_interface();
#endif /* HAVE_NATIVE_BORINGSSL_QUIC_API */

#ifndef HAVE_LIBRESSL
	return isc__tls_get_compat_quic_interface();
#endif /* HAVE_LIBRESSL */

	/* Unexpected - we need to investigate. */
	UNREACHABLE();
}

static isc_tls_quic_interface_t *
get_tls_quic_interface(const isc_tls_t *tls) {
	isc_tls_quic_interface_t *quicif = NULL;

	quicif = SSL_get_ex_data(tls, tls_quic_interface_index);

	RUNTIME_CHECK(quicif != NULL);

	return quicif;
}

void *
isc__tls_get_quic_data(const isc_tls_t *tls) {
	return SSL_get_ex_data(tls, tls_quic_data_index);
}

void
isc__tls_set_quic_data(isc_tls_t *tls, void *data) {
	int ret = SSL_set_ex_data(tls, tls_quic_data_index, data);
	RUNTIME_CHECK(ret == 1);
}

/* Will not be called on LibreSSL */
static void
quic_keylog_callback(const isc_tls_t *tls, const char *line) {
	isc_tls_quic_interface_t *quicif = NULL;
	isc_tls_keylog_cb_t cb = NULL;

	INSIST(tls != NULL);
	INSIST(line != NULL && *line != '\0');

	isc_tls_sslkeylogfile_append(line);

	quicif = get_tls_quic_interface(tls);

	if (quicif->tlsctx_keylog_callback != NULL) {
		quicif->tlsctx_keylog_callback(tls, line);
	}

	cb = SSL_get_ex_data(tls, tls_quic_keylog_cb_index);
	if (cb != NULL) {
		cb(tls, line);
	}
}

void
isc_tlsctx_quic_configure(isc_tlsctx_t *tlsctx,
			  const isc_tls_quic_interface_t *quic_interface) {
	REQUIRE(tlsctx != NULL);
	REQUIRE(quic_interface != NULL);

	/* QUIC uses TLSv1.3 and newer */
#ifdef TLS1_3_VERSION
	SSL_CTX_set_min_proto_version(tlsctx, TLS1_3_VERSION);
#else
	/* Everything older than TLSv1.2 is disabled by default */
	SSL_CTX_set_options(tlsctx, SSL_OP_NO_TLSv1_2);
#endif

#ifdef TLS1_3_VERSION
	SSL_CTX_set_max_proto_version(tlsctx, TLS1_3_VERSION);
#endif

#ifdef SSL_OP_ENABLE_MIDDLEBOX_COMPAT
	/*
	 * Disable middle-box compatibility mode for QUIC, as it makes no sense
	 * to use it in that case. See RFC9001, Section 8.4.
	 */
	SSL_CTX_clear_options(tlsctx, SSL_OP_ENABLE_MIDDLEBOX_COMPAT);
#endif

	INSIST(SSL_CTX_get_ex_data(tlsctx, tlsctx_quic_interface_index) ==
	       NULL);
	RUNTIME_CHECK(SSL_CTX_set_ex_data(tlsctx, tlsctx_quic_interface_index,
					  (void *)quic_interface) == 1);

	SSL_CTX_set_keylog_callback(tlsctx, quic_keylog_callback);
	quic_interface->tlsctx_configure(tlsctx);
}

void
isc__tls_quic_init(isc_tls_t *tls) {
	int ret = 0;
	isc_tlsctx_t *tlsctx = NULL;
	isc_tls_quic_interface_t *quicif = NULL;

	REQUIRE(tls != NULL);

	tlsctx = SSL_get_SSL_CTX(tls);
	INSIST(tlsctx != NULL);

	quicif = SSL_CTX_get_ex_data(tlsctx, tlsctx_quic_interface_index);
	RUNTIME_CHECK(quicif != NULL);

	ret = SSL_set_ex_data(tls, tls_quic_interface_index, quicif);
	RUNTIME_CHECK(ret == 1);

	quicif->tls_init(tls, tls__quic_mctx);
}

void
isc__tls_quic_uninit(isc_tls_t *tls) {
	int ret = 0;
	isc_tls_quic_interface_t *quicif = NULL;

	REQUIRE(tls != NULL);

	quicif = get_tls_quic_interface(tls);
	quicif->tls_uninit(tls);

	ret = SSL_set_ex_data(tls, tls_quic_interface_index, NULL);
	RUNTIME_CHECK(ret == 1);
}

bool
isc__tls_is_quic(isc_tls_t *tls) {
	REQUIRE(tls != NULL);

	return SSL_get_ex_data(tls, tls_quic_interface_index) != NULL;
}

void
isc_tls_quic_set_app_data(isc_tls_t *tls, void *app_data) {
	int ret = 0;
	REQUIRE(tls != NULL);

	ret = SSL_set_ex_data(tls, tls_quic_app_data_index, app_data);
	RUNTIME_CHECK(ret == 1);
}

void *
isc_tls_quic_get_app_data(isc_tls_t *tls) {
	REQUIRE(tls != NULL);

	return SSL_get_ex_data(tls, tls_quic_app_data_index);
}

void
isc_tls_quic_set_keylog_callback(isc_tls_t *tls, isc_tls_keylog_cb_t cb) {
	int ret = 0;

	REQUIRE(tls != NULL);

	ret = SSL_set_ex_data(tls, tls_quic_keylog_cb_index, cb);

	RUNTIME_CHECK(ret == 1);
}

isc_result_t
isc_tls_set_quic_method(isc_tls_t *tls, const isc_tls_quic_method_t *method) {
	isc_tls_quic_interface_t *quicif = NULL;
	int ret = 0;

	REQUIRE(tls != NULL);
	REQUIRE(method != NULL);

	quicif = get_tls_quic_interface(tls);

	RUNTIME_CHECK(!quicif->tls_calling_method_cb(tls));

	INSIST(method->add_handshake_data != NULL);
	INSIST(method->send_alert != NULL);
	INSIST(method->set_read_secret != NULL);
	INSIST(method->set_write_secret != NULL);

	ret = quicif->tls_set_quic_method(tls, method);
	if (ret == 0) {
		return ISC_R_FAILURE;
	}

	return ISC_R_SUCCESS;
}

isc_result_t
isc_tls_provide_quic_data(isc_tls_t *tls,
			  const isc_quic_encryption_level_t level,
			  const uint8_t *data, const size_t len) {
	isc_tls_quic_interface_t *quicif = NULL;
	int ret = 0;

	REQUIRE(tls != NULL);
	REQUIRE(len == 0 || data != NULL);

	quicif = get_tls_quic_interface(tls);

	RUNTIME_CHECK(!quicif->tls_calling_method_cb(tls));

	ret = quicif->tls_provide_quic_data(tls, level, data, len);
	if (ret == 0) {
		return ISC_R_FAILURE;
	}

	return ISC_R_SUCCESS;
}

int
isc_tls_do_quic_handshake(isc_tls_t *tls) {
	isc_tls_quic_interface_t *quicif = NULL;

	REQUIRE(tls != NULL);

	quicif = get_tls_quic_interface(tls);

	RUNTIME_CHECK(!quicif->tls_calling_method_cb(tls));

	return quicif->tls_do_quic_handshake(tls);
}

int
isc_tls_process_quic_post_handshake(isc_tls_t *tls) {
	isc_tls_quic_interface_t *quicif = NULL;

	REQUIRE(tls != NULL);

	quicif = get_tls_quic_interface(tls);

	RUNTIME_CHECK(!quicif->tls_calling_method_cb(tls));

	return quicif->tls_process_quic_post_handshake(tls);
}

isc_result_t
isc_tls_set_quic_transport_params(isc_tls_t *tls, const uint8_t *params,
				  const size_t params_len) {
	isc_tls_quic_interface_t *quicif = NULL;
	int ret = 0;

	REQUIRE(tls != NULL);
	REQUIRE(params != NULL);
	REQUIRE(params_len > 0);

	quicif = get_tls_quic_interface(tls);

	ret = quicif->tls_set_quic_transport_params(tls, params, params_len);
	if (ret == 0) {
		return ISC_R_FAILURE;
	}

	return ISC_R_SUCCESS;
}

void
isc_tls_get_peer_quic_transport_params(isc_tls_t *tls,
				       const uint8_t **out_params,
				       size_t *out_params_len) {
	isc_tls_quic_interface_t *quicif = NULL;

	REQUIRE(tls != NULL);
	REQUIRE(out_params != NULL && *out_params == NULL);
	REQUIRE(out_params_len != NULL && *out_params_len == 0);

	quicif = get_tls_quic_interface(tls);

	quicif->tls_get_peer_quic_transport_params(tls, out_params,
						   out_params_len);
}

isc_quic_encryption_level_t
isc_tls_quic_read_level(const isc_tls_t *tls) {
	isc_tls_quic_interface_t *quicif = NULL;

	REQUIRE(tls != NULL);

	quicif = get_tls_quic_interface(tls);

	RUNTIME_CHECK(!quicif->tls_calling_method_cb(tls));

	return quicif->tls_quic_read_level(tls);
}

isc_quic_encryption_level_t
isc_tls_quic_write_level(const isc_tls_t *tls) {
	isc_tls_quic_interface_t *quicif = NULL;

	REQUIRE(tls != NULL);

	quicif = get_tls_quic_interface(tls);

	RUNTIME_CHECK(!quicif->tls_calling_method_cb(tls));

	return quicif->tls_quic_write_level(tls);
}
