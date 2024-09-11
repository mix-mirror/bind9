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

#include <sched.h> /* IWYU pragma: keep */
#include <setjmp.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

#define UNIT_TESTING
#include <cmocka.h>

#include <isc/buffer.h>
#include <isc/lib.h>
#include <isc/mem.h>
#include <isc/os.h>
#include <isc/tls.h>

#include "../../lib/isc/quic/quic-int.h"
#include "../../lib/isc/quic/quic_crypto.h"

#include <tests/isc.h>

#if (defined(HAVE_NATIVE_BORINGSSL_QUIC_API) && !defined(HAVE_LIBRESSL))
#define EXTRA_NATIVE_AND_COMPAT_TESTS
#endif

/* Enable this to print extensive debugging information while running tests */
#undef PRINT_DEBUG

/*
 * This unit test is based on ideas of a test that is a part of LibreSSL:
 * https://github.com/libressl/openbsd/blob/master/src/regress/lib/libssl/quic/quictest.c
 *
 * It works in a very similar way but verifies more cases and is
 * compatible with QuicTLS.
 *
 * To the most part it is an OpenSSL QUIC compatibility code debugging
 * tool disguised as a unit test.
 */

#define INITIAL_BUFFER_SIZE (2048)
#define MAX_ITERATIONS	    (100)

static isc_mem_t *mctx = NULL;

static uint8_t server_transport_params[] = { 's', 'e', 'r', 'v', 'e',
					     'r', 't', 'r', 'a', 'n',
					     's', 'p', 'e', 'x', 't' };

static uint8_t client_transport_params[] = { 'c', 'l', 'i', 'e', 'n', 't',
					     't', 't', 'r', 'a', 'n', 's',
					     'p', 'e', 'x', 't' };

static isc_tlsctx_t *default_server_tlsctx = NULL;
static isc_tlsctx_t *default_client_tlsctx = NULL;

#ifdef EXTRA_NATIVE_AND_COMPAT_TESTS
static isc_tlsctx_t *native_server_tlsctx = NULL;
static isc_tlsctx_t *native_client_tlsctx = NULL;

static isc_tlsctx_t *compat_server_tlsctx = NULL;
static isc_tlsctx_t *compat_client_tlsctx = NULL;
#endif /* EXTRA_NATIVE_AND_COMPAT_TESTS */

static isc_tlsctx_t *server_tlsctx = NULL;
static isc_tlsctx_t *client_tlsctx = NULL;

static isc_tls_t *server_tls = NULL;
static isc_tls_t *client_tls = NULL;

typedef struct quic_data {
	bool hs_done;
	isc_quic_encryption_level_t rlevel;
	isc_quic_encryption_level_t wlevel;
	isc_buffer_t *input;
	isc_buffer_t *output;
} quic_data_t;

static bool
method_set_read_secret(isc_tls_t *tls, const isc_quic_encryption_level_t level,
		       const isc_tls_cipher_t *cipher, const uint8_t *secret,
		       const size_t secret_len);

static bool
method_set_write_secret(isc_tls_t *tls, const isc_quic_encryption_level_t level,
			const isc_tls_cipher_t *cipher, const uint8_t *secret,
			const size_t secret_len);

static bool
method_send_alert(isc_tls_t *tls, const isc_quic_encryption_level_t level,
		  const uint8_t alert);

static bool
method_add_handshake_data(isc_tls_t *tls,
			  const isc_quic_encryption_level_t level,
			  const uint8_t *data, const size_t len);

static const isc_tls_quic_method_t quic_method = (isc_tls_quic_method_t){
	.set_read_secret = method_set_read_secret,
	.set_write_secret = method_set_write_secret,
	.add_handshake_data = method_add_handshake_data,
	.send_alert = method_send_alert
};

static quic_data_t client_data = { 0 }, server_data = { 0 };
static isc_buffer_t *client_output = NULL, *server_output = NULL;

static void
vwarn(const char *fmt, va_list args) {
#ifdef PRINT_DEBUG
	vfprintf(stderr, fmt, args);
#else
	UNUSED(fmt);
	UNUSED(args);
#endif
}

static void
warn(const char *fmt, ...) {
	va_list args;

	va_start(args, fmt);
	vwarn(fmt, args);
	va_end(args);
}

static void
warntls(const isc_tls_t *tls, const char *fmt, ...) {
	va_list args;

	warn("%s: ", SSL_is_server(tls) ? "server" : "client");
	va_start(args, fmt);
	vwarn(fmt, args);
	va_end(args);
}

static void
hexdump(const unsigned char *buf, const size_t len) {
	for (size_t i = 0; i < len; i++) {
		warn("%02hhx", buf[i]);
	}
}

static int
warntls_err_cb(const char *str, size_t len, void *user_data) {
	isc_tls_t *tls = (isc_tls_t *)user_data;

	UNUSED(len);

	warntls(tls, "%s", str);

	return 1;
}

static void
warntls_keylog_cb(const isc_tls_t *tls, const char *line) {
	warntls(tls, "%s\n", line);
#ifndef HAVE_LIBRESSL
	uint8_t client_randdom_data[32];
	uint8_t secret_data[2048];
	isc_buffer_t client_random, secret;
	isc__tls_keylog_label_t label = ISC__TLS_KL_ILLEGAL;

	isc_buffer_init(&client_random, client_randdom_data,
			sizeof(client_randdom_data));
	isc_buffer_init(&secret, secret_data, sizeof(secret_data));

	isc_result_t result = isc__tls_parse_keylog_entry(
		line, &label, &client_random, &secret);
	if (result != ISC_R_SUCCESS) {
		warntls(tls, "parsing keylog entry failed: %s\n",
			isc_result_totext(result));
	} else {
		isc_region_t region;
		warntls(tls, "\tkeylog entry:\n");
		warntls(tls, "client random: ");
		isc_buffer_usedregion(&client_random, &region);
		hexdump(region.base, region.length);
		warn("\n");
		warntls(tls, "secret: ");
		isc_buffer_usedregion(&secret, &region);
		hexdump(region.base, region.length);
		warn("\n");
	}
	assert_int_equal(result, ISC_R_SUCCESS);
#endif /* HAVE_LIBRESSL */
}

static void
configure_tls(isc_tls_t *tls, const bool server, void *app_data) {
	isc_tls_set_quic_method(tls, &quic_method);
	isc_tls_quic_set_keylog_callback(tls, warntls_keylog_cb);
	isc_tls_quic_set_app_data(tls, app_data);
	if (server) {
		(void)SSL_set_accept_state(tls);
	} else {
		(void)SSL_set_connect_state(tls);
	}
}

static isc_tls_t *
create_tls(const bool server) {
	isc_tls_t *tls = NULL;
	void *app_data = NULL;

	if (server) {
		tls = isc_tls_create_quic(server_tlsctx);
		app_data = (void *)&server_data;
	} else {
		tls = isc_tls_create_quic(client_tlsctx);
		app_data = (void *)&client_data;
	}

	configure_tls(tls, server, app_data);

	return tls;
}

static int
setup_quic_tls_test(void **state) {
	UNUSED(state);

	(void)isc_buffer_allocate(mctx, &client_output, INITIAL_BUFFER_SIZE);
	(void)isc_buffer_allocate(mctx, &server_output, INITIAL_BUFFER_SIZE);

	server_data = (quic_data_t){ .rlevel = ISC_QUIC_ENCRYPTION_INITIAL,
				     .wlevel = ISC_QUIC_ENCRYPTION_INITIAL,
				     .input = client_output,
				     .output = server_output };

	client_data = (quic_data_t){ .rlevel = ISC_QUIC_ENCRYPTION_INITIAL,
				     .wlevel = ISC_QUIC_ENCRYPTION_INITIAL,
				     .input = server_output,
				     .output = client_output };

	server_tls = create_tls(true);

	client_tls = create_tls(false);

	return 0;
}

static void
set_ciphersuites(const char *ciphersuites) {
	RUNTIME_CHECK(SSL_set_ciphersuites(client_tls, ciphersuites) == 1);
	RUNTIME_CHECK(SSL_set_ciphersuites(server_tls, ciphersuites) == 1);
}

static int
setup_quic_tls_test_TLS_AES_128_GCM_SHA256(void **state) {
	int ret;

	ret = setup_quic_tls_test(state);

	set_ciphersuites("TLS_AES_128_GCM_SHA256");

	return ret;
}

static int
setup_quic_tls_test_TLS_AES_256_GCM_SHA384(void **state) {
	int ret;

	ret = setup_quic_tls_test(state);

	set_ciphersuites("TLS_AES_256_GCM_SHA384");

	return ret;
}

static int
setup_quic_tls_test_TLS_CHACHA20_POLY1305_SHA256(void **state) {
	int ret;

	ret = setup_quic_tls_test(state);

	set_ciphersuites("TLS_CHACHA20_POLY1305_SHA256");

	return ret;
}

#ifndef HAVE_LIBRESSL
static int
setup_quic_tls_test_TLS_AES_128_CCM_SHA256(void **state) {
	int ret;

	ret = setup_quic_tls_test(state);

	set_ciphersuites("TLS_AES_128_CCM_SHA256");

	return ret;
}
#endif /* HAVE_LIBRESSL */

static int
setup_quic_tls_test_TLS_AES_128_CCM_8_SHA256(void **state) {
	int ret;

	ret = setup_quic_tls_test(state);

	set_ciphersuites("TLS_AES_128_CCM_8_SHA256");

	return ret;
}

#ifdef EXTRA_NATIVE_AND_COMPAT_TESTS
static int
setup_quic_tls_native_to_compat_test(void **state) {
	client_tlsctx = native_client_tlsctx;
	server_tlsctx = compat_server_tlsctx;

	return setup_quic_tls_test(state);
}

static int
setup_quic_tls_native_to_compat_test_TLS_AES_128_GCM_SHA256(void **state) {
	int ret;

	ret = setup_quic_tls_native_to_compat_test(state);

	set_ciphersuites("TLS_AES_128_GCM_SHA256");

	return ret;
}

static int
setup_quic_tls_native_to_compat_test_TLS_AES_256_GCM_SHA384(void **state) {
	int ret;

	ret = setup_quic_tls_native_to_compat_test(state);

	set_ciphersuites("TLS_AES_256_GCM_SHA384");

	return ret;
}

static int
setup_quic_tls_native_to_compat_test_TLS_CHACHA20_POLY1305_SHA256(void **state) {
	int ret;

	ret = setup_quic_tls_native_to_compat_test(state);

	set_ciphersuites("TLS_CHACHA20_POLY1305_SHA256");

	return ret;
}

static int
setup_quic_tls_native_to_compat_test_TLS_AES_128_CCM_SHA256(void **state) {
	int ret;

	ret = setup_quic_tls_native_to_compat_test(state);

	set_ciphersuites("TLS_AES_128_CCM_SHA256");

	return ret;
}

static int
setup_quic_tls_native_to_compat_test_TLS_AES_128_CCM_8_SHA256(void **state) {
	int ret;

	ret = setup_quic_tls_native_to_compat_test(state);

	set_ciphersuites("TLS_AES_128_CCM_8_SHA256");

	return ret;
}

static int
setup_quic_tls_compat_to_native_test(void **state) {
	client_tlsctx = compat_client_tlsctx;
	server_tlsctx = native_server_tlsctx;

	return setup_quic_tls_test(state);
}

static int
setup_quic_tls_compat_to_native_test_TLS_AES_128_GCM_SHA256(void **state) {
	int ret;

	ret = setup_quic_tls_compat_to_native_test(state);

	set_ciphersuites("TLS_AES_128_GCM_SHA256");

	return ret;
}

static int
setup_quic_tls_compat_to_native_test_TLS_AES_256_GCM_SHA384(void **state) {
	int ret;

	ret = setup_quic_tls_compat_to_native_test(state);

	set_ciphersuites("TLS_AES_256_GCM_SHA384");

	return ret;
}

static int
setup_quic_tls_compat_to_native_test_TLS_CHACHA20_POLY1305_SHA256(void **state) {
	int ret;

	ret = setup_quic_tls_compat_to_native_test(state);

	set_ciphersuites("TLS_CHACHA20_POLY1305_SHA256");

	return ret;
}

static int
setup_quic_tls_compat_to_native_test_TLS_AES_128_CCM_SHA256(void **state) {
	int ret;

	ret = setup_quic_tls_compat_to_native_test(state);

	set_ciphersuites("TLS_AES_128_CCM_SHA256");

	return ret;
}

static int
setup_quic_tls_compat_to_native_test_TLS_AES_128_CCM_8_SHA256(void **state) {
	int ret;

	ret = setup_quic_tls_compat_to_native_test(state);

	set_ciphersuites("TLS_AES_128_CCM_8_SHA256");

	return ret;
}

#endif /* EXTRA_NATIVE_AND_COMPAT_TESTS */

static int
teardown_quic_tls_test(void **state) {
	UNUSED(state);

	isc_buffer_free(&server_output);
	isc_buffer_free(&client_output);

	isc_tls_free(&server_tls);
	isc_tls_free(&client_tls);

	/* use the default contexts by default */
	server_tlsctx = default_server_tlsctx;
	client_tlsctx = default_client_tlsctx;

	return 0;
}

static int
quic_tls_setup(void **state) {
	UNUSED(state);

	isc_tls_quic_crypto_initialize();

	isc_mem_create("testctx", &mctx);

	if (isc_tlsctx_createserver(NULL, NULL, &default_server_tlsctx) !=
	    ISC_R_SUCCESS)
	{
		return -1;
	}

	isc_tlsctx_set_random_session_id_context(default_server_tlsctx);

	isc_tlsctx_quic_configure(default_server_tlsctx,
				  isc_tls_get_default_quic_interface());

	if (isc_tlsctx_createclient(&default_client_tlsctx) != ISC_R_SUCCESS) {
		return -1;
	}

	isc_tlsctx_quic_configure(default_client_tlsctx,
				  isc_tls_get_default_quic_interface());

#ifdef EXTRA_NATIVE_AND_COMPAT_TESTS
	if (isc_tlsctx_createserver(NULL, NULL, &native_server_tlsctx) !=
	    ISC_R_SUCCESS)
	{
		return -1;
	}

	isc_tlsctx_quic_configure(native_server_tlsctx,
				  isc__tls_get_native_quic_interface());

	isc_tlsctx_set_random_session_id_context(native_server_tlsctx);

	if (isc_tlsctx_createclient(&native_client_tlsctx) != ISC_R_SUCCESS) {
		return -1;
	}

	isc_tlsctx_quic_configure(native_client_tlsctx,
				  isc__tls_get_native_quic_interface());

	if (isc_tlsctx_createserver(NULL, NULL, &compat_server_tlsctx) !=
	    ISC_R_SUCCESS)
	{
		return -1;
	}

	isc_tlsctx_quic_configure(compat_server_tlsctx,
				  isc__tls_get_compat_quic_interface());

	if (isc_tlsctx_createclient(&compat_client_tlsctx) != ISC_R_SUCCESS) {
		return -1;
	}

	isc_tlsctx_set_random_session_id_context(compat_server_tlsctx);

	isc_tlsctx_quic_configure(compat_client_tlsctx,
				  isc__tls_get_compat_quic_interface());
#endif /* EXTRA_NATIVE_AND_COMPAT_TESTS */

	/* use the default contexts by default */
	server_tlsctx = default_server_tlsctx;
	client_tlsctx = default_client_tlsctx;

	return 0;
}

static int
quic_tls_teardown(void **state) {
	UNUSED(state);

#ifdef EXTRA_NATIVE_AND_COMPAT_TESTS
	isc_tlsctx_free(&native_client_tlsctx);
	isc_tlsctx_free(&native_server_tlsctx);

	isc_tlsctx_free(&compat_client_tlsctx);
	isc_tlsctx_free(&compat_server_tlsctx);
#endif /* EXTRA_NATIVE_AND_COMPAT_TESTS */

	isc_tlsctx_free(&default_client_tlsctx);
	isc_tlsctx_free(&default_server_tlsctx);

	isc_mem_detach(&mctx);

	isc_tls_quic_crypto_shutdown();

	return 0;
}

/* QUIC method hooks */

static bool
method_set_read_secret(isc_tls_t *tls, const isc_quic_encryption_level_t level,
		       const isc_tls_cipher_t *cipher, const uint8_t *secret,
		       const size_t secret_len) {
	struct quic_data *qd = isc_tls_quic_get_app_data(tls);

	warntls(tls, "set read secret (level: %s (%d)): %p (length: %zu)\n",
		isc_tls_quic_encryption_level_text(level), level, secret,
		secret_len);

	warntls(tls, "read secret: ");
	hexdump(secret, secret_len);
	warn("\n");

	assert_true(SSL_get_current_cipher(tls) == cipher);

	qd->rlevel = level;

	if (!isc__quic_crypto_tls_cipher_supported(cipher)) {
		return false;
	}

	return true;
}

static bool
method_set_write_secret(isc_tls_t *tls, const isc_quic_encryption_level_t level,
			const isc_tls_cipher_t *cipher, const uint8_t *secret,
			const size_t secret_len) {
	struct quic_data *qd = isc_tls_quic_get_app_data(tls);

	warntls(tls, "set write secret (level: %s (%d)): %p (length: %zu)\n",
		isc_tls_quic_encryption_level_text(level), level, secret,
		secret_len);

	warntls(tls, "write secret: ");
	hexdump(secret, secret_len);
	warn("\n");

	assert_true(SSL_get_current_cipher(tls) == cipher);

	qd->wlevel = level;

	if (!isc__quic_crypto_tls_cipher_supported(cipher)) {
		return false;
	}

	return true;
}

static bool
method_add_handshake_data(isc_tls_t *tls,
			  const isc_quic_encryption_level_t level,
			  const uint8_t *data, const size_t len) {
	quic_data_t *qd = isc_tls_quic_get_app_data(tls);

	warntls(tls, "add handshake data (level: %s (%d)): %p (length: %zu)\n",
		isc_tls_quic_encryption_level_text(level), level, data, len);

	isc_buffer_putuint32(qd->output, (uint32_t)len);
	isc_buffer_putmem(qd->output, data, len);

	return true;
}

static bool
method_send_alert(isc_tls_t *tls, const isc_quic_encryption_level_t level,
		  const uint8_t alert) {
	warntls(tls, "send alert (level: %s (%d)): 0x%x (%d)\n",
		isc_tls_quic_encryption_level_text(level), level, alert, alert);

	return true;
}

/* test */

static bool
read_handshake_message(isc_tls_t *tls) {
	quic_data_t *qd = isc_tls_quic_get_app_data(tls);
	isc_result_t result = ISC_R_SUCCESS;

	/*
	 * We need to process the handshake data one message at a time due
	 * to QuicTLS limitation: it is not handling the case of passing
	 * multiple messages from different encryption levels at once. It
	 * should not be a problem when integrating with an actual QUIC
	 * implementation, though.
	 */

	if (isc_buffer_remaininglength(qd->input) > 0) {
		isc_region_t data = { 0 };
		size_t msg_size = isc_buffer_getuint32(qd->input);

		isc_buffer_remainingregion(qd->input, &data);

		result = isc_tls_provide_quic_data(
			tls, isc_tls_quic_read_level(tls), data.base, msg_size);

		isc_buffer_forward(qd->input, msg_size);
		isc_buffer_trycompact(qd->input);

		warntls(tls,
			"read handshake message: %zu bytes (unprocessed data + "
			"headers: %zu bytes left)\n",
			msg_size, isc_buffer_remaininglength(qd->input));
	}

	if (result != ISC_R_SUCCESS) {
		return false;
	}

	return true;
}

static bool
process_tls_error(isc_tls_t *tls, const int ssl_ret) {
	const int ssl_err = SSL_get_error(tls, ssl_ret);

	switch (ssl_err) {
	case SSL_ERROR_NONE:
	case SSL_ERROR_WANT_READ:
	case SSL_ERROR_WANT_WRITE:
	case SSL_ERROR_SYSCALL:
		/* Aaargh! read "BUGS" section for SSL_get_error() */
		if (errno == 0) {
			break;
		}
		return false;
	default:
		warntls(tls, "SSL error: %d\n", ssl_err);
		ERR_print_errors_cb(warntls_err_cb, tls);
		return false;
	}

	return true;
}

static bool
try_handshake(isc_tls_t *tls) {
	quic_data_t *qd = isc_tls_quic_get_app_data(tls);

	do {
		int ret = 0;

		if (!read_handshake_message(tls)) {
			return false;
		}

		if (!qd->hs_done) {
			ret = isc_tls_do_quic_handshake(tls);
			if (ret == 1) {
				qd->hs_done = true;

				assert_true(qd->rlevel ==
					    isc_tls_quic_read_level(tls));
				assert_true(qd->wlevel ==
					    isc_tls_quic_write_level(tls));

				warntls(tls,
					"TLS handshake has been completed\n");
				/*return (true);*/
				continue;
			}
		} else {
			ret = isc_tls_process_quic_post_handshake(tls);
			if (ret == 1) {
				continue;
			}
		}

		if (!process_tls_error(tls, ret)) {
			return false;
		}

	} while (isc_buffer_remaininglength(qd->input) > 0);

	return true;
}

static bool
client_server_loop(isc_tls_t *client, isc_tls_t *server) {
	int i = 0;
	isc_result_t result;
	const uint8_t *out_params = NULL;
	size_t out_params_len = 0;
	quic_data_t *client_app_data = NULL, *server_app_data = NULL;

	client_app_data = isc_tls_quic_get_app_data(client);
	server_app_data = isc_tls_quic_get_app_data(server);

	isc_buffer_clear(client_app_data->output);
	client_app_data->rlevel = client_app_data->wlevel =
		ISC_QUIC_ENCRYPTION_INITIAL;
	isc_buffer_clear(server_app_data->output);
	server_app_data->rlevel = server_app_data->wlevel =
		ISC_QUIC_ENCRYPTION_INITIAL;
	client_app_data->hs_done = server_app_data->hs_done = false;

	result = isc_tls_set_quic_transport_params(
		client, client_transport_params,
		sizeof(client_transport_params));

	if (result != ISC_R_SUCCESS) {
		return false;
	}

	result = isc_tls_set_quic_transport_params(
		server, server_transport_params,
		sizeof(server_transport_params));

	if (result != ISC_R_SUCCESS) {
		return false;
	}

	do {
		/* Read "BUGS" section for SSL_get_error() */
		ERR_clear_error();
		errno = 0;

		warn("\tClient:\n");
		if (!try_handshake(client)) {
			return false;
		}

		warn("\tServer:\n");
		if (!try_handshake(server)) {
			return false;
		}

		i++;
	} while (i < MAX_ITERATIONS &&
		 (!client_app_data->hs_done || !server_app_data->hs_done ||
		  (isc_buffer_remaininglength(server_app_data->output) > 0) ||
		  (isc_buffer_remaininglength(client_app_data->output) > 0)));

	if (!(client_app_data->hs_done && server_app_data->hs_done)) {
		warn("Cannot complete the handshake!\n");
		return false;
	}

	isc_tls_get_peer_quic_transport_params(server, &out_params,
					       &out_params_len);
	if (out_params_len == 0 ||
	    out_params_len != sizeof(client_transport_params))
	{
		warntls(server,
			"Cannot get the server's peer transport parameters!\n");
		return false;
	}

	if (memcmp(out_params, client_transport_params,
		   sizeof(client_transport_params)) != 0)
	{
		warntls(server,
			"Server's peer transport parameters are invalid!\n");
		return false;
	}

	out_params = NULL;
	out_params_len = 0;

	isc_tls_get_peer_quic_transport_params(client, &out_params,
					       &out_params_len);
	if (out_params_len == 0 ||
	    out_params_len != sizeof(server_transport_params))
	{
		warntls(client,
			"Cannot get the client's peer transport parameters!\n");
		return false;
	}

	if (memcmp(out_params, server_transport_params,
		   sizeof(server_transport_params)) != 0)
	{
		warntls(client,
			"Client's peer transport parameters are invalid!\n");
		return false;
	}

	if (isc_buffer_remaininglength(server_app_data->output) > 0) {
		warn("Server's output is not fully processed\n");
	}

	if (isc_buffer_remaininglength(client_app_data->output) > 0) {
		warn("Client's output is not fully processed\n");
	}

	return true;
}

static void
test_expect_success(void) {
	const bool handshake_successful = client_server_loop(client_tls,
							     server_tls);
	assert_true(handshake_successful);
}

static void
test_expect_failure(void) {
	const bool handshake_successful = client_server_loop(client_tls,
							     server_tls);
	assert_false(handshake_successful);
}

/*
 * Session resumptions is not supported on LibreSSL. Which is in line
 * with it being somewhat *special*, supposedly due to it being
 * SECURITY ORIENTED. Sigh...
 */
#ifndef HAVE_LIBRESSL
static void
test_resumption(void) {
	SSL_SESSION *sess = NULL;
	bool handshake_successful = client_server_loop(client_tls, server_tls);
	assert_true(handshake_successful);

	SSL_set_shutdown(client_tls, SSL_SENT_SHUTDOWN);
	sess = SSL_get1_session(client_tls);

	assert_true(SSL_SESSION_is_resumable(sess));

	isc_tls_free(&server_tls);
	isc_tls_free(&client_tls);

	server_tls = create_tls(true);
	client_tls = create_tls(false);

	SSL_set_session(client_tls, sess);
	SSL_SESSION_free(sess);

	handshake_successful = client_server_loop(client_tls, server_tls);
	assert_true(handshake_successful);
	assert_true(SSL_session_reused(client_tls));
}

#endif /* HAVE_LIBRESSL */

ISC_RUN_TEST_IMPL(quic_tls_test_default) { test_expect_success(); }

ISC_RUN_TEST_IMPL(quic_tls_test_default_TLS_AES_128_GCM_SHA256) {
	test_expect_success();
}

ISC_RUN_TEST_IMPL(quic_tls_test_default_TLS_AES_256_GCM_SHA384) {
	test_expect_success();
}

ISC_RUN_TEST_IMPL(quic_tls_test_default_TLS_CHACHA20_POLY1305_SHA256) {
	test_expect_success();
}

#ifndef HAVE_LIBRESSL
ISC_RUN_TEST_IMPL(quic_tls_test_default_TLS_AES_128_CCM_SHA256) {
	test_expect_success();
}
#endif /* HAVE_LIBRESSL */

ISC_RUN_TEST_IMPL(quic_tls_test_default_TLS_AES_128_CCM_8_SHA256_failure) {
	test_expect_failure();
}

#ifndef HAVE_LIBRESSL
ISC_RUN_TEST_IMPL(quic_tls_test_default_resumption) { test_resumption(); }
#endif /* HAVE_LIBRESSL */

#ifdef EXTRA_NATIVE_AND_COMPAT_TESTS
ISC_RUN_TEST_IMPL(quic_tls_test_native_to_compat) { test_expect_success(); }

ISC_RUN_TEST_IMPL(quic_tls_test_native_to_compat_TLS_AES_128_GCM_SHA256) {
	test_expect_success();
}

ISC_RUN_TEST_IMPL(quic_tls_test_native_to_compat_TLS_AES_256_GCM_SHA384) {
	test_expect_success();
}

ISC_RUN_TEST_IMPL(quic_tls_test_native_to_compat_TLS_CHACHA20_POLY1305_SHA256) {
	test_expect_success();
}

ISC_RUN_TEST_IMPL(quic_tls_test_native_to_compat_TLS_AES_128_CCM_SHA256) {
	test_expect_success();
}

ISC_RUN_TEST_IMPL(
	quic_tls_test_native_to_compat_TLS_AES_128_CCM_8_SHA256_failure) {
	test_expect_failure();
}

ISC_RUN_TEST_IMPL(quic_tls_test_native_to_compat_resumption) {
	test_resumption();
}

ISC_RUN_TEST_IMPL(quic_tls_test_compat_to_native) { test_expect_success(); }

ISC_RUN_TEST_IMPL(quic_tls_test_compat_to_native_TLS_AES_128_GCM_SHA256) {
	test_expect_success();
}

ISC_RUN_TEST_IMPL(quic_tls_test_compat_to_native_TLS_AES_256_GCM_SHA384) {
	test_expect_success();
}

ISC_RUN_TEST_IMPL(quic_tls_test_compat_to_native_TLS_CHACHA20_POLY1305_SHA256) {
	test_expect_success();
}

ISC_RUN_TEST_IMPL(quic_tls_test_compat_to_native_TLS_AES_128_CCM_SHA256) {
	test_expect_success();
}

ISC_RUN_TEST_IMPL(
	quic_tls_test_compat_to_native_TLS_AES_128_CCM_8_SHA256_failure) {
	test_expect_failure();
}

ISC_RUN_TEST_IMPL(quic_tls_test_compat_to_native_resumption) {
	test_resumption();
}

#endif /* EXTRA_NATIVE_AND_COMPAT_TESTS */

ISC_TEST_LIST_START
ISC_TEST_ENTRY_CUSTOM(quic_tls_test_default, setup_quic_tls_test,
		      teardown_quic_tls_test)
ISC_TEST_ENTRY_CUSTOM(quic_tls_test_default_TLS_AES_128_GCM_SHA256,
		      setup_quic_tls_test_TLS_AES_128_GCM_SHA256,
		      teardown_quic_tls_test)
ISC_TEST_ENTRY_CUSTOM(quic_tls_test_default_TLS_AES_256_GCM_SHA384,
		      setup_quic_tls_test_TLS_AES_256_GCM_SHA384,
		      teardown_quic_tls_test)
ISC_TEST_ENTRY_CUSTOM(quic_tls_test_default_TLS_CHACHA20_POLY1305_SHA256,
		      setup_quic_tls_test_TLS_CHACHA20_POLY1305_SHA256,
		      teardown_quic_tls_test)
/*
 * On LibreSSL it is not possible to negotiate on using
 * TLS_AES_128_CCM_SHA256.  Considering that we have no control over
 * the internal QUIC handshaking process on this library, it appears
 * to be a limitation of the library. It is worth noting that this
 * cipher is not enabled by default for TLSv1.3 as well, so maybe this
 * case was never tested. Oh well, not the first time when LibreSSL is
 * "special."
 */
#ifndef HAVE_LIBRESSL
ISC_TEST_ENTRY_CUSTOM(quic_tls_test_default_TLS_AES_128_CCM_SHA256,
		      setup_quic_tls_test_TLS_AES_128_CCM_SHA256,
		      teardown_quic_tls_test)
#endif /* HAVE_LIBRESSL */

ISC_TEST_ENTRY_CUSTOM(quic_tls_test_default_TLS_AES_128_CCM_8_SHA256_failure,
		      setup_quic_tls_test_TLS_AES_128_CCM_8_SHA256,
		      teardown_quic_tls_test)
#ifndef HAVE_LIBRESSL
ISC_TEST_ENTRY_CUSTOM(quic_tls_test_default_resumption, setup_quic_tls_test,
		      teardown_quic_tls_test)
#endif /* HAVE_LIBRESSL */
#ifdef EXTRA_NATIVE_AND_COMPAT_TESTS
ISC_TEST_ENTRY_CUSTOM(quic_tls_test_native_to_compat,
		      setup_quic_tls_native_to_compat_test,
		      teardown_quic_tls_test)
ISC_TEST_ENTRY_CUSTOM(
	quic_tls_test_native_to_compat_TLS_AES_128_GCM_SHA256,
	setup_quic_tls_native_to_compat_test_TLS_AES_128_GCM_SHA256,
	teardown_quic_tls_test)
ISC_TEST_ENTRY_CUSTOM(
	quic_tls_test_native_to_compat_TLS_AES_256_GCM_SHA384,
	setup_quic_tls_native_to_compat_test_TLS_AES_256_GCM_SHA384,
	teardown_quic_tls_test)
ISC_TEST_ENTRY_CUSTOM(
	quic_tls_test_native_to_compat_TLS_CHACHA20_POLY1305_SHA256,
	setup_quic_tls_native_to_compat_test_TLS_CHACHA20_POLY1305_SHA256,
	teardown_quic_tls_test)
ISC_TEST_ENTRY_CUSTOM(
	quic_tls_test_native_to_compat_TLS_AES_128_CCM_SHA256,
	setup_quic_tls_native_to_compat_test_TLS_AES_128_CCM_SHA256,
	teardown_quic_tls_test)
ISC_TEST_ENTRY_CUSTOM(
	quic_tls_test_native_to_compat_TLS_AES_128_CCM_8_SHA256_failure,
	setup_quic_tls_native_to_compat_test_TLS_AES_128_CCM_8_SHA256,
	teardown_quic_tls_test)
ISC_TEST_ENTRY_CUSTOM(quic_tls_test_native_to_compat_resumption,
		      setup_quic_tls_native_to_compat_test,
		      teardown_quic_tls_test)

ISC_TEST_ENTRY_CUSTOM(quic_tls_test_compat_to_native,
		      setup_quic_tls_compat_to_native_test,
		      teardown_quic_tls_test)
ISC_TEST_ENTRY_CUSTOM(
	quic_tls_test_compat_to_native_TLS_AES_128_GCM_SHA256,
	setup_quic_tls_compat_to_native_test_TLS_AES_128_GCM_SHA256,
	teardown_quic_tls_test)
ISC_TEST_ENTRY_CUSTOM(
	quic_tls_test_compat_to_native_TLS_AES_256_GCM_SHA384,
	setup_quic_tls_compat_to_native_test_TLS_AES_256_GCM_SHA384,
	teardown_quic_tls_test)
ISC_TEST_ENTRY_CUSTOM(
	quic_tls_test_compat_to_native_TLS_CHACHA20_POLY1305_SHA256,
	setup_quic_tls_compat_to_native_test_TLS_CHACHA20_POLY1305_SHA256,
	teardown_quic_tls_test)
ISC_TEST_ENTRY_CUSTOM(
	quic_tls_test_compat_to_native_TLS_AES_128_CCM_SHA256,
	setup_quic_tls_compat_to_native_test_TLS_AES_128_CCM_SHA256,
	teardown_quic_tls_test)
ISC_TEST_ENTRY_CUSTOM(
	quic_tls_test_compat_to_native_TLS_AES_128_CCM_8_SHA256_failure,
	setup_quic_tls_compat_to_native_test_TLS_AES_128_CCM_8_SHA256,
	teardown_quic_tls_test)
ISC_TEST_ENTRY_CUSTOM(quic_tls_test_compat_to_native_resumption,
		      setup_quic_tls_compat_to_native_test,
		      teardown_quic_tls_test)

#endif /* EXTRA_NATIVE_AND_COMPAT_TESTS */
ISC_TEST_LIST_END

ISC_TEST_MAIN_CUSTOM(quic_tls_setup, quic_tls_teardown);
