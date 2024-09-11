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
 * Compatibility QUIC interface for OpenSSL and its forks that do not
 * provide native support for BoringSSL-style QUIC integration API.
 *
 * Heavily inspired by the similar code found in NGINX and HAProxy
 * code-bases. The ideas behind it are described in detail by NGINX
 * authors in this article:
 *
 * https://thenewstack.io/how-we-added-quic-support-to-openssl-without-patches-or-rebuilds/
 *
 * There is one thing worth mentioning, though. The code is structured
 * in such a way that it can be compiled using crypto libraries that
 * provide native support for the QUIC TLS integration API (like
 * QuicTLS). That is useful for interoperability testing purposes.
 *
 * These libraries treat the QUIC transport extension internally as a
 * standard one, which means that we cannot treat it as a custom one
 * and use SSL_CTX_add_custom_ext() and related
 * functionality. Somewhat ironically, in this case we will use
 * SSL_set_quic_transport_params() and
 * SSL_get_peer_quic_transport_params() to manipulate the data carried
 * by this extension.
 *
 * Also, while this code should compile fine when LibreSSL is used, it
 * will not work with this crypto library due to
 * SSL_CTX_set_keylog_callback() and related functionality being
 * deliberately broken.
 */

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>

#include <isc/buffer.h>
#include <isc/magic.h>
#include <isc/mem.h>
#include <isc/tls.h>
#include <isc/util.h>

#include "quic-int.h"
#include "quic_crypto.h"

/*
 * Around 16Kb - should be more than enough for any TLS handshake related
 * messages.
 */
#define MAX_COMPAT_TLS_RECORD_SIZE \
	(SSL3_RT_HEADER_LENGTH + SSL3_RT_MAX_TLS13_ENCRYPTED_LENGTH)

/* See RFC9001, Section 8.2 */
#define QUIC_TLS_TRANSPORT_PARAMS_EXT (0x39)

#define INITIAL_TRANSP_PARAMS_SIZE (128)

#define QUIC_COMAPT_DATA_MAGIC	  ISC_MAGIC('Q', 'c', 'C', 'd')
#define VALID_QUIC_COMPAT_DATA(t) ISC_MAGIC_VALID(t, QUIC_COMAPT_DATA_MAGIC)

/*
 * We raise errors for better compatibility with crypto libraries that
 * provide native BoringSSL-style QUIC integration API.
 */
#ifdef ERR_raise
#define quic_compat_tls_error_raise(err) ERR_raise(ERR_LIB_USER, (err))
#else
#define quic_compat_tls_error_raise(err) \
	ERR_put_error(ERR_LIB_USER, 0, (err), OPENSSL_FILE, OPENSSL_LINE)
#endif

#define quic_compat_tls_error_raise_generic() \
	quic_compat_tls_error_raise(ERR_R_INTERNAL_ERROR)

typedef struct quic_crypto_secrets {
	isc_buffer_t secret;
	uint8_t secret_data[EVP_MAX_MD_SIZE];
	isc_buffer_t key;
	uint8_t key_data[EVP_MAX_KEY_LENGTH];
	isc_buffer_t iv;
	uint8_t iv_data[EVP_MAX_IV_LENGTH];
} quic_crypto_secrets_t;

typedef struct quic_crypto_data {
	quic_crypto_secrets_t secrets;
	const EVP_CIPHER *aead;
} quic_crypto_data_t;

typedef struct quic_compat_data {
	uint32_t magic;

	isc_mem_t *mctx;
	isc_tls_t *tls;

	const isc_tls_quic_method_t *method;
	bool calling_method_cb;

	bool internal_cb_failed;

	isc_quic_encryption_level_t write_level;
	isc_quic_encryption_level_t read_level;
	uint64_t read_record_no;

#ifndef HAVE_NATIVE_BORINGSSL_QUIC_API
	isc_buffer_t transp_params;
	uint8_t init_transp_params_buf[INITIAL_TRANSP_PARAMS_SIZE];

	isc_buffer_t peer_transp_params;
	uint8_t init_peer_transp_params_buf[INITIAL_TRANSP_PARAMS_SIZE];
#endif /* HAVE_NATIVE_BORINGSSL_QUIC_API */

	quic_crypto_data_t crypto_data;
} quic_compat_data_t;

static void
quic_compat_tlsctx_configure(isc_tlsctx_t *tlsctx);

static bool
quic_compat_set_encryption_secret(quic_compat_data_t *restrict compat,
				  const isc_tls_cipher_t *tls_cipher,
				  const isc_region_t *secret);

static void
quic_compat_tlsctx_keylog_callback(const isc_tls_t *tls, const char *line);

static void
quic_compat_tls_init(isc_tls_t *tls, isc_mem_t *mctx);

static void
quic_compat_tls_uninit(isc_tls_t *tls);

static void
quic_compat_message_callback(int write_p, int version, int content_type,
			     const void *buf, size_t len, isc_tls_t *tls,
			     void *arg);

static bool
quic_compat_tls_calling_method_cb(const isc_tls_t *tls);

static int
quic_compat_tls_set_quic_method(isc_tls_t *tls,
				const isc_tls_quic_method_t *method);

static bool
quic_compat_make_tls_record_header(isc_buffer_t *rec_buf, const uint8_t type,
				   const size_t payload_len,
				   const size_t tag_len);

static void
quic_compat_compute_nonce(uint8_t *restrict nonce, const size_t len,
			  const uint64_t record_no);

static bool
quic_compat_seal(uint8_t *out, const quic_compat_data_t *compat,
		 const uint8_t *nonce, const isc_region_t *plaintext,
		 const isc_region_t *aad);

static bool
quic_compat_make_tls_record(quic_compat_data_t *compat,
			    const uint64_t record_no,
			    const isc_region_t *tls_payload,
			    isc_buffer_t *out_rec_buf);

static int
quic_compat_tls_provide_quic_data(isc_tls_t *tls,
				  const isc_quic_encryption_level_t level,
				  const uint8_t *data, const size_t len);

static int
quic_compat_tls_do_quic_handshake(isc_tls_t *tls);

static int
quic_compat_tls_process_quic_post_handshake(isc_tls_t *tls);

#ifndef HAVE_NATIVE_BORINGSSL_QUIC_API
static int
quic_compat_add_transport_params_callback(isc_tls_t *tls, unsigned int ext_type,
					  unsigned int context,
					  const unsigned char **out,
					  size_t *out_len, X509 *x,
					  size_t chainidx, int *al,
					  void *add_arg);

static int
quic_compat_parse_transport_params_callback(
	isc_tls_t *tls, unsigned int ext_type, unsigned int context,
	const unsigned char *in, size_t inlen, X509 *x, size_t chainidx,
	int *al, void *parse_arg);
#endif /* HAVE_NATIVE_BORINGSSL_QUIC_API */

static int
quic_compat_tls_set_quic_transport_params(isc_tls_t *tls, const uint8_t *params,
					  const size_t params_len);

static void
quic_compat_tls_get_peer_quic_transport_params(isc_tls_t *tls,
					       const uint8_t **out_params,
					       size_t *out_params_len);

static isc_quic_encryption_level_t
quic_compat_read_level(const isc_tls_t *tls);

static isc_quic_encryption_level_t
quic_compat_write_level(const isc_tls_t *tls);

static isc_tls_quic_interface_t compat_quic_interface =
	(isc_tls_quic_interface_t){
		.tlsctx_configure = quic_compat_tlsctx_configure,
		.tlsctx_keylog_callback = quic_compat_tlsctx_keylog_callback,

		.tls_init = quic_compat_tls_init,
		.tls_uninit = quic_compat_tls_uninit,

		.tls_calling_method_cb = quic_compat_tls_calling_method_cb,
		.tls_set_quic_method = quic_compat_tls_set_quic_method,

		.tls_provide_quic_data = quic_compat_tls_provide_quic_data,
		.tls_do_quic_handshake = quic_compat_tls_do_quic_handshake,
		.tls_process_quic_post_handshake =
			quic_compat_tls_process_quic_post_handshake,

		.tls_set_quic_transport_params =
			quic_compat_tls_set_quic_transport_params,
		.tls_get_peer_quic_transport_params =
			quic_compat_tls_get_peer_quic_transport_params,

		.tls_quic_read_level = quic_compat_read_level,
		.tls_quic_write_level = quic_compat_write_level
	};

static bool
quic_add_handshake_data(quic_compat_data_t *compat,
			const isc_quic_encryption_level_t level,
			const uint8_t *data, const size_t len) {
	bool ret = false;

	compat->calling_method_cb = true;
	ret = compat->method->add_handshake_data(compat->tls, level, data, len);
	compat->calling_method_cb = false;

	return ret;
}

static bool
quic_send_alert(quic_compat_data_t *compat,
		const isc_quic_encryption_level_t level, const uint8_t alert) {
	bool ret = false;

	compat->calling_method_cb = true;
	ret = compat->method->send_alert(compat->tls, level, alert);
	compat->calling_method_cb = false;

	return ret;
}

static bool
quic_set_secret(quic_compat_data_t *compat, const bool write,
		const isc_quic_encryption_level_t level,
		const isc_tls_cipher_t *cipher, const uint8_t *data,
		const size_t len) {
	bool ret = false;

	compat->calling_method_cb = true;
	if (write) {
		ret = compat->method->set_write_secret(compat->tls, level,
						       cipher, data, len);
	} else {
		ret = compat->method->set_read_secret(compat->tls, level,
						      cipher, data, len);
	}
	compat->calling_method_cb = false;

	return ret;
}

static void
quic_compat_tlsctx_configure(isc_tlsctx_t *tlsctx) {
	int ret = 0;

	ret = SSL_CTX_has_client_custom_ext(tlsctx,
					    QUIC_TLS_TRANSPORT_PARAMS_EXT);
	RUNTIME_CHECK(ret == 0);

#ifndef HAVE_NATIVE_BORINGSSL_QUIC_API
	/* Add QUIC transport extension  */
	ret = SSL_CTX_add_custom_ext(
		tlsctx, QUIC_TLS_TRANSPORT_PARAMS_EXT,
		SSL_EXT_CLIENT_HELLO | SSL_EXT_TLS1_3_ENCRYPTED_EXTENSIONS |
			SSL_EXT_TLS1_3_ONLY | SSL_EXT_TLS_IMPLEMENTATION_ONLY,
		quic_compat_add_transport_params_callback, NULL, NULL,
		quic_compat_parse_transport_params_callback, NULL);
	RUNTIME_CHECK(ret == 1);
#endif /* HAVE_NATIVE_BORINGSSL_QUIC_API */

	/* Disable early data support */
	ret = SSL_CTX_set_max_early_data(tlsctx, 0);
	RUNTIME_CHECK(ret == 1);
}

static bool
quic_compat_set_encryption_secret(quic_compat_data_t *restrict compat,
				  const isc_tls_cipher_t *tls_cipher,
				  const isc_region_t *secret) {
	isc_result_t result = ISC_R_FAILURE;
	quic_crypto_data_t *restrict crypto_data = &compat->crypto_data;
	const EVP_MD *md = NULL;
	isc_region_t key = { 0 }, iv = { 0 };
	size_t keylen = 0, ivlen = 0;

	isc_buffer_clear(&crypto_data->secrets.secret);
	isc_buffer_clear(&crypto_data->secrets.key);
	isc_buffer_clear(&crypto_data->secrets.iv);

	crypto_data->aead = isc__quic_crypto_tls_cipher_aead(tls_cipher);
	if (crypto_data->aead == NULL) {
		return false;
	}

	md = isc__quic_crypto_tls_cipher_md(tls_cipher);
	if (md == NULL) {
		return false;
	}

	result = isc_buffer_copyregion(&crypto_data->secrets.secret, secret);
	if (result != ISC_R_SUCCESS) {
		return false;
	}

	keylen = isc__quic_crypto_aead_keylen(crypto_data->aead);
	result = isc_buffer_reserve(&crypto_data->secrets.key, keylen);
	if (result != ISC_R_SUCCESS) {
		return false;
	}

	isc_buffer_add(&crypto_data->secrets.key, keylen);
	isc_buffer_usedregion(&crypto_data->secrets.key, &key);
	INSIST(key.length > 0);

	ivlen = isc__quic_crypto_aead_ivlen(crypto_data->aead);
	result = isc_buffer_reserve(&crypto_data->secrets.iv, ivlen);
	if (result != ISC_R_SUCCESS) {
		return false;
	}

	isc_buffer_add(&crypto_data->secrets.iv, ivlen);
	isc_buffer_usedregion(&crypto_data->secrets.iv, &iv);
	INSIST(iv.length > 0);

	if (!isc__quic_crypto_hkdf_expand_label(
		    key.base, key.length, md, secret->base, secret->length,
		    (const uint8_t *)ISC__QUIC_CRYPTO_KEY_LABEL,
		    ISC__QUIC_CRYPTO_KEY_LABEL_LEN) ||
	    !isc__quic_crypto_hkdf_expand_label(
		    iv.base, iv.length, md, secret->base, secret->length,
		    (const uint8_t *)ISC__QUIC_CRYPTO_IV_LABEL,
		    ISC__QUIC_CRYPTO_IV_LABEL_LEN))
	{
		return false;
	}

	return true;
}

/* Will not be called on LibreSSL */
static void
quic_compat_tlsctx_keylog_callback(const isc_tls_t *tls, const char *line) {
	quic_compat_data_t *compat = isc__tls_get_quic_data(tls);
	isc__tls_keylog_label_t label = ISC__TLS_KL_ILLEGAL;
	isc_buffer_t secret_data[EVP_MAX_MD_SIZE];
	isc_buffer_t secret = { 0 };
	isc_region_t secret_region = { 0 };
	isc_result_t result = ISC_R_FAILURE;
	isc_quic_encryption_level_t level = ISC_QUIC_ENCRYPTION_INITIAL;
	bool write_secret = false;
	bool is_server = false;
	const isc_tls_cipher_t *cipher = NULL;
	bool ret = false;

	INSIST(VALID_QUIC_COMPAT_DATA(compat));

	if (compat->internal_cb_failed) {
		return;
	}

	isc_buffer_init(&secret, secret_data, sizeof(secret_data));

	/*
	 * That's right: we are parsing the string that OpenSSL gave us
	 * where it put the secret formatted as text in hexadecimal form
	 * in order to convert it back to the binary form. Such is the
	 * way.
	 */
	result = isc__tls_parse_keylog_entry(line, &label, NULL, &secret);
	if (result != ISC_R_SUCCESS) {
		return;
	}

	is_server = (bool)SSL_is_server(tls);

	switch (label) {
	case ISC__TLS_KL_CLIENT_HANDSHAKE_TRAFFIC_SECRET:
		level = ISC_QUIC_ENCRYPTION_HANDSHAKE;
		write_secret = !is_server;
		break;
	case ISC__TLS_KL_SERVER_HANDSHAKE_TRAFFIC_SECRET:
		level = ISC_QUIC_ENCRYPTION_HANDSHAKE;
		write_secret = is_server;
		break;
	case ISC__TLS_KL_CLIENT_TRAFFIC_SECRET_0:
		level = ISC_QUIC_ENCRYPTION_APPLICATION;
		write_secret = !is_server;
		break;
	case ISC__TLS_KL_SERVER_TRAFFIC_SECRET_0:
		level = ISC_QUIC_ENCRYPTION_APPLICATION;
		write_secret = is_server;
		break;
	default:
		return;
	};

	cipher = SSL_get_current_cipher(tls);
	RUNTIME_CHECK(cipher != NULL);

	isc_buffer_usedregion(&secret, &secret_region);
	INSIST(secret_region.length > 0);

	ret = quic_set_secret(compat, write_secret, level, cipher,
			      secret_region.base, secret_region.length);

	if (!ret) {
		compat->internal_cb_failed = true;
		return;
	}

	if (write_secret) {
		compat->write_level = level;
	} else {
		compat->read_level = level;
		compat->read_record_no = 0;

		RUNTIME_CHECK(quic_compat_set_encryption_secret(
				      compat, cipher, &secret_region) == true);
	}
}

static void
quic_compat_tls_init(isc_tls_t *tls, isc_mem_t *mctx) {
	int ret;
	BIO *rbio = NULL, *wbio = NULL;
	quic_compat_data_t *compat = isc_mem_cget(mctx, 1, sizeof(*compat));

	*compat = (quic_compat_data_t){
		.tls = tls,
		.read_level = ISC_QUIC_ENCRYPTION_INITIAL,
		.write_level = ISC_QUIC_ENCRYPTION_INITIAL
	};

	isc_mem_attach(mctx, &compat->mctx);

	INSIST(isc__tls_get_quic_data(tls) == NULL);
	isc__tls_set_quic_data(tls, compat);

#ifndef HAVE_NATIVE_BORINGSSL_QUIC_API
	isc_buffer_init(&compat->transp_params,
			(void *)compat->init_transp_params_buf,
			sizeof(compat->init_transp_params_buf));
	isc_buffer_setmctx(&compat->transp_params, mctx);

	isc_buffer_init(&compat->peer_transp_params,
			(void *)compat->init_peer_transp_params_buf,
			sizeof(compat->init_peer_transp_params_buf));
	isc_buffer_setmctx(&compat->peer_transp_params, mctx);
#endif /* HAVE_NATIVE_BORINGSSL_QUIC_API */

	isc_buffer_init(&compat->crypto_data.secrets.secret,
			compat->crypto_data.secrets.secret_data,
			sizeof(compat->crypto_data.secrets.secret_data));

	isc_buffer_init(&compat->crypto_data.secrets.key,
			compat->crypto_data.secrets.key_data,
			sizeof(compat->crypto_data.secrets.key_data));

	isc_buffer_init(&compat->crypto_data.secrets.iv,
			compat->crypto_data.secrets.iv_data,
			sizeof(compat->crypto_data.secrets.iv_data));

	rbio = BIO_new(BIO_s_mem());
	RUNTIME_CHECK(rbio != NULL);
	/*
	 * We get output via method callbacks, after that the data can be
	 * discarded.
	 */
	wbio = BIO_new(BIO_s_null());
	RUNTIME_CHECK(wbio != NULL);

	SSL_set_bio(tls, rbio, wbio);
	SSL_set_msg_callback(tls, quic_compat_message_callback);
	ret = SSL_set_max_early_data(tls, 0);
	RUNTIME_CHECK(ret == 1);

	compat->magic = QUIC_COMAPT_DATA_MAGIC;
}

static void
quic_compat_tls_uninit(isc_tls_t *tls) {
	isc_mem_t *mctx = NULL;
	quic_compat_data_t *compat = isc__tls_get_quic_data(tls);

	INSIST(VALID_QUIC_COMPAT_DATA(compat));

	isc_buffer_invalidate(&compat->crypto_data.secrets.iv);
	isc_buffer_invalidate(&compat->crypto_data.secrets.key);
	isc_buffer_invalidate(&compat->crypto_data.secrets.secret);

#ifndef HAVE_NATIVE_BORINGSSL_QUIC_API
	isc_buffer_clearmctx(&compat->peer_transp_params);
	isc_buffer_invalidate(&compat->peer_transp_params);

	isc_buffer_clearmctx(&compat->transp_params);
	isc_buffer_invalidate(&compat->transp_params);
#endif /* HAVE_NATIVE_BORINGSSL_QUIC_API */

	mctx = compat->mctx;
	compat->mctx = NULL;

	compat->tls = NULL;

	compat->magic = 0;

	isc_mem_cput(mctx, compat, 1, sizeof(*compat));
	isc__tls_set_quic_data(tls, NULL);
	SSL_set_msg_callback_arg(tls, NULL);

	isc_mem_detach(&mctx);
}

static void
quic_compat_message_callback(int write_p, int version, int content_type,
			     const void *buf, size_t len, isc_tls_t *tls,
			     void *arg) {
	isc_quic_encryption_level_t level;
	quic_compat_data_t *compat = isc__tls_get_quic_data(tls);
	const uint8_t *palert = NULL;
	bool ret = false;

	UNUSED(version);
	UNUSED(arg);

	INSIST(VALID_QUIC_COMPAT_DATA(compat));

	if (!write_p) {
		return;
	}

	if (compat->internal_cb_failed) {
		return;
	}

	level = compat->write_level;

	switch (content_type) {
	case SSL3_RT_HANDSHAKE:
		ret = quic_add_handshake_data(compat, level, buf, len);
		if (!ret) {
			compat->internal_cb_failed = true;
		}
		break;
	case SSL3_RT_ALERT:
		/*
		 * Skip the legacy severity field. See RFC8446, Section 6.
		 */
		palert = (const uint8_t *)buf;
		palert++;
		ret = quic_send_alert(compat, level, palert[0]);
		if (!ret) {
			compat->internal_cb_failed = true;
		}
		break;
	default:
		break;
	}
}

static bool
quic_compat_tls_calling_method_cb(const isc_tls_t *tls) {
	quic_compat_data_t *compat = isc__tls_get_quic_data(tls);

	INSIST(VALID_QUIC_COMPAT_DATA(compat));

	return compat->calling_method_cb;
}

static int
quic_compat_tls_set_quic_method(isc_tls_t *tls,
				const isc_tls_quic_method_t *method) {
	quic_compat_data_t *compat = isc__tls_get_quic_data(tls);

	INSIST(VALID_QUIC_COMPAT_DATA(compat));

	compat->read_level = compat->write_level = ISC_QUIC_ENCRYPTION_INITIAL;
	compat->method = method;
	compat->internal_cb_failed = false;

	return 1;
}

static bool
quic_compat_make_tls_record_header(isc_buffer_t *out_rec_buf,
				   const uint8_t type, const size_t payload_len,
				   const size_t tag_len) {
	size_t len = payload_len + tag_len;
	isc_result_t result = isc_buffer_reserve(out_rec_buf,
						 SSL3_RT_HEADER_LENGTH);

	if (result != ISC_R_SUCCESS) {
		return false;
	}

	/* type */
	isc_buffer_putuint8(out_rec_buf, type);
	/* Major and Minor version for record headers */
	isc_buffer_putuint8(out_rec_buf, 0x03);
	isc_buffer_putuint8(out_rec_buf, 0x03);
	/* length */
	isc_buffer_putuint16(out_rec_buf, (uint16_t)len);

	return true;
}

/*
 * See RFC9001, Section 5.3. In particular:
 *
 * "The nonce, N, is formed by combining the packet protection IV with
 * the packet number. The 62 bits of the reconstructed QUIC packet
 * number in network byte order are left-padded with zeros to the size
 * of the IV. The exclusive OR of the padded packet number and the IV
 * forms the AEAD nonce."
 */
static void
quic_compat_compute_nonce(uint8_t *restrict nonce, const size_t len,
			  const uint64_t record_no) {
	nonce[len - 8] ^= (record_no >> 56) & 0x3f;
	nonce[len - 7] ^= (record_no >> 48) & 0xff;
	nonce[len - 6] ^= (record_no >> 40) & 0xff;
	nonce[len - 5] ^= (record_no >> 32) & 0xff;
	nonce[len - 4] ^= (record_no >> 24) & 0xff;
	nonce[len - 3] ^= (record_no >> 16) & 0xff;
	nonce[len - 2] ^= (record_no >> 8) & 0xff;
	nonce[len - 1] ^= record_no & 0xff;
}

static bool
quic_compat_seal(uint8_t *out, const quic_compat_data_t *compat,
		 const uint8_t *nonce, const isc_region_t *plaintext,
		 const isc_region_t *aad) {
	const EVP_CIPHER *aead = compat->crypto_data.aead;
	EVP_CIPHER_CTX *aead_ctx = NULL;
	isc_region_t iv = { 0 }, key = { 0 };
	bool ret = false;

	isc_buffer_usedregion(&compat->crypto_data.secrets.iv, &iv);
	isc_buffer_usedregion(&compat->crypto_data.secrets.key, &key);

	ret = isc__quic_crypto_aead_ctx_encrypt_create(&aead_ctx, aead,
						       key.base, iv.length);
	if (!ret) {
		return false;
	}

	ret = isc__quic_crypto_aead_encrypt(out, aead, aead_ctx, nonce,
					    plaintext->base, plaintext->length,
					    aad->base, aad->length);

	isc__quic_crypto_cipher_ctx_free(&aead_ctx);

	return ret;
}

static bool
quic_compat_make_tls_record(quic_compat_data_t *compat,
			    const uint64_t record_no,
			    const isc_region_t *tls_payload,
			    isc_buffer_t *out_rec_buf) {
	isc_region_t aad = { 0 };
	isc_region_t iv = { 0 };
	uint8_t nonce[EVP_MAX_IV_LENGTH];
	const size_t tag_len =
		isc__quic_crypto_aead_taglen(compat->crypto_data.aead);
	isc_result_t result = isc_buffer_reserve(
		out_rec_buf,
		tls_payload->length + SSL3_RT_HEADER_LENGTH + tag_len);
	uint8_t *out = NULL;

	if (result != ISC_R_SUCCESS) {
		return false;
	}

	/* Must succeed as enough data is reserved in the buffer */
	RUNTIME_CHECK(quic_compat_make_tls_record_header(
			      out_rec_buf, SSL3_RT_APPLICATION_DATA,
			      tls_payload->length, tag_len) == true);

	aad.base = isc_buffer_used(out_rec_buf);
	aad.base -= SSL3_RT_HEADER_LENGTH;
	aad.length = SSL3_RT_HEADER_LENGTH;

	out = isc_buffer_used(out_rec_buf);
	isc_buffer_add(out_rec_buf, tls_payload->length + tag_len);

	isc_buffer_usedregion(&compat->crypto_data.secrets.iv, &iv);
	INSIST(iv.length > 0);
	memmove(nonce, iv.base, iv.length);

	quic_compat_compute_nonce(nonce, iv.length, record_no);

	return quic_compat_seal(out, compat, nonce, tls_payload, &aad);
}

static int
quic_compat_tls_provide_quic_data(isc_tls_t *tls,
				  const isc_quic_encryption_level_t level,
				  const uint8_t *data, const size_t len) {
	quic_compat_data_t *compat = isc__tls_get_quic_data(tls);
	uint8_t tls_rec_data[MAX_COMPAT_TLS_RECORD_SIZE];
	isc_buffer_t tls_rec_buf;
	isc_buffer_t in_data;
	size_t remaining = 0;
	BIO *rbio = NULL;

	/*
	 * Pack the QUIC handshake data into one or more regular TLS
	 * records so that it can be processed by SSL_do_handshake() as if
	 * it is a regular TLS handshake.
	 */

	INSIST(VALID_QUIC_COMPAT_DATA(compat));

	if (level < compat->read_level) {
		quic_compat_tls_error_raise_generic();
		return 0;
	}

	if (len == 0) {
		return 1;
	}

	rbio = SSL_get_rbio(tls);

	isc_buffer_init(&in_data, (void *)data, len);
	isc_buffer_add(&in_data, len);
	isc_buffer_init(&tls_rec_buf, (void *)tls_rec_data,
			sizeof(tls_rec_data));

	while ((remaining = isc_buffer_remaininglength(&in_data)) > 0) {
		isc_region_t quic_payload;
		size_t payload_data_sz = 0;
		int ret;
		uint64_t rec_no = compat->read_record_no++;

		if (level == ISC_QUIC_ENCRYPTION_INITIAL) {
			payload_data_sz = ISC_MIN(
				remaining, SSL3_RT_HEADER_LENGTH +
						   SSL3_RT_MAX_PLAIN_LENGTH);
		} else {
			payload_data_sz = ISC_MIN(remaining,
						  MAX_COMPAT_TLS_RECORD_SIZE);
		}

		isc_buffer_remainingregion(&in_data, &quic_payload);
		quic_payload.length = (unsigned int)payload_data_sz;

		if (level == ISC_QUIC_ENCRYPTION_INITIAL) {
			isc_region_t tls_header;

			/* the data is not protected - can be passed as is */
			quic_compat_make_tls_record_header(
				&tls_rec_buf, SSL3_RT_HANDSHAKE,
				quic_payload.length, 0);

			isc_buffer_usedregion(&tls_rec_buf, &tls_header);

			ret = BIO_write(rbio, tls_header.base,
					tls_header.length);
			if (ret <= 0) {
				return 0;
			}

			ret = BIO_write(rbio, quic_payload.base,
					quic_payload.length);
			if (ret <= 0) {
				return 0;
			}
		} else {
			uint8_t tls_payload_data[MAX_COMPAT_TLS_RECORD_SIZE];
			isc_buffer_t tls_payload_buf;
			isc_region_t tls_payload;
			isc_region_t tls_rec;
			isc_result_t result;

			if (compat->crypto_data.aead == NULL) {
				quic_compat_tls_error_raise_generic();
				return 0;
			}

			isc_buffer_init(&tls_payload_buf,
					(void *)tls_payload_data,
					sizeof(tls_payload_data));

			result = isc_buffer_copyregion(&tls_payload_buf,
						       &quic_payload);

			if (result != ISC_R_SUCCESS) {
				quic_compat_tls_error_raise_generic();
				return 0;
			}

			isc_buffer_putuint8(&tls_payload_buf,
					    (uint8_t)SSL3_RT_HANDSHAKE);

			isc_buffer_usedregion(&tls_payload_buf, &tls_payload);

			if (!quic_compat_make_tls_record(
				    compat, rec_no, &tls_payload, &tls_rec_buf))
			{
				quic_compat_tls_error_raise_generic();
				return 0;
			}

			isc_buffer_usedregion(&tls_rec_buf, &tls_rec);
			ret = BIO_write(rbio, tls_rec.base, tls_rec.length);
			if (ret <= 0) {
				return 0;
			}
		}

		isc_buffer_clear(&tls_rec_buf);
		isc_buffer_forward(&in_data, payload_data_sz);
	}

	return 1;
}

static int
quic_compat_tls_do_quic_handshake(isc_tls_t *tls) {
	quic_compat_data_t *compat = isc__tls_get_quic_data(tls);
	int ret = 0;

	INSIST(VALID_QUIC_COMPAT_DATA(compat));

	ret = SSL_do_handshake(tls);

	/* Similar to how LibreSSL does it internally. */
	if (compat->internal_cb_failed) {
		quic_compat_tls_error_raise_generic();
		return -1;
	}

	return ret;
}

static int
quic_compat_tls_process_quic_post_handshake(isc_tls_t *tls) {
	quic_compat_data_t *compat = isc__tls_get_quic_data(tls);
	BIO *rbio = NULL;

	INSIST(VALID_QUIC_COMPAT_DATA(compat));

	if (SSL_in_init(tls)) {
		quic_compat_tls_error_raise(ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
		return 0;
	}

	/*
	 * Let's do an approximation of what BoringSSL or QuicTLS do.
	 * The idea is that SSL_read(_ex)() can process handshake-related data
	 * and drive the handshake. If there are any handshake related records
	 * left unprocessed, it will process them and alter the sate of the
	 * given SSL object ('tls'). We need to use some read buffers to pass to
	 * the function, but we are not really interested in any data (and there
	 * should not be any).
	 */

	rbio = SSL_get_rbio(tls);

	while (BIO_pending(rbio) > 0) {
		uint8_t discard_buf[MAX_COMPAT_TLS_RECORD_SIZE];
		size_t discard_len = 0;
		int ret = SSL_read_ex(tls, discard_buf, sizeof(discard_buf),
				      &discard_len);
		int ssl_err;

		if (ret != 0) {
			continue;
		}

		ssl_err = SSL_get_error(tls, ret);
		switch (ssl_err) {
		case SSL_ERROR_NONE:
		case SSL_ERROR_WANT_READ:
		case SSL_ERROR_WANT_WRITE:
		case SSL_ERROR_ZERO_RETURN:
			return 1;
		default:
			return 0;
		}
	}

	return 1;
}

#ifndef HAVE_NATIVE_BORINGSSL_QUIC_API
static int
quic_compat_add_transport_params_callback(isc_tls_t *tls, unsigned int ext_type,
					  unsigned int context,
					  const unsigned char **out,
					  size_t *out_len, X509 *x,
					  size_t chainidx, int *al,
					  void *add_arg) {
	isc_region_t transp_params = { 0 };
	quic_compat_data_t *compat = isc__tls_get_quic_data(tls);

	UNUSED(context);
	UNUSED(x);
	UNUSED(chainidx);
	UNUSED(al);
	UNUSED(add_arg);

	INSIST(VALID_QUIC_COMPAT_DATA(compat));
	INSIST(ext_type == QUIC_TLS_TRANSPORT_PARAMS_EXT);

	isc_buffer_usedregion(&compat->transp_params, &transp_params);
	if (transp_params.length > 0) {
		*out = transp_params.base;
		*out_len = transp_params.length;
	}

	return 1;
}

static int
quic_compat_parse_transport_params_callback(
	isc_tls_t *tls, unsigned int ext_type, unsigned int context,
	const unsigned char *in, size_t inlen, X509 *x, size_t chainidx,
	int *al, void *parse_arg) {
	quic_compat_data_t *compat = isc__tls_get_quic_data(tls);

	UNUSED(context);
	UNUSED(x);
	UNUSED(chainidx);
	UNUSED(al);
	UNUSED(parse_arg);

	INSIST(compat != NULL);
	INSIST(ext_type == QUIC_TLS_TRANSPORT_PARAMS_EXT);

	isc_buffer_putmem(&compat->peer_transp_params, in, inlen);

	return 1;
}
#endif /* HAVE_NATIVE_BORINGSSL_QUIC_API */

static int
quic_compat_tls_set_quic_transport_params(isc_tls_t *tls, const uint8_t *params,
					  const size_t params_len) {
#ifndef HAVE_NATIVE_BORINGSSL_QUIC_API
	quic_compat_data_t *compat = isc__tls_get_quic_data(tls);

	INSIST(VALID_QUIC_COMPAT_DATA(compat));

	isc_buffer_clear(&compat->transp_params);
	isc_buffer_trycompact(&compat->transp_params);

	isc_buffer_putmem(&compat->transp_params, params, params_len);

	return 1;
#else
	return SSL_set_quic_transport_params(tls, params, params_len);
#endif /* HAVE_NATIVE_BORINGSSL_QUIC_API */
}

static void
quic_compat_tls_get_peer_quic_transport_params(isc_tls_t *tls,
					       const uint8_t **out_params,
					       size_t *out_params_len) {
#ifndef HAVE_NATIVE_BORINGSSL_QUIC_API
	quic_compat_data_t *compat = isc__tls_get_quic_data(tls);
	isc_region_t peer_params = { 0 };

	INSIST(VALID_QUIC_COMPAT_DATA(compat));

	*out_params = 0;
	isc_buffer_usedregion(&compat->peer_transp_params, &peer_params);
	if (peer_params.length == 0) {
		return;
	}

	*out_params = peer_params.base;
	*out_params_len = peer_params.length;
#else
	SSL_get_peer_quic_transport_params(tls, out_params, out_params_len);
#endif /* HAVE_NATIVE_BORINGSSL_QUIC_API */
}

static isc_quic_encryption_level_t
quic_compat_read_level(const isc_tls_t *tls) {
	quic_compat_data_t *compat = isc__tls_get_quic_data(tls);

	INSIST(VALID_QUIC_COMPAT_DATA(compat));

	return compat->read_level;
}

static isc_quic_encryption_level_t
quic_compat_write_level(const isc_tls_t *tls) {
	quic_compat_data_t *compat = isc__tls_get_quic_data(tls);

	INSIST(VALID_QUIC_COMPAT_DATA(compat));

	return compat->write_level;
}

const isc_tls_quic_interface_t *
isc__tls_get_compat_quic_interface(void) {
	return &compat_quic_interface;
}
