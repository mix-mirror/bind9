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
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/hkdf.h>
#include <openssl/kdf.h>
#include <openssl/opensslv.h>
#include <openssl/ssl.h>

#ifndef LIBRESSL_VERSION_NUMBER
#include <openssl/aead.h>
#endif

#include <isc/attributes.h>
#include <isc/buffer.h>
#include <isc/mem.h>
#include <isc/result.h>
#include <isc/safe.h>
#include <isc/tls.h>
#include <isc/types.h>
#include <isc/util.h>

#include "quic_p.h"

constexpr uint8_t quic_v1_initial_salt[] = {
	0x38, 0x76, 0x2C, 0xF7, 0xF5, 0x59, 0x34, 0xB3, 0x4D, 0x17,
	0x9A, 0xE6, 0xA4, 0xC8, 0x0C, 0xAD, 0xCC, 0xBB, 0x7F, 0x0A,
};

constexpr uint8_t quic_v2_initial_salt[] = {
	0x0D, 0xED, 0xE3, 0xDE, 0xF7, 0x00, 0xA6, 0xDB, 0x81, 0x93,
	0x81, 0xBE, 0x6E, 0x26, 0x9D, 0xCB, 0xF9, 0xBD, 0x2E, 0xD9,
};

constexpr uint8_t quic_client_label[] = {
	'c', 'l', 'i', 'e', 'n', 't', ' ', 'i', 'n',
};

constexpr uint8_t quic_server_label[] = {
	's', 'e', 'r', 'v', 'e', 'r', ' ', 'i', 'n',
};

static int
add_handshake_data(isc_tls_t *tls, enum ssl_encryption_level_t level,
		   const uint8_t *data, size_t len);

static int
flush_flight_cb(isc_tls_t *tls);

static int
send_alert_cb(isc_tls_t *tls, enum ssl_encryption_level_t level, uint8_t alert);

static ngtcp2_encryption_level libssl_to_ngtcp2_encrypt_level_lut[] = {
	[ssl_encryption_initial] = NGTCP2_ENCRYPTION_LEVEL_INITIAL,
	[ssl_encryption_early_data] = NGTCP2_ENCRYPTION_LEVEL_0RTT,
	[ssl_encryption_handshake] = NGTCP2_ENCRYPTION_LEVEL_HANDSHAKE,
	[ssl_encryption_application] = NGTCP2_ENCRYPTION_LEVEL_1RTT,
};

static enum ssl_encryption_level_t ngtcp2_to_libssl_encrypt_level_lut[] = {
	[NGTCP2_ENCRYPTION_LEVEL_INITIAL] = ssl_encryption_initial,
	[NGTCP2_ENCRYPTION_LEVEL_0RTT] = ssl_encryption_early_data,
	[NGTCP2_ENCRYPTION_LEVEL_HANDSHAKE] = ssl_encryption_handshake,
	[NGTCP2_ENCRYPTION_LEVEL_1RTT] = ssl_encryption_application,
};

static SSL_QUIC_METHOD method ISC_ATTR_UNUSED = {
	.add_handshake_data = add_handshake_data,
	.flush_flight = flush_flight_cb,
	.send_alert = send_alert_cb,
};

static int
add_handshake_data(isc_tls_t *tls, enum ssl_encryption_level_t level,
		   const uint8_t *data, size_t len) {
	ngtcp2_encryption_level nglevel;
	isc_quic_conn_t *conn;
	int r;

	REQUIRE(level <= sizeof(libssl_to_ngtcp2_encrypt_level_lut));

	conn = SSL_get_app_data(tls);
	nglevel = libssl_to_ngtcp2_encrypt_level_lut[level];
	r = ngtcp2_conn_submit_crypto_data(conn->inner, nglevel, data, len);
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
	isc_quic_conn_t *conn = SSL_get_app_data(tls);
	ngtcp2_conn_set_tls_alert(conn->inner, alert);
	return 1;
}

static isc_result_t
hkdf_expand_label(isc_region_t out, const EVP_MD *md, isc_constregion_t secret,
		  isc_constregion_t label) {
	const uint8_t label_prefix[] = { 't', 'l', 's', '1', '3', ' ' };
	uint8_t hkdf_label[256];
	isc_buffer_t buffer;

	/*
	 * struct {
	 *	uint16 length = Length;
	 *	opaque label<7..255> = "tls13 " + Label;
	 *	opaque context<0..255> = Context;
	 * } HkdfLabel;
	 */
	isc_buffer_init(&buffer, hkdf_label, sizeof(hkdf_label));
	isc_buffer_putuint16(&buffer, out.length);
	isc_buffer_putuint8(&buffer, sizeof(label_prefix) + label.length);
	isc_buffer_putmem(&buffer, label_prefix, sizeof(label_prefix));
	isc_buffer_putmem(&buffer, label.base, label.length);
	isc_buffer_putuint8(&buffer, 0);

	if (HKDF_expand(out.base, out.length, md, secret.base, secret.length,
			isc_buffer_base(&buffer),
			isc_buffer_usedlength(&buffer)) != 1)
	{
		return ISC_R_CRYPTOFAILURE;
	}

	return ISC_R_SUCCESS;
}

const int shim_ctx = 0;

struct shim {
	int kind;
	union {
		AES_KEY key;
		uint8_t rawkey[32];
	};
};

static isc_result_t
initial_key(ngtcp2_conn *ngconn, const ngtcp2_cid *dcid, uint32_t version) {
	ngtcp2_crypto_aead_ctx rx_aead_ctx, tx_aead_ctx, retry_aead_ctx;
	ngtcp2_crypto_cipher_ctx rx_hp_ctx, tx_hp_ctx;
	ngtcp2_crypto_aead retry_aead;
	uint8_t rx_secret[32], rx_key[16], rx_iv[12], rx_hp[16];
	uint8_t tx_secret[32], tx_key[16], tx_iv[12], tx_hp[16];
	uint8_t initial_secret[32];

	const uint8_t *salt;
	size_t salt_len;
	size_t len;

	ngtcp2_crypto_ctx ctx = {
		.aead = { .native_handle = UNCONST(EVP_aead_aes_128_gcm()),
			  .max_overhead = 16 },
		.md = { .native_handle = UNCONST(EVP_sha256()) },
		.hp = { .native_handle = UNCONST(&shim_ctx) },
	};

	switch (version) {
	case NGTCP2_PROTO_VER_V1:
		salt = quic_v1_initial_salt;
		salt_len = sizeof(quic_v1_initial_salt);
		break;
	case NGTCP2_PROTO_VER_V2:
		salt = quic_v2_initial_salt;
		salt_len = sizeof(quic_v2_initial_salt);
		break;
	default:
		UNREACHABLE();
	}

	ngtcp2_conn_set_initial_crypto_ctx(ngconn, &ctx);

	/* initial secret */
	len = EVP_MD_size(EVP_sha256());
	if (HKDF_extract(initial_secret, &len, EVP_sha256(), dcid->data,
			 dcid->datalen, salt, salt_len) != 1)
	{
		return ISC_R_CRYPTOFAILURE;
	}

	if (ngtcp2_conn_is_server2(ngconn)) {
		RETERR(hkdf_expand_label(
			(isc_region_t){ rx_secret, sizeof(rx_secret) },
			EVP_sha256(),
			(isc_constregion_t){ initial_secret,
					     sizeof(initial_secret) },
			(isc_constregion_t){ quic_client_label,
					     sizeof(quic_client_label) }));

		RETERR(hkdf_expand_label(
			(isc_region_t){ tx_secret, sizeof(tx_secret) },
			EVP_sha256(),
			(isc_constregion_t){ initial_secret,
					     sizeof(initial_secret) },
			(isc_constregion_t){ quic_server_label,
					     sizeof(quic_server_label) }));

	} else {
		RETERR(hkdf_expand_label(
			(isc_region_t){ rx_secret, sizeof(rx_secret) },
			EVP_sha256(),
			(isc_constregion_t){ initial_secret,
					     sizeof(initial_secret) },
			(isc_constregion_t){ quic_server_label,
					     sizeof(quic_server_label) }));

		RETERR(hkdf_expand_label(
			(isc_region_t){ tx_secret, sizeof(tx_secret) },
			EVP_sha256(),
			(isc_constregion_t){ initial_secret,
					     sizeof(initial_secret) },
			(isc_constregion_t){ quic_client_label,
					     sizeof(quic_client_label) }));
	}

	RETERR(hkdf_expand_label(
		(isc_region_t){ rx_key, sizeof(rx_key) }, EVP_sha256(),
		(isc_constregion_t){ rx_secret, sizeof(rx_secret) },
		(isc_constregion_t){ "quicv2 key", 10 }));
	RETERR(hkdf_expand_label(
		(isc_region_t){ rx_iv, sizeof(rx_iv) }, EVP_sha256(),
		(isc_constregion_t){ rx_secret, sizeof(rx_secret) },
		(isc_constregion_t){ "quicv2 iv", 9 }));
	RETERR(hkdf_expand_label(
		(isc_region_t){ rx_hp, sizeof(rx_hp) }, EVP_sha256(),
		(isc_constregion_t){ rx_secret, sizeof(rx_secret) },
		(isc_constregion_t){ "quicv2 hp", 9 }));

	RETERR(hkdf_expand_label(
		(isc_region_t){ tx_key, sizeof(tx_key) }, EVP_sha256(),
		(isc_constregion_t){ tx_secret, sizeof(tx_secret) },
		(isc_constregion_t){ "quicv2 key", 10 }));
	RETERR(hkdf_expand_label(
		(isc_region_t){ tx_iv, sizeof(tx_iv) }, EVP_sha256(),
		(isc_constregion_t){ tx_secret, sizeof(tx_secret) },
		(isc_constregion_t){ "quicv2 iv", 9 }));
	RETERR(hkdf_expand_label(
		(isc_region_t){ tx_hp, sizeof(tx_hp) }, EVP_sha256(),
		(isc_constregion_t){ tx_secret, sizeof(tx_secret) },
		(isc_constregion_t){ "quicv2 hp", 9 }));

#ifdef LIBRESSL_VERSION_NUMBER
	rx_aead_ctx = (ngtcp2_crypto_aead_ctx){
		.native_handle = EVP_AEAD_CTX_new(),
	};
	EVP_AEAD_CTX_init(rx_aead_ctx.native_handle, ctx.aead.native_handle,
			  rx_key, sizeof(rx_key), 0, NULL);

	tx_aead_ctx = (ngtcp2_crypto_aead_ctx){
		.native_handle = EVP_AEAD_CTX_new(),
	};
	EVP_AEAD_CTX_init(tx_aead_ctx.native_handle, ctx.aead.native_handle,
			  tx_key, sizeof(tx_key), 0, NULL);

#else
	rx_aead_ctx = (ngtcp2_crypto_aead_ctx){
		.native_handle = EVP_AEAD_CTX_new(ctx.aead.native_handle,
						  rx_key, sizeof(rx_key),
						  EVP_AEAD_DEFAULT_TAG_LENGTH),
	};

	tx_aead_ctx = (ngtcp2_crypto_aead_ctx){
		.native_handle = EVP_AEAD_CTX_new(ctx.aead.native_handle,
						  tx_key, sizeof(tx_key),
						  EVP_AEAD_DEFAULT_TAG_LENGTH),
	};
#endif

#ifdef LIBRESSL_VERSION_NUMBER
	rx_hp_ctx = (ngtcp2_crypto_cipher_ctx){
		.native_handle = EVP_CIPHER_CTX_new(),
	};
	EVP_EncryptInit_ex(rx_hp_ctx.native_handle, EVP_aes_128_ecb(), NULL,
			   rx_hp, NULL);

	tx_hp_ctx = (ngtcp2_crypto_cipher_ctx){
		.native_handle = EVP_CIPHER_CTX_new(),
	};
	EVP_EncryptInit_ex(tx_hp_ctx.native_handle, EVP_aes_128_ecb(), NULL,
			   tx_hp, NULL);
#else
	rx_hp_ctx = (ngtcp2_crypto_cipher_ctx){
		.native_handle = malloc(sizeof(struct shim)),
	};
	struct shim *s = rx_hp_ctx.native_handle;
	s->kind = 0;
	AES_set_encrypt_key(rx_hp, 128, &s->key);

	tx_hp_ctx = (ngtcp2_crypto_cipher_ctx){
		.native_handle = malloc(sizeof(struct shim)),
	};
	s = tx_hp_ctx.native_handle;
	s->kind = 0;
	AES_set_encrypt_key(tx_hp, 128, &s->key);

#endif

	if (!ngtcp2_conn_is_server2(ngconn) &&
	    !ngtcp2_conn_after_retry2(ngconn))
	{
		retry_aead = (ngtcp2_crypto_aead){
			.native_handle = UNCONST(EVP_aead_aes_128_gcm()),
			.max_overhead = 16,
		};

#ifdef LIBRESSL_VERSION_NUMBER
		retry_aead_ctx = (ngtcp2_crypto_aead_ctx){
			.native_handle = EVP_AEAD_CTX_new(),
		};
		EVP_AEAD_CTX_init(retry_aead_ctx.native_handle,
				  ctx.aead.native_handle,
				  UNCONST(NGTCP2_RETRY_KEY_V2),
				  strlen(NGTCP2_RETRY_KEY_V2) - 1, 0, NULL);

#else
		retry_aead_ctx = (ngtcp2_crypto_aead_ctx){
			.native_handle = EVP_AEAD_CTX_new(
				retry_aead.native_handle,
				UNCONST(NGTCP2_RETRY_KEY_V2),
				EVP_AEAD_key_length(retry_aead.native_handle),
				EVP_AEAD_DEFAULT_TAG_LENGTH),
		};
#endif
	}

	if (ngtcp2_conn_install_initial_key(ngconn, &rx_aead_ctx, rx_iv,
					    &rx_hp_ctx, &tx_aead_ctx, tx_iv,
					    &tx_hp_ctx, 12) != 0)
	{
		return ISC_R_CRYPTOFAILURE;
	}

	if (!ngtcp2_conn_is_server2(ngconn) &&
	    !ngtcp2_conn_after_retry2(ngconn))
	{
		ngtcp2_conn_set_retry_aead(ngconn, &retry_aead,
					   &retry_aead_ctx);
	}

	return ISC_R_SUCCESS;
}

#ifdef LIBRESSL_VERSION_NUMBER

static int
crypto_read_write_crypto_data(ngtcp2_conn *conn,
			      ngtcp2_encryption_level encryption_level,
			      const uint8_t *data, size_t datalen) {
	SSL *ssl = ngtcp2_conn_get_tls_native_handle2(conn);
	int rv;
	int err;

	if (datalen &&
	    SSL_provide_quic_data(
		    ssl, ngtcp2_to_libssl_encrypt_level_lut[encryption_level],
		    data, datalen) != 1)
	{
		return -1;
	}

	if (!ngtcp2_conn_get_handshake_completed2(conn)) {
		rv = SSL_do_handshake(ssl);
		if (rv <= 0) {
			err = SSL_get_error(ssl, rv);
			switch (err) {
			case SSL_ERROR_WANT_READ:
			case SSL_ERROR_WANT_WRITE:
				return 0;
			case SSL_ERROR_WANT_CLIENT_HELLO_CB:
				return -10002;
			case SSL_ERROR_WANT_X509_LOOKUP:
				return -10001;
			case SSL_ERROR_SSL:
				return -1;
			default:
				return -1;
			}
		}

		ngtcp2_conn_tls_handshake_completed(conn);
	}

	rv = SSL_process_quic_post_handshake(ssl);
	if (rv != 1) {
		err = SSL_get_error(ssl, rv);
		switch (err) {
		case SSL_ERROR_WANT_READ:
		case SSL_ERROR_WANT_WRITE:
			return 0;
		case SSL_ERROR_SSL:
		case SSL_ERROR_ZERO_RETURN:
			return -1;
		default:
			return -1;
		}
	}

	return 0;
}

#else

static int
crypto_read_write_crypto_data(ngtcp2_conn *conn,
			      ngtcp2_encryption_level encryption_level,
			      const uint8_t *data, size_t datalen) {
	SSL *ssl = ngtcp2_conn_get_tls_native_handle2(conn);
	int rv;
	int err;

	if (datalen &&
	    SSL_provide_quic_data(
		    ssl, ngtcp2_to_libssl_encrypt_level_lut[encryption_level],
		    data, datalen) != 1)
	{
		return -1;
	}

	if (!ngtcp2_conn_get_handshake_completed2(conn)) {
	retry:
		rv = SSL_do_handshake(ssl);
		if (rv <= 0) {
			err = SSL_get_error(ssl, rv);
			switch (err) {
			case SSL_ERROR_WANT_READ:
			case SSL_ERROR_WANT_WRITE:
				return 0;
			case SSL_ERROR_SSL:
				return -1;
			case SSL_ERROR_EARLY_DATA_REJECTED:
				assert(!ngtcp2_conn_is_server2(conn));

				SSL_reset_early_data_reject(ssl);

				rv = ngtcp2_conn_tls_early_data_rejected(conn);
				if (rv != 0) {
					return -1;
				}

				goto retry;
			case SSL_ERROR_WANT_X509_LOOKUP:
			case SSL_ERROR_WANT_PRIVATE_KEY_OPERATION:
			case SSL_ERROR_WANT_CERTIFICATE_VERIFY:
				/* It might be better to return this error, but
				   ngtcp2 does not need to know whether
				   handshake has been interrupted or not.  We
				   expect that necessary plumbing should be done
				   by application when handshake is interrupted
				   (e.g., via SSL_PRIVATE_KEY_METHOD).  If it
				   does not work, we will reconsider this. */
				return 0;
			default:
				return -1;
			}
		}

		if (SSL_in_early_data(ssl)) {
			return 0;
		}

		ngtcp2_conn_tls_handshake_completed(conn);
	}

	rv = SSL_process_quic_post_handshake(ssl);
	if (rv != 1) {
		err = SSL_get_error(ssl, rv);
		switch (err) {
		case SSL_ERROR_WANT_READ:
		case SSL_ERROR_WANT_WRITE:
			return 0;
		case SSL_ERROR_SSL:
		case SSL_ERROR_ZERO_RETURN:
			return -1;
		default:
			return -1;
		}
	}

	return 0;
}

#endif

int
isc__quic_client_initial_cb(ngtcp2_conn *ngconn,
			    void *user_data ISC_ATTR_UNUSED) {
	const ngtcp2_cid *dcid;
	isc_tls_t *tls;
	uint8_t buf[512];
	uint32_t version;
	ssize_t len;

#if NGTCP2_VERSION_NUM >= 0x011700
	dcid = ngtcp2_conn_get_dcid2(ngconn);
	tls = ngtcp2_conn_get_tls_native_handle2(ngconn);
	version = ngtcp2_conn_get_client_chosen_version2(ngconn);
#else
	dcid = ngtcp2_conn_get_dcid(ngconn);
	tls = ngtcp2_conn_get_tls_native_handle(ngconn);
	version = ngtcp2_conn_get_client_chosen_version(ngconn);
#endif

	initial_key(ngconn, dcid, version);

	len = ngtcp2_conn_encode_local_transport_params(ngconn, buf,
							sizeof(buf));
	INSIST(len >= 0);

	if (SSL_set_quic_transport_params(tls, buf, len) != 1) {
		return NGTCP2_ERR_CALLBACK_FAILURE;
	}

	crypto_read_write_crypto_data(ngconn, NGTCP2_ENCRYPTION_LEVEL_INITIAL,
				      NULL, 0);

	return 0;
}

int
isc__quic_encrypt_cb(uint8_t *dest, const ngtcp2_crypto_aead *ngaead,
		     const ngtcp2_crypto_aead_ctx *ngaeadctx,
		     const uint8_t *plaintext, size_t plaintextlen,
		     const uint8_t *nonce, size_t noncelen, const uint8_t *aad,
		     size_t aadlen) {
	const EVP_AEAD_CTX *ctx = ngaeadctx->native_handle;
	const EVP_AEAD *aead = ngaead->native_handle;
	size_t len, max;

	max = plaintextlen + EVP_AEAD_max_overhead(aead);

	if (EVP_AEAD_CTX_seal(ctx, dest, &len, max, nonce, noncelen, plaintext,
			      plaintextlen, aad, aadlen) != 1)
	{
		return NGTCP2_ERR_CALLBACK_FAILURE;
	}

	return 0;
}

int
isc__quic_decrypt_cb(uint8_t *dest, const ngtcp2_crypto_aead *ngaead,
		     const ngtcp2_crypto_aead_ctx *ngaeadctx,
		     const uint8_t *ciphertext, size_t ciphertextlen,
		     const uint8_t *nonce, size_t noncelen, const uint8_t *aad,
		     size_t aadlen) {
	const EVP_AEAD_CTX *ctx = ngaeadctx->native_handle;
	const EVP_AEAD *aead = ngaead->native_handle;
	size_t len, max;

	max = ciphertextlen + EVP_AEAD_max_overhead(aead);

	if (EVP_AEAD_CTX_open(ctx, dest, &len, max, nonce, noncelen, ciphertext,
			      ciphertextlen, aad, aadlen) != 1)
	{
		return NGTCP2_ERR_CALLBACK_FAILURE;
	}

	return 0;
}
