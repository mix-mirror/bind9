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

#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <isc/buffer.h>
#include <isc/endian.h>
#include <isc/ngtcp2_crypto.h>
#include <isc/random.h>

#include "quic_crypto.h"

/* define to see ngtcp2 crypto related tracing information */
#undef NGTCP2_CRYPTO_TRACE

#ifdef NGTCP2_CRYPTO_TRACE

#if defined(__linux__)
#include <syscall.h>
#define gettid() (uint32_t)syscall(SYS_gettid)
#else
#define gettid() (uint32_t)pthread_self()
#endif

#define NGTCP2_CRYPTO_LOG(format, ...)                                        \
	fprintf(stderr, "%" PRIu32 ":%s:%u:%s():" format, gettid(), __FILE__, \
		__LINE__, __func__, __VA_ARGS__)
#else
#define NGTCP2_CRYPTO_LOG(format, ...)
#endif

#define NGTCP2_TRACE_CB() NGTCP2_CRYPTO_LOG("%s", "\n")

/*
 * The code in this file mostly modelled after (or, in many cases,
 * adapted from) the portable part of the original ngtcp2 crypto
 * library. Though, there are many changes, additions,
 * simplifications, hardenings, magic constants removal, etc, the
 * overall structure remains very similar to simplify adopting changes
 * from the original ngtcp2 crypto library as QUIC and TLS evolve.
 */

#define LOCAL_TRANSPORT_PARAMS_MAX_SZ (UINT8_MAX)

#define RETRY_TOKEN_INFO_PREFIX	    "retry_token"
#define RETRY_TOKEN_INFO_PREFIX_LEN (sizeof(RETRY_TOKEN_INFO_PREFIX))
#define RETRY_TOKEN_AAD_LEN \
	(sizeof(uint32_t) + sizeof(ngtcp2_sockaddr_union) + NGTCP2_MAX_CIDLEN)
#define RETRY_TOKEN_PLAINTEXT_LEN                              \
	(/* cid len = */ sizeof(uint8_t) + NGTCP2_MAX_CIDLEN + \
	 sizeof(ngtcp2_tstamp))

#define REGULAR_TOKEN_INFO_PREFIX     "regular_token"
#define REGULAR_TOKEN_INFO_PREFIX_LEN (sizeof(REGULAR_TOKEN_INFO_PREFIX))

static inline void
ngtcp2_crypto_aead_init(ngtcp2_crypto_aead *restrict aead,
			const EVP_CIPHER *aead_native_handle);

static inline void
ngtcp2_crypto_aead_aes_128_gcm_init(ngtcp2_crypto_aead *restrict aead);

static inline void
ngtcp2_crypto_md_init(ngtcp2_crypto_md *restrict md,
		      const EVP_MD *md_native_handle);

static inline void
ngtcp2_crypto_md_sha256_init(ngtcp2_crypto_md *restrict md);

static inline void
ngtcp2_crypto_hp_cipher_init(ngtcp2_crypto_cipher *restrict hp,
			     const EVP_CIPHER *hp_cipher_handle);

static inline void
ngtcp2_crypto_aead_retry_init(ngtcp2_crypto_aead *restrict aead);

static inline void
ngtcp2_crypto_ctx_initial_init(ngtcp2_crypto_ctx *restrict ctx);

static inline bool
ngtcp2_crypto_ctx_tls_init(ngtcp2_crypto_ctx *restrict ctx,
			   const isc_tls_t *tls);

static inline bool
ngtcp2_crypto_aead_ctx_encrypt_init(ngtcp2_crypto_aead_ctx *restrict aead_ctx,
				    const ngtcp2_crypto_aead *restrict aead,
				    const uint8_t *key, const size_t noncelen);

static inline bool
ngtcp2_crypto_aead_ctx_decrypt_init(ngtcp2_crypto_aead_ctx *restrict aead_ctx,
				    const ngtcp2_crypto_aead *restrict aead,
				    const uint8_t *key, const size_t noncelen);

static inline void
ngtcp2_crypto_aead_ctx_free(ngtcp2_crypto_aead_ctx *restrict aead_ctx);

static inline bool
ngtcp2_crypto_cipher_ctx_encrypt_init(
	ngtcp2_crypto_cipher_ctx *restrict cipher_ctx,
	const ngtcp2_crypto_cipher *restrict cipher, const uint8_t *key);

static inline void
ngtcp2_crypto_cipher_ctx_free(ngtcp2_crypto_cipher_ctx *restrict cipher_ctx);

static bool
ngtcp2_crypto_derive_initial_secrets(uint8_t *rx_secret, uint8_t *tx_secret,
				     uint8_t *initial_secret,
				     const uint32_t version,
				     const ngtcp2_cid *client_dcid,
				     const bool is_server);

static bool
ngtcp2_crypto_derive_packet_protection_key(
	uint8_t *key, uint8_t *iv, uint8_t *hp_key, const uint32_t version,
	const ngtcp2_crypto_aead *aead, const ngtcp2_crypto_md *md,
	const uint8_t *secret, const size_t secretlen);

static bool
ngtcp2_crypto_derive_and_install_rx_key(ngtcp2_conn *conn, uint8_t *key,
					uint8_t *iv, uint8_t *hp_key,
					const ngtcp2_encryption_level level,
					const uint8_t *secret,
					const size_t secretlen);

static bool
ngtcp2_crypto_derive_and_install_tx_key(ngtcp2_conn *conn, uint8_t *key,
					uint8_t *iv, uint8_t *hp_key,
					const ngtcp2_encryption_level level,
					const uint8_t *secret,
					const size_t secretlen);

static bool
ngtcp2_crypto_derive_and_install_initial_key(ngtcp2_conn *conn,
					     const uint32_t version,
					     const ngtcp2_cid *client_dcid);

static bool
ngtcp2_crypto_derive_and_install_vneg_initial_key(ngtcp2_conn *conn,
						  const uint32_t version,
						  const ngtcp2_cid *client_dcid);

static bool
ngtcp2_crypto_update_traffic_secret(uint8_t *dest, uint32_t version,
				    const ngtcp2_crypto_md *md,
				    const uint8_t *secret,
				    const size_t secretlen);

static bool
ngtcp2_crypto_update_key(ngtcp2_conn *conn, uint8_t *rx_secret,
			 uint8_t *tx_secret,
			 ngtcp2_crypto_aead_ctx *rx_aead_ctx, uint8_t *rx_key,
			 uint8_t *rx_iv, ngtcp2_crypto_aead_ctx *tx_aead_ctx,
			 uint8_t *tx_key, uint8_t *tx_iv,
			 const uint8_t *current_rx_secret,
			 const uint8_t *current_tx_secret,
			 const size_t secretlen);

static bool
ngtcp2_crypto_process_data(ngtcp2_conn *conn,
			   const ngtcp2_encryption_level encryption_level,
			   const uint8_t *data, const size_t datalen);

static inline bool
ngtcp2_crypto_get_peer_transport_params_from_tls(ngtcp2_conn *conn);

static inline bool
ngtcp2_crypto_set_local_transport_params_to_tls(ngtcp2_conn *conn);

static inline ngtcp2_encryption_level
ngtcp2_crypto_convert_isc_encryption_level(
	const isc_quic_encryption_level_t level);

static inline isc_quic_encryption_level_t
ngtcp2_crypto_convert_ngtcp2_encryption_level(
	const ngtcp2_encryption_level level);

/* QUIC method callbacks */
static bool
ngtcp2_quic_method_set_read_secret(
	isc_tls_t *tls, const isc_quic_encryption_level_t isc_enc_level,
	const isc_tls_cipher_t *cipher, const uint8_t *secret,
	const size_t secret_len);

static bool
ngtcp2_quic_method_set_write_secret(
	isc_tls_t *tls, const isc_quic_encryption_level_t isc_enc_level,
	const isc_tls_cipher_t *cipher, const uint8_t *secret,
	const size_t secret_len);

static bool
ngtcp2_quic_method_send_alert(isc_tls_t *tls,
			      const isc_quic_encryption_level_t level,
			      const uint8_t alert);

static bool
ngtcp2_quic_method_add_handshake_data(isc_tls_t *tls,
				      const isc_quic_encryption_level_t level,
				      const uint8_t *data, const size_t len);

/* ngtcp2 integration callbacks */

static int
ngtcp2_crypto_client_initial_cb(ngtcp2_conn *conn, void *user_data);

static int
ngtcp2_crypto_version_negotiation_cb(ngtcp2_conn *conn, uint32_t version,
				     const ngtcp2_cid *client_dcid,
				     void *user_data);

static int
ngtcp2_crypto_recv_retry_cb(ngtcp2_conn *conn, const ngtcp2_pkt_hd *hd,
			    void *user_data);

static int
ngtcp2_crypto_recv_client_initial_cb(ngtcp2_conn *conn, const ngtcp2_cid *dcid,
				     void *user_data);

static int
ngtcp2_crypto_encrypt_cb(uint8_t *dest, const ngtcp2_crypto_aead *aead,
			 const ngtcp2_crypto_aead_ctx *aead_ctx,
			 const uint8_t *plaintext, size_t plaintextlen,
			 const uint8_t *nonce, size_t noncelen,
			 const uint8_t *aad, size_t aadlen);

static int
ngtcp2_crypto_decrypt_cb(uint8_t *dest, const ngtcp2_crypto_aead *aead,
			 const ngtcp2_crypto_aead_ctx *aead_ctx,
			 const uint8_t *ciphertext, size_t ciphertextlen,
			 const uint8_t *nonce, size_t noncelen,
			 const uint8_t *aad, size_t aadlen);

static int
ngtcp2_crypto_update_key_cb(ngtcp2_conn *conn, uint8_t *rx_secret,
			    uint8_t *tx_secret,
			    ngtcp2_crypto_aead_ctx *rx_aead_ctx, uint8_t *rx_iv,
			    ngtcp2_crypto_aead_ctx *tx_aead_ctx, uint8_t *tx_iv,
			    const uint8_t *current_rx_secret,
			    const uint8_t *current_tx_secret, size_t secretlen,
			    void *user_data);

static void
ngtcp2_crypto_delete_crypto_aead_ctx_cb(ngtcp2_conn *conn,
					ngtcp2_crypto_aead_ctx *aead_ctx,
					void *user_data);

static int
ngtcp2_crypto_hp_mask_cb(uint8_t *dest, const ngtcp2_crypto_cipher *hp,
			 const ngtcp2_crypto_cipher_ctx *hp_ctx,
			 const uint8_t *sample);

static void
ngtcp2_crypto_delete_crypto_cipher_ctx_cb(ngtcp2_conn *conn,
					  ngtcp2_crypto_cipher_ctx *cipher_ctx,
					  void *user_data);

static int
ngtcp2_crypto_recv_crypto_data_cb(ngtcp2_conn *conn,
				  ngtcp2_encryption_level encryption_level,
				  uint64_t offset, const uint8_t *data,
				  size_t datalen, void *user_data);

static void
ngtcp2_crypto_rand_cb(uint8_t *dest, size_t destlen,
		      const ngtcp2_rand_ctx *rand_ctx);

static int
ngtcp2_crypto_get_path_challenge_data_cb(ngtcp2_conn *conn, uint8_t *data,
					 void *user_data);

/* token-processing related functionality */

static bool
ngtcp2_crypto_derive_token_key(uint8_t *key, const size_t keylen, uint8_t *iv,
			       const size_t ivlen,
			       const ngtcp2_crypto_md *restrict md,
			       const uint8_t *secret, const size_t secretlen,
			       const uint8_t *salt, const size_t saltlen,
			       const uint8_t *info_prefix,
			       const size_t info_prefixlen);

static inline size_t
ngtcp2_crypto_generate_retry_token_aad(uint8_t *dest, const size_t destlen,
				       const uint32_t version,
				       const ngtcp2_sockaddr *sa,
				       const ngtcp2_socklen salen,
				       const ngtcp2_cid *restrict retry_scid);

static inline size_t
ngtcp2_crypto_generate_regular_token_aad(uint8_t *dest,
					 const ngtcp2_sockaddr *restrict sa);

/* ### */

static inline void
ngtcp2_crypto_aead_init(ngtcp2_crypto_aead *restrict aead,
			const EVP_CIPHER *aead_native_handle) {
	REQUIRE(aead != NULL);
	REQUIRE(aead_native_handle != NULL);

	*aead = (ngtcp2_crypto_aead){
		.native_handle = (void *)aead_native_handle,
		.max_overhead = isc__quic_crypto_aead_taglen(aead_native_handle)
	};
}

static inline void
ngtcp2_crypto_aead_aes_128_gcm_init(ngtcp2_crypto_aead *restrict aead) {
	ngtcp2_crypto_aead_init(aead,
				(void *)isc__quic_crypto_aead_aes_128_gcm());
}

static inline void
ngtcp2_crypto_md_init(ngtcp2_crypto_md *restrict md,
		      const EVP_MD *md_native_handle) {
	REQUIRE(md != NULL);
	REQUIRE(md_native_handle != NULL);

	*md = (ngtcp2_crypto_md){ .native_handle = (void *)md_native_handle };
}

static inline void
ngtcp2_crypto_md_sha256_init(ngtcp2_crypto_md *restrict md) {
	REQUIRE(md != NULL);

	*md = (ngtcp2_crypto_md){
		.native_handle = (void *)isc__quic_crypto_md_sha256()
	};
}

static inline void
ngtcp2_crypto_hp_cipher_init(ngtcp2_crypto_cipher *restrict hp,
			     const EVP_CIPHER *hp_cipher_handle) {
	REQUIRE(hp != NULL);
	REQUIRE(hp_cipher_handle != NULL);

	*hp = (ngtcp2_crypto_cipher){ .native_handle =
					      (void *)hp_cipher_handle };
}

static inline void
ngtcp2_crypto_aead_retry_init(ngtcp2_crypto_aead *restrict aead) {
	ngtcp2_crypto_aead_init(aead, isc__quic_crypto_aead_aes_128_gcm());
}

static inline void
ngtcp2_crypto_ctx_initial_init(ngtcp2_crypto_ctx *restrict ctx) {
	REQUIRE(ctx != NULL);

	*ctx = (ngtcp2_crypto_ctx){ 0 };

	ngtcp2_crypto_hp_cipher_init(&ctx->hp,
				     isc__quic_crypto_cipher_aes_128_ctr());
	ngtcp2_crypto_md_init(&ctx->md, isc__quic_crypto_md_sha256());
	ngtcp2_crypto_aead_init(&ctx->aead,
				isc__quic_crypto_aead_aes_128_gcm());
}

static inline bool
ngtcp2_crypto_ctx_tls_init(ngtcp2_crypto_ctx *restrict ctx,
			   const isc_tls_t *tls) {
	const isc_tls_cipher_t *cipher = NULL;

	REQUIRE(ctx != NULL);
	REQUIRE(tls != NULL);

	cipher = SSL_get_current_cipher(tls);

	if (cipher == NULL) {
		return false;
	}

	if (!isc__quic_crypto_tls_cipher_supported(cipher)) {
		return false;
	}

	*ctx = (ngtcp2_crypto_ctx){
		.max_encryption =
			isc__quic_crypto_tls_cipher_aead_max_encryption(cipher),
		.max_decryption_failure =
			isc__quic_crypto_tls_cipher_aead_max_decyption_failures(
				cipher)
	};

	ngtcp2_crypto_aead_init(&ctx->aead,
				isc__quic_crypto_tls_cipher_aead(cipher));
	ngtcp2_crypto_md_init(&ctx->md, isc__quic_crypto_tls_cipher_md(cipher));
	ngtcp2_crypto_hp_cipher_init(&ctx->hp,
				     isc__quic_crypto_tls_cipher_hp(cipher));

	return true;
}

static inline bool
ngtcp2_crypto_aead_ctx_encrypt_init(ngtcp2_crypto_aead_ctx *restrict aead_ctx,
				    const ngtcp2_crypto_aead *restrict aead,
				    const uint8_t *key, const size_t noncelen) {
	REQUIRE(aead_ctx != NULL);
	REQUIRE(aead != NULL);
	REQUIRE(key != NULL);

	EVP_CIPHER_CTX *actx = NULL;
	bool ret = isc__quic_crypto_aead_ctx_encrypt_create(
		&actx, aead->native_handle, key, noncelen);

	if (!ret) {
		return false;
	}

	*aead_ctx = (ngtcp2_crypto_aead_ctx){ .native_handle = (void *)actx };

	return true;
}

static inline bool
ngtcp2_crypto_aead_ctx_decrypt_init(ngtcp2_crypto_aead_ctx *restrict aead_ctx,
				    const ngtcp2_crypto_aead *restrict aead,
				    const uint8_t *key, const size_t noncelen) {
	REQUIRE(aead_ctx != NULL);
	REQUIRE(aead != NULL);
	REQUIRE(key != NULL);

	EVP_CIPHER_CTX *actx = NULL;
	bool ret = isc__quic_crypto_aead_ctx_decrypt_create(
		&actx, aead->native_handle, key, noncelen);

	if (!ret) {
		return false;
	}

	*aead_ctx = (ngtcp2_crypto_aead_ctx){ .native_handle = (void *)actx };

	return true;
}

static inline void
ngtcp2_crypto_aead_ctx_free(ngtcp2_crypto_aead_ctx *restrict aead_ctx) {
	REQUIRE(aead_ctx != NULL);

	if (aead_ctx->native_handle) {
		isc__quic_crypto_cipher_ctx_free(
			(EVP_CIPHER_CTX **)&aead_ctx->native_handle);
	}
}

static inline bool
ngtcp2_crypto_cipher_ctx_encrypt_init(
	ngtcp2_crypto_cipher_ctx *restrict cipher_ctx,
	const ngtcp2_crypto_cipher *restrict cipher, const uint8_t *key) {
	REQUIRE(cipher_ctx != NULL);
	REQUIRE(cipher != NULL);
	REQUIRE(key != NULL);

	EVP_CIPHER_CTX *hp_ctx = NULL;
	bool ret = isc__quic_crypto_hp_cipher_ctx_encrypt_create(
		&hp_ctx, cipher->native_handle, key);

	if (!ret) {
		return false;
	}

	*cipher_ctx =
		(ngtcp2_crypto_cipher_ctx){ .native_handle = (void *)hp_ctx };

	return true;
}

static inline void
ngtcp2_crypto_cipher_ctx_free(ngtcp2_crypto_cipher_ctx *restrict cipher_ctx) {
	REQUIRE(cipher_ctx != NULL);

	if (cipher_ctx->native_handle != NULL) {
		isc__quic_crypto_cipher_ctx_free(
			(EVP_CIPHER_CTX **)&cipher_ctx->native_handle);
	}
}

/* See RFC9001, Section 5.2 */
static bool
ngtcp2_crypto_derive_initial_secrets(uint8_t *rx_secret, uint8_t *tx_secret,
				     uint8_t *initial_secret,
				     const uint32_t version,
				     const ngtcp2_cid *client_dcid,
				     const bool is_server) {
	uint8_t initial_secret_buf[EVP_MAX_MD_SIZE];
	size_t initial_secret_len = 0;
	uint8_t *client_secret = NULL;
	uint8_t *server_secret = NULL;
	ngtcp2_crypto_ctx ctx;
	const uint8_t *salt = NULL;
	size_t saltlen = 0;

	REQUIRE(rx_secret != NULL);
	REQUIRE(client_dcid != NULL && client_dcid->data != NULL &&
		client_dcid->datalen > 0);

	if (!initial_secret) {
		initial_secret = initial_secret_buf;
	}

	ngtcp2_crypto_ctx_initial_init(&ctx);

	initial_secret_len = isc__quic_crypto_md_hashlen(ctx.md.native_handle);

	switch (version) {
	case NGTCP2_PROTO_VER_V2:
		salt = (const uint8_t *)ISC__QUIC_CRYPTO_INITIAL_SALT_V2;
		saltlen = ISC__QUIC_CRYPTO_INITIAL_SALT_V2_LEN;
		break;
	default:
		salt = (const uint8_t *)ISC__QUIC_CRYPTO_INITIAL_SALT_V1;
		saltlen = ISC__QUIC_CRYPTO_INITIAL_SALT_V1_LEN;
		break;
	}

	if (!isc__quic_crypto_hkdf_extract(initial_secret, ctx.md.native_handle,
					   client_dcid->data,
					   client_dcid->datalen, salt, saltlen))
	{
		return false;
	}

	if (is_server) {
		client_secret = rx_secret;
		server_secret = tx_secret;
	} else {
		client_secret = tx_secret;
		server_secret = rx_secret;
	}

	if (!isc__quic_crypto_hkdf_expand_label(
		    client_secret, initial_secret_len, ctx.md.native_handle,
		    initial_secret, initial_secret_len,
		    (const uint8_t *)ISC__QUIC_CRYPTO_CLIENT_IN_LABEL,
		    ISC__QUIC_CRYPTO_CLIENT_IN_LABEL_LEN) ||
	    !isc__quic_crypto_hkdf_expand_label(
		    server_secret, initial_secret_len, ctx.md.native_handle,
		    initial_secret, initial_secret_len,
		    (const uint8_t *)ISC__QUIC_CRYPTO_SERVER_IN_LABEL,
		    ISC__QUIC_CRYPTO_CLIENT_IN_LABEL_LEN))
	{
		return false;
	}

	return true;
}

/*
 * Derive packet protection and header protection keys.
 *
 * See RFC 9001, Sections:
 * 5.1. Packet Protection Keys
 * 5.4. Header Protection
 */
static bool
ngtcp2_crypto_derive_packet_protection_key(
	uint8_t *key, uint8_t *iv, uint8_t *hp_key, const uint32_t version,
	const ngtcp2_crypto_aead *aead, const ngtcp2_crypto_md *md,
	const uint8_t *secret, const size_t secretlen) {
	REQUIRE(key != NULL);
	REQUIRE(iv != NULL);
	REQUIRE(aead != NULL);
	REQUIRE(md != NULL);
	REQUIRE(secret != NULL);
	REQUIRE(secretlen > 0);

	const size_t keylen = isc__quic_crypto_aead_keylen(aead->native_handle);
	const size_t ivlen = isc__quic_crypto_aead_packet_protection_ivlen(
		aead->native_handle);
	const uint8_t *key_label = NULL;
	size_t key_labellen = 0;
	const uint8_t *iv_label = NULL;
	size_t iv_labellen = 0;
	const uint8_t *hp_key_label = NULL;
	size_t hp_key_labellen = 0;

	switch (version) {
	case NGTCP2_PROTO_VER_V2:
		key_label = (const uint8_t *)ISC__QUIC_CRYPTO_QUIC_KEY_LABEL_V2;
		key_labellen = ISC__QUIC_CRYPTO_QUIC_KEY_LABEL_V2_LEN;
		iv_label = (const uint8_t *)ISC__QUIC_CRYPTO_QUIC_IV_LABEL_V2;
		iv_labellen = ISC__QUIC_CRYPTO_QUIC_IV_LABEL_V2_LEN;
		hp_key_label =
			(const uint8_t *)ISC__QUIC_CRYPTO_QUIC_HP_LABEL_V2;
		hp_key_labellen = ISC__QUIC_CRYPTO_QUIC_HP_LABEL_V2_LEN;
		break;
	default:
		key_label = (const uint8_t *)ISC__QUIC_CRYPTO_QUIC_KEY_LABEL_V1;
		key_labellen = ISC__QUIC_CRYPTO_QUIC_KEY_LABEL_V1_LEN;
		iv_label = (const uint8_t *)ISC__QUIC_CRYPTO_QUIC_IV_LABEL_V1;
		iv_labellen = ISC__QUIC_CRYPTO_QUIC_IV_LABEL_V1_LEN;
		hp_key_label =
			(const uint8_t *)ISC__QUIC_CRYPTO_QUIC_HP_LABEL_V1;
		hp_key_labellen = ISC__QUIC_CRYPTO_QUIC_HP_LABEL_V1_LEN;
		break;
	}

	if (!isc__quic_crypto_hkdf_expand_label(key, keylen, md->native_handle,
						secret, secretlen, key_label,
						key_labellen))
	{
		return false;
	}

	if (!isc__quic_crypto_hkdf_expand_label(iv, ivlen, md->native_handle,
						secret, secretlen, iv_label,
						iv_labellen))
	{
		return false;
	}

	if (hp_key != NULL && !isc__quic_crypto_hkdf_expand_label(
				      hp_key, keylen, md->native_handle, secret,
				      secretlen, hp_key_label, hp_key_labellen))
	{
		return false;
	}

	return true;
}

static bool
ngtcp2_crypto_derive_and_install_rx_key(ngtcp2_conn *conn, uint8_t *key,
					uint8_t *iv, uint8_t *hp_key,
					const ngtcp2_encryption_level level,
					const uint8_t *secret,
					const size_t secretlen) {
	REQUIRE(conn != NULL);
	REQUIRE(secret != NULL);
	REQUIRE(secretlen > 0);

	const ngtcp2_crypto_ctx *ctx = NULL;
	const ngtcp2_crypto_aead *aead = NULL;
	const ngtcp2_crypto_md *md = NULL;
	const ngtcp2_crypto_cipher *hp = NULL;
	ngtcp2_crypto_aead_ctx aead_ctx = { 0 };
	ngtcp2_crypto_cipher_ctx hp_ctx = { 0 };
	isc_tls_t *tls = (isc_tls_t *)ngtcp2_conn_get_tls_native_handle(conn);
	uint8_t keybuf[EVP_MAX_KEY_LENGTH], ivbuf[EVP_MAX_IV_LENGTH],
		hp_keybuf[EVP_MAX_KEY_LENGTH];
	size_t ivlen = 0;
	int rv = 0;
	ngtcp2_crypto_ctx cctx = { 0 };
	uint32_t version = 0;

	INSIST(tls != NULL);

	if (level == NGTCP2_ENCRYPTION_LEVEL_0RTT &&
	    !ngtcp2_conn_is_server(conn))
	{
		return true;
	}

	if (!key) {
		key = keybuf;
	}
	if (!iv) {
		iv = ivbuf;
	}
	if (!hp_key) {
		hp_key = hp_keybuf;
	}

	switch (level) {
	case NGTCP2_ENCRYPTION_LEVEL_0RTT:
		if (!ngtcp2_crypto_ctx_tls_init(&cctx, tls)) {
			return false;
		}

		ngtcp2_conn_set_0rtt_crypto_ctx(conn, &cctx);
		ctx = ngtcp2_conn_get_0rtt_crypto_ctx(conn);
		version = ngtcp2_conn_get_client_chosen_version(conn);
		break;
	case NGTCP2_ENCRYPTION_LEVEL_HANDSHAKE:
		if (ngtcp2_conn_is_server(conn) &&
		    !ngtcp2_conn_get_negotiated_version(conn))
		{
			if (!ngtcp2_crypto_get_peer_transport_params_from_tls(
				    conn))
			{
				return false;
			}
		}
		FALLTHROUGH;
	case NGTCP2_ENCRYPTION_LEVEL_1RTT:
		ctx = ngtcp2_conn_get_crypto_ctx(conn);
		version = ngtcp2_conn_get_negotiated_version(conn);

		if (!ctx->aead.native_handle) {
			if (!ngtcp2_crypto_ctx_tls_init(&cctx, tls)) {
				return false;
			}

			ngtcp2_conn_set_crypto_ctx(conn, &cctx);
			ctx = ngtcp2_conn_get_crypto_ctx(conn);
		}
		break;
	default:
		return false;
	}

	aead = &ctx->aead;
	md = &ctx->md;
	hp = &ctx->hp;
	ivlen = isc__quic_crypto_aead_packet_protection_ivlen(
		aead->native_handle);

	if (!ngtcp2_crypto_derive_packet_protection_key(
		    key, iv, hp_key, version, aead, md, secret, secretlen))
	{
		return false;
	}

	if (!ngtcp2_crypto_aead_ctx_decrypt_init(&aead_ctx, aead, key, ivlen)) {
		goto fail;
	}

	if (!ngtcp2_crypto_cipher_ctx_encrypt_init(&hp_ctx, hp, hp_key)) {
		goto fail;
	}

	switch (level) {
	case NGTCP2_ENCRYPTION_LEVEL_0RTT:
		rv = ngtcp2_conn_install_0rtt_key(conn, &aead_ctx, iv, ivlen,
						  &hp_ctx);
		if (rv != 0) {
			goto fail;
		}
		break;
	case NGTCP2_ENCRYPTION_LEVEL_HANDSHAKE:
		rv = ngtcp2_conn_install_rx_handshake_key(conn, &aead_ctx, iv,
							  ivlen, &hp_ctx);
		if (rv != 0) {
			goto fail;
		}
		break;
	case NGTCP2_ENCRYPTION_LEVEL_1RTT:
		if (!ngtcp2_conn_is_server(conn)) {
			if (!ngtcp2_crypto_get_peer_transport_params_from_tls(
				    conn))
			{
				goto fail;
			}
		}

		rv = ngtcp2_conn_install_rx_key(conn, secret, secretlen,
						&aead_ctx, iv, ivlen, &hp_ctx);
		if (rv != 0) {
			goto fail;
		}

		break;
	default:
		goto fail;
	}

	return true;

fail:
	ngtcp2_crypto_cipher_ctx_free(&hp_ctx);
	ngtcp2_crypto_aead_ctx_free(&aead_ctx);

	return false;
}

static bool
ngtcp2_crypto_derive_and_install_tx_key(ngtcp2_conn *conn, uint8_t *key,
					uint8_t *iv, uint8_t *hp_key,
					const ngtcp2_encryption_level level,
					const uint8_t *secret,
					const size_t secretlen) {
	REQUIRE(conn != NULL);
	REQUIRE(secret != NULL);
	REQUIRE(secretlen > 0);

	const ngtcp2_crypto_ctx *ctx = NULL;
	const ngtcp2_crypto_aead *aead = NULL;
	const ngtcp2_crypto_md *md = NULL;
	const ngtcp2_crypto_cipher *hp = NULL;
	ngtcp2_crypto_aead_ctx aead_ctx = { 0 };
	ngtcp2_crypto_cipher_ctx hp_ctx = { 0 };
	isc_tls_t *tls = (isc_tls_t *)ngtcp2_conn_get_tls_native_handle(conn);
	uint8_t keybuf[EVP_MAX_KEY_LENGTH], ivbuf[EVP_MAX_IV_LENGTH],
		hp_keybuf[EVP_MAX_KEY_LENGTH];
	size_t ivlen = 0;
	int rv = 0;
	ngtcp2_crypto_ctx cctx = { 0 };
	uint32_t version = 0;

	INSIST(tls != NULL);

	if (level == NGTCP2_ENCRYPTION_LEVEL_0RTT &&
	    ngtcp2_conn_is_server(conn))
	{
		return true;
	}

	if (!key) {
		key = keybuf;
	}
	if (!iv) {
		iv = ivbuf;
	}
	if (!hp_key) {
		hp_key = hp_keybuf;
	}

	switch (level) {
	case NGTCP2_ENCRYPTION_LEVEL_0RTT:
		if (!ngtcp2_crypto_ctx_tls_init(&cctx, tls)) {
			return false;
		}

		ngtcp2_conn_set_0rtt_crypto_ctx(conn, &cctx);
		ctx = ngtcp2_conn_get_0rtt_crypto_ctx(conn);
		version = ngtcp2_conn_get_client_chosen_version(conn);
		break;
	case NGTCP2_ENCRYPTION_LEVEL_HANDSHAKE:
		if (ngtcp2_conn_is_server(conn) &&
		    !ngtcp2_conn_get_negotiated_version(conn))
		{
			if (!ngtcp2_crypto_get_peer_transport_params_from_tls(
				    conn))
			{
				return false;
			}
		}
		FALLTHROUGH;
	case NGTCP2_ENCRYPTION_LEVEL_1RTT:
		ctx = ngtcp2_conn_get_crypto_ctx(conn);
		version = ngtcp2_conn_get_negotiated_version(conn);

		if (!ctx->aead.native_handle) {
			if (!ngtcp2_crypto_ctx_tls_init(&cctx, tls)) {
				return false;
			}

			ngtcp2_conn_set_crypto_ctx(conn, &cctx);
			ctx = ngtcp2_conn_get_crypto_ctx(conn);
		}
		break;
	default:
		return false;
	}

	aead = &ctx->aead;
	md = &ctx->md;
	hp = &ctx->hp;
	ivlen = isc__quic_crypto_aead_packet_protection_ivlen(
		aead->native_handle);

	if (!ngtcp2_crypto_derive_packet_protection_key(
		    key, iv, hp_key, version, aead, md, secret, secretlen))
	{
		return false;
	}

	if (!ngtcp2_crypto_aead_ctx_encrypt_init(&aead_ctx, aead, key, ivlen)) {
		goto fail;
	}

	if (!ngtcp2_crypto_cipher_ctx_encrypt_init(&hp_ctx, hp, hp_key)) {
		goto fail;
	}

	switch (level) {
	case NGTCP2_ENCRYPTION_LEVEL_0RTT:
		rv = ngtcp2_conn_install_0rtt_key(conn, &aead_ctx, iv, ivlen,
						  &hp_ctx);
		if (rv != 0) {
			goto fail;
		}
		break;
	case NGTCP2_ENCRYPTION_LEVEL_HANDSHAKE:
		rv = ngtcp2_conn_install_tx_handshake_key(conn, &aead_ctx, iv,
							  ivlen, &hp_ctx);
		if (rv != 0) {
			goto fail;
		}

		if (ngtcp2_conn_is_server(conn) &&
		    !ngtcp2_crypto_set_local_transport_params_to_tls(conn))
		{
			goto fail;
		}

		break;
	case NGTCP2_ENCRYPTION_LEVEL_1RTT:
		rv = ngtcp2_conn_install_tx_key(conn, secret, secretlen,
						&aead_ctx, iv, ivlen, &hp_ctx);
		if (rv != 0) {
			goto fail;
		}

		break;
	default:
		goto fail;
	}

	return true;

fail:
	ngtcp2_crypto_cipher_ctx_free(&hp_ctx);
	ngtcp2_crypto_aead_ctx_free(&aead_ctx);

	return false;
}

/*
 * Derive and install initial protection and keying material for a
 * QUIC connection.
 */
static bool
ngtcp2_crypto_derive_and_install_initial_key(ngtcp2_conn *conn,
					     const uint32_t version,
					     const ngtcp2_cid *client_dcid) {
	uint8_t rx_secret[EVP_MAX_MD_SIZE];
	uint8_t tx_secret[EVP_MAX_MD_SIZE];
	uint8_t initial_secret[EVP_MAX_MD_SIZE];
	uint8_t rx_key[EVP_MAX_KEY_LENGTH];
	uint8_t rx_iv[EVP_MAX_IV_LENGTH];
	uint8_t rx_hp_key[EVP_MAX_KEY_LENGTH];
	uint8_t tx_key[EVP_MAX_KEY_LENGTH];
	uint8_t tx_iv[EVP_MAX_IV_LENGTH];
	uint8_t tx_hp_key[EVP_MAX_KEY_LENGTH];
	ngtcp2_crypto_ctx ctx = { 0 };
	ngtcp2_crypto_aead retry_aead = { 0 };
	ngtcp2_crypto_aead_ctx rx_aead_ctx = { 0 };
	ngtcp2_crypto_cipher_ctx rx_hp_ctx = { 0 };
	ngtcp2_crypto_aead_ctx tx_aead_ctx = { 0 };
	ngtcp2_crypto_cipher_ctx tx_hp_ctx = { 0 };
	ngtcp2_crypto_aead_ctx retry_aead_ctx = { 0 };
	bool is_server = false;
	const uint8_t *retry_key = NULL;
	int rv = 0;
	size_t retry_noncelen = 0;
	size_t secretlen = 0;
	size_t ivlen = 0;

	REQUIRE(conn != NULL);
	REQUIRE(client_dcid != NULL && client_dcid->data != NULL &&
		client_dcid->datalen > 0);

	is_server = (ngtcp2_conn_is_server(conn) != 0);

	ngtcp2_crypto_ctx_initial_init(&ctx);

	secretlen = isc__quic_crypto_md_hashlen(ctx.md.native_handle);
	ivlen = isc__quic_crypto_aead_ivlen(ctx.aead.native_handle);

	ngtcp2_conn_set_initial_crypto_ctx(conn, &ctx);

	if (!ngtcp2_crypto_derive_initial_secrets(rx_secret, tx_secret,
						  initial_secret, version,
						  client_dcid, is_server))
	{
		return false;
	}

	if (!ngtcp2_crypto_derive_packet_protection_key(
		    rx_key, rx_iv, rx_hp_key, version, &ctx.aead, &ctx.md,
		    rx_secret, secretlen))
	{
		return false;
	}

	if (!ngtcp2_crypto_derive_packet_protection_key(
		    tx_key, tx_iv, tx_hp_key, version, &ctx.aead, &ctx.md,
		    tx_secret, secretlen))
	{
		return false;
	}

	if (!ngtcp2_crypto_aead_ctx_decrypt_init(&rx_aead_ctx, &ctx.aead,
						 rx_key, ivlen))
	{
		goto fail;
	}

	if (!ngtcp2_crypto_cipher_ctx_encrypt_init(&rx_hp_ctx, &ctx.hp,
						   rx_hp_key))
	{
		goto fail;
	}

	if (!ngtcp2_crypto_aead_ctx_encrypt_init(&tx_aead_ctx, &ctx.aead,
						 tx_key, ivlen))
	{
		goto fail;
	}

	if (!ngtcp2_crypto_cipher_ctx_encrypt_init(&tx_hp_ctx, &ctx.hp,
						   tx_hp_key))
	{
		goto fail;
	}

	if (!is_server && !ngtcp2_conn_after_retry(conn)) {
		ngtcp2_crypto_aead_retry_init(&retry_aead);

		switch (version) {
		case NGTCP2_PROTO_VER_V2:
			retry_key = (const uint8_t *)NGTCP2_RETRY_KEY_V2;
			retry_noncelen = sizeof(NGTCP2_RETRY_NONCE_V2) - 1;
			break;
		default:
			retry_key = (const uint8_t *)NGTCP2_RETRY_KEY_V1;
			retry_noncelen = sizeof(NGTCP2_RETRY_NONCE_V1) - 1;
			break;
		}

		if (!ngtcp2_crypto_aead_ctx_encrypt_init(&retry_aead_ctx,
							 &retry_aead, retry_key,
							 retry_noncelen))
		{
			goto fail;
		}
	}

	rv = ngtcp2_conn_install_initial_key(conn, &rx_aead_ctx, rx_iv,
					     &rx_hp_ctx, &tx_aead_ctx, tx_iv,
					     &tx_hp_ctx, ivlen);
	if (rv != 0) {
		goto fail;
	}

	if (retry_aead_ctx.native_handle != NULL) {
		ngtcp2_conn_set_retry_aead(conn, &retry_aead, &retry_aead_ctx);
	}

	return true;

fail:
	ngtcp2_crypto_aead_ctx_free(&retry_aead_ctx);
	ngtcp2_crypto_cipher_ctx_free(&tx_hp_ctx);
	ngtcp2_crypto_aead_ctx_free(&tx_aead_ctx);
	ngtcp2_crypto_cipher_ctx_free(&rx_hp_ctx);
	ngtcp2_crypto_aead_ctx_free(&rx_aead_ctx);

	return false;
}

/*
 * Derive and install protection and keying material for a QUIC
 * connection in accordance to the negotiated QUIC version.
 */
static bool
ngtcp2_crypto_derive_and_install_vneg_initial_key(
	ngtcp2_conn *conn, const uint32_t version,
	const ngtcp2_cid *client_dcid) {
	REQUIRE(conn != NULL);
	REQUIRE(client_dcid != NULL && client_dcid->data != NULL &&
		client_dcid->datalen > 0);

	uint8_t rx_secret[EVP_MAX_MD_SIZE];
	uint8_t tx_secret[EVP_MAX_MD_SIZE];
	uint8_t initial_secret[EVP_MAX_MD_SIZE];
	uint8_t rx_key[EVP_MAX_KEY_LENGTH];
	uint8_t rx_iv[EVP_MAX_IV_LENGTH];
	uint8_t rx_hp_key[EVP_MAX_KEY_LENGTH];
	uint8_t tx_key[EVP_MAX_KEY_LENGTH];
	uint8_t tx_iv[EVP_MAX_IV_LENGTH];
	uint8_t tx_hp_key[EVP_MAX_IV_LENGTH];
	const ngtcp2_crypto_ctx *ctx = ngtcp2_conn_get_initial_crypto_ctx(conn);
	ngtcp2_crypto_aead_ctx rx_aead_ctx = { 0 };
	ngtcp2_crypto_cipher_ctx rx_hp_ctx = { 0 };
	ngtcp2_crypto_aead_ctx tx_aead_ctx = { 0 };
	ngtcp2_crypto_cipher_ctx tx_hp_ctx = { 0 };
	int rv = 0;
	const bool is_server = ngtcp2_conn_is_server(conn) != 0;
	const size_t initial_secretlen =
		isc__quic_crypto_md_hashlen(ctx->md.native_handle);
	const size_t initial_ivlen =
		isc__quic_crypto_aead_ivlen(ctx->aead.native_handle);

	if (!ngtcp2_crypto_derive_initial_secrets(rx_secret, tx_secret,
						  initial_secret, version,
						  client_dcid, is_server))
	{
		return false;
	}

	if (!ngtcp2_crypto_derive_packet_protection_key(
		    rx_key, rx_iv, rx_hp_key, version, &ctx->aead, &ctx->md,
		    rx_secret, initial_secretlen))
	{
		return false;
	}

	if (!ngtcp2_crypto_derive_packet_protection_key(
		    tx_key, tx_iv, tx_hp_key, version, &ctx->aead, &ctx->md,
		    tx_secret, initial_secretlen))
	{
		return false;
	}

	if (!ngtcp2_crypto_aead_ctx_decrypt_init(&rx_aead_ctx, &ctx->aead,
						 rx_key, initial_ivlen))
	{
		goto fail;
	}

	if (!ngtcp2_crypto_cipher_ctx_encrypt_init(&rx_hp_ctx, &ctx->hp,
						   rx_hp_key))
	{
		goto fail;
	}

	if (!ngtcp2_crypto_aead_ctx_encrypt_init(&tx_aead_ctx, &ctx->aead,
						 tx_key, initial_ivlen))
	{
		goto fail;
	}

	if (!ngtcp2_crypto_cipher_ctx_encrypt_init(&tx_hp_ctx, &ctx->hp,
						   tx_hp_key))
	{
		goto fail;
	}

	rv = ngtcp2_conn_install_vneg_initial_key(
		conn, version, &rx_aead_ctx, rx_iv, &rx_hp_ctx, &tx_aead_ctx,
		tx_iv, &tx_hp_ctx, initial_ivlen);
	if (rv != 0) {
		goto fail;
	}

	return true;

fail:
	ngtcp2_crypto_cipher_ctx_free(&tx_hp_ctx);
	ngtcp2_crypto_aead_ctx_free(&tx_aead_ctx);
	ngtcp2_crypto_cipher_ctx_free(&rx_hp_ctx);
	ngtcp2_crypto_aead_ctx_free(&rx_aead_ctx);

	return false;
}

/*
 * Derives the next generation  of the traffic secret.
 *
 * See RFC 9001, Section  6.1. Initiating a Key Update
 */
static bool
ngtcp2_crypto_update_traffic_secret(uint8_t *dest, uint32_t version,
				    const ngtcp2_crypto_md *md,
				    const uint8_t *secret,
				    const size_t secretlen) {
	const uint8_t *label = NULL;
	size_t labellen = 0;

	REQUIRE(dest != NULL);
	REQUIRE(md != NULL);
	REQUIRE(secret != NULL);
	REQUIRE(secretlen > 0);

	switch (version) {
	case NGTCP2_PROTO_VER_V2:
		label = (const uint8_t *)ISC__QUIC_CRYPTO_QUIC_KU_LABEL_V2;
		labellen = ISC__QUIC_CRYPTO_QUIC_KU_LABEL_V2_LEN;
		break;
	default:
		label = (const uint8_t *)ISC__QUIC_CRYPTO_QUIC_KU_LABEL_V1;
		labellen = ISC__QUIC_CRYPTO_QUIC_KU_LABEL_V1_LEN;
		break;
	}

	return isc__quic_crypto_hkdf_expand_label(dest, secretlen,
						  md->native_handle, secret,
						  secretlen, label, labellen);
}

static bool
ngtcp2_crypto_update_key(ngtcp2_conn *conn, uint8_t *rx_secret,
			 uint8_t *tx_secret,
			 ngtcp2_crypto_aead_ctx *rx_aead_ctx, uint8_t *rx_key,
			 uint8_t *rx_iv, ngtcp2_crypto_aead_ctx *tx_aead_ctx,
			 uint8_t *tx_key, uint8_t *tx_iv,
			 const uint8_t *current_rx_secret,
			 const uint8_t *current_tx_secret,
			 const size_t secretlen) {
	REQUIRE(conn != NULL);
	REQUIRE(tx_secret != NULL);
	REQUIRE(rx_secret != NULL);
	REQUIRE(rx_aead_ctx != NULL);
	REQUIRE(rx_key != NULL);
	REQUIRE(rx_iv != NULL);
	REQUIRE(tx_key != NULL);
	REQUIRE(tx_iv != NULL);
	REQUIRE(current_rx_secret != NULL);
	REQUIRE(current_tx_secret != NULL);
	REQUIRE(secretlen > 0);

	const ngtcp2_crypto_ctx *ctx = ngtcp2_conn_get_crypto_ctx(conn);
	const ngtcp2_crypto_aead *aead = &ctx->aead;
	const ngtcp2_crypto_md *md = &ctx->md;
	const size_t ivlen = isc__quic_crypto_aead_packet_protection_ivlen(
		aead->native_handle);
	const uint32_t version = ngtcp2_conn_get_negotiated_version(conn);

	if (!ngtcp2_crypto_update_traffic_secret(rx_secret, version, md,
						 current_rx_secret, secretlen))
	{
		return false;
	}

	if (!ngtcp2_crypto_derive_packet_protection_key(rx_key, rx_iv, NULL,
							version, aead, md,
							rx_secret, secretlen))
	{
		return false;
	}

	if (!ngtcp2_crypto_update_traffic_secret(tx_secret, version, md,
						 current_tx_secret, secretlen))
	{
		return false;
	}

	if (!ngtcp2_crypto_derive_packet_protection_key(tx_key, tx_iv, NULL,
							version, aead, md,
							tx_secret, secretlen))
	{
		return false;
	}

	if (!ngtcp2_crypto_aead_ctx_decrypt_init(rx_aead_ctx, aead, rx_key,
						 ivlen))
	{
		return false;
	}

	if (!ngtcp2_crypto_aead_ctx_encrypt_init(tx_aead_ctx, aead, tx_key,
						 ivlen))
	{
		ngtcp2_crypto_aead_ctx_free(rx_aead_ctx);
		return false;
	}

	return true;
}

static inline bool
process_tls_return_value(const isc_tls_t *tls, const int rv) {
	int err = 0;
	err = SSL_get_error(tls, rv);
	switch (err) {
	case SSL_ERROR_WANT_READ:
	case SSL_ERROR_WANT_WRITE:
		return true;
	default:
		return false;
	}

	return true;
}

static bool
ngtcp2_crypto_process_data(ngtcp2_conn *conn,
			   const ngtcp2_encryption_level encryption_level,
			   const uint8_t *data, const size_t datalen) {
	REQUIRE(conn != NULL);

	isc_tls_t *tls = ngtcp2_conn_get_tls_native_handle(conn);
	int rv = 0;
	isc_result_t result = ISC_R_FAILURE;
	const isc_quic_encryption_level_t level =
		ngtcp2_crypto_convert_ngtcp2_encryption_level(encryption_level);

	INSIST(tls != NULL);

	result = isc_tls_provide_quic_data(tls, level, data, datalen);
	if (result != ISC_R_SUCCESS) {
		return false;
	}

	if (!ngtcp2_conn_get_handshake_completed(conn)) {
		rv = isc_tls_do_quic_handshake(tls);

		if (rv <= 0) {
			return process_tls_return_value(tls, rv);
		}

		ngtcp2_conn_tls_handshake_completed(conn);
	}

	rv = isc_tls_process_quic_post_handshake(tls);
	if (rv != 1) {
		return process_tls_return_value(tls, rv);
	}

	return true;
}

static inline bool
ngtcp2_crypto_get_peer_transport_params_from_tls(ngtcp2_conn *conn) {
	REQUIRE(conn != NULL);

	isc_tls_t *tls = (isc_tls_t *)ngtcp2_conn_get_tls_native_handle(conn);
	const uint8_t *tp = NULL;
	size_t tplen = 0;
	int rv = 0;

	INSIST(tls != NULL);

	isc_tls_get_peer_quic_transport_params(tls, &tp, &tplen);

	rv = ngtcp2_conn_decode_and_set_remote_transport_params(conn, tp,
								tplen);
	if (rv != 0) {
		ngtcp2_conn_set_tls_error(conn, rv);
		return false;
	}

	return true;
}

static inline bool
ngtcp2_crypto_set_local_transport_params_to_tls(ngtcp2_conn *conn) {
	REQUIRE(conn != NULL);

	isc_tls_t *tls = (isc_tls_t *)ngtcp2_conn_get_tls_native_handle(conn);
	isc_result_t result = ISC_R_FAILURE;
	uint8_t buf[LOCAL_TRANSPORT_PARAMS_MAX_SZ];
	ngtcp2_ssize nwrite = 0;

	INSIST(tls != NULL);

	nwrite = ngtcp2_conn_encode_local_transport_params(conn, buf,
							   sizeof(buf));
	if (nwrite < 0) {
		return false;
	}

	result = isc_tls_set_quic_transport_params(tls, buf, (size_t)nwrite);
	if (result != ISC_R_SUCCESS) {
		return false;
	}

	return true;
}

static inline ngtcp2_encryption_level
ngtcp2_crypto_convert_isc_encryption_level(
	const isc_quic_encryption_level_t level) {
	switch (level) {
	case ISC_QUIC_ENCRYPTION_INITIAL:
		return NGTCP2_ENCRYPTION_LEVEL_INITIAL;
	case ISC_QUIC_ENCRYPTION_EARLY_DATA:
		return NGTCP2_ENCRYPTION_LEVEL_0RTT;
	case ISC_QUIC_ENCRYPTION_HANDSHAKE:
		return NGTCP2_ENCRYPTION_LEVEL_HANDSHAKE;
	case ISC_QUIC_ENCRYPTION_APPLICATION:
		return NGTCP2_ENCRYPTION_LEVEL_1RTT;
	}

	UNREACHABLE();
}

static inline isc_quic_encryption_level_t
ngtcp2_crypto_convert_ngtcp2_encryption_level(
	const ngtcp2_encryption_level level) {
	switch (level) {
	case NGTCP2_ENCRYPTION_LEVEL_INITIAL:
		return ISC_QUIC_ENCRYPTION_INITIAL;
	case NGTCP2_ENCRYPTION_LEVEL_0RTT:
		return ISC_QUIC_ENCRYPTION_EARLY_DATA;
	case NGTCP2_ENCRYPTION_LEVEL_HANDSHAKE:
		return ISC_QUIC_ENCRYPTION_HANDSHAKE;
	case NGTCP2_ENCRYPTION_LEVEL_1RTT:
		return ISC_QUIC_ENCRYPTION_APPLICATION;
	};

	UNREACHABLE();
}

static bool
ngtcp2_quic_method_set_read_secret(
	isc_tls_t *tls, const isc_quic_encryption_level_t isc_enc_level,
	const isc_tls_cipher_t *cipher, const uint8_t *secret,
	const size_t secret_len) {
	REQUIRE(tls != NULL);

	UNUSED(cipher);

	ngtcp2_conn *conn = isc_tls_quic_get_app_data(tls);
	const ngtcp2_encryption_level level =
		ngtcp2_crypto_convert_isc_encryption_level(isc_enc_level);

	INSIST(conn != NULL);

	return ngtcp2_crypto_derive_and_install_rx_key(
		conn, NULL, NULL, NULL, level, secret, secret_len);
}

static bool
ngtcp2_quic_method_set_write_secret(
	isc_tls_t *tls, const isc_quic_encryption_level_t isc_enc_level,
	const isc_tls_cipher_t *cipher, const uint8_t *secret,
	const size_t secret_len) {
	REQUIRE(tls != NULL);

	UNUSED(cipher);

	ngtcp2_conn *conn = isc_tls_quic_get_app_data(tls);
	const ngtcp2_encryption_level level =
		ngtcp2_crypto_convert_isc_encryption_level(isc_enc_level);

	INSIST(conn != NULL);

	return ngtcp2_crypto_derive_and_install_tx_key(
		conn, NULL, NULL, NULL, level, secret, secret_len);
}

static bool
ngtcp2_quic_method_send_alert(isc_tls_t *tls,
			      const isc_quic_encryption_level_t level,
			      const uint8_t alert) {
	REQUIRE(tls != NULL);

	UNUSED(level);

	ngtcp2_conn *conn = isc_tls_quic_get_app_data(tls);

	INSIST(conn != NULL);

	ngtcp2_conn_set_tls_alert(conn, alert);

	return true;
}

static bool
ngtcp2_quic_method_add_handshake_data(
	isc_tls_t *tls, const isc_quic_encryption_level_t isc_enc_level,
	const uint8_t *data, const size_t len) {
	REQUIRE(tls != NULL);

	ngtcp2_conn *conn = isc_tls_quic_get_app_data(tls);
	ngtcp2_encryption_level level =
		ngtcp2_crypto_convert_isc_encryption_level(isc_enc_level);
	int rv = 0;

	INSIST(conn != NULL);

	rv = ngtcp2_conn_submit_crypto_data(conn, level, data, len);
	if (rv != 0) {
		ngtcp2_conn_set_tls_error(conn, rv);
		return false;
	}

	return true;
}

/*
 * The callback function which is invoked when client asks TLS stack
 * to produce first TLS cryptographic handshake message.
 */
static int
ngtcp2_crypto_client_initial_cb(ngtcp2_conn *conn, void *user_data) {
	const ngtcp2_cid *dcid = ngtcp2_conn_get_dcid(conn);

	UNUSED(user_data);

	NGTCP2_TRACE_CB();

	if (!ngtcp2_crypto_derive_and_install_initial_key(
		    conn, ngtcp2_conn_get_client_chosen_version(conn), dcid))
	{
		return NGTCP2_ERR_CALLBACK_FAILURE;
	}

	if (!ngtcp2_crypto_set_local_transport_params_to_tls(conn)) {
		return NGTCP2_ERR_CALLBACK_FAILURE;
	}

	if (!ngtcp2_crypto_process_data(conn, NGTCP2_ENCRYPTION_LEVEL_INITIAL,
					NULL, 0))
	{
		return NGTCP2_ERR_CALLBACK_FAILURE;
	}

	return 0;
}

/*
 * The callback function which is invoked when the compatible version
 * negotiation takes place.
 */
static int
ngtcp2_crypto_version_negotiation_cb(ngtcp2_conn *conn, uint32_t version,
				     const ngtcp2_cid *client_dcid,
				     void *user_data) {
	UNUSED(user_data);

	NGTCP2_TRACE_CB();

	if (!ngtcp2_crypto_derive_and_install_vneg_initial_key(conn, version,
							       client_dcid))
	{
		return NGTCP2_ERR_CALLBACK_FAILURE;
	}

	return 0;
}

/*
 * The callback function which is invoked when a client receives Retry
 * packet.
 */
static int
ngtcp2_crypto_recv_retry_cb(ngtcp2_conn *conn, const ngtcp2_pkt_hd *hd,
			    void *user_data) {
	UNUSED(user_data);

	NGTCP2_TRACE_CB();

	if (!ngtcp2_crypto_derive_and_install_initial_key(
		    conn, ngtcp2_conn_get_client_chosen_version(conn),
		    &hd->scid))
	{
		return NGTCP2_ERR_CALLBACK_FAILURE;
	}

	return 0;
}

/*
 * The callback function which is invoked when a server receives the
 * first Initial packet from client.
 */
static int
ngtcp2_crypto_recv_client_initial_cb(ngtcp2_conn *conn, const ngtcp2_cid *dcid,
				     void *user_data) {
	UNUSED(user_data);

	NGTCP2_TRACE_CB();

	if (!ngtcp2_crypto_derive_and_install_initial_key(
		    conn, ngtcp2_conn_get_client_chosen_version(conn), dcid))
	{
		return NGTCP2_ERR_CALLBACK_FAILURE;
	}

	return 0;
}

/*
 *  The callback function which is invoked to encrypt a QUIC packet.
 */
static int
ngtcp2_crypto_encrypt_cb(uint8_t *dest, const ngtcp2_crypto_aead *aead,
			 const ngtcp2_crypto_aead_ctx *aead_ctx,
			 const uint8_t *plaintext, size_t plaintextlen,
			 const uint8_t *nonce, size_t noncelen,
			 const uint8_t *aad, size_t aadlen) {
	UNUSED(noncelen);

	NGTCP2_TRACE_CB();

	if (!isc__quic_crypto_aead_encrypt(
		    dest, (EVP_CIPHER *)aead->native_handle,
		    (EVP_CIPHER_CTX *)aead_ctx->native_handle, nonce, plaintext,
		    plaintextlen, aad, aadlen))
	{
		return NGTCP2_ERR_CALLBACK_FAILURE;
	}

	return 0;
}

/*
 *  The callback function which is invoked to decrypt a QUIC packet.
 */
static int
ngtcp2_crypto_decrypt_cb(uint8_t *dest, const ngtcp2_crypto_aead *aead,
			 const ngtcp2_crypto_aead_ctx *aead_ctx,
			 const uint8_t *ciphertext, size_t ciphertextlen,
			 const uint8_t *nonce, size_t noncelen,
			 const uint8_t *aad, size_t aadlen) {
	UNUSED(noncelen);

	NGTCP2_TRACE_CB();

	if (!isc__quic_crypto_aead_decrypt(
		    dest, (EVP_CIPHER *)aead->native_handle,
		    (EVP_CIPHER_CTX *)aead_ctx->native_handle, nonce,
		    ciphertext, ciphertextlen, aad, aadlen))
	{
		return NGTCP2_ERR_DECRYPT;
	}

	return 0;
}

/*
 * The callback function which is invoked when the library tells an
 * application that it must update keying materials, and install new
 * keys.
 */
static int
ngtcp2_crypto_update_key_cb(ngtcp2_conn *conn, uint8_t *rx_secret,
			    uint8_t *tx_secret,
			    ngtcp2_crypto_aead_ctx *rx_aead_ctx, uint8_t *rx_iv,
			    ngtcp2_crypto_aead_ctx *tx_aead_ctx, uint8_t *tx_iv,
			    const uint8_t *current_rx_secret,
			    const uint8_t *current_tx_secret, size_t secretlen,
			    void *user_data) {
	uint8_t rx_key[EVP_MAX_KEY_LENGTH];
	uint8_t tx_key[EVP_MAX_KEY_LENGTH];

	UNUSED(user_data);

	NGTCP2_TRACE_CB();

	if (!ngtcp2_crypto_update_key(conn, rx_secret, tx_secret, rx_aead_ctx,
				      rx_key, rx_iv, tx_aead_ctx, tx_key, tx_iv,
				      current_rx_secret, current_tx_secret,
				      secretlen))
	{
		return NGTCP2_ERR_CALLBACK_FAILURE;
	}

	return 0;
}

/*
 * The a callback function which deletes/uninitializes a given AEAD cipher
 * context object
 */
static void
ngtcp2_crypto_delete_crypto_aead_ctx_cb(ngtcp2_conn *conn,
					ngtcp2_crypto_aead_ctx *aead_ctx,
					void *user_data) {
	UNUSED(conn);
	UNUSED(user_data);

	NGTCP2_TRACE_CB();

	ngtcp2_crypto_aead_ctx_free(aead_ctx);
}

/*
 * The callback function which is invoked to get a mask to encrypt or
 * decrypt QUIC packet header.
 */
static int
ngtcp2_crypto_hp_mask_cb(uint8_t *dest, const ngtcp2_crypto_cipher *hp,
			 const ngtcp2_crypto_cipher_ctx *hp_ctx,
			 const uint8_t *sample) {
	UNUSED(hp);

	NGTCP2_TRACE_CB();

	if (!isc__quic_crypto_hp_mask(
		    dest, (EVP_CIPHER_CTX *)hp_ctx->native_handle, sample))
	{
		return NGTCP2_ERR_CALLBACK_FAILURE;
	}

	return 0;
}

/*
 * The a callback function which deletes/uninitializes a given header
 * protection cipher context object
 */
static void
ngtcp2_crypto_delete_crypto_cipher_ctx_cb(ngtcp2_conn *conn,
					  ngtcp2_crypto_cipher_ctx *cipher_ctx,
					  void *user_data) {
	UNUSED(conn);
	UNUSED(user_data);

	NGTCP2_TRACE_CB();

	ngtcp2_crypto_cipher_ctx_free(cipher_ctx);
}

/*
 *  The callback function which is invoked when cryptographic data
 * (CRYPTO frame, in other words, a TLS message but in QUIC framing)
 * is received.
 */
static int
ngtcp2_crypto_recv_crypto_data_cb(ngtcp2_conn *conn,
				  ngtcp2_encryption_level encryption_level,
				  uint64_t offset, const uint8_t *data,
				  size_t datalen, void *user_data) {
	int rv = 0;

	UNUSED(offset);
	UNUSED(user_data);

	NGTCP2_TRACE_CB();

	if (!ngtcp2_crypto_process_data(conn, encryption_level, data, datalen))
	{
		rv = ngtcp2_conn_get_tls_error(conn);
		if (rv) {
			return rv;
		}
		return NGTCP2_ERR_CRYPTO;
	}

	return 0;
}

/*
 * The callback function which is invoked when ngtcp2 needs
 * (pseudo)random data for non-crypto purposes.
 */
static void
ngtcp2_crypto_rand_cb(uint8_t *dest, size_t destlen,
		      const ngtcp2_rand_ctx *rand_ctx) {
	UNUSED(rand_ctx);

	NGTCP2_TRACE_CB();

	isc_random_buf((void *)dest, destlen);
}

/*
 * The callback function which is invoked when the library needs new
 * data to send along with 'PATH_CHALLENGE' frame.
 */
static int
ngtcp2_crypto_get_path_challenge_data_cb(ngtcp2_conn *conn, uint8_t *data,
					 void *user_data) {
	UNUSED(conn);
	UNUSED(user_data);

	NGTCP2_TRACE_CB();

	isc_random_buf(data, NGTCP2_PATH_CHALLENGE_DATALEN);

	return 0;
}

void
isc_ngtcp2_crypto_set_crypto_callbacks(ngtcp2_callbacks *callbacks) {
	REQUIRE(callbacks != NULL);

	if (callbacks->client_initial == NULL) {
		callbacks->client_initial = ngtcp2_crypto_client_initial_cb;
	}
	if (callbacks->version_negotiation == NULL) {
		callbacks->version_negotiation =
			ngtcp2_crypto_version_negotiation_cb;
	}
	if (callbacks->recv_retry == NULL) {
		callbacks->recv_retry = ngtcp2_crypto_recv_retry_cb;
	}
	if (callbacks->recv_client_initial == NULL) {
		callbacks->recv_client_initial =
			ngtcp2_crypto_recv_client_initial_cb;
	}
	if (callbacks->update_key == NULL) {
		callbacks->update_key = ngtcp2_crypto_update_key_cb;
	}

	if (callbacks->encrypt == NULL) {
		callbacks->encrypt = ngtcp2_crypto_encrypt_cb;
	}
	if (callbacks->decrypt == NULL) {
		callbacks->decrypt = ngtcp2_crypto_decrypt_cb;
	}
	if (callbacks->delete_crypto_aead_ctx == NULL) {
		callbacks->delete_crypto_aead_ctx =
			ngtcp2_crypto_delete_crypto_aead_ctx_cb;
	}

	if (callbacks->hp_mask == NULL) {
		callbacks->hp_mask = ngtcp2_crypto_hp_mask_cb;
	}
	if (callbacks->delete_crypto_cipher_ctx == NULL) {
		callbacks->delete_crypto_cipher_ctx =
			ngtcp2_crypto_delete_crypto_cipher_ctx_cb;
	}

	if (callbacks->recv_crypto_data == NULL) {
		callbacks->recv_crypto_data = ngtcp2_crypto_recv_crypto_data_cb;
	}

	if (callbacks->rand == NULL) {
		callbacks->rand = ngtcp2_crypto_rand_cb;
	}
	if (callbacks->get_path_challenge_data == NULL) {
		callbacks->get_path_challenge_data =
			ngtcp2_crypto_get_path_challenge_data_cb;
	}
}

static ngtcp2_callbacks default_crypto_callbacks = { 0 };

static void
ngtcp2__init_default_crypto_callbacks(void) __attribute__((__constructor__));

static void
ngtcp2__init_default_crypto_callbacks(void) {
	isc_ngtcp2_crypto_set_crypto_callbacks(&default_crypto_callbacks);
}

const ngtcp2_callbacks *
isc_ngtcp2_crypto_get_default_crypto_callbacks(void) {
	return &default_crypto_callbacks;
}

static const isc_tls_quic_method_t ngtcp2_quic_method = (isc_tls_quic_method_t){
	.set_read_secret = ngtcp2_quic_method_set_read_secret,
	.set_write_secret = ngtcp2_quic_method_set_write_secret,
	.add_handshake_data = ngtcp2_quic_method_add_handshake_data,
	.send_alert = ngtcp2_quic_method_send_alert
};

isc_result_t
isc_ngtcp2_crypto_bind_conn_tls(ngtcp2_conn *conn, isc_tls_t *tls) {
	REQUIRE(conn != NULL);
	REQUIRE(tls != NULL);

	const isc_result_t result =
		isc_tls_set_quic_method(tls, &ngtcp2_quic_method);

	if (result != ISC_R_SUCCESS) {
		return result;
	}

	ngtcp2_conn_set_tls_native_handle(conn, tls);
	isc_tls_quic_set_app_data(tls, conn);

	return result;
}

isc_result_t
isc_ngtcp2_crypto_generate_stateless_reset_token(uint8_t *token_buf,
						 const size_t token_buflen,
						 const uint8_t *secret,
						 const size_t secretlen,
						 const ngtcp2_cid *cid) {
	static const uint8_t info[] = "stateless_reset";
	const EVP_MD *sha256md = NULL;

	REQUIRE(token_buf != NULL);
	REQUIRE(token_buflen >= NGTCP2_STATELESS_RESET_TOKENLEN);
	REQUIRE(secret != NULL);
	REQUIRE(secretlen > 0);
	REQUIRE(cid != NULL && cid->data != NULL && cid->datalen > 0);

	sha256md = isc__quic_crypto_md_sha256();

	if (!isc__quic_crypto_hkdf(token_buf, NGTCP2_STATELESS_RESET_TOKENLEN,
				   sha256md, secret, secretlen, cid->data,
				   cid->datalen, info, sizeof(info) - 1))
	{
		return ISC_R_FAILURE;
	}

	return ISC_R_SUCCESS;
}

static bool
ngtcp2_crypto_derive_token_key(uint8_t *key, const size_t keylen, uint8_t *iv,
			       const size_t ivlen,
			       const ngtcp2_crypto_md *restrict md,
			       const uint8_t *secret, const size_t secretlen,
			       const uint8_t *salt, const size_t saltlen,
			       const uint8_t *info_prefix,
			       const size_t info_prefixlen) {
	static const uint8_t key_info_suffix[] = " key";
	static const uint8_t iv_info_suffix[] = " iv";
	uint8_t intsecret[EVP_MAX_MD_SIZE];
	size_t intsecret_len = 0;
	uint8_t info_buf[UINT8_MAX];
	isc_buffer_t info = { 0 };
	isc_region_t info_region = { 0 };

	REQUIRE(key != NULL);
	REQUIRE(keylen > 0);
	REQUIRE(iv != NULL);
	REQUIRE(ivlen > 0);
	REQUIRE(md != NULL);
	REQUIRE(secret != NULL);
	REQUIRE(secretlen > 0);
	REQUIRE(salt != NULL);
	REQUIRE(saltlen > 0);
	REQUIRE(info_prefix != NULL);
	REQUIRE(info_prefixlen > 0);

	intsecret_len = isc__quic_crypto_md_hashlen(md->native_handle);

	INSIST(intsecret_len <= sizeof(intsecret));
	INSIST((info_prefixlen + sizeof(key_info_suffix) - 1) <=
	       sizeof(info_buf));
	INSIST((info_prefixlen + sizeof(iv_info_suffix) - 1) <=
	       sizeof(info_buf));

	if (!isc__quic_crypto_hkdf_extract(intsecret, md->native_handle, secret,
					   secretlen, salt, saltlen))
	{
		return false;
	}

	isc_buffer_init(&info, info_buf, sizeof(info_buf));

	isc_buffer_putmem(&info, info_prefix, info_prefixlen);

	isc_buffer_putmem(&info, key_info_suffix, sizeof(key_info_suffix) - 1);
	isc_buffer_usedregion(&info, &info_region);

	if (!isc__quic_crypto_hkdf_expand(key, keylen, md->native_handle,
					  intsecret, intsecret_len,
					  info_region.base, info_region.length))
	{
		return false;
	}

	isc_buffer_subtract(&info, sizeof(key_info_suffix) - 1);

	isc_buffer_putmem(&info, iv_info_suffix, sizeof(iv_info_suffix) - 1);
	isc_buffer_usedregion(&info, &info_region);

	if (!isc__quic_crypto_hkdf_expand(iv, ivlen, md->native_handle,
					  intsecret, intsecret_len,
					  info_region.base, info_region.length))
	{
		return false;
	}

	return true;
}

static inline size_t
ngtcp2_crypto_generate_retry_token_aad(uint8_t *dest, const size_t destlen,
				       const uint32_t version,
				       const ngtcp2_sockaddr *sa,
				       const ngtcp2_socklen salen,
				       const ngtcp2_cid *restrict retry_scid) {
	isc_buffer_t aad = { 0 };

	REQUIRE(dest != NULL);
	REQUIRE(destlen > 0);
	REQUIRE(sa != NULL);
	REQUIRE(salen > 0);
	REQUIRE(retry_scid != NULL && retry_scid->data != NULL &&
		retry_scid->datalen > 0);

	isc_buffer_init(&aad, dest, destlen);

	isc_buffer_putuint32(&aad, version);
	isc_buffer_putmem(&aad, (uint8_t *)sa, salen);
	isc_buffer_putmem(&aad, retry_scid->data, retry_scid->datalen);

	return (size_t)isc_buffer_usedlength(&aad);
}

size_t
isc_ngtcp2_crypto_generate_retry_token(
	uint8_t *token_buf, const size_t token_buflen, const uint8_t *secret,
	const size_t secretlen, const uint32_t version,
	const ngtcp2_sockaddr *remote_addr, const ngtcp2_socklen remote_addrlen,
	const ngtcp2_cid *retry_scid, const ngtcp2_cid *orig_dcid,
	const ngtcp2_tstamp ts) {
	isc_buffer_t token = { 0 };
	isc_buffer_t plaintext = { 0 };
	uint8_t plaintext_buf[RETRY_TOKEN_PLAINTEXT_LEN] = { 0 };
	size_t plaintextlen = 0;
	uint8_t rand_data[ISC_NGTCP2_CRYPTO_TOKEN_RAND_DATA_LEN];
	uint8_t key[EVP_MAX_KEY_LENGTH];
	uint8_t iv[EVP_MAX_IV_LENGTH];
	size_t keylen = 0;
	size_t ivlen = 0;
	ngtcp2_crypto_aead aead = { 0 };
	ngtcp2_crypto_md md = { 0 };
	ngtcp2_crypto_aead_ctx aead_ctx = { 0 };
	uint8_t aad[RETRY_TOKEN_AAD_LEN] = { 0 };
	size_t aadlen = 0;
	uint8_t *p = NULL;
	uint8_t ts_be[sizeof(uint64_t)] = { 0 };
	bool ret = false;

	REQUIRE(token_buf != NULL);
	REQUIRE(token_buflen >= ISC_NGTCP2_CRYPTO_MAX_RETRY_TOKEN_LEN);
	REQUIRE(secret != NULL);
	REQUIRE(secretlen > 0);
	REQUIRE(remote_addr != NULL);
	REQUIRE(remote_addrlen > 0 &&
		remote_addrlen <= sizeof(ngtcp2_sockaddr_union));
	REQUIRE(retry_scid != NULL && retry_scid->data != NULL &&
		retry_scid->datalen > 0);
	REQUIRE(orig_dcid != NULL && orig_dcid->data != NULL &&
		orig_dcid->datalen > 0);

	isc_buffer_init(&plaintext, plaintext_buf, sizeof(plaintext_buf));

	isc_buffer_putuint8(&plaintext, (uint8_t)orig_dcid->datalen);
	isc_buffer_putmem(&plaintext, orig_dcid->data, orig_dcid->datalen);
	isc_buffer_add(&plaintext, NGTCP2_MAX_CIDLEN - orig_dcid->datalen);
	INSIST(isc_buffer_usedlength(&plaintext) == (NGTCP2_MAX_CIDLEN + 1));
	ISC_U64TO8_BE(ts_be, ts);
	isc_buffer_putmem(&plaintext, ts_be, sizeof(ts_be));
	plaintextlen = isc_buffer_usedlength(&plaintext);

	isc_random_buf(rand_data, sizeof(rand_data));

	ngtcp2_crypto_aead_aes_128_gcm_init(&aead);
	ngtcp2_crypto_md_sha256_init(&md);

	keylen = isc__quic_crypto_aead_keylen(aead.native_handle);
	ivlen = isc__quic_crypto_aead_ivlen(aead.native_handle);

	if (!ngtcp2_crypto_derive_token_key(
		    key, keylen, iv, ivlen, &md, secret, secretlen, rand_data,
		    sizeof(rand_data), (uint8_t *)RETRY_TOKEN_INFO_PREFIX,
		    RETRY_TOKEN_INFO_PREFIX_LEN))
	{
		return 0;
	}

	if (!ngtcp2_crypto_aead_ctx_encrypt_init(&aead_ctx, &aead, key, ivlen))
	{
		return 0;
	}

	aadlen = ngtcp2_crypto_generate_retry_token_aad(
		aad, sizeof(aad), version, remote_addr, remote_addrlen,
		retry_scid);

	INSIST(aadlen > 0);

	isc_buffer_init(&token, token_buf, token_buflen);
	isc_buffer_putuint8(&token, ISC_NGTCP2_CRYPTO_TOKEN_MAGIC_RETRY);
	isc_buffer_add(&token, plaintextlen + aead.max_overhead);

	p = isc_buffer_used(&token);
	p -= plaintextlen + aead.max_overhead;

	ret = isc__quic_crypto_aead_encrypt(
		p, aead.native_handle, aead_ctx.native_handle, iv,
		plaintext_buf, plaintextlen, aad, aadlen);

	ngtcp2_crypto_aead_ctx_free(&aead_ctx);

	if (!ret) {
		return 0;
	}
	isc_buffer_putmem(&token, rand_data, sizeof(rand_data));

	return isc_buffer_usedlength(&token);
}

isc_result_t
isc_ngtcp2_crypto_verify_retry_token(
	ngtcp2_cid *orig_dcid, const uint8_t *token_buf,
	const size_t token_buflen, const uint8_t *secret,
	const size_t secretlen, const uint32_t version,
	const ngtcp2_sockaddr *remote_addr, const ngtcp2_socklen remote_addrlen,
	const ngtcp2_cid *dcid, const ngtcp2_duration timeout,
	const ngtcp2_tstamp ts) {
	uint8_t plaintext[RETRY_TOKEN_PLAINTEXT_LEN];
	uint8_t key[EVP_MAX_KEY_LENGTH];
	uint8_t iv[EVP_MAX_IV_LENGTH];
	size_t keylen = 0;
	size_t ivlen = 0;
	ngtcp2_crypto_aead_ctx aead_ctx = { 0 };
	ngtcp2_crypto_aead aead = { 0 };
	ngtcp2_crypto_md md = { 0 };
	uint8_t aad[RETRY_TOKEN_AAD_LEN];
	size_t aadlen = 0;
	const uint8_t *rand_data = NULL;
	const uint8_t *ciphertext = NULL;
	size_t ciphertextlen = 0;
	size_t cid_len = 0;
	bool ret = false;
	ngtcp2_tstamp token_ts = 0;

	REQUIRE(orig_dcid != NULL && orig_dcid->data != NULL);
	REQUIRE(token_buf != NULL);
	REQUIRE(token_buflen >= ISC_NGTCP2_CRYPTO_MAX_RETRY_TOKEN_LEN);
	REQUIRE(secret != NULL);
	REQUIRE(secretlen > 0);
	REQUIRE(remote_addr != NULL);
	REQUIRE(remote_addrlen > 0);
	REQUIRE(dcid != NULL && dcid->data != NULL && dcid->datalen > 0);

	if (token_buf[0] != ISC_NGTCP2_CRYPTO_TOKEN_MAGIC_RETRY) {
		return ISC_R_UNEXPECTED;
	}

	rand_data = token_buf + token_buflen -
		    ISC_NGTCP2_CRYPTO_TOKEN_RAND_DATA_LEN;
	ciphertext = token_buf + 1;
	ciphertextlen = token_buflen - 1 -
			ISC_NGTCP2_CRYPTO_TOKEN_RAND_DATA_LEN;

	ngtcp2_crypto_aead_aes_128_gcm_init(&aead);
	ngtcp2_crypto_md_sha256_init(&md);

	keylen = isc__quic_crypto_aead_keylen(aead.native_handle);
	ivlen = isc__quic_crypto_aead_ivlen(aead.native_handle);

	if (!ngtcp2_crypto_derive_token_key(
		    key, keylen, iv, ivlen, &md, secret, secretlen, rand_data,
		    ISC_NGTCP2_CRYPTO_TOKEN_RAND_DATA_LEN,
		    (uint8_t *)RETRY_TOKEN_INFO_PREFIX,
		    RETRY_TOKEN_INFO_PREFIX_LEN))
	{
		return ISC_R_FAILURE;
	}

	aadlen = ngtcp2_crypto_generate_retry_token_aad(
		aad, sizeof(aad), version, remote_addr, remote_addrlen, dcid);

	INSIST(aadlen > 0);

	if (!ngtcp2_crypto_aead_ctx_decrypt_init(&aead_ctx, &aead, key, ivlen))
	{
		return ISC_R_FAILURE;
	}

	ret = isc__quic_crypto_aead_decrypt(
		plaintext, aead.native_handle, aead_ctx.native_handle, iv,
		ciphertext, ciphertextlen, aad, aadlen);

	ngtcp2_crypto_aead_ctx_free(&aead_ctx);

	if (!ret) {
		return ISC_R_FAILURE;
	}

	cid_len = plaintext[0];

	if (cid_len != 0 &&
	    (cid_len < NGTCP2_MIN_CIDLEN || cid_len > NGTCP2_MAX_CIDLEN))
	{
		return ISC_R_FAILURE;
	}

	token_ts = ISC_U8TO64_BE(plaintext + /* cid len = */ sizeof(uint8_t) +
				 NGTCP2_MAX_CIDLEN);

	if (ts >= (token_ts + timeout)) {
		return ISC_R_TIMEDOUT;
	}

	ngtcp2_cid_init(orig_dcid, plaintext + /* cid len = */ sizeof(uint8_t),
			cid_len);

	return ISC_R_SUCCESS;
}

static inline size_t
ngtcp2_crypto_generate_regular_token_aad(uint8_t *dest,
					 const ngtcp2_sockaddr *restrict sa) {
	const uint8_t *addr = NULL;
	size_t addrlen = 0;

	REQUIRE(dest != NULL);
	REQUIRE(sa != NULL);

	switch (sa->sa_family) {
	case NGTCP2_AF_INET:
		addr = (const uint8_t *)&(
			       (const ngtcp2_sockaddr_in *)(void *)sa)
			       ->sin_addr;
		addrlen = sizeof(
			((const ngtcp2_sockaddr_in *)(void *)sa)->sin_addr);
		break;
	case NGTCP2_AF_INET6:
		addr = (const uint8_t *)&(
			       (const ngtcp2_sockaddr_in6 *)(void *)sa)
			       ->sin6_addr;
		addrlen = sizeof(
			((const ngtcp2_sockaddr_in6 *)(void *)sa)->sin6_addr);
		break;
	default:
		UNREACHABLE();
	}

	memmove(dest, addr, addrlen);

	return addrlen;
}

size_t
isc_ngtcp2_crypto_generate_regular_token(
	uint8_t *token_buf, const size_t token_buflen, const uint8_t *secret,
	const size_t secretlen, const ngtcp2_sockaddr *remote_addr,
	const ngtcp2_socklen remote_addrlen, const ngtcp2_tstamp ts) {
	isc_buffer_t token = { 0 };
	isc_buffer_t plaintext = { 0 };
	uint8_t plaintext_buf[sizeof(ngtcp2_tstamp)];
	size_t plaintextlen = 0;
	uint8_t rand_data[ISC_NGTCP2_CRYPTO_TOKEN_RAND_DATA_LEN];
	uint8_t key[EVP_MAX_KEY_LENGTH];
	uint8_t iv[EVP_MAX_IV_LENGTH];
	size_t keylen = 0;
	size_t ivlen = 0;
	ngtcp2_crypto_aead aead = { 0 };
	ngtcp2_crypto_md md = { 0 };
	ngtcp2_crypto_aead_ctx aead_ctx = { 0 };
	uint8_t aad[sizeof(ngtcp2_sockaddr_in6)];
	size_t aadlen = 0;
	uint8_t *p = plaintext_buf;
	uint8_t ts_be[sizeof(uint64_t)] = { 0 };
	bool ret = false;

	REQUIRE(token_buf != NULL);
	REQUIRE(token_buflen >= ISC_NGTCP2_CRYPTO_MAX_REGULAR_TOKEN_LEN);
	REQUIRE(secret != NULL);
	REQUIRE(secretlen > 0);
	REQUIRE(remote_addr != NULL);
	REQUIRE(remote_addrlen > 0 &&
		remote_addrlen <= sizeof(ngtcp2_sockaddr_union));

	isc_buffer_init(&plaintext, plaintext_buf, sizeof(plaintext_buf));
	ISC_U64TO8_BE(ts_be, ts);
	isc_buffer_putmem(&plaintext, ts_be, sizeof(ts_be));
	plaintextlen = isc_buffer_usedlength(&plaintext);

	isc_random_buf(rand_data, sizeof(rand_data));

	ngtcp2_crypto_aead_aes_128_gcm_init(&aead);
	ngtcp2_crypto_md_sha256_init(&md);

	keylen = isc__quic_crypto_aead_keylen(aead.native_handle);
	ivlen = isc__quic_crypto_aead_ivlen(aead.native_handle);

	if (!ngtcp2_crypto_derive_token_key(
		    key, keylen, iv, ivlen, &md, secret, secretlen, rand_data,
		    sizeof(rand_data), (uint8_t *)REGULAR_TOKEN_INFO_PREFIX,
		    REGULAR_TOKEN_INFO_PREFIX_LEN))
	{
		return 0;
	}

	if (!ngtcp2_crypto_aead_ctx_encrypt_init(&aead_ctx, &aead, key, ivlen))
	{
		return 0;
	}

	aadlen = ngtcp2_crypto_generate_regular_token_aad(aad, remote_addr);

	INSIST(aadlen > 0);

	isc_buffer_init(&token, token_buf, token_buflen);
	isc_buffer_putuint8(&token, ISC_NGTCP2_CRYPTO_TOKEN_MAGIC_REGULAR);
	isc_buffer_add(&token, plaintextlen + aead.max_overhead);

	p = isc_buffer_used(&token);
	p -= plaintextlen + aead.max_overhead;

	ret = isc__quic_crypto_aead_encrypt(
		p, aead.native_handle, aead_ctx.native_handle, iv,
		plaintext_buf, plaintextlen, aad, aadlen);

	ngtcp2_crypto_aead_ctx_free(&aead_ctx);

	if (!ret) {
		return 0;
	}

	isc_buffer_putmem(&token, rand_data, sizeof(rand_data));

	return isc_buffer_usedlength(&token);
}

isc_result_t
isc_ngtcp2_crypto_verify_regular_token(const uint8_t *token,
				       const size_t tokenlen,
				       const uint8_t *secret, size_t secretlen,
				       const ngtcp2_sockaddr *remote_addr,
				       const ngtcp2_socklen remote_addrlen,
				       const ngtcp2_duration timeout,
				       const ngtcp2_tstamp ts) {
	uint8_t plaintext[sizeof(ngtcp2_tstamp)];
	uint8_t key[EVP_MAX_KEY_LENGTH];
	uint8_t iv[EVP_MAX_IV_LENGTH];
	size_t keylen = 0;
	size_t ivlen = 0;
	ngtcp2_crypto_aead_ctx aead_ctx = { 0 };
	ngtcp2_crypto_aead aead = { 0 };
	ngtcp2_crypto_md md = { 0 };
	uint8_t aad[sizeof(ngtcp2_sockaddr_in6)];
	size_t aadlen = 0;
	const uint8_t *rand_data = NULL;
	const uint8_t *ciphertext = NULL;
	size_t ciphertextlen = 0;
	bool ret = false;
	ngtcp2_tstamp token_ts = 0;

	REQUIRE(token != NULL);
	REQUIRE(tokenlen >= ISC_NGTCP2_CRYPTO_MAX_REGULAR_TOKEN_LEN);
	REQUIRE(secret != NULL);
	REQUIRE(secretlen > 0);
	REQUIRE(remote_addr != NULL);
	REQUIRE(remote_addrlen > 0);

	if (token[0] != ISC_NGTCP2_CRYPTO_TOKEN_MAGIC_REGULAR) {
		return ISC_R_UNEXPECTED;
	}

	rand_data = token + tokenlen - ISC_NGTCP2_CRYPTO_TOKEN_RAND_DATA_LEN;
	ciphertext = token + sizeof(uint8_t);
	ciphertextlen = tokenlen - sizeof(uint8_t) -
			ISC_NGTCP2_CRYPTO_TOKEN_RAND_DATA_LEN;

	ngtcp2_crypto_aead_aes_128_gcm_init(&aead);
	ngtcp2_crypto_md_sha256_init(&md);

	keylen = isc__quic_crypto_aead_keylen(aead.native_handle);
	ivlen = isc__quic_crypto_aead_ivlen(aead.native_handle);

	if (!ngtcp2_crypto_derive_token_key(
		    key, keylen, iv, ivlen, &md, secret, secretlen, rand_data,
		    ISC_NGTCP2_CRYPTO_TOKEN_RAND_DATA_LEN,
		    (uint8_t *)REGULAR_TOKEN_INFO_PREFIX,
		    REGULAR_TOKEN_INFO_PREFIX_LEN))
	{
		return ISC_R_FAILURE;
	}

	aadlen = ngtcp2_crypto_generate_regular_token_aad(aad, remote_addr);

	if (!ngtcp2_crypto_aead_ctx_decrypt_init(&aead_ctx, &aead, key, ivlen))
	{
		return ISC_R_FAILURE;
	}

	ret = isc__quic_crypto_aead_decrypt(
		plaintext, aead.native_handle, aead_ctx.native_handle, iv,
		ciphertext, ciphertextlen, aad, aadlen);

	ngtcp2_crypto_aead_ctx_free(&aead_ctx);

	if (!ret) {
		return ISC_R_FAILURE;
	}

	token_ts = ISC_U8TO64_BE(plaintext);

	if (ts >= (token_ts + timeout)) {
		return ISC_R_TIMEDOUT;
	}

	return ISC_R_SUCCESS;
}

ssize_t
isc_ngtcp2_crypto_write_connection_close(uint8_t *dest, const size_t destlen,
					 const uint32_t version,
					 const ngtcp2_cid *dcid,
					 const ngtcp2_cid *scid,
					 const uint64_t error_code,
					 const uint8_t *reason,
					 const size_t reasonlen) {
	uint8_t rx_secret[EVP_MAX_MD_SIZE];
	uint8_t tx_secret[EVP_MAX_MD_SIZE];
	uint8_t initial_secret[EVP_MAX_MD_SIZE];
	uint8_t tx_key[EVP_MAX_KEY_LENGTH];
	uint8_t tx_iv[EVP_MAX_IV_LENGTH];
	uint8_t tx_hp_key[EVP_MAX_KEY_LENGTH];
	size_t initial_secret_len = 0;
	size_t initial_iv_len = 0;
	ngtcp2_crypto_ctx ctx = { 0 };
	ngtcp2_crypto_aead_ctx aead_ctx = { 0 };
	ngtcp2_crypto_cipher_ctx hp_ctx = { 0 };
	ngtcp2_ssize ret_len = 0;

	REQUIRE(dest != NULL);
	REQUIRE(destlen > 0);
	REQUIRE(dcid != NULL && dcid->datalen > 0 && dcid->data != NULL);
	REQUIRE(scid != NULL && scid->datalen > 0 && scid->data != NULL);
	REQUIRE(reason != NULL);
	REQUIRE(reasonlen > 0);

	ngtcp2_crypto_ctx_initial_init(&ctx);

	initial_secret_len = isc__quic_crypto_md_hashlen(ctx.md.native_handle);
	initial_iv_len = isc__quic_crypto_aead_ivlen(ctx.aead.native_handle);

	if (!ngtcp2_crypto_derive_initial_secrets(
		    rx_secret, tx_secret, initial_secret, version, scid, true))
	{
		return 0;
	}

	if (!ngtcp2_crypto_derive_packet_protection_key(
		    tx_key, tx_iv, tx_hp_key, version, &ctx.aead, &ctx.md,
		    tx_secret, initial_secret_len))
	{
		return 0;
	}

	if (!ngtcp2_crypto_aead_ctx_encrypt_init(&aead_ctx, &ctx.aead, tx_key,
						 initial_iv_len))
	{
		goto end;
	}

	if (!ngtcp2_crypto_cipher_ctx_encrypt_init(&hp_ctx, &ctx.hp, tx_hp_key))
	{
		goto end;
	}

	ret_len = ngtcp2_pkt_write_connection_close(
		dest, destlen, version, dcid, scid, error_code, reason,
		reasonlen, ngtcp2_crypto_encrypt_cb, &ctx.aead, &aead_ctx,
		tx_iv, ngtcp2_crypto_hp_mask_cb, &ctx.hp, &hp_ctx);

end:
	ngtcp2_crypto_cipher_ctx_free(&hp_ctx);
	ngtcp2_crypto_aead_ctx_free(&aead_ctx);

	return ret_len;
}

ssize_t
isc_ngtcp2_crypto_write_retry(uint8_t *dest, const size_t destlen,
			      const uint32_t version, const ngtcp2_cid *dcid,
			      const ngtcp2_cid *scid,
			      const ngtcp2_cid *orig_dcid,
			      const uint8_t *token_buf,
			      const size_t token_buflen) {
	ngtcp2_crypto_aead aead = { 0 };
	ngtcp2_ssize ret_len = 0;
	ngtcp2_crypto_aead_ctx aead_ctx = { 0 };
	const uint8_t *key = NULL;
	size_t noncelen = 0;

	REQUIRE(dest != NULL);
	REQUIRE(destlen > 0);
	REQUIRE(dcid != NULL && dcid->datalen > 0 && dcid->data != NULL);
	REQUIRE(scid != NULL && scid->datalen > 0 && scid->data != NULL);
	REQUIRE(orig_dcid != NULL && orig_dcid->datalen > 0 &&
		orig_dcid->data != NULL);
	REQUIRE(token_buf != NULL);
	REQUIRE(token_buflen > 0);

	ngtcp2_crypto_aead_retry_init(&aead);

	switch (version) {
	case NGTCP2_PROTO_VER_V2:
		key = (const uint8_t *)NGTCP2_RETRY_KEY_V2;
		noncelen = sizeof(NGTCP2_RETRY_NONCE_V2) - 1;
		break;
	default:
		key = (const uint8_t *)NGTCP2_RETRY_KEY_V1;
		noncelen = sizeof(NGTCP2_RETRY_NONCE_V1) - 1;
		break;
	}

	if (!ngtcp2_crypto_aead_ctx_encrypt_init(&aead_ctx, &aead, key,
						 noncelen))
	{
		return 0;
	}

	ret_len = ngtcp2_pkt_write_retry(
		dest, destlen, version, dcid, scid, orig_dcid, token_buf,
		token_buflen, ngtcp2_crypto_encrypt_cb, &aead, &aead_ctx);

	ngtcp2_crypto_aead_ctx_free(&aead_ctx);

	return ret_len;
}

/* SCID + minimum expansion - NGTCP2_STATELESS_RESET_TOKENLEN */
#define MAX_STATLESS_RESET_RAND_BYTES \
	(NGTCP2_MAX_CIDLEN + 22 - NGTCP2_STATELESS_RESET_TOKENLEN)

ssize_t
isc_ngtcp2_crypto_write_stateless_reset_pkt(uint8_t *dest, const size_t destlen,
					    const size_t pkt_len,
					    const uint8_t *secret,
					    const size_t secretlen,
					    const ngtcp2_cid *dcid) {
	REQUIRE(dest != NULL);
	REQUIRE(destlen > 0);
	REQUIRE(secret != NULL);
	REQUIRE(secretlen > 0);
	REQUIRE(dcid != NULL && dcid->data != NULL && dcid->datalen > 0);

	uint8_t token[NGTCP2_STATELESS_RESET_TOKENLEN];
	ssize_t written = 0;

	isc_result_t result = isc_ngtcp2_crypto_generate_stateless_reset_token(
		token, NGTCP2_STATELESS_RESET_TOKENLEN, secret, secretlen,
		dcid);

	if (result != ISC_R_SUCCESS) {
		return -1;
	}

	uint8_t rand_bytes[MAX_STATLESS_RESET_RAND_BYTES];
	size_t rand_byteslen = 0;

	if (pkt_len <= 43) {
		/*
		 * See:
		 * https://datatracker.ietf.org/doc/html/rfc9000#section-10.3
		 */
		rand_byteslen = pkt_len - NGTCP2_STATELESS_RESET_TOKENLEN - 1;
	} else {
		rand_byteslen = MAX_STATLESS_RESET_RAND_BYTES;
	}

	isc_random_buf(rand_bytes, rand_byteslen);

	written = ngtcp2_pkt_write_stateless_reset(dest, destlen, token,
						   rand_bytes, rand_byteslen);

	return written;
}
