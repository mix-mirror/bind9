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
 * This file contains QUIC-flavoured TLSv1.3-related cryptography
 * functions. The code mostly inspired by QuicTLS/LibreSSL-specific
 * code found in ngtcp2's native crypto library but with some peeks at
 * similar code found in NGINX and HAProxy.
 *
 * The functions this code provides mostly fall into the following categories:
 *
 * 1. TLS cipher ('isc_tls_cipher_t' aka SSL_CIPHER) information retrieval:
 * getting associated message digest, AEAD-scheme, etc;
 * 2. HKDF-interface implementation (HKDF(), HKDF-Extract(), HKDF-Expand(),
 * HKDF-ExpandLabel());
 * 3. AEAD-interface (context creation, authenticated encryption/decryption);
 * 4. Header Protection mask calculation;
 *
 * The code is intended to be used in both the custom ngtcp2 crypto
 * library and OpenSSL QUIC compatibility code.
 */

#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/opensslv.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>

#if OPENSSL_VERSION_NUMBER >= 0x30000000L && OPENSSL_API_LEVEL >= 30000
#define OPENSSL_3_API_OR_NEWER 1
#include <openssl/core_names.h>
#endif

#include <isc/buffer.h>
#include <isc/crypto.h>

#include "quic_crypto.h"

/* See RFC9001, Section 6.6 (Limits on AEAD Usage ) for more details */

/* Maximum key usage (encryption) limits */
#define QUIC_CRYPTO_MAX_ENCRYPTION_AES_GCM	     (1ULL << 23)
#define QUIC_CRYPTO_MAX_ENCRYPTION_CHACHA20_POLY1305 (1ULL << 62)
#define QUIC_CRYPTO_MAX_ENCRYPTION_AES_CCM	     (2965820ULL)

/*
 * Maximum authentication failure (decryption) limits during the
 * lifetime of a connection.
 */
#define QUIC_CRYPTO_MAX_DECRYPTION_FAILURES_AES_GCM	      (1ULL << 52)
#define QUIC_CRYPTO_MAX_DECRYPTION_FAILURES_CHACHA20_POLY1305 (1ULL << 36)
#define QUIC_CRYPTO_MAX_DECRYPTION_FAILURES_AES_CCM	      (2965820ULL)

static void
quic_crypto_prefetch(void);

static void
quic_crypto_prefetch_clear(void);

static bool quic_crypto_initialized = false;
static bool fips_mode_used = false;

static const EVP_CIPHER *crypto_aead_aes_128_gcm = NULL;
static const EVP_CIPHER *crypto_aead_aes_256_gcm = NULL;
static const EVP_CIPHER *crypto_aead_aes_128_ccm = NULL;
static const EVP_CIPHER *crypto_aead_chacha20_poly1305 = NULL;

static const EVP_CIPHER *crypto_cipher_chacha20 = NULL;
static const EVP_CIPHER *crypto_cipher_aes_128_ctr = NULL;
static const EVP_CIPHER *crypto_cipher_aes_256_ctr = NULL;

static const EVP_MD *crypto_md_sha256 = NULL;
static const EVP_MD *crypto_md_sha384 = NULL;

#ifdef OPENSSL_3_API_OR_NEWER
static EVP_KDF *crypto_kdf_hkdf = NULL;
#endif /* OPENSSL_3_API_OR_NEWER */

#ifdef OPENSSL_3_API_OR_NEWER
/*
 * Explicitly prefetch certain objects to avoid performance penalty on
 * OpenSSL >= 3.0.
 *
 * See here for more details:
 * https://www.openssl.org/docs/man3.0/man7/crypto.html#Performance
 * https://www.openssl.org/docs/man3.0/man7/crypto.html#Explicit-fetching
 * https://www.openssl.org/docs/man3.0/man7/crypto.html#Implicit-fetching
 */

static void
quic_crypto_prefetch(void) {
	crypto_aead_aes_128_gcm = EVP_CIPHER_fetch(NULL, "AES-128-GCM", NULL);
	RUNTIME_CHECK(crypto_aead_aes_128_gcm != NULL);

	crypto_aead_aes_256_gcm = EVP_CIPHER_fetch(NULL, "AES-256-GCM", NULL);
	RUNTIME_CHECK(crypto_aead_aes_256_gcm != NULL);

	crypto_aead_aes_128_ccm = EVP_CIPHER_fetch(NULL, "AES-128-CCM", NULL);
	RUNTIME_CHECK(crypto_aead_aes_128_ccm != NULL);

	if (!fips_mode_used) {
		crypto_aead_chacha20_poly1305 =
			EVP_CIPHER_fetch(NULL, "ChaCha20-Poly1305", NULL);
		RUNTIME_CHECK(crypto_aead_chacha20_poly1305 != NULL);

		crypto_cipher_chacha20 = EVP_CIPHER_fetch(NULL, "ChaCha20",
							  NULL);
		RUNTIME_CHECK(crypto_cipher_chacha20 != NULL);
	}

	crypto_cipher_aes_128_ctr = EVP_CIPHER_fetch(NULL, "AES-128-CTR", NULL);
	RUNTIME_CHECK(crypto_cipher_aes_128_ctr != NULL);

	crypto_cipher_aes_256_ctr = EVP_CIPHER_fetch(NULL, "AES-256-CTR", NULL);
	RUNTIME_CHECK(crypto_cipher_aes_256_ctr != NULL);

	crypto_md_sha256 = EVP_MD_fetch(NULL, "sha256", NULL);
	RUNTIME_CHECK(crypto_md_sha256 != NULL);

	crypto_md_sha384 = EVP_MD_fetch(NULL, "sha384", NULL);
	RUNTIME_CHECK(crypto_md_sha384 != NULL);

	crypto_kdf_hkdf = EVP_KDF_fetch(NULL, "hkdf", NULL);
	RUNTIME_CHECK(crypto_kdf_hkdf != NULL);
}

#else /* !(OPENSSL_3_API_OR_NEWER) */

static void
quic_crypto_prefetch(void) {
	crypto_aead_aes_128_gcm = EVP_aes_128_gcm();
	RUNTIME_CHECK(crypto_aead_aes_128_gcm != NULL);

	crypto_aead_aes_256_gcm = EVP_aes_256_gcm();
	RUNTIME_CHECK(crypto_aead_aes_256_gcm != NULL);

	crypto_aead_aes_128_ccm = EVP_aes_128_ccm();
	RUNTIME_CHECK(crypto_aead_aes_128_ccm != NULL);

	if (!fips_mode_used) {
		crypto_aead_chacha20_poly1305 = EVP_chacha20_poly1305();
		RUNTIME_CHECK(crypto_aead_chacha20_poly1305 != NULL);

		crypto_cipher_chacha20 = EVP_chacha20();
		RUNTIME_CHECK(crypto_cipher_chacha20 != NULL);
	}

	crypto_cipher_aes_128_ctr = EVP_aes_128_ctr();
	RUNTIME_CHECK(crypto_cipher_aes_128_ctr != NULL);

	crypto_cipher_aes_256_ctr = EVP_aes_256_ctr();
	RUNTIME_CHECK(crypto_cipher_aes_256_ctr != NULL);

	crypto_md_sha256 = EVP_sha256();
	RUNTIME_CHECK(crypto_md_sha256 != NULL);

	crypto_md_sha384 = EVP_sha384();
	RUNTIME_CHECK(crypto_md_sha384 != NULL);
}

#endif /* OPENSSL_3_API_OR_NEWER */

static void
quic_crypto_prefetch_clear(void) {
	RUNTIME_CHECK(crypto_aead_aes_128_gcm != NULL);
	crypto_aead_aes_128_gcm = NULL;

	RUNTIME_CHECK(crypto_aead_aes_256_gcm != NULL);
	crypto_aead_aes_256_gcm = NULL;

	RUNTIME_CHECK(crypto_aead_aes_128_ccm != NULL);
	crypto_aead_aes_128_ccm = NULL;

	if (!fips_mode_used) {
		RUNTIME_CHECK(crypto_aead_chacha20_poly1305 != NULL);
		crypto_aead_chacha20_poly1305 = NULL;

		RUNTIME_CHECK(crypto_cipher_chacha20 != NULL);
		crypto_cipher_chacha20 = NULL;
	}

	RUNTIME_CHECK(crypto_cipher_aes_128_ctr != NULL);
	crypto_cipher_aes_128_ctr = NULL;

	RUNTIME_CHECK(crypto_cipher_aes_256_ctr != NULL);
	crypto_cipher_aes_256_ctr = NULL;

	RUNTIME_CHECK(crypto_md_sha256 != NULL);
	crypto_md_sha256 = NULL;

	RUNTIME_CHECK(crypto_md_sha384 != NULL);
	crypto_md_sha384 = NULL;

#ifdef OPENSSL_3_API_OR_NEWER
	RUNTIME_CHECK(crypto_kdf_hkdf != NULL);
	EVP_KDF_free(crypto_kdf_hkdf);
	crypto_kdf_hkdf = NULL;
#endif /* OPENSSL_3_API_OR_NEWER */
}

void
isc__quic_crypto_initialize(void) {
	if (quic_crypto_initialized) {
		return;
	}

	quic_crypto_initialized = true;
	fips_mode_used = isc_crypto_fips_mode();

	quic_crypto_prefetch();
}

void
isc__quic_crypto_shutdown(void) {
	if (!quic_crypto_initialized) {
		return;
	}

	quic_crypto_prefetch_clear();

	quic_crypto_initialized = false;
	fips_mode_used = false;
}

bool
isc__quic_crypto_tls_cipher_supported(const isc_tls_cipher_t *tls_cipher) {
	uint32_t tls_cipher_id;

	REQUIRE(tls_cipher != NULL);

	RUNTIME_CHECK(quic_crypto_initialized);

	tls_cipher_id = SSL_CIPHER_get_id(tls_cipher);

	switch (tls_cipher_id) {
	case TLS1_3_CK_AES_128_GCM_SHA256:
		return true;
	case TLS1_3_CK_AES_256_GCM_SHA384:
		return true;
	case TLS1_3_CK_CHACHA20_POLY1305_SHA256:
		return !fips_mode_used;
	case TLS1_3_CK_AES_128_CCM_SHA256:
		return true;
	}

	return false;
}

const EVP_CIPHER *
isc__quic_crypto_tls_cipher_aead(const isc_tls_cipher_t *tls_cipher) {
	uint32_t tls_cipher_id;

	REQUIRE(tls_cipher != NULL);

	RUNTIME_CHECK(quic_crypto_initialized);

	tls_cipher_id = SSL_CIPHER_get_id(tls_cipher);

	switch (tls_cipher_id) {
	case TLS1_3_CK_AES_128_GCM_SHA256:
		return crypto_aead_aes_128_gcm;
	case TLS1_3_CK_AES_256_GCM_SHA384:
		return crypto_aead_aes_256_gcm;
	case TLS1_3_CK_CHACHA20_POLY1305_SHA256:
		return crypto_aead_chacha20_poly1305;
	case TLS1_3_CK_AES_128_CCM_SHA256:
		return crypto_aead_aes_128_ccm;
	}

	return NULL;
}

size_t
isc__quic_crypto_aead_taglen(const EVP_CIPHER *aead) {
	REQUIRE(aead != NULL);

	RUNTIME_CHECK(quic_crypto_initialized);

	switch (EVP_CIPHER_nid(aead)) {
	case NID_aes_128_gcm:
	case NID_aes_256_gcm:
		return EVP_GCM_TLS_TAG_LEN;
	case NID_chacha20_poly1305:
		return EVP_CHACHAPOLY_TLS_TAG_LEN;
	case NID_aes_128_ccm:
		return EVP_CCM_TLS_TAG_LEN;
	}

	UNREACHABLE();
}

size_t
isc__quic_crypto_aead_keylen(const EVP_CIPHER *aead) {
	REQUIRE(aead != NULL);

	RUNTIME_CHECK(quic_crypto_initialized);

	return (size_t)EVP_CIPHER_key_length(aead);
}

size_t
isc__quic_crypto_aead_ivlen(const EVP_CIPHER *aead) {
	REQUIRE(aead != NULL);

	RUNTIME_CHECK(quic_crypto_initialized);

	return (size_t)EVP_CIPHER_iv_length(aead);
}

size_t
isc__quic_crypto_aead_packet_protection_ivlen(const EVP_CIPHER *aead) {
	/* By RFC9001, Section 5.1 it is at least 8 bytes long */
	return ISC_MAX(8, isc__quic_crypto_aead_ivlen(aead));
}

uint64_t
isc__quic_crypto_tls_cipher_aead_max_encryption(
	const isc_tls_cipher_t *tls_cipher) {
	uint32_t tls_cipher_id;

	REQUIRE(tls_cipher != NULL);

	RUNTIME_CHECK(quic_crypto_initialized);

	tls_cipher_id = SSL_CIPHER_get_id(tls_cipher);

	switch (tls_cipher_id) {
	case TLS1_3_CK_AES_128_GCM_SHA256:
	case TLS1_3_CK_AES_256_GCM_SHA384:
		return QUIC_CRYPTO_MAX_ENCRYPTION_AES_GCM;
	case TLS1_3_CK_CHACHA20_POLY1305_SHA256:
		return QUIC_CRYPTO_MAX_ENCRYPTION_CHACHA20_POLY1305;
	case TLS1_3_CK_AES_128_CCM_SHA256:
		return QUIC_CRYPTO_MAX_ENCRYPTION_AES_CCM;
	}

	UNREACHABLE();
}

uint64_t
isc__quic_crypto_tls_cipher_aead_max_decyption_failures(
	const isc_tls_cipher_t *tls_cipher) {
	uint32_t tls_cipher_id;

	REQUIRE(tls_cipher != NULL);

	RUNTIME_CHECK(quic_crypto_initialized);

	tls_cipher_id = SSL_CIPHER_get_id(tls_cipher);

	switch (tls_cipher_id) {
	case TLS1_3_CK_AES_128_GCM_SHA256:
	case TLS1_3_CK_AES_256_GCM_SHA384:
		return QUIC_CRYPTO_MAX_DECRYPTION_FAILURES_AES_GCM;
	case TLS1_3_CK_CHACHA20_POLY1305_SHA256:
		return QUIC_CRYPTO_MAX_DECRYPTION_FAILURES_CHACHA20_POLY1305;
	case TLS1_3_CK_AES_128_CCM_SHA256:
		return QUIC_CRYPTO_MAX_DECRYPTION_FAILURES_AES_CCM;
	}

	UNREACHABLE();
}

const EVP_MD *
isc__quic_crypto_tls_cipher_md(const isc_tls_cipher_t *tls_cipher) {
	uint32_t tls_cipher_id;

	REQUIRE(tls_cipher != NULL);

	RUNTIME_CHECK(quic_crypto_initialized);

	tls_cipher_id = SSL_CIPHER_get_id(tls_cipher);

	switch (tls_cipher_id) {
	case TLS1_3_CK_AES_128_GCM_SHA256:
	case TLS1_3_CK_CHACHA20_POLY1305_SHA256:
	case TLS1_3_CK_AES_128_CCM_SHA256:
		return crypto_md_sha256;
	case TLS1_3_CK_AES_256_GCM_SHA384:
		return crypto_md_sha384;
	}

	return NULL;
}

size_t
isc__quic_crypto_md_hashlen(const EVP_MD *md) {
	REQUIRE(md != NULL);

	RUNTIME_CHECK(quic_crypto_initialized);

	return (size_t)EVP_MD_size(md);
}

const EVP_CIPHER *
isc__quic_crypto_tls_cipher_hp(const isc_tls_cipher_t *tls_cipher) {
	uint32_t tls_cipher_id;

	REQUIRE(tls_cipher != NULL);

	RUNTIME_CHECK(quic_crypto_initialized);

	tls_cipher_id = SSL_CIPHER_get_id(tls_cipher);

	switch (tls_cipher_id) {
	case TLS1_3_CK_AES_128_GCM_SHA256:
	case TLS1_3_CK_AES_128_CCM_SHA256:
		return crypto_cipher_aes_128_ctr;
	case TLS1_3_CK_AES_256_GCM_SHA384:
		return crypto_cipher_aes_256_ctr;
	case TLS1_3_CK_CHACHA20_POLY1305_SHA256:
		return crypto_cipher_chacha20;
		break;
	}

	return NULL;
}

const EVP_MD *
isc__quic_crypto_md_sha256(void) {
	RUNTIME_CHECK(quic_crypto_initialized);

	return crypto_md_sha256;
}

const EVP_CIPHER *
isc__quic_crypto_aead_aes_128_gcm(void) {
	RUNTIME_CHECK(quic_crypto_initialized);

	return crypto_aead_aes_128_gcm;
}

const EVP_CIPHER *
isc__quic_crypto_cipher_aes_128_ctr(void) {
	RUNTIME_CHECK(quic_crypto_initialized);

	return crypto_cipher_aes_128_ctr;
}

bool
isc__quic_crypto_hkdf_extract(uint8_t *dest, const EVP_MD *md,
			      const uint8_t *secret, const size_t secretlen,
			      const uint8_t *salt, const size_t saltlen) {
	REQUIRE(dest != NULL);
	REQUIRE(md != NULL);
	REQUIRE(secret != NULL);
	REQUIRE(secretlen > 0);

	RUNTIME_CHECK(quic_crypto_initialized);
#ifdef OPENSSL_3_API_OR_NEWER
	EVP_KDF_CTX *kctx = EVP_KDF_CTX_new(crypto_kdf_hkdf);
	int mode = EVP_KDF_HKDF_MODE_EXTRACT_ONLY;
	OSSL_PARAM params[] = {
		OSSL_PARAM_construct_int(OSSL_KDF_PARAM_MODE, &mode),
		OSSL_PARAM_construct_utf8_string(
			OSSL_KDF_PARAM_DIGEST, (char *)EVP_MD_get0_name(md), 0),
		OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY,
						  (void *)secret, secretlen),
		OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT,
						  (void *)salt, saltlen),
		OSSL_PARAM_construct_end(),
	};
	bool ret = true;

	if (EVP_KDF_derive(kctx, dest, (size_t)EVP_MD_size(md), params) <= 0) {
		ret = false;
	}

	EVP_KDF_CTX_free(kctx);

	return ret;
#else  /* !( OPENSSL_3_API_OR_NEWER) */
	bool ret = true;
	EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
	size_t destlen = (size_t)EVP_MD_size(md);

	if (pctx == NULL) {
		return false;
	}

	if (EVP_PKEY_derive_init(pctx) != 1 ||
	    EVP_PKEY_CTX_hkdf_mode(pctx, EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY) !=
		    1 ||
	    EVP_PKEY_CTX_set_hkdf_md(pctx, md) != 1 ||
	    EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt, (int)saltlen) != 1 ||
	    EVP_PKEY_CTX_set1_hkdf_key(pctx, secret, (int)secretlen) != 1 ||
	    EVP_PKEY_derive(pctx, dest, &destlen) != 1)
	{
		ret = false;
	}

	EVP_PKEY_CTX_free(pctx);

	return ret;
#endif /* OPENSSL_3_API_OR_NEWER */
}

bool
isc__quic_crypto_hkdf_expand(uint8_t *dest, size_t destlen, const EVP_MD *md,
			     const uint8_t *secret, const size_t secretlen,
			     const uint8_t *info, const size_t infolen) {
	REQUIRE(dest != NULL);
	REQUIRE(destlen > 0);
	REQUIRE(md != NULL);
	REQUIRE(secret != NULL);
	REQUIRE(secretlen > 0);
	REQUIRE(info != NULL);
	REQUIRE(infolen > 0);

	RUNTIME_CHECK(quic_crypto_initialized);
#ifdef OPENSSL_3_API_OR_NEWER
	EVP_KDF_CTX *kdf_ctx = EVP_KDF_CTX_new(crypto_kdf_hkdf);
	int mode = EVP_KDF_HKDF_MODE_EXPAND_ONLY;
	OSSL_PARAM params[] = {
		OSSL_PARAM_construct_int(OSSL_KDF_PARAM_MODE, &mode),
		OSSL_PARAM_construct_utf8_string(
			OSSL_KDF_PARAM_DIGEST, (char *)EVP_MD_get0_name(md), 0),
		OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY,
						  (void *)secret, secretlen),
		OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO,
						  (void *)info, infolen),
		OSSL_PARAM_construct_end(),
	};
	bool ret = true;

	if (EVP_KDF_derive(kdf_ctx, dest, destlen, params) <= 0) {
		ret = false;
	}

	EVP_KDF_CTX_free(kdf_ctx);

	return ret;
#else  /* !(OPENSSL_3_API_OR_NEWER) */
	bool ret = true;
	EVP_PKEY_CTX *pkey_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);

	if (pkey_ctx == NULL) {
		return false;
	}

	if (EVP_PKEY_derive_init(pkey_ctx) != 1 ||
	    EVP_PKEY_CTX_hkdf_mode(pkey_ctx, EVP_PKEY_HKDEF_MODE_EXPAND_ONLY) !=
		    1 ||
	    EVP_PKEY_CTX_set_hkdf_md(pkey_ctx, md) != 1 ||
	    EVP_PKEY_CTX_set1_hkdf_salt(pkey_ctx, (const unsigned char *)"",
					0) != 1 ||
	    EVP_PKEY_CTX_set1_hkdf_key(pkey_ctx, secret, (int)secretlen) != 1 ||
	    EVP_PKEY_CTX_add1_hkdf_info(pkey_ctx, info, (int)infolen) != 1 ||
	    EVP_PKEY_derive(pkey_ctx, dest, &destlen) != 1)
	{
		ret = false;
	}

	EVP_PKEY_CTX_free(pkey_ctx);

	return ret;
#endif /* OPENSSL_3_API_OR_NEWER */
}

/*
 * See RFC8446, Section 7.1:
 * https://www.rfc-editor.org/rfc/rfc8446#section-7.1
 *
 *
 *      struct {
 *          uint16 length = Length;
 *          opaque label<7..255> = "tls13 " + Label;
 *          opaque context<0..255> = Context;
 *      } HkdfLabel;
 */
bool
isc__quic_crypto_hkdf_expand_label(uint8_t *dest, size_t destlen,
				   const EVP_MD *md, const uint8_t *secret,
				   const size_t secretlen, const uint8_t *label,
				   const size_t labellen) {
	uint8_t label_start[] = "tls13 ";
	uint8_t hkdf_buf[UINT8_MAX];
	isc_buffer_t hkdf_label = { 0 };
	isc_region_t hkdf_data = { 0 };

	RUNTIME_CHECK(quic_crypto_initialized);

	isc_buffer_init(&hkdf_label, hkdf_buf, sizeof(hkdf_buf));

	isc_buffer_putuint16(&hkdf_label, destlen);
	isc_buffer_putuint8(&hkdf_label,
			    (uint8_t)(sizeof(label_start) - 1 + labellen));
	isc_buffer_putmem(&hkdf_label, label_start, sizeof(label_start) - 1);
	isc_buffer_putmem(&hkdf_label, label, labellen);
	/* Zero-sized "Context" */
	isc_buffer_putuint8(&hkdf_label, 0);

	isc_buffer_usedregion(&hkdf_label, &hkdf_data);

	return isc__quic_crypto_hkdf_expand(dest, destlen, md, secret,
					    secretlen, hkdf_data.base,
					    hkdf_data.length);
}

bool
isc__quic_crypto_hkdf(uint8_t *dest, size_t destlen, const EVP_MD *md,
		      const uint8_t *secret, size_t secretlen,
		      const uint8_t *salt, size_t saltlen, const uint8_t *info,
		      size_t infolen) {
	REQUIRE(dest != NULL);
	REQUIRE(destlen > 0);
	REQUIRE(md != NULL);
	REQUIRE(secret != NULL);
	REQUIRE(secretlen > 0);
	REQUIRE(info != NULL);
	REQUIRE(infolen > 0);

	RUNTIME_CHECK(quic_crypto_initialized);
#ifdef OPENSSL_3_API_OR_NEWER
	EVP_KDF_CTX *kctx = EVP_KDF_CTX_new(crypto_kdf_hkdf);
	OSSL_PARAM params[] = {
		OSSL_PARAM_construct_utf8_string(
			OSSL_KDF_PARAM_DIGEST, (char *)EVP_MD_get0_name(md), 0),
		OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY,
						  (void *)secret, secretlen),
		OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT,
						  (void *)salt, saltlen),
		OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO,
						  (void *)info, infolen),
		OSSL_PARAM_construct_end(),
	};
	bool ret = true;

	if (EVP_KDF_derive(kctx, dest, destlen, params) <= 0) {
		ret = false;
	}

	EVP_KDF_CTX_free(kctx);

	return ret;
#else  /* !(OPENSSL_3_API_OR_NEWER) */
	bool ret = true;
	EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
	if (pctx == NULL) {
		return false;
	}

	if (EVP_PKEY_derive_init(pctx) != 1 ||
	    EVP_PKEY_CTX_hkdf_mode(
		    pctx, EVP_PKEY_HKDEF_MODE_EXTRACT_AND_EXPAND) != 1 ||
	    EVP_PKEY_CTX_set_hkdf_md(pctx, md) != 1 ||
	    EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt, (int)saltlen) != 1 ||
	    EVP_PKEY_CTX_set1_hkdf_key(pctx, secret, (int)secretlen) != 1 ||
	    EVP_PKEY_CTX_add1_hkdf_info(pctx, info, (int)infolen) != 1 ||
	    EVP_PKEY_derive(pctx, dest, &destlen) != 1)
	{
		ret = false;
	}

	EVP_PKEY_CTX_free(pctx);

	return ret;
#endif /* OPENSSL_3_API_OR_NEWER */
}

bool
isc__quic_crypto_aead_ctx_encrypt_create(EVP_CIPHER_CTX **out_aead_ctx,
					 const EVP_CIPHER *aead,
					 const uint8_t *key, size_t noncelen) {
	REQUIRE(out_aead_ctx != NULL && *out_aead_ctx == NULL);
	REQUIRE(aead != NULL);
	REQUIRE(key != NULL);

	RUNTIME_CHECK(quic_crypto_initialized);

	int cipher_nid = EVP_CIPHER_nid(aead);
	EVP_CIPHER_CTX *aead_ctx = NULL;
	size_t taglen = 0;
#ifdef OPENSSL_3_API_OR_NEWER
	OSSL_PARAM params[3];
#endif /* OPENSSL_3_API_OR_NEWER */

	taglen = isc__quic_crypto_aead_taglen(aead);

	aead_ctx = EVP_CIPHER_CTX_new();
	if (aead_ctx == NULL) {
		return false;
	}

#ifdef OPENSSL_3_API_OR_NEWER
	params[0] = OSSL_PARAM_construct_size_t(OSSL_CIPHER_PARAM_IVLEN,
						&noncelen);

	if (cipher_nid == NID_aes_128_ccm) {
		params[1] = OSSL_PARAM_construct_octet_string(
			OSSL_CIPHER_PARAM_AEAD_TAG, NULL, taglen);
		params[2] = OSSL_PARAM_construct_end();
	} else {
		params[1] = OSSL_PARAM_construct_end();
	}
#endif /* OPENSSL_3_API_OR_NEWER */
	if (!EVP_EncryptInit_ex(aead_ctx, aead, NULL, NULL, NULL) ||
#ifdef OPENSSL_3_API_OR_NEWER
	    !EVP_CIPHER_CTX_set_params(aead_ctx, params) ||
#else  /* !(OPENSSL_3_API_OR_NEWER) */
	    !EVP_CIPHER_CTX_ctrl(aead_ctx, EVP_CTRL_AEAD_SET_IVLEN,
				 (int)noncelen, NULL) ||
	    (cipher_nid == NID_aes_128_ccm &&
	     !EVP_CIPHER_CTX_ctrl(aead_ctx, EVP_CTRL_AEAD_SET_TAG, (int)taglen,
				  NULL)) ||
#endif /* OPENSSL_3_API_OR_NEWER */
	    !EVP_EncryptInit_ex(aead_ctx, NULL, NULL, key, NULL))
	{
		EVP_CIPHER_CTX_free(aead_ctx);
		return false;
	}

	*out_aead_ctx = aead_ctx;

	return true;
}

bool
isc__quic_crypto_aead_ctx_decrypt_create(EVP_CIPHER_CTX **out_aead_ctx,
					 const EVP_CIPHER *aead,
					 const uint8_t *key, size_t noncelen) {
	REQUIRE(out_aead_ctx != NULL && *out_aead_ctx == NULL);
	REQUIRE(aead != NULL);
	REQUIRE(key != NULL);

	RUNTIME_CHECK(quic_crypto_initialized);

	EVP_CIPHER_CTX *actx = NULL;
	int cipher_nid = EVP_CIPHER_nid(aead);
	size_t taglen = isc__quic_crypto_aead_taglen(aead);
#ifdef OPENSSL_3_API_OR_NEWER
	OSSL_PARAM params[3];
#endif /* OPENSSL_3_API_OR_NEWER */

	actx = EVP_CIPHER_CTX_new();
	if (actx == NULL) {
		return -1;
	}

#ifdef OPENSSL_3_API_OR_NEWER
	params[0] = OSSL_PARAM_construct_size_t(OSSL_CIPHER_PARAM_IVLEN,
						&noncelen);

	if (cipher_nid == NID_aes_128_ccm) {
		params[1] = OSSL_PARAM_construct_octet_string(
			OSSL_CIPHER_PARAM_AEAD_TAG, NULL, taglen);
		params[2] = OSSL_PARAM_construct_end();
	} else {
		params[1] = OSSL_PARAM_construct_end();
	}
#endif /*OPENSSL_3_API_OR_NEWER */

	if (!EVP_DecryptInit_ex(actx, aead, NULL, NULL, NULL) ||
#ifdef OPENSSL_3_API_OR_NEWER
	    !EVP_CIPHER_CTX_set_params(actx, params) ||
#else  /* !(OPENSSL_3_API_OR_NEWER) */
	    !EVP_CIPHER_CTX_ctrl(actx, EVP_CTRL_AEAD_SET_IVLEN, (int)noncelen,
				 NULL) ||
	    (cipher_nid == NID_aes_128_ccm &&
	     !EVP_CIPHER_CTX_ctrl(actx, EVP_CTRL_AEAD_SET_TAG, (int)taglen,
				  NULL)) ||
#endif /* !(OPENSSL_3_API_OR_NEWER) */
	    !EVP_DecryptInit_ex(actx, NULL, NULL, key, NULL))
	{
		EVP_CIPHER_CTX_free(actx);
		return false;
	}

	*out_aead_ctx = actx;

	return true;
}

bool
isc__quic_crypto_aead_encrypt(uint8_t *dest, const EVP_CIPHER *aead,
			      EVP_CIPHER_CTX *aead_ctx, const uint8_t *nonce,
			      const uint8_t *plaintext,
			      const size_t plaintextlen, const uint8_t *aad,
			      const size_t aadlen) {
	REQUIRE(dest != NULL);
	REQUIRE(aead != NULL);
	REQUIRE(aead_ctx != NULL);
	REQUIRE(nonce != NULL);

	RUNTIME_CHECK(quic_crypto_initialized);

	size_t taglen = isc__quic_crypto_aead_taglen(aead);
	int cipher_nid = EVP_CIPHER_nid(aead);
	int len = 0;
#ifdef OPENSSL_3_API_OR_NEWER
	OSSL_PARAM params[] = {
		OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG,
						  dest + plaintextlen, taglen),
		OSSL_PARAM_construct_end(),
	};
#endif /* OPENSSL_3_API_OR_NEWER */

	if (!EVP_EncryptInit_ex(aead_ctx, NULL, NULL, NULL, nonce) ||
	    (cipher_nid == NID_aes_128_ccm &&
	     !EVP_EncryptUpdate(aead_ctx, NULL, &len, NULL,
				(int)plaintextlen)) ||
	    !EVP_EncryptUpdate(aead_ctx, NULL, &len, aad, (int)aadlen) ||
	    !EVP_EncryptUpdate(aead_ctx, dest, &len, plaintext,
			       (int)plaintextlen) ||
	    !EVP_EncryptFinal_ex(aead_ctx, dest + len, &len) ||
#ifdef OPENSSL_3_API_OR_NEWER
	    !EVP_CIPHER_CTX_get_params(aead_ctx, params)
#else  /* !(OPENSSL_3_API_OR_NEWER) */
	    !EVP_CIPHER_CTX_ctrl(aead_ctx, EVP_CTRL_AEAD_GET_TAG, (int)taglen,
				 dest + plaintextlen)
#endif /* OPENSSL_3_API_OR_NEWER */
	)
	{
		return false;
	}

	return true;
}

bool
isc__quic_crypto_aead_decrypt(uint8_t *dest, const EVP_CIPHER *aead,
			      EVP_CIPHER_CTX *aead_ctx, const uint8_t *nonce,
			      const uint8_t *ciphertext, size_t ciphertextlen,
			      const uint8_t *aad, const size_t aadlen) {
	REQUIRE(dest != NULL);
	REQUIRE(aead != NULL);
	REQUIRE(aead_ctx != NULL);
	REQUIRE(nonce != NULL);
	REQUIRE(ciphertext != NULL);
	REQUIRE(ciphertextlen > 0);

	size_t taglen = isc__quic_crypto_aead_taglen(aead);
	int cipher_nid = EVP_CIPHER_nid(aead);
	int len = 0;
	const uint8_t *tag = NULL;
#ifdef OPENSSL_3_API_OR_NEWER
	OSSL_PARAM params[2];
#endif /* OPENSSL_3_API_OR_NEWER */

	if (taglen > ciphertextlen) {
		return false;
	}

	ciphertextlen -= taglen;
	tag = ciphertext + ciphertextlen;

#ifdef OPENSSL_3_API_OR_NEWER
	params[0] = OSSL_PARAM_construct_octet_string(
		OSSL_CIPHER_PARAM_AEAD_TAG, (void *)tag, taglen);
	params[1] = OSSL_PARAM_construct_end();
#endif /* OPENSSL_3_API_OR_NEWER */

	if (!EVP_DecryptInit_ex(aead_ctx, NULL, NULL, NULL, nonce) ||
#ifdef OPENSSL_3_API_OR_NEWER
	    !EVP_CIPHER_CTX_set_params(aead_ctx, params) ||
#else  /* !(OPENSSL_3_API_OR_NEWER) */
	    !EVP_CIPHER_CTX_ctrl(aead_ctx, EVP_CTRL_AEAD_SET_TAG, (int)taglen,
				 (uint8_t *)tag) ||
#endif /* !(OPENSSL_3_API_OR_NEWER) */
	    (cipher_nid == NID_aes_128_ccm &&
	     !EVP_DecryptUpdate(aead_ctx, NULL, &len, NULL,
				(int)ciphertextlen)) ||
	    !EVP_DecryptUpdate(aead_ctx, NULL, &len, aad, (int)aadlen) ||
	    !EVP_DecryptUpdate(aead_ctx, dest, &len, ciphertext,
			       (int)ciphertextlen) ||
	    (cipher_nid != NID_aes_128_ccm &&
	     !EVP_DecryptFinal_ex(aead_ctx, dest + ciphertextlen, &len)))
	{
		return false;
	}

	return true;
}

bool
isc__quic_crypto_hp_cipher_ctx_encrypt_create(EVP_CIPHER_CTX **out_hp_cipher_ctx,
					      const EVP_CIPHER *hp_cipher,
					      const uint8_t *key) {
	EVP_CIPHER_CTX *cipher_ctx = NULL;

	REQUIRE(out_hp_cipher_ctx != NULL && *out_hp_cipher_ctx == NULL);
	REQUIRE(hp_cipher != NULL);
	REQUIRE(key != NULL);

	RUNTIME_CHECK(quic_crypto_initialized);

	cipher_ctx = EVP_CIPHER_CTX_new();
	if (cipher_ctx == NULL) {
		return false;
	}

	if (!EVP_EncryptInit_ex(cipher_ctx, hp_cipher, NULL, key, NULL)) {
		EVP_CIPHER_CTX_free(cipher_ctx);
		return false;
	}

	*out_hp_cipher_ctx = cipher_ctx;

	return true;
}

/*
 * See RFC9001, sections 5.4.1-5.4.4 on QUIC header protection
 * details.  OpenSSL's EVP API (aka "EnVeloPe") hides gory details of
 * different algorithms here.
 */
bool
isc__quic_crypto_hp_mask(uint8_t *dest, EVP_CIPHER_CTX *hp_ctx,
			 const uint8_t *sample) {
	static const uint8_t mask[ISC__QUIC_CRYPTO_HP_MASK_LEN] = { 0 };
	int len = 0;

	REQUIRE(dest != NULL);
	REQUIRE(hp_ctx != NULL);
	REQUIRE(sample != NULL);

	RUNTIME_CHECK(quic_crypto_initialized);

	if (!EVP_EncryptInit_ex(hp_ctx, NULL, NULL, NULL, sample) ||
	    !EVP_EncryptUpdate(hp_ctx, dest, &len, mask, sizeof(mask)) ||
	    !EVP_EncryptFinal_ex(hp_ctx, dest + sizeof(mask), &len))
	{
		return false;
	}

	return true;
}

void
isc__quic_crypto_cipher_ctx_free(EVP_CIPHER_CTX **pcipher_ctx) {
	REQUIRE(pcipher_ctx != NULL && *pcipher_ctx != NULL);

	RUNTIME_CHECK(quic_crypto_initialized);

	EVP_CIPHER_CTX_free(*pcipher_ctx);
	*pcipher_ctx = NULL;
}
