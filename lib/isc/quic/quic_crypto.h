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

#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/ssl.h>

#include <isc/tls.h>
#include <isc/types.h>

/*
 * The following constants are either taken or derived from RFC9001, RFC9369
 * (QUICv2).
 */
#define ISC__QUIC_CRYPTO_HP_MASK_LEN (5)

/* Client initial key label */
#define ISC__QUIC_CRYPTO_CLIENT_IN_LABEL "client in"
#define ISC__QUIC_CRYPTO_CLIENT_IN_LABEL_LEN \
	(sizeof(ISC__QUIC_CRYPTO_CLIENT_IN_LABEL) - 1)

/* Server initial key label */
#define ISC__QUIC_CRYPTO_SERVER_IN_LABEL "server in"
#define ISC__QUIC_CRYPTO_SERVER_IN_LABEL_LEN \
	(sizeof(ISC__QUIC_CRYPTO_SERVER_IN_LABEL) - 1)

/* Salt to derive initial secret for QUIC */
#define ISC__QUIC_CRYPTO_INITIAL_SALT_V1                                       \
	"\x38\x76\x2c\xf7\xf5\x59\x34\xb3\x4d\x17\x9a\xe6\xa4\xc8\x0c\xad\xcc" \
	"\xbb\x7f\x0a"
#define ISC__QUIC_CRYPTO_INITIAL_SALT_V1_LEN \
	(sizeof(ISC__QUIC_CRYPTO_INITIAL_SALT_V1) - 1)

/* QUIC key label */
#define ISC__QUIC_CRYPTO_QUIC_KEY_LABEL_V1 "quic key"
#define ISC__QUIC_CRYPTO_QUIC_KEY_LABEL_V1_LEN \
	(sizeof(ISC__QUIC_CRYPTO_QUIC_KEY_LABEL_V1) - 1)

/* QUIC IV label */
#define ISC__QUIC_CRYPTO_QUIC_IV_LABEL_V1 "quic iv"
#define ISC__QUIC_CRYPTO_QUIC_IV_LABEL_V1_LEN \
	((sizeof(ISC__QUIC_CRYPTO_QUIC_IV_LABEL_V1) - 1))

/* QUIC header protection label */
#define ISC__QUIC_CRYPTO_QUIC_HP_LABEL_V1 "quic hp"
#define ISC__QUIC_CRYPTO_QUIC_HP_LABEL_V1_LEN \
	((sizeof(ISC__QUIC_CRYPTO_QUIC_HP_LABEL_V1) - 1))

/* QUIC key update label */
#define ISC__QUIC_CRYPTO_QUIC_KU_LABEL_V1 "quic ku"
#define ISC__QUIC_CRYPTO_QUIC_KU_LABEL_V1_LEN \
	((sizeof(ISC__QUIC_CRYPTO_QUIC_KU_LABEL_V1) - 1))

/* Salt to derive initial secret for QUICv2 */
#define ISC__QUIC_CRYPTO_INITIAL_SALT_V2                                       \
	"\x0d\xed\xe3\xde\xf7\x00\xa6\xdb\x81\x93\x81\xbe\x6e\x26\x9d\xcb\xf9" \
	"\xbd\x2e\xd9"
#define ISC__QUIC_CRYPTO_INITIAL_SALT_V2_LEN \
	(sizeof(ISC__QUIC_CRYPTO_INITIAL_SALT_V2) - 1)

/* QUICv2 key label */
#define ISC__QUIC_CRYPTO_QUIC_KEY_LABEL_V2 "quicv2 key"
#define ISC__QUIC_CRYPTO_QUIC_KEY_LABEL_V2_LEN \
	(sizeof(ISC__QUIC_CRYPTO_QUIC_KEY_LABEL_V2) - 1)

/* QUICv2 IV label */
#define ISC__QUIC_CRYPTO_QUIC_IV_LABEL_V2 "quicv2 iv"
#define ISC__QUIC_CRYPTO_QUIC_IV_LABEL_V2_LEN \
	((sizeof(ISC__QUIC_CRYPTO_QUIC_IV_LABEL_V2) - 1))

/* QUICv2 header protection label */
#define ISC__QUIC_CRYPTO_QUIC_HP_LABEL_V2 "quicv2 hp"
#define ISC__QUIC_CRYPTO_QUIC_HP_LABEL_V2_LEN \
	((sizeof(ISC__QUIC_CRYPTO_QUIC_HP_LABEL_V2) - 1))

/* QUICv2 key update label */
#define ISC__QUIC_CRYPTO_QUIC_KU_LABEL_V2 "quicv2 ku"
#define ISC__QUIC_CRYPTO_QUIC_KU_LABEL_V2_LEN \
	((sizeof(ISC__QUIC_CRYPTO_QUIC_KU_LABEL_V2) - 1))

/* These are defined in RFC8446 */
#define ISC__QUIC_CRYPTO_KEY_LABEL     "key"
#define ISC__QUIC_CRYPTO_KEY_LABEL_LEN (sizeof(ISC__QUIC_CRYPTO_KEY_LABEL) - 1)

#define ISC__QUIC_CRYPTO_IV_LABEL     "iv"
#define ISC__QUIC_CRYPTO_IV_LABEL_LEN ((sizeof(ISC__QUIC_CRYPTO_IV_LABEL) - 1))

bool
isc__quic_crypto_tls_cipher_supported(const isc_tls_cipher_t *tls_cipher);
/*%<
 * Check if the given TLS cipher can be used for QUIC.
 *
 * Requires:
 *\li	'tls_cipher' != NULL.
 */

const EVP_CIPHER *
isc__quic_crypto_tls_cipher_aead(const isc_tls_cipher_t *tls_cipher);
/*%<
 * Return the AEAD-scheme associated with the given TLS cipher.
 *
 * Requires:
 *\li	'tls_cipher' != NULL.
 */

size_t
isc__quic_crypto_aead_taglen(const EVP_CIPHER *aead);
/*%<
 * Return the tag length (overhead) for the given AEAD-scheme.
 *
 * Requires:
 *\li	'aead' != NULL.
 */

size_t
isc__quic_crypto_aead_keylen(const EVP_CIPHER *aead);
/*%<
 * Return the tag length for the given AEAD-scheme.
 *
 * Requires:
 *\li	'aead' != NULL.
 */

size_t
isc__quic_crypto_aead_ivlen(const EVP_CIPHER *aead);
/*%<
 * Return the IV (initialization vector) length for the given AEAD-scheme.
 *
 * Requires:
 *\li	'aead' != NULL.
 */

size_t
isc__quic_crypto_aead_packet_protection_ivlen(const EVP_CIPHER *aead);
/*%<
 * Return the packet protection IV (initialization vector) length for the given
 * AEAD-scheme.
 *
 * Requires:
 *\li	'aead' != NULL.
 */

uint64_t
isc__quic_crypto_tls_cipher_aead_max_encryption(
	const isc_tls_cipher_t *tls_cipher);
/*%<
 * Return the max encryption limit for the AEAD-scheme associated with the given
 * TLS cipher.
 *
 * Requires:
 *\li	'tls_cipher' != NULL.
 */

uint64_t
isc__quic_crypto_tls_cipher_aead_max_decyption_failures(
	const isc_tls_cipher_t *tls_cipher);
/*%<
 * Return the max decryption failures limit for the AEAD-scheme
 * associated with the given TLS cipher.
 *
 * Requires:
 *\li	'tls_cipher' != NULL.
 */

const EVP_MD *
isc__quic_crypto_tls_cipher_md(const isc_tls_cipher_t *tls_cipher);
/*%<
 * Return the message digest function associated with the given TLS cipher.
 *
 * Requires:
 *\li	'tls_cipher' != NULL.
 */

size_t
isc__quic_crypto_md_hashlen(const EVP_MD *md);
/*%<
 * Return the message digest (hash) size.
 *
 * Requires:
 *\li	'md' != NULL.
 */

const EVP_CIPHER *
isc__quic_crypto_tls_cipher_hp(const isc_tls_cipher_t *tls_cipher);
/*%<
 * Return the QUIC header protection cipher associated with the given TLS
 * cipher.
 *
 * Requires:
 *\li	'tls_cipher' != NULL.
 */

const EVP_MD *
isc__quic_crypto_md_sha256(void);
/*%<
 * Return the SHA256 message digest function.
 */

const EVP_CIPHER *
isc__quic_crypto_aead_aes_128_gcm(void);
/*%<
 * Return the AES-128-GCM AEAD-scheme.
 */

const EVP_CIPHER *
isc__quic_crypto_cipher_aes_128_ctr(void);
/*%<
 * Return the AES-128-CTR cipher.
 */

bool
isc__quic_crypto_hkdf_extract(uint8_t *dest, const EVP_MD *md,
			      const uint8_t *secret, const size_t secretlen,
			      const uint8_t *salt, const size_t saltlen);
/*%<
 * Perform "HKDF-Extract" operation.
 *
 * The caller is responsible to specify the destination buffer that
 * has enough capacity to store the output.
 *
 * See RFC5869 for more details.
 *
 * Requires:
 *\li	'dest' != NULL;
 *\li	'md' != NULL;
 *\li	'secret' != NULL;
 *\li	'secretlen' > 0.
 */

bool
isc__quic_crypto_hkdf_expand(uint8_t *dest, size_t destlen, const EVP_MD *md,
			     const uint8_t *secret, const size_t secretlen,
			     const uint8_t *info, const size_t infolen);
/*%<
 * Perform "HKDF-Expand" operation.
 *
 * See RFC5869 for more details.
 *
 * Requires:
 *\li	'dest' != NULL;
 *\li	'destlen' > 0;
 *\li	'md' != NULL;
 *\li	'secret' != NULL;
 *\li	'secretlen' > 0;
 *\li	'info' != NULL;
 *\li	'infolen' > 0.
 */

bool
isc__quic_crypto_hkdf_expand_label(uint8_t *dest, size_t destlen,
				   const EVP_MD *md, const uint8_t *secret,
				   const size_t secretlen, const uint8_t *label,
				   const size_t labellen);
/*%<
 * Perform "HKDF-Expand-Label" operation as defined for TLSv1.3.
 *
 * See RFC8446, Section 7.1 for more details.
 *
 * Requires:
 *\li	'dest' != NULL;
 *\li	'destlen' > 0;
 *\li	'md' != NULL;
 *\li	'secret' != NULL;
 *\li	'secretlen' > 0;
 *\li	'label' != NULL;
 *\li	'labellen' > 0.
 */

bool
isc__quic_crypto_hkdf(uint8_t *dest, size_t destlen, const EVP_MD *md,
		      const uint8_t *secret, size_t secretlen,
		      const uint8_t *salt, size_t saltlen, const uint8_t *info,
		      size_t infolen);
/*%<
 * Perform "HKDF" operation.
 *
 * See RFC5869 for more details.
 *
 * Requires:
 *\li	'dest' != NULL;
 *\li	'destlen' > 0;
 *\li	'md' != NULL;
 *\li	'secret' != NULL;
 *\li	'secretlen' > 0;
 *\li	'info' != NULL;
 *\li	'infolen' > 0.
 */

bool
isc__quic_crypto_aead_ctx_encrypt_create(EVP_CIPHER_CTX **out_aead_ctx,
					 const EVP_CIPHER *aead,
					 const uint8_t *key, size_t noncelen);
/*%<
 * Create AEAD encryption context.
 *
 * Requires:
 *\li	'out_aead_ctx' != NULL && '*out_aead_ctx' == NULL;
 *\li	'aead' != NULL;
 *\li	'key' != NULL.
 */

bool
isc__quic_crypto_aead_ctx_decrypt_create(EVP_CIPHER_CTX **out_aead_ctx,
					 const EVP_CIPHER *aead,
					 const uint8_t *key, size_t noncelen);
/*%<
 * Create AEAD decryption context.
 *
 * Requires:
 *\li	'out_aead_ctx' != NULL && '*out_aead_ctx' == NULL;
 *\li	'aead' != NULL;
 *\li	'key' != NULL.
 */

bool
isc__quic_crypto_aead_encrypt(uint8_t *dest, const EVP_CIPHER *aead,
			      EVP_CIPHER_CTX *aead_ctx, const uint8_t *nonce,
			      const uint8_t *plaintext,
			      const size_t plaintextlen, const uint8_t *aad,
			      const size_t aadlen);
/*%<
 * Perform authenticated encryption operation (aka "seal" in BoringSSL
 * parlance).
 *
 * The caller is responsible to specify the destination buffer that
 * has enough capacity to store the output.
 *
 * See RFC5116 for more details.
 *
 * Requires:
 *\li	'dest' != NULL;
 *\li	'aead' != NULL;
 *\li	'aead_ctx' != NULL;
 *\li	'nonce' != NULL.
 */

bool
isc__quic_crypto_aead_decrypt(uint8_t *dest, const EVP_CIPHER *aead,
			      EVP_CIPHER_CTX *aead_ctx, const uint8_t *nonce,
			      const uint8_t *ciphertext, size_t ciphertextlen,
			      const uint8_t *aad, const size_t aadlen);
/*%<
 * Perform authenticated decryption operation (aka "open" in BoringSSL
 * parlance).
 *
 * The caller is responsible to specify the destination buffer that
 * has enough capacity to store the output.
 *
 * See RFC5116 for more details.
 *
 * Requires:
 *\li	'dest' != NULL;
 *\li	'aead' != NULL;
 *\li	'aead_ctx' != NULL;
 *\li	'nonce' != NULL;
 *\li	'ciphertext' != NULL;
 *\li	'ciphertextlen' > 0.
 */

bool
isc__quic_crypto_hp_cipher_ctx_encrypt_create(EVP_CIPHER_CTX **out_hp_cipher_ctx,
					      const EVP_CIPHER *hp_cipher,
					      const uint8_t *key);
/*%<
 * Create header protection encryption context.
 *
 * See RFC9001, Section 5.4 for more details.
 *
 * Requires:
 *\li	'out_hp_cipher_ctx' != NULL && '*out_hp_cipher_ctx' == NULL;
 *\li	'hp_cipher' != NULL;
 *\li	'key' != NULL.
 */

bool
isc__quic_crypto_hp_mask(uint8_t *dest, EVP_CIPHER_CTX *hp_ctx,
			 const uint8_t *sample);
/*%<
 * Calculate header protection mask. The output buffer 'dest' should
 * be at least 'ISC__QUIC_CRYPTO_HP_MASK_LEN' bytes long.
 *
 * See RFC9001, Section 5.4.1 for more details.
 *
 * Requires:
 *\li	'dest' != NULL;
 *\li	'hp_ctx' != NULL;
 *\li	'sample' != NULL.
 */

void
isc__quic_crypto_cipher_ctx_free(EVP_CIPHER_CTX **pcipher_ctx);
/*%<
 * Free a header protection or AEAD encryption context.
 *
 * Requires:
 *\li	'pcipher_ctx' != NULL && '*pcipher_ctx' != NULL.
 */

void
isc__quic_crypto_initialize(void);

void
isc__quic_crypto_shutdown(void);
