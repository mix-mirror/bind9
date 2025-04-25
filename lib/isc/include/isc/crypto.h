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

#include <isc/types.h>

typedef void isc_crypto_signature_type_t;
typedef void isc_crypto_cipher_type_t;

extern EVP_MD *isc__crypto_md5;
extern EVP_MD *isc__crypto_sha1;
extern EVP_MD *isc__crypto_sha224;
extern EVP_MD *isc__crypto_sha256;
extern EVP_MD *isc__crypto_sha384;
extern EVP_MD *isc__crypto_sha512;

extern isc_crypto_signature_type_t *isc__crypto_rsa_pkcs1_v1_5_sha1;
extern isc_crypto_signature_type_t *isc__crypto_rsa_pkcs1_v1_5_sha2_256;
extern isc_crypto_signature_type_t *isc__crypto_rsa_pkcs1_v1_5_sha2_512;
extern isc_crypto_signature_type_t *isc__crypto_ecdsa_p256;
extern isc_crypto_signature_type_t *isc__crypto_ecdsa_p384;
extern isc_crypto_signature_type_t *isc__crypto_ed448;
extern isc_crypto_signature_type_t *isc__crypto_ed25519;

extern isc_crypto_cipher_type_t *isc__crypto_aes_128_gcm;
extern isc_crypto_cipher_type_t *isc__crypto_aes_256_gcm;
extern isc_crypto_cipher_type_t *isc__crypto_aes_128_ccm;
extern isc_crypto_cipher_type_t *isc__crypto_chacha20_poly1305;
extern isc_crypto_cipher_type_t *isc__crypto_aes_128_ctr;
extern isc_crypto_cipher_type_t *isc__crypto_aes_256_ctr;
extern isc_crypto_cipher_type_t *isc__crypto_chacha20;

extern void *isc__crypto_hkdf;

bool
isc_crypto_fips_mode(void);
/*
 * Return if FIPS mode is currently enabled or not.
 */

isc_result_t
isc_crypto_fips_enable(void);
/*
 * Enable FIPS mode. It cannot be disabled afterwards.
 *
 * This function is NOT thread safe.
 */

/**
 * Private
 */

void
isc__crypto_setdestroycheck(bool check);

void
isc__crypto_initialize(void);

void
isc__crypto_shutdown(void);
