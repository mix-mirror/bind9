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

#include <stdbool.h>
#include <stddef.h>

#include <openssl/bn.h>
#include <openssl/evp.h>

#include <isc/log.h>
#include <isc/types.h>

#define isc_ossl_wrap_logged_toresult(category, module, funcname, fallback)  \
	isc__ossl_wrap_logged_toresult(category, module, funcname, fallback, \
				       __FILE__, __LINE__)

typedef struct isc_ossl_wrap_rsa_components {
	bool	needs_cleanup;
	BIGNUM *e, *n, *d, *p, *q, *dmp1, *dmq1, *iqmp;
} isc_ossl_wrap_rsa_components_t;

isc_result_t
isc_ossl_wrap_generate_rsa_key(void (*callback)(int), size_t bit_size,
			       EVP_PKEY **pkeyp);
/*%
 * Creates a RSA key with the specified bit-size
 *
 * Requires:
 * \li `pkeyp != NULL`
 * \li `*pkeyp == NULL`
 */

isc_result_t
isc_ossl_wrap_generate_pkcs11_rsa_key(char *uri, size_t bit_size,
				      EVP_PKEY **pkeyp);
/*%
 * Creates a RSA key with the specified bit-size using the PKCS11 label
 * specified at `uri`.
 *
 * Requires:
 * \li `pkeyp != NULL`
 * \li `*pkeyp == NULL`
 * \li `uri != NULL` and is a NUL-terminated string
 */

bool
isc_ossl_wrap_rsa_key_bits_leq(EVP_PKEY *pkey, size_t limit);

isc_result_t
isc_ossl_wrap_rsa_public_components(EVP_PKEY			   *pkey,
				    isc_ossl_wrap_rsa_components_t *c);

isc_result_t
isc_ossl_wrap_rsa_secret_components(EVP_PKEY			   *pkey,
				    isc_ossl_wrap_rsa_components_t *c);

isc_result_t
isc_ossl_wrap_load_rsa_public_from_components(isc_ossl_wrap_rsa_components_t *c,
					      EVP_PKEY **pkeyp);
/*%
 * Create a verifying `EVP_PKEY` using the public RSA components at `c`
 *
 * Requires:
 * \li `pkeyp != NULL`
 * \li `*pkeyp == NULL`
 * \li `c != NULL`
 * \li `c.n != NULL`
 * \li `c.e != NULL`
 */

isc_result_t
isc_ossl_wrap_load_rsa_secret_from_components(isc_ossl_wrap_rsa_components_t *c,
					      EVP_PKEY **pkeyp);
/*%
 * Create a signing `EVP_PKEY` using the public and secret RSA components at `c`
 *
 * Requires:
 * \li `pkeyp != NULL`
 * \li `*pkeyp == NULL`
 * \li `c != NULL`
 * \li `c.n != NULL`
 * \li `c.e != NULL`
 */

void
isc_ossl_wrap_rsa_components_cleanup(isc_ossl_wrap_rsa_components_t *comp);

isc_result_t
isc_ossl_wrap_toresult(isc_result_t fallback);

isc_result_t
isc__ossl_wrap_logged_toresult(isc_logcategory_t category,
			       isc_logmodule_t module, const char *funcname,
			       isc_result_t fallback, const char *file,
			       int line);
