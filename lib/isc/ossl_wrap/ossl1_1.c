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

#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>

#include <isc/ossl_wrap.h>
#include <isc/util.h>

#define OSSL_WRAP_ERROR(fn)                                        \
	isc__ossl_wrap_logged_toresult(                            \
		ISC_LOGCATEGORY_GENERAL, ISC_LOGMODULE_CRYPTO, fn, \
		ISC_R_CRYPTOFAILURE, __FILE__, __LINE__)

static int
rsa_keygen_progress_cb(int p, int n, BN_GENCB *cb) {
	void (*fptr)(int);

	UNUSED(n);

	fptr = BN_GENCB_get_arg(cb);
	if (fptr != NULL) {
		fptr(p);
	}
	return 1;
}

isc_result_t
isc_ossl_wrap_generate_rsa_key(void (*callback)(int), size_t bit_size,
			       EVP_PKEY **pkeyp) {
	RSA *rsa = NULL;
	EVP_PKEY *pkey = NULL;
	BN_GENCB *cb = NULL;
	isc_result_t result;
	BIGNUM *e;

	e = BN_new();

	/* e = 65537 (0x10001, F4) */
	BN_set_bit(e, 0);
	BN_set_bit(e, 16);

	rsa = RSA_new();
	if (rsa == NULL) {
		CLEANUP(OSSL_WRAP_ERROR("RSA_new"));
	}

	pkey = EVP_PKEY_new();
	if (pkey == NULL) {
		CLEANUP(OSSL_WRAP_ERROR("EVP_PKEY_new"));
	}

	if (EVP_PKEY_set1_RSA(pkey, rsa) != 1) {
		CLEANUP(OSSL_WRAP_ERROR("EVP_PKEY_set1_RSA"));
	}

	if (callback != NULL) {
		cb = BN_GENCB_new();
		if (cb == NULL) {
			CLEANUP(OSSL_WRAP_ERROR("BN_GENCB_new"));
		}

		BN_GENCB_set(cb, rsa_keygen_progress_cb, (void *)callback);
	}

	if (RSA_generate_key_ex(rsa, bit_size, e, cb) != 1) {
		CLEANUP(OSSL_WRAP_ERROR("RSA_generate_key_ex"));
	}
	*pkeyp = pkey;
	pkey = NULL;
	result = ISC_R_SUCCESS;

cleanup:
	EVP_PKEY_free(pkey);
	RSA_free(rsa);
	BN_GENCB_free(cb);
	BN_free(e);
	return result;
}

isc_result_t
isc_ossl_wrap_generate_pkcs11_rsa_key(char *uri, size_t bit_size,
				      EVP_PKEY **pkeyp) {
	UNUSED(uri);

	return isc_ossl_wrap_generate_rsa_key(NULL, bit_size, pkeyp);
}

bool
isc_ossl_wrap_rsa_key_bits_leq(EVP_PKEY *pkey, size_t limit) {
	const RSA *rsa;
	const BIGNUM *ce;
	size_t bits = SIZE_MAX;

	REQUIRE(pkey != NULL);

	rsa = EVP_PKEY_get0_RSA(pkey);
	if (rsa != NULL) {
		ce = NULL;
		RSA_get0_key(rsa, NULL, &ce, NULL);
		if (ce != NULL) {
			bits = BN_num_bits(ce);
		}
	}

	return bits <= limit;
}

isc_result_t
isc_ossl_wrap_rsa_public_components(EVP_PKEY *pkey,
				    isc_ossl_wrap_rsa_components_t *c) {
	isc_result_t result;
	const RSA *rsa;

	REQUIRE(pkey != NULL);
	REQUIRE(c != NULL && c->e == NULL && c->n == NULL);

	rsa = EVP_PKEY_get0_RSA(pkey);
	if (rsa == NULL) {
		CLEANUP(OSSL_WRAP_ERROR("EVP_PKEY_get0_RSA"));
	}

	RSA_get0_key(rsa, (const BIGNUM **)&c->n, (const BIGNUM **)&c->e, NULL);

	result = ISC_R_SUCCESS;

cleanup:
	return result;
}

isc_result_t
isc_ossl_wrap_rsa_secret_components(EVP_PKEY *pkey,
				    isc_ossl_wrap_rsa_components_t *c) {
	isc_result_t result;
	const RSA *rsa;

	REQUIRE(pkey != NULL);
	REQUIRE(c != NULL && c->d == NULL && c->p == NULL && c->q == NULL &&
		c->dmp1 == NULL && c->dmq1 == NULL && c->iqmp == NULL);

	rsa = EVP_PKEY_get0_RSA(pkey);
	if (rsa == NULL) {
		CLEANUP(OSSL_WRAP_ERROR("EVP_PKEY_get0_RSA"));
	}

	/*
	 * We don't support PKCS11 with OpenSSL <=1.1.1a
	 * d *must* succeed.
	 */
	RSA_get0_key(rsa, NULL, NULL, (const BIGNUM **)&c->d);
	if (c->d == NULL) {
		CLEANUP(OSSL_WRAP_ERROR("RSA_get0_key"));
	}

	RSA_get0_factors(rsa, (const BIGNUM **)&c->p, (const BIGNUM **)&c->q);
	RSA_get0_crt_params(rsa, (const BIGNUM **)&c->dmp1,
			    (const BIGNUM **)&c->dmq1,
			    (const BIGNUM **)&c->iqmp);

	result = ISC_R_SUCCESS;

cleanup:
	return result;
}

isc_result_t
isc_ossl_wrap_load_rsa_public_from_components(isc_ossl_wrap_rsa_components_t *c,
					      EVP_PKEY **pkeyp) {
	isc_result_t result;
	EVP_PKEY *pkey = NULL;
	RSA *rsa = NULL;

	REQUIRE(pkeyp != NULL && *pkeyp == NULL);
	REQUIRE(c != NULL && c->e != NULL && c->n != NULL);
	REQUIRE(c->needs_cleanup);

	rsa = RSA_new();
	if (rsa == NULL) {
		CLEANUP(OSSL_WRAP_ERROR("RSA_new"));
	}

	if (RSA_set0_key(rsa, c->n, c->e, NULL) != 1) {
		CLEANUP(OSSL_WRAP_ERROR("RSA_set0_key"));
	}

	c->n = NULL;
	c->e = NULL;

	pkey = EVP_PKEY_new();
	if (pkey == NULL) {
		CLEANUP(OSSL_WRAP_ERROR("EVP_PKEY_new"));
	}

	if (EVP_PKEY_set1_RSA(pkey, rsa) != 1) {
		CLEANUP(OSSL_WRAP_ERROR("EVP_PKEY_set1_RSA"));
	}

	*pkeyp = pkey;
	pkey = NULL;
	result = ISC_R_SUCCESS;

cleanup:
	EVP_PKEY_free(pkey);
	RSA_free(rsa);
	return result;
}

isc_result_t
isc_ossl_wrap_load_rsa_secret_from_components(isc_ossl_wrap_rsa_components_t *c,
					      EVP_PKEY **pkeyp) {
	isc_result_t result;
	EVP_PKEY *pkey = NULL;
	RSA *rsa = NULL;

	REQUIRE(pkeyp != NULL && *pkeyp == NULL);
	REQUIRE(c != NULL);

	result = ISC_R_SUCCESS;

	rsa = RSA_new();
	if (rsa == NULL) {
		CLEANUP(OSSL_WRAP_ERROR("RSA_new"));
	}

	if (RSA_set0_key(rsa, c->n, c->e, c->d) != 1) {
		CLEANUP(OSSL_WRAP_ERROR("RSA_set0_key"));
	}

	c->n = NULL;
	c->e = NULL;
	c->d = NULL;

	if (c->p != NULL || c->q != NULL) {
		if (RSA_set0_factors(rsa, c->p, c->q) != 1) {
			CLEANUP(OSSL_WRAP_ERROR("RSA_set0_factors"));
		}

		c->p = NULL;
		c->q = NULL;
	}

	if (c->dmp1 != NULL || c->dmq1 != NULL || c->iqmp != NULL) {
		if (RSA_set0_crt_params(rsa, c->dmp1, c->dmq1, c->iqmp) != 1) {
			CLEANUP(OSSL_WRAP_ERROR("RSA_set0_crt_params"));
		}
		c->dmp1 = NULL;
		c->dmq1 = NULL;
		c->iqmp = NULL;
	}

	pkey = EVP_PKEY_new();
	if (pkey == NULL) {
		CLEANUP(OSSL_WRAP_ERROR("EVP_PKEY_new"));
	}

	if (EVP_PKEY_set1_RSA(pkey, rsa) != 1) {
		CLEANUP(OSSL_WRAP_ERROR("EVP_PKEY_set1_RSA"));
	}

	*pkeyp = pkey;
	pkey = NULL;
	result = ISC_R_SUCCESS;

cleanup:
	EVP_PKEY_free(pkey);
	RSA_free(rsa);
	isc_ossl_wrap_rsa_components_cleanup(c);
	return result;
}
