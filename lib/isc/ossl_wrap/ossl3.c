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

#include <stdbool.h>

#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>
#include <openssl/rsa.h>

#include <isc/ossl_wrap.h>
#include <isc/util.h>

#define OSSL_WRAP_ERROR(fn)                                        \
	isc__ossl_wrap_logged_toresult(                            \
		ISC_LOGCATEGORY_GENERAL, ISC_LOGMODULE_CRYPTO, fn, \
		ISC_R_CRYPTOFAILURE, __FILE__, __LINE__)

static int
rsa_keygen_progress_cb(EVP_PKEY_CTX *ctx) {
	void (*fptr)(int);

	fptr = EVP_PKEY_CTX_get_app_data(ctx);
	if (fptr != NULL) {
		int p = EVP_PKEY_CTX_get_keygen_info(ctx, 0);
		fptr(p);
	}
	return 1;
}

isc_result_t
isc_ossl_wrap_generate_rsa_key(void (*callback)(int), size_t bit_size,
			       EVP_PKEY **pkeyp) {
	isc_result_t result;
	EVP_PKEY_CTX *ctx;
	BIGNUM *e;

	REQUIRE(pkeyp != NULL && *pkeyp == NULL);

	e = BN_new();

	/* e = 65537 (0x10001, F4) */
	BN_set_bit(e, 0);
	BN_set_bit(e, 16);

	ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
	if (ctx == NULL) {
		CLEANUP(OSSL_WRAP_ERROR("EVP_PKEY_CTX_new_from_name"));
	}

	if (EVP_PKEY_keygen_init(ctx) != 1) {
		CLEANUP(OSSL_WRAP_ERROR("EVP_PKEY_keygen_init"));
	}

	if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bit_size) != 1) {
		CLEANUP(OSSL_WRAP_ERROR("EVP_PKEY_CTX_set_rsa_keygen_bits"));
	}

	if (EVP_PKEY_CTX_set1_rsa_keygen_pubexp(ctx, e) != 1) {
		CLEANUP(OSSL_WRAP_ERROR("EVP_PKEY_CTX_set1_rsa_keygen_pubexp"));
	}

	if (callback != NULL) {
		EVP_PKEY_CTX_set_app_data(ctx, (void *)callback);
		EVP_PKEY_CTX_set_cb(ctx, rsa_keygen_progress_cb);
	}

	if (EVP_PKEY_keygen(ctx, pkeyp) != 1) {
		CLEANUP(OSSL_WRAP_ERROR("EVP_PKEY_keygen"));
	}

	result = ISC_R_SUCCESS;

cleanup:
	EVP_PKEY_CTX_free(ctx);
	BN_free(e);
	return result;
}

isc_result_t
isc_ossl_wrap_generate_pkcs11_rsa_key(char *uri, size_t bit_size,
				      EVP_PKEY **pkeyp) {
	EVP_PKEY_CTX *ctx = NULL;
	OSSL_PARAM params[4];
	isc_result_t result;
	int status;

	params[0] = OSSL_PARAM_construct_utf8_string("pkcs11_uri", uri, 0);
	params[1] = OSSL_PARAM_construct_utf8_string(
		"pkcs11_key_usage", (char *)"digitalSignature", 0);
	params[2] = OSSL_PARAM_construct_size_t("rsa_keygen_bits", &bit_size);
	params[3] = OSSL_PARAM_construct_end();

	ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", "provider=pkcs11");
	if (ctx == NULL) {
		CLEANUP(OSSL_WRAP_ERROR("EVP_PKEY_CTX_new_from_name"));
	}

	status = EVP_PKEY_keygen_init(ctx);
	if (status != 1) {
		CLEANUP(OSSL_WRAP_ERROR("EVP_PKEY_keygen_init"));
	}

	status = EVP_PKEY_CTX_set_params(ctx, params);
	if (status != 1) {
		CLEANUP(OSSL_WRAP_ERROR("EVP_PKEY_CTX_set_params"));
	}

	status = EVP_PKEY_generate(ctx, pkeyp);
	if (status != 1) {
		CLEANUP(OSSL_WRAP_ERROR("EVP_PKEY_generate"));
	}

	result = ISC_R_SUCCESS;

cleanup:
	EVP_PKEY_CTX_free(ctx);
	return result;
}

bool
isc_ossl_wrap_rsa_key_bits_leq(EVP_PKEY *pkey, size_t limit) {
	size_t bits = SIZE_MAX;
	BIGNUM *e = NULL;
	if (EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_E, &e) == 1) {
		bits = BN_num_bits(e);
		BN_free(e);
	}
	return bits <= limit;
}

isc_result_t
isc_ossl_wrap_rsa_public_components(EVP_PKEY *pkey,
				    isc_ossl_wrap_rsa_components_t *c) {
	isc_result_t result;

	REQUIRE(pkey != NULL);
	REQUIRE(c != NULL && c->e == NULL && c->n == NULL);

	c->needs_cleanup = true;

	if (EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_E, &c->e) != 1) {
		CLEANUP(OSSL_WRAP_ERROR("EVP_PKEY_get_bn_param"));
	}

	if (EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_N, &c->n) != 1) {
		CLEANUP(OSSL_WRAP_ERROR("EVP_PKEY_get_bn_param"));
	}

	result = ISC_R_SUCCESS;

cleanup:
	return result;
}

isc_result_t
isc_ossl_wrap_rsa_secret_components(EVP_PKEY *pkey,
				    isc_ossl_wrap_rsa_components_t *c) {
	REQUIRE(pkey != NULL);
	REQUIRE(c != NULL && c->d == NULL && c->p == NULL && c->q == NULL &&
		c->dmp1 == NULL && c->dmq1 == NULL && c->iqmp == NULL);

	c->needs_cleanup = true;

	/*
	 * NOTE: Errors regarding private compoments are ignored.
	 *
	 * OpenSSL allows omitting the parameters for CRT based calculations
	 * (factors, exponents, coefficients). Only the 'd'  parameter is
	 * mandatory for software keys.
	 *
	 * However, for a label based keys, all private key component queries
	 * can fail if they key is e.g. on a hardware device.
	 */
	(void)EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_D, &c->d);
	(void)EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_FACTOR1, &c->p);
	(void)EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_FACTOR2, &c->q);
	(void)EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_EXPONENT1,
				    &c->dmp1);
	(void)EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_EXPONENT2,
				    &c->dmq1);
	(void)EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_COEFFICIENT1,
				    &c->iqmp);

	ERR_clear_error();

	return ISC_R_SUCCESS;
}

isc_result_t
isc_ossl_wrap_load_rsa_public_from_components(isc_ossl_wrap_rsa_components_t *c,
					      EVP_PKEY **pkeyp) {
	OSSL_PARAM_BLD *bld = NULL;
	EVP_PKEY_CTX *pctx = NULL;
	OSSL_PARAM *params = NULL;
	isc_result_t result;

	result = ISC_R_SUCCESS;

	REQUIRE(pkeyp != NULL && *pkeyp == NULL);
	REQUIRE(c != NULL && c->n != NULL && c->e != NULL);

	bld = OSSL_PARAM_BLD_new();
	if (bld == NULL) {
		CLEANUP(OSSL_WRAP_ERROR("OSSL_PARAM_BLD_new"));
	}

	if (OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_N, c->n) != 1) {
		CLEANUP(OSSL_WRAP_ERROR("OSSL_PARAM_BLD_push_BN"));
	}

	if (OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_E, c->e) != 1) {
		CLEANUP(OSSL_WRAP_ERROR("OSSL_PARAM_BLD_push_BN"));
	}

	params = OSSL_PARAM_BLD_to_param(bld);
	if (params == NULL) {
		CLEANUP(OSSL_WRAP_ERROR("OSSL_PARAM_BLD_to_param"));
	}

	pctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
	if (pctx == NULL) {
		CLEANUP(OSSL_WRAP_ERROR("EVP_PKEY_CTX_new_from_name"));
	}

	if (EVP_PKEY_fromdata_init(pctx) != 1) {
		CLEANUP(OSSL_WRAP_ERROR("EVP_PKEY_fromdata_init"));
	}

	if (EVP_PKEY_fromdata(pctx, pkeyp, EVP_PKEY_PUBLIC_KEY, params) != 1) {
		CLEANUP(OSSL_WRAP_ERROR("EVP_PKEY_fromdata"));
	}

	result = ISC_R_SUCCESS;

cleanup:
	EVP_PKEY_CTX_free(pctx);
	OSSL_PARAM_free(params);
	OSSL_PARAM_BLD_free(bld);
	return result;
}

isc_result_t
isc_ossl_wrap_load_rsa_secret_from_components(isc_ossl_wrap_rsa_components_t *c,
					      EVP_PKEY **pkeyp) {
	isc_result_t result;
	OSSL_PARAM_BLD *bld = NULL;
	EVP_PKEY_CTX *pctx = NULL;
	OSSL_PARAM *params = NULL;

	REQUIRE(pkeyp != NULL && *pkeyp == NULL);

	bld = OSSL_PARAM_BLD_new();
	if (bld == NULL) {
		CLEANUP(OSSL_WRAP_ERROR("OSSL_PARAM_BLD_new"));
	}

	if (OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_N, c->n) != 1) {
		CLEANUP(OSSL_WRAP_ERROR("OSSL_PARAM_BLD_push_BN"));
	}

	if (OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_E, c->e) != 1) {
		CLEANUP(OSSL_WRAP_ERROR("OSSL_PARAM_BLD_push_BN"));
	}

	if (c->d != NULL &&
	    OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_D, c->d) != 1)
	{
		CLEANUP(OSSL_WRAP_ERROR("OSSL_PARAM_BLD_push_BN"));
	}

	if (c->p != NULL &&
	    OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_FACTOR1, c->p) != 1)
	{
		CLEANUP(OSSL_WRAP_ERROR("OSSL_PARAM_BLD_push_BN"));
	}

	if (c->q != NULL &&
	    OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_FACTOR2, c->q) != 1)
	{
		CLEANUP(OSSL_WRAP_ERROR("OSSL_PARAM_BLD_push_BN"));
	}

	if (c->dmp1 != NULL &&
	    OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_EXPONENT1,
				   c->dmp1) != 1)
	{
		CLEANUP(OSSL_WRAP_ERROR("OSSL_PARAM_BLD_push_BN"));
	}

	if (c->dmq1 != NULL &&
	    OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_EXPONENT2,
				   c->dmq1) != 1)
	{
		CLEANUP(OSSL_WRAP_ERROR("OSSL_PARAM_BLD_push_BN"));
	}

	if (c->iqmp != NULL &&
	    OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_COEFFICIENT1,
				   c->iqmp) != 1)
	{
		CLEANUP(OSSL_WRAP_ERROR("OSSL_PARAM_BLD_push_BN"));
	}

	params = OSSL_PARAM_BLD_to_param(bld);
	if (params == NULL) {
		CLEANUP(OSSL_WRAP_ERROR("OSSL_PARAM_BLD_to_param"));
	}

	pctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
	if (pctx == NULL) {
		CLEANUP(OSSL_WRAP_ERROR("EVP_PKEY_CTX_new_from_name"));
	}

	if (EVP_PKEY_fromdata_init(pctx) != 1) {
		CLEANUP(OSSL_WRAP_ERROR("EVP_PKEY_fromdata_init"));
	}

	if (EVP_PKEY_fromdata(pctx, pkeyp, EVP_PKEY_KEYPAIR, params) != 1) {
		CLEANUP(OSSL_WRAP_ERROR("EVP_PKEY_fromdata"));
	}

	result = ISC_R_SUCCESS;

cleanup:
	EVP_PKEY_CTX_free(pctx);
	OSSL_PARAM_free(params);
	OSSL_PARAM_BLD_free(bld);
	return result;
}
