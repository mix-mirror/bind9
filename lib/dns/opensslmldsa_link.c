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

/*! \file */

#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/params.h>

#include <isc/buffer.h>
#include <isc/result.h>
#include <isc/safe.h>
#include <isc/util.h>

#include <dns/keyvalues.h>

#include "dst_internal.h"
#include "dst_openssl.h"
#include "dst_parse.h"

/*
 * draft-westerbaan-dnssec-mldsa uses pure ML-DSA-44 with an empty context.
 * Leave message encoding and hedged signing at their OpenSSL defaults.
 */
static const OSSL_PARAM signature_params[] = {
	OSSL_PARAM_octet_string(OSSL_SIGNATURE_PARAM_CONTEXT_STRING,
				(unsigned char *)"", 0),
	OSSL_PARAM_END,
};

static isc_result_t
opensslmldsa_createctx(dst_key_t *key, dst_context_t *dctx) {
	isc_buffer_t *buf = NULL;

	REQUIRE(key->key_alg == DST_ALG_MLDSA44);

	isc_buffer_allocate(dctx->mctx, &buf, 64);
	dctx->ctxdata.generic = buf;
	return ISC_R_SUCCESS;
}

static void
opensslmldsa_destroyctx(dst_context_t *dctx) {
	isc_buffer_t *buf = dctx->ctxdata.generic;

	if (buf != NULL) {
		isc_buffer_free(&buf);
	}
	dctx->ctxdata.generic = NULL;
}

static isc_result_t
opensslmldsa_adddata(dst_context_t *dctx, const isc_region_t *data) {
	isc_buffer_t *buf = dctx->ctxdata.generic;

	return isc_buffer_copyregion(buf, data);
}

static isc_result_t
opensslmldsa_sign(dst_context_t *dctx, isc_buffer_t *sig) {
	isc_result_t result;
	isc_region_t data, target;
	EVP_MD_CTX *ctx = NULL;
	EVP_PKEY *pkey = dctx->key->keydata.pkeypair.priv;
	size_t siglen = DNS_SIG_MLDSA44SIZE;

	if (pkey == NULL) {
		return DST_R_NULLKEY;
	}
	isc_buffer_availableregion(sig, &target);
	if (target.length < siglen) {
		return ISC_R_NOSPACE;
	}

	ctx = EVP_MD_CTX_new();
	if (ctx == NULL) {
		return dst__openssl_toresult(ISC_R_NOMEMORY);
	}
	isc_buffer_usedregion(dctx->ctxdata.generic, &data);
	if (EVP_DigestSignInit_ex(ctx, NULL, NULL, NULL, NULL, pkey,
				  signature_params) != 1)
	{
		CLEANUP(dst__openssl_toresult3(dctx->category,
					       "EVP_DigestSignInit_ex",
					       DST_R_SIGNFAILURE));
	}
	if (EVP_DigestSign(ctx, target.base, &siglen, data.base, data.length) !=
	    1)
	{
		CLEANUP(dst__openssl_toresult3(dctx->category, "EVP_DigestSign",
					       DST_R_SIGNFAILURE));
	}
	INSIST(siglen == DNS_SIG_MLDSA44SIZE);
	isc_buffer_add(sig, siglen);
	result = ISC_R_SUCCESS;

cleanup:
	EVP_MD_CTX_free(ctx);
	return result;
}

static isc_result_t
opensslmldsa_verify(dst_context_t *dctx, const isc_region_t *sig) {
	isc_result_t result;
	isc_region_t data;
	EVP_MD_CTX *ctx = NULL;
	EVP_PKEY *pkey = dctx->key->keydata.pkeypair.pub;

	if (sig->length != DNS_SIG_MLDSA44SIZE) {
		return DST_R_VERIFYFAILURE;
	}
	ctx = EVP_MD_CTX_new();
	if (ctx == NULL) {
		return dst__openssl_toresult(ISC_R_NOMEMORY);
	}
	isc_buffer_usedregion(dctx->ctxdata.generic, &data);
	if (EVP_DigestVerifyInit_ex(ctx, NULL, NULL, NULL, NULL, pkey,
				    signature_params) != 1)
	{
		CLEANUP(dst__openssl_toresult3(dctx->category,
					       "EVP_DigestVerifyInit_ex",
					       DST_R_VERIFYFAILURE));
	}
	if (EVP_DigestVerify(ctx, sig->base, sig->length, data.base,
			     data.length) != 1)
	{
		CLEANUP(dst__openssl_toresult(DST_R_VERIFYFAILURE));
	}
	result = ISC_R_SUCCESS;

cleanup:
	EVP_MD_CTX_free(ctx);
	return result;
}

static isc_result_t
opensslmldsa_generate(dst_key_t *key, int unused ISC_ATTR_UNUSED,
		      void (*callback ISC_ATTR_UNUSED)(int)) {
	isc_result_t result;
	EVP_PKEY_CTX *ctx = NULL;
	EVP_PKEY *pkey = NULL;
	int retain_seed = 1;
	OSSL_PARAM params[2];

	if (key->label != NULL) {
		return ISC_R_NOTIMPLEMENTED;
	}

	ctx = EVP_PKEY_CTX_new_from_name(NULL, "ML-DSA-44", NULL);
	if (ctx == NULL) {
		return dst__openssl_toresult2("EVP_PKEY_CTX_new_from_name",
					      DST_R_OPENSSLFAILURE);
	}
	if (EVP_PKEY_keygen_init(ctx) != 1) {
		CLEANUP(dst__openssl_toresult2("EVP_PKEY_keygen_init",
					       DST_R_OPENSSLFAILURE));
	}

	/*
	 * The private key file stores only the seed, so ask the provider
	 * to keep it regardless of its configured default.
	 */
	params[0] = OSSL_PARAM_construct_int(OSSL_PKEY_PARAM_ML_DSA_RETAIN_SEED,
					     &retain_seed);
	params[1] = OSSL_PARAM_construct_end();
	if (EVP_PKEY_CTX_set_params(ctx, params) != 1) {
		CLEANUP(dst__openssl_toresult2("EVP_PKEY_CTX_set_params",
					       DST_R_OPENSSLFAILURE));
	}
	if (EVP_PKEY_generate(ctx, &pkey) != 1) {
		CLEANUP(dst__openssl_toresult2("EVP_PKEY_generate",
					       DST_R_OPENSSLFAILURE));
	}

	key->key_size = DNS_KEY_MLDSA44SIZE * 8;
	key->keydata.pkeypair.priv = pkey;
	key->keydata.pkeypair.pub = pkey;
	result = ISC_R_SUCCESS;

cleanup:
	EVP_PKEY_CTX_free(ctx);
	return result;
}

static isc_result_t
opensslmldsa_todns(const dst_key_t *key, isc_buffer_t *data) {
	isc_region_t target;
	size_t len = DNS_KEY_MLDSA44SIZE;

	isc_buffer_availableregion(data, &target);
	if (target.length < len) {
		return ISC_R_NOSPACE;
	}
	if (EVP_PKEY_get_raw_public_key(key->keydata.pkeypair.pub, target.base,
					&len) != 1)
	{
		return dst__openssl_toresult(DST_R_INVALIDPUBLICKEY);
	}
	INSIST(len == DNS_KEY_MLDSA44SIZE);
	isc_buffer_add(data, len);
	return ISC_R_SUCCESS;
}

static isc_result_t
opensslmldsa_fromdns(dst_key_t *key, isc_buffer_t *data) {
	isc_region_t source;
	EVP_PKEY *pkey = NULL;

	isc_buffer_remainingregion(data, &source);
	if (source.length != DNS_KEY_MLDSA44SIZE) {
		return DST_R_INVALIDPUBLICKEY;
	}
	pkey = EVP_PKEY_new_raw_public_key_ex(NULL, "ML-DSA-44", NULL,
					      source.base, source.length);
	if (pkey == NULL) {
		return dst__openssl_toresult(DST_R_INVALIDPUBLICKEY);
	}
	isc_buffer_forward(data, source.length);
	key->keydata.pkeypair.pub = pkey;
	key->key_size = DNS_KEY_MLDSA44SIZE * 8;
	return ISC_R_SUCCESS;
}

static isc_result_t
opensslmldsa_tofile(const dst_key_t *key, const char *directory) {
	isc_result_t result;
	dst_private_t priv = { 0 };
	unsigned char seed[DNS_KEY_MLDSA44SEEDSIZE];
	size_t len = sizeof(seed);

	if (key->external) {
		return dst__privstruct_writefile(key, &priv, directory);
	}
	if (key->keydata.pkeypair.priv == NULL) {
		return DST_R_NULLKEY;
	}
	if (EVP_PKEY_get_octet_string_param(key->keydata.pkeypair.priv,
					    OSSL_PKEY_PARAM_ML_DSA_SEED, seed,
					    sizeof(seed), &len) != 1)
	{
		CLEANUP(dst__openssl_toresult(DST_R_INVALIDPRIVATEKEY));
	}
	INSIST(len == sizeof(seed));
	priv.nelements = 1;
	priv.elements[0].tag = TAG_MLDSA_PRIVATEKEY;
	priv.elements[0].length = len;
	priv.elements[0].data = seed;
	result = dst__privstruct_writefile(key, &priv, directory);

cleanup:
	isc_safe_memwipe(seed, sizeof(seed));
	return result;
}

static isc_result_t
opensslmldsa_parse(dst_key_t *key, isc_lex_t *lexer, dst_key_t *pub) {
	isc_result_t result;
	dst_private_t priv;
	EVP_PKEY_CTX *ctx = NULL;
	EVP_PKEY *pkey = NULL;
	OSSL_PARAM params[2];

	CHECK(dst__privstruct_parse(key, DST_ALG_MLDSA44, lexer, key->mctx,
				    &priv));
	if (key->external) {
		if (pub == NULL) {
			CLEANUP(DST_R_INVALIDPRIVATEKEY);
		}
		key->keydata.pkeypair = pub->keydata.pkeypair;
		pub->keydata.pkeypair.priv = NULL;
		pub->keydata.pkeypair.pub = NULL;
		CLEANUP(ISC_R_SUCCESS);
	}

	/* check_mldsa() requires exactly one 32-byte seed. */
	params[0] = OSSL_PARAM_construct_octet_string(
		OSSL_PKEY_PARAM_ML_DSA_SEED, priv.elements[0].data,
		priv.elements[0].length);
	params[1] = OSSL_PARAM_construct_end();
	ctx = EVP_PKEY_CTX_new_from_name(NULL, "ML-DSA-44", NULL);
	if (ctx == NULL || EVP_PKEY_fromdata_init(ctx) != 1 ||
	    EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_KEYPAIR, params) != 1)
	{
		CLEANUP(dst__openssl_toresult(DST_R_INVALIDPRIVATEKEY));
	}
	if (pub != NULL && EVP_PKEY_eq(pkey, pub->keydata.pkeypair.pub) != 1) {
		CLEANUP(DST_R_INVALIDPRIVATEKEY);
	}
	key->keydata.pkeypair.priv = pkey;
	key->keydata.pkeypair.pub = pkey;
	key->key_size = DNS_KEY_MLDSA44SIZE * 8;
	pkey = NULL;
	result = ISC_R_SUCCESS;

cleanup:
	EVP_PKEY_CTX_free(ctx);
	EVP_PKEY_free(pkey);
	dst__privstruct_free(&priv, key->mctx);
	isc_safe_memwipe(&priv, sizeof(priv));
	return result;
}

static dst_func_t opensslmldsa_functions = {
	.createctx = opensslmldsa_createctx,
	.destroyctx = opensslmldsa_destroyctx,
	.adddata = opensslmldsa_adddata,
	.sign = opensslmldsa_sign,
	.verify = opensslmldsa_verify,
	.compare = dst__openssl_keypair_compare,
	.generate = opensslmldsa_generate,
	.isprivate = dst__openssl_keypair_isprivate,
	.destroy = dst__openssl_keypair_destroy,
	.todns = opensslmldsa_todns,
	.fromdns = opensslmldsa_fromdns,
	.tofile = opensslmldsa_tofile,
	.parse = opensslmldsa_parse,
};

void
dst__opensslmldsa_init(dst_func_t **funcp) {
	EVP_KEYMGMT *keymgmt = NULL;
	EVP_SIGNATURE *signature = NULL;

	REQUIRE(funcp != NULL);

	/* Respect the configured providers and default property query. */
	keymgmt = EVP_KEYMGMT_fetch(NULL, "ML-DSA-44", NULL);
	signature = EVP_SIGNATURE_fetch(NULL, "ML-DSA-44", NULL);
	if (keymgmt != NULL && signature != NULL) {
		*funcp = &opensslmldsa_functions;
	}
	EVP_KEYMGMT_free(keymgmt);
	EVP_SIGNATURE_free(signature);
	ERR_clear_error();
}
