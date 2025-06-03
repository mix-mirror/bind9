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

#include <stdbool.h>
#include <stddef.h>

#include <openssl/bn.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/objects.h>

#include <isc/attributes.h>
#include <isc/crypto.h>
#include <isc/md.h>
#include <isc/mem.h>
#include <isc/ossl_wrap.h>
#include <isc/result.h>
#include <isc/safe.h>
#include <isc/string.h>
#include <isc/util.h>

#include <dns/keyvalues.h>

#include "dst_internal.h"
#include "dst_openssl.h"
#include "dst_parse.h"
#include "openssl_shim.h"

#ifndef NID_X9_62_prime256v1
#error "P-256 group is not known (NID_X9_62_prime256v1)"
#endif /* ifndef NID_X9_62_prime256v1 */
#ifndef NID_secp384r1
#error "P-384 group is not known (NID_secp384r1)"
#endif /* ifndef NID_secp384r1 */

#define MAX_PUBKEY_SIZE DNS_KEY_ECDSA384SIZE

#define MAX_PRIVKEY_SIZE (MAX_PUBKEY_SIZE / 2)

static bool
opensslecdsa_valid_key_alg(unsigned int key_alg) {
	switch (key_alg) {
	case DST_ALG_ECDSA256:
	case DST_ALG_ECDSA384:
		return true;
	default:
		return false;
	}
}

static size_t
opensslecdsa_key_alg_to_siglen(unsigned int key_alg) {
	switch (key_alg) {
	case DST_ALG_ECDSA256:
		return DNS_SIG_ECDSA256SIZE;
	case DST_ALG_ECDSA384:
		return DNS_SIG_ECDSA384SIZE;
	default:
		UNREACHABLE();
	}
}

static size_t
opensslecdsa_key_alg_to_publickey_size(unsigned int key_alg) {
	switch (key_alg) {
	case DST_ALG_ECDSA256:
		return DNS_KEY_ECDSA256SIZE;
	case DST_ALG_ECDSA384:
		return DNS_KEY_ECDSA384SIZE;
	default:
		UNREACHABLE();
	}
}

static int
BN_bn2bin_fixed(const BIGNUM *bn, unsigned char *buf, int size) {
	int bytes = size - BN_num_bytes(bn);

	INSIST(bytes >= 0);

	memset(buf, 0, bytes);
	BN_bn2bin(bn, buf + bytes);

	return size;
}

static isc_result_t
opensslecdsa_createctx(dst_key_t *key ISC_ATTR_UNUSED, dst_context_t *dctx) {
	REQUIRE(opensslecdsa_valid_key_alg(dctx->key->key_alg));

	const EVP_MD *type = NULL;
	const char *md = NULL;
	auto_EVP_MD_CTX *evp_md_ctx = EVP_MD_CTX_create();

	if (evp_md_ctx == NULL) {
		return dst__openssl_toresult(ISC_R_NOMEMORY);
	}

	if (dctx->key->key_alg == DST_ALG_ECDSA256) {
		type = isc__crypto_md[ISC_MD_SHA256];
		md = "SHA256";
	} else {
		type = isc__crypto_md[ISC_MD_SHA384];
		md = "SHA384";
	}

	switch (dctx->use) {
	case DO_SIGN: {
		EVP_PKEY_CTX *pctx = NULL;
		if (EVP_DigestSignInit(evp_md_ctx, &pctx, type, NULL,
				       dctx->key->keydata.pkeypair.priv) != 1)
		{
			return dst__openssl_toresult3(dctx->category,
						      "EVP_DigestSignInit",
						      ISC_R_FAILURE);
		}

		if (!isc_crypto_fips_mode()) {
			isc_result_t result =
				isc_ossl_wrap_ecdsa_set_deterministic(pctx, md);
			if (result != ISC_R_SUCCESS &&
			    result != ISC_R_NOTIMPLEMENTED)
			{
				return result;
			}
		}
		break;
	}
	case DO_VERIFY:
		if (EVP_DigestVerifyInit(evp_md_ctx, NULL, type, NULL,
					 dctx->key->keydata.pkeypair.pub) != 1)
		{
			return dst__openssl_toresult3(dctx->category,
						      "EVP_DigestVerifyInit",
						      ISC_R_FAILURE);
		}
		break;
	default:
		UNREACHABLE();
	}

	MOVE_INTO(dctx->ctxdata.evp_md_ctx, evp_md_ctx);

	return ISC_R_SUCCESS;
}

static void
opensslecdsa_destroyctx(dst_context_t *dctx) {
	REQUIRE(opensslecdsa_valid_key_alg(dctx->key->key_alg));

	EVP_MD_CTX *evp_md_ctx = dctx->ctxdata.evp_md_ctx;

	if (evp_md_ctx != NULL) {
		EVP_MD_CTX_destroy(evp_md_ctx);
		dctx->ctxdata.evp_md_ctx = NULL;
	}
}

static isc_result_t
opensslecdsa_adddata(dst_context_t *dctx, const isc_region_t *data) {
	REQUIRE(opensslecdsa_valid_key_alg(dctx->key->key_alg));

	EVP_MD_CTX *evp_md_ctx = dctx->ctxdata.evp_md_ctx;

	switch (dctx->use) {
	case DO_SIGN:
		if (EVP_DigestSignUpdate(evp_md_ctx, data->base,
					 data->length) != 1)
		{
			return dst__openssl_toresult3(dctx->category,
						      "EVP_DigestSignUpdate",
						      ISC_R_FAILURE);
		}
		break;
	case DO_VERIFY:
		if (EVP_DigestVerifyUpdate(evp_md_ctx, data->base,
					   data->length) != 1)
		{
			return dst__openssl_toresult3(dctx->category,
						      "EVP_DigestVerifyUpdate",
						      ISC_R_FAILURE);
		}
		break;
	default:
		UNREACHABLE();
	}

	return ISC_R_SUCCESS;
}

static isc_result_t
opensslecdsa_sign(dst_context_t *dctx, isc_buffer_t *sig) {
	isc_region_t region;
	EVP_MD_CTX *evp_md_ctx = dctx->ctxdata.evp_md_ctx;
	auto_ECDSA_SIG *ecdsasig = NULL;
	size_t siglen = opensslecdsa_key_alg_to_siglen(dctx->key->key_alg);
	auto_OPENSSL_void *sigder = NULL;
	size_t sigder_len = 0;
	const unsigned char *sigder_copy = NULL;
	const BIGNUM *r, *s;

	REQUIRE(opensslecdsa_valid_key_alg(dctx->key->key_alg));
	REQUIRE(dctx->use == DO_SIGN);

	isc_buffer_availableregion(sig, &region);
	if (region.length < siglen) {
		return ISC_R_NOSPACE;
	}

	if (EVP_DigestSignFinal(evp_md_ctx, NULL, &sigder_len) != 1) {
		return dst__openssl_toresult3(
			dctx->category, "EVP_DigestSignFinal", ISC_R_FAILURE);
	}
	if (sigder_len == 0) {
		return ISC_R_FAILURE;
	}
	sigder = OPENSSL_malloc(sigder_len);
	if (sigder == NULL) {
		return dst__openssl_toresult3(dctx->category, "OPENSSL_malloc",
					      ISC_R_FAILURE);
	}
	if (EVP_DigestSignFinal(evp_md_ctx, sigder, &sigder_len) != 1) {
		return dst__openssl_toresult3(
			dctx->category, "EVP_DigestSignFinal", ISC_R_FAILURE);
	}

	sigder_copy = sigder;
	if (d2i_ECDSA_SIG(&ecdsasig, &sigder_copy, sigder_len) == NULL) {
		return dst__openssl_toresult3(dctx->category, "d2i_ECDSA_SIG",
					      ISC_R_FAILURE);
	}

	ECDSA_SIG_get0(ecdsasig, &r, &s);
	BN_bn2bin_fixed(r, region.base, siglen / 2);
	isc_region_consume(&region, siglen / 2);
	BN_bn2bin_fixed(s, region.base, siglen / 2);
	isc_region_consume(&region, siglen / 2);

	isc_buffer_add(sig, siglen);

	return ISC_R_SUCCESS;
}

static isc_result_t
opensslecdsa_verify(dst_context_t *dctx, const isc_region_t *sig) {
	int status;
	auto_ECDSA_SIG *ecdsasig = NULL;
	EVP_MD_CTX *evp_md_ctx = dctx->ctxdata.evp_md_ctx;
	size_t siglen = opensslecdsa_key_alg_to_siglen(dctx->key->key_alg);
	auto_OPENSSL_void *sigder = NULL;
	unsigned char *sigder_copy = NULL;
	size_t sigder_len = 0;
	BIGNUM *r = NULL, *s = NULL;

	REQUIRE(opensslecdsa_valid_key_alg(dctx->key->key_alg));
	REQUIRE(dctx->use == DO_VERIFY);

	if (sig->length != siglen) {
		return DST_R_VERIFYFAILURE;
	}

	ecdsasig = ECDSA_SIG_new();
	if (ecdsasig == NULL) {
		return dst__openssl_toresult(ISC_R_NOMEMORY);
	}

	r = BN_bin2bn(sig->base, siglen / 2, NULL);
	s = BN_bin2bn(sig->base + siglen / 2, siglen / 2, NULL);
	(void)ECDSA_SIG_set0(ecdsasig, r, s);

	status = i2d_ECDSA_SIG(ecdsasig, NULL);
	if (status <= 0) {
		return dst__openssl_toresult3(dctx->category, "i2d_ECDSA_SIG",
					      DST_R_VERIFYFAILURE);
	}

	sigder_len = status;
	sigder = OPENSSL_malloc(sigder_len);
	if (sigder == NULL) {
		return dst__openssl_toresult3(dctx->category, "OPENSSL_malloc",
					      DST_R_OPENSSLFAILURE);
	}

	sigder_copy = sigder;
	status = i2d_ECDSA_SIG(ecdsasig, &sigder_copy);
	if (status <= 0) {
		return dst__openssl_toresult3(dctx->category, "i2d_ECDSA_SIG",
					      DST_R_VERIFYFAILURE);
	}

	/*
	 * EVP_DigestVerifyFinal() and EVP_DigestVerify() return 1 for success;
	 * any other value indicates failure.  A return value of zero indicates
	 * that the signature did not verify successfully (that is, tbs did not
	 * match the original data or the signature had an invalid form), while
	 * other values indicate a more serious error (and sometimes also
	 * indicate an invalid signature form).
	 */
	status = EVP_DigestVerifyFinal(evp_md_ctx, sigder, sigder_len);
	switch (status) {
	case 1:
		return ISC_R_SUCCESS;
	case 0:
		return DST_R_VERIFYFAILURE;
	default:
		return dst__openssl_toresult3(dctx->category,
					      "EVP_DigestVerifyFinal",
					      DST_R_OPENSSLFAILURE);
	}
}

static isc_result_t
opensslecdsa_generate(dst_key_t *key, void (*callback)(int)) {
	REQUIRE(opensslecdsa_valid_key_alg(key->key_alg));
	UNUSED(callback);

	auto_EVP_PKEY *pkey = NULL;

	if (key->label != NULL) {
		switch (key->key_alg) {
		case DST_ALG_ECDSA256:
			RETERR(isc_ossl_wrap_generate_pkcs11_p256_key(
				key->label, &pkey));
			break;
		case DST_ALG_ECDSA384:
			RETERR(isc_ossl_wrap_generate_pkcs11_p384_key(
				key->label, &pkey));
			break;
		default:
			UNREACHABLE();
		}
	} else {
		switch (key->key_alg) {
		case DST_ALG_ECDSA256:
			RETERR(isc_ossl_wrap_generate_p256_key(&pkey));
			break;
		case DST_ALG_ECDSA384:
			RETERR(isc_ossl_wrap_generate_p384_key(&pkey));
			break;
		default:
			UNREACHABLE();
		}
	}

	key->key_size = EVP_PKEY_bits(pkey);
	COPY_INTO(key->keydata.pkeypair.priv, pkey);
	MOVE_INTO(key->keydata.pkeypair.pub, pkey);

	return ISC_R_SUCCESS;
}

static isc_result_t
opensslecdsa_todns(const dst_key_t *key, isc_buffer_t *data) {
	REQUIRE(opensslecdsa_valid_key_alg(key->key_alg));
	REQUIRE(key->keydata.pkeypair.pub != NULL);

	isc_region_t r;
	size_t keysize = opensslecdsa_key_alg_to_publickey_size(key->key_alg);
	EVP_PKEY *pkey = key->keydata.pkeypair.pub;

	isc_buffer_availableregion(data, &r);
	if (r.length < keysize) {
		return ISC_R_NOSPACE;
	}

	switch (key->key_alg) {
	case DST_ALG_ECDSA256:
		if (isc_ossl_wrap_p256_public_region(pkey, r) != ISC_R_SUCCESS)
		{
			return dst__openssl_toresult(DST_R_OPENSSLFAILURE);
		}
		break;
	case DST_ALG_ECDSA384:
		if (isc_ossl_wrap_p384_public_region(pkey, r) != ISC_R_SUCCESS)
		{
			return dst__openssl_toresult(DST_R_OPENSSLFAILURE);
		}
		break;
	default:
		UNREACHABLE();
	}

	isc_buffer_add(data, keysize);

	return ISC_R_SUCCESS;
}

static isc_result_t
opensslecdsa_fromdns(dst_key_t *key, isc_buffer_t *data) {
	REQUIRE(opensslecdsa_valid_key_alg(key->key_alg));

	auto_EVP_PKEY *pkey = NULL;
	isc_region_t r;
	size_t len = opensslecdsa_key_alg_to_publickey_size(key->key_alg);

	isc_buffer_remainingregion(data, &r);
	if (r.length == 0) {
		return ISC_R_SUCCESS;
	}
	if (r.length != len) {
		return DST_R_INVALIDPUBLICKEY;
	}

	switch (key->key_alg) {
	case DST_ALG_ECDSA256:
		RETERR(isc_ossl_wrap_load_p256_public_from_region(r, &pkey));
		break;
	case DST_ALG_ECDSA384:
		RETERR(isc_ossl_wrap_load_p384_public_from_region(r, &pkey));
		break;
	default:
		UNREACHABLE();
	}

	isc_buffer_forward(data, len);
	key->key_size = EVP_PKEY_bits(pkey);
	MOVE_INTO(key->keydata.pkeypair.pub, pkey);

	return ISC_R_SUCCESS;
}

static isc_result_t
opensslecdsa_tofile(const dst_key_t *key, const char *directory) {
	isc_result_t result;
	dst_private_t priv;
	unsigned char buf[MAX_PRIVKEY_SIZE];
	size_t keylen = 0;
	unsigned short i;
	EVP_PKEY *pkey;

	if (key->keydata.pkeypair.pub == NULL) {
		return DST_R_NULLKEY;
	}

	if (key->external) {
		priv.nelements = 0;
		return dst__privstruct_writefile(key, &priv, directory);
	}

	if (key->keydata.pkeypair.priv == NULL) {
		return DST_R_NULLKEY;
	}

	keylen = opensslecdsa_key_alg_to_publickey_size(key->key_alg) / 2;
	INSIST(keylen <= sizeof(buf));

	pkey = key->keydata.pkeypair.priv;

	i = 0;
	switch (key->key_alg) {
	case DST_ALG_ECDSA256:
		result = isc_ossl_wrap_p256_secret_region(
			pkey, (isc_region_t){ buf, keylen });
		break;
	case DST_ALG_ECDSA384:
		result = isc_ossl_wrap_p384_secret_region(
			pkey, (isc_region_t){ buf, keylen });
		break;
	default:
		UNREACHABLE();
	}

	if (result == ISC_R_SUCCESS) {
		priv.elements[i].tag = TAG_ECDSA_PRIVATEKEY;
		priv.elements[i].length = keylen;
		priv.elements[i].data = buf;
		i++;
	}

	if (key->label != NULL) {
		priv.elements[i].tag = TAG_ECDSA_LABEL;
		priv.elements[i].length = (unsigned short)strlen(key->label) +
					  1;
		priv.elements[i].data = (unsigned char *)key->label;
		i++;
	}

	priv.nelements = i;
	result = dst__privstruct_writefile(key, &priv, directory);

	isc_safe_memwipe(buf, keylen);

	return result;
}

static isc_result_t
opensslecdsa_fromlabel(dst_key_t *key, const char *label, const char *pin);

static isc_result_t
opensslecdsa_parse_priv(dst_key_t *key, dst_key_t *pub, dst_private_t *priv) {
	auto_EVP_PKEY *pkey = NULL;
	const char *label = NULL;
	int privkey_index = -1;
	isc_region_t r;

	if (key->external) {
		if (priv->nelements != 0 || pub == NULL) {
			return dst__openssl_toresult(DST_R_INVALIDPRIVATEKEY);
		}
		MOVE_INTO(key->keydata.pkeypair.priv,
			  pub->keydata.pkeypair.priv);
		MOVE_INTO(key->keydata.pkeypair.pub, pub->keydata.pkeypair.pub);
		return ISC_R_SUCCESS;
	}

	for (int i = 0; i < priv->nelements; i++) {
		switch (priv->elements[i].tag) {
		case TAG_ECDSA_ENGINE:
			/* The Engine: tag is explicitly ignored */
			break;
		case TAG_ECDSA_LABEL:
			/* NUL terminated data? */
			RETERR(dst__privelement_is_nul_terminated(
				&priv->elements[i]));
			label = (char *)priv->elements[i].data;
			break;
		case TAG_ECDSA_PRIVATEKEY:
			privkey_index = i;
			break;
		default:
			break;
		}
	}

	if (label != NULL) {
		RETERR(opensslecdsa_fromlabel(key, label, NULL));
		/* Check that the public component matches if given */
		if (pub != NULL && EVP_PKEY_eq(key->keydata.pkeypair.pub,
					       pub->keydata.pkeypair.pub) != 1)
		{
			return DST_R_INVALIDPRIVATEKEY;
		}
		return ISC_R_SUCCESS;
	}

	if (privkey_index < 0) {
		return dst__openssl_toresult(DST_R_INVALIDPRIVATEKEY);
	}

	r = (isc_region_t){
		.base = priv->elements[privkey_index].data,
		.length = priv->elements[privkey_index].length,
	};

	switch (key->key_alg) {
	case DST_ALG_ECDSA256:
		RETERR(isc_ossl_wrap_load_p256_secret_from_region(r, &pkey));
		break;
	case DST_ALG_ECDSA384:
		RETERR(isc_ossl_wrap_load_p384_secret_from_region(r, &pkey));
		break;
	default:
		UNREACHABLE();
	}

	/* Check that the public component matches if given */
	if (pub != NULL && EVP_PKEY_eq(pkey, pub->keydata.pkeypair.pub) != 1) {
		return DST_R_INVALIDPRIVATEKEY;
	}

	key->key_size = EVP_PKEY_bits(pkey);
	COPY_INTO(key->keydata.pkeypair.priv, pkey);
	MOVE_INTO(key->keydata.pkeypair.pub, pkey);

	return ISC_R_SUCCESS;
}

static isc_result_t
opensslecdsa_parse(dst_key_t *key, isc_lex_t *lexer, dst_key_t *pub) {
	REQUIRE(opensslecdsa_valid_key_alg(key->key_alg));

	dst_private_t priv;
	isc_result_t result;

	/* read private key file */
	RETERR(dst__privstruct_parse(key, DST_ALG_ECDSA256, lexer, key->mctx,
				     &priv));

	result = opensslecdsa_parse_priv(key, pub, &priv);
	if (result != ISC_R_SUCCESS) {
		key->keydata.pkeypair.pub = NULL;
		key->keydata.pkeypair.priv = NULL;
	}
	dst__privstruct_free(&priv, key->mctx);
	isc_safe_memwipe(&priv, sizeof(priv));

	return result;
}

static isc_result_t
opensslecdsa_fromlabel(dst_key_t *key, const char *label,
		       const char *pin ISC_ATTR_UNUSED) {
	REQUIRE(opensslecdsa_valid_key_alg(key->key_alg));

	auto_EVP_PKEY *privpkey = NULL;
	auto_EVP_PKEY *pubpkey = NULL;

	RETERR(dst__openssl_fromlabel(EVP_PKEY_EC, label, pin, &pubpkey,
				      &privpkey));

	switch (key->key_alg) {
	case DST_ALG_ECDSA256:
		RETERR(isc_ossl_wrap_validate_p256_pkey(privpkey));
		RETERR(isc_ossl_wrap_validate_p256_pkey(pubpkey));
		break;
	case DST_ALG_ECDSA384:
		RETERR(isc_ossl_wrap_validate_p384_pkey(privpkey));
		RETERR(isc_ossl_wrap_validate_p384_pkey(pubpkey));
		break;
	default:
		UNREACHABLE();
	}

	key->label = isc_mem_strdup(key->mctx, label);
	key->key_size = EVP_PKEY_bits(privpkey);
	MOVE_INTO(key->keydata.pkeypair.priv, privpkey);
	MOVE_INTO(key->keydata.pkeypair.pub, pubpkey);

	return ISC_R_SUCCESS;
}

static dst_func_t opensslecdsa_functions = {
	.createctx = opensslecdsa_createctx,
	.destroyctx = opensslecdsa_destroyctx,
	.adddata = opensslecdsa_adddata,
	.sign = opensslecdsa_sign,
	.verify = opensslecdsa_verify,
	.compare = dst__openssl_keypair_compare,
	.generate = opensslecdsa_generate,
	.isprivate = dst__openssl_keypair_isprivate,
	.destroy = dst__openssl_keypair_destroy,
	.todns = opensslecdsa_todns,
	.fromdns = opensslecdsa_fromdns,
	.tofile = opensslecdsa_tofile,
	.parse = opensslecdsa_parse,
	.fromlabel = opensslecdsa_fromlabel,
};

void
dst__opensslecdsa_init(dst_func_t **funcp) {
	REQUIRE(funcp != NULL);

	if (*funcp == NULL) {
		*funcp = &opensslecdsa_functions;
	}
}
