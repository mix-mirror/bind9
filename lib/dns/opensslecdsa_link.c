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
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/opensslv.h>

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/core_names.h>
#include <openssl/param_build.h>
#endif

#include <isc/attributes.h>
#include <isc/mem.h>
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

#if OPENSSL_VERSION_NUMBER >= 0x30200000L
static isc_result_t
opensslecdsa_set_deterministic(EVP_PKEY_CTX *pctx, unsigned int key_alg) {
	unsigned int rfc6979 = 1;
	char *md = NULL;
	OSSL_PARAM params[3];

	switch (key_alg) {
	case DST_ALG_ECDSA256:
		md = (char *)"SHA256";
		break;
	case DST_ALG_ECDSA384:
		md = (char *)"SHA384";
		break;
	default:
		UNREACHABLE();
	}

	params[0] = OSSL_PARAM_construct_utf8_string("digest", md, 0);
	params[1] = OSSL_PARAM_construct_uint("nonce-type", &rfc6979);
	params[2] = OSSL_PARAM_construct_end();

	if (EVP_PKEY_CTX_set_params(pctx, params) != 1) {
		return dst__openssl_toresult2("EVP_PKEY_CTX_set_params",
					      DST_R_OPENSSLFAILURE);
	}

	return ISC_R_SUCCESS;
}
#endif /* OPENSSL_VERSION_NUMBER >= 0x30200000L */

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

static const EVP_MD *
opensslecdsa_key_alg_to_EVP_MD(unsigned int key_alg) {
	switch (key_alg) {
	case DST_ALG_ECDSA256:
		return isc__crypto_sha256;
	case DST_ALG_ECDSA384:
		return isc__crypto_sha384;
	default:
		UNREACHABLE();
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

static int
opensslecdsa_key_alg_to_group_nid(unsigned int key_alg) {
	switch (key_alg) {
	case DST_ALG_ECDSA256:
		return NID_X9_62_prime256v1;
	case DST_ALG_ECDSA384:
		return NID_secp384r1;
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

/*
 * OpenSSL requires us to set the public key portion, but since our private key
 * file format does not contain it directly, we generate it as needed.
 */
static EC_POINT *
opensslecdsa_generate_public_key(const EC_GROUP *group, const BIGNUM *privkey) {
	EC_POINT *pubkey = EC_POINT_new(group);
	if (pubkey == NULL) {
		return NULL;
	}
	if (EC_POINT_mul(group, pubkey, privkey, NULL, NULL, NULL) != 1) {
		EC_POINT_free(pubkey);
		return NULL;
	}

	return pubkey;
}

static int
BN_bn2bin_fixed(const BIGNUM *bn, unsigned char *buf, int size) {
	int bytes = size - BN_num_bytes(bn);

	INSIST(bytes >= 0);

	memset(buf, 0, bytes);
	BN_bn2bin(bn, buf + bytes);

	return size;
}

#if OPENSSL_VERSION_NUMBER >= 0x30000000L

static const char *
opensslecdsa_key_alg_to_group_name(unsigned int key_alg) {
	switch (key_alg) {
	case DST_ALG_ECDSA256:
		return "prime256v1";
	case DST_ALG_ECDSA384:
		return "secp384r1";
	default:
		UNREACHABLE();
	}
}

static isc_result_t
opensslecdsa_create_pkey(unsigned int key_alg, bool private,
			 const unsigned char *key, size_t key_len,
			 EVP_PKEY **pkey) {
	int status;
	int group_nid = opensslecdsa_key_alg_to_group_nid(key_alg);
	const char *groupname = opensslecdsa_key_alg_to_group_name(key_alg);
	auto_OSSL_PARAM_BLD *bld = NULL;
	auto_OSSL_PARAM *params = NULL;
	auto_EVP_PKEY_CTX *ctx = NULL;
	auto_EC_POINT *pubkey = NULL;
	auto_EC_GROUP *group = NULL;
	auto_BIGNUM *priv = NULL;
	unsigned char buf[MAX_PUBKEY_SIZE + 1];

	bld = OSSL_PARAM_BLD_new();
	if (bld == NULL) {
		return dst__openssl_toresult2("OSSL_PARAM_BLD_new",
					      DST_R_OPENSSLFAILURE);
	}
	status = OSSL_PARAM_BLD_push_utf8_string(
		bld, OSSL_PKEY_PARAM_GROUP_NAME, groupname, 0);
	if (status != 1) {
		return dst__openssl_toresult2("OSSL_PARAM_BLD_push_utf8_string",
					      DST_R_OPENSSLFAILURE);
	}

	if (private) {
		group = EC_GROUP_new_by_curve_name(group_nid);
		if (group == NULL) {
			return dst__openssl_toresult2(
				"EC_GROUP_new_by_curve_name",
				DST_R_OPENSSLFAILURE);
		}

		priv = BN_bin2bn(key, key_len, NULL);
		if (priv == NULL) {
			return dst__openssl_toresult2("BN_bin2bn",
						      DST_R_OPENSSLFAILURE);
		}

		status = OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_PRIV_KEY,
						priv);
		if (status != 1) {
			return dst__openssl_toresult2("OSSL_PARAM_BLD_push_BN",
						      DST_R_OPENSSLFAILURE);
		}

		pubkey = opensslecdsa_generate_public_key(group, priv);
		if (pubkey == NULL) {
			return dst__openssl_toresult(DST_R_OPENSSLFAILURE);
		}

		key = buf;
		key_len = EC_POINT_point2oct(group, pubkey,
					     POINT_CONVERSION_UNCOMPRESSED, buf,
					     sizeof(buf), NULL);
		if (key_len == 0) {
			return dst__openssl_toresult2("EC_POINT_point2oct",
						      DST_R_OPENSSLFAILURE);
		}
	} else {
		INSIST(key_len + 1 <= sizeof(buf));
		buf[0] = POINT_CONVERSION_UNCOMPRESSED;
		memmove(buf + 1, key, key_len);
		key = buf;
		key_len = key_len + 1;
	}

	status = OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PUB_KEY,
						  key, key_len);
	if (status != 1) {
		return dst__openssl_toresult2(
			"OSSL_PARAM_BLD_push_octet_string",
			DST_R_OPENSSLFAILURE);
	}

	params = OSSL_PARAM_BLD_to_param(bld);
	if (params == NULL) {
		return dst__openssl_toresult2("OSSL_PARAM_BLD_to_param",
					      DST_R_OPENSSLFAILURE);
	}
	ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
	if (ctx == NULL) {
		return dst__openssl_toresult2("EVP_PKEY_CTX_new_from_name",
					      DST_R_OPENSSLFAILURE);
	}
	status = EVP_PKEY_fromdata_init(ctx);
	if (status != 1) {
		/* This will fail if the default provider is an engine.
		 * Return ISC_R_FAILURE to retry using the legacy API. */
		return dst__openssl_toresult(ISC_R_FAILURE);
	}
	status = EVP_PKEY_fromdata(
		ctx, pkey, private ? EVP_PKEY_KEYPAIR : EVP_PKEY_PUBLIC_KEY,
		params);
	if (status != 1 || *pkey == NULL) {
		return dst__openssl_toresult2("EVP_PKEY_fromdata",
					      DST_R_OPENSSLFAILURE);
	}

	return ISC_R_SUCCESS;
}

static bool
opensslecdsa_extract_public_key(const dst_key_t *key, unsigned char *dst,
				size_t dstlen) {
	EVP_PKEY *pkey = key->keydata.pkeypair.pub;
	auto_BIGNUM *x = NULL;
	auto_BIGNUM *y = NULL;

	if (EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_EC_PUB_X, &x) != 1 ||
	    EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_EC_PUB_Y, &y) != 1)
	{
		return false;
	}

	BN_bn2bin_fixed(x, &dst[0], dstlen / 2);
	BN_bn2bin_fixed(y, &dst[dstlen / 2], dstlen / 2);
	return true;
}

#endif

#if OPENSSL_VERSION_NUMBER < 0x30000000L

static isc_result_t
opensslecdsa_create_pkey(unsigned int key_alg, bool private,
			 const unsigned char *key, size_t key_len,
			 EVP_PKEY **retkey) {
	auto_EC_KEY *eckey = NULL;
	auto_EVP_PKEY *pkey = NULL;
	auto_BIGNUM *privkey = NULL;
	auto_EC_POINT *pubkey = NULL;
	unsigned char buf[MAX_PUBKEY_SIZE + 1];
	int group_nid = opensslecdsa_key_alg_to_group_nid(key_alg);

	eckey = EC_KEY_new_by_curve_name(group_nid);
	if (eckey == NULL) {
		return dst__openssl_toresult(DST_R_OPENSSLFAILURE);
	}

	if (private) {
		const EC_GROUP *group = EC_KEY_get0_group(eckey);

		privkey = BN_bin2bn(key, key_len, NULL);
		if (privkey == NULL) {
			return dst__openssl_toresult(DST_R_OPENSSLFAILURE);
		}
		if (!EC_KEY_set_private_key(eckey, privkey)) {
			return dst__openssl_toresult(DST_R_INVALIDPRIVATEKEY);
		}

		pubkey = opensslecdsa_generate_public_key(group, privkey);
		if (pubkey == NULL) {
			return dst__openssl_toresult(DST_R_OPENSSLFAILURE);
		}
		if (EC_KEY_set_public_key(eckey, pubkey) != 1) {
			return dst__openssl_toresult(DST_R_OPENSSLFAILURE);
		}
	} else {
		const unsigned char *cp = buf;
		INSIST(key_len + 1 <= sizeof(buf));
		buf[0] = POINT_CONVERSION_UNCOMPRESSED;
		memmove(buf + 1, key, key_len);
		if (o2i_ECPublicKey(&eckey, &cp, key_len + 1) == NULL) {
			return dst__openssl_toresult(DST_R_INVALIDPUBLICKEY);
		}
		if (EC_KEY_check_key(eckey) != 1) {
			return dst__openssl_toresult(DST_R_INVALIDPUBLICKEY);
		}
	}

	pkey = EVP_PKEY_new();
	if (pkey == NULL) {
		return dst__openssl_toresult(ISC_R_NOMEMORY);
	}
	if (EVP_PKEY_set1_EC_KEY(pkey, eckey) != 1) {
		return dst__openssl_toresult(DST_R_OPENSSLFAILURE);
	}

	MOVE_INTO(*retkey, pkey);

	return ISC_R_SUCCESS;
}

static bool
opensslecdsa_extract_public_key(const dst_key_t *key, unsigned char *dst,
				size_t dstlen) {
	EVP_PKEY *pkey = key->keydata.pkeypair.pub;
	const EC_KEY *eckey = EVP_PKEY_get0_EC_KEY(pkey);
	const EC_GROUP *group = (eckey == NULL) ? NULL
						: EC_KEY_get0_group(eckey);
	const EC_POINT *pub = (eckey == NULL) ? NULL
					      : EC_KEY_get0_public_key(eckey);
	unsigned char buf[MAX_PUBKEY_SIZE + 1];
	size_t len;

	if (group == NULL || pub == NULL) {
		return false;
	}

	len = EC_POINT_point2oct(group, pub, POINT_CONVERSION_UNCOMPRESSED, buf,
				 sizeof(buf), NULL);
	if (len == dstlen + 1) {
		memmove(dst, buf + 1, dstlen);
		return true;
	}
	return false;
}

#endif

#if OPENSSL_VERSION_NUMBER >= 0x30000000L

static isc_result_t
opensslecdsa_generate_pkey_with_uri(int group_nid, const char *label,
				    EVP_PKEY **retkey) {
	int status;
	char *uri = UNCONST(label);
	auto_EVP_PKEY_CTX *ctx = NULL;
	OSSL_PARAM params[3];

	/* Generate the key's parameters. */
	params[0] = OSSL_PARAM_construct_utf8_string("pkcs11_uri", uri, 0);
	params[1] = OSSL_PARAM_construct_utf8_string(
		"pkcs11_key_usage", (char *)"digitalSignature", 0);
	params[2] = OSSL_PARAM_construct_end();

	ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", "provider=pkcs11");
	if (ctx == NULL) {
		return dst__openssl_toresult2("EVP_PKEY_CTX_new_from_name",
					      DST_R_OPENSSLFAILURE);
	}

	status = EVP_PKEY_keygen_init(ctx);
	if (status != 1) {
		return dst__openssl_toresult2("EVP_PKEY_keygen_init",
					      DST_R_OPENSSLFAILURE);
	}

	status = EVP_PKEY_CTX_set_params(ctx, params);
	if (status != 1) {
		return dst__openssl_toresult2("EVP_PKEY_CTX_set_params",
					      DST_R_OPENSSLFAILURE);
	}
	/*
	 * Setting the P-384 curve doesn't work correctly when using:
	 * OSSL_PARAM_construct_utf8_string("ec_paramgen_curve", "P-384", 0);
	 *
	 * Instead use the OpenSSL function to set the curve nid param.
	 */
	status = EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, group_nid);
	if (status != 1) {
		return dst__openssl_toresult2(
			"EVP_PKEY_CTX_set_ec_paramgen_curve_nid",
			DST_R_OPENSSLFAILURE);
	}

	/* Generate the key. */
	status = EVP_PKEY_generate(ctx, retkey);
	if (status != 1) {
		return dst__openssl_toresult2("EVP_PKEY_generate",
					      DST_R_OPENSSLFAILURE);
	}

	return ISC_R_SUCCESS;
}

static isc_result_t
opensslecdsa_generate_pkey(unsigned int key_alg, const char *label,
			   EVP_PKEY **retkey) {
	auto_EVP_PKEY_CTX *ctx = NULL;
	auto_EVP_PKEY *params_pkey = NULL;
	int group_nid = opensslecdsa_key_alg_to_group_nid(key_alg);
	int status;

	if (label != NULL) {
		return opensslecdsa_generate_pkey_with_uri(group_nid, label,
							   retkey);
	}

	/* Generate the key's parameters. */
	ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
	if (ctx == NULL) {
		return dst__openssl_toresult2("EVP_PKEY_CTX_new_from_name",
					      DST_R_OPENSSLFAILURE);
	}
	status = EVP_PKEY_paramgen_init(ctx);
	if (status != 1) {
		return dst__openssl_toresult2("EVP_PKEY_paramgen_init",
					      DST_R_OPENSSLFAILURE);
	}
	status = EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, group_nid);
	if (status != 1) {
		return dst__openssl_toresult2(
			"EVP_PKEY_CTX_set_ec_paramgen_curve_nid",
			DST_R_OPENSSLFAILURE);
	}
	status = EVP_PKEY_paramgen(ctx, &params_pkey);
	if (status != 1 || params_pkey == NULL) {
		return dst__openssl_toresult2("EVP_PKEY_paramgen",
					      DST_R_OPENSSLFAILURE);
	}
	EVP_PKEY_CTX_free(ctx);

	/* Generate the key. */
	ctx = EVP_PKEY_CTX_new(params_pkey, NULL);
	if (ctx == NULL) {
		return dst__openssl_toresult2("EVP_PKEY_CTX_new",
					      DST_R_OPENSSLFAILURE);
	}

	status = EVP_PKEY_keygen_init(ctx);
	if (status != 1) {
		return dst__openssl_toresult2("EVP_PKEY_keygen_init",
					      DST_R_OPENSSLFAILURE);
	}
	status = EVP_PKEY_keygen(ctx, retkey);
	if (status != 1) {
		return dst__openssl_toresult2("EVP_PKEY_keygen",
					      DST_R_OPENSSLFAILURE);
	}

	return ISC_R_SUCCESS;
}

static isc_result_t
opensslecdsa_validate_pkey_group(unsigned int key_alg, EVP_PKEY *pkey) {
	const char *groupname = opensslecdsa_key_alg_to_group_name(key_alg);
	char gname[64];

	if (EVP_PKEY_get_group_name(pkey, gname, sizeof(gname), NULL) != 1) {
		return DST_R_INVALIDPRIVATEKEY;
	}
	if (strcmp(gname, groupname) != 0) {
		return DST_R_INVALIDPRIVATEKEY;
	}
	return ISC_R_SUCCESS;
}

static bool
opensslecdsa_extract_private_key(const dst_key_t *key, unsigned char *buf,
				 size_t buflen) {
	EVP_PKEY *pkey = key->keydata.pkeypair.priv;
	auto_BIGNUM *priv = NULL;

	if (EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_PRIV_KEY, &priv) != 1) {
		return false;
	}

	BN_bn2bin_fixed(priv, buf, buflen);

	return true;
}

#else

static isc_result_t
opensslecdsa_generate_pkey(unsigned int key_alg,
			   const char *label ISC_ATTR_UNUSED,
			   EVP_PKEY **retkey) {
	int group_nid = opensslecdsa_key_alg_to_group_nid(key_alg);
	auto_EC_KEY *eckey = NULL;
	auto_EVP_PKEY *pkey = NULL;

	eckey = EC_KEY_new_by_curve_name(group_nid);
	if (eckey == NULL) {
		return dst__openssl_toresult2("EC_KEY_new_by_curve_name",
					      DST_R_OPENSSLFAILURE);
	}

	if (EC_KEY_generate_key(eckey) != 1) {
		return dst__openssl_toresult2("EC_KEY_generate_key",
					      DST_R_OPENSSLFAILURE);
	}

	pkey = EVP_PKEY_new();
	if (pkey == NULL) {
		return dst__openssl_toresult(ISC_R_NOMEMORY);
	}
	if (EVP_PKEY_set1_EC_KEY(pkey, eckey) != 1) {
		return dst__openssl_toresult2("EVP_PKEY_set1_EC_KEY",
					      DST_R_OPENSSLFAILURE);
	}

	MOVE_INTO(*retkey, pkey);

	return ISC_R_SUCCESS;
}

static isc_result_t
opensslecdsa_validate_pkey_group(unsigned int key_alg, EVP_PKEY *pkey) {
	const EC_KEY *eckey = EVP_PKEY_get0_EC_KEY(pkey);
	int group_nid;

	if (eckey == NULL) {
		return dst__openssl_toresult(DST_R_INVALIDPRIVATEKEY);
	}

	group_nid = opensslecdsa_key_alg_to_group_nid(key_alg);

	if (EC_GROUP_get_curve_name(EC_KEY_get0_group(eckey)) != group_nid) {
		return DST_R_INVALIDPRIVATEKEY;
	}

	return ISC_R_SUCCESS;
}

static bool
opensslecdsa_extract_private_key(const dst_key_t *key, unsigned char *buf,
				 size_t buflen) {
	const EC_KEY *eckey = NULL;
	const BIGNUM *privkey = NULL;

	eckey = EVP_PKEY_get0_EC_KEY(key->keydata.pkeypair.priv);
	if (eckey == NULL) {
		ERR_clear_error();
		return false;
	}

	privkey = EC_KEY_get0_private_key(eckey);
	if (privkey == NULL) {
		ERR_clear_error();
		return false;
	}

	BN_bn2bin_fixed(privkey, buf, buflen);
	return true;
}

#endif /* OPENSSL_VERSION_NUMBER >= 0x30000000L */

static isc_result_t
opensslecdsa_createctx(dst_key_t *key ISC_ATTR_UNUSED, dst_context_t *dctx) {
	REQUIRE(opensslecdsa_valid_key_alg(dctx->key->key_alg));

	const EVP_MD *type = opensslecdsa_key_alg_to_EVP_MD(dctx->key->key_alg);
	auto_EVP_MD_CTX *evp_md_ctx = EVP_MD_CTX_create();

	if (evp_md_ctx == NULL) {
		return dst__openssl_toresult(ISC_R_NOMEMORY);
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

#if OPENSSL_VERSION_NUMBER >= 0x30200000L
		if (!isc_crypto_fips_mode()) {
			isc_result_t result = opensslecdsa_set_deterministic(
				pctx, dctx->key->key_alg);
			if (result != ISC_R_SUCCESS) {
				return dst__openssl_toresult(result);
			}
		}
#endif /* OPENSSL_VERSION_NUMBER >= 0x30200000L */
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

	isc_result_t result;
	auto_EVP_PKEY *pkey = NULL;

	result = opensslecdsa_generate_pkey(key->key_alg, key->label, &pkey);
	if (result != ISC_R_SUCCESS) {
		return result;
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
	size_t keysize;

	keysize = opensslecdsa_key_alg_to_publickey_size(key->key_alg);
	isc_buffer_availableregion(data, &r);
	if (r.length < keysize) {
		return ISC_R_NOSPACE;
	}
	if (!opensslecdsa_extract_public_key(key, r.base, keysize)) {
		return dst__openssl_toresult(DST_R_OPENSSLFAILURE);
	}

	isc_buffer_add(data, keysize);

	return ISC_R_SUCCESS;
}

static isc_result_t
opensslecdsa_fromdns(dst_key_t *key, isc_buffer_t *data) {
	isc_result_t result;
	auto_EVP_PKEY *pkey = NULL;
	isc_region_t r;
	size_t len;

	REQUIRE(opensslecdsa_valid_key_alg(key->key_alg));
	len = opensslecdsa_key_alg_to_publickey_size(key->key_alg);

	isc_buffer_remainingregion(data, &r);
	if (r.length == 0) {
		return ISC_R_SUCCESS;
	}
	if (r.length != len) {
		return DST_R_INVALIDPUBLICKEY;
	}

	result = opensslecdsa_create_pkey(key->key_alg, false, r.base, len,
					  &pkey);
	if (result != ISC_R_SUCCESS) {
		return result;
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

	i = 0;
	if (opensslecdsa_extract_private_key(key, buf, keylen)) {
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
	isc_result_t result;
	auto_EVP_PKEY *pkey = NULL;
	const char *label = NULL;
	int privkey_index = -1;

	if (key->external) {
		if (priv->nelements != 0 || pub == NULL) {
			return dst__openssl_toresult(DST_R_INVALIDPRIVATEKEY);
		}
		MOVE_INTO(key->keydata.pkeypair.priv,
			  pub->keydata.pkeypair.priv);
		MOVE_INTO(key->keydata.pkeypair.pub, pub->keydata.pkeypair.pub);
		return ISC_R_SUCCESS;
	}

	for (size_t i = 0; i < priv->nelements; i++) {
		switch (priv->elements[i].tag) {
		case TAG_ECDSA_ENGINE:
			/* The Engine: tag is explicitly ignored */
			break;
		case TAG_ECDSA_LABEL:
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
		result = opensslecdsa_fromlabel(key, label, NULL);
		if (result != ISC_R_SUCCESS) {
			return result;
		}
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

	result = opensslecdsa_create_pkey(
		key->key_alg, true, priv->elements[privkey_index].data,
		priv->elements[privkey_index].length, &pkey);
	if (result != ISC_R_SUCCESS) {
		return result;
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
	result = dst__privstruct_parse(key, DST_ALG_ECDSA256, lexer, key->mctx,
				       &priv);
	if (result != ISC_R_SUCCESS) {
		return result;
	}

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
	isc_result_t result;

	result = dst__openssl_fromlabel(EVP_PKEY_EC, label, pin, &pubpkey,
					&privpkey);
	if (result != ISC_R_SUCCESS) {
		return result;
	}

	result = opensslecdsa_validate_pkey_group(key->key_alg, privpkey);
	if (result != ISC_R_SUCCESS) {
		return result;
	}

	result = opensslecdsa_validate_pkey_group(key->key_alg, pubpkey);
	if (result != ISC_R_SUCCESS) {
		return result;
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
