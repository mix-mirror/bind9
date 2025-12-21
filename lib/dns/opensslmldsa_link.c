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

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/x509.h>

#include <isc/mem.h>
#include <isc/result.h>
#include <isc/safe.h>
#include <isc/string.h>
#include <isc/util.h>

#include <dns/keyvalues.h>

#include "dst/dst.h"
#include "dst_internal.h"
#include "dst_openssl.h"
#include "dst_parse.h"

typedef struct mldsa_alginfo {
	int pkey_type, nid;
	unsigned int key_size, sig_size;
} mldsa_alginfo_t;

static const mldsa_alginfo_t *
opensslmldsa_alg_info(unsigned int key_alg) {
	if (key_alg == DST_ALG_MLDSA44) {
		static const mldsa_alginfo_t mldsa44_alginfo = {
			.pkey_type = EVP_PKEY_ML_DSA_44,
			.nid = NID_ML_DSA_44,
			.key_size = DNS_KEY_MLDSA44SIZE,
			.sig_size = DNS_SIG_MLDSA44SIZE,
		};
		return &mldsa44_alginfo;
	}
	if (key_alg == DST_ALG_MLDSA65) {
		static const mldsa_alginfo_t mldsa65_alginfo = {
			.pkey_type = EVP_PKEY_ML_DSA_65,
			.nid = NID_ML_DSA_65,
			.key_size = DNS_KEY_MLDSA65SIZE,
			.sig_size = DNS_SIG_MLDSA65SIZE,
		};
		return &mldsa65_alginfo;
	}
	if (key_alg == DST_ALG_MLDSA87) {
		static const mldsa_alginfo_t mldsa65_alginfo = {
			.pkey_type = EVP_PKEY_ML_DSA_87,
			.nid = NID_ML_DSA_87,
			.key_size = DNS_KEY_MLDSA87SIZE,
			.sig_size = DNS_SIG_MLDSA87SIZE,
		};
		return &mldsa65_alginfo;
	}
	return NULL;
}

static isc_result_t
raw_key_to_ossl(const mldsa_alginfo_t *alginfo, int private,
		const unsigned char *key, size_t *key_len, EVP_PKEY **pkey) {
	isc_result_t result;
	int pkey_type = alginfo->pkey_type;
	size_t len = private ? MAX_MLDSA_PRIVKEY_SIZE : alginfo->key_size;

	result = (private ? DST_R_INVALIDPRIVATEKEY : DST_R_INVALIDPUBLICKEY);

	if (*key_len < len && !private) {
		return result;
	}

	if (private) {
		*pkey = EVP_PKEY_new_raw_private_key(pkey_type, NULL, key,
						     *key_len);
	} else {
		*pkey = EVP_PKEY_new_raw_public_key(pkey_type, NULL, key, len);
	}

	if (*pkey == NULL) {
		return dst__openssl_toresult(result);
	}

	if (!private) {
		*key_len = len;
	}
	return ISC_R_SUCCESS;
}

static isc_result_t
opensslmldsa_fromlabel(dst_key_t *key, const char *label, const char *pin);

static isc_result_t
opensslmldsa_createctx(dst_key_t *key ISC_ATTR_UNUSED, dst_context_t *dctx) {
	isc_buffer_t *buf = NULL;
	const mldsa_alginfo_t *alginfo =
		opensslmldsa_alg_info(dctx->key->key_alg);

	REQUIRE(alginfo != NULL);

	isc_buffer_allocate(dctx->mctx, &buf, 64);
	dctx->ctxdata.generic = buf;

	return ISC_R_SUCCESS;
}

static void
opensslmldsa_destroyctx(dst_context_t *dctx) {
	isc_buffer_t *buf = (isc_buffer_t *)dctx->ctxdata.generic;
	const mldsa_alginfo_t *alginfo =
		opensslmldsa_alg_info(dctx->key->key_alg);

	REQUIRE(alginfo != NULL);
	if (buf != NULL) {
		isc_buffer_free(&buf);
	}
	dctx->ctxdata.generic = NULL;
}

static isc_result_t
opensslmldsa_adddata(dst_context_t *dctx, const isc_region_t *data) {
	isc_buffer_t *buf = (isc_buffer_t *)dctx->ctxdata.generic;
	isc_buffer_t *nbuf = NULL;
	isc_region_t r;
	unsigned int length;
	isc_result_t result;
	const mldsa_alginfo_t *alginfo =
		opensslmldsa_alg_info(dctx->key->key_alg);

	REQUIRE(alginfo != NULL);

	result = isc_buffer_copyregion(buf, data);
	if (result == ISC_R_SUCCESS) {
		return ISC_R_SUCCESS;
	}

	length = isc_buffer_length(buf) + data->length + 64;
	isc_buffer_allocate(dctx->mctx, &nbuf, length);
	isc_buffer_usedregion(buf, &r);
	(void)isc_buffer_copyregion(nbuf, &r);
	(void)isc_buffer_copyregion(nbuf, data);
	isc_buffer_free(&buf);
	dctx->ctxdata.generic = nbuf;

	return ISC_R_SUCCESS;
}

static isc_result_t
opensslmldsa_sign(dst_context_t *dctx, isc_buffer_t *sig) {
	isc_result_t result;
	dst_key_t *key = dctx->key;
	isc_region_t tbsreg;
	isc_region_t sigreg;
	EVP_PKEY *pkey = key->keydata.pkeypair.priv;
	EVP_MD_CTX *ctx = NULL;
	isc_buffer_t *buf = (isc_buffer_t *)dctx->ctxdata.generic;
	const mldsa_alginfo_t *alginfo = opensslmldsa_alg_info(key->key_alg);
	size_t siglen;

	REQUIRE(alginfo != NULL);

	if (pkey == NULL) {
		return DST_R_NULLKEY;
	}

	EVP_PKEY_CTX *sctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
	EVP_SIGNATURE *sig_alg = NULL;

	/* FIXME: do this once in the initializer */
	switch (alginfo->pkey_type) {
	case EVP_PKEY_ML_DSA_44:
		sig_alg = sig_alg_ml_dsa_44;
		break;
	case EVP_PKEY_ML_DSA_65:
		sig_alg = sig_alg_ml_dsa_65;
		break;
	case EVP_PKEY_ML_DSA_87:
		sig_alg = sig_alg_ml_dsa_87;
		break;
	default:
		UNREACHABLE();
	}

	isc_buffer_usedregion(buf, &tbsreg);

	if (EVP_PKEY_sign_message_init(sctx, sig_alg, NULL) != 1) {
		result = dst__openssl_toresult3(dctx->category,
						"EVP_PKEY_sign_message_init",
						DST_R_SIGNFAILURE);
		goto cleanup;
	}

	if (EVP_PKEY_sign(sctx, NULL, &siglen, tbsreg.base, tbsreg.length) != 1)
	{
		result = dst__openssl_toresult3(dctx->category, "EVP_PKEY_sign",
						DST_R_SIGNFAILURE);
		goto cleanup;
	}

	isc_buffer_availableregion(sig, &sigreg);
	if (sigreg.length < siglen) {
		EVP_MD_CTX_free(ctx);
		result = ISC_R_NOSPACE;
		goto cleanup;
	}

	if (EVP_PKEY_sign(sctx, sigreg.base, &siglen, tbsreg.base,
			  tbsreg.length) != 1)
	{
		result = dst__openssl_toresult3(dctx->category, "EVP_PKEY_sign",
						DST_R_SIGNFAILURE);
		goto cleanup;
	}

	isc_buffer_add(sig, (unsigned int)siglen);
	result = ISC_R_SUCCESS;

cleanup:
	isc_buffer_free(&buf);
	dctx->ctxdata.generic = NULL;

	EVP_PKEY_CTX_free(sctx);

	return result;
}

static isc_result_t
opensslmldsa_verify(dst_context_t *dctx, const isc_region_t *sig) {
	isc_result_t result;
	dst_key_t *key = dctx->key;
	int status;
	isc_region_t tbsreg;
	EVP_PKEY *pkey = key->keydata.pkeypair.pub;
	isc_buffer_t *buf = (isc_buffer_t *)dctx->ctxdata.generic;
	const mldsa_alginfo_t *alginfo = opensslmldsa_alg_info(key->key_alg);

	REQUIRE(alginfo != NULL);

	if (pkey == NULL) {
		return DST_R_NULLKEY;
	}

	EVP_PKEY_CTX *sctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
	EVP_SIGNATURE *sig_alg = NULL;

	switch (alginfo->pkey_type) {
	case EVP_PKEY_ML_DSA_44:
		sig_alg = sig_alg_ml_dsa_44;
		break;
	case EVP_PKEY_ML_DSA_65:
		sig_alg = sig_alg_ml_dsa_65;
		break;
	case EVP_PKEY_ML_DSA_87:
		sig_alg = sig_alg_ml_dsa_87;
		break;
	default:
		UNREACHABLE();
	}

	isc_buffer_usedregion(buf, &tbsreg);

	if (EVP_PKEY_verify_message_init(sctx, sig_alg, NULL) != 1) {
		result = dst__openssl_toresult3(dctx->category,
						"EVP_PKEY_verify_message_init",
						DST_R_VERIFYFAILURE);
		goto cleanup;
	}

	status = EVP_PKEY_verify(sctx, sig->base, sig->length, tbsreg.base,
				 tbsreg.length);

	switch (status) {
	case 1:
		result = ISC_R_SUCCESS;
		break;
	case 0:
		result = dst__openssl_toresult(DST_R_VERIFYFAILURE);
		break;
	default:
		result = dst__openssl_toresult3(
			dctx->category, "EVP_PKEY_verify", DST_R_VERIFYFAILURE);
		break;
	}

cleanup:
	isc_buffer_free(&buf);
	dctx->ctxdata.generic = NULL;
	EVP_PKEY_CTX_free(sctx);

	return result;
}

static isc_result_t
opensslmldsa_generate(dst_key_t *key, int unused ISC_ATTR_UNUSED,
		      void (*callback ISC_ATTR_UNUSED)(int)) {
	isc_result_t result;
	EVP_PKEY *pkey = NULL;
	EVP_PKEY_CTX *ctx = NULL;
	const mldsa_alginfo_t *alginfo = opensslmldsa_alg_info(key->key_alg);

	REQUIRE(alginfo != NULL);

	ctx = EVP_PKEY_CTX_new_id(alginfo->nid, NULL);
	if (ctx == NULL) {
		return dst__openssl_toresult2("EVP_PKEY_CTX_new_id",
					      DST_R_OPENSSLFAILURE);
	}

	if (EVP_PKEY_keygen_init(ctx) != 1) {
		result = dst__openssl_toresult2("EVP_PKEY_keygen_init",
						DST_R_OPENSSLFAILURE);
		goto cleanup;
	}

	if (EVP_PKEY_keygen(ctx, &pkey) != 1) {
		result = dst__openssl_toresult2("EVP_PKEY_keygen",
						DST_R_OPENSSLFAILURE);
		goto cleanup;
	}

	key->key_size = alginfo->key_size * 8;
	key->keydata.pkeypair.priv = pkey;
	key->keydata.pkeypair.pub = pkey;
	result = ISC_R_SUCCESS;

cleanup:
	EVP_PKEY_CTX_free(ctx);
	return result;
}

static isc_result_t
opensslmldsa_todns(const dst_key_t *key, isc_buffer_t *data) {
	const mldsa_alginfo_t *alginfo = opensslmldsa_alg_info(key->key_alg);
	EVP_PKEY *pkey = key->keydata.pkeypair.pub;
	isc_region_t r;
	size_t len;

	REQUIRE(pkey != NULL);
	REQUIRE(alginfo != NULL);

	len = alginfo->key_size;
	isc_buffer_availableregion(data, &r);
	if (r.length < len) {
		return ISC_R_NOSPACE;
	}

	if (EVP_PKEY_get_raw_public_key(pkey, r.base, &len) != 1) {
		return dst__openssl_toresult(ISC_R_FAILURE);
	}

	isc_buffer_add(data, len);
	return ISC_R_SUCCESS;
}

static isc_result_t
opensslmldsa_fromdns(dst_key_t *key, isc_buffer_t *data) {
	const mldsa_alginfo_t *alginfo = opensslmldsa_alg_info(key->key_alg);
	isc_region_t r;
	size_t len;
	EVP_PKEY *pkey = NULL;

	REQUIRE(alginfo != NULL);

	isc_buffer_remainingregion(data, &r);
	if (r.length == 0) {
		return ISC_R_SUCCESS;
	}

	len = r.length;
	RETERR(raw_key_to_ossl(alginfo, 0, r.base, &len, &pkey));

	isc_buffer_forward(data, len);
	key->keydata.pkeypair.pub = pkey;
	key->key_size = len * 8;
	return ISC_R_SUCCESS;
}

static isc_result_t
opensslmldsa_tofile(const dst_key_t *key, const char *directory) {
	const mldsa_alginfo_t *alginfo = opensslmldsa_alg_info(key->key_alg);
	isc_result_t result;
	dst_private_t priv;
	unsigned char *buf = NULL;
	size_t len;
	int i;

	REQUIRE(alginfo != NULL);

	if (key->keydata.pkeypair.pub == NULL) {
		return DST_R_NULLKEY;
	}

	if (key->external) {
		priv.nelements = 0;
		return dst__privstruct_writefile(key, &priv, directory);
	}

	i = 0;

	if (dst__openssl_keypair_isprivate(key)) {
		len = MAX_MLDSA_PRIVKEY_SIZE;
		buf = isc_mem_get(key->mctx, len);
		if (EVP_PKEY_get_raw_private_key(key->keydata.pkeypair.priv,
						 buf, &len) != 1)
		{
			result = dst__openssl_toresult(ISC_R_FAILURE);
			goto cleanup;
		}
		priv.elements[i].tag = TAG_MLDSA_PRIVATEKEY;
		priv.elements[i].length = len;
		priv.elements[i].data = buf;
		i++;
	}

	if (key->label != NULL) {
		priv.elements[i].tag = TAG_MLDSA_LABEL;
		priv.elements[i].length = (unsigned short)strlen(key->label) +
					  1;
		priv.elements[i].data = (unsigned char *)key->label;
		i++;
	}

	priv.nelements = i;
	result = dst__privstruct_writefile(key, &priv, directory);

cleanup:
	if (buf != NULL) {
		isc_safe_memwipe(buf, MAX_MLDSA_PRIVKEY_SIZE);
		isc_mem_put(key->mctx, buf, MAX_MLDSA_PRIVKEY_SIZE);
	}
	return result;
}

static isc_result_t
opensslmldsa_parse(dst_key_t *key, isc_lex_t *lexer, dst_key_t *pub) {
	const mldsa_alginfo_t *alginfo = opensslmldsa_alg_info(key->key_alg);
	dst_private_t priv;
	isc_result_t result;
	int i, privkey_index = -1;
	const char *label = NULL;
	EVP_PKEY *pkey = NULL;
	size_t len;
	isc_mem_t *mctx = key->mctx;

	REQUIRE(alginfo != NULL);

	/* read private key file */
	CHECK(dst__privstruct_parse(key, key->key_alg, lexer, mctx, &priv));

	if (key->external) {
		if (priv.nelements != 0) {
			result = DST_R_INVALIDPRIVATEKEY;
			goto cleanup;
		}
		if (pub == NULL) {
			result = DST_R_INVALIDPRIVATEKEY;
			goto cleanup;
		}
		key->keydata.pkeypair.priv = pub->keydata.pkeypair.priv;
		key->keydata.pkeypair.pub = pub->keydata.pkeypair.pub;
		pub->keydata.pkeypair.priv = NULL;
		pub->keydata.pkeypair.pub = NULL;
		result = ISC_R_SUCCESS;
		goto cleanup;
	}

	for (i = 0; i < priv.nelements; i++) {
		switch (priv.elements[i].tag) {
		case TAG_MLDSA_ENGINE:
			/* The Engine: tag is explicitly ignored */
			break;
		case TAG_MLDSA_LABEL:
			label = (char *)priv.elements[i].data;
			break;
		case TAG_MLDSA_PRIVATEKEY:
			privkey_index = i;
			break;
		default:
			break;
		}
	}

	if (label != NULL) {
		CHECK(opensslmldsa_fromlabel(key, label, NULL));
		/* Check that the public component matches if given */
		if (pub != NULL && EVP_PKEY_eq(key->keydata.pkeypair.pub,
					       pub->keydata.pkeypair.pub) != 1)
		{
			result = DST_R_INVALIDPRIVATEKEY;
			goto cleanup;
		}
		result = ISC_R_SUCCESS;
		goto cleanup;
	}

	if (privkey_index < 0) {
		result = DST_R_INVALIDPRIVATEKEY;
		goto cleanup;
	}

	len = priv.elements[privkey_index].length;
	CHECK(raw_key_to_ossl(alginfo, 1, priv.elements[privkey_index].data,
			      &len, &pkey));

	/* Check that the public component matches if given */
	if (pub != NULL && EVP_PKEY_eq(pkey, pub->keydata.pkeypair.pub) != 1) {
		result = DST_R_INVALIDPRIVATEKEY;
		goto cleanup;
	}

	key->keydata.pkeypair.priv = pkey;
	key->keydata.pkeypair.pub = pkey;
	key->key_size = alginfo->key_size * 8;
	pkey = NULL;
	result = ISC_R_SUCCESS;

cleanup:
	EVP_PKEY_free(pkey);
	dst__privstruct_free(&priv, mctx);
	isc_safe_memwipe(&priv, sizeof(priv));
	return result;
}

static isc_result_t
opensslmldsa_fromlabel(dst_key_t *key, const char *label, const char *pin) {
	const mldsa_alginfo_t *alginfo = opensslmldsa_alg_info(key->key_alg);
	EVP_PKEY *privpkey = NULL, *pubpkey = NULL;
	isc_result_t result;

	REQUIRE(alginfo != NULL);
	UNUSED(pin);

	CHECK(dst__openssl_fromlabel(alginfo->pkey_type, label, pin, &pubpkey,
				     &privpkey));

	key->label = isc_mem_strdup(key->mctx, label);
	key->key_size = EVP_PKEY_bits(privpkey);
	key->keydata.pkeypair.priv = privpkey;
	key->keydata.pkeypair.pub = pubpkey;
	privpkey = NULL;
	pubpkey = NULL;

cleanup:
	EVP_PKEY_free(privpkey);
	EVP_PKEY_free(pubpkey);
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
	.fromlabel = opensslmldsa_fromlabel,
};

/*
 * Test vectors for ML-DSA validation
 * These should be updated with official NIST test vectors
 */
static unsigned char mldsa44_pub[] = {
	/* Placeholder for ML-DSA-44 public key test vector */
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	/* ... rest of public key ... */
};

static unsigned char mldsa44_sig[] = {
	/* Placeholder for ML-DSA-44 signature test vector */
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	/* ... rest of signature ... */
};

static unsigned char mldsa65_pub[] = {
	/* Placeholder for ML-DSA-65 public key test vector */
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	/* ... rest of public key ... */
};

static unsigned char mldsa65_sig[] = {
	/* Placeholder for ML-DSA-65 signature test vector */
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	/* ... rest of signature ... */
};

static isc_result_t
check_algorithm(unsigned char algorithm) {
	EVP_MD_CTX *evp_md_ctx = EVP_MD_CTX_create();
	EVP_PKEY *pkey = NULL;
	const mldsa_alginfo_t *alginfo = NULL;
	const unsigned char *key = NULL;
	const unsigned char *sig = NULL;
	const unsigned char test[] = "test";
	isc_result_t result = ISC_R_SUCCESS;
	size_t key_len, sig_len;

	if (evp_md_ctx == NULL) {
		return ISC_R_NOMEMORY;
	}

	switch (algorithm) {
	case DST_ALG_MLDSA44:
		sig = mldsa44_sig;
		sig_len = sizeof(mldsa44_sig) - 1;
		key = mldsa44_pub;
		key_len = sizeof(mldsa44_pub) - 1;
		alginfo = opensslmldsa_alg_info(algorithm);
		break;
	case DST_ALG_MLDSA65:
		sig = mldsa65_sig;
		sig_len = sizeof(mldsa65_sig) - 1;
		key = mldsa65_pub;
		key_len = sizeof(mldsa65_pub) - 1;
		alginfo = opensslmldsa_alg_info(algorithm);
		break;
	default:
		result = ISC_R_NOTIMPLEMENTED;
		goto cleanup;
	}

	INSIST(alginfo != NULL);
	result = raw_key_to_ossl(alginfo, 0, key, &key_len, &pkey);
	if (result != ISC_R_SUCCESS) {
		goto cleanup;
	}

	/*
	 * Check that we can verify the signature.
	 */
	if (EVP_DigestVerifyInit(evp_md_ctx, NULL, NULL, NULL, pkey) != 1 ||
	    EVP_DigestVerify(evp_md_ctx, sig, sig_len, test,
			     sizeof(test) - 1) != 1)
	{
		result = ISC_R_NOTIMPLEMENTED;
	}

cleanup:
	if (pkey != NULL) {
		EVP_PKEY_free(pkey);
	}
	if (evp_md_ctx != NULL) {
		EVP_MD_CTX_destroy(evp_md_ctx);
	}
	ERR_clear_error();
	return result;
}

void
dst__opensslmldsa_init(dst_func_t **funcp, unsigned char algorithm) {
	REQUIRE(funcp != NULL);

	if (*funcp == NULL) {
		if (check_algorithm(algorithm) == ISC_R_SUCCESS) {
			*funcp = &opensslmldsa_functions;
		}
	}
}
