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

#include <string.h>

#include <isc/mem.h>
#include <isc/result.h>
#include <isc/safe.h>
#include <isc/util.h>

#include <dns/keyvalues.h>
#include <dns/mayo.h>

#include "dst_internal.h"
#include "dst_parse.h"

/*
 * The DNS_*_MAYOSIZE constants in <dns/keyvalues.h> are hand-written literals
 * so that <oqs/oqs.h> does not need to be pulled in tree-wide. Make sure they
 * still match the variant provided by liboqs.
 */
STATIC_ASSERT(DNS_KEY_MAYOSIZE == OQS_SIG_mayo_2_length_public_key,
	      "DNS_KEY_MAYOSIZE does not match liboqs MAYO-2 public key size");
STATIC_ASSERT(DNS_SEC_MAYOSIZE == OQS_SIG_mayo_2_length_secret_key,
	      "DNS_SEC_MAYOSIZE does not match liboqs MAYO-2 secret key size");
STATIC_ASSERT(DNS_SIG_MAYOSIZE == OQS_SIG_mayo_2_length_signature,
	      "DNS_SIG_MAYOSIZE does not match liboqs MAYO-2 signature size");

static isc_result_t
dst__mayo_createctx(dst_key_t *key ISC_ATTR_UNUSED, dst_context_t *dctx) {
	isc_buffer_t *buf = NULL;

	REQUIRE(dctx != NULL && dctx->key != NULL);
	REQUIRE(dctx->key->key_alg == DST_ALG_MAYO);

	isc_buffer_allocate(dctx->mctx, &buf, 64);
	dctx->ctxdata.generic = buf;

	return ISC_R_SUCCESS;
}

static void
dst__mayo_destroyctx(dst_context_t *dctx) {
	isc_buffer_t *buf = dctx->ctxdata.generic;

	REQUIRE(dctx != NULL && dctx->key != NULL);
	REQUIRE(dctx->key->key_alg == DST_ALG_MAYO);

	if (buf != NULL) {
		isc_buffer_free(&buf);
		dctx->ctxdata.generic = NULL;
	}
}

static isc_result_t
dst__mayo_adddata(dst_context_t *dctx, const isc_region_t *data) {
	isc_buffer_t *buf = dctx->ctxdata.generic;
	isc_result_t result;

	REQUIRE(dctx != NULL && dctx->key != NULL);
	REQUIRE(dctx->key->key_alg == DST_ALG_MAYO);

	result = isc_buffer_copyregion(buf, data);
	INSIST(result == ISC_R_SUCCESS);

	return ISC_R_SUCCESS;
}

static isc_result_t
dst__mayo_sign(dst_context_t *dctx, isc_buffer_t *sig) {
	isc_result_t result = ISC_R_SUCCESS;
	dst_key_t *key = dctx->key;
	isc_buffer_t *buf = dctx->ctxdata.generic;
	OQS_SIG *oqs = NULL;
	isc_region_t tbsreg;
	isc_region_t sigreg;
	uint8_t *sigout = NULL;
	size_t siglen = DNS_SIG_MAYOSIZE;

	REQUIRE(dctx != NULL && dctx->key != NULL);
	REQUIRE(dctx->key->key_alg == DST_ALG_MAYO);

	isc_buffer_availableregion(sig, &sigreg);
	if (sigreg.length < DNS_SIG_MAYOSIZE) {
		result = ISC_R_NOSPACE;
		goto done;
	}

	oqs = OQS_SIG_new(DNS_MAYO_ALG);
	if (oqs == NULL) {
		result = DST_R_SIGNFAILURE;
		goto done;
	}

	isc_buffer_usedregion(buf, &tbsreg);

	sigout = isc_mem_get(dctx->mctx, DNS_SIG_MAYOSIZE);
	if (OQS_SIG_sign(oqs, sigout, &siglen, tbsreg.base, tbsreg.length,
			 key->keydata.keypair.priv) != OQS_SUCCESS)
	{
		result = DST_R_SIGNFAILURE;
		goto done;
	}
	INSIST(siglen == DNS_SIG_MAYOSIZE);

	isc_buffer_putmem(sig, sigout, siglen);

done:
	if (sigout != NULL) {
		isc_mem_put(dctx->mctx, sigout, DNS_SIG_MAYOSIZE);
	}
	if (oqs != NULL) {
		OQS_SIG_free(oqs);
	}
	isc_buffer_free(&buf);
	dctx->ctxdata.generic = NULL;

	return result;
}

static isc_result_t
dst__mayo_verify(dst_context_t *dctx, const isc_region_t *sigreg) {
	isc_result_t result = ISC_R_SUCCESS;
	dst_key_t *key = dctx->key;
	isc_buffer_t *buf = dctx->ctxdata.generic;
	OQS_SIG *oqs = NULL;
	isc_region_t tbsreg;

	REQUIRE(dctx != NULL && dctx->key != NULL);
	REQUIRE(dctx->key->key_alg == DST_ALG_MAYO);

	if (sigreg->length != DNS_SIG_MAYOSIZE) {
		result = DST_R_VERIFYFAILURE;
		goto done;
	}

	oqs = OQS_SIG_new(DNS_MAYO_ALG);
	if (oqs == NULL) {
		result = DST_R_VERIFYFAILURE;
		goto done;
	}

	isc_buffer_usedregion(buf, &tbsreg);

	if (OQS_SIG_verify(oqs, tbsreg.base, tbsreg.length, sigreg->base,
			   sigreg->length,
			   key->keydata.keypair.pub) != OQS_SUCCESS)
	{
		result = DST_R_VERIFYFAILURE;
		goto done;
	}

done:
	if (oqs != NULL) {
		OQS_SIG_free(oqs);
	}
	isc_buffer_free(&buf);
	dctx->ctxdata.generic = NULL;

	return result;
}

static bool
dst__mayo_compare(const dst_key_t *key1, const dst_key_t *key2) {
	uint8_t *pk1 = key1->keydata.keypair.pub;
	uint8_t *pk2 = key2->keydata.keypair.pub;
	uint8_t *sk1 = key1->keydata.keypair.priv;
	uint8_t *sk2 = key2->keydata.keypair.priv;

	if (pk1 == pk2 && sk1 == sk2) {
		/* The keys are identical or all NULL. */
		return true;
	} else if (pk1 == NULL || pk2 == NULL) {
		return false;
	}

	if (memcmp(pk1, pk2, DNS_KEY_MAYOSIZE) != 0) {
		return false;
	}

	if (sk1 == sk2) {
		/* The private keys are identical or both NULL. */
		return true;
	} else if (sk1 == NULL || sk2 == NULL) {
		return false;
	}

	if (isc_safe_memequal(sk1, sk2, DNS_SEC_MAYOSIZE) == 0) {
		return false;
	}

	return true;
}

static isc_result_t
dst__mayo_generate(dst_key_t *key, int unused ISC_ATTR_UNUSED,
		   void (*callback ISC_ATTR_UNUSED)(int)) {
	isc_result_t result = ISC_R_SUCCESS;
	OQS_SIG *oqs = NULL;
	uint8_t *pk = NULL;
	uint8_t *sk = NULL;

	REQUIRE(key != NULL);
	REQUIRE(key->key_alg == DST_ALG_MAYO);
	REQUIRE(key->keydata.keypair.pub == NULL &&
		key->keydata.keypair.priv == NULL);

	oqs = OQS_SIG_new(DNS_MAYO_ALG);
	if (oqs == NULL) {
		return DST_R_CRYPTOFAILURE;
	}

	pk = isc_mem_get(key->mctx, DNS_KEY_MAYOSIZE);
	sk = isc_mem_get(key->mctx, DNS_SEC_MAYOSIZE);

	if (OQS_SIG_keypair(oqs, pk, sk) != OQS_SUCCESS) {
		result = DST_R_CRYPTOFAILURE;
		goto done;
	}

	key->keydata.keypair.pub = pk;
	key->keydata.keypair.priv = sk;
	key->key_size = DNS_KEY_MAYOSIZE * 8;
	pk = NULL;
	sk = NULL;

done:
	if (pk != NULL) {
		isc_mem_put(key->mctx, pk, DNS_KEY_MAYOSIZE);
	}
	if (sk != NULL) {
		isc_safe_memwipe(sk, DNS_SEC_MAYOSIZE);
		isc_mem_put(key->mctx, sk, DNS_SEC_MAYOSIZE);
	}
	OQS_SIG_free(oqs);

	return result;
}

static isc_result_t
dst__mayo_todns(const dst_key_t *key, isc_buffer_t *data) {
	isc_region_t r;

	REQUIRE(key != NULL);
	REQUIRE(key->key_alg == DST_ALG_MAYO);
	REQUIRE(key->keydata.keypair.pub != NULL);

	isc_buffer_availableregion(data, &r);
	if (r.length < DNS_KEY_MAYOSIZE) {
		return ISC_R_NOSPACE;
	}

	isc_buffer_putmem(data, key->keydata.keypair.pub, DNS_KEY_MAYOSIZE);

	return ISC_R_SUCCESS;
}

static isc_result_t
dst__mayo_fromdns(dst_key_t *key, isc_buffer_t *data) {
	isc_region_t r;

	REQUIRE(key != NULL);
	REQUIRE(key->key_alg == DST_ALG_MAYO);
	REQUIRE(key->keydata.keypair.pub == NULL);

	isc_buffer_remainingregion(data, &r);
	if (r.length == 0) {
		return ISC_R_SUCCESS;
	}
	if (r.length != DNS_KEY_MAYOSIZE) {
		return DST_R_INVALIDPUBLICKEY;
	}

	key->keydata.keypair.pub = isc_mem_get(key->mctx, DNS_KEY_MAYOSIZE);
	memmove(key->keydata.keypair.pub, r.base, DNS_KEY_MAYOSIZE);
	isc_buffer_forward(data, DNS_KEY_MAYOSIZE);
	key->key_size = DNS_KEY_MAYOSIZE * 8;

	return ISC_R_SUCCESS;
}

static bool
dst__mayo_isprivate(const dst_key_t *key) {
	return key->keydata.keypair.priv != NULL;
}

static void
dst__mayo_destroy(dst_key_t *key) {
	REQUIRE(key != NULL);
	REQUIRE(key->key_alg == DST_ALG_MAYO);

	if (key->keydata.keypair.priv != NULL) {
		isc_safe_memwipe(key->keydata.keypair.priv, DNS_SEC_MAYOSIZE);
		isc_mem_put(key->mctx, key->keydata.keypair.priv,
			    DNS_SEC_MAYOSIZE);
	}

	if (key->keydata.keypair.pub != NULL) {
		isc_mem_put(key->mctx, key->keydata.keypair.pub,
			    DNS_KEY_MAYOSIZE);
	}
}

static isc_result_t
dst__mayo_tofile(const dst_key_t *key, const char *directory) {
	dst_private_t priv;
	int i = 0;

	REQUIRE(key != NULL);
	REQUIRE(key->key_alg == DST_ALG_MAYO);

	if (key->keydata.keypair.pub == NULL) {
		return DST_R_NULLKEY;
	}

	INSIST(!key->external);

	priv.elements[i].tag = TAG_MAYO_PUBLICKEY;
	priv.elements[i].length = DNS_KEY_MAYOSIZE;
	priv.elements[i].data = key->keydata.keypair.pub;
	i++;

	if (dst_key_isprivate(key)) {
		priv.elements[i].tag = TAG_MAYO_SECRETKEY;
		priv.elements[i].length = DNS_SEC_MAYOSIZE;
		priv.elements[i].data = key->keydata.keypair.priv;
		i++;
	}

	priv.nelements = i;

	return dst__privstruct_writefile(key, &priv, directory);
}

static isc_result_t
dst__mayo_parse(dst_key_t *key, isc_lex_t *lexer, dst_key_t *pub) {
	isc_result_t result = ISC_R_UNSET;
	dst_private_t priv;
	uint8_t *pk = NULL;
	uint8_t *sk = NULL;

	REQUIRE(key != NULL);
	REQUIRE(key->key_alg == DST_ALG_MAYO);
	REQUIRE(key->keydata.keypair.pub == NULL &&
		key->keydata.keypair.priv == NULL);

	result = dst__privstruct_parse(key, DST_ALG_MAYO, lexer, key->mctx,
				       &priv);
	if (result != ISC_R_SUCCESS) {
		goto done;
	}

	if (key->external) {
		if (priv.nelements != 0 || pub == NULL) {
			result = DST_R_INVALIDPRIVATEKEY;
			goto done;
		}

		key->keydata.keypair.priv = pub->keydata.keypair.priv;
		key->keydata.keypair.pub = pub->keydata.keypair.pub;
		pub->keydata.keypair.priv = NULL;
		pub->keydata.keypair.pub = NULL;

		result = ISC_R_SUCCESS;
		goto done;
	}

	/*
	 * check_mayo() (called from dst__privstruct_parse) has already
	 * verified that both the public and secret key elements are present
	 * with the correct tags, so both branches below are always taken.
	 */
	pk = isc_mem_get(key->mctx, DNS_KEY_MAYOSIZE);
	sk = isc_mem_get(key->mctx, DNS_SEC_MAYOSIZE);

	for (size_t j = 0; j < priv.nelements; j++) {
		switch (priv.elements[j].tag) {
		case TAG_MAYO_PUBLICKEY:
			if (priv.elements[j].length != DNS_KEY_MAYOSIZE) {
				result = DST_R_INVALIDPUBLICKEY;
				goto done;
			}
			memmove(pk, priv.elements[j].data, DNS_KEY_MAYOSIZE);
			break;
		case TAG_MAYO_SECRETKEY:
			if (priv.elements[j].length != DNS_SEC_MAYOSIZE) {
				result = DST_R_INVALIDPRIVATEKEY;
				goto done;
			}
			memmove(sk, priv.elements[j].data, DNS_SEC_MAYOSIZE);
			break;
		default:
			break;
		}
	}

	key->keydata.keypair.priv = sk;
	key->keydata.keypair.pub = pk;
	key->key_size = DNS_KEY_MAYOSIZE * 8;
	pk = NULL;
	sk = NULL;

	result = ISC_R_SUCCESS;

done:
	if (pk != NULL) {
		isc_safe_memwipe(pk, DNS_KEY_MAYOSIZE);
		isc_mem_put(key->mctx, pk, DNS_KEY_MAYOSIZE);
	}
	if (sk != NULL) {
		isc_safe_memwipe(sk, DNS_SEC_MAYOSIZE);
		isc_mem_put(key->mctx, sk, DNS_SEC_MAYOSIZE);
	}

	dst__privstruct_free(&priv, key->mctx);
	isc_safe_memwipe(&priv, sizeof(priv));

	return result;
}

static dst_func_t dst__mayo_functions = {
	dst__mayo_createctx,
	dst__mayo_destroyctx,
	dst__mayo_adddata,
	dst__mayo_sign,
	dst__mayo_verify,
	dst__mayo_compare,
	dst__mayo_generate,
	dst__mayo_isprivate,
	dst__mayo_destroy,
	dst__mayo_todns,
	dst__mayo_fromdns,
	dst__mayo_tofile,
	dst__mayo_parse,
	NULL, /*%< fromlabel */
	NULL, /*%< dump */
	NULL, /*%< restore */
};

void
dst__mayo_init(dst_func_t **funcp, unsigned char algorithm) {
	REQUIRE(funcp != NULL);

	if (algorithm != DST_ALG_MAYO) {
		return;
	}

	if (*funcp == NULL) {
		*funcp = &dst__mayo_functions;
	}
}
