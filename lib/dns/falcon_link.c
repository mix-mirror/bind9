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

#include <isc/attributes.h>
#include <isc/buffer.h>
#include <isc/entropy.h>
#include <isc/hash.h>
#include <isc/mem.h>
#include <isc/result.h>
#include <isc/safe.h>
#include <isc/util.h>

#include <dns/keyvalues.h>

#include "dst_internal.h"
#include "dst_parse.h"
#include "falcon-512/api.h"

static isc_result_t
dst__falcon_createctx(dst_key_t *key ISC_ATTR_UNUSED, dst_context_t *dctx) {
	REQUIRE(dctx != NULL && dctx->key != NULL);
	REQUIRE(dctx->key->key_alg == DST_ALG_FALCON);

	isc_buffer_t *buf = NULL;

	isc_buffer_allocate(dctx->mctx, &buf, 64);
	dctx->ctxdata.generic = buf;

	return ISC_R_SUCCESS;
}

static void
dst__falcon_destroyctx(dst_context_t *dctx) {
	REQUIRE(dctx != NULL && dctx->key != NULL);
	REQUIRE(dctx->key->key_alg == DST_ALG_FALCON);

	isc_buffer_t *buf = dctx->ctxdata.generic;
	if (buf != NULL) {
		isc_buffer_free(&buf);
		dctx->ctxdata.generic = NULL;
	}
}

static isc_result_t
dst__falcon_adddata(dst_context_t *dctx, const isc_region_t *data) {
	REQUIRE(dctx != NULL && dctx->key != NULL);
	REQUIRE(dctx->key->key_alg == DST_ALG_FALCON);

	isc_buffer_t *buf = dctx->ctxdata.generic;
	isc_result_t result = isc_buffer_copyregion(buf, data);
	INSIST(result == ISC_R_SUCCESS);

	return ISC_R_SUCCESS;
}

static isc_result_t
dst__falcon_sign(dst_context_t *dctx, isc_buffer_t *sig) {
	REQUIRE(dctx != NULL && dctx->key != NULL);
	REQUIRE(dctx->key->key_alg == DST_ALG_FALCON);

	isc_result_t result = ISC_R_UNSET;
	dst_key_t *key = dctx->key;
	isc_buffer_t *buf = dctx->ctxdata.generic;
	isc_region_t msgreg;
	isc_region_t sigreg;

	isc_buffer_usedregion(buf, &msgreg);
	isc_buffer_availableregion(sig, &sigreg);

	unsigned long siglen = sigreg.length;
	uint8_t *sigbuf = sigreg.base;

	if (siglen != DNS_SIG_FALCONSIZE) {
		result = DST_R_SIGNFAILURE;
		goto done;
	}

	int status = PQCLEAN_FALCONPADDED512_CLEAN_crypto_sign_signature(
		sigbuf, &siglen, msgreg.base, msgreg.length,
		key->keydata.keypair.priv);
	if (status != 0) {
		result = DST_R_SIGNFAILURE;
		isc_log_write(
			dctx->category, DNS_LOGMODULE_CRYPTO, ISC_LOG_WARNING,
			"PQCLEAN_FALCONPADDED512_CLEAN_crypto_sign_signature "
			"(%s:%d) failed (%s)",
			__FILE__, __LINE__, isc_result_totext(result));
		goto done;
	}
	INSIST(siglen <= DNS_SIG_FALCONSIZE);
	isc_buffer_add(sig, DNS_SIG_FALCONSIZE);
	result = ISC_R_SUCCESS;

done:
	isc_buffer_free(&buf);
	dctx->ctxdata.generic = NULL;

	return result;
}

static isc_result_t
dst__falcon_verify(dst_context_t *dctx, const isc_region_t *sigreg) {
	REQUIRE(dctx != NULL && dctx->key != NULL);
	REQUIRE(dctx->key->key_alg == DST_ALG_FALCON);

	isc_result_t result = ISC_R_UNSET;
	dst_key_t *key = dctx->key;
	isc_buffer_t *buf = dctx->ctxdata.generic;
	isc_region_t msgreg;
	unsigned long siglen = sigreg->length;
	uint8_t *sigbuf = sigreg->base;

	if (siglen != DNS_SIG_FALCONSIZE) {
		result = DST_R_VERIFYFAILURE;
		goto done;
	}

	isc_buffer_usedregion(buf, &msgreg);

	int status = PQCLEAN_FALCONPADDED512_CLEAN_crypto_sign_verify(
		sigbuf, siglen, msgreg.base, msgreg.length,
		key->keydata.keypair.pub);

	if (status != 0) {
		result = DST_R_VERIFYFAILURE;
		isc_log_write(
			dctx->category, DNS_LOGMODULE_CRYPTO, ISC_LOG_WARNING,
			"PQCLEAN_FALCONPADDED512_CLEAN_crypto_sign_verify "
			"(%s:%d) failed (%s)",
			__FILE__, __LINE__, isc_result_totext(result));
		goto done;
	}

	result = ISC_R_SUCCESS;

done:
	isc_buffer_free(&buf);
	dctx->ctxdata.generic = NULL;

	return result;
}

static bool
dst__falcon_compare(const dst_key_t *key1, const dst_key_t *key2) {
	uint8_t *pk1 = key1->keydata.keypair.pub;
	uint8_t *pk2 = key2->keydata.keypair.pub;

	uint8_t *sk1 = key1->keydata.keypair.priv;
	uint8_t *sk2 = key2->keydata.keypair.priv;

	if ((pk1 == pk2) && (sk1 == sk2)) {
		/* The keys are identical or all NULL */
		return true;
	} else if (pk1 == NULL || pk2 == NULL) {
		return false;
	}

	if (memcmp(pk1, pk2, DNS_KEY_FALCONSIZE) != 0) {
		return false;
	}

	if (sk1 == sk2) {
		/* The keys are identical or both NULL */
		return true;
	} else if (sk1 == NULL || sk1 == NULL) {
		return false;
	}

	if (memcmp(sk1, sk2, DNS_SEC_FALCONSIZE) != 0) {
		return false;
	}

	return true;
}

static isc_result_t
dst__falcon_generate(dst_key_t *key, int unused ISC_ATTR_UNUSED,
		     void (*callback ISC_ATTR_UNUSED)(int)) {
	REQUIRE(key != NULL);
	REQUIRE(key->key_alg == DST_ALG_FALCON);
	REQUIRE(key->keydata.keypair.pub == NULL &&
		key->keydata.keypair.priv == NULL);

	isc_result_t result = ISC_R_UNSET;
	uint8_t *pk = isc_mem_get(key->mctx, DNS_KEY_FALCONSIZE);
	uint8_t *sk = isc_mem_get(key->mctx, DNS_SEC_FALCONSIZE);

	int status = PQCLEAN_FALCONPADDED512_CLEAN_crypto_sign_keypair(pk, sk);

	if (status != 0) {
		result = DST_R_CRYPTOFAILURE;
		isc_log_write(DNS_LOGCATEGORY_GENERAL, DNS_LOGMODULE_CRYPTO,
			      ISC_LOG_WARNING,
			      "falcon_keypair (%s:%d) failed (%s)", __FILE__,
			      __LINE__, isc_result_totext(result));
		goto done;
	}

	key->keydata.keypair.pub = pk;
	key->keydata.keypair.priv = sk;
	key->key_size = DNS_KEY_FALCONSIZE * 8;

	result = ISC_R_SUCCESS;

done:
	if (result != ISC_R_SUCCESS) {
		isc_mem_put(key->mctx, pk, DNS_KEY_FALCONSIZE);
	}

	return ISC_R_SUCCESS;
}

static isc_result_t
dst__falcon_todns(const dst_key_t *key, isc_buffer_t *data) {
	REQUIRE(key != NULL);
	REQUIRE(key->key_alg == DST_ALG_FALCON);

	uint8_t *pk = key->keydata.keypair.pub;
	isc_region_t r;

	isc_buffer_availableregion(data, &r);
	if (r.length < DNS_KEY_FALCONSIZE) {
		return ISC_R_NOSPACE;
	}

	isc_buffer_putmem(data, pk, DNS_KEY_FALCONSIZE);

	return ISC_R_SUCCESS;
}

static isc_result_t
dst__falcon_fromdns(dst_key_t *key, isc_buffer_t *data) {
	REQUIRE(key != NULL);
	REQUIRE(key->key_alg == DST_ALG_FALCON);
	REQUIRE(key->keydata.keypair.pub == NULL);

	isc_region_t r;

	isc_buffer_remainingregion(data, &r);
	if (r.length == 0) {
		return ISC_R_SUCCESS;
	}
	INSIST(r.length == DNS_KEY_FALCONSIZE);

	key->keydata.keypair.pub = isc_mem_get(key->mctx, DNS_KEY_FALCONSIZE);
	memmove(key->keydata.keypair.pub, r.base, r.length);
	key->key_size = DNS_KEY_FALCONSIZE * 8;

	return ISC_R_SUCCESS;
}

static bool
dst__falcon_isprivate(const dst_key_t *key) {
	return key->keydata.keypair.priv != NULL;
}

static void
dst__falcon_destroy(dst_key_t *key) {
	REQUIRE(key != NULL);
	REQUIRE(key->key_alg == DST_ALG_FALCON);
	REQUIRE(key->keydata.keypair.pub != NULL);

	if (key->keydata.keypair.priv != NULL) {
		isc_mem_put(key->mctx, key->keydata.keypair.priv,
			    DNS_SEC_FALCONSIZE);
	}

	isc_mem_put(key->mctx, key->keydata.keypair.pub, DNS_KEY_FALCONSIZE);
}

static isc_result_t
dst__falcon_tofile(const dst_key_t *key, const char *directory) {
	REQUIRE(key != NULL);
	REQUIRE(key->key_alg == DST_ALG_FALCON);

	dst_private_t priv;
	int i = 0;

	if (key->keydata.pkeypair.pub == NULL) {
		return DST_R_NULLKEY;
	}

	INSIST(!key->external);

	priv.elements[i].tag = TAG_FALCON_PUBLICKEY;
	priv.elements[i].length = DNS_KEY_FALCONSIZE;
	priv.elements[i].data = key->keydata.keypair.pub;
	i++;

	if (dst_key_isprivate(key)) {
		priv.elements[i].tag = TAG_FALCON_SECRETKEY;
		priv.elements[i].length = DNS_SEC_FALCONSIZE;
		priv.elements[i].data = key->keydata.keypair.priv;
		i++;
	}

	priv.nelements = i;

	return dst__privstruct_writefile(key, &priv, directory);
}

static isc_result_t
dst__falcon_parse(dst_key_t *key, isc_lex_t *lexer, dst_key_t *pub) {
	REQUIRE(key != NULL);
	REQUIRE(key->key_alg == DST_ALG_FALCON);
	REQUIRE(key->keydata.keypair.pub == NULL &&
		key->keydata.keypair.priv == NULL);

	isc_result_t result = ISC_R_UNSET;
	dst_private_t priv;
	uint8_t *pk = isc_mem_get(key->mctx, DNS_KEY_FALCONSIZE);
	uint8_t *sk = isc_mem_get(key->mctx, DNS_SEC_FALCONSIZE);

	result = dst__privstruct_parse(key, DST_ALG_FALCON, lexer, key->mctx,
				       &priv);
	if (result != ISC_R_SUCCESS) {
		goto done;
	}

	if (key->external) {
		if (priv.nelements != 0 || pub == NULL) {
			result = DST_R_INVALIDPRIVATEKEY;
			goto done;
		}

		key->keydata.pkeypair.priv = pub->keydata.pkeypair.priv;
		key->keydata.pkeypair.pub = pub->keydata.pkeypair.pub;
		pub->keydata.pkeypair.priv = NULL;
		pub->keydata.pkeypair.pub = NULL;

		result = ISC_R_SUCCESS;
		goto done;
	}

	for (size_t i = 0; i < priv.nelements; i++) {
		switch (priv.elements[i].tag) {
		case TAG_FALCON_PUBLICKEY:
			if (priv.elements[i].length != DNS_KEY_FALCONSIZE) {
				result = DST_R_INVALIDPUBLICKEY;
				goto done;
			}
			memmove(pk, priv.elements[i].data, DNS_KEY_FALCONSIZE);
			break;
		case TAG_FALCON_SECRETKEY:
			if (priv.elements[i].length != DNS_SEC_FALCONSIZE) {
				result = DST_R_INVALIDPRIVATEKEY;
				goto done;
			}
			memmove(sk, priv.elements[i].data, DNS_SEC_FALCONSIZE);
			break;
		default:
			break;
		}
	}

	if (pk == NULL) {
		result = DST_R_INVALIDPUBLICKEY;
		goto done;
	}

	if (sk == NULL) {
		result = DST_R_INVALIDPRIVATEKEY;
		goto done;
	}

	key->keydata.keypair.priv = sk;
	key->keydata.keypair.pub = pk;
	key->key_size = DNS_KEY_FALCONSIZE * 8;

	result = ISC_R_SUCCESS;

done:
	if (result != ISC_R_SUCCESS) {
		isc_safe_memwipe(pk, DNS_KEY_FALCONSIZE);
		isc_mem_put(key->mctx, pk, DNS_KEY_FALCONSIZE);

		isc_safe_memwipe(sk, DNS_SEC_FALCONSIZE);
		isc_mem_put(key->mctx, sk, DNS_SEC_FALCONSIZE);

		key->keydata.generic = NULL;
	}

	dst__privstruct_free(&priv, key->mctx);
	isc_safe_memwipe(&priv, sizeof(priv));

	return result;
}

static dst_func_t dst__falcon_functions = {
	dst__falcon_createctx,
	dst__falcon_destroyctx,
	dst__falcon_adddata,
	dst__falcon_sign,
	dst__falcon_verify,
	dst__falcon_compare,
	dst__falcon_generate,
	dst__falcon_isprivate,
	dst__falcon_destroy,
	dst__falcon_todns,
	dst__falcon_fromdns,
	dst__falcon_tofile,
	dst__falcon_parse,
	NULL, /*%< fromlabel */
	NULL, /*%< dump */
	NULL, /*%< restore */
};

static isc_result_t
check_algorithm(unsigned char algorithm) {
	switch (algorithm) {
	case DST_ALG_FALCON:
		break;
	default:
		return ISC_R_NOTIMPLEMENTED;
	}

	/*
	 * TODO: check that we can verify FalconHD signature
	 * like we do with the other algorithms.
	 */

	return ISC_R_SUCCESS;
}

void
dst__falcon_init(dst_func_t **funcp, unsigned char algorithm) {
	REQUIRE(funcp != NULL);

	if (*funcp == NULL) {
		if (check_algorithm(algorithm) == ISC_R_SUCCESS) {
			*funcp = &dst__falcon_functions;
		}
	}
}
