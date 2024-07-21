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

#include <hawk/hawk.h>

#include <isc/entropy.h>
#include <isc/mem.h>
#include <isc/result.h>
#include <isc/safe.h>
#include <isc/util.h>

#include <dns/keyvalues.h>

#include "dst_internal.h"
#include "dst_parse.h"
#include "hawk/sha3.h"
#include "isc/attributes.h"
#include "isc/buffer.h"
#include "isc/hash.h"
#include "isc/result.h"

static void
dst__hawk_rng(void *ctx ISC_ATTR_UNUSED, void *dst, size_t len) {
	isc_entropy_get(dst, len);
}

static isc_result_t
dst__hawk_createctx(dst_key_t *key ISC_ATTR_UNUSED, dst_context_t *dctx) {
	REQUIRE(dctx != NULL && dctx->key != NULL);
	REQUIRE(dctx->key->key_alg == DST_ALG_HAWK);

	hawk_sign_start(&dctx->ctxdata.shake_context);

	return ISC_R_SUCCESS;
}

static void
dst__hawk_destroyctx(dst_context_t *dctx) {
	REQUIRE(dctx != NULL && dctx->key != NULL);
	REQUIRE(dctx->key->key_alg == DST_ALG_HAWK);
}

static isc_result_t
dst__hawk_adddata(dst_context_t *dctx, const isc_region_t *data) {
	REQUIRE(dctx != NULL && dctx->key != NULL);
	REQUIRE(dctx->key->key_alg == DST_ALG_HAWK);

	shake_inject(&dctx->ctxdata.shake_context, data->base, data->length);

	return ISC_R_SUCCESS;
}

static isc_result_t
dst__hawk_sign(dst_context_t *dctx, isc_buffer_t *sig) {
	REQUIRE(dctx != NULL && dctx->key != NULL);
	REQUIRE(dctx->key->key_alg == DST_ALG_HAWK);

	isc_result_t result = ISC_R_SUCCESS;
	dst_key_t *key = dctx->key;
	isc_region_t sigreg;
	uint8_t tmp[HAWK_TMPSIZE_SIGN(8)];

	isc_buffer_availableregion(sig, &sigreg);
	if (sigreg.length < DNS_SIG_HAWKSIZE) {
		result = ISC_R_NOSPACE;
		goto done;
	}

	int status = hawk_sign_finish(
		8, dst__hawk_rng, NULL, sig->base, &dctx->ctxdata.shake_context,
		key->keydata.keypair.priv, tmp, sizeof(tmp));
	if (status == 0) {
		result = DST_R_SIGNFAILURE;
		isc_log_write(dctx->category, DNS_LOGMODULE_CRYPTO,
			      ISC_LOG_WARNING, "hawk_sign (%s:%d) failed (%s)",
			      __FILE__, __LINE__, isc_result_totext(result));
		goto done;
	}
	isc_buffer_add(sig, DNS_SIG_HAWKSIZE);

done:
	dctx->ctxdata.generic = NULL;

	return result;
}

static isc_result_t
dst__hawk_verify(dst_context_t *dctx, const isc_region_t *sig) {
	REQUIRE(dctx != NULL && dctx->key != NULL);
	REQUIRE(dctx->key->key_alg == DST_ALG_HAWK);

	isc_result_t result = ISC_R_SUCCESS;
	dst_key_t *key = dctx->key;
	uint8_t tmp[HAWK_TMPSIZE_VERIFY_FAST(8)];

	if (sig->length != DNS_SIG_HAWKSIZE) {
		result = DST_R_VERIFYFAILURE;
		goto done;
	}

	int status = hawk_verify_finish(
		8, sig->base, sig->length, &dctx->ctxdata.shake_context,
		key->keydata.keypair.pub, DNS_KEY_HAWKSIZE, tmp, sizeof(tmp));
	if (status == 0) {
		result = DST_R_VERIFYFAILURE;
		/* FIXME: Is it really a warning if the verification fails */
		isc_log_write(dctx->category, DNS_LOGMODULE_CRYPTO,
			      ISC_LOG_WARNING,
			      "hawk_verify (%s:%d) failed (%s)", __FILE__,
			      __LINE__, isc_result_totext(result));
		goto done;
	}
done:
	return result;
}

static bool
dst__hawk_compare(const dst_key_t *key1, const dst_key_t *key2) {
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

	if (memcmp(pk1, pk2, DNS_KEY_HAWKSIZE) != 0) {
		return false;
	}

	if (sk1 == sk2) {
		/* The keys are identical or both NULL */
		return true;
	} else if (sk1 == NULL || sk1 == NULL) {
		return false;
	}

	if (memcmp(sk1, sk2, DNS_SEC_HAWKSIZE) != 0) {
		return false;
	}

	return true;
}

static isc_result_t
dst__hawk_generate(dst_key_t *key, int unused ISC_ATTR_UNUSED,
		   void (*callback ISC_ATTR_UNUSED)(int)) {
	REQUIRE(key != NULL);
	REQUIRE(key->key_alg == DST_ALG_HAWK);
	REQUIRE(key->keydata.keypair.pub == NULL &&
		key->keydata.keypair.priv == NULL);

	isc_result_t result = ISC_R_UNSET;
	uint8_t *pk = isc_mem_get(key->mctx, DNS_KEY_HAWKSIZE);
	uint8_t *sk = isc_mem_get(key->mctx, DNS_SEC_HAWKSIZE);
	uint8_t tmp[HAWK_TMPSIZE_KEYGEN(8)];

	int status = hawk_keygen(8, sk, pk, dst__hawk_rng, NULL, tmp,
				 sizeof(tmp));
	if (status == 0) {
		result = DST_R_CRYPTOFAILURE;
		isc_log_write(DNS_LOGCATEGORY_GENERAL, DNS_LOGMODULE_CRYPTO,
			      ISC_LOG_WARNING,
			      "hawk_keypair (%s:%d) failed (%s)", __FILE__,
			      __LINE__, isc_result_totext(result));
		goto done;
	}

	key->keydata.keypair.pub = pk;
	key->keydata.keypair.priv = sk;
	key->key_size = DNS_KEY_HAWKSIZE * 8;

	result = ISC_R_SUCCESS;

done:
	if (result != ISC_R_SUCCESS) {
		isc_mem_put(key->mctx, pk, DNS_KEY_HAWKSIZE);
	}

	return ISC_R_SUCCESS;
}

static isc_result_t
dst__hawk_todns(const dst_key_t *key, isc_buffer_t *data) {
	REQUIRE(key != NULL);
	REQUIRE(key->key_alg == DST_ALG_HAWK);

	uint8_t *pk = key->keydata.keypair.pub;
	isc_region_t r;

	isc_buffer_availableregion(data, &r);
	if (r.length < DNS_KEY_HAWKSIZE) {
		return ISC_R_NOSPACE;
	}

	isc_buffer_putmem(data, pk, DNS_KEY_HAWKSIZE);

	return ISC_R_SUCCESS;
}

static isc_result_t
dst__hawk_fromdns(dst_key_t *key, isc_buffer_t *data) {
	REQUIRE(key != NULL);
	REQUIRE(key->key_alg == DST_ALG_HAWK);
	REQUIRE(key->keydata.keypair.pub == NULL);

	isc_region_t r;

	isc_buffer_remainingregion(data, &r);
	if (r.length == 0) {
		return ISC_R_SUCCESS;
	}
	INSIST(r.length == DNS_KEY_HAWKSIZE);

	key->keydata.keypair.pub = isc_mem_get(key->mctx, DNS_KEY_HAWKSIZE);
	memmove(key->keydata.keypair.pub, r.base, r.length);
	key->key_size = DNS_KEY_HAWKSIZE * 8;

	return ISC_R_SUCCESS;
}

static bool
dst__hawk_isprivate(const dst_key_t *key) {
	return key->keydata.keypair.priv != NULL;
}

static void
dst__hawk_destroy(dst_key_t *key) {
	REQUIRE(key != NULL);
	REQUIRE(key->key_alg == DST_ALG_HAWK);
	REQUIRE(key->keydata.keypair.pub != NULL);

	if (key->keydata.keypair.priv != NULL) {
		isc_mem_put(key->mctx, key->keydata.keypair.priv,
			    DNS_SEC_HAWKSIZE);
	}

	isc_mem_put(key->mctx, key->keydata.keypair.pub, DNS_KEY_HAWKSIZE);
}

static isc_result_t
dst__hawk_tofile(const dst_key_t *key, const char *directory) {
	REQUIRE(key != NULL);
	REQUIRE(key->key_alg == DST_ALG_HAWK);

	dst_private_t priv;
	int i = 0;

	if (key->keydata.pkeypair.pub == NULL) {
		return DST_R_NULLKEY;
	}

	INSIST(!key->external);

	priv.elements[i].tag = TAG_HAWK_PUBLICKEY;
	priv.elements[i].length = DNS_KEY_HAWKSIZE;
	priv.elements[i].data = key->keydata.keypair.pub;
	i++;

	if (dst_key_isprivate(key)) {
		priv.elements[i].tag = TAG_HAWK_SECRETKEY;
		priv.elements[i].length = DNS_SEC_HAWKSIZE;
		priv.elements[i].data = key->keydata.keypair.priv;
		i++;
	}

	priv.nelements = i;

	return dst__privstruct_writefile(key, &priv, directory);
}

static isc_result_t
dst__hawk_parse(dst_key_t *key, isc_lex_t *lexer, dst_key_t *pub) {
	REQUIRE(key != NULL);
	REQUIRE(key->key_alg == DST_ALG_HAWK);
	REQUIRE(key->keydata.keypair.pub == NULL &&
		key->keydata.keypair.priv == NULL);

	isc_result_t result = ISC_R_UNSET;
	dst_private_t priv;
	uint8_t *pk = isc_mem_get(key->mctx, DNS_KEY_HAWKSIZE);
	uint8_t *sk = isc_mem_get(key->mctx, DNS_SEC_HAWKSIZE);

	result = dst__privstruct_parse(key, DST_ALG_HAWK, lexer, key->mctx,
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
		case TAG_HAWK_PUBLICKEY:
			if (priv.elements[i].length != DNS_KEY_HAWKSIZE) {
				result = DST_R_INVALIDPUBLICKEY;
				goto done;
			}
			memmove(pk, priv.elements[i].data, DNS_KEY_HAWKSIZE);
			break;
		case TAG_HAWK_SECRETKEY:
			if (priv.elements[i].length != DNS_SEC_HAWKSIZE) {
				result = DST_R_INVALIDPRIVATEKEY;
				goto done;
			}
			memmove(sk, priv.elements[i].data, DNS_SEC_HAWKSIZE);
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
	key->key_size = DNS_KEY_HAWKSIZE * 8;

	result = ISC_R_SUCCESS;

done:
	if (result != ISC_R_SUCCESS) {
		isc_safe_memwipe(pk, DNS_KEY_HAWKSIZE);
		isc_mem_put(key->mctx, pk, DNS_KEY_HAWKSIZE);

		isc_safe_memwipe(sk, DNS_SEC_HAWKSIZE);
		isc_mem_put(key->mctx, sk, DNS_SEC_HAWKSIZE);

		key->keydata.generic = NULL;
	}

	dst__privstruct_free(&priv, key->mctx);
	isc_safe_memwipe(&priv, sizeof(priv));

	return result;
}

static dst_func_t dst__hawk_functions = {
	dst__hawk_createctx,
	dst__hawk_destroyctx,
	dst__hawk_adddata,
	dst__hawk_sign,
	dst__hawk_verify,
	dst__hawk_compare,
	dst__hawk_generate,
	dst__hawk_isprivate,
	dst__hawk_destroy,
	dst__hawk_todns,
	dst__hawk_fromdns,
	dst__hawk_tofile,
	dst__hawk_parse,
	NULL, /*%< fromlabel */
	NULL, /*%< dump */
	NULL, /*%< restore */
};

static isc_result_t
check_algorithm(unsigned char algorithm) {
	switch (algorithm) {
	case DST_ALG_HAWK:
		break;
	default:
		return ISC_R_NOTIMPLEMENTED;
	}

	/*
	 * TODO: check that we can verify HawkHD signature
	 * like we do with the other algorithms.
	 */

	return ISC_R_SUCCESS;
}

void
dst__hawk_init(dst_func_t **funcp, unsigned char algorithm) {
	REQUIRE(funcp != NULL);

	if (*funcp == NULL) {
		if (check_algorithm(algorithm) == ISC_R_SUCCESS) {
			*funcp = &dst__hawk_functions;
		}
	}
}
