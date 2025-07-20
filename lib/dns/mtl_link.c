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

#include <mtllib/mtl_error.h>
#include <mtllib/mtllib.h>
#include <stdbool.h>
#include <zlib.h>

#include <isc/hashmap.h>
#include <isc/mem.h>
#include <isc/result.h>
#include <isc/safe.h>
#include <isc/util.h>

#include <dns/fixedname.h>
#include <dns/keyvalues.h>
#include <dns/mtl.h>

#include "dns/name.h"
#include "dst_internal.h"
#include "dst_parse.h"

typedef struct mtl_handle {
	uint32_t hashval;
	MTL_HANDLE *handle;
} mtl_handle_t;

static bool
handle_match(void *node, const void *key) {
	mtl_handle_t *handle = node;
	uint32_t hashval = (uintptr_t)key;

	return handle->hashval == hashval;
}

static isc_result_t
dst__mtl_createctx(dst_key_t *key ISC_ATTR_UNUSED, dst_context_t *dctx) {
	REQUIRE(dctx != NULL && dctx->key != NULL);
	REQUIRE(dctx->key->key_alg == DST_ALG_MTL);

	isc_buffer_t *buf = NULL;

	isc_buffer_allocate(dctx->mctx, &buf, 64);
	dctx->ctxdata.generic = buf;

	return ISC_R_SUCCESS;
}

static void
dst__mtl_destroyctx(dst_context_t *dctx) {
	REQUIRE(dctx != NULL && dctx->key != NULL);
	REQUIRE(dctx->key->key_alg == DST_ALG_MTL);

	isc_buffer_t *buf = dctx->ctxdata.generic;
	if (buf != NULL) {
		isc_buffer_free(&buf);
		dctx->ctxdata.generic = NULL;
	}
}

static isc_result_t
dst__mtl_adddata(dst_context_t *dctx, const isc_region_t *data) {
	REQUIRE(dctx != NULL && dctx->key != NULL);
	REQUIRE(dctx->key->key_alg == DST_ALG_MTL);

	isc_buffer_t *buf = dctx->ctxdata.generic;
	isc_result_t result = isc_buffer_copyregion(buf, data);
	INSIST(result == ISC_R_SUCCESS);

	return ISC_R_SUCCESS;
}

static isc_result_t
dst__mtl_sign(dst_context_t *dctx, isc_buffer_t *sig, bool final, bool full) {
	REQUIRE(dctx != NULL && dctx->key != NULL);
	REQUIRE(dctx->key->key_alg == DST_ALG_MTL);

	isc_result_t result = ISC_R_UNSET;
	dst_key_t *key = dctx->key;
	isc_buffer_t *buf = dctx->ctxdata.generic;
	isc_region_t tbsreg;
	isc_region_t sigreg;

	MTLLIB_STATUS status;
	MTLLIB_CTX *mtl_ctx = key->keydata.mtl.ctx;

	isc_buffer_availableregion(sig, &sigreg);

	isc_buffer_usedregion(buf, &tbsreg);

	if (key->keydata.mtl.hashmap == NULL) {
		isc_hashmap_create(key->mctx, 12, &key->keydata.mtl.hashmap);
	}

	isc_hashmap_t *hashmap = key->keydata.mtl.hashmap;
	INSIST(hashmap != NULL);

	uintptr_t hashval = isc_hash32(tbsreg.base, tbsreg.length, false);

	if (!final) {
		MTL_HANDLE *handle = NULL;
		status = mtllib_sign_append(mtl_ctx, tbsreg.base, tbsreg.length,
					    &handle);
		if (status != MTLLIB_OK) {
			result = DST_R_SIGNFAILURE;
			goto done;
		}

		mtl_handle_t *h = isc_mem_get(key->mctx, sizeof(*h));
		*h = (mtl_handle_t){
			.hashval = hashval,
			.handle = handle,
		};
		result = isc_hashmap_add(hashmap, hashval, handle_match,
					 (void *)hashval, h, NULL);
		INSIST(result == ISC_R_SUCCESS);
	} else {
		uint8_t *sigbuf = NULL;
		size_t siglen = 0;
		mtl_handle_t *h = NULL;

		result = isc_hashmap_find(hashmap, hashval, handle_match,
					  (void *)hashval, (void **)&h);
		INSIST(result == ISC_R_SUCCESS);

		if (full) {
			status = mtllib_sign_get_full_sig(mtl_ctx, h->handle,
							  &sigbuf, &siglen);
		} else {
			status = mtllib_sign_get_condensed_sig(
				mtl_ctx, h->handle, &sigbuf, &siglen);
		}
		if (status != MTLLIB_OK) {
			result = DST_R_SIGNFAILURE;
			goto done;
		}

		if (sigreg.length < siglen) {
			free(sigbuf);
			result = ISC_R_NOSPACE;
			goto done;
		}

		result = isc_hashmap_delete(hashmap, hashval, handle_match,
					    (void *)hashval);
		INSIST(result == ISC_R_SUCCESS);

		free(h->handle);
		isc_mem_put(key->mctx, h, sizeof(*h));

		isc_buffer_putmem(sig, sigbuf, siglen);

		free(sigbuf);
	}

	return ISC_R_SUCCESS;

done:
	isc_buffer_free(&buf);
	dctx->ctxdata.generic = NULL;

	return result;
}

static isc_result_t
dst__mtl_verify(dst_context_t *dctx, const isc_region_t *sigreg,
		const isc_region_t *ladder) {
	REQUIRE(dctx != NULL && dctx->key != NULL);
	REQUIRE(dctx->key->key_alg == DST_ALG_MTL);

	isc_result_t result = ISC_R_UNSET;
	dst_key_t *key = dctx->key;
	isc_buffer_t *buf = dctx->ctxdata.generic;
	isc_region_t tbsreg;
	MTLLIB_CTX *mtl_ctx = key->keydata.mtl.ctx;

	isc_buffer_usedregion(buf, &tbsreg);

	uint8_t *ladbuf = (ladder != NULL && ladder->length != 0) ? ladder->base
								  : NULL;
	size_t ladlen = (ladder != NULL) ? ladder->length : 0;

	int status = mtllib_verify(mtl_ctx, tbsreg.base, tbsreg.length,
				   sigreg->base, sigreg->length, ladbuf, ladlen,
				   NULL);
	if (status != MTL_OK) {
		result = DST_R_VERIFYFAILURE;
		isc_log_write(dctx->category, DNS_LOGMODULE_CRYPTO,
			      ISC_LOG_WARNING, "mtl_verify (%s:%d) failed (%s)",
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
dst__mtl_compare(const dst_key_t *key1, const dst_key_t *key2) {
	MTLLIB_CTX *mtl_ctx1 = key1->keydata.mtl.ctx;
	MTLLIB_CTX *mtl_ctx2 = key2->keydata.mtl.ctx;

	if (mtl_ctx1 == mtl_ctx2) {
		/* The keys are identical or all NULL */
		return true;
	}

	uint8_t *pk1 = NULL;
	size_t pk1_len = mtllib_key_get_pubkey_bytes(mtl_ctx1, &pk1);
	uint8_t *pk2 = NULL;
	size_t pk2_len = mtllib_key_get_pubkey_bytes(mtl_ctx1, &pk2);

	if (pk1_len != pk2_len || pk1 == NULL || pk2 == NULL) {
		return false;
	}

	if (memcmp(pk1, pk2, pk1_len) != 0) {
		return false;
	}

	uint8_t *sk1 = NULL;
	size_t sk1_len = mtllib_key_to_buffer(mtl_ctx1, &sk1);
	uint8_t *sk2 = NULL;
	size_t sk2_len = mtllib_key_to_buffer(mtl_ctx1, &sk2);

	if (sk1_len != sk2_len || sk1 == NULL || sk2 == NULL) {
		goto fail;
	}

	if (memcmp(sk1, sk2, sk1_len) != 0) {
		goto fail;
	}

	return true;
fail:
	if (sk1 != NULL) {
		free(sk1);
	}
	if (sk2 != NULL) {
		free(sk2);
	}
	return false;
}

static isc_result_t
dst__mtl_generate(dst_key_t *key, int unused ISC_ATTR_UNUSED,
		  void (*callback ISC_ATTR_UNUSED)(int)) {
	REQUIRE(key != NULL);
	REQUIRE(key->key_alg == DST_ALG_MTL);
	REQUIRE(key->keydata.mtl.ctx == NULL);

	isc_result_t result = ISC_R_UNSET;
	MTLLIB_CTX *mtl_ctx = NULL;
	char *algo_name = (char *)"SLH-DSA-MTL-SHAKE-128S";

	MTLLIB_STATUS status = mtllib_key_new(algo_name, &mtl_ctx, NULL);
	if (status != MTLLIB_OK) {
		isc_log_write(DNS_LOGCATEGORY_GENERAL, DNS_LOGMODULE_CRYPTO,
			      ISC_LOG_WARNING,
			      "mtllib_key_new (%s:%d) failed (%s)", __FILE__,
			      __LINE__, isc_result_totext(result));
		return DST_R_CRYPTOFAILURE;
	}

	key->keydata.mtl.ctx = mtl_ctx;
	key->key_size = 32;

	return ISC_R_SUCCESS;
}

static isc_result_t
dst__mtl_todns(const dst_key_t *key, isc_buffer_t *data) {
	REQUIRE(key != NULL);
	REQUIRE(key->key_alg == DST_ALG_MTL);

	MTLLIB_CTX *mtl_ctx = key->keydata.mtl.ctx;
	uint8_t *pk = NULL;
	size_t pk_len = mtllib_key_get_pubkey_bytes(mtl_ctx, &pk);
	isc_region_t r;

	INSIST(pk_len == 32);

	isc_buffer_availableregion(data, &r);

	if (r.length < pk_len + mtl_ctx->mtl->sid.length) {
		return ISC_R_NOSPACE;
	}

	isc_buffer_putmem(data, pk, pk_len);
	isc_buffer_putmem(data, mtl_ctx->mtl->sid.id, mtl_ctx->mtl->sid.length);

	return ISC_R_SUCCESS;
}

static isc_result_t
dst__mtl_fromdns(dst_key_t *key, isc_buffer_t *data) {
	REQUIRE(key != NULL);
	REQUIRE(key->key_alg == DST_ALG_MTL);
	REQUIRE(key->keydata.mtl.ctx == NULL);

	char *algo_name = (char *)"SLH-DSA-MTL-SHAKE-128S";
	isc_region_t r;
	MTLLIB_CTX *mtl_ctx = NULL;

	isc_buffer_remainingregion(data, &r);
	if (r.length == 0) {
		return ISC_R_SUCCESS;
	}

	INSIST(r.length == 32 + 8);

	MTLLIB_STATUS status = mtllib_key_pubkey_from_params(
		algo_name, &mtl_ctx, NULL, r.base, 32, r.base + 32, 8);
	if (status != MTLLIB_OK) {
		return DST_R_CRYPTOFAILURE;
	}

	key->keydata.mtl.ctx = mtl_ctx;
	key->key_size = 32;

	return ISC_R_SUCCESS;
}

static bool
dst__mtl_isprivate(const dst_key_t *key) {
	/* FIXME: There's no way how to check if the key is private or public */
	return key->keydata.mtl.ctx != NULL;
}

static void
dst__mtl_destroy(dst_key_t *key) {
	REQUIRE(key != NULL);
	REQUIRE(key->key_alg == DST_ALG_MTL);
	REQUIRE(key->keydata.mtl.ctx != NULL);

	mtllib_key_free(key->keydata.mtl.ctx);
	key->keydata.mtl.ctx = NULL;

	if (key->keydata.mtl.hashmap != NULL) {
		RUNTIME_CHECK(isc_hashmap_count(key->keydata.mtl.hashmap) == 0);
		isc_hashmap_destroy(&key->keydata.mtl.hashmap);
	}
}

static isc_result_t
dst__mtl_tofile(const dst_key_t *key, const char *directory) {
	REQUIRE(key != NULL);
	REQUIRE(key->key_alg == DST_ALG_MTL);

	isc_result_t result;
	dst_private_t priv;
	int i = 0;
	uint8_t *sk = NULL;

	if (key->keydata.mtl.ctx == NULL) {
		return DST_R_NULLKEY;
	}

	INSIST(!key->external);

	MTLLIB_CTX *mtl_ctx = key->keydata.mtl.ctx;

	if (dst_key_isprivate(key)) {
		size_t sk_len = mtllib_key_to_buffer(mtl_ctx, &sk);

		priv.elements[i].tag = TAG_MTL_PRIVATEKEY;
		priv.elements[i].length = sk_len;
		priv.elements[i].data = sk;

		i++;
	}

	priv.nelements = i;

	result = dst__privstruct_writefile(key, &priv, directory);

	if (sk != NULL) {
		free(sk);
	}

	return result;
}

static isc_result_t
dst__mtl_parse(dst_key_t *key, isc_lex_t *lexer,
	       dst_key_t *pub ISC_ATTR_UNUSED) {
	REQUIRE(key != NULL);
	REQUIRE(key->key_alg == DST_ALG_MTL);
	REQUIRE(key->keydata.mtl.ctx == NULL);

	isc_result_t result = ISC_R_UNSET;
	dst_private_t priv;
	MTLLIB_CTX *mtl_ctx = NULL;

	result = dst__privstruct_parse(key, DST_ALG_MTL, lexer, key->mctx,
				       &priv);
	if (result != ISC_R_SUCCESS) {
		goto done;
	}

	INSIST(!key->external);
	INSIST(priv.nelements <= 1);

	size_t i = 0;
	MTLLIB_STATUS status;
	switch (priv.elements[i].tag) {
	case TAG_MTL_PRIVATEKEY:
		status = mtllib_key_from_buffer(priv.elements[i].data,
						priv.elements[i].length,
						&mtl_ctx);
		if (status != MTLLIB_OK) {
			result = DST_R_INVALIDPRIVATEKEY;
			goto done;
		}
		break;
	default:
		break;
	}

	if (mtl_ctx == NULL) {
		result = DST_R_INVALIDPRIVATEKEY;
		goto done;
	}

	key->keydata.mtl.ctx = mtl_ctx;
	key->key_size = 32; /* FIXME: Use per-algorithm constant */

	result = ISC_R_SUCCESS;

done:
	dst__privstruct_free(&priv, key->mctx);
	isc_safe_memwipe(&priv, sizeof(priv));

	return result;
}

static dst_func_t dst__mtl_functions = {
	dst__mtl_createctx,
	dst__mtl_destroyctx,
	dst__mtl_adddata,
	dst__mtl_sign,
	dst__mtl_verify,
	dst__mtl_compare,
	dst__mtl_generate,
	dst__mtl_isprivate,
	dst__mtl_destroy,
	dst__mtl_todns,
	dst__mtl_fromdns,
	dst__mtl_tofile,
	dst__mtl_parse,
	NULL, /*%< fromlabel */
	NULL, /*%< dump */
	NULL, /*%< restore */
};

static isc_result_t
check_algorithm(unsigned char algorithm) {
	switch (algorithm) {
	case DST_ALG_MTL:
		break;
	default:
		return ISC_R_NOTIMPLEMENTED;
	}

	/*
	 * TODO: check that we can verify signature
	 * like we do with the other algorithms.
	 */

	return ISC_R_SUCCESS;
}

void
dst__mtl_init(dst_func_t **funcp, unsigned char algorithm) {
	REQUIRE(funcp != NULL);

	if (*funcp == NULL) {
		if (check_algorithm(algorithm) == ISC_R_SUCCESS) {
			*funcp = &dst__mtl_functions;
		}
	}
}
