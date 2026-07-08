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

#include <mtllib/mtllib.h>

#include <stdbool.h>
#include <string.h>

#include <isc/hashmap.h>
#include <isc/mem.h>
#include <isc/result.h>
#include <isc/safe.h>
#include <isc/util.h>

#include <dns/keyvalues.h>

#include "dst_internal.h"
#include "dst_parse.h"

#define MTL_DNSKEY_SIZE	  DNS_KEY_SLHDSAMTL128SSIZE
#define MTL_TYPE_CONDENSED 0
#define MTL_TYPE_FULL	  1

typedef struct mtl_handle {
	uint32_t hashval;
	MTL_HANDLE *handle;
} mtl_handle_t;

static const char *
mtl_algorithm_name(unsigned int algorithm) {
	switch (algorithm) {
	case DST_ALG_SLHDSAMTLSHA2128S:
		return "SLH-DSA-SHA2-128s-MTL-SHA2-128";
	case DST_ALG_SLHDSAMTLSHAKE128S:
		return "SLH-DSA-SHAKE-128s-MTL-SHAKE-128";
	default:
		UNREACHABLE();
	}
}

static bool
mtl_algorithm_supported(unsigned int algorithm) {
	switch (algorithm) {
	case DST_ALG_SLHDSAMTLSHA2128S:
	case DST_ALG_SLHDSAMTLSHAKE128S:
		return true;
	default:
		return false;
	}
}

static bool
handle_match(void *node, const void *key) {
	mtl_handle_t *handle = node;
	uint32_t hashval = (uintptr_t)key;

	return handle->hashval == hashval;
}

static isc_result_t
mtl_buffer_from_region(const isc_region_t *region, MTLLIB_BUFFER **bufferp) {
	MTLLIB_STATUS status;

	REQUIRE(region != NULL);
	REQUIRE(bufferp != NULL && *bufferp == NULL);

	status = mtllib_buffer_initialize(bufferp, region->length, region->base);
	return status == MTLLIB_OK ? ISC_R_SUCCESS : ISC_R_NOMEMORY;
}

static isc_result_t
mtl_buffer_allocate(size_t length, MTLLIB_BUFFER **bufferp) {
	MTLLIB_STATUS status;

	REQUIRE(bufferp != NULL && *bufferp == NULL);

	status = mtllib_buffer_initialize(bufferp, length, NULL);
	return status == MTLLIB_OK ? ISC_R_SUCCESS : ISC_R_NOMEMORY;
}

static void
mtl_buffer_free(MTLLIB_BUFFER **bufferp) {
	if (bufferp != NULL && *bufferp != NULL) {
		mtllib_buffer_free(*bufferp);
		*bufferp = NULL;
	}
}

static isc_result_t
mtl_status_to_result(MTLLIB_STATUS status) {
	switch (status) {
	case MTLLIB_OK:
	case MTLLIB_OK_VALIDATED_LADDER:
		return ISC_R_SUCCESS;
	case MTLLIB_NO_LADDER:
	case MTLLIB_BOGUS_CRYPTO:
	case MTLLIB_INDETERMINATE:
		return DST_R_VERIFYFAILURE;
	case MTLLIB_BAD_VALUE:
	case MTLLIB_BAD_ALGORITHM:
		return DST_R_INVALIDPUBLICKEY;
	case MTLLIB_BUFFER_ISSUE:
	case MTLLIB_MEMORY_ERROR:
		return ISC_R_NOMEMORY;
	default:
		return DST_R_CRYPTOFAILURE;
	}
}

static isc_result_t
mtl_context_from_public(unsigned int algorithm, const isc_region_t *pubkey,
			const uint8_t *sid, MTLLIB_CTX **ctxp) {
	MTLLIB_BUFFER *pubkey_buffer = NULL;
	MTLLIB_STATUS status;
	isc_result_t result;

	REQUIRE(pubkey != NULL);
	REQUIRE(sid != NULL);
	REQUIRE(ctxp != NULL && *ctxp == NULL);

	result = mtl_buffer_from_region(pubkey, &pubkey_buffer);
	if (result != ISC_R_SUCCESS) {
		return result;
	}

	status = mtllib_pubkey_from_buffer((char *)mtl_algorithm_name(algorithm),
					   ctxp, pubkey_buffer, (uint8_t *)sid);
	mtl_buffer_free(&pubkey_buffer);

	return status == MTLLIB_OK ? ISC_R_SUCCESS : mtl_status_to_result(status);
}

static void
mtl_ladder_clear(dst_key_t *key) {
	REQUIRE(key != NULL);

	if (key->keydata.mtl.ladder != NULL) {
		isc_mem_put(key->mctx, key->keydata.mtl.ladder,
			    key->keydata.mtl.ladder_len);
		key->keydata.mtl.ladder = NULL;
		key->keydata.mtl.ladder_len = 0;
	}
}

static isc_result_t
mtl_ladder_store(dst_key_t *key, const uint8_t *base, size_t length) {
	REQUIRE(key != NULL);
	REQUIRE(base != NULL || length == 0);

	mtl_ladder_clear(key);

	if (length == 0) {
		return ISC_R_SUCCESS;
	}

	key->keydata.mtl.ladder = isc_mem_get(key->mctx, length);
	memmove(key->keydata.mtl.ladder, base, length);
	key->keydata.mtl.ladder_len = length;

	return ISC_R_SUCCESS;
}

static isc_result_t
mtl_ladder_cache_current(dst_key_t *key) {
	MTLLIB_BUFFER *ladder = NULL;
	MTLLIB_STATUS status;
	isc_result_t result;
	size_t ladder_len;

	REQUIRE(key != NULL);
	REQUIRE(key->keydata.mtl.ctx != NULL);

	ladder_len = mtllib_sign_get_signed_ladder_length(key->keydata.mtl.ctx);
	if (ladder_len == 0) {
		return DST_R_SIGNFAILURE;
	}

	result = mtl_buffer_allocate(ladder_len, &ladder);
	if (result != ISC_R_SUCCESS) {
		return result;
	}

	status = mtllib_sign_get_signed_ladder(key->keydata.mtl.ctx, ladder);
	if (status == MTLLIB_OK) {
		result = mtl_ladder_store(key, mtllib_buffer_data_ptr(ladder),
					  mtllib_buffer_in_use(ladder));
	} else {
		result = DST_R_SIGNFAILURE;
	}

	mtl_buffer_free(&ladder);
	return result;
}

static isc_result_t
mtl_ladder_cache_from_fullsig(dst_key_t *key, const isc_region_t *rawsig,
			      size_t condensed_len) {
	REQUIRE(key != NULL);
	REQUIRE(rawsig != NULL);

	if (condensed_len > rawsig->length) {
		return DST_R_VERIFYFAILURE;
	}

	return mtl_ladder_store(key, rawsig->base + condensed_len,
				rawsig->length - condensed_len);
}

static isc_result_t
dst__mtl_createctx(dst_key_t *key ISC_ATTR_UNUSED, dst_context_t *dctx) {
	REQUIRE(dctx != NULL && dctx->key != NULL);
	REQUIRE(mtl_algorithm_supported(dctx->key->key_alg));

	isc_buffer_t *buf = NULL;

	isc_buffer_allocate(dctx->mctx, &buf, 512);
	dctx->ctxdata.generic = buf;

	return ISC_R_SUCCESS;
}

static void
dst__mtl_destroyctx(dst_context_t *dctx) {
	REQUIRE(dctx != NULL && dctx->key != NULL);
	REQUIRE(mtl_algorithm_supported(dctx->key->key_alg));

	isc_buffer_t *buf = dctx->ctxdata.generic;
	if (buf != NULL) {
		isc_buffer_free(&buf);
		dctx->ctxdata.generic = NULL;
	}
}

static isc_result_t
dst__mtl_adddata(dst_context_t *dctx, const isc_region_t *data) {
	REQUIRE(dctx != NULL && dctx->key != NULL);
	REQUIRE(mtl_algorithm_supported(dctx->key->key_alg));

	isc_buffer_t *buf = dctx->ctxdata.generic;
	return isc_buffer_copyregion(buf, data);
}

static isc_result_t
dst__mtl_sign(dst_context_t *dctx, isc_buffer_t *sig, bool final, bool full) {
	REQUIRE(dctx != NULL && dctx->key != NULL);
	REQUIRE(mtl_algorithm_supported(dctx->key->key_alg));

	isc_result_t result = ISC_R_UNSET;
	dst_key_t *key = dctx->key;
	isc_buffer_t *buf = dctx->ctxdata.generic;
	isc_region_t tbsreg;
	MTLLIB_BUFFER *msg = NULL;
	MTLLIB_BUFFER *mtlsig = NULL;
	MTLLIB_STATUS status;
	MTLLIB_CTX *mtl_ctx = key->keydata.mtl.ctx;
	mtl_handle_t *h = NULL;
	bool local_handle = false;

	isc_buffer_usedregion(buf, &tbsreg);

	result = mtl_buffer_from_region(&tbsreg, &msg);
	if (result != ISC_R_SUCCESS) {
		goto done;
	}

	if (key->keydata.mtl.hashmap == NULL) {
		isc_hashmap_create(key->mctx, 12, &key->keydata.mtl.hashmap);
	}

	isc_hashmap_t *hashmap = key->keydata.mtl.hashmap;
	INSIST(hashmap != NULL);

	uintptr_t hashval = isc_hash32(tbsreg.base, tbsreg.length, false);

	if (!final) {
		MTL_HANDLE *handle = NULL;

		status = mtllib_sign_append(mtl_ctx, msg, &handle);
		if (status != MTLLIB_OK) {
			result = DST_R_SIGNFAILURE;
			goto done;
		}

		h = isc_mem_get(key->mctx, sizeof(*h));
		*h = (mtl_handle_t){
			.hashval = hashval,
			.handle = handle,
		};
		result = isc_hashmap_add(hashmap, hashval, handle_match,
					 (void *)hashval, h, NULL);
		if (result != ISC_R_SUCCESS) {
			mtllib_sign_free_handle(&handle);
			isc_mem_put(key->mctx, h, sizeof(*h));
			goto done;
		}
		goto done;
	}

	result = isc_hashmap_find(hashmap, hashval, handle_match,
				  (void *)hashval, (void **)&h);
	if (result != ISC_R_SUCCESS) {
		MTL_HANDLE *handle = NULL;

		status = mtllib_sign_append(mtl_ctx, msg, &handle);
		if (status != MTLLIB_OK) {
			result = DST_R_SIGNFAILURE;
			goto done;
		}
		h = isc_mem_get(key->mctx, sizeof(*h));
		*h = (mtl_handle_t){
			.hashval = hashval,
			.handle = handle,
		};
		local_handle = true;
	}

	size_t siglen = full ? mtllib_sign_get_full_sig_length(mtl_ctx, h->handle)
			     : mtllib_sign_get_condensed_sig_length(mtl_ctx,
								    h->handle);
	if (siglen == 0) {
		result = DST_R_SIGNFAILURE;
		goto done;
	}

	result = mtl_buffer_allocate(siglen, &mtlsig);
	if (result != ISC_R_SUCCESS) {
		goto done;
	}

	status = full ? mtllib_sign_get_full_sig(mtl_ctx, h->handle, mtlsig)
		      : mtllib_sign_get_condensed_sig(mtl_ctx, h->handle, mtlsig);
	if (status != MTLLIB_OK) {
		result = DST_R_SIGNFAILURE;
		goto done;
	}

	siglen = mtllib_buffer_in_use(mtlsig);
	result = isc_buffer_reserve(sig, siglen + 1);
	if (result != ISC_R_SUCCESS) {
		goto done;
	}

	isc_buffer_putuint8(sig, full ? MTL_TYPE_FULL : MTL_TYPE_CONDENSED);
	isc_buffer_putmem(sig, mtllib_buffer_data_ptr(mtlsig), siglen);

	if (full) {
		result = mtl_ladder_cache_current(key);
		if (result != ISC_R_SUCCESS) {
			goto done;
		}
	}

	if (!local_handle) {
		result = isc_hashmap_delete(hashmap, hashval, handle_match,
					    (void *)hashval);
		INSIST(result == ISC_R_SUCCESS);
	}

	mtllib_sign_free_handle(&h->handle);
	isc_mem_put(key->mctx, h, sizeof(*h));
	h = NULL;

	result = ISC_R_SUCCESS;

done:
	if (h != NULL && local_handle) {
		mtllib_sign_free_handle(&h->handle);
		isc_mem_put(key->mctx, h, sizeof(*h));
	}
	mtl_buffer_free(&msg);
	mtl_buffer_free(&mtlsig);
	return result;
}

static isc_result_t
dst__mtl_verify(dst_context_t *dctx, const isc_region_t *sigreg,
		const isc_region_t *ladder) {
	REQUIRE(dctx != NULL && dctx->key != NULL);
	REQUIRE(mtl_algorithm_supported(dctx->key->key_alg));

	isc_result_t result = ISC_R_UNSET;
	dst_key_t *key = dctx->key;
	isc_buffer_t *buf = dctx->ctxdata.generic;
	isc_region_t tbsreg;
	isc_region_t rawsig;
	MTLLIB_BUFFER *msg = NULL;
	MTLLIB_BUFFER *mtlsig = NULL;
	MTLLIB_BUFFER *mtlladder = NULL;
	MTLLIB_STATUS status;
	MTLLIB_CTX *mtl_ctx = key->keydata.mtl.ctx;
	isc_region_t cached_ladder = { 0 };
	const isc_region_t *verify_ladder = ladder;
	size_t condensed_len = 0;

	if (sigreg->length < 2) {
		return DST_R_VERIFYFAILURE;
	}

	if (sigreg->base[0] != MTL_TYPE_CONDENSED &&
	    sigreg->base[0] != MTL_TYPE_FULL)
	{
		return DST_R_VERIFYFAILURE;
	}

	isc_buffer_usedregion(buf, &tbsreg);
	result = mtl_buffer_from_region(&tbsreg, &msg);
	if (result != ISC_R_SUCCESS) {
		goto done;
	}

	rawsig = (isc_region_t){
		.base = sigreg->base + 1,
		.length = sigreg->length - 1,
	};
	result = mtl_buffer_from_region(&rawsig, &mtlsig);
	if (result != ISC_R_SUCCESS) {
		goto done;
	}

	if ((verify_ladder == NULL || verify_ladder->length == 0) &&
	    key->keydata.mtl.ladder != NULL)
	{
		cached_ladder = (isc_region_t){
			.base = key->keydata.mtl.ladder,
			.length = key->keydata.mtl.ladder_len,
		};
		verify_ladder = &cached_ladder;
	}

	if (verify_ladder != NULL && verify_ladder->length != 0) {
		result = mtl_buffer_from_region(verify_ladder, &mtlladder);
		if (result != ISC_R_SUCCESS) {
			goto done;
		}
	}

	status = mtllib_verify(mtl_ctx, msg, mtlsig, mtlladder, &condensed_len);
	result = mtl_status_to_result(status);
	if (result != ISC_R_SUCCESS) {
		isc_log_write(dctx->category, DNS_LOGMODULE_CRYPTO,
			      ISC_LOG_WARNING, "mtl_verify (%s:%d) failed (%s)",
			      __FILE__, __LINE__, isc_result_totext(result));
	} else if (sigreg->base[0] == MTL_TYPE_FULL) {
		result = mtl_ladder_cache_from_fullsig(key, &rawsig, condensed_len);
	}

done:
	mtl_buffer_free(&msg);
	mtl_buffer_free(&mtlsig);
	mtl_buffer_free(&mtlladder);
	return result;
}

static bool
dst__mtl_compare(const dst_key_t *key1, const dst_key_t *key2) {
	MTLLIB_CTX *mtl_ctx1 = key1->keydata.mtl.ctx;
	MTLLIB_CTX *mtl_ctx2 = key2->keydata.mtl.ctx;
	MTLLIB_BUFFER *pk1 = NULL;
	MTLLIB_BUFFER *pk2 = NULL;
	size_t pk1_len;
	size_t pk2_len;
	bool match = false;

	if (mtl_ctx1 == mtl_ctx2) {
		return true;
	} else if (mtl_ctx1 == NULL || mtl_ctx2 == NULL) {
		return false;
	}

	pk1_len = mtllib_pubkey_to_buffer_length(mtl_ctx1);
	pk2_len = mtllib_pubkey_to_buffer_length(mtl_ctx2);
	if (pk1_len == 0 || pk1_len != pk2_len) {
		goto done;
	}

	if (mtl_buffer_allocate(pk1_len, &pk1) != ISC_R_SUCCESS ||
	    mtl_buffer_allocate(pk2_len, &pk2) != ISC_R_SUCCESS)
	{
		goto done;
	}

	if (mtllib_pubkey_to_buffer(mtl_ctx1, pk1) != MTLLIB_OK ||
	    mtllib_pubkey_to_buffer(mtl_ctx2, pk2) != MTLLIB_OK)
	{
		goto done;
	}

	if (memcmp(mtllib_buffer_data_ptr(pk1), mtllib_buffer_data_ptr(pk2),
		   pk1_len) != 0)
	{
		goto done;
	}

	match = key1->keydata.mtl.isprivate == key2->keydata.mtl.isprivate;

done:
	mtl_buffer_free(&pk1);
	mtl_buffer_free(&pk2);
	return match;
}

static isc_result_t
dst__mtl_generate(dst_key_t *key, int unused ISC_ATTR_UNUSED,
		  void (*callback ISC_ATTR_UNUSED)(int)) {
	REQUIRE(key != NULL);
	REQUIRE(mtl_algorithm_supported(key->key_alg));
	REQUIRE(key->keydata.mtl.ctx == NULL);

	MTLLIB_CTX *mtl_ctx = NULL;
	MTLLIB_STATUS status;

	status = mtllib_key_new((char *)mtl_algorithm_name(key->key_alg),
				&mtl_ctx);
	if (status != MTLLIB_OK) {
		isc_log_write(DNS_LOGCATEGORY_GENERAL, DNS_LOGMODULE_CRYPTO,
			      ISC_LOG_WARNING,
			      "mtllib_key_new (%s:%d) failed (%d)", __FILE__,
			      __LINE__, status);
		return DST_R_CRYPTOFAILURE;
	}

	key->keydata.mtl.ctx = mtl_ctx;
	key->keydata.mtl.isprivate = true;
	key->key_size = MTL_DNSKEY_SIZE * 8;

	return ISC_R_SUCCESS;
}

static isc_result_t
dst__mtl_todns(const dst_key_t *key, isc_buffer_t *data) {
	REQUIRE(key != NULL);
	REQUIRE(mtl_algorithm_supported(key->key_alg));

	MTLLIB_CTX *mtl_ctx = key->keydata.mtl.ctx;
	MTLLIB_BUFFER *pubkey = NULL;
	isc_result_t result = ISC_R_UNSET;
	size_t pk_len;

	pk_len = mtllib_pubkey_to_buffer_length(mtl_ctx);
	if (pk_len != MTL_DNSKEY_SIZE) {
		return DST_R_INVALIDPUBLICKEY;
	}

	if (isc_buffer_availablelength(data) < pk_len) {
		return ISC_R_NOSPACE;
	}

	result = mtl_buffer_allocate(pk_len, &pubkey);
	if (result != ISC_R_SUCCESS) {
		return result;
	}

	if (mtllib_pubkey_to_buffer(mtl_ctx, pubkey) != MTLLIB_OK) {
		result = DST_R_INVALIDPUBLICKEY;
		goto done;
	}

	isc_buffer_putmem(data, mtllib_buffer_data_ptr(pubkey), pk_len);
	result = ISC_R_SUCCESS;

done:
	mtl_buffer_free(&pubkey);
	return result;
}

static isc_result_t
dst__mtl_fromdns(dst_key_t *key, isc_buffer_t *data) {
	REQUIRE(key != NULL);
	REQUIRE(mtl_algorithm_supported(key->key_alg));
	REQUIRE(key->keydata.mtl.ctx == NULL);

	isc_region_t r;
	uint8_t sid[MTL_DNSKEY_SIZE] = { 0 };
	MTLLIB_CTX *mtl_ctx = NULL;
	isc_result_t result;

	isc_buffer_remainingregion(data, &r);
	if (r.length != MTL_DNSKEY_SIZE) {
		return DST_R_INVALIDPUBLICKEY;
	}

	result = mtl_context_from_public(key->key_alg, &r, sid, &mtl_ctx);
	if (result != ISC_R_SUCCESS) {
		return result;
	}

	key->keydata.mtl.ctx = mtl_ctx;
	key->keydata.mtl.isprivate = false;
	key->key_size = MTL_DNSKEY_SIZE * 8;
	isc_buffer_forward(data, r.length);

	return ISC_R_SUCCESS;
}

static bool
dst__mtl_isprivate(const dst_key_t *key) {
	return key->keydata.mtl.isprivate;
}

static void
dst__mtl_destroy(dst_key_t *key) {
	REQUIRE(key != NULL);
	REQUIRE(mtl_algorithm_supported(key->key_alg));

	if (key->keydata.mtl.ctx != NULL) {
		mtllib_key_free(key->keydata.mtl.ctx);
		key->keydata.mtl.ctx = NULL;
	}
	mtl_ladder_clear(key);
	key->keydata.mtl.isprivate = false;

	if (key->keydata.mtl.hashmap != NULL) {
		RUNTIME_CHECK(isc_hashmap_count(key->keydata.mtl.hashmap) == 0);
		isc_hashmap_destroy(&key->keydata.mtl.hashmap);
	}
}

static isc_result_t
dst__mtl_tofile(const dst_key_t *key, const char *directory) {
	REQUIRE(key != NULL);
	REQUIRE(mtl_algorithm_supported(key->key_alg));

	isc_result_t result = ISC_R_UNSET;
	dst_private_t priv;
	MTLLIB_BUFFER *sk = NULL;

	memset(&priv, 0, sizeof(priv));

	if (key->keydata.mtl.ctx == NULL) {
		return DST_R_NULLKEY;
	}

	INSIST(!key->external);

	if (dst_key_isprivate(key)) {
		size_t sk_len = mtllib_key_to_buffer_length(key->keydata.mtl.ctx);
		if (sk_len == 0) {
			return DST_R_INVALIDPRIVATEKEY;
		}

		result = mtl_buffer_allocate(sk_len, &sk);
		if (result != ISC_R_SUCCESS) {
			return result;
		}

		if (mtllib_key_to_buffer(key->keydata.mtl.ctx, sk) !=
		    MTLLIB_OK)
		{
			result = DST_R_INVALIDPRIVATEKEY;
			goto done;
		}

		priv.elements[0].tag = TAG(key->key_alg, 0);
		priv.elements[0].length = mtllib_buffer_in_use(sk);
		priv.elements[0].data = mtllib_buffer_data_ptr(sk);
		priv.nelements = 1;
	}

	result = dst__privstruct_writefile(key, &priv, directory);

done:
	mtl_buffer_free(&sk);
	return result;
}

static isc_result_t
dst__mtl_parse(dst_key_t *key, isc_lex_t *lexer, dst_key_t *pub) {
	REQUIRE(key != NULL);
	REQUIRE(mtl_algorithm_supported(key->key_alg));
	REQUIRE(key->keydata.mtl.ctx == NULL);

	isc_result_t result = ISC_R_UNSET;
	dst_private_t priv;
	MTLLIB_CTX *mtl_ctx = NULL;
	MTLLIB_BUFFER *sk = NULL;

	memset(&priv, 0, sizeof(priv));

	result = dst__privstruct_parse(key, key->key_alg, lexer, key->mctx,
				       &priv);
	if (result != ISC_R_SUCCESS) {
		goto done;
	}

	INSIST(!key->external);
	INSIST(priv.nelements <= 1);

	if (priv.nelements == 0 || priv.elements[0].tag != TAG(key->key_alg, 0))
	{
		result = DST_R_INVALIDPRIVATEKEY;
		goto done;
	}

	result = mtl_buffer_from_region(&(isc_region_t){
						.base = priv.elements[0].data,
						.length = priv.elements[0].length,
					},
					&sk);
	if (result != ISC_R_SUCCESS) {
		goto done;
	}

	if (mtllib_key_from_buffer(sk, &mtl_ctx) != MTLLIB_OK) {
		result = DST_R_INVALIDPRIVATEKEY;
		goto done;
	}

	if (pub != NULL && pub->keydata.mtl.ctx != NULL) {
		dst_key_t tmpkey = *key;
		tmpkey.keydata.mtl.ctx = mtl_ctx;
		tmpkey.keydata.mtl.isprivate = pub->keydata.mtl.isprivate;
		if (!dst__mtl_compare(&tmpkey, pub)) {
			result = DST_R_INVALIDPRIVATEKEY;
			goto done;
		}
	}

	key->keydata.mtl.ctx = mtl_ctx;
	key->keydata.mtl.isprivate = true;
	key->key_size = MTL_DNSKEY_SIZE * 8;
	mtl_ctx = NULL;

	result = ISC_R_SUCCESS;

done:
	if (mtl_ctx != NULL) {
		mtllib_key_free(mtl_ctx);
	}
	mtl_buffer_free(&sk);
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
	return mtl_algorithm_supported(algorithm) ? ISC_R_SUCCESS
						  : ISC_R_NOTIMPLEMENTED;
}

void
dst__mtl_init(dst_func_t **funcp, unsigned char algorithm) {
	REQUIRE(funcp != NULL);

	if (*funcp == NULL && check_algorithm(algorithm) == ISC_R_SUCCESS) {
		*funcp = &dst__mtl_functions;
	}
}
