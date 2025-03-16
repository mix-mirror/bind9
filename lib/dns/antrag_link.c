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

#include <isc/mem.h>
#include <isc/safe.h>
#include <isc/util.h>

#include <dns/keyvalues.h>

#include "antrag/antrag/api.h"
#include "dst_internal.h"
#include "dst_parse.h"
#include "isc/result.h"
#include "isc/time.h"

static isc_result_t
dst__antrag_createctx(dst_key_t *key ISC_ATTR_UNUSED, dst_context_t *dctx) {
	REQUIRE(dctx != NULL && dctx->key != NULL);
	REQUIRE(dctx->key->key_alg == DST_ALG_ANTRAG);

	isc_buffer_t *buf = NULL;

	isc_buffer_allocate(dctx->mctx, &buf, 64);
	dctx->ctxdata.generic = buf;

	return ISC_R_SUCCESS;
}

static void
dst__antrag_destroyctx(dst_context_t *dctx) {
	REQUIRE(dctx != NULL && dctx->key != NULL);
	REQUIRE(dctx->key->key_alg == DST_ALG_ANTRAG);

	isc_buffer_t *buf = dctx->ctxdata.generic;
	if (buf != NULL) {
		isc_buffer_free(&buf);
		dctx->ctxdata.generic = NULL;
	}
}

static isc_result_t
dst__antrag_adddata(dst_context_t *dctx, const isc_region_t *data) {
	REQUIRE(dctx != NULL && dctx->key != NULL);
	REQUIRE(dctx->key->key_alg == DST_ALG_ANTRAG);

	isc_buffer_t *buf = dctx->ctxdata.generic;
	isc_result_t result = isc_buffer_copyregion(buf, data);
	INSIST(result == ISC_R_SUCCESS);

	return ISC_R_SUCCESS;
}

static isc_result_t
dst__antrag_sign(dst_context_t *dctx, isc_buffer_t *sig) {
	REQUIRE(dctx != NULL && dctx->key != NULL);
	REQUIRE(dctx->key->key_alg == DST_ALG_ANTRAG);

	isc_result_t result = ISC_R_UNSET;
	dst_key_t *key = dctx->key;
	isc_buffer_t *buf = dctx->ctxdata.generic;
	isc_region_t msgreg;
	isc_region_t sigreg;
	signature s = { 0 };
	int status;

	isc_buffer_availableregion(sig, &sigreg);
	if (sigreg.length < DNS_SIG_ANTRAGSIZE) {
		result = ISC_R_NOSPACE;
		goto done;
	}

	isc_buffer_usedregion(buf, &msgreg);

	do {
		sign(msgreg.length, msgreg.base, key->keydata.antrag.priv, &s);

		status = encode_sig(sigreg.base, &s);
	} while (status != 0);

	isc_buffer_add(sig, DNS_SIG_ANTRAGSIZE);
	result = ISC_R_SUCCESS;

done:
	isc_buffer_free(&buf);
	dctx->ctxdata.generic = NULL;

	return result;
}

static isc_result_t
dst__antrag_verify(dst_context_t *dctx, const isc_region_t *sigreg) {
	REQUIRE(dctx != NULL && dctx->key != NULL);
	REQUIRE(dctx->key->key_alg == DST_ALG_ANTRAG);

	isc_result_t result = ISC_R_UNSET;
	dst_key_t *key = dctx->key;
	isc_buffer_t *buf = dctx->ctxdata.generic;
	isc_region_t msg;
	signature sig;

	if (sigreg->length != DNS_SIG_ANTRAGSIZE) {
		result = DST_R_VERIFYFAILURE;
		goto done;
	}

	isc_buffer_usedregion(buf, &msg);

	int status = decode_sig(&sig, sigreg->base);
	if (status == 1) {
		result = DST_R_VERIFYFAILURE;
		isc_log_write(dctx->category, DNS_LOGMODULE_CRYPTO,
			      ISC_LOG_WARNING, "decode_sig (%s:%d) failed (%s)",
			      __FILE__, __LINE__, isc_result_totext(result));
		goto done;
	}

	status = verify(msg.length, msg.base, key->keydata.antrag.pub, &sig);
	if (status == 0) {
		result = DST_R_VERIFYFAILURE;
		isc_log_write(dctx->category, DNS_LOGMODULE_CRYPTO,
			      ISC_LOG_WARNING, "verify (%s:%d) failed (%s)",
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
dst__antrag_compare(const dst_key_t *key1, const dst_key_t *key2) {
	public_key *pk1 = key1->keydata.antrag.pub;
	public_key *pk2 = key2->keydata.antrag.pub;
	uint8_t pk_buf1[DNS_KEY_ANTRAGSIZE];
	uint8_t pk_buf2[DNS_KEY_ANTRAGSIZE];

	secret_key *sk1 = key1->keydata.antrag.priv;
	secret_key *sk2 = key2->keydata.antrag.priv;
	uint8_t sk_buf1[DNS_SEC_ANTRAGSIZE];
	uint8_t sk_buf2[DNS_SEC_ANTRAGSIZE];

	if ((pk1 == pk2) && (sk1 == sk2)) {
		/* The keys are identical or all NULL */
		return true;
	} else if (pk1 == NULL || pk2 == NULL) {
		return false;
	}

	encode_pk(pk_buf1, pk1);
	encode_pk(pk_buf2, pk2);

	if (memcmp(pk_buf1, pk_buf2, DNS_KEY_ANTRAGSIZE) != 0) {
		return false;
	}

	if (sk1 == sk2) {
		/* The keys are identical or both NULL */
		return true;
	} else if (sk1 == NULL || sk1 == NULL) {
		return false;
	}

	encode_sk(sk_buf1, sk1);
	encode_sk(sk_buf2, sk2);

	if (memcmp(sk_buf1, sk_buf2, DNS_SEC_ANTRAGSIZE) != 0) {
		return false;
	}

	return true;
}

static isc_result_t
dst__antrag_generate(dst_key_t *key, int unused ISC_ATTR_UNUSED,
		     void (*callback ISC_ATTR_UNUSED)(int)) {
	REQUIRE(key != NULL);
	REQUIRE(key->key_alg == DST_ALG_ANTRAG);
	REQUIRE(key->keydata.antrag.pub == NULL &&
		key->keydata.antrag.priv == NULL);

	isc_result_t result = ISC_R_UNSET;
	public_key *pk = isc_mem_get(key->mctx, sizeof(*pk));
	secret_key *sk = isc_mem_get(key->mctx, sizeof(*sk));

	int status = keygen_full(sk, pk);
	if (status == 0) {
		result = DST_R_CRYPTOFAILURE;
		isc_log_write(DNS_LOGCATEGORY_GENERAL, DNS_LOGMODULE_CRYPTO,
			      ISC_LOG_WARNING,
			      "keygen_full (%s:%d) failed (%s)", __FILE__,
			      __LINE__, isc_result_totext(result));
		goto done;
	}

	key->keydata.antrag.pub = pk;
	key->keydata.antrag.priv = sk;
	key->key_size = DNS_KEY_ANTRAGSIZE * 8;

	result = ISC_R_SUCCESS;

done:
	if (result != ISC_R_SUCCESS) {
		isc_mem_put(key->mctx, sk, sizeof(*sk));
		isc_mem_put(key->mctx, pk, sizeof(*pk));
	}

	return ISC_R_SUCCESS;
}

static isc_result_t
dst__antrag_todns(const dst_key_t *key, isc_buffer_t *data) {
	REQUIRE(key != NULL);
	REQUIRE(key->key_alg == DST_ALG_ANTRAG);

	isc_region_t r;

	isc_buffer_availableregion(data, &r);

	REQUIRE(r.length >= DNS_KEY_ANTRAGSIZE);

	if (r.length < DNS_KEY_ANTRAGSIZE) {
		return ISC_R_NOSPACE;
	}

	encode_pk(r.base, key->keydata.antrag.pub);
	isc_buffer_add(data, DNS_KEY_ANTRAGSIZE);

	return ISC_R_SUCCESS;
}

static isc_result_t
dst__antrag_fromdns(dst_key_t *key, isc_buffer_t *data) {
	REQUIRE(key != NULL);
	REQUIRE(key->key_alg == DST_ALG_ANTRAG);
	REQUIRE(key->keydata.antrag.pub == NULL);

	isc_region_t r;

	isc_buffer_remainingregion(data, &r);
	if (r.length == 0) {
		return ISC_R_SUCCESS;
	}
	INSIST(r.length == DNS_KEY_ANTRAGSIZE);

	public_key *pk = isc_mem_get(key->mctx, sizeof(*pk));
	decode_pk(pk, r.base);

	key->keydata.antrag.pub = pk;
	key->key_size = DNS_KEY_ANTRAGSIZE * 8;

	return ISC_R_SUCCESS;
}

static bool
dst__antrag_isprivate(const dst_key_t *key) {
	return key->keydata.antrag.priv != NULL;
}

static void
dst__antrag_destroy(dst_key_t *key) {
	REQUIRE(key != NULL);
	REQUIRE(key->key_alg == DST_ALG_ANTRAG);
	REQUIRE(key->keydata.antrag.pub != NULL);

	if (key->keydata.antrag.priv != NULL) {
		isc_mem_put(key->mctx, key->keydata.antrag.priv,
			    sizeof(*key->keydata.antrag.priv));
	}

	isc_mem_put(key->mctx, key->keydata.antrag.pub,
		    sizeof(*key->keydata.antrag.pub));
}

static isc_result_t
dst__antrag_tofile(const dst_key_t *key, const char *directory) {
	REQUIRE(key != NULL);
	REQUIRE(key->key_alg == DST_ALG_ANTRAG);

	dst_private_t priv;
	int i = 0;
	uint8_t pkbuf[DNS_KEY_ANTRAGSIZE];
	uint8_t skbuf[DNS_SEC_ANTRAGSIZE];

	if (key->keydata.antrag.pub == NULL) {
		return DST_R_NULLKEY;
	}

	INSIST(!key->external);

	encode_pk(pkbuf, key->keydata.antrag.pub);
	priv.elements[i].tag = TAG_ANTRAG_PUBLICKEY;
	priv.elements[i].length = DNS_KEY_ANTRAGSIZE;
	priv.elements[i].data = pkbuf;
	i++;

	if (dst_key_isprivate(key)) {
		encode_sk(skbuf, key->keydata.antrag.priv);
		priv.elements[i].tag = TAG_ANTRAG_SECRETKEY;
		priv.elements[i].length = DNS_SEC_ANTRAGSIZE;
		priv.elements[i].data = skbuf;
		i++;
	}

	priv.nelements = i;

	return dst__privstruct_writefile(key, &priv, directory);
}

static isc_result_t
dst__antrag_parse(dst_key_t *key, isc_lex_t *lexer, dst_key_t *pub) {
	REQUIRE(key != NULL);
	REQUIRE(key->key_alg == DST_ALG_ANTRAG);
	REQUIRE(key->keydata.antrag.pub == NULL &&
		key->keydata.antrag.priv == NULL);

	isc_result_t result = ISC_R_UNSET;
	dst_private_t priv;
	public_key *pk = isc_mem_get(key->mctx, sizeof(*pk));
	secret_key *sk = isc_mem_get(key->mctx, sizeof(*sk));

	result = dst__privstruct_parse(key, DST_ALG_ANTRAG, lexer, key->mctx,
				       &priv);
	if (result != ISC_R_SUCCESS) {
		goto done;
	}

	if (key->external) {
		if (priv.nelements != 0 || pub == NULL) {
			result = DST_R_INVALIDPRIVATEKEY;
			goto done;
		}

		key->keydata.antrag.priv = pub->keydata.antrag.priv;
		key->keydata.antrag.pub = pub->keydata.antrag.pub;
		pub->keydata.antrag.priv = NULL;
		pub->keydata.antrag.pub = NULL;

		result = ISC_R_SUCCESS;
		goto done;
	}

	for (size_t i = 0; i < priv.nelements; i++) {
		switch (priv.elements[i].tag) {
		case TAG_ANTRAG_PUBLICKEY:
			if (priv.elements[i].length != DNS_KEY_ANTRAGSIZE) {
				result = DST_R_INVALIDPUBLICKEY;
				goto done;
			}
			decode_pk(pk, priv.elements[i].data);
			break;
		case TAG_ANTRAG_SECRETKEY:
			if (priv.elements[i].length != DNS_SEC_ANTRAGSIZE) {
				result = DST_R_INVALIDPRIVATEKEY;
				goto done;
			}
			decode_sk(sk, priv.elements[i].data);
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

	key->keydata.antrag.priv = sk;
	key->keydata.antrag.pub = pk;
	key->key_size = DNS_KEY_ANTRAGSIZE * 8;

	result = ISC_R_SUCCESS;

done:
	if (result != ISC_R_SUCCESS) {
		isc_safe_memwipe(pk, sizeof(*pk));
		isc_mem_put(key->mctx, pk, sizeof(*pk));

		isc_safe_memwipe(sk, sizeof(*sk));
		isc_mem_put(key->mctx, sk, sizeof(*sk));
	}

	dst__privstruct_free(&priv, key->mctx);
	isc_safe_memwipe(&priv, sizeof(priv));

	return result;
}

static dst_func_t dst__antrag_functions = {
	dst__antrag_createctx,
	dst__antrag_destroyctx,
	dst__antrag_adddata,
	dst__antrag_sign,
	dst__antrag_verify,
	dst__antrag_compare,
	dst__antrag_generate,
	dst__antrag_isprivate,
	dst__antrag_destroy,
	dst__antrag_todns,
	dst__antrag_fromdns,
	dst__antrag_tofile,
	dst__antrag_parse,
	NULL, /*%< fromlabel */
	NULL, /*%< dump */
	NULL, /*%< restore */
};

static isc_result_t
check_algorithm(unsigned char algorithm) {
	switch (algorithm) {
	case DST_ALG_ANTRAG:
		break;
	default:
		return ISC_R_NOTIMPLEMENTED;
	}

	/*
	 * TODO: check that we can verify AntragHD signature
	 * like we do with the other algorithms.
	 */

	return ISC_R_SUCCESS;
}

void
dst__antrag_init(dst_func_t **funcp, unsigned char algorithm) {
	REQUIRE(funcp != NULL);

	if (*funcp == NULL) {
		if (check_algorithm(algorithm) == ISC_R_SUCCESS) {
			*funcp = &dst__antrag_functions;
		}
	}
}
