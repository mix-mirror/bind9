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

#pragma once

#include <openssl/bn.h>
#include <openssl/conf.h>
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include <isc/log.h>
#include <isc/result.h>
#include <isc/tls.h>

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/param_build.h>
#include <openssl/store.h>
#endif /* OPENSSL_VERSION_NUMBER >= 0x30000000L */

#include "dst_internal.h"

#define dst__openssl_toresult(fallback)                                    \
	isc__tlserr2result(ISC_LOGCATEGORY_INVALID, ISC_LOGMODULE_INVALID, \
			   NULL, fallback, __FILE__, __LINE__)
#define dst__openssl_toresult2(funcname, fallback)                        \
	isc__tlserr2result(DNS_LOGCATEGORY_GENERAL, DNS_LOGMODULE_CRYPTO, \
			   funcname, fallback, __FILE__, __LINE__)
#define dst__openssl_toresult3(category, funcname, fallback)                   \
	isc__tlserr2result(category, DNS_LOGMODULE_CRYPTO, funcname, fallback, \
			   __FILE__, __LINE__)

isc_result_t
dst__openssl_fromlabel(int key_base_id, const char *label, const char *pin,
		       EVP_PKEY **ppub, EVP_PKEY **ppriv);

bool
dst__openssl_keypair_compare(const dst_key_t *key1, const dst_key_t *key2);

bool
dst__openssl_keypair_isprivate(const dst_key_t *key);

void
dst__openssl_keypair_destroy(dst_key_t *key);

ISC_AUTO_DECL(EVP_PKEY, EVP_PKEY_free)
#define auto_EVP_PKEY ISC_AUTO(EVP_PKEY)

#if OPENSSL_VERSION_NUMBER >= 0x30000000L

ISC_AUTO_DECL(OSSL_STORE_CTX, OSSL_STORE_close)
#define auto_OSSL_STORE_CTX ISC_AUTO(OSSL_STORE_CTX)

ISC_AUTO_DECL(OSSL_STORE_INFO, OSSL_STORE_INFO_free)
#define auto_OSSL_STORE_INFO ISC_AUTO(OSSL_STORE_INFO)

ISC_AUTO_DECL(OSSL_PARAM, OSSL_PARAM_free)
#define auto_OSSL_PARAM ISC_AUTO(OSSL_PARAM)

ISC_AUTO_DECL(OSSL_PARAM_BLD, OSSL_PARAM_BLD_free)
#define auto_OSSL_PARAM_BLD ISC_AUTO(OSSL_PARAM_BLD)

#else /* OPENSSL_VERSION_NUMBER >= 0x30000000L */

ISC_AUTO_DECL(EC_KEY, EC_KEY_free)
#define auto_EC_KEY   ISC_AUTO(EC_KEY)

ISC_AUTO_DECL(RSA, RSA_free)
#define auto_RSA      ISC_AUTO(RSA)

ISC_AUTO_DECL(BN_GENCB, BN_GENCB_free)
#define auto_BN_GENCB ISC_AUTO(BN_GENCB)

#endif

ISC_AUTO_DECL(EVP_PKEY_CTX, EVP_PKEY_CTX_free)
#define auto_EVP_PKEY_CTX ISC_AUTO(EVP_PKEY_CTX)

ISC_AUTO_DECL(BIGNUM, BN_clear_free)
#define auto_BIGNUM ISC_AUTO(BIGNUM)

ISC_AUTO_DECL(EC_POINT, EC_POINT_free)
#define auto_EC_POINT ISC_AUTO(EC_POINT)

ISC_AUTO_DECL(EC_GROUP, EC_GROUP_free)
#define auto_EC_GROUP ISC_AUTO(EC_GROUP)

ISC_AUTO_DECL(EVP_MD_CTX, EVP_MD_CTX_free)
#define auto_EVP_MD_CTX ISC_AUTO(EVP_MD_CTX)

ISC_AUTO_DECL(ECDSA_SIG, ECDSA_SIG_free)
#define auto_ECDSA_SIG ISC_AUTO(ECDSA_SIG)

typedef void OPENSSL_void;
ISC_AUTO_DECL(OPENSSL_void, OPENSSL_free)
#define auto_OPENSSL_void ISC_AUTO(OPENSSL_void)
