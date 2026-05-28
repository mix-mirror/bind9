/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * SPDX-License-Identifier: MPL-2.0 AND ISC
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * See the COPYRIGHT file distributed with this work for additional
 * information regarding copyright ownership.
 */

/*
 * Copyright (C) Network Associates, Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND ISC AND NETWORK ASSOCIATES DISCLAIMS
 * ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE
 * FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR
 * IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <time.h>

#include <isc/log.h>
#include <isc/mem.h>
#include <isc/mutex.h>
#include <isc/once.h>
#include <isc/result.h>
#include <isc/string.h>
#include <isc/thread.h>
#include <isc/tls.h>
#include <isc/util.h>

#include "dst_internal.h"
#include "dst_openssl.h"

static isc_once_t toklock_once = ISC_ONCE_INITIALIZER;
static isc_mutex_t toklock;

static void
toklock_initialize(void) {
	isc_mutex_init(&toklock);
}

void
dst__openssl_toklock(void) {
	isc_once_do(&toklock_once, toklock_initialize);
	isc_mutex_lock(&toklock);
}

void
dst__openssl_tokunlock(void) {
	isc_mutex_unlock(&toklock);
}

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/core_names.h>
#include <openssl/store.h>
#endif

#include "openssl_shim.h"

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
static isc_result_t
fromlabel_provider_once(int key_base_id, const char *label, EVP_PKEY **ppub,
			EVP_PKEY **ppriv) {
	isc_result_t result = DST_R_OPENSSLFAILURE;
	OSSL_STORE_CTX *ctx = NULL;

	ctx = OSSL_STORE_open(label, NULL, NULL, NULL, NULL);
	if (!ctx) {
		CLEANUP(dst__openssl_toresult(DST_R_OPENSSLFAILURE));
	}

	while (!OSSL_STORE_eof(ctx)) {
		OSSL_STORE_INFO *info = OSSL_STORE_load(ctx);
		if (info == NULL) {
			continue;
		}
		switch (OSSL_STORE_INFO_get_type(info)) {
		case OSSL_STORE_INFO_PKEY:
			if (*ppriv != NULL) {
				OSSL_STORE_INFO_free(info);
				CLEANUP(DST_R_INVALIDPRIVATEKEY);
			}
			*ppriv = OSSL_STORE_INFO_get1_PKEY(info);
			if (EVP_PKEY_get_base_id(*ppriv) != key_base_id) {
				OSSL_STORE_INFO_free(info);
				CLEANUP(DST_R_BADKEYTYPE);
			}
			break;
		case OSSL_STORE_INFO_PUBKEY:
			if (*ppub != NULL) {
				OSSL_STORE_INFO_free(info);
				CLEANUP(DST_R_INVALIDPUBLICKEY);
			}
			*ppub = OSSL_STORE_INFO_get1_PUBKEY(info);
			if (EVP_PKEY_get_base_id(*ppub) != key_base_id) {
				OSSL_STORE_INFO_free(info);
				CLEANUP(DST_R_BADKEYTYPE);
			}
			break;
		}
		OSSL_STORE_INFO_free(info);
	}
	if (*ppriv != NULL && *ppub == NULL) {
		/* No separate public object; the private key carries it. */
		EVP_PKEY_up_ref(*ppriv);
		*ppub = *ppriv;
	}
	if (*ppriv != NULL && *ppub != NULL) {
		result = ISC_R_SUCCESS;
	}
cleanup:
	if (ctx != NULL) {
		OSSL_STORE_close(ctx);
	}
	return result;
}
#endif

static isc_result_t
dst__openssl_fromlabel_provider(int key_base_id, const char *label,
				const char *pin, EVP_PKEY *cmp_pub,
				EVP_PKEY **ppub, EVP_PKEY **ppriv) {
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
	isc_result_t result = DST_R_OPENSSLFAILURE;

	UNUSED(pin);

	/*
	 * A token load can transiently return an empty set or, for a freshly
	 * created key, an object whose public key does not match 'cmp_pub'.
	 * Retry with a short backoff, dropping the lock while sleeping.
	 */
	for (unsigned int attempt = 0;; attempt++) {
		dst__openssl_toklock();
		result = fromlabel_provider_once(key_base_id, label, ppub,
						 ppriv);
		dst__openssl_tokunlock();
		if (result == ISC_R_SUCCESS && cmp_pub != NULL &&
		    EVP_PKEY_eq(*ppub, cmp_pub) != 1)
		{
			result = DST_R_INVALIDPRIVATEKEY;
		}
		if (result == ISC_R_SUCCESS || attempt >= 199) {
			break;
		}
		if (*ppub != NULL) {
			EVP_PKEY_free(*ppub);
			*ppub = NULL;
		}
		if (*ppriv != NULL) {
			EVP_PKEY_free(*ppriv);
			*ppriv = NULL;
		}
		(void)nanosleep(&(struct timespec){ .tv_nsec = 10000000 },
				NULL);
	}
	return result;
#else
	UNUSED(key_base_id);
	UNUSED(label);
	UNUSED(pin);
	UNUSED(cmp_pub);
	UNUSED(ppub);
	UNUSED(ppriv);
	return DST_R_OPENSSLFAILURE;
#endif
}

isc_result_t
dst__openssl_fromlabel(int key_base_id, const char *label, const char *pin,
		       EVP_PKEY *cmp_pub, EVP_PKEY **ppub, EVP_PKEY **ppriv) {
	return dst__openssl_fromlabel_provider(key_base_id, label, pin, cmp_pub,
					       ppub, ppriv);
}

bool
dst__openssl_keypair_compare(const dst_key_t *key1, const dst_key_t *key2) {
	EVP_PKEY *pkey1 = key1->keydata.pkeypair.pub;
	EVP_PKEY *pkey2 = key2->keydata.pkeypair.pub;

	if (pkey1 == pkey2) {
		return true;
	} else if (pkey1 == NULL || pkey2 == NULL) {
		return false;
	}

	/* `EVP_PKEY_eq` checks only the public components and parameters. */
	if (EVP_PKEY_eq(pkey1, pkey2) != 1) {
		return false;
	}
	/* The private key presence must be same for keys to match. */
	if ((key1->keydata.pkeypair.priv != NULL) !=
	    (key2->keydata.pkeypair.priv != NULL))
	{
		return false;
	}
	return true;
}

bool
dst__openssl_keypair_isprivate(const dst_key_t *key) {
	return key->keydata.pkeypair.priv != NULL;
}

void
dst__openssl_keypair_destroy(dst_key_t *key) {
	if (key->keydata.pkeypair.priv != key->keydata.pkeypair.pub) {
		EVP_PKEY_free(key->keydata.pkeypair.priv);
	}
	EVP_PKEY_free(key->keydata.pkeypair.pub);
	key->keydata.pkeypair.pub = NULL;
	key->keydata.pkeypair.priv = NULL;
}

/*! \file */
