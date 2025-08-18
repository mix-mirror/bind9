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

#include <isc/log.h>
#include <isc/mem.h>
#include <isc/mutex.h>
#include <isc/result.h>
#include <isc/string.h>
#include <isc/thread.h>
#include <isc/tls.h>
#include <isc/util.h>

#include "dst_internal.h"
#include "dst_openssl.h"

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/core_names.h>
#include <openssl/param_build.h>
#include <openssl/store.h>
#endif

#include "openssl_shim.h"

#if OPENSSL_VERSION_NUMBER >= 0x30000000L

isc_result_t
dst__openssl_fromlabel(int key_base_id, const char *label,
		       const char *pin ISC_ATTR_UNUSED, EVP_PKEY **ppub,
		       EVP_PKEY **ppriv) {
	REQUIRE(ppub != NULL && *ppub == NULL);
	REQUIRE(ppriv != NULL && *ppriv == NULL);

	auto_EVP_PKEY *pub = NULL;
	auto_EVP_PKEY *priv = NULL;
	auto_OSSL_STORE_CTX *ctx = OSSL_STORE_open(label, NULL, NULL, NULL,
						   NULL);
	if (ctx == NULL) {
		return dst__openssl_toresult(DST_R_OPENSSLFAILURE);
	}

	while (!OSSL_STORE_eof(ctx)) {
		auto_OSSL_STORE_INFO *info = OSSL_STORE_load(ctx);
		if (info == NULL) {
			continue;
		}

		switch (OSSL_STORE_INFO_get_type(info)) {
		case OSSL_STORE_INFO_PKEY:
			if (priv != NULL) {
				return DST_R_INVALIDPRIVATEKEY;
			}
			priv = OSSL_STORE_INFO_get1_PKEY(info);
			if (EVP_PKEY_get_base_id(priv) != key_base_id) {
				return DST_R_BADKEYTYPE;
			}
			break;
		case OSSL_STORE_INFO_PUBKEY:
			if (pub != NULL) {
				return DST_R_INVALIDPUBLICKEY;
			}
			pub = OSSL_STORE_INFO_get1_PUBKEY(info);
			if (EVP_PKEY_get_base_id(pub) != key_base_id) {
				return DST_R_BADKEYTYPE;
			}
			break;
		}
	}
	if (priv == NULL || pub == NULL) {
		return DST_R_OPENSSLFAILURE;
	}

	MOVE_INTO(*ppub, pub);
	MOVE_INTO(*ppriv, priv);

	return ISC_R_SUCCESS;
}

#else /* OPENSSL_VERSION_NUMBER >= 0x30000000L */

isc_result_t
dst__openssl_fromlabel(int key_base_id ISC_ATTR_UNUSED,
		       const char *label ISC_ATTR_UNUSED,
		       const char *pin ISC_ATTR_UNUSED,
		       EVP_PKEY **ppub ISC_ATTR_UNUSED,
		       EVP_PKEY **ppriv ISC_ATTR_UNUSED) {
	return DST_R_OPENSSLFAILURE;
}

#endif /* OPENSSL_VERSION_NUMBER >= 0x30000000L */

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
