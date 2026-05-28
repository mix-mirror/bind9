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

#include <string.h>

#include <isc/assertions.h>
#include <isc/buffer.h>
#include <isc/dir.h>
#include <isc/hex.h>
#include <isc/md.h>
#include <isc/mem.h>
#include <isc/time.h>
#include <isc/util.h>

#include <dns/fixedname.h>
#include <dns/keystore.h>
#include <dns/keyvalues.h>

void
dns_keystore_create(isc_mem_t *mctx, const char *name, dns_keystore_t **kspp) {
	dns_keystore_t *keystore;

	REQUIRE(name != NULL);
	REQUIRE(kspp != NULL && *kspp == NULL);

	keystore = isc_mem_get(mctx, sizeof(*keystore));
	keystore->mctx = NULL;
	isc_mem_attach(mctx, &keystore->mctx);

	keystore->name = isc_mem_strdup(mctx, name);
	isc_mutex_init(&keystore->lock);

	isc_refcount_init(&keystore->references, 1);

	ISC_LINK_INIT(keystore, link);

	keystore->directory = NULL;
	keystore->pkcs11uri = NULL;

	keystore->magic = DNS_KEYSTORE_MAGIC;
	*kspp = keystore;
}

static inline void
dns__keystore_destroy(dns_keystore_t *keystore) {
	char *name;

	REQUIRE(!ISC_LINK_LINKED(keystore, link));

	isc_mutex_destroy(&keystore->lock);
	name = UNCONST(keystore->name);
	isc_mem_free(keystore->mctx, name);
	if (keystore->directory != NULL) {
		isc_mem_free(keystore->mctx, keystore->directory);
	}
	if (keystore->pkcs11uri != NULL) {
		isc_mem_free(keystore->mctx, keystore->pkcs11uri);
	}
	isc_mem_putanddetach(&keystore->mctx, keystore, sizeof(*keystore));
}

#ifdef DNS_KEYSTORE_TRACE
ISC_REFCOUNT_TRACE_IMPL(dns_keystore, dns__keystore_destroy);
#else
ISC_REFCOUNT_IMPL(dns_keystore, dns__keystore_destroy);
#endif

const char *
dns_keystore_name(dns_keystore_t *keystore) {
	REQUIRE(DNS_KEYSTORE_VALID(keystore));

	return keystore->name;
}

const char *
dns_keystore_directory(dns_keystore_t *keystore, const char *keydir) {
	if (keystore == NULL) {
		return keydir;
	}

	INSIST(DNS_KEYSTORE_VALID(keystore));

	if (keystore->directory == NULL) {
		return keydir;
	}

	return keystore->directory;
}

void
dns_keystore_setdirectory(dns_keystore_t *keystore, const char *dir) {
	REQUIRE(DNS_KEYSTORE_VALID(keystore));

	if (keystore->directory != NULL) {
		isc_mem_free(keystore->mctx, keystore->directory);
	}
	keystore->directory = (dir == NULL)
				      ? NULL
				      : isc_mem_strdup(keystore->mctx, dir);
}

const char *
dns_keystore_pkcs11uri(dns_keystore_t *keystore) {
	REQUIRE(DNS_KEYSTORE_VALID(keystore));

	return keystore->pkcs11uri;
}

void
dns_keystore_setpkcs11uri(dns_keystore_t *keystore, const char *uri) {
	REQUIRE(DNS_KEYSTORE_VALID(keystore));

	if (keystore->pkcs11uri != NULL) {
		isc_mem_free(keystore->mctx, keystore->pkcs11uri);
	}
	keystore->pkcs11uri = (uri == NULL)
				      ? NULL
				      : isc_mem_strdup(keystore->mctx, uri);
}

static isc_result_t
buildpkcs11label(const char *uri, const dns_name_t *zname, const char *policy,
		 int flags, isc_buffer_t *buf) {
	bool ksk = ((flags & DNS_KEYFLAG_KSK) != 0);
	char timebuf[18];
	isc_time_t now = isc_time_now();
	unsigned char digest[ISC_MAX_MD_SIZE];
	unsigned int digestlen = sizeof(digest);
	char hexbuf[ISC_MAX_MD_SIZE * 2 + 1];
	isc_buffer_t hexb;
	isc_region_t hexr;

	/* uri + object */
	if (isc_buffer_availablelength(buf) < strlen(uri) + strlen(";object="))
	{
		return ISC_R_NOSPACE;
	}
	isc_buffer_putstr(buf, uri);
	isc_buffer_putstr(buf, ";object=");

	/*
	 * Object identifier: SHA-1 of the zone wire name + policy.  A
	 * fixed-length digest avoids pkcs11-provider label-length limits.
	 */
	{
		isc_md_t *md = isc_md_new();
		isc_result_t r;

		r = isc_md_init(md, ISC_MD_SHA1);
		if (r == ISC_R_SUCCESS) {
			r = isc_md_update(md, zname->ndata, zname->length);
		}
		if (r == ISC_R_SUCCESS) {
			r = isc_md_update(md, (const unsigned char *)policy,
					  strlen(policy));
		}
		if (r == ISC_R_SUCCESS) {
			r = isc_md_final(md, digest, &digestlen);
		}
		isc_md_free(md);
		RETERR(r);
	}

	isc_buffer_init(&hexb, hexbuf, sizeof(hexbuf));
	hexr = (isc_region_t){ digest, digestlen };
	RETERR(isc_hex_totext(&hexr, 0, "", &hexb));

	if (isc_buffer_availablelength(buf) < isc_buffer_usedlength(&hexb)) {
		return ISC_R_NOSPACE;
	}
	isc_buffer_putmem(buf, isc_buffer_base(&hexb),
			  isc_buffer_usedlength(&hexb));

	/* key type + current time */
	isc_time_formatshorttimestamp(&now, timebuf, sizeof(timebuf));
	return isc_buffer_printf(buf, "-%s-%s", ksk ? "ksk" : "zsk", timebuf);
}

isc_result_t
dns_keystore_keygen(dns_keystore_t *keystore, const dns_name_t *origin,
		    const char *policy, dns_rdataclass_t rdclass,
		    isc_mem_t *mctx, uint32_t alg, int size, int flags,
		    dst_key_t **dstkey) {
	isc_result_t result;
	dst_key_t *newkey = NULL;
	const char *uri = NULL;

	REQUIRE(DNS_KEYSTORE_VALID(keystore));
	REQUIRE(dns_name_isvalid(origin));
	REQUIRE(policy != NULL);
	REQUIRE(mctx != NULL);
	REQUIRE(dstkey != NULL && *dstkey == NULL);

	uri = dns_keystore_pkcs11uri(keystore);
	if (uri != NULL) {
		/*
		 * Build the PKCS#11 object label.  At most one key per type
		 * exists for a zone in a policy at a given time, so the label
		 * (zone + policy + key type + time) is unique.
		 */
		char label[NAME_MAX];
		isc_buffer_t buf;
		isc_buffer_init(&buf, label, sizeof(label));
		result = buildpkcs11label(uri, origin, policy, flags, &buf);
		if (result != ISC_R_SUCCESS) {
			char namebuf[DNS_NAME_FORMATSIZE];
			dns_name_format(origin, namebuf, sizeof(namebuf));
			isc_log_write(
				DNS_LOGCATEGORY_DNSSEC, DNS_LOGMODULE_DNSSEC,
				ISC_LOG_ERROR,
				"keystore: failed to create PKCS#11 object "
				"for zone %s, policy %s: %s",
				namebuf, policy, isc_result_totext(result));
			return result;
		}

		/* Retry: concurrent token keygen can fail transiently. */
		for (unsigned int attempt = 0; attempt < 3; attempt++) {
			result = dst_key_generate(origin, alg, size, 0, flags,
						  DNS_KEYPROTO_DNSSEC, rdclass,
						  label, mctx, &newkey, NULL);
			if (result == ISC_R_SUCCESS) {
				break;
			}
		}

		if (result != ISC_R_SUCCESS) {
			isc_log_write(
				DNS_LOGCATEGORY_DNSSEC, DNS_LOGMODULE_DNSSEC,
				ISC_LOG_ERROR,
				"keystore: failed to generate PKCS#11 object "
				"%s: %s",
				label, isc_result_totext(result));
			return result;
		}
		isc_log_write(DNS_LOGCATEGORY_DNSSEC, DNS_LOGMODULE_DNSSEC,
			      ISC_LOG_DEBUG(3),
			      "keystore: generated PKCS#11 object %s", label);
	} else {
		result = dst_key_generate(origin, alg, size, 0, flags,
					  DNS_KEYPROTO_DNSSEC, rdclass, NULL,
					  mctx, &newkey, NULL);
	}

	if (result == ISC_R_SUCCESS) {
		*dstkey = newkey;
	}
	return result;
}

isc_result_t
dns_keystorelist_find(dns_keystorelist_t *list, const char *name,
		      dns_keystore_t **kspp) {
	REQUIRE(kspp != NULL && *kspp == NULL);

	if (list == NULL) {
		return ISC_R_NOTFOUND;
	}

	ISC_LIST_FOREACH(*list, keystore, link) {
		if (strcmp(keystore->name, name) == 0) {
			dns_keystore_attach(keystore, kspp);
			return ISC_R_SUCCESS;
		}
	}

	return ISC_R_NOTFOUND;
}
