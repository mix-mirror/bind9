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

#include <isc/heap.h>
#include <isc/md.h>
#include <isc/mem.h>
#include <isc/result.h>
#include <isc/string.h>
#include <isc/util.h>

#include <dns/db.h>
#include <dns/dbiterator.h>
#include <dns/name.h>
#include <dns/rdataset.h>
#include <dns/rdatasetiter.h>
#include <dns/rdatastruct.h>
#include <dns/result.h>
#include <dns/zonemd.h>

#define CHECK(r)                             \
	do {                                 \
		result = (r);                \
		if (result != ISC_R_SUCCESS) \
			goto cleanup;        \
	} while (0)

static isc_result_t
digest_callback(void *arg, isc_region_t *data) {
#ifdef ISC_ZONEMD_DEBUG
	unsigned int j;
	for (j = 0; j < data->length; j++) {
		fprintf(stderr, "%02x", data->base[j]);
	}
#endif
	return isc_md_update(arg, data->base, data->length);
}

static isc_result_t
digest_rdataset(dns_name_t *name, dns_rdataset_t *rds, isc_mem_t *mctx,
		isc_md_t *md) {
	dns_fixedname_t fixed;
	isc_region_t r;
	char data[256 + 8];
	isc_buffer_t envbuf;
	isc_result_t result;
	dns_rdata_t *rdatas = NULL;
	unsigned int i, nrdatas;
#ifdef ISC_ZONEMD_DEBUG
	char namebuf[DNS_NAME_FORMATSIZE];
#endif

	dns_fixedname_init(&fixed);
	RUNTIME_CHECK(dns_name_downcase(name, dns_fixedname_name(&fixed)) ==
		      ISC_R_SUCCESS);
	dns_name_toregion(dns_fixedname_name(&fixed), &r);
#ifdef ISC_ZONEMD_DEBUG
	dns_name_format(dns_fixedname_name(&fixed), namebuf, sizeof(namebuf));
#endif

	/*
	 * Create an envelope for each rdata: <name|type|class|ttl>.
	 */
	isc_buffer_init(&envbuf, data, sizeof(data));
	memmove(data, r.base, r.length);
	isc_buffer_add(&envbuf, r.length);
	isc_buffer_putuint16(&envbuf, rds->type);
	isc_buffer_putuint16(&envbuf, rds->rdclass);
	isc_buffer_putuint32(&envbuf, rds->ttl);

	CHECK(dns_rdataset_tosortedarray(rds, mctx, &rdatas, &nrdatas));

	isc_buffer_usedregion(&envbuf, &r);

	for (i = 0; i < nrdatas; i++) {
		unsigned char len[2];

		/*
		 * Skip duplicates.
		 */
		if (i > 0 && dns_rdata_compare(&rdatas[i], &rdatas[i - 1]) == 0)
		{
			continue;
		}

		/*
		 * Digest the envelope.
		 */
		CHECK(isc_md_update(md, r.base, r.length));

		/*
		 * Digest the length of the rdata.
		 */
		len[0] = rdatas[i].length >> 8;
		len[1] = rdatas[i].length & 0xff;
		CHECK(isc_md_update(md, len, 2));

#ifdef ISC_ZONEMD_DEBUG
		isc_buffer_t b;
		char rdatabuf[65 * 1024];
		unsigned int j;
		isc_buffer_init(&b, rdatabuf, sizeof(rdatabuf));
		dns_rdata_totext(&rdatas[i], NULL, &b);
		fprintf(stderr,
			"digest %s type=%u class=%u ttl=%u rdlen=%u %.*s\n",
			namebuf, rds->type, rds->rdclass, rds->ttl,
			rdatas[i].length, (int)isc_buffer_usedlength(&b),
			rdatabuf);
		fprintf(stderr, "DIGEST:");
		for (j = 0; j < r.length; j++) {
			fprintf(stderr, "%02x", r.base[j]);
		}
		fprintf(stderr, "%02x%02x", len[0], len[1]);
#endif
		/*
		 * Digest the rdata.
		 */
		CHECK(dns_rdata_digest(&rdatas[i], digest_callback, md));
#ifdef ISC_ZONEMD_DEBUG
		fprintf(stderr, "\n");
#endif
	}

cleanup:
	if (rdatas != NULL) {
		isc_mem_cput(mctx, rdatas, nrdatas, sizeof(*rdatas));
	}

	return result;
}

static isc_result_t
get_serial(dns_rdataset_t *rds, unsigned char *buf) {
	dns_rdata_t rdata = DNS_RDATA_INIT;
	dns_rdata_soa_t soa;
	isc_result_t result;

	CHECK(dns_rdataset_first(rds));
	dns_rdataset_current(rds, &rdata);
	CHECK(dns_rdata_tostruct(&rdata, &soa, NULL));
	buf[0] = (soa.serial >> 24) & 0xff;
	buf[1] = (soa.serial >> 16) & 0xff;
	buf[2] = (soa.serial >> 8) & 0xff;
	buf[3] = (soa.serial >> 0) & 0xff;
cleanup:
	return result;
}

static bool
bytype(void *a, void *b) {
	dns_rdataset_t *ra = (dns_rdataset_t *)a, *rb = (dns_rdataset_t *)b;

	if (ra->type < rb->type) {
		return true;
	}
	if (ra->type != dns_rdatatype_rrsig) {
		return false;
	}
	if (ra->covers < rb->covers) {
		return true;
	}
	return false;
}

static isc_result_t
add_rdatasets(dns_db_t *db, dns_dbversion_t *version, dns_dbnode_t *node,
	      isc_mem_t *mctx, isc_heap_t *heap) {
	dns_rdatasetiter_t *iter = NULL;
	isc_result_t result;

	CHECK(dns_db_allrdatasets(db, node, version, 0, 0, &iter));
	DNS_RDATASETITER_FOREACH(iter) {
		dns_rdataset_t *rdataset = isc_mem_get(mctx, sizeof(*rdataset));
		dns_rdataset_init(rdataset);
		dns_rdatasetiter_current(iter, rdataset);
		isc_heap_insert(heap, rdataset);
	}

cleanup:
	if (iter != NULL) {
		dns_rdatasetiter_destroy(&iter);
	}
	return result;
}

static isc_result_t
process_name(dns_db_t *db, dns_dbversion_t *version, dns_name_t *name,
	     dns_dbnode_t *nsecnode, dns_dbnode_t *nsec3node, isc_heap_t *heap,
	     isc_mem_t *mctx, unsigned char *buf, isc_md_t *md,
	     bool *seen_soa) {
	dns_rdataset_t *rdataset = NULL;
	isc_result_t result = ISC_R_SUCCESS;

	char namebuf[DNS_NAME_FORMATSIZE];
	dns_name_format(name, namebuf, sizeof(namebuf));

	if (!dns_name_issubdomain(name, dns_db_origin(db))) {
#ifdef ISC_ZONEMD_DEBUG
		fprintf(stderr, "skipping %s out-of-zone\n", namebuf);
#endif
		return ISC_R_SUCCESS;
	}

	if (nsecnode != NULL) {
		CHECK(add_rdatasets(db, version, nsecnode, mctx, heap));
	}
	if (nsec3node != NULL) {
		CHECK(add_rdatasets(db, version, nsec3node, mctx, heap));
	}

	while ((rdataset = isc_heap_element(heap, 1)) != NULL) {
#ifdef ISC_ZONEMD_DEBUG
		fprintf(stderr, "looking at %s %u/%u\n", namebuf,
			rdataset->type, rdataset->covers);
#endif
		/*
		 * Don't digest ZONEMD or RRSIG(ZONEMD).
		 */
		if ((rdataset->type == dns_rdatatype_zonemd ||
		     (rdataset->type == dns_rdatatype_rrsig &&
		      rdataset->covers == dns_rdatatype_zonemd)) &&
		    dns_name_equal(name, dns_db_origin(db)))
		{
			goto skip;
		}
		if (rdataset->type == dns_rdatatype_soa &&
		    dns_name_equal(name, dns_db_origin(db)))
		{
			CHECK(get_serial(rdataset, buf));
			*seen_soa = true;
		}

		CHECK(digest_rdataset(name, rdataset, mctx, md));
	skip:
		isc_heap_delete(heap, 1);
		dns_rdataset_disassociate(rdataset);
		isc_mem_put(mctx, rdataset, sizeof(*rdataset));
	}
cleanup:
	while ((rdataset = isc_heap_element(heap, 1)) != NULL) {
		isc_heap_delete(heap, 1);
		dns_rdataset_disassociate(rdataset);
		isc_mem_put(mctx, rdataset, sizeof(*rdataset));
	}
	return result;
}

static isc_result_t
zonemd_simple(dns_rdata_t *rdata, dns_db_t *db, dns_dbversion_t *version,
	      uint8_t algorithm, isc_mem_t *mctx, unsigned char *buf,
	      size_t size) {
	bool seen_soa = false;
	dns_dbiterator_t *nsecdbiter = NULL;
	dns_dbiterator_t *nsec3dbiter = NULL;
	dns_dbnode_t *nsecnode = NULL;
	dns_dbnode_t *nsec3node = NULL;
	dns_fixedname_t nsecfixed;
	dns_fixedname_t nsec3fixed;
	dns_name_t *nsecname;
	dns_name_t *nsec3name;
	isc_md_t *md = isc_md_new();
	isc_heap_t *heap = NULL;
	isc_result_t result, nsecresult, nsec3result;
	isc_region_t r;

	if (md == NULL) {
		CHECK(ISC_R_NOMEMORY);
	}
	switch (algorithm) {
	case DNS_ZONEMD_DIGEST_SHA384:
		if (size < ISC_SHA384_DIGESTLENGTH + 6) {
			CHECK(ISC_R_NOSPACE);
		}
		r.base = buf;
		r.length = ISC_SHA384_DIGESTLENGTH + 6;
		CHECK(isc_md_init(md, ISC_MD_SHA384));
		break;
	case DNS_ZONEMD_DIGEST_SHA512:
		if (size < ISC_SHA512_DIGESTLENGTH + 6) {
			CHECK(ISC_R_NOSPACE);
		}
		r.base = buf;
		r.length = ISC_SHA512_DIGESTLENGTH + 6;
		CHECK(isc_md_init(md, ISC_MD_SHA512));
		break;
	default:
		CHECK(ISC_R_NOTIMPLEMENTED);
	}
	dns_fixedname_init(&nsecfixed);
	dns_fixedname_init(&nsec3fixed);
	isc_heap_create(mctx, bytype, NULL, 0, &heap);
	CHECK(dns_db_createiterator(db, DNS_DB_NONSEC3, &nsecdbiter));
	CHECK(dns_db_createiterator(db, DNS_DB_NSEC3ONLY, &nsec3dbiter));
	nsecresult = dns_dbiterator_first(nsecdbiter);
	nsec3result = dns_dbiterator_first(nsec3dbiter);
	while (nsecresult == ISC_R_SUCCESS || nsec3result == ISC_R_SUCCESS) {
		if (nsecresult == ISC_R_SUCCESS) {
			nsecname = dns_fixedname_name(&nsecfixed);
			CHECK(dns_dbiterator_current(nsecdbiter, &nsecnode,
						     nsecname));
			dns_dbiterator_pause(nsecdbiter);
		} else {
			nsecname = NULL;
		}
		if (nsec3result == ISC_R_SUCCESS) {
			nsec3name = dns_fixedname_name(&nsec3fixed);
			CHECK(dns_dbiterator_current(nsec3dbiter, &nsec3node,
						     nsec3name));
			dns_dbiterator_pause(nsec3dbiter);
		} else {
			nsec3name = NULL;
		}
		/*
		 * Workout which name / node to process next.
		 */
		if (nsecname != NULL && nsec3name != NULL) {
			int n = dns_name_compare(nsecname, nsec3name);
			if (n < 0) {
				nsec3name = NULL;
				if (nsec3node != NULL) {
					dns_db_detachnode(&nsec3node);
				}
			}
			if (n > 0) {
				nsecname = NULL;
				if (nsecnode != NULL) {
					dns_db_detachnode(&nsecnode);
				}
			}
		}
		CHECK(process_name(
			db, version, nsecname != NULL ? nsecname : nsec3name,
			nsecnode, nsec3node, heap, mctx, buf, md, &seen_soa));
		if (nsecnode != NULL) {
			dns_db_detachnode(&nsecnode);
		}
		if (nsec3node != NULL) {
			dns_db_detachnode(&nsec3node);
		}
		if (nsecname != NULL) {
			nsecresult = dns_dbiterator_next(nsecdbiter);
		}
		if (nsec3name != NULL) {
			nsec3result = dns_dbiterator_next(nsec3dbiter);
		}
	}
	if (nsecresult == ISC_R_NOMORE && nsec3result == ISC_R_NOMORE) {
		unsigned int len = size - 6;
		buf[4] = 1;
		buf[5] = algorithm;
		CHECK(isc_md_final(md, buf + 6, &len));
		if (!seen_soa) {
			CHECK(DNS_R_BADZONE);
		}
		if (len + 6 != r.length) {
			CHECK(ISC_R_FAILURE);
		}
		if (rdata != NULL) {
			dns_rdata_fromregion(rdata, dns_db_class(db),
					     dns_rdatatype_zonemd, &r);
		}
	} else {
		result = nsecresult != ISC_R_NOMORE ? nsecresult : nsec3result;
	}

cleanup:
	if (md != NULL) {
		isc_md_free(md);
	}
	if (heap != NULL) {
		isc_heap_destroy(&heap);
	}
	if (nsecnode != NULL) {
		dns_db_detachnode(&nsecnode);
	}
	if (nsec3node != NULL) {
		dns_db_detachnode(&nsec3node);
	}
	if (nsecdbiter != NULL) {
		dns_dbiterator_destroy(&nsecdbiter);
	}
	if (nsec3dbiter != NULL) {
		dns_dbiterator_destroy(&nsec3dbiter);
	}
	return result;
}

isc_result_t
dns_zonemd_buildrdata(dns_rdata_t *rdata, dns_db_t *db,
		      dns_dbversion_t *version, uint8_t scheme,
		      uint8_t algorithm, isc_mem_t *mctx, unsigned char *buf,
		      size_t size) {
	REQUIRE(db != NULL);
	REQUIRE(buf != NULL);

	/*
	 * Check for supported scheme/algorithm combinations.
	 */
	switch (scheme) {
	case DNS_ZONEMD_SCHEME_SIMPLE:
		switch (algorithm) {
		case DNS_ZONEMD_DIGEST_SHA384:
		case DNS_ZONEMD_DIGEST_SHA512:
			return zonemd_simple(rdata, db, version, algorithm,
					     mctx, buf, size);
		default:
			return ISC_R_NOTIMPLEMENTED;
		}
	default:
		return ISC_R_NOTIMPLEMENTED;
	}
}

bool
dns_zonemd_supported(dns_rdata_t *rdata) {
	REQUIRE(rdata != NULL);
	REQUIRE(rdata->length >= 6);
	REQUIRE(rdata->type == dns_rdatatype_zonemd);

	switch (rdata->data[4]) {
	case DNS_ZONEMD_SCHEME_SIMPLE:
		switch (rdata->data[5]) {
		case DNS_ZONEMD_DIGEST_SHA384:
		case DNS_ZONEMD_DIGEST_SHA512:
			return true;
		default:
			return false;
		}
	default:
		return false;
	}
}
