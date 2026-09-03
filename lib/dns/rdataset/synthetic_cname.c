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

#include <stdint.h>
#include <string.h>

#include <isc/mem.h>
#include <isc/refcount.h>
#include <isc/result.h>
#include <isc/util.h>

#include <dns/name.h>
#include <dns/rdata.h>
#include <dns/rdataset.h>
#include <dns/types.h>

struct dns_synthetic_cname {
	isc_mem_t *mctx;
	isc_refcount_t references;
	uint16_t length;
	unsigned char target[];
};

ISC_REFCOUNT_STATIC_DECL(dns_synthetic_cname);

static void
synthetic_cname_destroy(dns_synthetic_cname_t *cname) {
	size_t size = STRUCT_FLEX_SIZE(cname, target, cname->length);

	isc_mem_putanddetach(&cname->mctx, cname, size);
}

ISC_REFCOUNT_STATIC_IMPL(dns_synthetic_cname, synthetic_cname_destroy);

static void
synthetic_cname_disassociate(dns_rdataset_t *rdataset DNS__DB_FLARG) {
	dns_synthetic_cname_unref(rdataset->synthetic_cname.data);
}

static isc_result_t
synthetic_cname_first(dns_rdataset_t *rdataset) {
	rdataset->synthetic_cname.iter = true;
	return ISC_R_SUCCESS;
}

static isc_result_t
synthetic_cname_next(dns_rdataset_t *rdataset) {
	rdataset->synthetic_cname.iter = false;
	return ISC_R_NOMORE;
}

static void
synthetic_cname_current(dns_rdataset_t *rdataset, dns_rdata_t *rdata) {
	dns_synthetic_cname_t *cname = rdataset->synthetic_cname.data;
	isc_region_t region = {
		.base = cname->target,
		.length = cname->length,
	};

	INSIST(rdataset->synthetic_cname.iter);
	dns_rdata_fromregion(rdata, rdataset->rdclass, dns_rdatatype_cname,
			     &region);
}

static void
synthetic_cname_clone(const dns_rdataset_t *source,
		      dns_rdataset_t *target DNS__DB_FLARG) {
	INSIST(!ISC_LINK_LINKED(target, link));
	*target = *source;
	ISC_LINK_INIT(target, link);
	target->synthetic_cname.data =
		dns_synthetic_cname_ref(source->synthetic_cname.data);
	target->synthetic_cname.iter = false;
}

static unsigned int
synthetic_cname_count(dns_rdataset_t *rdataset ISC_ATTR_UNUSED) {
	return 1;
}

static dns_rdatasetmethods_t synthetic_cname_methods = {
	.disassociate = synthetic_cname_disassociate,
	.first = synthetic_cname_first,
	.next = synthetic_cname_next,
	.current = synthetic_cname_current,
	.clone = synthetic_cname_clone,
	.count = synthetic_cname_count,
};

void
dns_rdataset_make_synthetic_cname(dns_rdataset_t *rdataset, isc_mem_t *mctx,
				  dns_rdataclass_t rdclass, dns_ttl_t ttl,
				  const dns_name_t *target) {
	dns_synthetic_cname_t *cname = NULL;
	isc_region_t region;
	size_t size;

	REQUIRE(DNS_RDATASET_VALID(rdataset));
	REQUIRE(rdataset->methods == NULL);
	REQUIRE(mctx != NULL);
	REQUIRE(dns_name_isabsolute(target));

	dns_name_toregion(target, &region);
	size = STRUCT_FLEX_SIZE(cname, target, region.length);
	cname = isc_mem_get(mctx, size);
	*cname = (dns_synthetic_cname_t){
		.mctx = isc_mem_ref(mctx),
		.references = ISC_REFCOUNT_INITIALIZER(1),
		.length = region.length,
	};
	memmove(cname->target, region.base, region.length);

	rdataset->methods = &synthetic_cname_methods;
	rdataset->rdclass = rdclass;
	rdataset->type = dns_rdatatype_cname;
	rdataset->covers = dns_rdatatype_none;
	rdataset->ttl = ttl;
	rdataset->synthetic_cname.data = cname;
	rdataset->synthetic_cname.iter = false;
}
