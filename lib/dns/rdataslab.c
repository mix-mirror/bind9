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

#include <stdbool.h>
#include <stdlib.h>

#include <isc/ascii.h>
#include <isc/atomic.h>
#include <isc/list.h>
#include <isc/mem.h>
#include <isc/region.h>
#include <isc/result.h>
#include <isc/string.h>
#include <isc/urcu.h>
#include <isc/util.h>

#include <dns/db.h>
#include <dns/rdata.h>
#include <dns/rdataset.h>
#include <dns/rdataslab.h>
#include <dns/stats.h>

#include "rdataslab_p.h"

/*
 * The memory structure of an rdataslab is as follows:
 *
 *	header		(dns_slabheader_t)
 *	record count	(2 bytes)
 *	data records
 *		data length	(2 bytes)
 *		order		(2 bytes)
 *		meta data	(1 byte for RRSIG, 0 for all other types)
 *		data		(data length bytes)
 *
 * A "bare" rdataslab is everything after "header".
 *
 * When a slab is created, data records are sorted into DNSSEC order.
 */

static void
rdataset_disassociate(dns_rdataset_t *rdataset DNS__DB_FLARG);
static isc_result_t
rdataset_first(dns_rdataset_t *rdataset);
static isc_result_t
rdataset_next(dns_rdataset_t *rdataset);
static void
rdataset_current(dns_rdataset_t *rdataset, dns_rdata_t *rdata);
static void
rdataset_clone(const dns_rdataset_t *source,
	       dns_rdataset_t *target DNS__DB_FLARG);
static unsigned int
rdataset_count(dns_rdataset_t *rdataset);
static isc_result_t
rdataset_getnoqname(dns_rdataset_t *rdataset, dns_name_t *name,
		    dns_rdataset_t *neg, dns_rdataset_t *negsig DNS__DB_FLARG);
static void
rdataset_settrust(dns_rdataset_t *rdataset, dns_trust_t trust);
static void
rdataset_expire(dns_rdataset_t *rdataset DNS__DB_FLARG);
static void
rdataset_clearprefetch(dns_rdataset_t *rdataset);
static dns_slabheader_t *
rdataset_getheader(const dns_rdataset_t *rdataset);

dns_rdatasetmethods_t dns_rdataslab_rdatasetmethods = {
	.disassociate = rdataset_disassociate,
	.first = rdataset_first,
	.next = rdataset_next,
	.current = rdataset_current,
	.clone = rdataset_clone,
	.count = rdataset_count,
	.getnoqname = rdataset_getnoqname,
	.settrust = rdataset_settrust,
	.expire = rdataset_expire,
	.clearprefetch = rdataset_clearprefetch,
};

static void
slabheader_proof_disassociate(dns_rdataset_t *rdataset DNS__DB_FLARG);
static isc_result_t
slabheader_proof_first(dns_rdataset_t *rdataset);
static isc_result_t
slabheader_proof_next(dns_rdataset_t *rdataset);
static void
slabheader_proof_current(dns_rdataset_t *rdataset, dns_rdata_t *rdata);
static void
slabheader_proof_clone(const dns_rdataset_t *source,
		       dns_rdataset_t *target DNS__DB_FLARG);
static unsigned int
slabheader_proof_count(dns_rdataset_t *rdataset);
static dns_slabheader_t *
slabheader_proof_getheader(const dns_rdataset_t *rdataset);

dns_rdatasetmethods_t dns_rdataslab_proof_rdatasetmethods = {
	.disassociate = slabheader_proof_disassociate,
	.first = slabheader_proof_first,
	.next = slabheader_proof_next,
	.current = slabheader_proof_current,
	.clone = slabheader_proof_clone,
	.count = slabheader_proof_count,
	.getnoqname = NULL,
	.settrust = NULL,
	.expire = NULL,
	.clearprefetch = NULL,
	.getownercase = NULL,
};

static unsigned char *
newslab(dns_rdataset_t *rdataset, isc_mem_t *mctx, isc_region_t *region,
	uint16_t nitems, size_t size, const char *func, const char *file,
	const unsigned int line) {
	dns_slabheader_t *header = isc_mem_get(mctx, size);

	*header = (dns_slabheader_t){
		.headers_link = CDS_LIST_HEAD_INIT(header->headers_link),
		.trust = rdataset->trust,
		.nitems = nitems,
		.references = ISC_REFCOUNT_INITIALIZER(1),
		.mctx = isc_mem_ref(mctx),
		.lrulink = ISC_LINK_INITIALIZER,
	};

#if DNS_SLABHEADER_TRACE
	fprintf(stderr,
		"%s:%s:%s:%u:t%" PRItid ":%p->references = %" PRIuFAST32 "\n",
		__func__, func, file, line, isc_tid(), header,
		header->references);
#else
	UNUSED(func);
	UNUSED(file);
	UNUSED(line);
#endif

	region->base = (unsigned char *)header;
	region->length = size;

	return (unsigned char *)header + sizeof(*header);
}

static isc_result_t
makeslab(dns_rdataset_t *rdataset, isc_mem_t *mctx, isc_region_t *region,
	 uint32_t maxrrperset, const char *func, const char *file,
	 const unsigned int line) {
	REQUIRE(rdataset->methods != &dns_rdataslab_rdatasetmethods);

	unsigned int headerlen = sizeof(dns_slabheader_t);
	uint32_t buflen = headerlen;
	isc_result_t result;
	unsigned int nitems = dns_rdataset_count(rdataset);

	/*
	 * If there are no rdata then we just need to allocate a header
	 * with a zero record count.  Only a negative cache entry (e.g.
	 * an uncacheable NODATA proof) may be empty.
	 */
	if (nitems == 0) {
		if (!rdataset->attributes.negative) {
			return ISC_R_FAILURE;
		}
		(void)newslab(rdataset, mctx, region, 0, buflen, func, file,
			      line);
		return ISC_R_SUCCESS;
	}

	if (maxrrperset > 0 && nitems > maxrrperset) {
		return DNS_R_TOOMANYRECORDS;
	}

	if (nitems > 0xffff) {
		return ISC_R_NOSPACE;
	}

	/*
	 * Ensure that singleton types are actually singletons.  The check
	 * doesn't apply to a negative cache entry: it stores ncache-encoded
	 * records rather than RRs of 'rdataset->type'.
	 */
	if (nitems > 1 && !rdataset->attributes.negative &&
	    dns_rdatatype_issingleton(rdataset->type))
	{
		/*
		 * We have a singleton type, but there's more than one
		 * RR in the rdataset.
		 */
		return DNS_R_SINGLETON;
	}

	unsigned char *rawbuf = newslab(rdataset, mctx, region, nitems,
					headerlen + DNS_RDATA_MAXLENGTH, func,
					file, line);

	size_t i = 0;
	size_t remaining = region->length - headerlen;
	DNS_RDATASET_FOREACH(rdataset) {
		dns_rdata_t rdata = DNS_RDATA_INIT;
		i++;

		dns_rdataset_current(rdataset, &rdata);

		size_t length = rdata.length;
		if (rdataset->type == dns_rdatatype_rrsig) {
			length++;
		}
		INSIST(length <= 0xffff);

		if (length + sizeof(uint16_t) > remaining) {
			result = ISC_R_NOSPACE;
			goto free_rdatas;
		}

		put_uint16(rawbuf, length);

		if (rdataset->type == dns_rdatatype_rrsig) {
			*rawbuf++ = (rdata.flags & DNS_RDATA_OFFLINE)
					    ? DNS_RDATASLAB_OFFLINE
					    : 0;
		}

		if (rdata.length != 0) {
			memmove(rawbuf, rdata.data, rdata.length);
			rawbuf += rdata.length;
		}
		buflen += length + sizeof(uint16_t);
		remaining -= length + sizeof(uint16_t);
	}
	INSIST(i == nitems);
	region->base = isc_mem_reget(mctx, region->base, region->length,
				     buflen);
	region->length = buflen;

	return ISC_R_SUCCESS;

free_rdatas:
	if (region->length != 0) {
		dns_slabheader_t *header = (dns_slabheader_t *)region->base;
		isc_mem_putanddetach(&header->mctx, header,
				     headerlen + DNS_RDATA_MAXLENGTH);
	}
	return result;
}

isc_result_t
dns_rdataslab__fromrdataset(dns_rdataset_t *rdataset, isc_mem_t *mctx,
			    isc_region_t *region, uint32_t maxrrperset,
			    const char *func, const char *file,
			    const unsigned int line) {
	if (rdataset->type == dns_rdatatype_none &&
	    rdataset->covers == dns_rdatatype_none)
	{
		return DNS_R_DISALLOWED;
	}

	isc_result_t result = makeslab(rdataset, mctx, region, maxrrperset,
				       func, file, line);
	if (result != ISC_R_SUCCESS) {
		return result;
	}

	dns_slabheader_t *header = (dns_slabheader_t *)region->base;
	INSIST(rdataset->type != dns_rdatatype_none);
	INSIST(dns_rdatatype_issig(rdataset->type) ||
	       rdataset->covers == dns_rdatatype_none);
	header->typepair = DNS_TYPEPAIR_VALUE(rdataset->type, rdataset->covers);

	return ISC_R_SUCCESS;
}

unsigned int
dns_rdataslab_size(dns_slabheader_t *header) {
	REQUIRE(header != NULL);

	unsigned char *slab = (unsigned char *)header +
			      sizeof(dns_slabheader_t);
	INSIST(slab != NULL);

	unsigned char *current = slab;
	uint16_t count = header->nitems;

	while (count-- > 0) {
		uint16_t length = get_uint16(current);
		current += length;
	}

	return (unsigned int)(current - slab) + sizeof(dns_slabheader_t);
}

unsigned int
dns_rdataslab_count(dns_slabheader_t *header) {
	REQUIRE(header != NULL);

	return header->nitems;
}

/*
 * Make the dns_rdata_t 'rdata' refer to the slab item
 * beginning at '*current' (which is part of a slab of type
 * 'type' and class 'rdclass') and advance '*current' to
 * point to the next item in the slab.
 */
static void
rdata_from_slabitem(unsigned char **current, dns_rdataclass_t rdclass,
		    dns_rdatatype_t type, dns_rdata_t *rdata) {
	unsigned char *tcurrent = *current;
	isc_region_t region;
	bool offline = false;
	uint16_t length = get_uint16(tcurrent);

	if (type == dns_rdatatype_rrsig) {
		if ((*tcurrent & DNS_RDATASLAB_OFFLINE) != 0) {
			offline = true;
		}
		length--;
		tcurrent++;
	}
	region.length = length;
	region.base = tcurrent;
	tcurrent += region.length;
	dns_rdata_fromregion(rdata, rdclass, type, &region);
	if (offline) {
		rdata->flags |= DNS_RDATA_OFFLINE;
	}
	*current = tcurrent;
}

bool
dns_rdataslab_equal(dns_slabheader_t *slab1, dns_slabheader_t *slab2) {
	unsigned char *current1 = NULL, *current2 = NULL;
	unsigned int count1, count2;

	current1 = (unsigned char *)slab1 + sizeof(dns_slabheader_t);
	count1 = slab1->nitems;

	current2 = (unsigned char *)slab2 + sizeof(dns_slabheader_t);
	count2 = slab2->nitems;

	if (count1 != count2) {
		return false;
	} else if (count1 == 0) {
		return true;
	}

	while (count1-- > 0) {
		unsigned int length1 = get_uint16(current1);
		unsigned int length2 = get_uint16(current2);

		if (length1 != length2 ||
		    memcmp(current1, current2, length1) != 0)
		{
			return false;
		}

		current1 += length1;
		current2 += length1;
	}
	return true;
}

bool
dns_rdataslab_equalx(dns_slabheader_t *slab1, dns_slabheader_t *slab2,
		     dns_rdataclass_t rdclass, dns_rdatatype_t type) {
	unsigned char *current1 = NULL, *current2 = NULL;
	unsigned int count1, count2;

	current1 = (unsigned char *)slab1 + sizeof(dns_slabheader_t);
	count1 = slab1->nitems;

	current2 = (unsigned char *)slab2 + sizeof(dns_slabheader_t);
	count2 = slab2->nitems;

	if (count1 != count2) {
		return false;
	} else if (count1 == 0) {
		return true;
	}

	while (count1-- > 0) {
		dns_rdata_t rdata1 = DNS_RDATA_INIT;
		dns_rdata_t rdata2 = DNS_RDATA_INIT;

		rdata_from_slabitem(&current1, rdclass, type, &rdata1);
		rdata_from_slabitem(&current2, rdclass, type, &rdata2);
		if (dns_rdata_compare(&rdata1, &rdata2) != 0) {
			return false;
		}
	}
	return true;
}

void
dns_slabheader__reset(dns_slabheader_t *h, dns_dbnode_t *node, const char *func,
		      const char *file, const unsigned int line) {
	h->node = node;

	atomic_init(&h->attributes, 0);
	atomic_init(&h->last_refresh_fail_ts, 0);
	isc_refcount_init(&h->references, 1);

	STATIC_ASSERT(sizeof(h->attributes) == 2,
		      "The .attributes field of dns_slabheader_t needs to be "
		      "16-bit int type exactly.");

#if DNS_SLABHEADER_TRACE
	fprintf(stderr,
		"%s:%s:%s:%u:t%" PRItid ":%p->references = %" PRIuFAST32 "\n",
		__func__, func, file, line, isc_tid(), h, h->references);
#else
	UNUSED(func);
	UNUSED(file);
	UNUSED(line);
#endif
}

static void
slabheader_destroy(dns_slabheader_t *header) {
	unsigned int size = dns_rdataslab_size(header);

	if (header->noqname != NULL) {
		dns_slabheader_freeproof(header->mctx, &header->noqname);
	}

	isc_mem_putanddetach(&header->mctx, header, size);
}

void
dns_slabheader_freeproof(isc_mem_t *mctx, dns_slabheader_proof_t **proofp) {
	dns_slabheader_proof_t *proof = *proofp;
	*proofp = NULL;

	if (dns_name_dynamic(&proof->name)) {
		dns_name_free(&proof->name, mctx);
	}
	if (proof->neg != NULL) {
		dns_slabheader_t *header =
			(dns_slabheader_t *)((uint8_t *)proof->neg -
					     sizeof(dns_slabheader_t));
		dns_slabheader_detach(&header);
	}
	if (proof->negsig != NULL) {
		dns_slabheader_t *header =
			(dns_slabheader_t *)((uint8_t *)proof->negsig -
					     sizeof(dns_slabheader_t));
		dns_slabheader_detach(&header);
	}
	isc_mem_put(mctx, proof, sizeof(*proof));
}

#if DNS_SLABHEADER_TRACE
ISC_REFCOUNT_TRACE_IMPL(dns_slabheader, slabheader_destroy);
#else
ISC_REFCOUNT_IMPL(dns_slabheader, slabheader_destroy);
#endif

/* Fixed RRSet helper macros */

static void
rdataset_disassociate(dns_rdataset_t *rdataset DNS__DB_FLARG) {
	dns_slabheader_t *header = rdataset_getheader(rdataset);

	dns_slabheader_detach(&header);

	dns__db_detachnode(&rdataset->slab.node DNS__DB_FLARG_PASS);
}

static isc_result_t
rdataset_first(dns_rdataset_t *rdataset) {
	dns_slabheader_t *header = rdataset_getheader(rdataset);
	unsigned char *raw = rdataset->slab.raw;
	uint16_t count = header->nitems;

	if (count == 0) {
		rdataset->slab.iter_pos = NULL;
		rdataset->slab.iter_count = 0;
		return ISC_R_NOMORE;
	}

	/*
	 * iter_count is the number of rdata beyond the cursor
	 * position, so we decrement the total count by one before
	 * storing it.
	 *
	 * 'raw' points to the first record.
	 */
	rdataset->slab.iter_pos = raw;
	rdataset->slab.iter_count = count - 1;

	return ISC_R_SUCCESS;
}

static isc_result_t
rdataset_next(dns_rdataset_t *rdataset) {
	uint16_t count = rdataset->slab.iter_count;
	if (count == 0) {
		rdataset->slab.iter_pos = NULL;
		return ISC_R_NOMORE;
	}
	rdataset->slab.iter_count = count - 1;

	/*
	 * Skip forward one record (length + 4) or one offset (4).
	 */
	unsigned char *raw = rdataset->slab.iter_pos;
	uint16_t length = peek_uint16(raw);
	raw += length;
	rdataset->slab.iter_pos = raw + sizeof(uint16_t);

	return ISC_R_SUCCESS;
}

static void
rdataset_current(dns_rdataset_t *rdataset, dns_rdata_t *rdata) {
	unsigned char *raw = NULL;
	unsigned int length;
	isc_region_t r;
	unsigned int flags = 0;

	raw = rdataset->slab.iter_pos;
	REQUIRE(raw != NULL);

	/*
	 * Find the start of the record if not already in iter_pos
	 * then skip the length and order fields.
	 */
	length = get_uint16(raw);

	if (rdataset->type == dns_rdatatype_rrsig) {
		if (*raw & DNS_RDATASLAB_OFFLINE) {
			flags |= DNS_RDATA_OFFLINE;
		}
		length--;
		raw++;
	}
	r.length = length;
	r.base = raw;
	dns_rdata_fromregion(rdata, rdataset->rdclass, rdataset->type, &r);
	rdata->flags |= flags;
}

static void
rdataset_clone(const dns_rdataset_t *source,
	       dns_rdataset_t *target DNS__DB_FLARG) {
	dns_slabheader_t *header = rdataset_getheader(source);

	INSIST(target->slab.node == NULL);
	INSIST(!ISC_LINK_LINKED(target, link));
	*target = *source;
	ISC_LINK_INIT(target, link);
	target->slab.node = NULL;
	dns__db_attachnode(source->slab.node,
			   &target->slab.node DNS__DB_FLARG_PASS);

	target->slab.iter_pos = NULL;
	target->slab.iter_count = 0;

	dns_slabheader_ref(header);
}

static unsigned int
rdataset_count(dns_rdataset_t *rdataset) {
	dns_slabheader_t *header = rdataset_getheader(rdataset);

	return header->nitems;
}

static isc_result_t
rdataset_getnoqname(dns_rdataset_t *rdataset, dns_name_t *name,
		    dns_rdataset_t *nsec,
		    dns_rdataset_t *nsecsig DNS__DB_FLARG) {
	dns_dbnode_t *node = rdataset->slab.node;
	dns_slabheader_t *header = rdataset_getheader(rdataset);
	const dns_slabheader_proof_t *noqname = rdataset->slab.noqname;

	/*
	 * Normally, rdataset->slab.raw points to the data immediately
	 * following a dns_slabheader in memory. Here, though, it will
	 * point to a bare rdataslab, a pointer to which is stored in
	 * the dns_slabheader's `noqname` field.
	 *
	 * The 'keepcase' attribute is set to prevent setownercase and
	 * getownercase methods from affecting the case of NSEC/NSEC3
	 * owner names.
	 */
	*nsec = (dns_rdataset_t){
		.methods = &dns_rdataslab_proof_rdatasetmethods,
		.rdclass = rdataset->rdclass,
		.type = noqname->type,
		.ttl = rdataset->ttl,
		.trust = rdataset->trust,
		.proof.header = dns_slabheader_ref(header),
		.proof.raw = noqname->neg,
		.link = nsec->link,
		.attributes = nsec->attributes,
		.magic = nsec->magic,
	};
	nsec->attributes.keepcase = true;
	dns__db_attachnode(node, &nsec->proof.node DNS__DB_FLARG_PASS);

	*nsecsig = (dns_rdataset_t){
		.methods = &dns_rdataslab_proof_rdatasetmethods,
		.rdclass = rdataset->rdclass,
		.type = dns_rdatatype_rrsig,
		.covers = noqname->type,
		.ttl = rdataset->ttl,
		.trust = rdataset->trust,
		.proof.header = dns_slabheader_ref(header),
		.proof.raw = noqname->negsig,
		.link = nsecsig->link,
		.attributes = nsecsig->attributes,
		.magic = nsecsig->magic,
	};
	nsecsig->attributes.keepcase = true;
	dns__db_attachnode(node, &nsecsig->proof.node DNS__DB_FLARG_PASS);

	dns_name_clone(&noqname->name, name);

	return ISC_R_SUCCESS;
}

static void
rdataset_settrust(dns_rdataset_t *rdataset, dns_trust_t trust) {
	dns_slabheader_t *header = rdataset_getheader(rdataset);

	rdataset->trust = trust;
	atomic_store_release(&header->trust, trust);
}

static void
rdataset_expire(dns_rdataset_t *rdataset DNS__DB_FLARG) {
	dns_slabheader_t *header = rdataset_getheader(rdataset);

	dns_db_expiredata(rdataset->slab.node, header);
}

static void
rdataset_clearprefetch(dns_rdataset_t *rdataset) {
	dns_slabheader_t *header = rdataset_getheader(rdataset);

	DNS_SLABHEADER_CLRATTR(header, DNS_SLABHEADERATTR_PREFETCH);
}

static dns_slabheader_t *
rdataset_getheader(const dns_rdataset_t *rdataset) {
	uint8_t *rawbuf = rdataset->slab.raw;
	return (dns_slabheader_t *)(rawbuf - offsetof(dns_slabheader_t, raw));
}

/* Fixed Proof helper macros */

static void
slabheader_proof_disassociate(dns_rdataset_t *rdataset DNS__DB_FLARG) {
	dns_slabheader_detach(&rdataset->proof.header);
	dns__db_detachnode(&rdataset->proof.node DNS__DB_FLARG_PASS);
}

static isc_result_t
slabheader_proof_first(dns_rdataset_t *rdataset) {
	unsigned char *raw = rdataset->proof.raw;
	uint16_t count = slabheader_proof_count(rdataset);

	if (count == 0) {
		rdataset->proof.iter_pos = NULL;
		rdataset->proof.iter_count = 0;
		return ISC_R_NOMORE;
	}

	/*
	 * iter_count is the number of rdata beyond the cursor
	 * position, so we decrement the total count by one before
	 * storing it.
	 *
	 * 'raw' points to the first record.
	 */
	rdataset->proof.iter_pos = raw;
	rdataset->proof.iter_count = count - 1;

	return ISC_R_SUCCESS;
}

static isc_result_t
slabheader_proof_next(dns_rdataset_t *rdataset) {
	uint16_t count = rdataset->proof.iter_count;
	if (count == 0) {
		rdataset->proof.iter_pos = NULL;
		return ISC_R_NOMORE;
	}
	rdataset->proof.iter_count = count - 1;

	/*
	 * Skip forward one record (length + 4) or one offset (4).
	 */
	unsigned char *raw = rdataset->proof.iter_pos;
	uint16_t length = peek_uint16(raw);
	raw += length;
	rdataset->proof.iter_pos = raw + sizeof(uint16_t);

	return ISC_R_SUCCESS;
}

static void
slabheader_proof_current(dns_rdataset_t *rdataset, dns_rdata_t *rdata) {
	unsigned char *raw = NULL;
	unsigned int length;
	isc_region_t r;
	unsigned int flags = 0;

	raw = rdataset->proof.iter_pos;
	REQUIRE(raw != NULL);

	/*
	 * Find the start of the record if not already in iter_pos
	 * then skip the length and order fields.
	 */
	length = get_uint16(raw);

	if (rdataset->type == dns_rdatatype_rrsig) {
		if (*raw & DNS_RDATASLAB_OFFLINE) {
			flags |= DNS_RDATA_OFFLINE;
		}
		length--;
		raw++;
	}
	r.length = length;
	r.base = raw;
	dns_rdata_fromregion(rdata, rdataset->rdclass, rdataset->type, &r);
	rdata->flags |= flags;
}

static void
slabheader_proof_clone(const dns_rdataset_t *source,
		       dns_rdataset_t *target DNS__DB_FLARG) {
	INSIST(!ISC_LINK_LINKED(target, link));
	INSIST(target->proof.node == NULL);
	INSIST(target->proof.header == NULL);

	*target = *source;

	ISC_LINK_INIT(target, link);
	target->proof.node = NULL;
	dns__db_attachnode(source->proof.node,
			   &target->proof.node DNS__DB_FLARG_PASS);
	dns_slabheader_ref(target->proof.header);

	target->proof.iter_pos = NULL;
	target->proof.iter_count = 0;
}

static unsigned int
slabheader_proof_count(dns_rdataset_t *rdataset) {
	dns_slabheader_t *header = slabheader_proof_getheader(rdataset);

	return header->nitems;
}

static dns_slabheader_t *
slabheader_proof_getheader(const dns_rdataset_t *rdataset) {
	uint8_t *rawbuf = rdataset->proof.raw;
	return (dns_slabheader_t *)(rawbuf - offsetof(dns_slabheader_t, raw));
}
