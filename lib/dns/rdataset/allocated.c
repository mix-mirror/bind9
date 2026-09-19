/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * SPDX-License-Identifier: MPL-2.0
 */

/*! \file */

#include <stdint.h>
#include <string.h>

#include <isc/hash.h>
#include <isc/mem.h>
#include <isc/refcount.h>
#include <isc/region.h>
#include <isc/result.h>
#include <isc/util.h>

#include <dns/db.h>
#include <dns/rdata.h>
#include <dns/rdataset.h>
#include <dns/types.h>

#include "../rdataslab_p.h"

struct dns_allocated_rdata {
	isc_mem_t *mctx;
	isc_refcount_t references;
	uint32_t length;
	unsigned char raw[];
};

ISC_REFCOUNT_STATIC_DECL(dns_allocated_rdata);

static void
allocated_rdata_destroy(dns_allocated_rdata_t *data) {
	size_t size = STRUCT_FLEX_SIZE(data, raw, data->length);
	isc_refcount_destroy(&data->references);
	isc_mem_putanddetach(&data->mctx, data, size);
}

ISC_REFCOUNT_STATIC_IMPL(dns_allocated_rdata, allocated_rdata_destroy);

static dns_typepair_t
allocated_typepair(const dns_rdataset_t *rdataset);

static uint32_t
allocated_raw_length(const dns_rdataset_t *rdataset) {
	return rdataset->allocated.proof_name != NULL
		       ? (uint32_t)(rdataset->allocated.proof_name -
				    rdataset->allocated.raw)
		       : rdataset->allocated.data->length;
}

static void
allocated_disassociate(dns_rdataset_t *rdataset DNS__DB_FLARG) {
	dns_dbnode_t *node = rdataset->allocated.node;
	uint32_t length = allocated_raw_length(rdataset);
	if (rdataset->attributes.negative && node != NULL &&
	    node->methods->updateraw != NULL &&
	    isc_hash64(rdataset->allocated.raw, length, true) !=
		    rdataset->allocated.raw_hash)
	{
		isc_region_t raw = {
			.base = rdataset->allocated.raw,
			.length = length,
		};
		node->methods->updateraw(node, allocated_typepair(rdataset),
					 &raw);
	}
	dns_allocated_rdata_unref(rdataset->allocated.data);
	if (node != NULL) {
		dns__db_detachnode(&rdataset->allocated.node DNS__DB_FLARG_PASS);
	}
}

static isc_result_t
allocated_first(dns_rdataset_t *rdataset) {
	if (rdataset->allocated.count == 0) {
		rdataset->allocated.iter_pos = NULL;
		rdataset->allocated.iter_count = 0;
		return ISC_R_NOMORE;
	}
	rdataset->allocated.iter_pos = rdataset->allocated.raw;
	rdataset->allocated.iter_count = rdataset->allocated.count - 1;
	return ISC_R_SUCCESS;
}

static isc_result_t
allocated_next(dns_rdataset_t *rdataset) {
	if (rdataset->allocated.iter_count == 0) {
		rdataset->allocated.iter_pos = NULL;
		return ISC_R_NOMORE;
	}
	rdataset->allocated.iter_count--;
	unsigned char *raw = rdataset->allocated.iter_pos;
	uint16_t length = peek_uint16(raw);
	rdataset->allocated.iter_pos = raw + sizeof(uint16_t) + length;
	return ISC_R_SUCCESS;
}

static void
allocated_current(dns_rdataset_t *rdataset, dns_rdata_t *rdata) {
	unsigned char *raw = rdataset->allocated.iter_pos;
	REQUIRE(raw != NULL);
	uint16_t length = get_uint16(raw);
	unsigned int flags = 0;
	if (rdataset->type == dns_rdatatype_rrsig) {
		if ((*raw & DNS_RDATASLAB_OFFLINE) != 0) {
			flags |= DNS_RDATA_OFFLINE;
		}
		length--;
		raw++;
	}
	isc_region_t region = { .base = raw, .length = length };
	dns_rdata_fromregion(rdata, rdataset->rdclass, rdataset->type, &region);
	rdata->flags |= flags;
}

static void
allocated_clone(const dns_rdataset_t *source,
		dns_rdataset_t *target DNS__DB_FLARG) {
	INSIST(!ISC_LINK_LINKED(target, link));
	*target = *source;
	ISC_LINK_INIT(target, link);
	target->allocated.data =
		dns_allocated_rdata_ref(source->allocated.data);
	target->allocated.node = NULL;
	if (source->allocated.node != NULL) {
		dns__db_attachnode(source->allocated.node,
				   &target->allocated.node DNS__DB_FLARG_PASS);
	}
	target->allocated.iter_pos = NULL;
	target->allocated.iter_count = 0;
}

static unsigned int
allocated_count(dns_rdataset_t *rdataset) {
	return rdataset->allocated.count;
}

static void
allocated_associate_view(const dns_rdataset_t *source,
			 dns_rdataset_t *target, dns_rdatatype_t type,
			 dns_rdatatype_t covers, uint16_t count,
			 unsigned char *raw DNS__DB_FLARG) {
	*target = (dns_rdataset_t){
		.magic = target->magic,
		.methods = source->methods,
		.link = target->link,
		.rdclass = source->rdclass,
		.type = type,
		.covers = covers,
		.ttl = source->ttl,
		.trust = source->trust,
		.attributes = target->attributes,
		.allocated.data = dns_allocated_rdata_ref(source->allocated.data),
		.allocated.raw = raw,
		.allocated.count = count,
	};
	target->attributes.keepcase = true;
	if (source->allocated.node != NULL) {
		dns__db_attachnode(source->allocated.node, &target->allocated.node
				   DNS__DB_FLARG_PASS);
	}
}

static isc_result_t
allocated_getnoqname(dns_rdataset_t *rdataset, dns_name_t *name,
		     dns_rdataset_t *nsec,
		     dns_rdataset_t *nsecsig DNS__DB_FLARG) {
	if (rdataset->allocated.proof_name == NULL) {
		return ISC_R_NOTFOUND;
	}

	allocated_associate_view(rdataset, nsec, rdataset->allocated.proof_type,
				 dns_rdatatype_none,
				 rdataset->allocated.proof_count,
				 rdataset->allocated.proof_raw DNS__DB_FLARG_PASS);
	allocated_associate_view(rdataset, nsecsig, dns_rdatatype_rrsig,
				 rdataset->allocated.proof_type,
				 rdataset->allocated.proof_sig_count,
				 rdataset->allocated.proof_sig_raw
				 DNS__DB_FLARG_PASS);

	isc_region_t region = {
		.base = rdataset->allocated.proof_name,
		.length = rdataset->allocated.proof_name_length,
	};
	dns_name_fromregion(name, &region);
	return ISC_R_SUCCESS;
}

static dns_typepair_t
allocated_typepair(const dns_rdataset_t *rdataset) {
	return DNS_TYPEPAIR_VALUE(rdataset->type, rdataset->covers);
}

static void
allocated_settrust(dns_rdataset_t *rdataset, dns_trust_t trust) {
	rdataset->trust = trust;
	dns_dbnode_t *node = rdataset->allocated.node;
	if (node != NULL && node->methods->settrust != NULL) {
		node->methods->settrust(node, allocated_typepair(rdataset), trust);
	}
}

static void
allocated_expire(dns_rdataset_t *rdataset DNS__DB_FLARG) {
	dns_dbnode_t *node = rdataset->allocated.node;
	if (node != NULL && node->methods->expirerdataset != NULL) {
		node->methods->expirerdataset(node,
					       allocated_typepair(rdataset));
	}
}

static void
allocated_clearprefetch(dns_rdataset_t *rdataset) {
	rdataset->attributes.prefetch = false;
	dns_dbnode_t *node = rdataset->allocated.node;
	if (node != NULL && node->methods->clearprefetch != NULL) {
		node->methods->clearprefetch(node,
					      allocated_typepair(rdataset));
	}
}

static dns_rdatasetmethods_t allocated_methods = {
	.disassociate = allocated_disassociate,
	.first = allocated_first,
	.next = allocated_next,
	.current = allocated_current,
	.clone = allocated_clone,
	.count = allocated_count,
	.getnoqname = allocated_getnoqname,
	.settrust = allocated_settrust,
	.expire = allocated_expire,
	.clearprefetch = allocated_clearprefetch,
};

void
dns_rdataset_makeallocated(dns_rdataset_t *rdataset, isc_mem_t *mctx,
			   dns_dbnode_t *node, uint16_t count,
			   const isc_region_t *raw) {
	dns_rdataset_makeallocatedproof(rdataset, mctx, node, count, raw, NULL,
				       dns_rdatatype_none, 0, NULL, 0, NULL);
}

void
dns_rdataset_makeallocatedproof(
	dns_rdataset_t *rdataset, isc_mem_t *mctx, dns_dbnode_t *node,
	uint16_t count, const isc_region_t *raw, const isc_region_t *proof_name,
	dns_rdatatype_t proof_type, uint16_t proof_count,
	const isc_region_t *proof, uint16_t proof_sig_count,
	const isc_region_t *proof_sig) {
	REQUIRE(DNS_RDATASET_VALID(rdataset));
	REQUIRE(rdataset->methods == NULL);
	REQUIRE(mctx != NULL);
	REQUIRE(raw != NULL);

	REQUIRE((proof_name == NULL) == (proof == NULL));
	REQUIRE((proof_name == NULL) == (proof_sig == NULL));

	uint32_t proof_name_length = proof_name != NULL ? proof_name->length : 0;
	uint32_t proof_length = proof != NULL ? proof->length : 0;
	uint32_t proof_sig_length = proof_sig != NULL ? proof_sig->length : 0;
	uint32_t length = raw->length + proof_name_length + proof_length +
			  proof_sig_length;
	dns_allocated_rdata_t *data = NULL;
	size_t size = STRUCT_FLEX_SIZE(data, raw, length);
	data = isc_mem_get(mctx, size);
	*data = (dns_allocated_rdata_t){
		.mctx = isc_mem_ref(mctx),
		.references = ISC_REFCOUNT_INITIALIZER(1),
		.length = length,
	};
	unsigned char *cursor = data->raw;
	memmove(cursor, raw->base, raw->length);
	unsigned char *main_raw = cursor;
	cursor += raw->length;
	unsigned char *proof_name_raw = NULL;
	unsigned char *proof_raw = NULL;
	unsigned char *proof_sig_raw = NULL;
	if (proof_name != NULL) {
		proof_name_raw = cursor;
		memmove(cursor, proof_name->base, proof_name->length);
		cursor += proof_name->length;
		proof_raw = cursor;
		memmove(cursor, proof->base, proof->length);
		cursor += proof->length;
		proof_sig_raw = cursor;
		memmove(cursor, proof_sig->base, proof_sig->length);
	}

	rdataset->methods = &allocated_methods;
	rdataset->allocated.data = data;
	rdataset->allocated.raw = main_raw;
	rdataset->allocated.count = count;
	rdataset->allocated.raw_hash = isc_hash64(main_raw, raw->length, true);
	rdataset->allocated.iter_pos = NULL;
	rdataset->allocated.iter_count = 0;
	rdataset->allocated.node = NULL;
	rdataset->allocated.proof_name = proof_name_raw;
	rdataset->allocated.proof_name_length = proof_name_length;
	rdataset->allocated.proof_type = proof_type;
	rdataset->allocated.proof_raw = proof_raw;
	rdataset->allocated.proof_count = proof_count;
	rdataset->allocated.proof_sig_raw = proof_sig_raw;
	rdataset->allocated.proof_sig_count = proof_sig_count;
	if (node != NULL) {
		dns__db_attachnode(node,
				   &rdataset->allocated.node DNS__DB_FILELINE);
	}
}
