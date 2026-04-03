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

#include <string.h>

#include <isc/net.h>

#include "../rdata_helpers.h"

#define RRTYPE_A_ATTRIBUTES (0)

static isc_result_t
fromtext_in_a(ARGS_FROMTEXT) {
	isc_token_t token;
	struct in_addr addr;
	isc_region_t region;

	REQUIRE(type == dns_rdatatype_a);
	REQUIRE(rdclass == dns_rdataclass_in);

	UNUSED(type);
	UNUSED(origin);
	UNUSED(options);
	UNUSED(rdclass);
	UNUSED(callbacks);

	RETERR(isc_lex_getmastertoken(lexer, &token, isc_tokentype_string,
				      false));

	if (inet_pton(AF_INET, DNS_AS_STR(token), &addr) != 1) {
		RETTOK(DNS_R_BADDOTTEDQUAD);
	}
	isc_buffer_availableregion(target, &region);
	if (region.length < 4) {
		return ISC_R_NOSPACE;
	}
	memmove(region.base, &addr, 4);
	isc_buffer_add(target, 4);
	return ISC_R_SUCCESS;
}

static isc_result_t
totext_in_a(ARGS_TOTEXT) {
	isc_region_t region;

	REQUIRE(rdata->type == dns_rdatatype_a);
	REQUIRE(rdata->rdclass == dns_rdataclass_in);
	REQUIRE(rdata->length == 4);

	UNUSED(tctx);

	dns_rdata_toregion(rdata, &region);
	return inet_totext(AF_INET, tctx->flags, &region, target);
}

static isc_result_t
fromwire_in_a(ARGS_FROMWIRE) {
	isc_region_t sregion;
	isc_region_t tregion;

	REQUIRE(type == dns_rdatatype_a);
	REQUIRE(rdclass == dns_rdataclass_in);

	UNUSED(type);
	UNUSED(dctx);
	UNUSED(rdclass);

	isc_buffer_activeregion(source, &sregion);
	isc_buffer_availableregion(target, &tregion);
	if (sregion.length < 4) {
		return ISC_R_UNEXPECTEDEND;
	}
	if (tregion.length < 4) {
		return ISC_R_NOSPACE;
	}

	memmove(tregion.base, sregion.base, 4);
	isc_buffer_forward(source, 4);
	isc_buffer_add(target, 4);
	return ISC_R_SUCCESS;
}

static isc_result_t
towire_in_a(ARGS_TOWIRE) {
	isc_region_t region;

	REQUIRE(rdata->type == dns_rdatatype_a);
	REQUIRE(rdata->rdclass == dns_rdataclass_in);
	REQUIRE(rdata->length == 4);

	UNUSED(cctx);

	isc_buffer_availableregion(target, &region);
	if (region.length < rdata->length) {
		return ISC_R_NOSPACE;
	}
	memmove(region.base, rdata->data, rdata->length);
	isc_buffer_add(target, 4);
	return ISC_R_SUCCESS;
}

static int
compare_in_a(ARGS_COMPARE) {
	isc_region_t r1;
	isc_region_t r2;

	REQUIRE(rdata1->type == rdata2->type);
	REQUIRE(rdata1->rdclass == rdata2->rdclass);
	REQUIRE(rdata1->type == dns_rdatatype_a);
	REQUIRE(rdata1->rdclass == dns_rdataclass_in);
	REQUIRE(rdata1->length == 4);
	REQUIRE(rdata2->length == 4);

	dns_rdata_toregion(rdata1, &r1);
	dns_rdata_toregion(rdata2, &r2);
	return isc_region_compare(&r1, &r2);
}

static isc_result_t
fromstruct_in_a(ARGS_FROMSTRUCT) {
	dns_rdata_in_a_t *a = source;
	uint32_t n;

	REQUIRE(type == dns_rdatatype_a);
	REQUIRE(rdclass == dns_rdataclass_in);
	REQUIRE(a != NULL);
	REQUIRE(a->common.rdtype == type);
	REQUIRE(a->common.rdclass == rdclass);

	UNUSED(type);
	UNUSED(rdclass);

	n = ntohl(a->in_addr.s_addr);

	return uint32_tobuffer(n, target);
}

static isc_result_t
tostruct_in_a(ARGS_TOSTRUCT) {
	dns_rdata_in_a_t *a = target;
	uint32_t n;
	isc_region_t region;

	REQUIRE(a != NULL);
	REQUIRE(rdata->type == dns_rdatatype_a);
	REQUIRE(rdata->rdclass == dns_rdataclass_in);
	REQUIRE(rdata->length == 4);

	UNUSED(mctx);

	DNS_RDATACOMMON_INIT(a, rdata->type, rdata->rdclass);

	dns_rdata_toregion(rdata, &region);
	n = uint32_fromregion(&region);
	a->in_addr.s_addr = htonl(n);

	return ISC_R_SUCCESS;
}

static void
freestruct_in_a(ARGS_FREESTRUCT) {
	dns_rdata_in_a_t *a = source;

	REQUIRE(a != NULL);
	REQUIRE(a->common.rdtype == dns_rdatatype_a);
	REQUIRE(a->common.rdclass == dns_rdataclass_in);

	UNUSED(a);
}

static isc_result_t
additionaldata_in_a(ARGS_ADDLDATA) {
	REQUIRE(rdata->type == dns_rdatatype_a);
	REQUIRE(rdata->rdclass == dns_rdataclass_in);

	UNUSED(rdata);
	UNUSED(owner);
	UNUSED(add);
	UNUSED(arg);

	return ISC_R_SUCCESS;
}

static isc_result_t
digest_in_a(ARGS_DIGEST) {
	isc_region_t r;

	REQUIRE(rdata->type == dns_rdatatype_a);
	REQUIRE(rdata->rdclass == dns_rdataclass_in);

	dns_rdata_toregion(rdata, &r);

	return (digest)(arg, &r);
}

static bool
checkowner_in_a(ARGS_CHECKOWNER) {
	dns_name_t prefix, suffix;
	unsigned int labels, i;

	REQUIRE(type == dns_rdatatype_a);
	REQUIRE(rdclass == dns_rdataclass_in);

	UNUSED(type);
	UNUSED(rdclass);

	labels = dns_name_countlabels(name);
	if (labels > 2U) {
		/*
		 * Handle Active Directory gc._msdcs.<forest> name.
		 */
		dns_name_init(&prefix);
		dns_name_init(&suffix);
		dns_name_split(name, labels - 2, &prefix, &suffix);
		if (dns_name_equal(&gc_msdcs, &prefix) &&
		    dns_name_ishostname(&suffix, false))
		{
			return true;
		}

		/*
		 * Handle SPF exists targets when the seperating label is:
		 * - "_spf" RFC7208, section 5.7
		 * - "_spf_verify" RFC7208, Appendix D1
		 * - "_spf_rate" RFC7208, Appendix D1
		 */
		for (i = 0; i < labels - 2; i++) {
			dns_label_t label;
			dns_name_getlabel(name, i, &label);
			if ((label.length == 5 &&
			     strncasecmp((char *)label.base, "\x04_spf", 5) ==
				     0) ||
			    (label.length == 12 &&
			     strncasecmp((char *)label.base, "\x0b_spf_verify",
					 12) == 0) ||
			    (label.length == 10 &&
			     strncasecmp((char *)label.base, "\x09_spf_rate",
					 10) == 0))
			{
				return true;
			}
		}
	}

	return dns_name_ishostname(name, wildcard);
}

static bool
checknames_in_a(ARGS_CHECKNAMES) {
	REQUIRE(rdata->type == dns_rdatatype_a);
	REQUIRE(rdata->rdclass == dns_rdataclass_in);

	UNUSED(rdata);
	UNUSED(owner);
	UNUSED(bad);

	return true;
}

static int
casecompare_in_a(ARGS_COMPARE) {
	return compare_in_a(rdata1, rdata2);
}

const dns_rdata_typedesc_t dns__rdata_in_a_typedesc = {
	.type = 1,
	.rdclass = 1,
	.name = "A",
	.attributes = RRTYPE_A_ATTRIBUTES,
	.methods =
		&(const dns_rdata_methods_t){
			.fromtext = fromtext_in_a,
			.totext = totext_in_a,
			.fromwire = fromwire_in_a,
			.towire = towire_in_a,
			.compare = compare_in_a,
			.casecompare = casecompare_in_a,
			.fromstruct = fromstruct_in_a,
			.tostruct = tostruct_in_a,
			.freestruct = freestruct_in_a,
			.additionaldata = additionaldata_in_a,
			.digest = digest_in_a,
			.checkowner = checkowner_in_a,
			.checknames = checknames_in_a,
		},
};

/*
 * Chaos class A record.
 */

#include <isc/net.h>

#define RRTYPE_A_ATTRIBUTES (0)

static isc_result_t
fromtext_ch_a(ARGS_FROMTEXT) {
	isc_token_t token;
	dns_fixedname_t fn;
	dns_name_t *name = dns_fixedname_initname(&fn);
	isc_buffer_t buffer;

	REQUIRE(type == dns_rdatatype_a);
	REQUIRE(rdclass == dns_rdataclass_ch); /* 3 */

	UNUSED(type);
	UNUSED(callbacks);

	RETERR(isc_lex_getmastertoken(lexer, &token, isc_tokentype_string,
				      false));

	/* get domain name */
	buffer_fromregion(&buffer, &token.value.as_region);
	if (origin == NULL) {
		origin = dns_rootname;
	}
	RETTOK(dns_name_fromtext(name, &buffer, origin, options));
	RETTOK(dns_name_towire(name, NULL, target));
	if ((options & DNS_RDATA_CHECKNAMES) != 0 &&
	    (options & DNS_RDATA_CHECKREVERSE) != 0)
	{
		bool ok;
		ok = dns_name_ishostname(name, false);
		if (!ok && (options & DNS_RDATA_CHECKNAMESFAIL) != 0) {
			RETTOK(DNS_R_BADNAME);
		}
		if (!ok && callbacks != NULL) {
			warn_badname(name, lexer, callbacks);
		}
	}

	/* 16-bit octal address */
	RETERR(isc_lex_getoctaltoken(lexer, &token, false));
	if (token.value.as_ulong > 0xffffU) {
		RETTOK(ISC_R_RANGE);
	}
	return uint16_tobuffer(token.value.as_ulong, target);
}

static isc_result_t
totext_ch_a(ARGS_TOTEXT) {
	isc_region_t region;
	dns_name_t name;
	dns_name_t prefix;
	unsigned int opts;
	char buf[sizeof("0177777")];
	uint16_t addr;

	REQUIRE(rdata->type == dns_rdatatype_a);
	REQUIRE(rdata->rdclass == dns_rdataclass_ch); /* 3 */
	REQUIRE(rdata->length != 0);

	dns_name_init(&name);
	dns_name_init(&prefix);

	dns_rdata_toregion(rdata, &region);
	dns_name_fromregion(&name, &region);
	isc_region_consume(&region, name_length(&name));
	addr = uint16_fromregion(&region);

	opts = name_prefix(&name, tctx->origin, &prefix) ? DNS_NAME_OMITFINALDOT
							 : 0;
	RETERR(dns_name_totext(&prefix, opts, target));

	snprintf(buf, sizeof(buf), "%o", addr); /* note octal */
	RETERR(str_totext(" ", target));
	return str_totext(buf, target);
}

static isc_result_t
fromwire_ch_a(ARGS_FROMWIRE) {
	isc_region_t sregion;
	isc_region_t tregion;
	dns_name_t name;

	REQUIRE(type == dns_rdatatype_a);
	REQUIRE(rdclass == dns_rdataclass_ch);

	UNUSED(type);
	UNUSED(rdclass);

	dctx = dns_decompress_setpermitted(dctx, true);

	dns_name_init(&name);

	RETERR(dns_name_fromwire(&name, source, dctx, target));

	isc_buffer_activeregion(source, &sregion);
	isc_buffer_availableregion(target, &tregion);
	if (sregion.length < 2) {
		return ISC_R_UNEXPECTEDEND;
	}
	if (tregion.length < 2) {
		return ISC_R_NOSPACE;
	}

	memmove(tregion.base, sregion.base, 2);
	isc_buffer_forward(source, 2);
	isc_buffer_add(target, 2);

	return ISC_R_SUCCESS;
}

static isc_result_t
towire_ch_a(ARGS_TOWIRE) {
	dns_name_t name;
	isc_region_t sregion;
	isc_region_t tregion;

	REQUIRE(rdata->type == dns_rdatatype_a);
	REQUIRE(rdata->rdclass == dns_rdataclass_ch);
	REQUIRE(rdata->length != 0);

	dns_compress_setpermitted(cctx, true);

	dns_name_init(&name);

	dns_rdata_toregion(rdata, &sregion);

	dns_name_fromregion(&name, &sregion);
	isc_region_consume(&sregion, name_length(&name));
	RETERR(dns_name_towire(&name, cctx, target));

	isc_buffer_availableregion(target, &tregion);
	if (tregion.length < 2) {
		return ISC_R_NOSPACE;
	}

	memmove(tregion.base, sregion.base, 2);
	isc_buffer_add(target, 2);
	return ISC_R_SUCCESS;
}

static int
compare_ch_a(ARGS_COMPARE) {
	dns_name_t name1;
	dns_name_t name2;
	isc_region_t region1;
	isc_region_t region2;
	int order;

	REQUIRE(rdata1->type == rdata2->type);
	REQUIRE(rdata1->rdclass == rdata2->rdclass);
	REQUIRE(rdata1->type == dns_rdatatype_a);
	REQUIRE(rdata1->rdclass == dns_rdataclass_ch);
	REQUIRE(rdata1->length != 0);
	REQUIRE(rdata2->length != 0);

	dns_name_init(&name1);
	dns_name_init(&name2);

	dns_rdata_toregion(rdata1, &region1);
	dns_rdata_toregion(rdata2, &region2);

	dns_name_fromregion(&name1, &region1);
	dns_name_fromregion(&name2, &region2);
	isc_region_consume(&region1, name_length(&name1));
	isc_region_consume(&region2, name_length(&name2));

	order = dns_name_rdatacompare(&name1, &name2);
	if (order != 0) {
		return order;
	}

	order = memcmp(region1.base, region2.base, 2);
	if (order != 0) {
		order = (order < 0) ? -1 : 1;
	}
	return order;
}

static isc_result_t
fromstruct_ch_a(ARGS_FROMSTRUCT) {
	dns_rdata_ch_a_t *a = source;
	isc_region_t region;

	REQUIRE(type == dns_rdatatype_a);
	REQUIRE(a != NULL);
	REQUIRE(a->common.rdtype == type);
	REQUIRE(a->common.rdclass == rdclass);

	UNUSED(type);
	UNUSED(rdclass);

	dns_name_toregion(&a->ch_addr_dom, &region);
	RETERR(isc_buffer_copyregion(target, &region));

	return uint16_tobuffer(ntohs(a->ch_addr), target);
}

static isc_result_t
tostruct_ch_a(ARGS_TOSTRUCT) {
	dns_rdata_ch_a_t *a = target;
	isc_region_t region;
	dns_name_t name;

	REQUIRE(rdata->type == dns_rdatatype_a);
	REQUIRE(rdata->rdclass == dns_rdataclass_ch);
	REQUIRE(rdata->length != 0);

	DNS_RDATACOMMON_INIT(a, rdata->type, rdata->rdclass);

	dns_rdata_toregion(rdata, &region);

	dns_name_init(&name);
	dns_name_fromregion(&name, &region);
	isc_region_consume(&region, name_length(&name));

	dns_name_init(&a->ch_addr_dom);
	name_duporclone(&name, mctx, &a->ch_addr_dom);
	a->ch_addr = htons(uint16_fromregion(&region));
	a->mctx = mctx;
	return ISC_R_SUCCESS;
}

static void
freestruct_ch_a(ARGS_FREESTRUCT) {
	dns_rdata_ch_a_t *a = source;

	REQUIRE(a != NULL);
	REQUIRE(a->common.rdtype == dns_rdatatype_a);

	if (a->mctx == NULL) {
		return;
	}

	dns_name_free(&a->ch_addr_dom, a->mctx);
	a->mctx = NULL;
}

static isc_result_t
additionaldata_ch_a(ARGS_ADDLDATA) {
	REQUIRE(rdata->type == dns_rdatatype_a);
	REQUIRE(rdata->rdclass == dns_rdataclass_ch);

	UNUSED(rdata);
	UNUSED(owner);
	UNUSED(add);
	UNUSED(arg);

	return ISC_R_SUCCESS;
}

static isc_result_t
digest_ch_a(ARGS_DIGEST) {
	isc_region_t r;
	dns_name_t name;

	REQUIRE(rdata->type == dns_rdatatype_a);
	REQUIRE(rdata->rdclass == dns_rdataclass_ch);

	dns_rdata_toregion(rdata, &r);
	dns_name_init(&name);
	dns_name_fromregion(&name, &r);
	isc_region_consume(&r, name_length(&name));
	RETERR(dns_name_digest(&name, digest, arg));
	return (digest)(arg, &r);
}

static bool
checkowner_ch_a(ARGS_CHECKOWNER) {
	REQUIRE(type == dns_rdatatype_a);
	REQUIRE(rdclass == dns_rdataclass_ch);

	UNUSED(type);

	return dns_name_ishostname(name, wildcard);
}

static bool
checknames_ch_a(ARGS_CHECKNAMES) {
	isc_region_t region;
	dns_name_t name;

	REQUIRE(rdata->type == dns_rdatatype_a);
	REQUIRE(rdata->rdclass == dns_rdataclass_ch);

	UNUSED(owner);

	dns_rdata_toregion(rdata, &region);
	dns_name_init(&name);
	dns_name_fromregion(&name, &region);
	if (!dns_name_ishostname(&name, false)) {
		if (bad != NULL) {
			dns_name_clone(&name, bad);
		}
		return false;
	}

	return true;
}

static int
casecompare_ch_a(ARGS_COMPARE) {
	return compare_ch_a(rdata1, rdata2);
}
const dns_rdata_typedesc_t dns__rdata_ch_a_typedesc = {
	.type = 1,
	.rdclass = 3,
	.name = "A",
	.attributes = RRTYPE_A_ATTRIBUTES,
	.methods =
		&(const dns_rdata_methods_t){
			.fromtext = fromtext_ch_a,
			.totext = totext_ch_a,
			.fromwire = fromwire_ch_a,
			.towire = towire_ch_a,
			.compare = compare_ch_a,
			.casecompare = casecompare_ch_a,
			.fromstruct = fromstruct_ch_a,
			.tostruct = tostruct_ch_a,
			.freestruct = freestruct_ch_a,
			.additionaldata = additionaldata_ch_a,
			.digest = digest_ch_a,
			.checkowner = checkowner_ch_a,
			.checknames = checknames_ch_a,
		},
};

/*
 * Hesiod class A record.
 */

#include <isc/net.h>

#define RRTYPE_A_ATTRIBUTES (0)

static isc_result_t
fromtext_hs_a(ARGS_FROMTEXT) {
	isc_token_t token;
	struct in_addr addr;
	isc_region_t region;

	REQUIRE(type == dns_rdatatype_a);
	REQUIRE(rdclass == dns_rdataclass_hs);

	UNUSED(type);
	UNUSED(origin);
	UNUSED(options);
	UNUSED(rdclass);
	UNUSED(callbacks);

	RETERR(isc_lex_getmastertoken(lexer, &token, isc_tokentype_string,
				      false));

	if (inet_pton(AF_INET, DNS_AS_STR(token), &addr) != 1) {
		RETTOK(DNS_R_BADDOTTEDQUAD);
	}
	isc_buffer_availableregion(target, &region);
	if (region.length < 4) {
		return ISC_R_NOSPACE;
	}
	memmove(region.base, &addr, 4);
	isc_buffer_add(target, 4);
	return ISC_R_SUCCESS;
}

static isc_result_t
totext_hs_a(ARGS_TOTEXT) {
	isc_region_t region;

	REQUIRE(rdata->type == dns_rdatatype_a);
	REQUIRE(rdata->rdclass == dns_rdataclass_hs);
	REQUIRE(rdata->length == 4);

	UNUSED(tctx);

	dns_rdata_toregion(rdata, &region);
	return inet_totext(AF_INET, tctx->flags, &region, target);
}

static isc_result_t
fromwire_hs_a(ARGS_FROMWIRE) {
	isc_region_t sregion;
	isc_region_t tregion;

	REQUIRE(type == dns_rdatatype_a);
	REQUIRE(rdclass == dns_rdataclass_hs);

	UNUSED(type);
	UNUSED(dctx);
	UNUSED(rdclass);

	isc_buffer_activeregion(source, &sregion);
	isc_buffer_availableregion(target, &tregion);
	if (sregion.length < 4) {
		return ISC_R_UNEXPECTEDEND;
	}
	if (tregion.length < 4) {
		return ISC_R_NOSPACE;
	}

	memmove(tregion.base, sregion.base, 4);
	isc_buffer_forward(source, 4);
	isc_buffer_add(target, 4);
	return ISC_R_SUCCESS;
}

static isc_result_t
towire_hs_a(ARGS_TOWIRE) {
	isc_region_t region;

	REQUIRE(rdata->type == dns_rdatatype_a);
	REQUIRE(rdata->rdclass == dns_rdataclass_hs);
	REQUIRE(rdata->length == 4);

	UNUSED(cctx);

	isc_buffer_availableregion(target, &region);
	if (region.length < rdata->length) {
		return ISC_R_NOSPACE;
	}
	memmove(region.base, rdata->data, rdata->length);
	isc_buffer_add(target, 4);
	return ISC_R_SUCCESS;
}

static int
compare_hs_a(ARGS_COMPARE) {
	int order;

	REQUIRE(rdata1->type == rdata2->type);
	REQUIRE(rdata1->rdclass == rdata2->rdclass);
	REQUIRE(rdata1->type == dns_rdatatype_a);
	REQUIRE(rdata1->rdclass == dns_rdataclass_hs);
	REQUIRE(rdata1->length == 4);
	REQUIRE(rdata2->length == 4);

	order = memcmp(rdata1->data, rdata2->data, 4);
	if (order != 0) {
		order = (order < 0) ? -1 : 1;
	}

	return order;
}

static isc_result_t
fromstruct_hs_a(ARGS_FROMSTRUCT) {
	dns_rdata_hs_a_t *a = source;
	uint32_t n;

	REQUIRE(type == dns_rdatatype_a);
	REQUIRE(rdclass == dns_rdataclass_hs);
	REQUIRE(a != NULL);
	REQUIRE(a->common.rdtype == type);
	REQUIRE(a->common.rdclass == rdclass);

	UNUSED(type);
	UNUSED(rdclass);

	n = ntohl(a->in_addr.s_addr);

	return uint32_tobuffer(n, target);
}

static isc_result_t
tostruct_hs_a(ARGS_TOSTRUCT) {
	dns_rdata_hs_a_t *a = target;
	uint32_t n;
	isc_region_t region;

	REQUIRE(rdata->type == dns_rdatatype_a);
	REQUIRE(rdata->rdclass == dns_rdataclass_hs);
	REQUIRE(rdata->length == 4);
	REQUIRE(a != NULL);

	UNUSED(mctx);

	DNS_RDATACOMMON_INIT(a, rdata->type, rdata->rdclass);

	dns_rdata_toregion(rdata, &region);
	n = uint32_fromregion(&region);
	a->in_addr.s_addr = htonl(n);

	return ISC_R_SUCCESS;
}

static void
freestruct_hs_a(ARGS_FREESTRUCT) {
	UNUSED(source);

	REQUIRE(source != NULL);
}

static isc_result_t
additionaldata_hs_a(ARGS_ADDLDATA) {
	REQUIRE(rdata->type == dns_rdatatype_a);
	REQUIRE(rdata->rdclass == dns_rdataclass_hs);

	UNUSED(rdata);
	UNUSED(owner);
	UNUSED(add);
	UNUSED(arg);

	return ISC_R_SUCCESS;
}

static isc_result_t
digest_hs_a(ARGS_DIGEST) {
	isc_region_t r;

	REQUIRE(rdata->type == dns_rdatatype_a);
	REQUIRE(rdata->rdclass == dns_rdataclass_hs);

	dns_rdata_toregion(rdata, &r);

	return (digest)(arg, &r);
}

static bool
checkowner_hs_a(ARGS_CHECKOWNER) {
	REQUIRE(type == dns_rdatatype_a);
	REQUIRE(rdclass == dns_rdataclass_hs);

	UNUSED(name);
	UNUSED(type);
	UNUSED(rdclass);
	UNUSED(wildcard);

	return true;
}

static bool
checknames_hs_a(ARGS_CHECKNAMES) {
	REQUIRE(rdata->type == dns_rdatatype_a);
	REQUIRE(rdata->rdclass == dns_rdataclass_hs);

	UNUSED(rdata);
	UNUSED(owner);
	UNUSED(bad);

	return true;
}

static int
casecompare_hs_a(ARGS_COMPARE) {
	return compare_hs_a(rdata1, rdata2);
}

const dns_rdata_typedesc_t dns__rdata_hs_a_typedesc = {
	.type = 1,
	.rdclass = 4,
	.name = "A",
	.attributes = RRTYPE_A_ATTRIBUTES,
	.methods =
		&(const dns_rdata_methods_t){
			.fromtext = fromtext_hs_a,
			.totext = totext_hs_a,
			.fromwire = fromwire_hs_a,
			.towire = towire_hs_a,
			.compare = compare_hs_a,
			.casecompare = casecompare_hs_a,
			.fromstruct = fromstruct_hs_a,
			.tostruct = tostruct_hs_a,
			.freestruct = freestruct_hs_a,
			.additionaldata = additionaldata_hs_a,
			.digest = digest_hs_a,
			.checkowner = checkowner_hs_a,
			.checknames = checknames_hs_a,
		},
};
