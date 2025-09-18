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

#include <stdbool.h>

#include <isc/result.h>

#define RRTYPE_DELEG_ATTRIBUTES \
	(DNS_RDATATYPEATTR_FOLLOWADDITIONAL | DNS_RDATATYPEATTR_ATPARENT)

/*
 * Delegation Information Registry
 */
enum deleg_encoding { deleg_unknown, deleg_namelist, deleg_ipv4, deleg_ipv6 };

static const struct {
	const char *name;
	unsigned int value;
	enum deleg_encoding encoding;
	bool initial; /* Part of the first defined set of encodings. */
} direg[] = {
	{ "server-ipv4", 1, deleg_ipv4, true },
	{ "server-ipv6", 2, deleg_ipv6, true },
	{ "server-name", 3, deleg_namelist, true },
	{ "include-delegi", 4, deleg_namelist, true },
};

static isc_result_t
deleg_validate(uint16_t key, isc_region_t *region) {
	size_t i, j;

	for (i = 0; i < ARRAY_SIZE(direg); i++) {
		if (direg[i].value == key) {
			switch (direg[i].encoding) {
			case deleg_ipv4:
				if ((region->length % 4) != 0 ||
				    region->length == 0)
				{
					return DNS_R_FORMERR;
				}
				break;
			case deleg_ipv6:
				if ((region->length % 16) != 0 ||
				    region->length == 0)
				{
					return DNS_R_FORMERR;
				}
				break;
			case deleg_unknown:
				for (j = 0; j < region->length; j++) {
					if (!islower(region->base[j]) &&
					    !isdigit(region->base[j]) &&
					    region->base[j] != '-')
					{
						return DNS_R_FORMERR;
					}
				}
				break;
			case deleg_namelist:
				break;
			default:
				UNREACHABLE();
			}
		}
	}
	return ISC_R_SUCCESS;
}

/*
 * Parse keyname from region.
 */
static isc_result_t
deleg_keyfromregion(isc_textregion_t *region, uint16_t *value,
		    isc_buffer_t *target) {
	char *e = NULL;
	size_t i;
	unsigned long ul;

	/* Look for known key names.  */
	for (i = 0; i < ARRAY_SIZE(direg); i++) {
		size_t len = strlen(direg[i].name);
		if (strncasecmp(region->base, direg[i].name, len) != 0 ||
		    (region->base[len] != 0 && region->base[len] != '='))
		{
			continue;
		}
		isc_textregion_consume(region, len);
		ul = direg[i].value;
		goto finish;
	}
	/* Handle keyXXXXX form. */
	if (strncmp(region->base, "key", 3) != 0) {
		return DNS_R_SYNTAX;
	}
	isc_textregion_consume(region, 3);
	/* Disallow [+-]XXXXX which is allowed by strtoul. */
	if (region->length == 0 || *region->base == '-' || *region->base == '+')
	{
		return DNS_R_SYNTAX;
	}
	/* No zero padding. */
	if (region->length > 1 && *region->base == '0' &&
	    region->base[1] != '=')
	{
		return DNS_R_SYNTAX;
	}
	ul = strtoul(region->base, &e, 10);
	/* Valid number? */
	if (e == region->base || (*e != '=' && *e != 0)) {
		return DNS_R_SYNTAX;
	}
	if (ul > 0xffff) {
		return ISC_R_RANGE;
	}
	isc_textregion_consume(region, e - region->base);
finish:
	/* Consume separator. */
	if (region->length != 0) {
		isc_textregion_consume(region, 1);
	}
	RETERR(uint16_tobuffer(ul, target));
	SET_IF_NOT_NULL(value, ul);
	return ISC_R_SUCCESS;
}

static isc_result_t
deleg_fromtext(isc_textregion_t *region, const dns_name_t *origin,
	       unsigned int options, isc_buffer_t *target) {
	char *e = NULL;
	char abuf[16];
	char tbuf[sizeof("aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:255.255.255.255,")];
	isc_buffer_t sb;
	isc_region_t keyregion;
	size_t len;
	uint16_t key;
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(direg); i++) {
		len = strlen(direg[i].name);
		if (strncmp(region->base, direg[i].name, len) != 0 ||
		    (region->base[len] != 0 && region->base[len] != '='))
		{
			continue;
		}

		if (region->base[len] == '=') {
			len++;
		}

		RETERR(uint16_tobuffer(direg[i].value, target));
		isc_textregion_consume(region, len);

		sb = *target;
		RETERR(uint16_tobuffer(0, target)); /* dummy length */

		switch (direg[i].encoding) {
		case deleg_ipv4:
			do {
				snprintf(tbuf, sizeof(tbuf), "%*s",
					 (int)(region->length), region->base);
				e = strchr(tbuf, ',');
				if (e != NULL) {
					*e++ = 0;
					isc_textregion_consume(region,
							       e - tbuf);
				}
				if (inet_pton(AF_INET, tbuf, abuf) != 1) {
					return DNS_R_SYNTAX;
				}
				mem_tobuffer(target, abuf, 4);
			} while (e != NULL);
			break;
		case deleg_ipv6:
			do {
				snprintf(tbuf, sizeof(tbuf), "%*s",
					 (int)(region->length), region->base);
				e = strchr(tbuf, ',');
				if (e != NULL) {
					*e++ = 0;
					isc_textregion_consume(region,
							       e - tbuf);
				}
				if (inet_pton(AF_INET6, tbuf, abuf) != 1) {
					return DNS_R_SYNTAX;
				}
				mem_tobuffer(target, abuf, 16);
			} while (e != NULL);
			break;
		case deleg_namelist:
			do {
				isc_buffer_t b;
				size_t rlen = region->length;
				dns_fixedname_t fn;
				dns_name_t *name = dns_fixedname_initname(&fn);
				isc_buffer_init(&b, region->base, rlen);

				snprintf(tbuf, sizeof(tbuf), "%*s", (int)rlen,
					 region->base);
				e = strchr(tbuf, ',');
				if (e == NULL) {
					isc_buffer_add(&b, rlen);
				} else {
					*e++ = 0;
					rlen = e - tbuf;
					isc_buffer_add(&b, rlen - 1);
				}

				if (origin == NULL) {
					origin = dns_rootname;
				}
				RETERR(dns_name_fromtext(name, &b, origin,
							 options));
				RETERR(dns_name_towire(name, NULL, target));
				isc_textregion_consume(region, rlen);
			} while (e != NULL);
			break;
		case deleg_unknown:
		default:
			UNREACHABLE();
		}

		len = isc_buffer_usedlength(target) -
		      isc_buffer_usedlength(&sb) - 2;
		RETERR(uint16_tobuffer(len, &sb)); /* actual length */
		return ISC_R_SUCCESS;
	}

	RETERR(deleg_keyfromregion(region, &key, target));
	if (region->length == 0) {
		RETERR(uint16_tobuffer(0, target)); /* length */
		/* Sanity check keyXXXXX form. */
		keyregion.base = isc_buffer_used(target);
		keyregion.length = 0;
		return deleg_validate(key, &keyregion);
	}
	sb = *target;
	RETERR(uint16_tobuffer(0, target)); /* dummy length */
	RETERR(multitxt_fromtext(region, target));
	len = isc_buffer_usedlength(target) - isc_buffer_usedlength(&sb) - 2;
	RETERR(uint16_tobuffer(len, &sb)); /* length */
	/* Sanity check keyXXXXX form. */
	keyregion.base = isc_buffer_used(&sb);
	keyregion.length = len;
	return deleg_validate(key, &keyregion);
}

static isc_result_t
delegsortkeys(isc_buffer_t *target, unsigned int used) {
	isc_region_t r1, r2;
	unsigned char buf[1024];

	if (isc_buffer_usedlength(target) == used) {
		return ISC_R_SUCCESS;
	}

	/*
	 * Get the parameters into r1.
	 */
	isc_buffer_usedregion(target, &r1);
	isc_region_consume(&r1, used);

	while (1) {
		uint16_t key1, len1, key2, len2;
		unsigned char *base1, *base2;

		r2 = r1;

		/*
		 * Get the first parameter.
		 */
		base1 = r1.base;
		key1 = uint16_fromregion(&r1);
		isc_region_consume(&r1, 2);
		len1 = uint16_fromregion(&r1);
		isc_region_consume(&r1, 2);
		isc_region_consume(&r1, len1);

		/*
		 * Was there only one key left?
		 */
		if (r1.length == 0) {
			return ISC_R_SUCCESS;
		}

		/*
		 * Find the smallest parameter.
		 */
		while (r1.length != 0) {
			base2 = r1.base;
			key2 = uint16_fromregion(&r1);
			isc_region_consume(&r1, 2);
			len2 = uint16_fromregion(&r1);
			isc_region_consume(&r1, 2);
			isc_region_consume(&r1, len2);
			if (key2 == key1) {
				return DNS_R_DUPLICATE;
			}
			if (key2 < key1) {
				base1 = base2;
				key1 = key2;
				len1 = len2;
			}
		}

		/*
		 * Do we need to move the smallest parameter to the start?
		 */
		if (base1 != r2.base) {
			size_t offset = 0;
			size_t bytes = len1 + 4;
			size_t length = base1 - r2.base;

			/*
			 * Move the smallest parameter to the start.
			 */
			while (bytes > 0) {
				size_t count;

				if (bytes > sizeof(buf)) {
					count = sizeof(buf);
				} else {
					count = bytes;
				}
				memmove(buf, base1, count);
				memmove(r2.base + offset + count,
					r2.base + offset, length);
				memmove(r2.base + offset, buf, count);
				base1 += count;
				bytes -= count;
				offset += count;
			}
		}

		/*
		 * Consume the smallest parameter.
		 */
		isc_region_consume(&r2, len1 + 4);
		r1 = r2;
	}
}

static isc_result_t
generic_fromtext_in_deleg(ARGS_FROMTEXT) {
	isc_token_t token;
	unsigned int used;

	UNUSED(type);
	UNUSED(rdclass);
	UNUSED(callbacks);

	/*
	 * DelegInfos
	 */
	used = isc_buffer_usedlength(target);
	while (1) {
		RETERR(isc_lex_getmastertoken(lexer, &token,
					      isc_tokentype_qvpair, true));
		if (token.type == isc_tokentype_eol ||
		    token.type == isc_tokentype_eof)
		{
			isc_lex_ungettoken(lexer, &token);
			return delegsortkeys(target, used);
		}

		if (token.type != isc_tokentype_qvpair &&
		    token.type != isc_tokentype_vpair)
		{
			RETTOK(DNS_R_SYNTAX);
		}
		RETTOK(deleg_fromtext(&token.value.as_textregion, origin,
				      options, target));
	}
}

static const char *
deleginfokey(unsigned short value, enum deleg_encoding *encoding, char *buf,
	     size_t len, bool compat) {
	size_t i;
	int n;

	for (i = 0; i < ARRAY_SIZE(direg); i++) {
		if (direg[i].value == value && (direg[i].initial || !compat)) {
			*encoding = direg[i].encoding;
			return direg[i].name;
		}
	}
	n = snprintf(buf, len, "key%u", value);
	INSIST(n > 0 && (unsigned int)n < len);
	*encoding = deleg_unknown;
	return buf;
}

static isc_result_t
generic_totext_in_deleg(ARGS_TOTEXT) {
	isc_region_t region;
	char buf[sizeof("xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:255.255.255.255")];
	unsigned short num;
	bool compat = (tctx->flags & DNS_STYLEFLAG_SVCPARAMKEYCOMPAT) != 0;
	bool first = true;

	REQUIRE(rdata->length != 0);

	dns_rdata_toregion(rdata, &region);

	while (region.length > 0) {
		isc_region_t r;
		enum deleg_encoding encoding;

		if (!first) {
			RETERR(str_totext(" ", target));
		}
		first = false;

		INSIST(region.length >= 2);
		num = uint16_fromregion(&region);
		isc_region_consume(&region, 2);
		RETERR(str_totext(
			deleginfokey(num, &encoding, buf, sizeof(buf), compat),
			target));

		INSIST(region.length >= 2);
		num = uint16_fromregion(&region);
		isc_region_consume(&region, 2);

		INSIST(region.length >= num);
		r = region;
		r.length = num;
		isc_region_consume(&region, num);
		if (num == 0) {
			continue;
		}
		RETERR(str_totext("=", target));
		switch (encoding) {
		case deleg_ipv4:
			while (r.length > 0U) {
				INSIST(r.length >= 4U);
				inet_ntop(AF_INET, r.base, buf, sizeof(buf));
				RETERR(str_totext(buf, target));
				isc_region_consume(&r, 4);
				if (r.length != 0U) {
					RETERR(str_totext(",", target));
				}
			}
			break;
		case deleg_ipv6:
			while (r.length > 0U) {
				INSIST(r.length >= 16U);
				inet_ntop(AF_INET6, r.base, buf, sizeof(buf));
				RETERR(str_totext(buf, target));
				isc_region_consume(&r, 16);
				if (r.length != 0U) {
					RETERR(str_totext(",", target));
				}
			}
			break;
		case deleg_namelist:
			while (r.length > 0U) {
				dns_fixedname_t fn;
				dns_name_t *name = dns_fixedname_initname(&fn);
				isc_buffer_t b;

				isc_buffer_init(&b, r.base, r.length);
				isc_buffer_add(&b, r.length);
				RETERR(dns_name_fromwire(
					name, &b, DNS_DECOMPRESS_NEVER, NULL));
				RETERR(dns_name_totext(name, 0, target));

				isc_region_consume(
					&r, isc_buffer_consumedlength(&b));
				if (r.length != 0U) {
					RETERR(str_totext(",", target));
				}
			}
			break;
		case deleg_unknown:
			RETERR(multitxt_totext(&r, false, target));
			break;
		default:
			UNREACHABLE();
		}
	}
	return ISC_R_SUCCESS;
}

static isc_result_t
generic_fromwire_in_deleg(ARGS_FROMWIRE) {
	dns_name_t name;
	isc_region_t region;
	bool first = true;
	uint16_t lastkey = 0;

	UNUSED(type);
	UNUSED(rdclass);

	dctx = dns_decompress_setpermitted(dctx, false);

	dns_name_init(&name);

	/*
	 * DelegInfos
	 */
	isc_buffer_activeregion(source, &region);
	if (region.length < 2) {
		return ISC_R_UNEXPECTEDEND;
	}

	while (region.length > 0U) {
		isc_region_t keyregion;
		uint16_t key, len;

		/*
		 * DelegInfoKey
		 */
		if (region.length < 2U) {
			return ISC_R_UNEXPECTEDEND;
		}
		RETERR(mem_tobuffer(target, region.base, 2));
		key = uint16_fromregion(&region);
		isc_region_consume(&region, 2);

		/*
		 * Keys must be unique and in order.
		 */
		if (!first && key <= lastkey) {
			return DNS_R_FORMERR;
		}

		first = false;
		lastkey = key;

		/*
		 * DelegInfoValue length.
		 */
		if (region.length < 2U) {
			return ISC_R_UNEXPECTEDEND;
		}
		RETERR(mem_tobuffer(target, region.base, 2));
		len = uint16_fromregion(&region);
		isc_region_consume(&region, 2);

		/*
		 * DelegInfoValue.
		 */
		if (region.length < len) {
			return ISC_R_UNEXPECTEDEND;
		}

		keyregion = region;
		keyregion.length = len;
		RETERR(deleg_validate(key, &keyregion));
		RETERR(mem_tobuffer(target, region.base, len));
		isc_region_consume(&region, len);
		isc_buffer_forward(source, len + 4);
	}

	return ISC_R_SUCCESS;
}

static isc_result_t
generic_towire_in_deleg(ARGS_TOWIRE) {
	isc_region_t region;

	REQUIRE(rdata->length != 0);

	dns_compress_setpermitted(cctx, false);

	/*
	 * DelegInfos.
	 */
	dns_rdata_toregion(rdata, &region);
	return mem_tobuffer(target, region.base, region.length);
}

static isc_result_t
generic_fromstruct_in_deleg(ARGS_FROMSTRUCT) {
	dns_rdata_in_deleg_t *deleg = source;

	REQUIRE(deleg != NULL);
	REQUIRE(deleg->common.rdtype == type);
	REQUIRE(deleg->common.rdclass == rdclass);

	UNUSED(type);
	UNUSED(rdclass);

	return mem_tobuffer(target, deleg->dinfo, deleg->dinfolen);
}

static isc_result_t
generic_tostruct_in_deleg(ARGS_TOSTRUCT) {
	isc_region_t region;
	dns_rdata_in_deleg_t *deleg = target;

	REQUIRE(deleg != NULL);
	REQUIRE(rdata->length != 0);

	DNS_RDATACOMMON_INIT(deleg, rdata->type, rdata->rdclass);

	dns_rdata_toregion(rdata, &region);

	deleg->dinfolen = region.length;
	deleg->dinfo = mem_maybedup(mctx, region.base, region.length);

	deleg->offset = 0;
	deleg->mctx = mctx;

	return ISC_R_SUCCESS;
}

static void
generic_freestruct_in_deleg(ARGS_FREESTRUCT) {
	dns_rdata_in_deleg_t *deleg = source;

	REQUIRE(deleg != NULL);

	if (deleg->mctx == NULL) {
		return;
	}

	isc_mem_free(deleg->mctx, deleg->dinfo);
	deleg->mctx = NULL;
}

static bool
generic_checknames_in_deleg(ARGS_CHECKNAMES) {
	isc_region_t region;
	dns_name_t name;
	bool alias;

	UNUSED(owner);

	dns_rdata_toregion(rdata, &region);
	INSIST(region.length > 1);
	alias = uint16_fromregion(&region) == 0;
	isc_region_consume(&region, 2);
	dns_name_init(&name);
	dns_name_fromregion(&name, &region);
	if (!alias && !dns_name_ishostname(&name, false)) {
		if (bad != NULL) {
			dns_name_clone(&name, bad);
		}
		return false;
	}
	return true;
}

static isc_result_t
generic_rdata_in_deleg_first(dns_rdata_in_deleg_t *deleg) {
	if (deleg->dinfolen == 0) {
		return ISC_R_NOMORE;
	}
	deleg->offset = 0;
	return ISC_R_SUCCESS;
}

static isc_result_t
generic_rdata_in_deleg_next(dns_rdata_in_deleg_t *deleg) {
	isc_region_t region;
	size_t len;

	if (deleg->offset >= deleg->dinfolen) {
		return ISC_R_NOMORE;
	}

	region.base = deleg->dinfo + deleg->offset;
	region.length = deleg->dinfolen - deleg->offset;
	INSIST(region.length >= 4);
	isc_region_consume(&region, 2);
	len = uint16_fromregion(&region);
	INSIST(region.length >= len + 2);
	deleg->offset += len + 4;
	return deleg->offset >= deleg->dinfolen ? ISC_R_NOMORE : ISC_R_SUCCESS;
}

static void
generic_rdata_in_deleg_current(dns_rdata_in_deleg_t *deleg,
			       isc_region_t *region) {
	size_t len;

	INSIST(deleg->offset <= deleg->dinfolen);

	region->base = deleg->dinfo + deleg->offset;
	region->length = deleg->dinfolen - deleg->offset;
	INSIST(region->length >= 4);
	isc_region_consume(region, 2);
	len = uint16_fromregion(region);
	INSIST(region->length >= len + 2);
	region->base = deleg->dinfo + deleg->offset;
	region->length = len + 4;
}

static isc_result_t
fromtext_in_deleg(ARGS_FROMTEXT) {
	REQUIRE(type == dns_rdatatype_deleg);
	REQUIRE(rdclass == dns_rdataclass_in);

	return generic_fromtext_in_deleg(CALL_FROMTEXT);
}

static isc_result_t
totext_in_deleg(ARGS_TOTEXT) {
	REQUIRE(rdata->type == dns_rdatatype_deleg);
	REQUIRE(rdata->rdclass == dns_rdataclass_in);
	REQUIRE(rdata->length != 0);

	return generic_totext_in_deleg(CALL_TOTEXT);
}

static isc_result_t
fromwire_in_deleg(ARGS_FROMWIRE) {
	REQUIRE(type == dns_rdatatype_deleg);
	REQUIRE(rdclass == dns_rdataclass_in);

	return generic_fromwire_in_deleg(CALL_FROMWIRE);
}

static isc_result_t
towire_in_deleg(ARGS_TOWIRE) {
	REQUIRE(rdata->type == dns_rdatatype_deleg);
	REQUIRE(rdata->length != 0);

	return generic_towire_in_deleg(CALL_TOWIRE);
}

static int
compare_in_deleg(ARGS_COMPARE) {
	isc_region_t region1;
	isc_region_t region2;

	REQUIRE(rdata1->type == rdata2->type);
	REQUIRE(rdata1->rdclass == rdata2->rdclass);
	REQUIRE(rdata1->type == dns_rdatatype_deleg);
	REQUIRE(rdata1->rdclass == dns_rdataclass_in);
	REQUIRE(rdata1->length != 0);
	REQUIRE(rdata2->length != 0);

	dns_rdata_toregion(rdata1, &region1);
	dns_rdata_toregion(rdata2, &region2);

	return isc_region_compare(&region1, &region2);
}

static isc_result_t
fromstruct_in_deleg(ARGS_FROMSTRUCT) {
	dns_rdata_in_deleg_t *deleg = source;

	REQUIRE(type == dns_rdatatype_deleg);
	REQUIRE(rdclass == dns_rdataclass_in);
	REQUIRE(deleg != NULL);
	REQUIRE(deleg->common.rdtype == type);
	REQUIRE(deleg->common.rdclass == rdclass);

	return generic_fromstruct_in_deleg(CALL_FROMSTRUCT);
}

static isc_result_t
tostruct_in_deleg(ARGS_TOSTRUCT) {
	dns_rdata_in_deleg_t *deleg = target;

	REQUIRE(rdata->rdclass == dns_rdataclass_in);
	REQUIRE(rdata->type == dns_rdatatype_deleg);
	REQUIRE(deleg != NULL);
	REQUIRE(rdata->length != 0);

	return generic_tostruct_in_deleg(CALL_TOSTRUCT);
}

static void
freestruct_in_deleg(ARGS_FREESTRUCT) {
	dns_rdata_in_deleg_t *deleg = source;

	REQUIRE(deleg != NULL);
	REQUIRE(deleg->common.rdclass == dns_rdataclass_in);
	REQUIRE(deleg->common.rdtype == dns_rdatatype_deleg);

	generic_freestruct_in_deleg(CALL_FREESTRUCT);
}

static isc_result_t
additionaldata_in_deleg(ARGS_ADDLDATA) {
	REQUIRE(rdata->type == dns_rdatatype_deleg);
	REQUIRE(rdata->rdclass == dns_rdataclass_in);

	UNUSED(rdata);
	UNUSED(owner);
	UNUSED(add);
	UNUSED(arg);

	return ISC_R_SUCCESS;
}

static isc_result_t
digest_in_deleg(ARGS_DIGEST) {
	isc_region_t region1;

	REQUIRE(rdata->type == dns_rdatatype_deleg);
	REQUIRE(rdata->rdclass == dns_rdataclass_in);

	dns_rdata_toregion(rdata, &region1);
	return (digest)(arg, &region1);
}

static bool
checkowner_in_deleg(ARGS_CHECKOWNER) {
	REQUIRE(type == dns_rdatatype_deleg);
	REQUIRE(rdclass == dns_rdataclass_in);

	return true;
}

static bool
checknames_in_deleg(ARGS_CHECKNAMES) {
	REQUIRE(rdata->type == dns_rdatatype_deleg);
	REQUIRE(rdata->rdclass == dns_rdataclass_in);

	return generic_checknames_in_deleg(CALL_CHECKNAMES);
}

static int
casecompare_in_deleg(ARGS_COMPARE) {
	return compare_in_deleg(rdata1, rdata2);
}

isc_result_t
dns_rdata_in_deleg_first(dns_rdata_in_deleg_t *deleg) {
	REQUIRE(deleg != NULL);
	REQUIRE(deleg->common.rdtype == dns_rdatatype_deleg);
	REQUIRE(deleg->common.rdclass == dns_rdataclass_in);

	return generic_rdata_in_deleg_first(deleg);
}

isc_result_t
dns_rdata_in_deleg_next(dns_rdata_in_deleg_t *deleg) {
	REQUIRE(deleg != NULL);
	REQUIRE(deleg->common.rdtype == dns_rdatatype_deleg);
	REQUIRE(deleg->common.rdclass == dns_rdataclass_in);

	return generic_rdata_in_deleg_next(deleg);
}

void
dns_rdata_in_deleg_current(dns_rdata_in_deleg_t *deleg, isc_region_t *region) {
	REQUIRE(deleg != NULL);
	REQUIRE(deleg->common.rdtype == dns_rdatatype_deleg);
	REQUIRE(deleg->common.rdclass == dns_rdataclass_in);
	REQUIRE(region != NULL);

	generic_rdata_in_deleg_current(deleg, region);
}
