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

#include <locale.h>

#include <isc/lex.h>
#include <isc/string.h>
#include <isc/types.h>

#ifdef HAVE_LIBIDN2
#include <idn2.h>
#endif /* HAVE_LIBIDN2 */

#include <dns/name.h>
#include <dns/psl.h>
#include <dns/rdatalist.h>
#include <dns/types.h>

#define TOKENSIZ (8 * 1024)
#define MXNAME	 (DNS_NAME_MAXTEXT + 1)

#define CHECK(x)                               \
	{                                      \
		result = (x);                  \
		if (result != ISC_R_SUCCESS) { \
			goto cleanup;          \
		}                              \
	}

#define AS_STR(x) (x).value.as_textregion.base

#ifdef HAVE_LIBIDN2
static void
idn_input(const char *src, char *dst, size_t dstlen) {
	char *ascii = NULL;
	size_t len;
	int res;

	/*
	 * We trust libidn2 to return an error if 'src' is too large to be a
	 * valid domain name.
	 *
	 * If conversion fails under IDNA2008 rules, retry with transitional
	 * rules. The aim is that characters whose interpretation changed will
	 * be handled under the new rules, but we will accept characters (such
	 * as emoji) that were OK but are now forbidden.
	 */
	(void)setlocale(LC_ALL, "");
	res = idn2_to_ascii_lz(src, &ascii, IDN2_NONTRANSITIONAL);
	if (res == IDN2_DISALLOWED) {
		res = idn2_to_ascii_lz(src, &ascii, IDN2_TRANSITIONAL);
	}
	(void)setlocale(LC_ALL, "C");

	/*
	 * idn2_to_ascii_lz() normalizes all strings to lower case, but
	 * we generally don't want to lowercase all input strings; make
	 * sure to return the original case if the two strings differ
	 * only in case.
	 */
	if (res == IDN2_OK && strcasecmp(src, ascii) != 0) {
		len = strlcpy(dst, ascii, dstlen);
	} else {
		len = strlcpy(dst, src, dstlen);
	}
	INSIST(len < dstlen);
	idn2_free(ascii);
}
#endif

isc_result_t
dns_psl_fromfile(const char *file, isc_mem_t *mctx, dns_db_t **psl) {
	bool bang = false;
	bool done = false;
	bool eol = false;
	bool skip = false;
	const char *s;
	dns_db_t *db = NULL;
	dns_dbnode_t *node = NULL;
	dns_dbversion_t *version = NULL;
	dns_fixedname_t fixed;
	dns_name_t *name = dns_fixedname_initname(&fixed);
	isc_lex_t *lex = NULL;
	isc_result_t result;
	isc_token_t token;
	unsigned int options = ISC_LEXOPT_EOL | ISC_LEXOPT_EOF;
	unsigned int records = 0;
	unsigned char data[4] = { 0 };

	REQUIRE(file != NULL);
	REQUIRE(psl != NULL && *psl == NULL);

	CHECK(dns_db_create(mctx, ZONEDB_DEFAULT, dns_rootname, dns_dbtype_zone,
			    dns_rdataclass_in, 0, NULL, &db));
	CHECK(dns_db_newversion(db, &version));

	isc_lex_create(mctx, TOKENSIZ, &lex);
	CHECK(isc_lex_openfile(lex, file));

	do {
		dns_rdata_t rdata = DNS_RDATA_INIT;
		dns_rdatalist_t rdatalist;
		dns_rdataset_t rdataset = DNS_RDATASET_INIT;

		CHECK(isc_lex_gettoken(lex, options, &token));
		switch (token.type) {
		case isc_tokentype_eof:
			done = true;
			break;
		case isc_tokentype_eol:
			skip = false;
			eol = true;
			break;
		case isc_tokentype_string:
			eol = false;
			if (skip) {
				break;
			}
			s = AS_STR(token);
			if (strncmp(s, "//", 2) == 0) {
				skip = true;
				break;
			}
			if (strncmp(s, "!", 1) == 0) {
				bang = true;
				s++;
			} else {
				bang = false;
			}
#ifdef HAVE_LIBIDN2
			char idn_textname[MXNAME];
			idn_input(s, idn_textname, sizeof(idn_textname));
			s = idn_textname;
#else
			if (strspn(s, "*.-"
				      "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN"
				      "OPQRSTUVWXYZ0123456789") != strlen(s))
			{
				fprintf(stderr,
					"psl: dropped non LDH name: %s\n", s);
				break;
			}
#endif
			result = dns_name_fromstring(name, s, dns_rootname, 0,
						     NULL);
			if (result != ISC_R_SUCCESS) {
				fprintf(stderr,
					"%s:%lu: dns_name_fromstring failed: "
					"%s\n",
					file, isc_lex_getsourceline(lex),
					isc_result_totext(result));
				break;
			}
			if (bang) {
				data[3] = 0;
			} else {
				data[3] = dns_name_countlabels(name);
			}
			rdata.type = dns_rdatatype_a;
			rdata.rdclass = dns_rdataclass_in;
			rdata.data = data;
			rdata.length = sizeof(data);
			dns_rdatalist_init(&rdatalist);
			rdatalist.type = rdata.type;
			rdatalist.rdclass = rdata.rdclass;
			rdatalist.ttl = 0;
			ISC_LIST_APPEND(rdatalist.rdata, &rdata, link);
			dns_rdatalist_tordataset(&rdatalist, &rdataset);
			CHECK(dns_db_findnode(db, name, true, &node));
			CHECK(dns_db_addrdataset(db, node, version, 0,
						 &rdataset, 0, NULL));
			fprintf(stderr, "%s A %u.%u.%u.%u\n", s, data[0],
				data[1], data[2], data[3]);
			dns_db_detachnode(&node);
			records++;
			break;
		default:
			eol = false;
			done = true;
		}
	} while (!done);

	isc_lex_close(lex);

	if (eol && records != 0) {
		dns_db_closeversion(db, &version, true);
		*psl = db;
		db = NULL;
		fprintf(stderr, "found %u psl records\n", records);
		result = ISC_R_SUCCESS;
	}

cleanup:
	if (lex != NULL) {
		isc_lex_destroy(&lex);
	}
	if (version != NULL) {
		dns_db_closeversion(db, &version, false);
	}
	if (node != NULL) {
		dns_db_detachnode(&node);
	}
	if (db != NULL) {
		dns_db_detach(&db);
	}
	return result;
}
