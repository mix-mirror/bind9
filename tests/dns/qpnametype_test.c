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

#include <inttypes.h>
#include <sched.h> /* IWYU pragma: keep */
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define UNIT_TESTING
#include <cmocka.h>

#include <isc/lib.h>
#include <isc/random.h>
#include <isc/refcount.h>
#include <isc/result.h>
#include <isc/string.h>
#include <isc/urcu.h>
#include <isc/util.h>

#include <dns/lib.h>
#include <dns/name.h>
#include <dns/qp.h>

#include "qp_p.h"

#include <tests/dns.h>
#include <tests/qp.h>

#define DBNS_NORMAL DNS_DBNAMESPACE_NORMAL
#define DBNS_NSEC   DNS_DBNAMESPACE_NSEC
#define DBNS_NSEC3  DNS_DBNAMESPACE_NSEC3

#define NAMESPACESTR(s) \
	(s) == DBNS_NSEC3 ? "NSEC3:" : ((s) == DBNS_NSEC ? "NSEC:" : "")

ISC_RUN_TEST_IMPL(qpkey_name) {
	struct {
		const char *namestr;
		dns_rdatatype_t type;
		dns_namespace_t space;
		uint8_t key[512];
		size_t len;
	} testcases[] = {
		{
			.namestr = "",
			.type = 0,
			.space = DBNS_NORMAL,
			.key = { 0x08, 0x03, 0x03, 0x03, 0x03, 0x02 },
			.len = 1 + QPKEYTYPELEN,
		},
		{
			.namestr = ".",
			.type = 1,
			.space = DBNS_NORMAL,
			.key = { 0x08, 0x02, 0x03, 0x03, 0x03, 0x04, 0x02 },
			.len = 2 + QPKEYTYPELEN,
		},
		{
			.namestr = "\\000",
			.type = 55,
			.space = DBNS_NORMAL,
			.key = { 0x08, 0x04, 0x04, 0x02, 0x03, 0x03, 0x04, 0x0b,
				 0x02 },
			.len = 4 + QPKEYTYPELEN,
		},
		{
			.namestr = "\\000\\009",
			.type = 252,
			.space = DBNS_NORMAL,
			.key = { 0x08, 0x04, 0x04, 0x04, 0x0d, 0x02, 0x03, 0x03,
				 0x08, 0x14, 0x02 },
			.len = 6 + QPKEYTYPELEN,
		},
		{
			.namestr = "com",
			.type = 253,
			.space = DBNS_NORMAL,
			.key = { 0x08, 0x17, 0x23, 0x21, 0x02, 0x03, 0x03, 0x08,
				 0x15, 0x02 },
			.len = 5 + QPKEYTYPELEN,
		},
		{
			.namestr = "com.",
			.type = 1234,
			.space = DBNS_NSEC,
			.key = { 0x09, 0x02, 0x17, 0x23, 0x21, 0x02, 0x03, 0x03,
				 0x1d, 0x0f, 0x02 },
			.len = 6 + QPKEYTYPELEN,
		},
		{
			.namestr = "com.",
			.type = 1234,
			.space = DBNS_NSEC3,
			.key = { 0x0a, 0x02, 0x17, 0x23, 0x21, 0x02, 0x03, 0x03,
				 0x1d, 0x0f, 0x02 },
			.len = 6 + QPKEYTYPELEN,
		},
		{
			.namestr = "com.",
			.type = 1234,
			.space = DBNS_NORMAL,
			.key = { 0x08, 0x02, 0x17, 0x23, 0x21, 0x02, 0x03, 0x03,
				 0x1d, 0x0f, 0x02 },
			.len = 6 + QPKEYTYPELEN,
		},
		{
			.namestr = "example.com.",
			.type = 34567,
			.space = DBNS_NORMAL,
			.key = { 0x08, 0x02, 0x17, 0x23, 0x21, 0x02, 0x19, 0x2c,
				 0x15, 0x21, 0x24, 0x20, 0x19, 0x02, 0x03, 0x12,
				 0x21, 0x19, 0x02 },
			.len = 14 + QPKEYTYPELEN,
		},
		{
			.namestr = "example.com",
			.type = 65534,
			.space = DBNS_NORMAL,
			.key = { 0x08, 0x17, 0x23, 0x21, 0x02, 0x19, 0x2c, 0x15,
				 0x21, 0x24, 0x20, 0x19, 0x02, 0x03, 0x20, 0x22,
				 0x13, 0x02 },
			.len = 13 + QPKEYTYPELEN,
		},
		{
			.namestr = "EXAMPLE.COM",
			.type = 65535,
			.space = DBNS_NORMAL,
			.key = { 0x08, 0x17, 0x23, 0x21, 0x02, 0x19, 0x2c, 0x15,
				 0x21, 0x24, 0x20, 0x19, 0x02, 0x03, 0x20, 0x22,
				 0x14, 0x02 },
			.len = 13 + QPKEYTYPELEN,
		},
	};

	for (size_t i = 0; i < ARRAY_SIZE(testcases); i++) {
		size_t len;
		dns_qpkey_t key;
		dns_fixedname_t fn1, fn2;
		dns_name_t *in = NULL, *out = NULL;
		dns_rdatatype_t type;
		dns_namespace_t space;

		in = dns_fixedname_initname(&fn1);
		if (testcases[i].len > 1 + QPKEYTYPELEN) {
			dns_test_namefromstring(testcases[i].namestr, &fn1);
		}
		len = dns_qpkey_fromnametype(key, in, testcases[i].type,
					     testcases[i].space);
#if 0
		fprintf(stderr, "qpkey_name: %s len %lu\n", testcases[i].namestr, len);
		qp_test_printkey(key, len);
#endif

		assert_int_equal(testcases[i].len, len);
		assert_memory_equal(testcases[i].key, key, len);

		out = dns_fixedname_initname(&fn2);
		dns_qpkey_tonametype(key, len, out, &type, &space);
		assert_true(dns_name_equal(in, out));
		assert_int_equal(type, testcases[i].type);
		assert_int_equal(space, testcases[i].space);
	}
}

#define SORTCASE(n, t, s)       \
	{                       \
		.namestr = (n), \
		.type = (t),    \
		.space = (s),   \
	}

#define SORTCASES(n, s)                                                       \
	SORTCASE((n), 1, (s)), SORTCASE((n), 2, (s)), SORTCASE((n), 48, (s)), \
		SORTCASE((n), 236, (s)), SORTCASE((n), 60021, (s))

ISC_RUN_TEST_IMPL(qpkey_sort) {
	struct {
		const char *namestr;
		dns_name_t *name;
		dns_fixedname_t fixed;
		dns_rdatatype_t type;
		dns_namespace_t space;
		size_t len;
		dns_qpkey_t key;
	} testcases[] = { SORTCASES(".", DBNS_NORMAL),
			  SORTCASES("\\000.", DBNS_NORMAL),
			  SORTCASES("\\000.\\000.", DBNS_NORMAL),
			  SORTCASES("\\000.\\009.", DBNS_NORMAL),
			  SORTCASES("\\007.", DBNS_NORMAL),
			  SORTCASES("example.com.", DBNS_NORMAL),
			  SORTCASES("EXAMPLE.COM.", DBNS_NORMAL),
			  SORTCASES("www.example.com.", DBNS_NORMAL),
			  SORTCASES("exam.com.", DBNS_NORMAL),
			  SORTCASES("exams.com.", DBNS_NORMAL),
			  SORTCASES("exam\\000.com.", DBNS_NORMAL),
			  SORTCASES("exam.com.", DBNS_NSEC),
			  SORTCASES("exams."
				    "com.",
				    DBNS_NSEC),
			  SORTCASES("exam.com.", DBNS_NSEC3),
			  SORTCASES("exams.com.", DBNS_NSEC3) };

	for (size_t i = 0; i < ARRAY_SIZE(testcases); i++) {
		dns_test_namefromstring(testcases[i].namestr,
					&testcases[i].fixed);
		testcases[i].name = dns_fixedname_name(&testcases[i].fixed);
		testcases[i].len = dns_qpkey_fromnametype(
			testcases[i].key, testcases[i].name, testcases[i].type,
			testcases[i].space);
	}

	for (size_t i = 0; i < ARRAY_SIZE(testcases); i++) {
		for (size_t j = 0; j < ARRAY_SIZE(testcases); j++) {
			int namecmp = dns_name_compare(testcases[i].name,
						       testcases[j].name);
			int typecmp = testcases[i].type < testcases[j].type ? -1
				      : testcases[i].type > testcases[j].type
					      ? 1
					      : 0;

			size_t len = ISC_MIN(testcases[i].len,
					     testcases[j].len);
			/* include extra terminating NOBYTE */
			int keycmp = memcmp(testcases[i].key, testcases[j].key,
					    len + 1);
			if (testcases[i].space == testcases[j].space) {
				if (namecmp == 0) {
					assert_true((typecmp < 0) ==
						    (keycmp < 0));
					assert_true((typecmp > 0) ==
						    (keycmp > 0));
					assert_true((typecmp == 0) ==
						    (keycmp == 0));
				} else {
					assert_true((namecmp < 0) ==
						    (keycmp < 0));
					assert_true((namecmp > 0) ==
						    (keycmp > 0));
				}
			} else {
				uint8_t di = testcases[i].space;
				uint8_t dj = testcases[j].space;
				assert_true((di < dj) == (keycmp < 0));
				assert_true((di > dj) == (keycmp > 0));
			}
		}
	}
}

static void
getname(void *uctx, char *buf, size_t size) {
	strlcpy(buf, "test", size);
	UNUSED(uctx);
	UNUSED(size);
}

static void
no_op(void *uctx, void *pval, uint32_t ival) {
	UNUSED(uctx);
	UNUSED(pval);
	UNUSED(ival);
}

static size_t
qpkey_fromstring(dns_qpkey_t key, void *uctx, void *pval, uint32_t ival) {
	dns_fixedname_t fixed;
	dns_namespace_t space = ival & 0x0f;
	dns_rdatatype_t type = ival >> 16;

	UNUSED(uctx);
	if (*(char *)pval == '\0') {
		size_t i = 0;
		key[i++] = SHIFT_RRTYPE;
		key[i++] = SHIFT_RRTYPE;
		key[i++] = SHIFT_RRTYPE;
		key[i++] = SHIFT_RRTYPE;
		key[i] = SHIFT_NOBYTE;
		return i;
	}
	dns_test_namefromstring(pval, &fixed);
	return dns_qpkey_fromnametype(key, dns_fixedname_name(&fixed), type,
				      space);
}

const dns_qpmethods_t string_methods = {
	no_op,
	no_op,
	qpkey_fromstring,
	getname,
};

struct check_partialmatch {
	const char *name;
	dns_rdatatype_t type;
	isc_result_t result;
	const char *found;
};

static void
check_partialmatch(dns_qp_t *qp, struct check_partialmatch check[],
		   dns_namespace_t space) {
	for (int i = 0; check[i].name != NULL; i++) {
		isc_result_t result;
		dns_fixedname_t fn1, fn2;
		dns_name_t *name = dns_fixedname_initname(&fn1);
		dns_name_t *foundname = dns_fixedname_initname(&fn2);
		void *pval = NULL;
		uint32_t ival = 0;

		dns_test_namefromstring(check[i].name, &fn1);
		result = dns_qp_lookup(qp, name, check[i].type, space,
				       foundname, NULL, NULL, &pval, &ival);

#if 0
		fprintf(stderr,
			"%s%s type %u result %s (expected %s) "
			"value \"%s\" (expected \"%s\")\n",
			NAMESPACESTR(space),
			check[i].name, check[i].type, isc_result_totext(result),
			isc_result_totext(check[i].result), (char *)pval,
			check[i].found);
#endif

		assert_int_equal(result, check[i].result);
		if (result == ISC_R_SUCCESS) {
			assert_true(dns_name_equal(name, foundname));
			assert_true(space == (ival & 0x0f));
			assert_true(check[i].type == (ival >> 16));
		} else if (result == DNS_R_PARTIALMATCH) {
			/*
			 * there are cases where we may have passed a
			 * query name that was relative to the zone apex,
			 * and gotten back an absolute name from the
			 * partial match. it's also possible for an
			 * absolute query to get a partial match on a
			 * node that had an empty name. in these cases,
			 * sanity checking the relations between name
			 * and foundname can trigger an assertion, so
			 * let's just skip them.
			 */
			if (dns_name_isabsolute(name) ==
			    dns_name_isabsolute(foundname))
			{
				assert_false(dns_name_equal(name, foundname));
				assert_true(
					dns_name_issubdomain(name, foundname));
			}
			/* ensure same namespace */
			assert_true(space == (ival & 0x0f));
		}
		if (check[i].found == NULL) {
			assert_null(pval);
		} else {
			assert_string_equal(pval, check[i].found);
		}
	}
}

struct inserting {
	/* Fixed size strings [32] should ensure leaf-compatible alignment. */
	const char name[32];
	dns_rdatatype_t type;
	dns_namespace_t space;
	/* Padding */
	uint8_t pad;
};

static void
insert_nametype(dns_qp_t *qp, const char *str, dns_rdatatype_t type,
		dns_namespace_t space, bool verbose) {
	isc_result_t result;
	uintptr_t pval = (uintptr_t)str;
	uint32_t ival = (uint32_t)(type << 16) | space;

	if (verbose) {
		fprintf(stderr, "INSERT: %lx name %s type %u space %u\n", pval,
			str, type, space);
	}
	INSIST((pval & 3) == 0);
	result = dns_qp_insert(qp, (void *)pval, ival);
	assert_int_equal(result, ISC_R_SUCCESS);
}

static void
delete_rootkey(dns_qp_t *qp, dns_rdatatype_t type, dns_namespace_t space) {
	uint8_t d = dns_qp_bits_for_byte[space + 48];
	dns_qpkey_t rootkey = { d,
				SHIFT_NOBYTE,
				SHIFT_RRTYPE,
				SHIFT_RRTYPE,
				SHIFT_RRTYPE,
				SHIFT_RRTYPE + type,
				SHIFT_NOBYTE };

	isc_result_t result = dns_qp_deletekey(qp, rootkey, 6, NULL, NULL);
	assert_int_equal(result, ISC_R_SUCCESS);
}

#define INSERT(n, t, s) { (n), (t), (s) }

#define INSERTING(n, t)                                             \
	INSERT((n), (t), DBNS_NORMAL), INSERT((n), (t), DBNS_NSEC), \
		INSERT((n), (t), DBNS_NSEC3)

ISC_RUN_TEST_IMPL(partialmatch) {
	dns_qp_t *qp = NULL;
	int i = 0;

	dns_qp_create(mctx, &string_methods, NULL, &qp);

	static struct inserting insert[] = {
		INSERTING("a.b.", 1),
		INSERTING("a.b.", 60021),
		INSERTING("b.", 0),
		INSERTING("b.", 48),
		INSERTING("fo.bar.", 1),
		INSERTING("foo.bar.", 1),
		INSERTING("foo.bar.", 2),
		INSERTING("foo.bar.", 48),
		INSERTING("foo.bar.", 236),
		INSERTING("foo.bar.", 60021),
		INSERTING("fooo.bar.", 1),
		INSERTING("fooo.bar.", 2),
		INSERTING("web.foo.bar.", 18),
		INSERTING("web.foo.bar.", 303),
		INSERTING(".", 1),
		INSERTING("", 1),
	};

	/*
	 * omit the root node for now, otherwise we'll get "partial match"
	 * results when we want "not found".
	 */
	while (insert[i].name[0] != '.') {
		insert_nametype(qp, insert[i].name, insert[i].type,
				insert[i].space, false);
		i++;
	}

	static struct check_partialmatch check1[] = {
		{ "a.b.", 0, DNS_R_NODATA, "a.b." },
		{ "a.b.", 1, ISC_R_SUCCESS, "a.b." },
		{ "a.b.", 3, DNS_R_NODATA, "a.b." },

		{ "b.c.", 404, ISC_R_NOTFOUND, NULL },

		{ "bar.", 1, ISC_R_NOTFOUND, NULL },

		{ "f.bar.", 0, ISC_R_NOTFOUND, NULL },

		{ "fo.bar.", 1, ISC_R_SUCCESS, "fo.bar." },

		{ "foo.bar.", 1, ISC_R_SUCCESS, "foo.bar." },
		{ "foo.bar.", 2, ISC_R_SUCCESS, "foo.bar." },
		{ "foo.bar.", 48, ISC_R_SUCCESS, "foo.bar." },
		{ "foo.bar.", 236, ISC_R_SUCCESS, "foo.bar." },
		{ "foo.bar.", 60021, ISC_R_SUCCESS, "foo.bar." },
		{ "foo.bar.", 0, DNS_R_NODATA, "foo.bar." },
		{ "foo.bar.", 3, DNS_R_NODATA, "foo.bar." },
		{ "foo.bar.", 60020, DNS_R_NODATA, "foo.bar." },

		{ "foooo.bar.", 3, ISC_R_NOTFOUND, NULL },

		{ "w.foo.bar.", 1, DNS_R_PARTIALMATCH, "foo.bar." },
		{ "w.foo.bar.", 3, DNS_R_PARTIALMATCH, "foo.bar." },

		{ "www.foo.bar.", 1, DNS_R_PARTIALMATCH, "foo.bar." },
		{ "www.foo.bar.", 3, DNS_R_PARTIALMATCH, "foo.bar." },

		{ "web.foo.bar.", 18, ISC_R_SUCCESS, "web.foo.bar." },
		{ "web.foo.bar.", 17, DNS_R_NODATA, "web.foo.bar." },
		{ "web.foo.bar.", 19, DNS_R_NODATA, "web.foo.bar." },

		{ "webby.foo.bar.", 18, DNS_R_PARTIALMATCH, "foo.bar." },
		{ "webby.foo.bar.", 19, DNS_R_PARTIALMATCH, "foo.bar." },

		{ "my.web.foo.bar.", 18, DNS_R_PARTIALMATCH, "web.foo.bar." },
		{ "my.web.foo.bar.", 19, DNS_R_PARTIALMATCH, "web.foo.bar." },

		{ "my.other.foo.bar.", 1, DNS_R_PARTIALMATCH, "foo.bar." },
		{ "my.other.foo.bar.", 3, DNS_R_PARTIALMATCH, "foo.bar." },

		{ NULL, 0, 0, NULL },
	};
	check_partialmatch(qp, check1, DBNS_NORMAL);
	check_partialmatch(qp, check1, DBNS_NSEC);
	check_partialmatch(qp, check1, DBNS_NSEC3);

	/* what if the trie contains the root? */
	INSIST(insert[i].name[0] == '.');
	while (insert[i].name[0] != '\0') {
		insert_nametype(qp, insert[i].name, insert[i].type,
				insert[i].space, false);
		i++;
	}

	static struct check_partialmatch check2[] = {
		{ "b.c.", 1, DNS_R_PARTIALMATCH, "." },
		{ "bar.", 1, DNS_R_PARTIALMATCH, "." },
		{ "foo.bar.", 1, ISC_R_SUCCESS, "foo.bar." },
		{ "foo.bar.", 3, DNS_R_NODATA, "foo.bar." },
		{ "bar", 1, ISC_R_NOTFOUND, NULL },
		{ NULL, 0, 0, NULL },
	};
	check_partialmatch(qp, check2, DBNS_NORMAL);
	check_partialmatch(qp, check2, DBNS_NSEC);
	check_partialmatch(qp, check2, DBNS_NSEC3);

	/*
	 * what if entries in the trie are relative to the zone apex
	 * and there's no root node?
	 */
	delete_rootkey(qp, 1, DBNS_NORMAL);
	delete_rootkey(qp, 1, DBNS_NSEC);
	delete_rootkey(qp, 1, DBNS_NSEC3);

	static struct check_partialmatch check3[] = {
		{ "bar", 1, ISC_R_NOTFOUND, NULL },
		{ "bar.", 1, ISC_R_NOTFOUND, NULL },
		{ NULL, 0, 0, NULL },
	};
	check_partialmatch(qp, check3, DBNS_NORMAL);
	check_partialmatch(qp, check3, DBNS_NSEC);
	check_partialmatch(qp, check3, DBNS_NSEC3);

	dns_qp_destroy(&qp);
}

struct check_qpchain {
	const char *name;
	dns_rdatatype_t type;
	dns_namespace_t space;
	isc_result_t result;
	unsigned int length;
	const char *names[10];
};

static void
check_qpchainiter(dns_qp_t *qp, struct check_qpchain check[],
		  dns_qpiter_t *iter) {
	for (int i = 0; check[i].name != NULL; i++) {
		isc_result_t result;
		dns_fixedname_t fn1;
		dns_name_t *name = dns_fixedname_initname(&fn1);
		dns_rdatatype_t type = check[i].type;
		dns_namespace_t space = check[i].space;
		dns_qpchain_t chain;
		uint32_t ival = 0;

		dns_qpchain_init(qp, &chain);
		dns_test_namefromstring(check[i].name, &fn1);
		result = dns_qp_lookup(qp, name, type, space, NULL, iter,
				       &chain, NULL, &ival);
#if 0
		fprintf(stderr,
			"%s%s type %u result %s (expected %s), "
			"len %d (expected %d)\n",
			NAMESPACESTR(space), check[i].name, type,
			isc_result_totext(result),
			isc_result_totext(check[i].result),
			dns_qpchain_length(&chain), check[i].length);
#endif

		assert_int_equal(result, check[i].result);
		assert_int_equal(dns_qpchain_length(&chain), check[i].length);
		for (unsigned int j = 0; j < check[i].length; j++) {
			dns_fixedname_t fn2, fn3;
			dns_name_t *expected = dns_fixedname_initname(&fn2);
			dns_name_t *found = dns_fixedname_initname(&fn3);
			dns_test_namefromstring(check[i].names[j], &fn2);
			dns_qpchain_node(&chain, j, found, NULL, NULL);
#if 0
			char nb[DNS_NAME_FORMATSIZE];
			dns_name_format(found, nb, sizeof(nb));
			fprintf(stderr, "got %s, expected %s\n", nb,
				check[i].names[j]);
#endif
			assert_true(dns_name_equal(found, expected));
		}
	}
}

static void
check_qpchain(dns_qp_t *qp, struct check_qpchain check[]) {
	dns_qpiter_t iter;
	dns_qpiter_init(qp, &iter);
	check_qpchainiter(qp, check, NULL);
	check_qpchainiter(qp, check, &iter);
}

ISC_RUN_TEST_IMPL(qpchain) {
	int i = 0;
	dns_qp_t *qp = NULL;
	static struct inserting insert1[] = {
		INSERTING("a.", 53),	    INSERTING("b.", 1),
		INSERTING("b.", 2),	    INSERTING("b.", 50),
		INSERTING("b.", 250),	    INSERTING("b.", 65000),
		INSERTING("c.b.a.", 53),    INSERTING("e.d.c.b.a.", 1),
		INSERTING("c.b.b.", 2),	    INSERTING("c.d.", 3),
		INSERTING("a.b.c.d.", 1),   INSERTING("a.b.c.d.e.", 1),
		INSERTING("b.a.", 1),	    INSERTING("x.k.c.d.", 1),
		INSERTING("x.k.c.d.", 2),   INSERTING("x.k.c.d.", 50),
		INSERTING("x.k.c.d.", 250), INSERTING("x.k.c.d.", 65000),
		INSERTING(".", 1),	    INSERTING(".", 2),
		INSERTING(".", 50),	    INSERTING(".", 250),
		INSERTING(".", 65000),	    INSERTING("", 0),
	};

	dns_qp_create(mctx, &string_methods, NULL, &qp);

	while (insert1[i].name[0] != '\0') {
		insert_nametype(qp, insert1[i].name, insert1[i].type,
				insert1[i].space, false);
		i++;
	}

	static struct check_qpchain check1[] = {
		{ "b.", 1, DBNS_NORMAL, ISC_R_SUCCESS, 2, { ".", "b." } },
		{ "b.", 1, DBNS_NSEC, ISC_R_SUCCESS, 2, { ".", "b." } },
		{ "b.", 1, DBNS_NSEC3, ISC_R_SUCCESS, 2, { ".", "b." } },

		{ "b.", 249, DBNS_NORMAL, DNS_R_NODATA, 2, { ".", "b." } },
		{ "b.", 249, DBNS_NSEC, DNS_R_NODATA, 2, { ".", "b." } },
		{ "b.", 249, DBNS_NSEC3, DNS_R_NODATA, 2, { ".", "b." } },

		{ "b.a.",
		  1,
		  DBNS_NORMAL,
		  ISC_R_SUCCESS,
		  3,
		  { ".", "a.", "b.a." } },
		{ "b.a.", 1, DBNS_NSEC, ISC_R_SUCCESS, 3, { ".", "a.", "b.a." } },
		{ "b.a.",
		  1,
		  DBNS_NSEC3,
		  ISC_R_SUCCESS,
		  3,
		  { ".", "a.", "b.a." } },

		{ "b.a.",
		  2,
		  DBNS_NORMAL,
		  DNS_R_NODATA,
		  3,
		  { ".", "a.", "b.a." } },
		{ "b.a.", 2, DBNS_NSEC, DNS_R_NODATA, 3, { ".", "a.", "b.a." } },
		{ "b.a.", 2, DBNS_NSEC3, DNS_R_NODATA, 3, { ".", "a.", "b.a." } },

		{ "c.", 1, DBNS_NORMAL, DNS_R_PARTIALMATCH, 1, { "." } },
		{ "c.", 1, DBNS_NSEC, DNS_R_PARTIALMATCH, 1, { "." } },
		{ "c.", 1, DBNS_NSEC3, DNS_R_PARTIALMATCH, 1, { "." } },

		{ "e.d.c.b.a.",
		  1,
		  DBNS_NORMAL,
		  ISC_R_SUCCESS,
		  5,
		  { ".", "a.", "b.a.", "c.b.a.", "e.d.c.b.a." } },
		{ "e.d.c.b.a.",
		  1,
		  DBNS_NSEC,
		  ISC_R_SUCCESS,
		  5,
		  { ".", "a.", "b.a.", "c.b.a.", "e.d.c.b.a." } },
		{ "e.d.c.b.a.",
		  1,
		  DBNS_NSEC3,
		  ISC_R_SUCCESS,
		  5,
		  { ".", "a.", "b.a.", "c.b.a.", "e.d.c.b.a." } },

		{ "e.d.c.b.a.",
		  2,
		  DBNS_NORMAL,
		  DNS_R_NODATA,
		  5,
		  { ".", "a.", "b.a.", "c.b.a.", "e.d.c.b.a." } },
		{ "e.d.c.b.a.",
		  2,
		  DBNS_NSEC,
		  DNS_R_NODATA,
		  5,
		  { ".", "a.", "b.a.", "c.b.a.", "e.d.c.b.a." } },
		{ "e.d.c.b.a.",
		  2,
		  DBNS_NSEC3,
		  DNS_R_NODATA,
		  5,
		  { ".", "a.", "b.a.", "c.b.a.", "e.d.c.b.a." } },

		{ "a.b.c.d.",
		  1,
		  DBNS_NORMAL,
		  ISC_R_SUCCESS,
		  3,
		  { ".", "c.d.", "a.b.c.d." } },
		{ "a.b.c.d.",
		  1,
		  DBNS_NSEC,
		  ISC_R_SUCCESS,
		  3,
		  { ".", "c.d.", "a.b.c.d." } },
		{ "a.b.c.d.",
		  1,
		  DBNS_NSEC3,
		  ISC_R_SUCCESS,
		  3,
		  { ".", "c.d.", "a.b.c.d." } },

		{ "b.c.d.",
		  1,
		  DBNS_NORMAL,
		  DNS_R_PARTIALMATCH,
		  2,
		  { ".", "c.d." } },
		{ "b.c.d.",
		  1,
		  DBNS_NSEC,
		  DNS_R_PARTIALMATCH,
		  2,
		  { ".", "c.d." } },
		{ "b.c.d.",
		  1,
		  DBNS_NSEC3,
		  DNS_R_PARTIALMATCH,
		  2,
		  { ".", "c.d." } },

		{ "b.c.d.",
		  2,
		  DBNS_NORMAL,
		  DNS_R_PARTIALMATCH,
		  2,
		  { ".", "c.d." } },
		{ "b.c.d.",
		  2,
		  DBNS_NSEC,
		  DNS_R_PARTIALMATCH,
		  2,
		  { ".", "c.d." } },
		{ "b.c.d.",
		  2,
		  DBNS_NSEC3,
		  DNS_R_PARTIALMATCH,
		  2,
		  { ".", "c.d." } },

		{ "x.k.c.d.",
		  250,
		  DBNS_NORMAL,
		  ISC_R_SUCCESS,
		  3,
		  { ".", "c.d.", "x.k.c.d." } },
		{ "x.k.c.d.",
		  250,
		  DBNS_NSEC,
		  ISC_R_SUCCESS,
		  3,
		  { ".", "c.d.", "x.k.c.d." } },
		{ "x.k.c.d.",
		  250,
		  DBNS_NSEC3,
		  ISC_R_SUCCESS,
		  3,
		  { ".", "c.d.", "x.k.c.d." } },

		{ "x.k.c.d.",
		  251,
		  DBNS_NORMAL,
		  DNS_R_NODATA,
		  3,
		  { ".", "c.d.", "x.k.c.d." } },
		{ "x.k.c.d.",
		  251,
		  DBNS_NSEC,
		  DNS_R_NODATA,
		  3,
		  { ".", "c.d.", "x.k.c.d." } },
		{ "x.k.c.d.",
		  251,
		  DBNS_NSEC3,
		  DNS_R_NODATA,
		  3,
		  { ".", "c.d.", "x.k.c.d." } },

		{ "z.x.k.c.d.",
		  1,
		  DBNS_NORMAL,
		  DNS_R_PARTIALMATCH,
		  3,
		  { ".", "c.d.", "x.k.c.d." } },
		{ "z.x.k.c.d.",
		  1,
		  DBNS_NSEC,
		  DNS_R_PARTIALMATCH,
		  3,
		  { ".", "c.d.", "x.k.c.d." } },
		{ "z.x.k.c.d.",
		  1,
		  DBNS_NSEC3,
		  DNS_R_PARTIALMATCH,
		  3,
		  { ".", "c.d.", "x.k.c.d." } },

		{ NULL, 0, 0, 0, 0, { NULL } },
	};

	check_qpchain(qp, check1);
	dns_qp_destroy(&qp);

	static struct inserting insert2[] = {
		INSERTING("a.", 1),	  INSERTING("a.", 53),
		INSERTING("d.b.a.", 1),	  INSERTING("d.b.a.", 53),
		INSERTING("z.d.b.a.", 1), INSERTING("z.d.b.a.", 53),
		INSERTING("", 0),
	};

	i = 0;
	dns_qp_create(mctx, &string_methods, NULL, &qp);

	while (insert2[i].name[0] != '\0') {
		insert_nametype(qp, insert2[i].name, insert2[i].type,
				insert2[i].space, false);
		i++;
	}

	static struct check_qpchain check2[] = {
		{ "f.c.b.a.", 1, DBNS_NORMAL, DNS_R_PARTIALMATCH, 1, { "a." } },
		{ "f.c.b.a.", 1, DBNS_NSEC, DNS_R_PARTIALMATCH, 1, { "a." } },
		{ "f.c.b.a.", 1, DBNS_NSEC3, DNS_R_PARTIALMATCH, 1, { "a." } },
		{ NULL, 0, 0, 0, 0, { NULL } },
	};

	check_qpchain(qp, check2);
	dns_qp_destroy(&qp);
}

struct check_predecessors {
	const char *name;
	dns_rdatatype_t type;
	dns_namespace_t space;
	const char *predecessor;
	dns_rdatatype_t ptype;
	dns_namespace_t pspace;
	isc_result_t result;
	int remaining;
};

static void
check_predecessors_withchain(dns_qp_t *qp, struct check_predecessors check[],
			     dns_qpchain_t *chain) {
	isc_result_t result;
	dns_fixedname_t fn1, fn2;
	dns_name_t *name = dns_fixedname_initname(&fn1);
	dns_name_t *pred = dns_fixedname_initname(&fn2);
	char *namestr = NULL;
	uint32_t ival = 0;

	for (int i = 0; check[i].name != NULL; i++) {
		dns_qpiter_t it;

		dns_test_namefromstring(check[i].name, &fn1);

		/*
		 * normalize the expected predecessor name, in
		 * case it has escaped characters, so we can compare
		 * apples to apples.
		 */
		dns_fixedname_t fn3;
		dns_name_t *expred = dns_fixedname_initname(&fn3);
		char *predstr = NULL;
		dns_test_namefromstring(check[i].predecessor, &fn3);
		result = dns_name_tostring(expred, &predstr, mctx);
		assert_int_equal(result, ISC_R_SUCCESS);

		result = dns_qp_lookup(qp, name, check[i].type, check[i].space,
				       NULL, &it, chain, NULL, &ival);
#if 0
		fprintf(stderr, "%s%s type %u: expected %s got %s\n",
			NAMESPACESTR(check[i].space), check[i].name,
			check[i].type, isc_result_totext(check[i].result),
			isc_result_totext(result));
#endif
		assert_int_equal(result, check[i].result);

		if (result == ISC_R_SUCCESS) {
			/*
			 * we found an exact match; iterate to find
			 * the predecessor.
			 */
			result = dns_qpiter_prev(&it, pred, NULL, &ival);
			if (result == ISC_R_NOMORE) {
				result = dns_qpiter_prev(&it, pred, NULL,
							 &ival);
			}
		} else {
			/*
			 * we didn't find a match, so the iterator should
			 * already be pointed at the predecessor node.
			 */
			result = dns_qpiter_current(&it, pred, NULL, &ival);
		}
		assert_int_equal(result, ISC_R_SUCCESS);

		result = dns_name_tostring(pred, &namestr, mctx);
#if 0
		fprintf(stderr,
			"... expected predecessor %s%s type %u, got %s%s type "
			"%u\n",
			NAMESPACESTR(check[i].pspace), predstr, check[i].ptype,
			NAMESPACESTR(ival & 0x0f), namestr, (ival >> 16));
#endif
		assert_int_equal(result, ISC_R_SUCCESS);
		assert_string_equal(namestr, predstr);
		assert_int_equal(ival & 0x0f, check[i].pspace);
		assert_int_equal(ival >> 16, check[i].ptype);

#if 0
		fprintf(stderr, "%d: remaining names after %s:\n", i, namestr);
#endif
		isc_mem_free(mctx, namestr);
		isc_mem_free(mctx, predstr);

		int j = 0;
		while (dns_qpiter_next(&it, name, NULL, &ival) == ISC_R_SUCCESS)
		{
#if 0
			result = dns_name_tostring(name, &namestr, mctx);
			assert_int_equal(result, ISC_R_SUCCESS);
			fprintf(stderr, "%s[%d]%s%s:%u", j > 0 ? "->\n  " : "",
				j + 1, NAMESPACESTR(ival & 0x0f), namestr,
				(ival >> 16));

			isc_mem_free(mctx, namestr);
#endif
			j++;
		}

#if 0
		fprintf(stderr, "\n...expected %d got %d\n", check[i].remaining,
			j);
#endif

		assert_int_equal(j, check[i].remaining);
	}
}

static void
check_predecessors(dns_qp_t *qp, struct check_predecessors check[]) {
	dns_qpchain_t chain;
	dns_qpchain_init(qp, &chain);
	check_predecessors_withchain(qp, check, NULL);
	check_predecessors_withchain(qp, check, &chain);
}

ISC_RUN_TEST_IMPL(predecessors) {
	int i = 0;
	dns_qp_t *qp = NULL;
	static struct inserting insert1[] = { INSERTING("a.", 1),
					      INSERTING("a.", 10),
					      INSERTING("b.", 2),
					      INSERTING("b.", 20),
					      INSERTING("c.b.a.", 3),
					      INSERTING("c.b.a.", 30),
					      INSERTING("c.b.a.", 300),
					      INSERTING("e.d.c.b.a.", 4),
					      INSERTING("e.d.c.b.a.", 400),
					      INSERTING("c.b.b.", 5),
					      INSERTING("c.b.b.", 50),
					      INSERTING("c.d.", 6),
					      INSERTING("c.d.", 60),
					      INSERTING("c.d.", 600),
					      INSERTING("a.b.c.d.", 7),
					      INSERTING("a.b.c.d.", 70),
					      INSERTING("a.b.c.d.", 700),
					      INSERTING("a.b.c.d.e.", 8),
					      INSERTING("a.b.c.d.e.", 80),
					      INSERTING("a.b.c.d.e.", 800),
					      INSERTING("b.a.", 9),
					      INSERTING("b.a.", 90),
					      INSERTING("x.k.c.d.", 1),
					      INSERTING("x.k.c.d.", 10),
					      INSERTING("x."
							"k."
							"c."
							"d.",
							100),
					      INSERTING("moog.", 2),
					      INSERTING("moog.", 20),
					      INSERTING("moog.", 200),
					      INSERTING("mooker"
							".",
							3),
					      INSERTING("mooker.", 30),
					      INSERTING("mooko.", 4),
					      INSERTING("mooko.", 40),
					      INSERTING("mooko.", 400),
					      INSERTING("moon.", 5),
					      INSERTING("moon.", 50),
					      INSERTING("moon.", 500),
					      INSERTING("moops.", 6),
					      INSERTING("moops.", 60),
					      INSERTING("moops.", 600),
					      INSERTING(".", 7),
					      INSERTING(".", 70),
					      INSERTING("", 0) };

	dns_qp_create(mctx, &string_methods, NULL, &qp);
	while (insert1[i].name[0] != '.') {
		insert_nametype(qp, insert1[i].name, insert1[i].type,
				insert1[i].space, false);
		i++;
	}

	/* first check: no root label in the database */
	static struct check_predecessors check1[] = {
		{ ".", 7, DBNS_NORMAL, "moops.", 600, DBNS_NSEC3,
		  ISC_R_NOTFOUND, 0 },
		{ ".", 7, DBNS_NSEC, "moops.", 600, DBNS_NORMAL, ISC_R_NOTFOUND,
		  78 },
		{ ".", 7, DBNS_NSEC3, "moops.", 600, DBNS_NSEC, ISC_R_NOTFOUND,
		  39 },

		{ "a.", 1, DBNS_NORMAL, "moops.", 600, DBNS_NSEC3,
		  ISC_R_SUCCESS, 0 },
		{ "a.", 1, DBNS_NSEC, "moops.", 600, DBNS_NORMAL, ISC_R_SUCCESS,
		  78 },
		{ "a.", 1, DBNS_NSEC3, "moops.", 600, DBNS_NSEC, ISC_R_SUCCESS,
		  39 },

		{ "a.", 9, DBNS_NORMAL, "a.", 1, DBNS_NORMAL, DNS_R_NODATA,
		  116 },
		{ "a.", 9, DBNS_NSEC, "a.", 1, DBNS_NSEC, DNS_R_NODATA, 77 },
		{ "a.", 9, DBNS_NSEC3, "a.", 1, DBNS_NSEC3, DNS_R_NODATA, 38 },

		{ "a.", 11, DBNS_NORMAL, "a.", 10, DBNS_NORMAL, DNS_R_NODATA,
		  115 },
		{ "a.", 11, DBNS_NSEC, "a.", 10, DBNS_NSEC, DNS_R_NODATA, 76 },
		{ "a.", 11, DBNS_NSEC3, "a.", 10, DBNS_NSEC3, DNS_R_NODATA,
		  37 },

		{ "b.a.", 8, DBNS_NORMAL, "a.", 10, DBNS_NORMAL, DNS_R_NODATA,
		  115 },
		{ "b.a.", 8, DBNS_NSEC, "a.", 10, DBNS_NSEC, DNS_R_NODATA, 76 },
		{ "b.a.", 8, DBNS_NSEC3, "a.", 10, DBNS_NSEC3, DNS_R_NODATA,
		  37 },

		{ "b.a.", 9, DBNS_NORMAL, "a.", 10, DBNS_NORMAL, ISC_R_SUCCESS,
		  115 },
		{ "b.a.", 9, DBNS_NSEC, "a.", 10, DBNS_NSEC, ISC_R_SUCCESS,
		  76 },
		{ "b.a.", 9, DBNS_NSEC3, "a.", 10, DBNS_NSEC3, ISC_R_SUCCESS,
		  37 },

		{ "b.a.", 80, DBNS_NORMAL, "b.a.", 9, DBNS_NORMAL, DNS_R_NODATA,
		  114 },
		{ "b.a.", 80, DBNS_NSEC, "b.a.", 9, DBNS_NSEC, DNS_R_NODATA,
		  75 },
		{ "b.a.", 80, DBNS_NSEC3, "b.a.", 9, DBNS_NSEC3, DNS_R_NODATA,
		  36 },

		{ "b.a.", 90, DBNS_NORMAL, "b.a.", 9, DBNS_NORMAL,
		  ISC_R_SUCCESS, 114 },
		{ "b.a.", 90, DBNS_NSEC, "b.a.", 9, DBNS_NSEC, ISC_R_SUCCESS,
		  75 },
		{ "b.a.", 90, DBNS_NSEC3, "b.a.", 9, DBNS_NSEC3, ISC_R_SUCCESS,
		  36 },

		{ "b.a.", 100, DBNS_NORMAL, "b.a.", 90, DBNS_NORMAL,
		  DNS_R_NODATA, 113 },
		{ "b.a.", 100, DBNS_NSEC, "b.a.", 90, DBNS_NSEC, DNS_R_NODATA,
		  74 },
		{ "b.a.", 100, DBNS_NSEC3, "b.a.", 90, DBNS_NSEC3, DNS_R_NODATA,
		  35 },

		{ "b.", 0, DBNS_NORMAL, "e.d.c.b.a.", 400, DBNS_NORMAL,
		  DNS_R_NODATA, 108 },
		{ "b.", 0, DBNS_NSEC, "e.d.c.b.a.", 400, DBNS_NSEC,
		  DNS_R_NODATA, 69 },
		{ "b.", 0, DBNS_NSEC3, "e.d.c.b.a.", 400, DBNS_NSEC3,
		  DNS_R_NODATA, 30 },

		{ "b.", 1, DBNS_NORMAL, "e.d.c.b.a.", 400, DBNS_NORMAL,
		  DNS_R_NODATA, 108 },
		{ "b.", 1, DBNS_NSEC, "e.d.c.b.a.", 400, DBNS_NSEC,
		  DNS_R_NODATA, 69 },
		{ "b.", 1, DBNS_NSEC3, "e.d.c.b.a.", 400, DBNS_NSEC3,
		  DNS_R_NODATA, 30 },

		{ "b.", 2, DBNS_NORMAL, "e.d.c.b.a.", 400, DBNS_NORMAL,
		  ISC_R_SUCCESS, 108 },
		{ "b.", 2, DBNS_NSEC, "e.d.c.b.a.", 400, DBNS_NSEC,
		  ISC_R_SUCCESS, 69 },
		{ "b.", 2, DBNS_NSEC3, "e.d.c.b.a.", 400, DBNS_NSEC3,
		  ISC_R_SUCCESS, 30 },

		{ "b.", 3, DBNS_NORMAL, "b.", 2, DBNS_NORMAL, DNS_R_NODATA,
		  107 },
		{ "b.", 3, DBNS_NSEC, "b.", 2, DBNS_NSEC, DNS_R_NODATA, 68 },
		{ "b.", 3, DBNS_NSEC3, "b.", 2, DBNS_NSEC3, DNS_R_NODATA, 29 },

		{ "b.", 19, DBNS_NORMAL, "b.", 2, DBNS_NORMAL, DNS_R_NODATA,
		  107 },
		{ "b.", 19, DBNS_NSEC, "b.", 2, DBNS_NSEC, DNS_R_NODATA, 68 },
		{ "b.", 19, DBNS_NSEC3, "b.", 2, DBNS_NSEC3, DNS_R_NODATA, 29 },

		{ "b.", 21, DBNS_NORMAL, "b.", 20, DBNS_NORMAL, DNS_R_NODATA,
		  106 },
		{ "b.", 21, DBNS_NSEC, "b.", 20, DBNS_NSEC, DNS_R_NODATA, 67 },
		{ "b.", 21, DBNS_NSEC3, "b.", 20, DBNS_NSEC3, DNS_R_NODATA,
		  28 },

		{ "aaa.a.", 1, DBNS_NORMAL, "a.", 10, DBNS_NORMAL,
		  DNS_R_PARTIALMATCH, 115 },
		{ "aaa.a.", 1, DBNS_NSEC, "a.", 10, DBNS_NSEC,
		  DNS_R_PARTIALMATCH, 76 },
		{ "aaa.a.", 1, DBNS_NSEC3, "a.", 10, DBNS_NSEC3,
		  DNS_R_PARTIALMATCH, 37 },

		{ "ddd.a.", 1, DBNS_NORMAL, "e.d.c.b.a.", 400, DBNS_NORMAL,
		  DNS_R_PARTIALMATCH, 108 },
		{ "ddd.a.", 1, DBNS_NSEC, "e.d.c.b.a.", 400, DBNS_NSEC,
		  DNS_R_PARTIALMATCH, 69 },
		{ "ddd.a.", 1, DBNS_NSEC3, "e.d.c.b.a.", 400, DBNS_NSEC3,
		  DNS_R_PARTIALMATCH, 30 },

		{ "d.c.", 1, DBNS_NORMAL, "c.b.b.", 50, DBNS_NORMAL,
		  ISC_R_NOTFOUND, 104 },
		{ "d.c.", 1, DBNS_NSEC, "c.b.b.", 50, DBNS_NSEC, ISC_R_NOTFOUND,
		  65 },
		{ "d.c.", 1, DBNS_NSEC3, "c.b.b.", 50, DBNS_NSEC3,
		  ISC_R_NOTFOUND, 26 },

		{ "1.2.c.b.a.", 0, DBNS_NORMAL, "c.b.a.", 300, DBNS_NORMAL,
		  DNS_R_PARTIALMATCH, 110 },
		{ "1.2.c.b.a.", 0, DBNS_NSEC, "c.b.a.", 300, DBNS_NSEC,
		  DNS_R_PARTIALMATCH, 71 },
		{ "1.2.c.b.a.", 0, DBNS_NSEC3, "c.b.a.", 300, DBNS_NSEC3,
		  DNS_R_PARTIALMATCH, 32 },

		{ "1.2.c.b.a.", 65535, DBNS_NORMAL, "c.b.a.", 300, DBNS_NORMAL,
		  DNS_R_PARTIALMATCH, 110 },
		{ "1.2.c.b.a.", 65535, DBNS_NSEC, "c.b.a.", 300, DBNS_NSEC,
		  DNS_R_PARTIALMATCH, 71 },
		{ "1.2.c.b.a.", 65535, DBNS_NSEC3, "c.b.a.", 300, DBNS_NSEC3,
		  DNS_R_PARTIALMATCH, 32 },

		{ "a.b.c.e.f.", 1, DBNS_NORMAL, "a.b.c.d.e.", 800, DBNS_NORMAL,
		  ISC_R_NOTFOUND, 92 },
		{ "a.b.c.e.f.", 1, DBNS_NSEC, "a.b.c.d.e.", 800, DBNS_NSEC,
		  ISC_R_NOTFOUND, 53 },
		{ "a.b.c.e.f.", 1, DBNS_NSEC3, "a.b.c.d.e.", 800, DBNS_NSEC3,
		  ISC_R_NOTFOUND, 14 },

		{ "z.y.x.", 1, DBNS_NORMAL, "moops.", 600, DBNS_NORMAL,
		  ISC_R_NOTFOUND, 78 },
		{ "z.y.x.", 1, DBNS_NSEC, "moops.", 600, DBNS_NSEC,
		  ISC_R_NOTFOUND, 39 },
		{ "z.y.x.", 1, DBNS_NSEC3, "moops.", 600, DBNS_NSEC3,
		  ISC_R_NOTFOUND, 0 },

		{ "w.c.d.", 1, DBNS_NORMAL, "x.k.c.d.", 100, DBNS_NORMAL,
		  DNS_R_PARTIALMATCH, 95 },
		{ "w.c.d.", 1, DBNS_NSEC, "x.k.c.d.", 100, DBNS_NSEC,
		  DNS_R_PARTIALMATCH, 56 },
		{ "w.c.d.", 1, DBNS_NSEC3, "x.k.c.d.", 100, DBNS_NSEC3,
		  DNS_R_PARTIALMATCH, 17 },

		{ "z.z.z.z.k.c.d.", 1, DBNS_NORMAL, "x.k.c.d.", 100,
		  DBNS_NORMAL, DNS_R_PARTIALMATCH, 95 },
		{ "z.z.z.z.k.c.d.", 1, DBNS_NSEC, "x.k.c.d.", 100, DBNS_NSEC,
		  DNS_R_PARTIALMATCH, 56 },
		{ "z.z.z.z.k.c.d.", 1, DBNS_NSEC3, "x.k.c.d.", 100, DBNS_NSEC3,
		  DNS_R_PARTIALMATCH, 17 },

		{ "w.k.c.d.", 1, DBNS_NORMAL, "a.b.c.d.", 700, DBNS_NORMAL,
		  DNS_R_PARTIALMATCH, 98 },
		{ "w.k.c.d.", 1, DBNS_NSEC, "a.b.c.d.", 700, DBNS_NSEC,
		  DNS_R_PARTIALMATCH, 59 },
		{ "w.k.c.d.", 1, DBNS_NSEC3, "a.b.c.d.", 700, DBNS_NSEC3,
		  DNS_R_PARTIALMATCH, 20 },

		{ "d.a.", 1, DBNS_NORMAL, "e.d.c.b.a.", 400, DBNS_NORMAL,
		  DNS_R_PARTIALMATCH, 108 },
		{ "d.a.", 1, DBNS_NSEC, "e.d.c.b.a.", 400, DBNS_NSEC,
		  DNS_R_PARTIALMATCH, 69 },
		{ "d.a.", 1, DBNS_NSEC3, "e.d.c.b.a.", 400, DBNS_NSEC3,
		  DNS_R_PARTIALMATCH, 30 },

		{ "0.b.c.d.e.", 1, DBNS_NORMAL, "x.k.c.d.", 100, DBNS_NORMAL,
		  ISC_R_NOTFOUND, 95 },
		{ "0.b.c.d.e.", 1, DBNS_NSEC, "x.k.c.d.", 100, DBNS_NSEC,
		  ISC_R_NOTFOUND, 56 },
		{ "0.b.c.d.e.", 1, DBNS_NSEC3, "x.k.c.d.", 100, DBNS_NSEC3,
		  ISC_R_NOTFOUND, 17 },

		{ "b.d.", 1, DBNS_NORMAL, "c.b.b.", 50, DBNS_NORMAL,
		  ISC_R_NOTFOUND, 104 },
		{ "b.d.", 1, DBNS_NSEC, "c.b.b.", 50, DBNS_NSEC, ISC_R_NOTFOUND,
		  65 },
		{ "b.d.", 1, DBNS_NSEC3, "c.b.b.", 50, DBNS_NSEC3,
		  ISC_R_NOTFOUND, 26 },

		{ "mon.", 1, DBNS_NORMAL, "a.b.c.d.e.", 800, DBNS_NORMAL,
		  ISC_R_NOTFOUND, 92 },
		{ "mon.", 1, DBNS_NSEC, "a.b.c.d.e.", 800, DBNS_NSEC,
		  ISC_R_NOTFOUND, 53 },
		{ "mon.", 1, DBNS_NSEC3, "a.b.c.d.e.", 800, DBNS_NSEC3,
		  ISC_R_NOTFOUND, 14 },

		{ "moor.", 1, DBNS_NORMAL, "moops.", 600, DBNS_NORMAL,
		  ISC_R_NOTFOUND, 78 },
		{ "moor.", 1, DBNS_NSEC, "moops.", 600, DBNS_NSEC,
		  ISC_R_NOTFOUND, 39 },
		{ "moor.", 1, DBNS_NSEC3, "moops.", 600, DBNS_NSEC3,
		  ISC_R_NOTFOUND, 0 },

		{ "mopbop.", 1, DBNS_NORMAL, "moops.", 600, DBNS_NORMAL,
		  ISC_R_NOTFOUND, 78 },
		{ "mopbop.", 1, DBNS_NSEC, "moops.", 600, DBNS_NSEC,
		  ISC_R_NOTFOUND, 39 },
		{ "mopbop.", 1, DBNS_NSEC3, "moops.", 600, DBNS_NSEC3,
		  ISC_R_NOTFOUND, 0 },

		{ "moppop.", 1, DBNS_NORMAL, "moops.", 600, DBNS_NORMAL,
		  ISC_R_NOTFOUND, 78 },
		{ "moppop.", 1, DBNS_NSEC, "moops.", 600, DBNS_NSEC,
		  ISC_R_NOTFOUND, 39 },
		{ "moppop.", 1, DBNS_NSEC3, "moops.", 600, DBNS_NSEC3,
		  ISC_R_NOTFOUND, 0 },

		{ "mopps.", 1, DBNS_NORMAL, "moops.", 600, DBNS_NORMAL,
		  ISC_R_NOTFOUND, 78 },
		{ "mopps.", 1, DBNS_NSEC, "moops.", 600, DBNS_NSEC,
		  ISC_R_NOTFOUND, 39 },
		{ "mopps.", 1, DBNS_NSEC3, "moops.", 600, DBNS_NSEC3,
		  ISC_R_NOTFOUND, 0 },

		{ "mopzop.", 1, DBNS_NORMAL, "moops.", 600, DBNS_NORMAL,
		  ISC_R_NOTFOUND, 78 },
		{ "mopzop.", 1, DBNS_NSEC, "moops.", 600, DBNS_NSEC,
		  ISC_R_NOTFOUND, 39 },
		{ "mopzop.", 1, DBNS_NSEC3, "moops.", 600, DBNS_NSEC3,
		  ISC_R_NOTFOUND, 0 },

		{ "mop.", 1, DBNS_NORMAL, "moops.", 600, DBNS_NORMAL,
		  ISC_R_NOTFOUND, 78 },
		{ "mop.", 1, DBNS_NSEC, "moops.", 600, DBNS_NSEC,
		  ISC_R_NOTFOUND, 39 },
		{ "mop.", 1, DBNS_NSEC3, "moops.", 600, DBNS_NSEC3,
		  ISC_R_NOTFOUND, 0 },

		{ "monbop.", 1, DBNS_NORMAL, "a.b.c.d.e.", 800, DBNS_NORMAL,
		  ISC_R_NOTFOUND, 92 },
		{ "monbop.", 1, DBNS_NSEC, "a.b.c.d.e.", 800, DBNS_NSEC,
		  ISC_R_NOTFOUND, 53 },
		{ "monbop.", 1, DBNS_NSEC3, "a.b.c.d.e.", 800, DBNS_NSEC3,
		  ISC_R_NOTFOUND, 14 },

		{ "monpop.", 1, DBNS_NORMAL, "a.b.c.d.e.", 800, DBNS_NORMAL,
		  ISC_R_NOTFOUND, 92 },
		{ "monpop.", 1, DBNS_NSEC, "a.b.c.d.e.", 800, DBNS_NSEC,
		  ISC_R_NOTFOUND, 53 },
		{ "monpop.", 1, DBNS_NSEC3, "a.b.c.d.e.", 800, DBNS_NSEC3,
		  ISC_R_NOTFOUND, 14 },

		{ "monps.", 1, DBNS_NORMAL, "a.b.c.d.e.", 800, DBNS_NORMAL,
		  ISC_R_NOTFOUND, 92 },
		{ "monps.", 1, DBNS_NSEC, "a.b.c.d.e.", 800, DBNS_NSEC,
		  ISC_R_NOTFOUND, 53 },
		{ "monps.", 1, DBNS_NSEC3, "a.b.c.d.e.", 800, DBNS_NSEC3,
		  ISC_R_NOTFOUND, 14 },

		{ "monzop.", 1, DBNS_NORMAL, "a.b.c.d.e.", 800, DBNS_NORMAL,
		  ISC_R_NOTFOUND, 92 },
		{ "monzop.", 1, DBNS_NSEC, "a.b.c.d.e.", 800, DBNS_NSEC,
		  ISC_R_NOTFOUND, 53 },
		{ "monzop.", 1, DBNS_NSEC3, "a.b.c.d.e.", 800, DBNS_NSEC3,
		  ISC_R_NOTFOUND, 14 },

		{ "mon.", 1, DBNS_NORMAL, "a.b.c.d.e.", 800, DBNS_NORMAL,
		  ISC_R_NOTFOUND, 92 },
		{ "mon.", 1, DBNS_NSEC, "a.b.c.d.e.", 800, DBNS_NSEC,
		  ISC_R_NOTFOUND, 53 },
		{ "mon.", 1, DBNS_NSEC3, "a.b.c.d.e.", 800, DBNS_NSEC3,
		  ISC_R_NOTFOUND, 14 },

		{ "moop.", 1, DBNS_NORMAL, "moon.", 500, DBNS_NORMAL,
		  ISC_R_NOTFOUND, 81 },
		{ "moop.", 1, DBNS_NSEC, "moon.", 500, DBNS_NSEC,
		  ISC_R_NOTFOUND, 42 },
		{ "moop.", 1, DBNS_NSEC3, "moon.", 500, DBNS_NSEC3,
		  ISC_R_NOTFOUND, 3 },

		{ "moopser.", 1, DBNS_NORMAL, "moops.", 600, DBNS_NORMAL,
		  ISC_R_NOTFOUND, 78 },
		{ "moopser.", 1, DBNS_NSEC, "moops.", 600, DBNS_NSEC,
		  ISC_R_NOTFOUND, 39 },
		{ "moopser.", 1, DBNS_NSEC3, "moops.", 600, DBNS_NSEC3,
		  ISC_R_NOTFOUND, 0 },

		{ "monky.", 1, DBNS_NORMAL, "a.b.c.d.e.", 800, DBNS_NORMAL,
		  ISC_R_NOTFOUND, 92 },
		{ "monky.", 1, DBNS_NSEC, "a.b.c.d.e.", 800, DBNS_NSEC,
		  ISC_R_NOTFOUND, 53 },
		{ "monky.", 1, DBNS_NSEC3, "a.b.c.d.e.", 800, DBNS_NSEC3,
		  ISC_R_NOTFOUND, 14 },

		{ "monkey.", 1, DBNS_NORMAL, "a.b.c.d.e.", 800, DBNS_NORMAL,
		  ISC_R_NOTFOUND, 92 },
		{ "monkey.", 1, DBNS_NSEC, "a.b.c.d.e.", 800, DBNS_NSEC,
		  ISC_R_NOTFOUND, 53 },
		{ "monkey.", 1, DBNS_NSEC3, "a.b.c.d.e.", 800, DBNS_NSEC3,
		  ISC_R_NOTFOUND, 14 },

		{ "monker.", 1, DBNS_NORMAL, "a.b.c.d.e.", 800, DBNS_NORMAL,
		  ISC_R_NOTFOUND, 92 },
		{ "monker.", 1, DBNS_NSEC, "a.b.c.d.e.", 800, DBNS_NSEC,
		  ISC_R_NOTFOUND, 53 },
		{ "monker.", 1, DBNS_NSEC3, "a.b.c.d.e.", 800, DBNS_NSEC3,
		  ISC_R_NOTFOUND, 14 },

		{ NULL, 0, 0, NULL, 0, 0, 0, 0 }
	};

	check_predecessors(qp, check1);

	/* second check: add a root label and try again */
	while (insert1[i].name[0] != '\0') {
		insert_nametype(qp, insert1[i].name, insert1[i].type,
				insert1[i].space, false);
		i++;
	}

	static struct check_predecessors check2[] = {
		{ ".", 6, DBNS_NORMAL, "moops.", 600, DBNS_NSEC3, DNS_R_NODATA,
		  0 },
		{ ".", 6, DBNS_NSEC, "moops.", 600, DBNS_NORMAL, DNS_R_NODATA,
		  82 },
		{ ".", 6, DBNS_NSEC3, "moops.", 600, DBNS_NSEC, DNS_R_NODATA,
		  41 },

		{ ".", 7, DBNS_NORMAL, "moops.", 600, DBNS_NSEC3, ISC_R_SUCCESS,
		  0 },
		{ ".", 7, DBNS_NSEC, "moops.", 600, DBNS_NORMAL, ISC_R_SUCCESS,
		  82 },
		{ ".", 7, DBNS_NSEC3, "moops.", 600, DBNS_NSEC, ISC_R_SUCCESS,
		  41 },

		{ ".", 8, DBNS_NORMAL, ".", 7, DBNS_NORMAL, DNS_R_NODATA, 122 },
		{ ".", 8, DBNS_NSEC, ".", 7, DBNS_NSEC, DNS_R_NODATA, 81 },
		{ ".", 8, DBNS_NSEC3, ".", 7, DBNS_NSEC3, DNS_R_NODATA, 40 },

		{ ".", 69, DBNS_NORMAL, ".", 7, DBNS_NORMAL, DNS_R_NODATA,
		  122 },
		{ ".", 69, DBNS_NSEC, ".", 7, DBNS_NSEC, DNS_R_NODATA, 81 },
		{ ".", 69, DBNS_NSEC3, ".", 7, DBNS_NSEC3, DNS_R_NODATA, 40 },

		{ ".", 70, DBNS_NORMAL, ".", 7, DBNS_NORMAL, ISC_R_SUCCESS,
		  122 },
		{ ".", 70, DBNS_NSEC, ".", 7, DBNS_NSEC, ISC_R_SUCCESS, 81 },
		{ ".", 70, DBNS_NSEC3, ".", 7, DBNS_NSEC3, ISC_R_SUCCESS, 40 },

		{ ".", 71, DBNS_NORMAL, ".", 70, DBNS_NORMAL, DNS_R_NODATA,
		  121 },
		{ ".", 71, DBNS_NSEC, ".", 70, DBNS_NSEC, DNS_R_NODATA, 80 },
		{ ".", 71, DBNS_NSEC3, ".", 70, DBNS_NSEC3, DNS_R_NODATA, 39 },

		{ "a.", 1, DBNS_NORMAL, ".", 70, DBNS_NORMAL, ISC_R_SUCCESS,
		  121 },
		{ "a.", 1, DBNS_NSEC, ".", 70, DBNS_NSEC, ISC_R_SUCCESS, 80 },
		{ "a.", 1, DBNS_NSEC3, ".", 70, DBNS_NSEC3, ISC_R_SUCCESS, 39 },

		{ "a.", 9, DBNS_NORMAL, "a.", 1, DBNS_NORMAL, DNS_R_NODATA,
		  120 },
		{ "a.", 9, DBNS_NSEC, "a.", 1, DBNS_NSEC, DNS_R_NODATA, 79 },
		{ "a.", 9, DBNS_NSEC3, "a.", 1, DBNS_NSEC3, DNS_R_NODATA, 38 },

		{ "a.", 11, DBNS_NORMAL, "a.", 10, DBNS_NORMAL, DNS_R_NODATA,
		  119 },
		{ "a.", 11, DBNS_NSEC, "a.", 10, DBNS_NSEC, DNS_R_NODATA, 78 },
		{ "a.", 11, DBNS_NSEC3, "a.", 10, DBNS_NSEC3, DNS_R_NODATA,
		  37 },

		{ "b.a.", 8, DBNS_NORMAL, "a.", 10, DBNS_NORMAL, DNS_R_NODATA,
		  119 },
		{ "b.a.", 8, DBNS_NSEC, "a.", 10, DBNS_NSEC, DNS_R_NODATA, 78 },
		{ "b.a.", 8, DBNS_NSEC3, "a.", 10, DBNS_NSEC3, DNS_R_NODATA,
		  37 },

		{ "b.a.", 9, DBNS_NORMAL, "a.", 10, DBNS_NORMAL, ISC_R_SUCCESS,
		  119 },
		{ "b.a.", 9, DBNS_NSEC, "a.", 10, DBNS_NSEC, ISC_R_SUCCESS,
		  78 },
		{ "b.a.", 9, DBNS_NSEC3, "a.", 10, DBNS_NSEC3, ISC_R_SUCCESS,
		  37 },

		{ "b.a.", 80, DBNS_NORMAL, "b.a.", 9, DBNS_NORMAL, DNS_R_NODATA,
		  118 },
		{ "b.a.", 80, DBNS_NSEC, "b.a.", 9, DBNS_NSEC, DNS_R_NODATA,
		  77 },
		{ "b.a.", 80, DBNS_NSEC3, "b.a.", 9, DBNS_NSEC3, DNS_R_NODATA,
		  36 },

		{ "b.a.", 90, DBNS_NORMAL, "b.a.", 9, DBNS_NORMAL,
		  ISC_R_SUCCESS, 118 },
		{ "b.a.", 90, DBNS_NSEC, "b.a.", 9, DBNS_NSEC, ISC_R_SUCCESS,
		  77 },
		{ "b.a.", 90, DBNS_NSEC3, "b.a.", 9, DBNS_NSEC3, ISC_R_SUCCESS,
		  36 },

		{ "b.a.", 100, DBNS_NORMAL, "b.a.", 90, DBNS_NORMAL,
		  DNS_R_NODATA, 117 },
		{ "b.a.", 100, DBNS_NSEC, "b.a.", 90, DBNS_NSEC, DNS_R_NODATA,
		  76 },
		{ "b.a.", 100, DBNS_NSEC3, "b.a.", 90, DBNS_NSEC3, DNS_R_NODATA,
		  35 },

		{ "b.", 0, DBNS_NORMAL, "e.d.c.b.a.", 400, DBNS_NORMAL,
		  DNS_R_NODATA, 112 },
		{ "b.", 0, DBNS_NSEC, "e.d.c.b.a.", 400, DBNS_NSEC,
		  DNS_R_NODATA, 71 },
		{ "b.", 0, DBNS_NSEC3, "e.d.c.b.a.", 400, DBNS_NSEC3,
		  DNS_R_NODATA, 30 },

		{ "b.", 1, DBNS_NORMAL, "e.d.c.b.a.", 400, DBNS_NORMAL,
		  DNS_R_NODATA, 112 },
		{ "b.", 1, DBNS_NSEC, "e.d.c.b.a.", 400, DBNS_NSEC,
		  DNS_R_NODATA, 71 },
		{ "b.", 1, DBNS_NSEC3, "e.d.c.b.a.", 400, DBNS_NSEC3,
		  DNS_R_NODATA, 30 },

		{ "b.", 2, DBNS_NORMAL, "e.d.c.b.a.", 400, DBNS_NORMAL,
		  ISC_R_SUCCESS, 112 },
		{ "b.", 2, DBNS_NSEC, "e.d.c.b.a.", 400, DBNS_NSEC,
		  ISC_R_SUCCESS, 71 },
		{ "b.", 2, DBNS_NSEC3, "e.d.c.b.a.", 400, DBNS_NSEC3,
		  ISC_R_SUCCESS, 30 },

		{ "b.", 3, DBNS_NORMAL, "b.", 2, DBNS_NORMAL, DNS_R_NODATA,
		  111 },
		{ "b.", 3, DBNS_NSEC, "b.", 2, DBNS_NSEC, DNS_R_NODATA, 70 },
		{ "b.", 3, DBNS_NSEC3, "b.", 2, DBNS_NSEC3, DNS_R_NODATA, 29 },

		{ "b.", 19, DBNS_NORMAL, "b.", 2, DBNS_NORMAL, DNS_R_NODATA,
		  111 },
		{ "b.", 19, DBNS_NSEC, "b.", 2, DBNS_NSEC, DNS_R_NODATA, 70 },
		{ "b.", 19, DBNS_NSEC3, "b.", 2, DBNS_NSEC3, DNS_R_NODATA, 29 },

		{ "b.", 21, DBNS_NORMAL, "b.", 20, DBNS_NORMAL, DNS_R_NODATA,
		  110 },
		{ "b.", 21, DBNS_NSEC, "b.", 20, DBNS_NSEC, DNS_R_NODATA, 69 },
		{ "b.", 21, DBNS_NSEC3, "b.", 20, DBNS_NSEC3, DNS_R_NODATA,
		  28 },

		{ "aaa.a.", 1, DBNS_NORMAL, "a.", 10, DBNS_NORMAL,
		  DNS_R_PARTIALMATCH, 119 },
		{ "aaa.a.", 1, DBNS_NSEC, "a.", 10, DBNS_NSEC,
		  DNS_R_PARTIALMATCH, 78 },
		{ "aaa.a.", 1, DBNS_NSEC3, "a.", 10, DBNS_NSEC3,
		  DNS_R_PARTIALMATCH, 37 },

		{ "ddd.a.", 1, DBNS_NORMAL, "e.d.c.b.a.", 400, DBNS_NORMAL,
		  DNS_R_PARTIALMATCH, 112 },
		{ "ddd.a.", 1, DBNS_NSEC, "e.d.c.b.a.", 400, DBNS_NSEC,
		  DNS_R_PARTIALMATCH, 71 },
		{ "ddd.a.", 1, DBNS_NSEC3, "e.d.c.b.a.", 400, DBNS_NSEC3,
		  DNS_R_PARTIALMATCH, 30 },

		{ "d.c.", 1, DBNS_NORMAL, "c.b.b.", 50, DBNS_NORMAL,
		  DNS_R_PARTIALMATCH, 108 },
		{ "d.c.", 1, DBNS_NSEC, "c.b.b.", 50, DBNS_NSEC,
		  DNS_R_PARTIALMATCH, 67 },
		{ "d.c.", 1, DBNS_NSEC3, "c.b.b.", 50, DBNS_NSEC3,
		  DNS_R_PARTIALMATCH, 26 },

		{ "1.2.c.b.a.", 0, DBNS_NORMAL, "c.b.a.", 300, DBNS_NORMAL,
		  DNS_R_PARTIALMATCH, 114 },
		{ "1.2.c.b.a.", 0, DBNS_NSEC, "c.b.a.", 300, DBNS_NSEC,
		  DNS_R_PARTIALMATCH, 73 },
		{ "1.2.c.b.a.", 0, DBNS_NSEC3, "c.b.a.", 300, DBNS_NSEC3,
		  DNS_R_PARTIALMATCH, 32 },

		{ "1.2.c.b.a.", 65535, DBNS_NORMAL, "c.b.a.", 300, DBNS_NORMAL,
		  DNS_R_PARTIALMATCH, 114 },
		{ "1.2.c.b.a.", 65535, DBNS_NSEC, "c.b.a.", 300, DBNS_NSEC,
		  DNS_R_PARTIALMATCH, 73 },
		{ "1.2.c.b.a.", 65535, DBNS_NSEC3, "c.b.a.", 300, DBNS_NSEC3,
		  DNS_R_PARTIALMATCH, 32 },

		{ "a.b.c.e.f.", 1, DBNS_NORMAL, "a.b.c.d.e.", 800, DBNS_NORMAL,
		  DNS_R_PARTIALMATCH, 96 },
		{ "a.b.c.e.f.", 1, DBNS_NSEC, "a.b.c.d.e.", 800, DBNS_NSEC,
		  DNS_R_PARTIALMATCH, 55 },
		{ "a.b.c.e.f.", 1, DBNS_NSEC3, "a.b.c.d.e.", 800, DBNS_NSEC3,
		  DNS_R_PARTIALMATCH, 14 },

		{ "z.y.x.", 1, DBNS_NORMAL, "moops.", 600, DBNS_NORMAL,
		  DNS_R_PARTIALMATCH, 82 },
		{ "z.y.x.", 1, DBNS_NSEC, "moops.", 600, DBNS_NSEC,
		  DNS_R_PARTIALMATCH, 41 },
		{ "z.y.x.", 1, DBNS_NSEC3, "moops.", 600, DBNS_NSEC3,
		  DNS_R_PARTIALMATCH, 0 },

		{ "w.c.d.", 1, DBNS_NORMAL, "x.k.c.d.", 100, DBNS_NORMAL,
		  DNS_R_PARTIALMATCH, 99 },
		{ "w.c.d.", 1, DBNS_NSEC, "x.k.c.d.", 100, DBNS_NSEC,
		  DNS_R_PARTIALMATCH, 58 },
		{ "w.c.d.", 1, DBNS_NSEC3, "x.k.c.d.", 100, DBNS_NSEC3,
		  DNS_R_PARTIALMATCH, 17 },

		{ "z.z.z.z.k.c.d.", 1, DBNS_NORMAL, "x.k.c.d.", 100,
		  DBNS_NORMAL, DNS_R_PARTIALMATCH, 99 },
		{ "z.z.z.z.k.c.d.", 1, DBNS_NSEC, "x.k.c.d.", 100, DBNS_NSEC,
		  DNS_R_PARTIALMATCH, 58 },
		{ "z.z.z.z.k.c.d.", 1, DBNS_NSEC3, "x.k.c.d.", 100, DBNS_NSEC3,
		  DNS_R_PARTIALMATCH, 17 },

		{ "w.k.c.d.", 1, DBNS_NORMAL, "a.b.c.d.", 700, DBNS_NORMAL,
		  DNS_R_PARTIALMATCH, 102 },
		{ "w.k.c.d.", 1, DBNS_NSEC, "a.b.c.d.", 700, DBNS_NSEC,
		  DNS_R_PARTIALMATCH, 61 },
		{ "w.k.c.d.", 1, DBNS_NSEC3, "a.b.c.d.", 700, DBNS_NSEC3,
		  DNS_R_PARTIALMATCH, 20 },

		{ "d.a.", 1, DBNS_NORMAL, "e.d.c.b.a.", 400, DBNS_NORMAL,
		  DNS_R_PARTIALMATCH, 112 },
		{ "d.a.", 1, DBNS_NSEC, "e.d.c.b.a.", 400, DBNS_NSEC,
		  DNS_R_PARTIALMATCH, 71 },
		{ "d.a.", 1, DBNS_NSEC3, "e.d.c.b.a.", 400, DBNS_NSEC3,
		  DNS_R_PARTIALMATCH, 30 },

		{ "0.b.c.d.e.", 1, DBNS_NORMAL, "x.k.c.d.", 100, DBNS_NORMAL,
		  DNS_R_PARTIALMATCH, 99 },
		{ "0.b.c.d.e.", 1, DBNS_NSEC, "x.k.c.d.", 100, DBNS_NSEC,
		  DNS_R_PARTIALMATCH, 58 },
		{ "0.b.c.d.e.", 1, DBNS_NSEC3, "x.k.c.d.", 100, DBNS_NSEC3,
		  DNS_R_PARTIALMATCH, 17 },

		{ "b.d.", 1, DBNS_NORMAL, "c.b.b.", 50, DBNS_NORMAL,
		  DNS_R_PARTIALMATCH, 108 },
		{ "b.d.", 1, DBNS_NSEC, "c.b.b.", 50, DBNS_NSEC,
		  DNS_R_PARTIALMATCH, 67 },
		{ "b.d.", 1, DBNS_NSEC3, "c.b.b.", 50, DBNS_NSEC3,
		  DNS_R_PARTIALMATCH, 26 },

		{ "mon.", 1, DBNS_NORMAL, "a.b.c.d.e.", 800, DBNS_NORMAL,
		  DNS_R_PARTIALMATCH, 96 },
		{ "mon.", 1, DBNS_NSEC, "a.b.c.d.e.", 800, DBNS_NSEC,
		  DNS_R_PARTIALMATCH, 55 },
		{ "mon.", 1, DBNS_NSEC3, "a.b.c.d.e.", 800, DBNS_NSEC3,
		  DNS_R_PARTIALMATCH, 14 },

		{ "moor.", 1, DBNS_NORMAL, "moops.", 600, DBNS_NORMAL,
		  DNS_R_PARTIALMATCH, 82 },
		{ "moor.", 1, DBNS_NSEC, "moops.", 600, DBNS_NSEC,
		  DNS_R_PARTIALMATCH, 41 },
		{ "moor.", 1, DBNS_NSEC3, "moops.", 600, DBNS_NSEC3,
		  DNS_R_PARTIALMATCH, 0 },

		{ "mopbop.", 1, DBNS_NORMAL, "moops.", 600, DBNS_NORMAL,
		  DNS_R_PARTIALMATCH, 82 },
		{ "mopbop.", 1, DBNS_NSEC, "moops.", 600, DBNS_NSEC,
		  DNS_R_PARTIALMATCH, 41 },
		{ "mopbop.", 1, DBNS_NSEC3, "moops.", 600, DBNS_NSEC3,
		  DNS_R_PARTIALMATCH, 0 },

		{ "moppop.", 1, DBNS_NORMAL, "moops.", 600, DBNS_NORMAL,
		  DNS_R_PARTIALMATCH, 82 },
		{ "moppop.", 1, DBNS_NSEC, "moops.", 600, DBNS_NSEC,
		  DNS_R_PARTIALMATCH, 41 },
		{ "moppop.", 1, DBNS_NSEC3, "moops.", 600, DBNS_NSEC3,
		  DNS_R_PARTIALMATCH, 0 },

		{ "mopps.", 1, DBNS_NORMAL, "moops.", 600, DBNS_NORMAL,
		  DNS_R_PARTIALMATCH, 82 },
		{ "mopps.", 1, DBNS_NSEC, "moops.", 600, DBNS_NSEC,
		  DNS_R_PARTIALMATCH, 41 },
		{ "mopps.", 1, DBNS_NSEC3, "moops.", 600, DBNS_NSEC3,
		  DNS_R_PARTIALMATCH, 0 },

		{ "mopzop.", 1, DBNS_NORMAL, "moops.", 600, DBNS_NORMAL,
		  DNS_R_PARTIALMATCH, 82 },
		{ "mopzop.", 1, DBNS_NSEC, "moops.", 600, DBNS_NSEC,
		  DNS_R_PARTIALMATCH, 41 },
		{ "mopzop.", 1, DBNS_NSEC3, "moops.", 600, DBNS_NSEC3,
		  DNS_R_PARTIALMATCH, 0 },

		{ "mop.", 1, DBNS_NORMAL, "moops.", 600, DBNS_NORMAL,
		  DNS_R_PARTIALMATCH, 82 },
		{ "mop.", 1, DBNS_NSEC, "moops.", 600, DBNS_NSEC,
		  DNS_R_PARTIALMATCH, 41 },
		{ "mop.", 1, DBNS_NSEC3, "moops.", 600, DBNS_NSEC3,
		  DNS_R_PARTIALMATCH, 0 },

		{ "monbop.", 1, DBNS_NORMAL, "a.b.c.d.e.", 800, DBNS_NORMAL,
		  DNS_R_PARTIALMATCH, 96 },
		{ "monbop.", 1, DBNS_NSEC, "a.b.c.d.e.", 800, DBNS_NSEC,
		  DNS_R_PARTIALMATCH, 55 },
		{ "monbop.", 1, DBNS_NSEC3, "a.b.c.d.e.", 800, DBNS_NSEC3,
		  DNS_R_PARTIALMATCH, 14 },

		{ "monpop.", 1, DBNS_NORMAL, "a.b.c.d.e.", 800, DBNS_NORMAL,
		  DNS_R_PARTIALMATCH, 96 },
		{ "monpop.", 1, DBNS_NSEC, "a.b.c.d.e.", 800, DBNS_NSEC,
		  DNS_R_PARTIALMATCH, 55 },
		{ "monpop.", 1, DBNS_NSEC3, "a.b.c.d.e.", 800, DBNS_NSEC3,
		  DNS_R_PARTIALMATCH, 14 },

		{ "monps.", 1, DBNS_NORMAL, "a.b.c.d.e.", 800, DBNS_NORMAL,
		  DNS_R_PARTIALMATCH, 96 },
		{ "monps.", 1, DBNS_NSEC, "a.b.c.d.e.", 800, DBNS_NSEC,
		  DNS_R_PARTIALMATCH, 55 },
		{ "monps.", 1, DBNS_NSEC3, "a.b.c.d.e.", 800, DBNS_NSEC3,
		  DNS_R_PARTIALMATCH, 14 },

		{ "monzop.", 1, DBNS_NORMAL, "a.b.c.d.e.", 800, DBNS_NORMAL,
		  DNS_R_PARTIALMATCH, 96 },
		{ "monzop.", 1, DBNS_NSEC, "a.b.c.d.e.", 800, DBNS_NSEC,
		  DNS_R_PARTIALMATCH, 55 },
		{ "monzop.", 1, DBNS_NSEC3, "a.b.c.d.e.", 800, DBNS_NSEC3,
		  DNS_R_PARTIALMATCH, 14 },

		{ "mon.", 1, DBNS_NORMAL, "a.b.c.d.e.", 800, DBNS_NORMAL,
		  DNS_R_PARTIALMATCH, 96 },
		{ "mon.", 1, DBNS_NSEC, "a.b.c.d.e.", 800, DBNS_NSEC,
		  DNS_R_PARTIALMATCH, 55 },
		{ "mon.", 1, DBNS_NSEC3, "a.b.c.d.e.", 800, DBNS_NSEC3,
		  DNS_R_PARTIALMATCH, 14 },

		{ "moop.", 1, DBNS_NORMAL, "moon.", 500, DBNS_NORMAL,
		  DNS_R_PARTIALMATCH, 85 },
		{ "moop.", 1, DBNS_NSEC, "moon.", 500, DBNS_NSEC,
		  DNS_R_PARTIALMATCH, 44 },
		{ "moop.", 1, DBNS_NSEC3, "moon.", 500, DBNS_NSEC3,
		  DNS_R_PARTIALMATCH, 3 },

		{ "moopser.", 1, DBNS_NORMAL, "moops.", 600, DBNS_NORMAL,
		  DNS_R_PARTIALMATCH, 82 },
		{ "moopser.", 1, DBNS_NSEC, "moops.", 600, DBNS_NSEC,
		  DNS_R_PARTIALMATCH, 41 },
		{ "moopser.", 1, DBNS_NSEC3, "moops.", 600, DBNS_NSEC3,
		  DNS_R_PARTIALMATCH, 0 },

		{ "monky.", 1, DBNS_NORMAL, "a.b.c.d.e.", 800, DBNS_NORMAL,
		  DNS_R_PARTIALMATCH, 96 },
		{ "monky.", 1, DBNS_NSEC, "a.b.c.d.e.", 800, DBNS_NSEC,
		  DNS_R_PARTIALMATCH, 55 },
		{ "monky.", 1, DBNS_NSEC3, "a.b.c.d.e.", 800, DBNS_NSEC3,
		  DNS_R_PARTIALMATCH, 14 },

		{ "monkey.", 1, DBNS_NORMAL, "a.b.c.d.e.", 800, DBNS_NORMAL,
		  DNS_R_PARTIALMATCH, 96 },
		{ "monkey.", 1, DBNS_NSEC, "a.b.c.d.e.", 800, DBNS_NSEC,
		  DNS_R_PARTIALMATCH, 55 },
		{ "monkey.", 1, DBNS_NSEC3, "a.b.c.d.e.", 800, DBNS_NSEC3,
		  DNS_R_PARTIALMATCH, 14 },

		{ "monker.", 1, DBNS_NORMAL, "a.b.c.d.e.", 800, DBNS_NORMAL,
		  DNS_R_PARTIALMATCH, 96 },
		{ "monker.", 1, DBNS_NSEC, "a.b.c.d.e.", 800, DBNS_NSEC,
		  DNS_R_PARTIALMATCH, 55 },
		{ "monker.", 1, DBNS_NSEC3, "a.b.c.d.e.", 800, DBNS_NSEC3,
		  DNS_R_PARTIALMATCH, 14 },

		{ NULL, 0, 0, NULL, 0, 0, 0, 0 }
	};

	check_predecessors(qp, check2);

	dns_qp_destroy(&qp);
}

/*
 * this is a regression test for an infinite loop that could
 * previously occur in fix_iterator()
 */
ISC_RUN_TEST_IMPL(fixiterator) {
	int i = 0;
	dns_qp_t *qp = NULL;
	static struct inserting insert1[] = {
		INSERTING("dynamic.", 6),
		INSERTING("dynamic.", 2),
		INSERTING("a.dynamic.", 1),
		INSERTING("aaaa.dynamic.", 28),
		INSERTING("cdnskey.dynamic.", 60),
		INSERTING("cds.dynamic.", 59),
		INSERTING("cname.dynamic.", 5),
		INSERTING("dname.dynamic.", 39),
		INSERTING("dnskey.dynamic.", 48),
		INSERTING("ds.dynamic.", 43),
		INSERTING("mx.dynamic.", 15),
		INSERTING("ns.dynamic.", 2),
		INSERTING("nsec.dynamic.", 47),
		INSERTING("private-"
			  "cdnskey."
			  "dynamic.",
			  60),
		INSERTING("private-dnskey.dynamic.", 48),
		INSERTING("rrsig."
			  "dynamic.",
			  46),
		INSERTING("txt.dynamic.", 16),
		INSERTING("traili"
			  "ng.",
			  6),
		INSERTING("trailing.", 2),
		INSERTING("", 0)
	};

	dns_qp_create(mctx, &string_methods, NULL, &qp);
	while (insert1[i].name[0] != '\0') {
		insert_nametype(qp, insert1[i].name, insert1[i].type,
				insert1[i].space, false);
		i++;
	}

	static struct check_predecessors check1[] = {
		{ "newtext.dynamic.", 1, DBNS_NORMAL, "mx.dynamic.", 15,
		  DBNS_NORMAL, DNS_R_PARTIALMATCH, 46 },
		{ "newtext.dynamic.", 1, DBNS_NSEC, "mx.dynamic.", 15,
		  DBNS_NSEC, DNS_R_PARTIALMATCH, 27 },
		{ "newtext.dynamic.", 1, DBNS_NSEC3, "mx.dynamic.", 15,
		  DBNS_NSEC3, DNS_R_PARTIALMATCH, 8 },

		{ "nsd.dynamic.", 1, DBNS_NORMAL, "ns.dynamic.", 2, DBNS_NORMAL,
		  DNS_R_PARTIALMATCH, 45 },
		{ "nsd.dynamic.", 1, DBNS_NSEC, "ns.dynamic.", 2, DBNS_NSEC,
		  DNS_R_PARTIALMATCH, 26 },
		{ "nsd.dynamic.", 1, DBNS_NSEC3, "ns.dynamic.", 2, DBNS_NSEC3,
		  DNS_R_PARTIALMATCH, 7 },

		{ "nsf.dynamic.", 1, DBNS_NORMAL, "nsec.dynamic.", 47,
		  DBNS_NORMAL, DNS_R_PARTIALMATCH, 44 },
		{ "nsf.dynamic.", 1, DBNS_NSEC, "nsec.dynamic.", 47, DBNS_NSEC,
		  DNS_R_PARTIALMATCH, 25 },
		{ "nsf.dynamic.", 1, DBNS_NSEC3, "nsec.dynamic.", 47,
		  DBNS_NSEC3, DNS_R_PARTIALMATCH, 6 },

		{ "d.", 1, DBNS_NORMAL, "trailing.", 6, DBNS_NSEC3,
		  ISC_R_NOTFOUND, 0 },
		{ "d.", 1, DBNS_NSEC, "trailing.", 6, DBNS_NORMAL,
		  ISC_R_NOTFOUND, 38 },
		{ "d.", 1, DBNS_NSEC3, "trailing.", 6, DBNS_NSEC,
		  ISC_R_NOTFOUND, 19 },

		{ "absent.", 1, DBNS_NORMAL, "trailing.", 6, DBNS_NSEC3,
		  ISC_R_NOTFOUND, 0 },
		{ "absent.", 1, DBNS_NSEC, "trailing.", 6, DBNS_NORMAL,
		  ISC_R_NOTFOUND, 38 },
		{ "absent.", 1, DBNS_NSEC3, "trailing.", 6, DBNS_NSEC,
		  ISC_R_NOTFOUND, 19 },

		{ "nonexistent.", 1, DBNS_NORMAL, "txt.dynamic.", 16,
		  DBNS_NORMAL, ISC_R_NOTFOUND, 40 },
		{ "nonexistent.", 1, DBNS_NSEC, "txt.dynamic.", 16, DBNS_NSEC,
		  ISC_R_NOTFOUND, 21 },
		{ "nonexistent.", 1, DBNS_NSEC3, "txt.dynamic.", 16, DBNS_NSEC3,
		  ISC_R_NOTFOUND, 2 },

		{ "wayback.", 1, DBNS_NORMAL, "trailing.", 6, DBNS_NORMAL,
		  ISC_R_NOTFOUND, 38 },
		{ "wayback.", 1, DBNS_NSEC, "trailing.", 6, DBNS_NSEC,
		  ISC_R_NOTFOUND, 19 },
		{ "wayback.", 1, DBNS_NSEC3, "trailing.", 6, DBNS_NSEC3,
		  ISC_R_NOTFOUND, 0 },

		{ NULL, 0, 0, NULL, 0, 0, 0, 0 }
	};

	check_predecessors(qp, check1);
	dns_qp_destroy(&qp);

	i = 0;
	static struct inserting insert2[] = {
		INSERTING(".", 1),    INSERTING(".", 65535),
		INSERTING("abb.", 1), INSERTING("abb.", 65535),
		INSERTING("abc.", 1), INSERTING("abc.", 65535),
		INSERTING("", 0)
	};

	dns_qp_create(mctx, &string_methods, NULL, &qp);
	while (insert2[i].name[0] != '\0') {
		insert_nametype(qp, insert2[i].name, insert2[i].type,
				insert2[i].space, false);
		i++;
	}

	static struct check_predecessors check2[] = {
		{ "acb.", 1, DBNS_NORMAL, "abc.", 65535, DBNS_NORMAL,
		  DNS_R_PARTIALMATCH, 12 },
		{ "acb.", 1, DBNS_NSEC, "abc.", 65535, DBNS_NSEC,
		  DNS_R_PARTIALMATCH, 6 },
		{ "acb.", 1, DBNS_NSEC3, "abc.", 65535, DBNS_NSEC3,
		  DNS_R_PARTIALMATCH, 0 },

		{ "acc.", 1, DBNS_NORMAL, "abc.", 65535, DBNS_NORMAL,
		  DNS_R_PARTIALMATCH, 12 },
		{ "acc.", 1, DBNS_NSEC, "abc.", 65535, DBNS_NSEC,
		  DNS_R_PARTIALMATCH, 6 },
		{ "acc.", 1, DBNS_NSEC3, "abc.", 65535, DBNS_NSEC3,
		  DNS_R_PARTIALMATCH, 0 },

		{ "abbb.", 1, DBNS_NORMAL, "abb.", 65535, DBNS_NORMAL,
		  DNS_R_PARTIALMATCH, 14 },
		{ "abbb.", 1, DBNS_NSEC, "abb.", 65535, DBNS_NSEC,
		  DNS_R_PARTIALMATCH, 8 },
		{ "abbb.", 1, DBNS_NSEC3, "abb.", 65535, DBNS_NSEC3,
		  DNS_R_PARTIALMATCH, 2 },

		{ "aab.", 1, DBNS_NORMAL, ".", 65535, DBNS_NORMAL,
		  DNS_R_PARTIALMATCH, 16 },
		{ "aab.", 1, DBNS_NSEC, ".", 65535, DBNS_NSEC,
		  DNS_R_PARTIALMATCH, 10 },
		{ "aab.", 1, DBNS_NSEC3, ".", 65535, DBNS_NSEC3,
		  DNS_R_PARTIALMATCH, 4 },

		{ NULL, 0, 0, NULL, 0, 0, 0, 0 }
	};

	check_predecessors(qp, check2);
	dns_qp_destroy(&qp);

	static struct inserting insert3[] = {
		INSERTING("example.", 6),
		INSERTING("example.", 2),
		INSERTING("example.", 48),
		INSERTING("example.", 47),
		INSERTING("example.", 46),
		INSERTING("key-is-13779.example.", 32768),
		INSERTING("key-is-13779.example.", 46),
		INSERTING("key-is-13779.example.", 47),
		INSERTING("key-is-14779."
			  "example.",
			  32768),
		INSERTING("key-is-14779.example.", 46),
		INSERTING("key-is-14779.example.", 47),
		INSERTING("key-not-14779.example.", 32768),
		INSERTING("key-not-14779.example.", 46),
		INSERTING("key-not-14779."
			  "example.",
			  47),
		INSERTING("", 0)
	};

	i = 0;
	dns_qp_create(mctx, &string_methods, NULL, &qp);
	while (insert3[i].name[0] != '\0') {
		insert_nametype(qp, insert3[i].name, insert3[i].type,
				insert3[i].space, false);
		i++;
	}

	static struct check_predecessors check3[] = {
		{ "key-is-21556.example.", 32768, DBNS_NORMAL,
		  "key-is-14779.example.", 32768, DBNS_NORMAL,
		  DNS_R_PARTIALMATCH, 31 },
		{ "key-is-21556.example.", 32768, DBNS_NSEC,
		  "key-is-14779.example.", 32768, DBNS_NSEC, DNS_R_PARTIALMATCH,
		  17 },
		{ "key-is-21556.example.", 32768, DBNS_NSEC3,
		  "key-is-14779.example.", 32768, DBNS_NSEC3,
		  DNS_R_PARTIALMATCH, 3 },
		{ NULL, 0, 0, NULL, 0, 0, 0, 0 }
	};

	check_predecessors(qp, check3);
	dns_qp_destroy(&qp);

	static struct inserting insert4[] = { INSERTING(".", 1),
					      INSERTING(".", 2),
					      INSERTING(".", 3),
					      INSERTING("\\000.", 1),
					      INSERTING("\\000.", 2),
					      INSERTING("\\000.", 3),
					      INSERTING("\\000.\\000.", 1),
					      INSERTING("\\000.\\000.", 2),
					      INSERTING("\\000.\\000.", 3),
					      INSERTING("\\000\\009.", 1),
					      INSERTING("\\000\\009.", 2),
					      INSERTING("\\000\\009.", 3),
					      INSERTING("", 0) };

	i = 0;
	dns_qp_create(mctx, &string_methods, NULL, &qp);
	while (insert4[i].name[0] != '\0') {
		insert_nametype(qp, insert4[i].name, insert4[i].type,
				insert4[i].space, false);
		i++;
	}

	static struct check_predecessors check4[] = {
		{ "\\007.", 1, DBNS_NORMAL, "\\000\\009.", 3, DBNS_NORMAL,
		  DNS_R_PARTIALMATCH, 24 },
		{ "\\007.", 1, DBNS_NSEC, "\\000\\009.", 3, DBNS_NSEC,
		  DNS_R_PARTIALMATCH, 12 },
		{ "\\007.", 1, DBNS_NSEC3, "\\000\\009.", 3, DBNS_NSEC3,
		  DNS_R_PARTIALMATCH, 0 },

		{ "\\009.", 1, DBNS_NORMAL, "\\000\\009.", 3, DBNS_NORMAL,
		  DNS_R_PARTIALMATCH, 24 },
		{ "\\009.", 1, DBNS_NSEC, "\\000\\009.", 3, DBNS_NSEC,
		  DNS_R_PARTIALMATCH, 12 },
		{ "\\009.", 1, DBNS_NSEC3, "\\000\\009.", 3, DBNS_NSEC3,
		  DNS_R_PARTIALMATCH, 0 },

		{ "\\045.", 1, DBNS_NORMAL, "\\000\\009.", 3, DBNS_NORMAL,
		  DNS_R_PARTIALMATCH, 24 },
		{ "\\045.", 1, DBNS_NSEC, "\\000\\009.", 3, DBNS_NSEC,
		  DNS_R_PARTIALMATCH, 12 },
		{ "\\045.", 1, DBNS_NSEC3, "\\000\\009.", 3, DBNS_NSEC3,
		  DNS_R_PARTIALMATCH, 0 },

		{ "\\044.", 1, DBNS_NORMAL, "\\000\\009.", 3, DBNS_NORMAL,
		  DNS_R_PARTIALMATCH, 24 },
		{ "\\044.", 1, DBNS_NSEC, "\\000\\009.", 3, DBNS_NSEC,
		  DNS_R_PARTIALMATCH, 12 },
		{ "\\044.", 1, DBNS_NSEC3, "\\000\\009.", 3, DBNS_NSEC3,
		  DNS_R_PARTIALMATCH, 0 },

		{ "\\000.", 1, DBNS_NORMAL, ".", 3, DBNS_NORMAL, ISC_R_SUCCESS,
		  33 },
		{ "\\000.", 1, DBNS_NSEC, ".", 3, DBNS_NSEC, ISC_R_SUCCESS,
		  21 },
		{ "\\000.", 1, DBNS_NSEC3, ".", 3, DBNS_NSEC3, ISC_R_SUCCESS,
		  9 },

		{ NULL, 0, 0, NULL, 0, 0, 0, 0 },
	};

	check_predecessors(qp, check4);
	dns_qp_destroy(&qp);
}

struct check_delete {
	const char *name;
	dns_rdatatype_t type;
	dns_namespace_t space;
	isc_result_t result;
};

static void
check_delete(dns_qp_t *qp, struct check_delete check[]) {
	for (int i = 0; check[i].name != NULL; i++) {
		isc_result_t result;
		dns_fixedname_t fn1;
		dns_name_t *name = dns_fixedname_initname(&fn1);
		dns_qpchain_t chain;

		dns_qpchain_init(qp, &chain);
		dns_test_namefromstring(check[i].name, &fn1);
		result = dns_qp_deletenametype(qp, name, check[i].type,
					       check[i].space, NULL, NULL);
#if 0
		fprintf(stderr, "%s%s type %u result %s (expected %s)\n",
			NAMESPACESTR(check[i].space), check[i].name,
			check[i].type, isc_result_totext(result),
			isc_result_totext(check[i].result));
#endif
		assert_int_equal(result, check[i].result);
	}
}

ISC_RUN_TEST_IMPL(qpkey_delete) {
	int i = 0;
	dns_qp_t *qp = NULL;
	static struct inserting insert1[] = {
		INSERT("a.", 53, DBNS_NORMAL),
		INSERT("b.a.", 1, DBNS_NORMAL),
		INSERT("c.b.a.", 53, DBNS_NORMAL),
		INSERT("e.d.c.b.a.", 1, DBNS_NORMAL),
		INSERT("b.", 1, DBNS_NORMAL),
		INSERT("b.", 2, DBNS_NORMAL),
		INSERT("b.", 65000, DBNS_NORMAL),
		INSERT("a.b.c.d.", 1, DBNS_NORMAL),
		INSERT("a.b.c.d.e.", 1, DBNS_NORMAL),
		INSERT("b.a.", 1, DBNS_NSEC),
		INSERT("e.d.c.b.a.", 1, DBNS_NSEC),
		INSERT("b.", 47, DBNS_NSEC),
		INSERT("b.", 47, DBNS_NSEC3),
		INSERT("c.b.b.", 2, DBNS_NSEC3),
		INSERT("c.d.", 3, DBNS_NSEC3),
		INSERT("", 0, 0),
	};
	/*
	 * NORMAL:         a. 53
	 * NORMAL:       b.a. 1
	 * NORMAL:     c.b.a. 53
	 * NORMAL: e.d.c.b.a. 1
	 * NORMAL:         b. 1, 2, 65000
	 * NORMAL:   a.b.c.d. 1
	 * NORMAL: a.b.c.d.e. 1
	 *
	 * NSEC:         b.a. 1
	 * NSEC:   e.d.c.b.a. 1
	 * NSEC:           b. 47
	 *
	 * NSEC3:          b. 47
	 * NSEC3:      c.b.b. 2
	 * NSEC3:        c.d. 3
	 */

	dns_qp_create(mctx, &string_methods, NULL, &qp);

	while (insert1[i].name[0] != '\0') {
		insert_nametype(qp, insert1[i].name, insert1[i].type,
				insert1[i].space, false);
		i++;
	}

	qp_test_dumpqp(qp);
	qp_test_dumptrie(qp);
	qp_test_dumpdot(qp);

	/* lookup checks before deleting */
	static struct check_qpchain chain1[] = {
		{ ".", 1, DBNS_NORMAL, ISC_R_NOTFOUND, 0, { NULL } },
		{ ".", 1, DBNS_NSEC, ISC_R_NOTFOUND, 0, { NULL } },
		{ ".", 1, DBNS_NSEC3, ISC_R_NOTFOUND, 0, { NULL } },

		{ "a.", 53, DBNS_NORMAL, ISC_R_SUCCESS, 1, { "a." } },
		{ "a.", 53, DBNS_NSEC, ISC_R_NOTFOUND, 0, { NULL } },
		{ "a.", 53, DBNS_NSEC3, ISC_R_NOTFOUND, 0, { NULL } },

		{ "b.", 1, DBNS_NORMAL, ISC_R_SUCCESS, 1, { "b." } },
		{ "b.", 1, DBNS_NSEC, DNS_R_NODATA, 1, { "b." } },
		{ "b.", 1, DBNS_NSEC3, DNS_R_NODATA, 1, { "b." } },

		{ "b.", 249, DBNS_NORMAL, DNS_R_NODATA, 1, { "b." } },
		{ "b.", 249, DBNS_NSEC, DNS_R_NODATA, 1, { "b." } },
		{ "b.", 249, DBNS_NSEC3, DNS_R_NODATA, 1, { "b." } },

		{ "b.a.", 1, DBNS_NORMAL, ISC_R_SUCCESS, 2, { "a.", "b.a." } },
		{ "b.a.", 1, DBNS_NSEC, ISC_R_SUCCESS, 1, { "b.a." } },
		{ "b.a.", 1, DBNS_NSEC3, ISC_R_NOTFOUND, 0, { NULL } },

		{ "c.b.a.",
		  53,
		  DBNS_NORMAL,
		  ISC_R_SUCCESS,
		  3,
		  { "a.", "b.a.", "c.b.a." } },
		{ "c.b.a.", 53, DBNS_NSEC, DNS_R_PARTIALMATCH, 1, { "b.a." } },
		{ "c.b.a.", 53, DBNS_NSEC3, ISC_R_NOTFOUND, 0, { NULL } },

		{ "c.", 1, DBNS_NORMAL, ISC_R_NOTFOUND, 0, { NULL } },
		{ "c.", 1, DBNS_NSEC, ISC_R_NOTFOUND, 0, { NULL } },
		{ "c.", 1, DBNS_NSEC3, ISC_R_NOTFOUND, 0, { NULL } },

		{ "e.d.c.b.a.",
		  1,
		  DBNS_NORMAL,
		  ISC_R_SUCCESS,
		  4,
		  { "a.", "b.a.", "c.b.a.", "e.d.c.b.a." } },
		{ "e.d.c.b.a.",
		  1,
		  DBNS_NSEC,
		  ISC_R_SUCCESS,
		  2,
		  { "b.a.", "e.d.c.b.a." } },
		{ "e.d.c.b.a.", 1, DBNS_NSEC3, ISC_R_NOTFOUND, 0, { NULL } },

		{ "a.b.c.d.", 1, DBNS_NORMAL, ISC_R_SUCCESS, 1, { "a.b.c.d." } },
		{ "a.b.c.d.", 1, DBNS_NSEC, ISC_R_NOTFOUND, 0, { NULL } },
		{ "a.b.c.d.", 1, DBNS_NSEC3, DNS_R_PARTIALMATCH, 1, { "c.d." } },

		{ "b.c.d.", 1, DBNS_NORMAL, ISC_R_NOTFOUND, 0, { NULL } },
		{ "b.c.d.", 1, DBNS_NSEC, ISC_R_NOTFOUND, 0, { NULL } },
		{ "b.c.d.", 1, DBNS_NSEC3, DNS_R_PARTIALMATCH, 1, { "c.d." } },

		{ "f.b.b.d.", 1, DBNS_NORMAL, ISC_R_NOTFOUND, 0, { NULL } },
		{ "f.b.b.d.", 1, DBNS_NSEC, ISC_R_NOTFOUND, 0, { NULL } },
		{ "f.b.b.d.", 1, DBNS_NSEC3, ISC_R_NOTFOUND, 0, { NULL } },

		{ NULL, 0, 0, 0, 0, { NULL } },
	};
	check_qpchain(qp, chain1);

	static struct check_predecessors pred1[] = {
		{ ".", 1, DBNS_NORMAL, "c.d.", 3, DBNS_NSEC3, ISC_R_NOTFOUND,
		  0 },
		{ ".", 1, DBNS_NSEC, "a.b.c.d.e.", 1, DBNS_NORMAL,
		  ISC_R_NOTFOUND, 6 },
		{ ".", 1, DBNS_NSEC3, "b.", 47, DBNS_NSEC, ISC_R_NOTFOUND, 3 },

		{ "a.", 53, DBNS_NORMAL, "c.d.", 3, DBNS_NSEC3, ISC_R_SUCCESS,
		  0 },
		{ "a.", 53, DBNS_NSEC, "a.b.c.d.e.", 1, DBNS_NORMAL,
		  ISC_R_NOTFOUND, 6 },
		{ "a.", 53, DBNS_NSEC3, "b.", 47, DBNS_NSEC, ISC_R_NOTFOUND,
		  3 },

		{ "b.", 1, DBNS_NORMAL, "e.d.c.b.a.", 1, DBNS_NORMAL,
		  ISC_R_SUCCESS, 11 },
		{ "b.", 1, DBNS_NSEC, "e.d.c.b.a.", 1, DBNS_NSEC, DNS_R_NODATA,
		  4 },
		{ "b.", 1, DBNS_NSEC3, "b.", 47, DBNS_NSEC, DNS_R_NODATA, 3 },

		{ "b.a.", 1, DBNS_NORMAL, "a.", 53, DBNS_NORMAL, ISC_R_SUCCESS,
		  14 },
		{ "b.a.", 1, DBNS_NSEC, "a.b.c.d.e.", 1, DBNS_NORMAL,
		  ISC_R_SUCCESS, 6 },
		{ "b.a.", 1, DBNS_NSEC3, "b.", 47, DBNS_NSEC, ISC_R_NOTFOUND,
		  3 },

		{ "c.b.a.", 53, DBNS_NORMAL, "b.a.", 1, DBNS_NORMAL,
		  ISC_R_SUCCESS, 13 },
		{ "c.b.a.", 53, DBNS_NSEC, "b.a.", 1, DBNS_NSEC,
		  DNS_R_PARTIALMATCH, 5 },
		{ "c.b.a.", 53, DBNS_NSEC3, "b.", 47, DBNS_NSEC, ISC_R_NOTFOUND,
		  3 },

		{ "c.", 1, DBNS_NORMAL, "b.", 65000, DBNS_NORMAL,
		  ISC_R_NOTFOUND, 8 },
		{ "c.", 1, DBNS_NSEC, "b.", 47, DBNS_NSEC, ISC_R_NOTFOUND, 3 },
		{ "c.", 1, DBNS_NSEC3, "c.b.b.", 2, DBNS_NSEC3, ISC_R_NOTFOUND,
		  1 },

		{ "e.d.c.b.a.", 1, DBNS_NORMAL, "c.b.a.", 53, DBNS_NORMAL,
		  ISC_R_SUCCESS, 12 },
		{ "e.d.c.b.a.", 1, DBNS_NSEC, "b.a.", 1, DBNS_NSEC,
		  ISC_R_SUCCESS, 5 },
		{ "e.d.c.b.a.", 1, DBNS_NSEC3, "b.", 47, DBNS_NSEC,
		  ISC_R_NOTFOUND, 3 },

		{ "a.b.c.d.", 1, DBNS_NORMAL, "b.", 65000, DBNS_NORMAL,
		  ISC_R_SUCCESS, 8 },
		{ "a.b.c.d.", 1, DBNS_NSEC, "b.", 47, DBNS_NSEC, ISC_R_NOTFOUND,
		  3 },
		{ "a.b.c.d.", 1, DBNS_NSEC3, "c.d.", 3, DBNS_NSEC3,
		  DNS_R_PARTIALMATCH, 0 },

		{ "b.c.d.", 1, DBNS_NORMAL, "b.", 65000, DBNS_NORMAL,
		  ISC_R_NOTFOUND, 8 },
		{ "b.c.d.", 1, DBNS_NSEC, "b.", 47, DBNS_NSEC, ISC_R_NOTFOUND,
		  3 },
		{ "b.c.d.", 1, DBNS_NSEC3, "c.d.", 3, DBNS_NSEC3,
		  DNS_R_PARTIALMATCH, 0 },

		{ "f.b.b.d.", 1, DBNS_NORMAL, "b.", 65000, DBNS_NORMAL,
		  ISC_R_NOTFOUND, 8 },
		{ "f.b.b.d.", 1, DBNS_NSEC, "b.", 47, DBNS_NSEC, ISC_R_NOTFOUND,
		  3 },
		{ "f.b.b.d.", 1, DBNS_NSEC3, "c.b.b.", 2, DBNS_NSEC3,
		  ISC_R_NOTFOUND, 1 },

		{ NULL, 0, 0, NULL, 0, 0, 0 },
	};
	check_predecessors(qp, pred1);

	/* delete checks */
	static struct check_delete del1[] = {
		{ ".", 1, DBNS_NORMAL, ISC_R_NOTFOUND },
		{ "a.", 1, DBNS_NSEC, ISC_R_NOTFOUND },
		{ "a.", 53, DBNS_NORMAL, ISC_R_SUCCESS },
		{ "b.", 2, DBNS_NORMAL, ISC_R_SUCCESS },
		{ "b.", 65000, DBNS_NSEC, ISC_R_NOTFOUND },
		{ "b.", 65000, DBNS_NORMAL, ISC_R_SUCCESS },
		{ "b.", 47, DBNS_NSEC3, ISC_R_SUCCESS },
		{ "b.a.", 3, DBNS_NSEC3, ISC_R_NOTFOUND },
		{ "b.a.", 3, DBNS_NORMAL, ISC_R_NOTFOUND },
		{ "b.a.", 1, DBNS_NORMAL, ISC_R_SUCCESS },
		{ "c.d.", 3, DBNS_NSEC3, ISC_R_SUCCESS },
		{ "c.b.b.", 2, DBNS_NSEC3, ISC_R_SUCCESS },
		{ "e.d.c.b.a.", 1, DBNS_NORMAL, ISC_R_SUCCESS },
		{ NULL, 0, 0 },
	};
	check_delete(qp, del1);

	/* again */
	static struct check_delete del2[] = {
		{ ".", 1, DBNS_NORMAL, ISC_R_NOTFOUND },
		{ "a.", 1, DBNS_NSEC, ISC_R_NOTFOUND },
		{ "a.", 53, DBNS_NORMAL, ISC_R_NOTFOUND },
		{ "b.", 2, DBNS_NORMAL, ISC_R_NOTFOUND },
		{ "b.", 65000, DBNS_NSEC, ISC_R_NOTFOUND },
		{ "b.", 65000, DBNS_NORMAL, ISC_R_NOTFOUND },
		{ "b.", 47, DBNS_NSEC3, ISC_R_NOTFOUND },
		{ "b.a.", 3, DBNS_NSEC3, ISC_R_NOTFOUND },
		{ "b.a.", 3, DBNS_NORMAL, ISC_R_NOTFOUND },
		{ "b.a.", 1, DBNS_NORMAL, ISC_R_NOTFOUND },
		{ "c.d.", 3, DBNS_NORMAL, ISC_R_NOTFOUND },
		{ "c.b.b.", 2, DBNS_NORMAL, ISC_R_NOTFOUND },
		{ "e.d.c.b.a.", 1, DBNS_NORMAL, ISC_R_NOTFOUND },
		{ NULL, 0, 0 },
	};
	check_delete(qp, del2);

	/* lookup checks after deleting */
	static struct check_qpchain chain2[] = {
		{ ".", 1, DBNS_NORMAL, ISC_R_NOTFOUND, 0, { NULL } },
		{ ".", 1, DBNS_NSEC, ISC_R_NOTFOUND, 0, { NULL } },
		{ ".", 1, DBNS_NSEC3, ISC_R_NOTFOUND, 0, { NULL } },

		{ "a.", 53, DBNS_NORMAL, ISC_R_NOTFOUND, 0, { NULL } },
		{ "a.", 53, DBNS_NSEC, ISC_R_NOTFOUND, 0, { NULL } },
		{ "a.", 53, DBNS_NSEC3, ISC_R_NOTFOUND, 0, { NULL } },

		{ "b.", 1, DBNS_NORMAL, ISC_R_SUCCESS, 1, { "b." } },
		{ "b.", 1, DBNS_NSEC, DNS_R_NODATA, 1, { "b." } },
		{ "b.", 1, DBNS_NSEC3, ISC_R_NOTFOUND, 0, { NULL } },

		{ "b.", 2, DBNS_NORMAL, DNS_R_NODATA, 1, { "b." } },
		{ "b.", 2, DBNS_NSEC, DNS_R_NODATA, 1, { "b." } },
		{ "b.", 2, DBNS_NSEC3, ISC_R_NOTFOUND, 0, { NULL } },

		{ "b.", 249, DBNS_NORMAL, DNS_R_NODATA, 1, { "b." } },
		{ "b.", 249, DBNS_NSEC, DNS_R_NODATA, 1, { "b." } },
		{ "b.", 249, DBNS_NSEC3, ISC_R_NOTFOUND, 0, { NULL } },

		{ "b.a.", 1, DBNS_NORMAL, ISC_R_NOTFOUND, 0, { NULL } },
		{ "b.a.", 1, DBNS_NSEC, ISC_R_SUCCESS, 1, { "b.a." } },
		{ "b.a.", 1, DBNS_NSEC3, ISC_R_NOTFOUND, 0, { NULL } },

		{ "c.b.a.", 53, DBNS_NORMAL, ISC_R_SUCCESS, 1, { "c.b.a." } },
		{ "c.b.a.", 53, DBNS_NSEC, DNS_R_PARTIALMATCH, 1, { "b.a." } },
		{ "c.b.a.", 53, DBNS_NSEC3, ISC_R_NOTFOUND, 0, { NULL } },

		{ "c.", 1, DBNS_NORMAL, ISC_R_NOTFOUND, 0, { NULL } },
		{ "c.", 1, DBNS_NSEC, ISC_R_NOTFOUND, 0, { NULL } },
		{ "c.", 1, DBNS_NSEC3, ISC_R_NOTFOUND, 0, { NULL } },

		{ "e.d.c.b.a.",
		  1,
		  DBNS_NORMAL,
		  DNS_R_PARTIALMATCH,
		  1,
		  { "c.b.a." } },
		{ "e.d.c.b.a.",
		  1,
		  DBNS_NSEC,
		  ISC_R_SUCCESS,
		  2,
		  { "b.a.", "e.d.c.b.a." } },
		{ "e.d.c.b.a.", 1, DBNS_NSEC3, ISC_R_NOTFOUND, 0, { NULL } },

		{ "a.b.c.d.", 1, DBNS_NORMAL, ISC_R_SUCCESS, 1, { "a.b.c.d." } },
		{ "a.b.c.d.", 1, DBNS_NSEC, ISC_R_NOTFOUND, 0, { NULL } },
		{ "a.b.c.d.", 1, DBNS_NSEC3, ISC_R_NOTFOUND, 0, { NULL } },

		{ "b.c.d.", 1, DBNS_NORMAL, ISC_R_NOTFOUND, 0, { NULL } },
		{ "b.c.d.", 1, DBNS_NSEC, ISC_R_NOTFOUND, 0, { NULL } },
		{ "b.c.d.", 1, DBNS_NSEC3, ISC_R_NOTFOUND, 0, { NULL } },

		{ "f.b.b.d.", 1, DBNS_NORMAL, ISC_R_NOTFOUND, 0, { NULL } },
		{ "f.b.b.d.", 1, DBNS_NSEC, ISC_R_NOTFOUND, 0, { NULL } },
		{ "f.b.b.d.", 1, DBNS_NSEC3, ISC_R_NOTFOUND, 0, { NULL } },

		{ NULL, 0, 0, 0, 0, { NULL } },
	};
	check_qpchain(qp, chain2);

	static struct check_predecessors pred2[] = {
		{ ".", 1, DBNS_NORMAL, "b.", 47, DBNS_NSEC, ISC_R_NOTFOUND, 0 },
		{ ".", 1, DBNS_NSEC, "a.b.c.d.e.", 1, DBNS_NORMAL,
		  ISC_R_NOTFOUND, 3 },
		{ ".", 1, DBNS_NSEC3, "b.", 47, DBNS_NSEC, ISC_R_NOTFOUND, 0 },

		{ "a.", 53, DBNS_NORMAL, "b.", 47, DBNS_NSEC, ISC_R_NOTFOUND,
		  0 },
		{ "a.", 53, DBNS_NSEC, "a.b.c.d.e.", 1, DBNS_NORMAL,
		  ISC_R_NOTFOUND, 3 },
		{ "a.", 53, DBNS_NSEC3, "b.", 47, DBNS_NSEC, ISC_R_NOTFOUND,
		  0 },

		{ "b.", 1, DBNS_NORMAL, "c.b.a.", 53, DBNS_NORMAL,
		  ISC_R_SUCCESS, 6 },
		{ "b.", 1, DBNS_NSEC, "e.d.c.b.a.", 1, DBNS_NSEC, DNS_R_NODATA,
		  1 },
		{ "b.", 1, DBNS_NSEC3, "b.", 47, DBNS_NSEC, ISC_R_NOTFOUND, 0 },

		{ "b.a.", 1, DBNS_NORMAL, "b.", 47, DBNS_NSEC, ISC_R_NOTFOUND,
		  0 },
		{ "b.a.", 1, DBNS_NSEC, "a.b.c.d.e.", 1, DBNS_NORMAL,
		  ISC_R_SUCCESS, 3 },
		{ "b.a.", 1, DBNS_NSEC3, "b.", 47, DBNS_NSEC, ISC_R_NOTFOUND,
		  0 },

		{ "c.b.a.", 53, DBNS_NORMAL, "b.", 47, DBNS_NSEC, ISC_R_SUCCESS,
		  0 },
		{ "c.b.a.", 53, DBNS_NSEC, "b.a.", 1, DBNS_NSEC,
		  DNS_R_PARTIALMATCH, 2 },
		{ "c.b.a.", 53, DBNS_NSEC3, "b.", 47, DBNS_NSEC, ISC_R_NOTFOUND,
		  0 },

		{ "c.", 1, DBNS_NORMAL, "b.", 1, DBNS_NORMAL, ISC_R_NOTFOUND,
		  5 },
		{ "c.", 1, DBNS_NSEC, "b.", 47, DBNS_NSEC, ISC_R_NOTFOUND, 0 },
		{ "c.", 1, DBNS_NSEC3, "b.", 47, DBNS_NSEC, ISC_R_NOTFOUND, 0 },

		{ "e.d.c.b.a.", 1, DBNS_NORMAL, "c.b.a.", 53, DBNS_NORMAL,
		  DNS_R_PARTIALMATCH, 6 },
		{ "e.d.c.b.a.", 1, DBNS_NSEC, "b.a.", 1, DBNS_NSEC,
		  ISC_R_SUCCESS, 2 },
		{ "e.d.c.b.a.", 1, DBNS_NSEC3, "b.", 47, DBNS_NSEC,
		  ISC_R_NOTFOUND, 0 },

		{ "a.b.c.d.", 1, DBNS_NORMAL, "b.", 1, DBNS_NORMAL,
		  ISC_R_SUCCESS, 5 },
		{ "a.b.c.d.", 1, DBNS_NSEC, "b.", 47, DBNS_NSEC, ISC_R_NOTFOUND,
		  0 },
		{ "a.b.c.d.", 1, DBNS_NSEC3, "b.", 47, DBNS_NSEC,
		  ISC_R_NOTFOUND, 0 },

		{ "b.c.d.", 1, DBNS_NORMAL, "b.", 1, DBNS_NORMAL,
		  ISC_R_NOTFOUND, 5 },
		{ "b.c.d.", 1, DBNS_NSEC, "b.", 47, DBNS_NSEC, ISC_R_NOTFOUND,
		  0 },
		{ "b.c.d.", 1, DBNS_NSEC3, "b.", 47, DBNS_NSEC, ISC_R_NOTFOUND,
		  0 },

		{ "f.b.b.d.", 1, DBNS_NORMAL, "b.", 1, DBNS_NORMAL,
		  ISC_R_NOTFOUND, 5 },
		{ "f.b.b.d.", 1, DBNS_NSEC, "b.", 47, DBNS_NSEC, ISC_R_NOTFOUND,
		  0 },
		{ "f.b.b.d.", 1, DBNS_NSEC3, "b.", 47, DBNS_NSEC,
		  ISC_R_NOTFOUND, 0 },

		{ NULL, 0, 0, NULL, 0, 0, 0, 0 },
	};
	check_predecessors(qp, pred2);

	dns_qp_destroy(&qp);
}

ISC_TEST_LIST_START
ISC_TEST_ENTRY(qpkey_name)
ISC_TEST_ENTRY(qpkey_sort)
ISC_TEST_ENTRY(partialmatch)
ISC_TEST_ENTRY(qpchain)
ISC_TEST_ENTRY(predecessors)
ISC_TEST_ENTRY(fixiterator)
ISC_TEST_ENTRY(qpkey_delete)
ISC_TEST_LIST_END

ISC_TEST_MAIN
