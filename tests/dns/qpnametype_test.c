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

#include <isc/random.h>
#include <isc/refcount.h>
#include <isc/result.h>
#include <isc/string.h>
#include <isc/urcu.h>
#include <isc/util.h>

#include <dns/name.h>
#include <dns/qp.h>

#include "qp_p.h"

#include <tests/dns.h>
#include <tests/qp.h>

bool verbose = true;

ISC_RUN_TEST_IMPL(qpkey_nametype) {
	struct {
		const char *namestr;
		uint16_t type;
		uint8_t key[512];
		size_t len;
	} testcases[] = {
		{
			.namestr = "",
			.type = 0,
			.key = { 0x03, 0x03, 0x03, 0x03, 0x02 },
			.len = 0 + QPKEYTYPELEN,
		},
		{
			.namestr = ".",
			.type = 1,
			.key = { 0x02, 0x03, 0x03, 0x03, 0x04, 0x02 },
			.len = 1 + QPKEYTYPELEN,
		},
		{
			.namestr = "\\000",
			.type = 55,
			.key = { 0x04, 0x04, 0x02, 0x03, 0x03, 0x04, 0x0b,
				 0x02 },
			.len = 3 + QPKEYTYPELEN,
		},
		{
			.namestr = "\\000\\009",
			.type = 252,
			.key = { 0x04, 0x04, 0x04, 0x0d, 0x02, 0x03, 0x03, 0x08,
				 0x14, 0x02 },
			.len = 5 + QPKEYTYPELEN,
		},
		{
			.namestr = "com",
			.type = 253,
			.key = { 0x17, 0x23, 0x21, 0x02, 0x03, 0x03, 0x08, 0x15,
				 0x02 },
			.len = 4 + QPKEYTYPELEN,
		},
		{
			.namestr = "com.",
			.type = 1234,
			.key = { 0x02, 0x17, 0x23, 0x21, 0x02, 0x03, 0x03, 0x1d,
				 0x0f, 0x02 },
			.len = 5 + QPKEYTYPELEN,
		},
		{
			.namestr = "example.com.",
			.type = 34567,
			.key = { 0x02, 0x17, 0x23, 0x21, 0x02, 0x19, 0x2c, 0x15,
				 0x21, 0x24, 0x20, 0x19, 0x02, 0x03, 0x12, 0x21,
				 0x19, 0x02 },
			.len = 13 + QPKEYTYPELEN,
		},
		{
			.namestr = "example.com",
			.type = 65534,
			.key = { 0x17, 0x23, 0x21, 0x02, 0x19, 0x2c, 0x15, 0x21,
				 0x24, 0x20, 0x19, 0x02, 0x03, 0x20, 0x22, 0x13,
				 0x02 },
			.len = 12 + QPKEYTYPELEN,
		},
		{
			.namestr = "EXAMPLE.COM",
			.type = 65535,
			.key = { 0x17, 0x23, 0x21, 0x02, 0x19, 0x2c, 0x15, 0x21,
				 0x24, 0x20, 0x19, 0x02, 0x03, 0x20, 0x22, 0x14,
				 0x02 },
			.len = 12 + QPKEYTYPELEN,
		},
	};

	for (size_t i = 0; i < ARRAY_SIZE(testcases); i++) {
		size_t len;
		dns_qpkey_t key;
		dns_fixedname_t fn1, fn2;
		dns_name_t *in = NULL, *out = NULL;
		uint16_t typeout = 0;

		in = dns_fixedname_initname(&fn1);
		if ((testcases[i].len - QPKEYTYPELEN) != 0) {
			dns_test_namefromstring(testcases[i].namestr, &fn1);
		}
		len = dns_qpkey_fromnametype(key, in, testcases[i].type);
		if (verbose) {
			qp_test_printkey(key, len);
		}

		assert_int_equal(testcases[i].len, len);
		assert_memory_equal(testcases[i].key, key, len);

		out = dns_fixedname_initname(&fn2);
		dns_qpkey_tonametype(key, len, out, &typeout);
		assert_true(dns_name_equal(in, out));
		assert_int_equal(testcases[i].type, typeout);
	}
}

ISC_RUN_TEST_IMPL(qpkey_sort) {
	struct {
		const char *namestr;
		dns_name_t *name;
		dns_fixedname_t fixed;
		uint16_t type;
		size_t len;
		dns_qpkey_t key;
	} testcases[] = {
		{ .namestr = ".", .type = 1 },
		{ .namestr = ".", .type = 2 },
		{ .namestr = ".", .type = 48 },
		{ .namestr = ".", .type = 236 },
		{ .namestr = ".", .type = 60021 },

		{ .namestr = "\\000.", .type = 1 },
		{ .namestr = "\\000.", .type = 2 },
		{ .namestr = "\\000.", .type = 48 },
		{ .namestr = "\\000.", .type = 236 },
		{ .namestr = "\\000.", .type = 60021 },

		{ .namestr = "\\000.\\000.", .type = 1 },
		{ .namestr = "\\000.\\000.", .type = 2 },
		{ .namestr = "\\000.\\000.", .type = 48 },
		{ .namestr = "\\000.\\000.", .type = 236 },
		{ .namestr = "\\000.\\000.", .type = 60021 },

		{ .namestr = "\\000\\009.", .type = 1 },
		{ .namestr = "\\000\\009.", .type = 2 },
		{ .namestr = "\\000\\009.", .type = 48 },
		{ .namestr = "\\000\\009.", .type = 236 },
		{ .namestr = "\\000\\009.", .type = 60021 },

		{ .namestr = "\\007.", .type = 1 },
		{ .namestr = "\\007.", .type = 2 },
		{ .namestr = "\\007.", .type = 48 },
		{ .namestr = "\\007.", .type = 236 },
		{ .namestr = "\\007.", .type = 60021 },

		{ .namestr = "example.com.", .type = 1 },
		{ .namestr = "example.com.", .type = 2 },
		{ .namestr = "example.com.", .type = 48 },
		{ .namestr = "example.com.", .type = 236 },
		{ .namestr = "example.com.", .type = 60021 },

		{ .namestr = "EXAMPLE.COM.", .type = 1 },
		{ .namestr = "EXAMPLE.COM.", .type = 2 },
		{ .namestr = "EXAMPLE.COM.", .type = 48 },
		{ .namestr = "EXAMPLE.COM.", .type = 236 },
		{ .namestr = "EXAMPLE.COM.", .type = 60021 },

		{ .namestr = "www.example.com.", .type = 1 },
		{ .namestr = "www.example.com.", .type = 2 },
		{ .namestr = "www.example.com.", .type = 48 },
		{ .namestr = "www.example.com.", .type = 236 },
		{ .namestr = "www.example.com.", .type = 60021 },

		{ .namestr = "exam.com.", .type = 1 },
		{ .namestr = "exam.com.", .type = 2 },
		{ .namestr = "exam.com.", .type = 48 },
		{ .namestr = "exam.com.", .type = 236 },
		{ .namestr = "exam.com.", .type = 60021 },

		{ .namestr = "exams.com.", .type = 1 },
		{ .namestr = "exams.com.", .type = 2 },
		{ .namestr = "exams.com.", .type = 48 },
		{ .namestr = "exams.com.", .type = 236 },
		{ .namestr = "exams.com.", .type = 60021 },

		{ .namestr = "exam\\000.com.", .type = 1 },
		{ .namestr = "exam\\000.com.", .type = 2 },
		{ .namestr = "exam\\000.com.", .type = 48 },
		{ .namestr = "exam\\000.com.", .type = 236 },
		{ .namestr = "exam\\000.com.", .type = 60021 },
	};

	for (size_t i = 0; i < ARRAY_SIZE(testcases); i++) {
		dns_test_namefromstring(testcases[i].namestr,
					&testcases[i].fixed);
		testcases[i].name = dns_fixedname_name(&testcases[i].fixed);
		testcases[i].len = dns_qpkey_fromnametype(
			testcases[i].key, testcases[i].name, testcases[i].type);
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
			if (namecmp == 0) {
				assert_true((typecmp < 0) == (keycmp < 0));
				assert_true((typecmp > 0) == (keycmp > 0));
				assert_true((typecmp == 0) == (keycmp == 0));
			} else {
				assert_true((namecmp < 0) == (keycmp < 0));
				assert_true((namecmp > 0) == (keycmp > 0));
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
	uint16_t type = (uint16_t)ival;

	UNUSED(uctx);
	UNUSED(ival);
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
	return dns_qpkey_fromnametype(key, dns_fixedname_name(&fixed), type);
}

const dns_qpmethods_t string_methods = {
	no_op,
	no_op,
	qpkey_fromstring,
	getname,
};

struct inserting {
	/* Fixed size strings [32] should ensure leaf-compatible alignment. */
	const char name[32];
	uint16_t type;
	/* Add padding to ensure leaf-compatible alignment. */
	uint16_t pad;
};

struct check_partialmatch {
	const char *name;
	uint16_t type;
	isc_result_t result;
	const char *found;
};

static void
check_partialmatch(dns_qp_t *qp, struct check_partialmatch check[]) {
	for (int i = 0; check[i].name != NULL; i++) {
		isc_result_t result;
		dns_fixedname_t fn1, fn2;
		dns_name_t *name = dns_fixedname_initname(&fn1);
		dns_name_t *foundname = dns_fixedname_initname(&fn2);
		uint16_t type = check[i].type;
		void *pval = NULL;

		dns_test_namefromstring(check[i].name, &fn1);
		result = dns_qp_lookup(qp, name, type, foundname, NULL, NULL,
				       &pval, NULL);

#if 0
		fprintf(stderr,
			"%s type %u %s (expected %s) "
			"value \"%s\" (expected \"%s\")\n",
			check[i].name, check[i].type, isc_result_totext(result),
			isc_result_totext(check[i].result), (char *)pval,
			check[i].found);
#endif

		assert_int_equal(result, check[i].result);
		if (result == ISC_R_SUCCESS) {
			assert_true(dns_name_equal(name, foundname));
		} else if (result == DNS_R_NODATA) {
			assert_true(dns_name_equal(name, foundname));
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
		}
		if (check[i].found == NULL) {
			assert_null(pval);
		} else {
			assert_string_equal(pval, check[i].found);
		}
	}
}

static void
insert_nametype(dns_qp_t *qp, const char *str, uint16_t type) {
	isc_result_t result;
	uintptr_t pval = (uintptr_t)str;
	uint32_t ival = (uint32_t)type;
	fprintf(stderr, "INSERT: %lx %s %u\n", pval, str, type);
	INSIST((pval & 3) == 0);
	result = dns_qp_insert(qp, (void *)pval, ival);
	assert_int_equal(result, ISC_R_SUCCESS);
}

ISC_RUN_TEST_IMPL(partialmatch) {
	isc_result_t result;
	dns_qp_t *qp = NULL;
	int i = 0;

	dns_qp_create(mctx, &string_methods, NULL, &qp);

	static struct inserting insert1[] = {
		{ "a.b.", 1 },
		{ "a.b.", 60021 },

		{ "b.", 0 },
		{ "b.", 48 },

		{ "fo.bar.", 1 },

		{ "foo.bar.", 1 },
		{ "foo.bar.", 2 },
		{ "foo.bar.", 48 },
		{ "foo.bar.", 236 },
		{ "foo.bar.", 60021 },

		{ "fooo.bar.", 1 },
		{ "fooo.bar.", 2 },

		{ "web.foo.bar.", 18 },
		{ "web.foo.bar.", 303 },

		{ ".", 1 },

		{ "", 1 },
	};

	/*
	 * omit the root node for now, otherwise we'll get "partial match"
	 * results when we want "not found".
	 */
	while (insert1[i].name[0] != '.') {
		insert_nametype(qp, insert1[i].name, insert1[i].type);
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
	check_partialmatch(qp, check1);

	/* what if the trie contains the root? */
	INSIST(insert1[i].name[0] == '.');
	insert_nametype(qp, insert1[i].name, insert1[i].type);

	static struct check_partialmatch check2[] = {
		{ "b.c.", 1, DNS_R_PARTIALMATCH, "." },
		{ "bar.", 1, DNS_R_PARTIALMATCH, "." },
		{ "foo.bar.", 1, ISC_R_SUCCESS, "foo.bar." },
		{ "foo.bar.", 3, DNS_R_NODATA, "foo.bar." },
		{ "bar", 1, ISC_R_NOTFOUND, NULL },
		{ NULL, 0, 0, NULL },
	};
	check_partialmatch(qp, check2);

	/*
	 * what if entries in the trie are relative to the zone apex
	 * and there's no root node?
	 */
	dns_qpkey_t rootkey = { SHIFT_NOBYTE, SHIFT_RRTYPE,	SHIFT_RRTYPE,
				SHIFT_RRTYPE, SHIFT_RRTYPE + 1, SHIFT_NOBYTE };
	result = dns_qp_deletekey(qp, rootkey, 5, NULL, NULL);
	assert_int_equal(result, ISC_R_SUCCESS);

	check_partialmatch(qp, (struct check_partialmatch[]){
				       { "bar", 1, ISC_R_NOTFOUND, NULL },
				       { "bar.", 1, ISC_R_NOTFOUND, NULL },
				       { NULL, 0, 0, NULL },
			       });

	dns_qp_destroy(&qp);
}

struct check_qpchain {
	const char *name;
	uint16_t type;
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
		uint16_t type = check[i].type;
		dns_qpchain_t chain;

		dns_qpchain_init(qp, &chain);
		dns_test_namefromstring(check[i].name, &fn1);
		result = dns_qp_lookup(qp, name, type, NULL, iter, &chain, NULL,
				       NULL);
#if 0
		fprintf(stderr,
			"%s %s (expected %s), "
			"len %d (expected %d)\n",
			check[i].name, isc_result_totext(result),
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
		{ "a.", 53 },

		{ "b.", 1 },
		{ "b.", 2 },
		{ "b.", 50 },
		{ "b.", 250 },
		{ "b.", 65000 },

		{ "c.b.a.", 53 },

		{ "e.d.c.b.a.", 1 },

		{ "c.b.b.", 2 },

		{ "c.d.", 3 },

		{ "a.b.c.d.", 1 },

		{ "a.b.c.d.e.", 1 },

		{ "b.a.", 1 },

		{ "x.k.c.d.", 1 },
		{ "x.k.c.d.", 2 },
		{ "x.k.c.d.", 50 },
		{ "x.k.c.d.", 250 },
		{ "x.k.c.d.", 65000 },

		{ ".", 1 },
		{ ".", 2 },
		{ ".", 50 },
		{ ".", 250 },
		{ ".", 65000 },

		{ "", 0 },
	};

	dns_qp_create(mctx, &string_methods, NULL, &qp);

	while (insert1[i].name[0] != '\0') {
		insert_nametype(qp, insert1[i].name, insert1[i].type);
		i++;
	}

	static struct check_qpchain check1[] = {
		{ "b.", 1, ISC_R_SUCCESS, 2, { ".", "b." } },
		{ "b.", 249, DNS_R_NODATA, 2, { ".", "b." } },

		{ "b.a.", 1, ISC_R_SUCCESS, 3, { ".", "a.", "b.a." } },
		{ "b.a.", 2, DNS_R_NODATA, 3, { ".", "a.", "b.a." } },

		{ "c.", 1, DNS_R_PARTIALMATCH, 1, { "." } },

		{ "e.d.c.b.a.",
		  1,
		  ISC_R_SUCCESS,
		  5,
		  { ".", "a.", "b.a.", "c.b.a.", "e.d.c.b.a." } },
		{ "e.d.c.b.a.",
		  2,
		  DNS_R_NODATA,
		  5,
		  { ".", "a.", "b.a.", "c.b.a.", "e.d.c.b.a." } },

		{ "a.b.c.d.", 1, ISC_R_SUCCESS, 3, { ".", "c.d.", "a.b.c.d." } },

		{ "b.c.d.", 1, DNS_R_PARTIALMATCH, 2, { ".", "c.d." } },
		{ "b.c.d.", 2, DNS_R_PARTIALMATCH, 2, { ".", "c.d." } },

		{ "x.k.c.d.",
		  250,
		  ISC_R_SUCCESS,
		  3,
		  { ".", "c.d.", "x.k.c.d." } },
		{ "x.k.c.d.",
		  251,
		  DNS_R_NODATA,
		  3,
		  { ".", "c.d.", "x.k.c.d." } },

		{ "z.x.k.c.d.",
		  1,
		  DNS_R_PARTIALMATCH,
		  3,
		  { ".", "c.d.", "x.k.c.d." } },

		{ NULL, 0, 0, 0, { NULL } },
	};

	check_qpchain(qp, check1);
	dns_qp_destroy(&qp);

	static struct inserting insert2[] = {
		{ "a.", 1 },	  { "a.", 53 },	     { "d.b.a.", 1 },
		{ "d.b.a.", 53 }, { "z.d.b.a.", 1 }, { "z.d.b.a.", 53 },
		{ "", 0 },
	};

	i = 0;
	dns_qp_create(mctx, &string_methods, NULL, &qp);

	while (insert2[i].name[0] != '\0') {
		insert_nametype(qp, insert2[i].name, insert2[i].type);
		i++;
	}

	static struct check_qpchain check2[] = {
		{ "f.c.b.a.", 1, DNS_R_PARTIALMATCH, 1, { "a." } },
		{ NULL, 0, 0, 0, { NULL } },
	};

	check_qpchain(qp, check2);
	dns_qp_destroy(&qp);
}

struct check_predecessors {
	const char *name;
	uint16_t type;
	const char *predecessor;
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

	for (int i = 0; check[i].name != NULL; i++) {
		dns_qpiter_t it;
		uint16_t type = check[i].type;

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

		result = dns_qp_lookup(qp, name, type, NULL, &it, chain, NULL,
				       NULL);
#if 0
		fprintf(stderr, "%s %u: expected %s got %s\n", check[i].name,
			type, isc_result_totext(check[i].result),
			isc_result_totext(result));
#endif
		assert_int_equal(result, check[i].result);

		if (result == ISC_R_SUCCESS) {
			/*
			 * we found an exact match; iterate to find
			 * the predecessor.
			 */
			result = dns_qpiter_prev(&it, pred, NULL, NULL);
			if (result == ISC_R_NOMORE) {
				result = dns_qpiter_prev(&it, pred, NULL, NULL);
			}
		} else {
			/*
			 * we didn't find a match, so the iterator should
			 * already be pointed at the predecessor node.
			 */
			result = dns_qpiter_current(&it, pred, NULL, NULL);
		}
		assert_int_equal(result, ISC_R_SUCCESS);

		result = dns_name_tostring(pred, &namestr, mctx);
		assert_int_equal(result, ISC_R_SUCCESS);
#if 0
		fprintf(stderr, "... expected predecessor %s got %s\n", predstr,
			namestr);

		fprintf(stderr, "%d: remaining names after %s:\n", i, namestr);
#endif

		int j = 0;
		char *remainstr = NULL;
		while (dns_qpiter_next(&it, name, NULL, NULL) == ISC_R_SUCCESS)
		{
			result = dns_name_tostring(name, &remainstr, mctx);
			assert_int_equal(result, ISC_R_SUCCESS);
#if 0
			fprintf(stderr, "%s%s", j > 0 ? "->" : "", remainstr);
#endif
			isc_mem_free(mctx, remainstr);
			j++;
		}
#if 0
		fprintf(stderr, "\n...expected %d got %d\n", check[i].remaining,
			j);
#endif

		assert_string_equal(namestr, predstr);

		isc_mem_free(mctx, namestr);
		isc_mem_free(mctx, predstr);

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
	static struct inserting insert1[] = {
		{ "a.", 1 },
		{ "a.", 10 },

		{ "b.", 2 },
		{ "b.", 20 },

		{ "c.b.a.", 3 },
		{ "c.b.a.", 30 },
		{ "c.b.a.", 300 },

		{ "e.d.c.b.a.", 4 },
		{ "e.d.c.b.a.", 400 },

		{ "c.b.b.", 5 },
		{ "c.b.b.", 50 },

		{ "c.d.", 6 },
		{ "c.d.", 60 },
		{ "c.d.", 600 },

		{ "a.b.c.d.", 7 },
		{ "a.b.c.d.", 70 },
		{ "a.b.c.d.", 700 },

		{ "a.b.c.d.e.", 8 },
		{ "a.b.c.d.e.", 80 },
		{ "a.b.c.d.e.", 800 },

		{ "b.a.", 9 },
		{ "b.a.", 90 },

		{ "x.k.c.d.", 1 },
		{ "x.k.c.d.", 10 },
		{ "x.k.c.d.", 100 },

		{ "moog.", 2 },
		{ "moog.", 20 },
		{ "moog.", 200 },

		{ "mooker.", 3 },
		{ "mooker.", 30 },

		{ "mooko.", 4 },
		{ "mooko.", 40 },
		{ "mooko.", 400 },

		{ "moon.", 5 },
		{ "moon.", 50 },
		{ "moon.", 500 },

		{ "moops.", 6 },
		{ "moops.", 60 },
		{ "moops.", 600 },

		{ ".", 7 },
		{ ".", 70 },

		{ "", 0 },
	};

	dns_qp_create(mctx, &string_methods, NULL, &qp);
	while (insert1[i].name[0] != '.') {
		insert_nametype(qp, insert1[i].name, insert1[i].type);
		i++;
	}

	/* first check: no root label in the database */
	static struct check_predecessors check1[] = {
		{ ".", 7, "moops.", ISC_R_NOTFOUND, 0 },

		{ "a.", 1, "moops.", ISC_R_SUCCESS, 0 },
		{ "a.", 9, "a.", DNS_R_NODATA, 38 },
		{ "a.", 11, "a.", DNS_R_NODATA, 37 },

		{ "b.a.", 8, "a.", DNS_R_NODATA, 37 },
		{ "b.a.", 9, "a.", ISC_R_SUCCESS, 37 },
		{ "b.a.", 80, "b.a.", DNS_R_NODATA, 36 },
		{ "b.a.", 90, "b.a.", ISC_R_SUCCESS, 36 },
		{ "b.a.", 100, "b.a.", DNS_R_NODATA, 35 },

		{ "b.", 0, "e.d.c.b.a.", DNS_R_NODATA, 30 },
		{ "b.", 1, "e.d.c.b.a.", DNS_R_NODATA, 30 },
		{ "b.", 2, "e.d.c.b.a.", ISC_R_SUCCESS, 30 },
		{ "b.", 3, "b.", DNS_R_NODATA, 29 },
		{ "b.", 19, "b.", DNS_R_NODATA, 29 },
		{ "b.", 21, "b.", DNS_R_NODATA, 28 },

		{ "aaa.a.", 1, "a.", DNS_R_PARTIALMATCH, 37 },
		{ "ddd.a.", 1, "e.d.c.b.a.", DNS_R_PARTIALMATCH, 30 },
		{ "d.c.", 1, "c.b.b.", ISC_R_NOTFOUND, 26 },
		{ "1.2.c.b.a.", 0, "c.b.a.", DNS_R_PARTIALMATCH, 32 },
		{ "1.2.c.b.a.", 65535, "c.b.a.", DNS_R_PARTIALMATCH, 32 },
		{ "a.b.c.e.f.", 1, "a.b.c.d.e.", ISC_R_NOTFOUND, 14 },
		{ "z.y.x.", 1, "moops.", ISC_R_NOTFOUND, 0 },
		{ "w.c.d.", 1, "x.k.c.d.", DNS_R_PARTIALMATCH, 17 },
		{ "z.z.z.z.k.c.d.", 1, "x.k.c.d.", DNS_R_PARTIALMATCH, 17 },
		{ "w.k.c.d.", 1, "a.b.c.d.", DNS_R_PARTIALMATCH, 20 },
		{ "d.a.", 1, "e.d.c.b.a.", DNS_R_PARTIALMATCH, 30 },
		{ "0.b.c.d.e.", 1, "x.k.c.d.", ISC_R_NOTFOUND, 17 },
		{ "b.d.", 1, "c.b.b.", ISC_R_NOTFOUND, 26 },
		{ "mon.", 1, "a.b.c.d.e.", ISC_R_NOTFOUND, 14 },
		{ "moor.", 1, "moops.", ISC_R_NOTFOUND, 0 },
		{ "mopbop.", 1, "moops.", ISC_R_NOTFOUND, 0 },
		{ "moppop.", 1, "moops.", ISC_R_NOTFOUND, 0 },
		{ "mopps.", 1, "moops.", ISC_R_NOTFOUND, 0 },
		{ "mopzop.", 1, "moops.", ISC_R_NOTFOUND, 0 },
		{ "mop.", 1, "moops.", ISC_R_NOTFOUND, 0 },
		{ "monbop.", 1, "a.b.c.d.e.", ISC_R_NOTFOUND, 14 },
		{ "monpop.", 1, "a.b.c.d.e.", ISC_R_NOTFOUND, 14 },
		{ "monps.", 1, "a.b.c.d.e.", ISC_R_NOTFOUND, 14 },
		{ "monzop.", 1, "a.b.c.d.e.", ISC_R_NOTFOUND, 14 },
		{ "mon.", 1, "a.b.c.d.e.", ISC_R_NOTFOUND, 14 },
		{ "moop.", 1, "moon.", ISC_R_NOTFOUND, 3 },
		{ "moopser.", 1, "moops.", ISC_R_NOTFOUND, 0 },
		{ "monky.", 1, "a.b.c.d.e.", ISC_R_NOTFOUND, 14 },
		{ "monkey.", 1, "a.b.c.d.e.", ISC_R_NOTFOUND, 14 },
		{ "monker.", 1, "a.b.c.d.e.", ISC_R_NOTFOUND, 14 },
		{ NULL, 0, NULL, 0, 0 }
	};

	check_predecessors(qp, check1);

	/* second check: add a root label and try again */
	while (insert1[i].name[0] == '.') {
		insert_nametype(qp, insert1[i].name, insert1[i].type);
		i++;
	}

	static struct check_predecessors check2[] = {
		{ ".", 6, "moops.", DNS_R_NODATA, 0 },
		{ ".", 7, "moops.", ISC_R_SUCCESS, 0 },
		{ ".", 8, ".", DNS_R_NODATA, 40 },
		{ ".", 69, ".", DNS_R_NODATA, 40 },
		{ ".", 70, ".", ISC_R_SUCCESS, 40 },
		{ ".", 71, ".", DNS_R_NODATA, 39 },

		{ "a.", 1, ".", ISC_R_SUCCESS, 39 },
		{ "a.", 9, "a.", DNS_R_NODATA, 38 },
		{ "a.", 11, "a.", DNS_R_NODATA, 37 },

		{ "b.a.", 8, "a.", DNS_R_NODATA, 37 },
		{ "b.a.", 9, "a.", ISC_R_SUCCESS, 37 },
		{ "b.a.", 80, "b.a.", DNS_R_NODATA, 36 },
		{ "b.a.", 90, "b.a.", ISC_R_SUCCESS, 36 },
		{ "b.a.", 100, "b.a.", DNS_R_NODATA, 35 },

		{ "b.", 0, "e.d.c.b.a.", DNS_R_NODATA, 30 },
		{ "b.", 1, "e.d.c.b.a.", DNS_R_NODATA, 30 },
		{ "b.", 2, "e.d.c.b.a.", ISC_R_SUCCESS, 30 },
		{ "b.", 3, "b.", DNS_R_NODATA, 29 },
		{ "b.", 19, "b.", DNS_R_NODATA, 29 },
		{ "b.", 21, "b.", DNS_R_NODATA, 28 },

		{ "aaa.a.", 1, "a.", DNS_R_PARTIALMATCH, 37 },
		{ "ddd.a.", 1, "e.d.c.b.a.", DNS_R_PARTIALMATCH, 30 },
		{ "d.c.", 1, "c.b.b.", DNS_R_PARTIALMATCH, 26 },
		{ "1.2.c.b.a.", 0, "c.b.a.", DNS_R_PARTIALMATCH, 32 },
		{ "1.2.c.b.a.", 65535, "c.b.a.", DNS_R_PARTIALMATCH, 32 },
		{ "a.b.c.e.f.", 1, "a.b.c.d.e.", DNS_R_PARTIALMATCH, 14 },
		{ "z.y.x.", 1, "moops.", DNS_R_PARTIALMATCH, 0 },
		{ "w.c.d.", 1, "x.k.c.d.", DNS_R_PARTIALMATCH, 17 },
		{ "z.z.z.z.k.c.d.", 1, "x.k.c.d.", DNS_R_PARTIALMATCH, 17 },
		{ "w.k.c.d.", 1, "a.b.c.d.", DNS_R_PARTIALMATCH, 20 },
		{ "d.a.", 1, "e.d.c.b.a.", DNS_R_PARTIALMATCH, 30 },
		{ "0.b.c.d.e.", 1, "x.k.c.d.", DNS_R_PARTIALMATCH, 17 },
		{ "b.d.", 1, "c.b.b.", DNS_R_PARTIALMATCH, 26 },
		{ "mon.", 1, "a.b.c.d.e.", DNS_R_PARTIALMATCH, 14 },
		{ "moor.", 1, "moops.", DNS_R_PARTIALMATCH, 0 },
		{ "mopbop.", 1, "moops.", DNS_R_PARTIALMATCH, 0 },
		{ "moppop.", 1, "moops.", DNS_R_PARTIALMATCH, 0 },
		{ "mopps.", 1, "moops.", DNS_R_PARTIALMATCH, 0 },
		{ "mopzop.", 1, "moops.", DNS_R_PARTIALMATCH, 0 },
		{ "mop.", 1, "moops.", DNS_R_PARTIALMATCH, 0 },
		{ "monbop.", 1, "a.b.c.d.e.", DNS_R_PARTIALMATCH, 14 },
		{ "monpop.", 1, "a.b.c.d.e.", DNS_R_PARTIALMATCH, 14 },
		{ "monps.", 1, "a.b.c.d.e.", DNS_R_PARTIALMATCH, 14 },
		{ "monzop.", 1, "a.b.c.d.e.", DNS_R_PARTIALMATCH, 14 },
		{ "mon.", 1, "a.b.c.d.e.", DNS_R_PARTIALMATCH, 14 },
		{ "moop.", 1, "moon.", DNS_R_PARTIALMATCH, 3 },
		{ "moopser.", 1, "moops.", DNS_R_PARTIALMATCH, 0 },
		{ "monky.", 1, "a.b.c.d.e.", DNS_R_PARTIALMATCH, 14 },
		{ "monkey.", 1, "a.b.c.d.e.", DNS_R_PARTIALMATCH, 14 },
		{ "monker.", 1, "a.b.c.d.e.", DNS_R_PARTIALMATCH, 14 },
		{ NULL, 0, NULL, 0, 0 }
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
		{ "dynamic.", 6 },
		{ "dynamic.", 2 },
		{ "a.dynamic.", 1 },
		{ "aaaa.dynamic.", 28 },
		{ "cdnskey.dynamic.", 60 },
		{ "cds.dynamic.", 59 },
		{ "cname.dynamic.", 5 },
		{ "dname.dynamic.", 39 },
		{ "dnskey.dynamic.", 48 },
		{ "ds.dynamic.", 43 },
		{ "mx.dynamic.", 15 },
		{ "ns.dynamic.", 2 },
		{ "nsec.dynamic.", 47 },
		{ "private-cdnskey.dynamic.", 60 },
		{ "private-dnskey.dynamic.", 48 },
		{ "rrsig.dynamic.", 46 },
		{ "txt.dynamic.", 16 },
		{ "trailing.", 6 },
		{ "trailing.", 2 },
		{ "", 0 },
	};

	dns_qp_create(mctx, &string_methods, NULL, &qp);
	while (insert1[i].name[0] != '\0') {
		insert_nametype(qp, insert1[i].name, insert1[i].type);
		i++;
	}

	static struct check_predecessors check1[] = {
		{ "newtext.dynamic.", 1, "mx.dynamic.", DNS_R_PARTIALMATCH, 8 },
		{ "nsd.dynamic.", 1, "ns.dynamic.", DNS_R_PARTIALMATCH, 7 },
		{ "nsf.dynamic.", 1, "nsec.dynamic.", DNS_R_PARTIALMATCH, 6 },
		{ "d.", 1, "trailing.", ISC_R_NOTFOUND, 0 },
		{ "absent.", 1, "trailing.", ISC_R_NOTFOUND, 0 },
		{ "nonexistent.", 1, "txt.dynamic.", ISC_R_NOTFOUND, 2 },
		{ "wayback.", 1, "trailing.", ISC_R_NOTFOUND, 0 },
		{ NULL, 0, NULL, 0, 0 }
	};

	check_predecessors(qp, check1);
	dns_qp_destroy(&qp);

	static struct inserting insert2[] = {
		{ ".", 1 },	   { ".", 65535 }, { "abb.", 1 },
		{ "abb.", 65535 }, { "abc.", 1 },  { "abc.", 65535 },
		{ "", 0 },
	};

	i = 0;
	dns_qp_create(mctx, &string_methods, NULL, &qp);
	while (insert2[i].name[0] != '\0') {
		insert_nametype(qp, insert2[i].name, insert2[i].type);
		i++;
	}

	static struct check_predecessors check2[] = {
		{ "acb.", 1, "abc.", DNS_R_PARTIALMATCH, 0 },
		{ "acc.", 1, "abc.", DNS_R_PARTIALMATCH, 0 },
		{ "abbb.", 1, "abb.", DNS_R_PARTIALMATCH, 2 },
		{ "aab.", 1, ".", DNS_R_PARTIALMATCH, 4 },
		{ NULL, 0, NULL, 0, 0 }
	};

	check_predecessors(qp, check2);
	dns_qp_destroy(&qp);

	static struct inserting insert3[] = {
		{ "example.", 6 },
		{ "example.", 2 },
		{ "example.", 48 },
		{ "example.", 47 },
		{ "example.", 46 },

		{ "key-is-13779.example.", 32768 },
		{ "key-is-13779.example.", 46 },
		{ "key-is-13779.example.", 47 },

		{ "key-is-14779.example.", 32768 },
		{ "key-is-14779.example.", 46 },
		{ "key-is-14779.example.", 47 },

		{ "key-not-13779.example.", 32768 },
		{ "key-not-14779.example.", 46 },
		{ "key-not-14779.example.", 47 },

		{ "", 0 },
	};

	i = 0;
	dns_qp_create(mctx, &string_methods, NULL, &qp);
	while (insert3[i].name[0] != '\0') {
		insert_nametype(qp, insert3[i].name, insert3[i].type);
		i++;
	}

	static struct check_predecessors check3[] = {
		{ "key-is-21556.example.", 32768, "key-is-14779.example.",
		  DNS_R_PARTIALMATCH, 3 },
		{ NULL, 0, NULL, 0, 0 }
	};

	check_predecessors(qp, check3);
	dns_qp_destroy(&qp);

	static struct inserting insert4[] = {
		{ ".", 1 },
		{ ".", 2 },
		{ ".", 3 },

		{ "\\000.", 1 },
		{ "\\000.", 2 },
		{ "\\000.", 3 },

		{ "\\000.\\000.", 1 },
		{ "\\000.\\000.", 2 },
		{ "\\000.\\000.", 3 },

		{ "\\000\\009.", 1 },
		{ "\\000\\009.", 2 },
		{ "\\000\\009.", 3 },

		{ "", 0 },
	};

	i = 0;
	dns_qp_create(mctx, &string_methods, NULL, &qp);
	while (insert4[i].name[0] != '\0') {
		insert_nametype(qp, insert4[i].name, insert4[i].type);
		i++;
	}

	static struct check_predecessors check4[] = {
		{ "\\007.", 1, "\\000\\009.", DNS_R_PARTIALMATCH, 0 },
		{ "\\009.", 1, "\\000\\009.", DNS_R_PARTIALMATCH, 0 },
		{ "\\045.", 1, "\\000\\009.", DNS_R_PARTIALMATCH, 0 },
		{ "\\044.", 1, "\\000\\009.", DNS_R_PARTIALMATCH, 0 },
		{ "\\000.", 1, ".", ISC_R_SUCCESS, 9 },
		{ NULL, 0, NULL, 0, 0 },
	};

	check_predecessors(qp, check4);
	dns_qp_destroy(&qp);
}

ISC_TEST_LIST_START
ISC_TEST_ENTRY(qpkey_nametype)
ISC_TEST_ENTRY(qpkey_sort)
ISC_TEST_ENTRY(partialmatch)
ISC_TEST_ENTRY(qpchain)
ISC_TEST_ENTRY(predecessors)
ISC_TEST_ENTRY(fixiterator)
ISC_TEST_LIST_END

ISC_TEST_MAIN
