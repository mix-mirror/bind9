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

#define UNIT_TESTING
#include <cmocka.h>

#include <isc/buffer.h>
#include <isc/lib.h>
#include <isc/mem.h>
#include <isc/result.h>
#include <isc/util.h>

#include <dns/db.h>
#include <dns/fixedname.h>
#include <dns/lib.h>
#include <dns/name.h>
#include <dns/rdata.h>
#include <dns/rdataclass.h>
#include <dns/rdatalist.h>
#include <dns/rdataset.h>
#include <dns/rdatatype.h>
#include <dns/rdatavec.h>

#include <tests/dns.h>
#include <tests/isc.h>

/* Helper function to create a vecheader directly */
static isc_result_t
create_vecheader(isc_mem_t *mctx, dns_rdatatype_t type,
		 dns_rdataclass_t rdclass, dns_ttl_t ttl,
		 const char *rdata_text, dns_vecheader_t **headerp) {
	dns_rdataset_t rdataset;
	dns_rdatalist_t *rdatalist;
	dns_rdata_t *rdata;
	unsigned char *data;
	isc_region_t region;
	isc_result_t result;

	/* Allocate temporary structures */
	data = isc_mem_get(mctx, 256);
	rdatalist = isc_mem_get(mctx, sizeof(*rdatalist));
	rdata = isc_mem_get(mctx, sizeof(*rdata));

	/* Initialize rdataset and rdatalist */
	dns_rdataset_init(&rdataset);
	dns_rdatalist_init(rdatalist);
	rdatalist->type = type;
	rdatalist->rdclass = rdclass;
	rdatalist->ttl = ttl;

	/* Create rdata */
	dns_rdata_init(rdata);
	CHECK(dns_test_rdatafromstring(rdata, rdclass, type, data, 256,
				       rdata_text, false));

	ISC_LIST_APPEND(rdatalist->rdata, rdata, link);
	dns_rdatalist_tordataset(rdatalist, &rdataset);

	/* Convert to vecheader */
	CHECK(dns_rdatavec_fromrdataset(&rdataset, mctx, &region, 0));
	*headerp = (dns_vecheader_t *)region.base;

	/* Cleanup rdataset */
	dns_rdataset_disassociate(&rdataset);

cleanup:
	/* Cleanup temporary structures */
	isc_mem_put(mctx, rdata, sizeof(*rdata));
	isc_mem_put(mctx, rdatalist, sizeof(*rdatalist));
	isc_mem_put(mctx, data, 256);

	return result;
}

/* Helper function to create an rdataset from a vecheader */
static void
create_rdataset_from_vecheader(dns_vecheader_t *header,
			       dns_rdataclass_t rdclass, dns_rdatatype_t type,
			       dns_rdataset_t *rdataset) {
	dns_rdataset_init(rdataset);
	rdataset->methods = &dns_rdatavec_rdatasetmethods;
	rdataset->rdclass = rdclass;
	rdataset->type = type;
	rdataset->vec.header = header;
}

/* Test merging two headers */
ISC_RUN_TEST_IMPL(merge_headers) {
	isc_mem_t *mctx = isc_g_mctx;
	UNUSED(state);
	dns_vecheader_t *header1 = NULL, *header2 = NULL, *merged_header = NULL;
	unsigned int size1, size2, merged_size, expected_size;
	unsigned int count1, count2, merged_count, expected_count;
	isc_result_t result;

	/* Create vecheaders with A records */
	CHECK(create_vecheader(mctx, dns_rdatatype_a, dns_rdataclass_in, 300,
			       "192.168.1.1", &header1));

	CHECK(create_vecheader(mctx, dns_rdatatype_a, dns_rdataclass_in, 300,
			       "192.168.1.2", &header2));

	/* Get sizes and counts before merging */
	size1 = dns_rdatavec_size(header1);
	size2 = dns_rdatavec_size(header2);
	count1 = dns_rdatavec_count(header1);
	count2 = dns_rdatavec_count(header2);

	/* Merge headers */
	CHECK(dns_rdatavec_merge(header1, header2, mctx, dns_rdataclass_in,
				 dns_rdatatype_a, 0, 0, &merged_header));
	assert_non_null(merged_header);

	/* Get merged size and count */
	merged_size = dns_rdatavec_size(merged_header);
	merged_count = dns_rdatavec_count(merged_header);

	/* Test: merged size should be first_size + second_size - sizeof(header)
	 * - count_field_size */
	expected_size = size1 + size2 - sizeof(dns_vecheader_t) - 2;
	assert_int_equal(merged_size, expected_size);

	/* Test: merged count should be first_count + second_count */
	expected_count = count1 + count2;
	assert_int_equal(merged_count, expected_count);

cleanup:
	/* Cleanup */
	if (header1 != NULL) {
		size1 = dns_rdatavec_size(header1);
		isc_mem_put(mctx, header1, size1);
	}
	if (header2 != NULL) {
		size2 = dns_rdatavec_size(header2);
		isc_mem_put(mctx, header2, size2);
	}
	if (merged_header != NULL) {
		merged_size = dns_rdatavec_size(merged_header);
		isc_mem_put(mctx, merged_header, merged_size);
	}
}

/* Test case preservation during merge */
ISC_RUN_TEST_IMPL(merge_case_preservation) {
	isc_mem_t *mctx = isc_g_mctx;
	UNUSED(state);
	dns_vecheader_t *header1 = NULL, *header2 = NULL, *merged_header = NULL;
	dns_fixedname_t fname1, fname2, fmerged_name;
	dns_name_t *name1 = dns_fixedname_initname(&fname1);
	dns_name_t *name2 = dns_fixedname_initname(&fname2);
	dns_name_t *merged_name = dns_fixedname_initname(&fmerged_name);
	unsigned int size1, size2, merged_size;
	isc_result_t result;

	dns_test_namefromstring("Example.COM", &fname1);
	dns_test_namefromstring("example.com", &fname2);

	/* Create vecheaders */
	CHECK(create_vecheader(mctx, dns_rdatatype_a, dns_rdataclass_in, 300,
			       "192.168.1.1", &header1));

	CHECK(create_vecheader(mctx, dns_rdatatype_a, dns_rdataclass_in, 300,
			       "192.168.1.2", &header2));

	/* Set case on first header */
	dns_vecheader_setownercase(header1, name1);

	/* Set case on second header */
	dns_vecheader_setownercase(header2, name2);

	/* Get sizes */
	size1 = dns_rdatavec_size(header1);
	size2 = dns_rdatavec_size(header2);

	/* Merge headers */
	CHECK(dns_rdatavec_merge(header1, header2, mctx, dns_rdataclass_in,
				 dns_rdatatype_a, 0, 0, &merged_header));
	assert_non_null(merged_header);

	/* Test: case should be the same as the first header */
	/* Copy the name for testing */
	dns_name_copy(name1, merged_name);

	/* Create a test rdataset from merged header to test case */
	dns_rdataset_t test_rdataset;
	create_rdataset_from_vecheader(merged_header, dns_rdataclass_in,
				       dns_rdatatype_a, &test_rdataset);

	/* Apply case from merged header */
	dns_rdataset_getownercase(&test_rdataset, merged_name);

	/* The case should match the original first name */
	assert_true(dns_name_caseequal(name1, merged_name));

cleanup:
	/* Cleanup */
	if (header1 != NULL) {
		size1 = dns_rdatavec_size(header1);
		isc_mem_put(mctx, header1, size1);
	}
	if (header2 != NULL) {
		size2 = dns_rdatavec_size(header2);
		isc_mem_put(mctx, header2, size2);
	}
	if (merged_header != NULL) {
		merged_size = dns_rdatavec_size(merged_header);
		isc_mem_put(mctx, merged_header, merged_size);
	}
}

/* Test size consistency after setting case */
ISC_RUN_TEST_IMPL(setcase_size_consistency) {
	isc_mem_t *mctx = isc_g_mctx;
	UNUSED(state);
	dns_vecheader_t *header = NULL;
	dns_fixedname_t fname, flower_fname, fretrieved_fname;
	dns_name_t *name = dns_fixedname_initname(&fname);
	dns_name_t *lower_name = dns_fixedname_initname(&flower_fname);
	dns_name_t *retrieved_name = dns_fixedname_initname(&fretrieved_fname);
	unsigned int original_size, cased_size;
	dns_rdataset_t test_rdataset;
	isc_result_t result;

	/* Initialize name */
	dns_test_namefromstring("Example.COM", &fname);

	/* Create vecheader */
	CHECK(create_vecheader(mctx, dns_rdatatype_a, dns_rdataclass_in, 300,
			       "192.168.1.1", &header));

	/* Get original size */
	original_size = dns_rdatavec_size(header);

	/* Set case */
	dns_vecheader_setownercase(header, name);

	/* Get size after setting case */
	cased_size = dns_rdatavec_size(header);

	/* Test: size should be the same after setting case */
	assert_int_equal(cased_size, original_size);

	/* Create lowercase version of the original name */
	dns_test_namefromstring("example.com", &flower_fname);

	/* Copy lowercase name to retrieved_name for testing */
	dns_name_copy(lower_name, retrieved_name);

	/* Create a test rdataset from cased header */
	create_rdataset_from_vecheader(header, dns_rdataclass_in,
				       dns_rdatatype_a, &test_rdataset);

	/* Apply case from cased header to retrieved_name */
	dns_rdataset_getownercase(&test_rdataset, retrieved_name);

	/* Test: retrieved case should match the original mixed case */
	assert_true(dns_name_caseequal(name, retrieved_name));

cleanup:
	/* Cleanup */
	if (header != NULL) {
		cased_size = dns_rdatavec_size(header);
		isc_mem_put(mctx, header, cased_size);
	}
}

ISC_TEST_LIST_START
ISC_TEST_ENTRY_CUSTOM(merge_headers, setup_mctx, teardown_mctx)
ISC_TEST_ENTRY_CUSTOM(merge_case_preservation, setup_mctx, teardown_mctx)
ISC_TEST_ENTRY_CUSTOM(setcase_size_consistency, setup_mctx, teardown_mctx)
ISC_TEST_LIST_END

ISC_TEST_MAIN
