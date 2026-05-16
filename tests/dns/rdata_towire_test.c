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

#include <sched.h> /* IWYU pragma: keep */
#include <setjmp.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define UNIT_TESTING
#include <cmocka.h>

#include <isc/buffer.h>
#include <isc/lib.h>
#include <isc/list.h>
#include <isc/mem.h>
#include <isc/util.h>

#include <dns/compress.h>
#include <dns/fixedname.h>
#include <dns/lib.h>
#include <dns/message.h>
#include <dns/name.h>
#include <dns/rdata.h>
#include <dns/rdatalist.h>
#include <dns/rdataset.h>

#include <tests/dns.h>

/*
 * dns_rdata_towire() no longer rolls itself back on failure: its
 * contract (see dns/rdata.h) hands that work to the caller, on the
 * assumption that the only legitimate callers — dns_rdataset_towire()
 * and dns_ncache_towire() — already wrap each RR in a wider rollback
 * scope. These tests pin the new contract by exercising the failure
 * paths directly; if a future change reintroduces per-RR rollback or
 * breaks the outer scope, one of the assertions below will fail.
 */

static const unsigned char ns1_example_com[] = {
	3,   'n', 's', '1', 7,	 'e', 'x', 'a', 'm',
	'p', 'l', 'e', 3,   'c', 'o', 'm', 0,
};
static const unsigned char ns2_example_com[] = {
	3,   'n', 's', '2', 7,	 'e', 'x', 'a', 'm',
	'p', 'l', 'e', 3,   'c', 'o', 'm', 0,
};
static const unsigned char ns3_example_com[] = {
	3,   'n', 's', '3', 7,	 'e', 'x', 'a', 'm',
	'p', 'l', 'e', 3,   'c', 'o', 'm', 0,
};
static const unsigned char ns4_example_com[] = {
	3,   'n', 's', '4', 7,	 'e', 'x', 'a', 'm',
	'p', 'l', 'e', 3,   'c', 'o', 'm', 0,
};

static const unsigned char *const ns_wires[] = {
	ns1_example_com,
	ns2_example_com,
	ns3_example_com,
	ns4_example_com,
};

static void
init_ns_rdata(dns_rdata_t *rdata, const unsigned char *wire, size_t len) {
	dns_rdata_init(rdata);
	rdata->rdclass = dns_rdataclass_in;
	rdata->type = dns_rdatatype_ns;
	rdata->data = (unsigned char *)(uintptr_t)wire;
	rdata->length = (unsigned int)len;
}

/*
 * dns_compress_name() inserts the name's labels into the table before
 * the buffer-length check inside dns_name_towire(), so on NOSPACE
 * those labels remain. Pre-d9dfa26, dns_rdata_towire() walked them
 * back via dns_compress_rollback(); post-d9dfa26 it does not, and the
 * caller must.
 */
ISC_RUN_TEST_IMPL(rdata_towire_nospace_cctx_not_rolled_back) {
	dns_compress_t cctx;
	isc_buffer_t buffer;
	unsigned char bufdata[12]; /* < 17, the uncompressed NS name */
	dns_rdata_t rdata;
	unsigned int count_before;
	isc_buffer_t saved;

	dns_compress_init(&cctx, isc_g_mctx, 0);
	isc_buffer_init(&buffer, bufdata, sizeof(bufdata));
	saved = buffer;
	count_before = cctx.count;

	init_ns_rdata(&rdata, ns1_example_com, sizeof(ns1_example_com));

	assert_int_equal(dns_rdata_towire(&rdata, &cctx, &buffer),
			 ISC_R_NOSPACE);

	/* Contract: cctx was modified and NOT auto-rolled-back. */
	assert_true(cctx.count > count_before);

	/* Caller restores buffer + compression context. */
	buffer = saved;
	dns_compress_rollback(&cctx, buffer.used);
	assert_int_equal(cctx.count, count_before);

	dns_compress_invalidate(&cctx);
}

/*
 * MX towire writes the 2-byte preference before attempting the name.
 * With room for the preference but not the name, dns_rdata_towire()
 * returns NOSPACE with the buffer advanced past the preference.
 * Pre-d9dfa26 the function restored *target; post-d9dfa26 it does not.
 */
ISC_RUN_TEST_IMPL(rdata_towire_nospace_target_not_restored) {
	dns_compress_t cctx;
	isc_buffer_t buffer;
	unsigned char bufdata[2]; /* fits MX preference, not the name */
	dns_rdata_t rdata;
	static const unsigned char mx_wire[] = {
		0,   10, /* preference */
		3,   'm', 'x', '1', 7,	 'e', 'x', 'a', 'm',
		'p', 'l', 'e', 3,   'c', 'o', 'm', 0,
	};
	unsigned int pre_used;

	dns_compress_init(&cctx, isc_g_mctx, 0);
	isc_buffer_init(&buffer, bufdata, sizeof(bufdata));
	pre_used = buffer.used;

	dns_rdata_init(&rdata);
	rdata.rdclass = dns_rdataclass_in;
	rdata.type = dns_rdatatype_mx;
	rdata.data = (unsigned char *)(uintptr_t)mx_wire;
	rdata.length = sizeof(mx_wire);

	assert_int_equal(dns_rdata_towire(&rdata, &cctx, &buffer),
			 ISC_R_NOSPACE);

	/* Contract: 2-byte preference committed, target NOT rewound. */
	assert_true(buffer.used > pre_used);

	dns_compress_invalidate(&cctx);
}

static void
build_ns_rdataset(dns_rdatalist_t *rdatalist, dns_rdataset_t *rdataset,
		  dns_rdata_t *rdatas, size_t n) {
	dns_rdataset_init(rdataset);
	dns_rdatalist_init(rdatalist);
	rdatalist->rdclass = dns_rdataclass_in;
	rdatalist->type = dns_rdatatype_ns;
	rdatalist->ttl = 3600;
	for (size_t i = 0; i < n; i++) {
		init_ns_rdata(&rdatas[i], ns_wires[i], sizeof(ns1_example_com));
		ISC_LIST_APPEND(rdatalist->rdata, &rdatas[i], link);
	}
	dns_rdatalist_tordataset(rdatalist, rdataset);
}

/*
 * Force a mid-rdataset NOSPACE with partial=true: dns_rdataset_towire()
 * must restore the buffer to the boundary after the last successful RR
 * (rrbuffer.used) and roll the compression context back to that same
 * position. With the now-dropped inner dns_rdata_towire() rollback,
 * any compression entry that the aborted RR inserted past the boundary
 * is cleared only by this outer rollback.
 */
ISC_RUN_TEST_IMPL(rdataset_towire_partial_nospace_outer_rollback) {
	dns_compress_t cctx;
	isc_buffer_t buffer;
	unsigned char bufdata[80];
	dns_fixedname_t owner_fixed;
	dns_name_t *owner = NULL;
	dns_rdatalist_t rdatalist;
	dns_rdataset_t rdataset;
	dns_rdata_t rdatas[4];
	unsigned int count = 0;
	isc_result_t result;

	isc_buffer_init(&buffer, bufdata, sizeof(bufdata));
	dns_compress_init(&cctx, isc_g_mctx, 0);

	owner = dns_fixedname_initname(&owner_fixed);
	assert_int_equal(
		dns_name_fromstring(owner, "example.com.", NULL, 0, NULL),
		ISC_R_SUCCESS);

	build_ns_rdataset(&rdatalist, &rdataset, rdatas, ARRAY_SIZE(rdatas));

	result = dns_rdataset_towire(&rdataset, owner, 0, &cctx, &buffer, true,
				     0, &count);

	assert_int_equal(result, ISC_R_NOSPACE);
	assert_true(count >= 1);
	assert_true(count < ARRAY_SIZE(rdatas));

	/*
	 * No compression entry may point past the committed prefix of
	 * the buffer — otherwise a follow-up rendering could emit a
	 * pointer into a never-written region.
	 */
	for (unsigned int i = 0; i <= cctx.mask; i++) {
		assert_true(cctx.set[i].coff <= buffer.used);
	}

	dns_compress_invalidate(&cctx);
}

/*
 * Non-partial path: dns_rdataset_towire() must fully restore the
 * caller's buffer position, zero *countp, and roll the compression
 * context back to savedbuffer.used. With the inner rollback removed
 * from dns_rdata_towire(), this is entirely the responsibility of the
 * outer rollback branch in dns_rdataset_towire().
 */
ISC_RUN_TEST_IMPL(rdataset_towire_nonpartial_nospace_full_rollback) {
	dns_compress_t cctx;
	isc_buffer_t buffer;
	unsigned char bufdata[40];
	dns_fixedname_t owner_fixed;
	dns_name_t *owner = NULL;
	dns_rdatalist_t rdatalist;
	dns_rdataset_t rdataset;
	dns_rdata_t rdatas[4];
	unsigned int count = 0;
	isc_result_t result;
	unsigned int pre_used;

	isc_buffer_init(&buffer, bufdata, sizeof(bufdata));
	/* Simulate the caller having already written a DNS header. */
	isc_buffer_add(&buffer, DNS_MESSAGE_HEADERLEN);
	pre_used = buffer.used;

	dns_compress_init(&cctx, isc_g_mctx, 0);

	owner = dns_fixedname_initname(&owner_fixed);
	assert_int_equal(
		dns_name_fromstring(owner, "example.com.", NULL, 0, NULL),
		ISC_R_SUCCESS);

	build_ns_rdataset(&rdatalist, &rdataset, rdatas, ARRAY_SIZE(rdatas));

	result = dns_rdataset_towire(&rdataset, owner, 0, &cctx, &buffer, false,
				     0, &count);

	assert_int_equal(result, ISC_R_NOSPACE);
	assert_int_equal(buffer.used, pre_used);
	assert_int_equal(count, 0);
	for (unsigned int i = 0; i <= cctx.mask; i++) {
		assert_true(cctx.set[i].coff <= pre_used);
	}

	dns_compress_invalidate(&cctx);
}

ISC_TEST_LIST_START
ISC_TEST_ENTRY(rdata_towire_nospace_cctx_not_rolled_back)
ISC_TEST_ENTRY(rdata_towire_nospace_target_not_restored)
ISC_TEST_ENTRY(rdataset_towire_partial_nospace_outer_rollback)
ISC_TEST_ENTRY(rdataset_towire_nonpartial_nospace_full_rollback)
ISC_TEST_LIST_END
ISC_TEST_MAIN
