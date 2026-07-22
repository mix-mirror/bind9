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

#define UNIT_TESTING
#include <cmocka.h>

#include <isc/lib.h>
#include <isc/urcu.h>

#include <dns/lib.h>
#include <dns/view.h>

#include "../../lib/dns/rpz/rpz_p.h"

#include <tests/isc.h>

static dns_view_t *view = NULL;
static dns_rpz_qp_t *table = NULL;

static int
setup(void **state ISC_ATTR_UNUSED) {
	dns_view_create(isc_g_mctx, NULL, dns_rdataclass_in, "rpz test", &view);
	dns__rpz_qp_create(isc_g_mctx, view, &table);
	return 0;
}

static int
teardown(void **state ISC_ATTR_UNUSED) {
	dns__rpz_qp_destroy(&table);
	dns_view_detach(&view);
	rcu_barrier();
	return 0;
}

static dns_rpz_cidr_key_t
ipv4(uint32_t addr) {
	return (dns_rpz_cidr_key_t){
		.w = { 0, 0, DNS_RPZ_ADDR_V4MAPPED, addr },
		.ipv4 = true,
	};
}

static dns_rpz_addr_zbits_t
addr_data(dns_rpz_type_t type, dns_rpz_num_t rpz_num) {
	dns_rpz_addr_zbits_t data = { 0 };

	switch (type) {
	case DNS_RPZ_TYPE_CLIENT_IP:
		data.client_ip = DNS_RPZ_ZBIT(rpz_num);
		break;
	case DNS_RPZ_TYPE_IP:
		data.ip = DNS_RPZ_ZBIT(rpz_num);
		break;
	case DNS_RPZ_TYPE_NSIP:
		data.nsip = DNS_RPZ_ZBIT(rpz_num);
		break;
	default:
		UNREACHABLE();
	}

	return data;
}

static isc_result_t
add(const dns_rpz_cidr_key_t *addr, dns_rpz_prefix_t prefix,
    dns_rpz_type_t type, dns_rpz_num_t rpz_num) {
	dns_rpz_addr_zbits_t data = addr_data(type, rpz_num);
	dns_rpz_qp_write_t write = { 0 };
	isc_result_t result;

	dns__rpz_qp_write(table, &write);
	result = dns__rpz_qp_add_cidr(&write, addr, prefix, &data);
	dns__rpz_qp_commit(&write);
	return result;
}

static bool
del(const dns_rpz_cidr_key_t *addr, dns_rpz_prefix_t prefix,
    dns_rpz_type_t type, dns_rpz_num_t rpz_num) {
	dns_rpz_addr_zbits_t data = addr_data(type, rpz_num);
	dns_rpz_qp_write_t write = { 0 };
	isc_result_t result;
	bool exists;

	dns__rpz_qp_write(table, &write);
	result = dns__rpz_qp_delete_cidr(&write, addr, prefix, &data, &exists);
	assert_int_equal(result, ISC_R_SUCCESS);
	dns__rpz_qp_commit(&write);
	return exists;
}

static dns_rpz_num_t
find(const dns_rpz_cidr_key_t *addr, dns_rpz_type_t type, dns_rpz_zbits_t zbits,
     dns_rpz_prefix_t *prefixp) {
	return dns__rpz_qp_find_addr(table, type, zbits, addr, prefixp);
}

ISC_RUN_TEST_IMPL(cidr) {
	dns_rpz_cidr_key_t net_a = ipv4(0xa0000000);
	dns_rpz_cidr_key_t query_a = ipv4(0xa1234567);
	dns_rpz_cidr_key_t query_b = ipv4(0xb1234567);
	dns_rpz_cidr_key_t query_c = ipv4(0xc1234567);
	dns_rpz_cidr_key_t ip6_net = { .w = { 0xa0000000, 0, 0, 0 } };
	dns_rpz_cidr_key_t ip6_query = { .w = { 0xb1234567, 0, 0, 1 } };
	dns_rpz_cidr_key_t mapped4 = ipv4(0);
	dns_rpz_cidr_key_t mapped6 = {
		.w = { 0, 0, DNS_RPZ_ADDR_V4MAPPED, 0 },
	};
	dns_rpz_prefix_t prefix = 0;

	/* A /3 is expanded into the A and B final-nibble buckets. */
	assert_int_equal(add(&net_a, 99, DNS_RPZ_TYPE_IP, 0), ISC_R_SUCCESS);
	assert_int_equal(add(&net_a, 99, DNS_RPZ_TYPE_IP, 0), ISC_R_EXISTS);
	assert_int_equal(
		find(&query_a, DNS_RPZ_TYPE_IP, DNS_RPZ_ALL_ZBITS, &prefix), 0);
	assert_int_equal(prefix, 99);
	assert_int_equal(
		find(&query_b, DNS_RPZ_TYPE_IP, DNS_RPZ_ALL_ZBITS, &prefix), 0);
	assert_int_equal(prefix, 99);
	assert_int_equal(
		find(&query_c, DNS_RPZ_TYPE_IP, DNS_RPZ_ALL_ZBITS, &prefix),
		DNS_RPZ_INVALID_NUM);
	assert_int_equal(
		find(&query_a, DNS_RPZ_TYPE_NSIP, DNS_RPZ_ALL_ZBITS, &prefix),
		DNS_RPZ_INVALID_NUM);

	/* IPv6 uses a separate QP namespace even with identical leading bits.
	 */
	assert_int_equal(add(&ip6_net, 3, DNS_RPZ_TYPE_IP, 1), ISC_R_SUCCESS);
	assert_int_equal(
		find(&ip6_query, DNS_RPZ_TYPE_IP, DNS_RPZ_ALL_ZBITS, &prefix),
		1);
	assert_int_equal(prefix, 3);
	assert_int_equal(
		find(&query_b, DNS_RPZ_TYPE_IP, DNS_RPZ_ALL_ZBITS, &prefix), 0);
	assert_int_equal(add(&mapped4, 128, DNS_RPZ_TYPE_IP, 2), ISC_R_SUCCESS);
	assert_int_equal(add(&mapped6, 128, DNS_RPZ_TYPE_IP, 3), ISC_R_SUCCESS);
	assert_int_equal(
		find(&mapped4, DNS_RPZ_TYPE_IP, DNS_RPZ_ALL_ZBITS, &prefix), 2);
	assert_int_equal(
		find(&mapped6, DNS_RPZ_TYPE_IP, DNS_RPZ_ALL_ZBITS, &prefix), 3);

	assert_true(del(&net_a, 99, DNS_RPZ_TYPE_IP, 0));
	assert_false(del(&net_a, 99, DNS_RPZ_TYPE_IP, 0));
	assert_int_equal(
		find(&query_b, DNS_RPZ_TYPE_IP, DNS_RPZ_ALL_ZBITS, &prefix),
		DNS_RPZ_INVALID_NUM);
}

ISC_RUN_TEST_IMPL(priority_and_prefix) {
	dns_rpz_cidr_key_t slash1 = ipv4(0x80000000);
	dns_rpz_cidr_key_t slash2 = ipv4(0x80000000);
	dns_rpz_cidr_key_t slash8 = ipv4(0x0a000000);
	dns_rpz_cidr_key_t slash16 = ipv4(0x0a010000);
	dns_rpz_cidr_key_t query = ipv4(0x0a010203);
	dns_rpz_cidr_key_t shared_query = ipv4(0xa0000000);
	dns_rpz_prefix_t prefix = 0;

	/* The caller iterates zones from higher numbers toward higher priority.
	 */
	assert_int_equal(add(&slash8, 104, DNS_RPZ_TYPE_IP, 0), ISC_R_SUCCESS);
	assert_int_equal(add(&slash16, 112, DNS_RPZ_TYPE_IP, 1), ISC_R_SUCCESS);
	assert_int_equal(
		find(&query, DNS_RPZ_TYPE_IP, DNS_RPZ_ALL_ZBITS, &prefix), 1);
	assert_int_equal(prefix, 112);
	assert_int_equal(
		find(&query, DNS_RPZ_TYPE_IP, DNS_RPZ_ZBIT(0), &prefix), 0);
	assert_int_equal(prefix, 104);

	/* Different prefix slots can coexist in the same expanded bucket. */
	assert_int_equal(add(&slash1, 97, DNS_RPZ_TYPE_IP, 2), ISC_R_SUCCESS);
	assert_int_equal(add(&slash2, 98, DNS_RPZ_TYPE_IP, 2), ISC_R_SUCCESS);
	assert_int_equal(
		find(&shared_query, DNS_RPZ_TYPE_IP, DNS_RPZ_ZBIT(2), &prefix),
		2);
	assert_int_equal(prefix, 98);
	assert_true(del(&slash2, 98, DNS_RPZ_TYPE_IP, 2));
	assert_int_equal(
		find(&shared_query, DNS_RPZ_TYPE_IP, DNS_RPZ_ZBIT(2), &prefix),
		2);
	assert_int_equal(prefix, 97);
	assert_true(del(&slash1, 97, DNS_RPZ_TYPE_IP, 2));
	assert_int_equal(
		find(&shared_query, DNS_RPZ_TYPE_IP, DNS_RPZ_ZBIT(2), &prefix),
		DNS_RPZ_INVALID_NUM);
}

static void
check_prefix_lengths(const dns_rpz_cidr_key_t *addr, unsigned int maxbits,
		     unsigned int prefixbase, dns_rpz_num_t rpz_num) {
	dns_rpz_prefix_t prefix = 0;

	for (unsigned int bits = 1; bits <= maxbits; bits++) {
		assert_int_equal(
			add(addr, prefixbase + bits, DNS_RPZ_TYPE_IP, rpz_num),
			ISC_R_SUCCESS);
	}

	for (unsigned int bits = maxbits; bits > 0; bits--) {
		assert_int_equal(find(addr, DNS_RPZ_TYPE_IP,
				      DNS_RPZ_ZBIT(rpz_num), &prefix),
				 rpz_num);
		assert_int_equal(prefix, prefixbase + bits);
		assert_true(
			del(addr, prefixbase + bits, DNS_RPZ_TYPE_IP, rpz_num));
	}
	assert_int_equal(
		find(addr, DNS_RPZ_TYPE_IP, DNS_RPZ_ZBIT(rpz_num), &prefix),
		DNS_RPZ_INVALID_NUM);
}

ISC_RUN_TEST_IMPL(all_prefix_lengths) {
	dns_rpz_cidr_key_t ip4 = ipv4(0);
	dns_rpz_cidr_key_t ip6 = { 0 };

	check_prefix_lengths(&ip4, 32, 96, 4);
	check_prefix_lengths(&ip6, 128, 0, 5);
}

ISC_TEST_LIST_START
ISC_TEST_ENTRY_CUSTOM(cidr, setup, teardown)
ISC_TEST_ENTRY_CUSTOM(priority_and_prefix, setup, teardown)
ISC_TEST_ENTRY_CUSTOM(all_prefix_lengths, setup, teardown)
ISC_TEST_LIST_END

ISC_TEST_MAIN
