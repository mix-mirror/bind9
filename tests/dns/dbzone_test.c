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
#include <unistd.h>

#include "dns/enumtype.h"
#include "isc/result.h"
#include "tests/isc.h"

#define UNIT_TESTING
#include <cmocka.h>

#include <dns/db.h>
#include <dns/dbiterator.h>
#include <dns/journal.h>
#include <dns/name.h>
#include <dns/rdatalist.h>

#include <tests/dns.h>

static isc_result_t
dns_test_addrr(dns_db_t *db, dns_dbversion_t *version, const char *rname,
	       dns_ttl_t ttl, dns_rdatatype_t rtype, const char *rdatastr,
	       unsigned int options) {
	isc_result_t result;
	dns_rdata_t rdata;
	dns_rdatalist_t rdatalist;
	dns_rdataset_t rdataset;
	dns_dbnode_t *node = NULL;
	dns_fixedname_t fixed;
	dns_name_t *name = dns_fixedname_initname(&fixed);
	unsigned char rdatabuf[DNS_RDATA_MAXLENGTH] = { 0 };

	dns_test_namefromstring(rname, &fixed);

	result = dns_db_findnode(db, name, true, &node);
	if (result != ISC_R_SUCCESS) {
		return result;
	}
	assert_non_null(node);

	dns_rdata_init(&rdata);
	result = dns_test_rdatafromstring(&rdata, dns_rdataclass_in, rtype,
					  rdatabuf, sizeof(rdatabuf), rdatastr,
					  true);
	if (result != ISC_R_SUCCESS) {
		dns_db_detachnode(db, &node);
		return result;
	}

	dns_rdatalist_init(&rdatalist);
	rdatalist.rdclass = dns_rdataclass_in;
	rdatalist.type = rtype;
	rdatalist.ttl = ttl;

	ISC_LIST_APPEND(rdatalist.rdata, &rdata, link);

	dns_rdataset_init(&rdataset);
	dns_rdatalist_tordataset(&rdatalist, &rdataset);

	result = dns_db_addrdataset(db, node, version, 0, &rdataset, options,
				    NULL);

	if (dns_rdataset_isassociated(&rdataset)) {
		dns_rdataset_disassociate(&rdataset);
	}

	dns_rdatalist_disassociate(&rdataset);
	dns_db_detachnode(db, &node);

	return result;
}

typedef struct dns_test_vector {
	const char *name;
	const dns_ttl_t ttl;
	const dns_rdatatype_t type;
	const char *rdatastr;
	const isc_result_t result;
} dns_test_vector_t;

static isc_result_t
dns_test_existrr(dns_db_t *db, dns_dbversion_t *version, const char *rname,
		 dns_rdatatype_t rtype, const char *rdatastr) {
	isc_result_t result;
	dns_rdataset_t rdataset;
	dns_dbnode_t *node = NULL;
	dns_fixedname_t fixed;
	dns_name_t *name = dns_fixedname_initname(&fixed);

	dns_test_namefromstring(rname, &fixed);

	result = dns_db_findnode(db, name, false, &node);
	if (result != ISC_R_SUCCESS) {
		return result;
	}

	dns_rdataset_init(&rdataset);

	result = dns_db_findrdataset(db, node, version, rtype, 0, 0, &rdataset,
				     NULL);
	if (result != ISC_R_SUCCESS) {
		dns_db_detachnode(db, &node);
		return result;
	}

	for (result = dns_rdataset_first(&rdataset); result == ISC_R_SUCCESS;
	     result = dns_rdataset_next(&rdataset))
	{
		dns_rdata_t rdata;
		isc_buffer_t b;
		char rdatabuf[DNS_RDATA_MAXLENGTH];
		isc_buffer_init(&b, rdatabuf, sizeof(rdatabuf));

		dns_rdata_init(&rdata);
		dns_rdataset_current(&rdataset, &rdata);

		result = dns_rdata_totext(&rdata, NULL, &b);
		assert_int_equal(result, ISC_R_SUCCESS);

		*(uint8_t *)isc_buffer_used(&b) = 0;

		if (strncasecmp(rdatastr, rdatabuf, sizeof(rdatabuf)) == 0) {
			break;
		}
	}
	if (result == ISC_R_NOMORE) {
		result = ISC_R_NOTFOUND;
	}
	dns_rdataset_disassociate(&rdataset);

	dns_db_detachnode(db, &node);

	return result;
}

ISC_LOOP_TEST_IMPL(addrdataset) {
	dns_db_t *db = NULL;
	dns_dbversion_t *version = NULL;
	isc_result_t result;
	dns_fixedname_t forigin;
	dns_name_t *origin = dns_fixedname_initname(&forigin);
	unsigned int options = 0;

	dns_test_namefromstring("test.", &forigin);

	result = dns_db_create(mctx, ZONEDB_DEFAULT, origin, dns_dbtype_zone,
			       dns_rdataclass_in, 0, NULL, &db);
	assert_int_equal(result, ISC_R_SUCCESS);

	{
		dns_test_vector_t vectors[] = {
			{ "a.test.", 3600, dns_rdatatype_a, "192.0.2.1",
			  ISC_R_SUCCESS },
			{ "a.test.", 3600, dns_rdatatype_a, "192.0.2.1",
			  ISC_R_SUCCESS },
			{ "a.test.", 3600, dns_rdatatype_a, "192.0.2.255",
			  ISC_R_SUCCESS },
		};

		dns_db_newversion(db, &version);

		for (size_t i = 0; i < ARRAY_SIZE(vectors); i++) {
			result = dns_test_addrr(db, version, vectors[i].name,
						vectors[i].ttl, vectors[i].type,
						vectors[i].rdatastr, options);
			assert_int_equal(result, vectors[i].result);
		}

		dns_db_closeversion(db, &version, true);
	}

	{
		dns_test_vector_t vectors[] = {
			{ "a.test.", 3600, dns_rdatatype_a, "192.0.2.1",
			  ISC_R_NOTFOUND },
			{ "a.test.", 3600, dns_rdatatype_a, "192.0.2.255",
			  ISC_R_SUCCESS },
		};

		dns_db_currentversion(db, &version);

		for (size_t i = 0; i < ARRAY_SIZE(vectors); i++) {
			result = dns_test_existrr(db, version, vectors[i].name,
						  vectors[i].type,
						  vectors[i].rdatastr);
			assert_int_equal(result, vectors[i].result);
		}

		dns_db_closeversion(db, &version, false);
	}

	{
		dns_test_vector_t vectors[] = {
			{ "a.test.", 3600, dns_rdatatype_a, "192.0.2.254",
			  ISC_R_SUCCESS },
		};

		dns_db_newversion(db, &version);

		for (size_t i = 0; i < ARRAY_SIZE(vectors); i++) {
			result = dns_test_addrr(db, version, vectors[i].name,
						vectors[i].ttl, vectors[i].type,
						vectors[i].rdatastr, options);
			assert_int_equal(result, vectors[i].result);
		}

		dns_db_closeversion(db, &version, true);
	}

	{
		dns_test_vector_t vectors[] = {
			{ "a.test.", 3600, dns_rdatatype_a, "192.0.2.1",
			  ISC_R_NOTFOUND },
			{ "a.test.", 3600, dns_rdatatype_a, "192.0.2.254",
			  ISC_R_SUCCESS },
			{ "a.test.", 3600, dns_rdatatype_a, "192.0.2.255",
			  ISC_R_NOTFOUND },
		};

		dns_db_currentversion(db, &version);

		for (size_t i = 0; i < ARRAY_SIZE(vectors); i++) {
			result = dns_test_existrr(db, version, vectors[i].name,
						  vectors[i].type,
						  vectors[i].rdatastr);
			assert_int_equal(result, vectors[i].result);
		}

		dns_db_closeversion(db, &version, false);
	}

	dns_db_detach(&db);
	isc_loopmgr_shutdown(loopmgr);
}

ISC_LOOP_TEST_IMPL(addrdataset_exact) {
	dns_db_t *db = NULL;
	dns_dbversion_t *version = NULL;
	isc_result_t result;
	dns_fixedname_t forigin;
	dns_name_t *origin = dns_fixedname_initname(&forigin);
	unsigned int options = DNS_DBADD_MERGE | DNS_DBADD_EXACT;

	dns_test_namefromstring("test.", &forigin);

	result = dns_db_create(mctx, ZONEDB_DEFAULT, origin, dns_dbtype_zone,
			       dns_rdataclass_in, 0, NULL, &db);
	assert_int_equal(result, ISC_R_SUCCESS);

	{
		dns_test_vector_t vectors[] = {
			{ "a.test.", 3600, dns_rdatatype_a, "192.0.2.1",
			  ISC_R_SUCCESS },
			{ "a.test.", 3600, dns_rdatatype_a, "192.0.2.1",
			  DNS_R_NOTEXACT },
			{ "a.test.", 3600, dns_rdatatype_a, "192.0.2.255",
			  ISC_R_SUCCESS },
		};

		dns_db_newversion(db, &version);

		for (size_t i = 0; i < ARRAY_SIZE(vectors); i++) {
			result = dns_test_addrr(db, version, vectors[i].name,
						vectors[i].ttl, vectors[i].type,
						vectors[i].rdatastr, options);
			assert_int_equal(result, vectors[i].result);
		}

		dns_db_closeversion(db, &version, true);
	}

	{
		dns_test_vector_t vectors[] = {
			{ "a.test.", 3600, dns_rdatatype_a, "192.0.2.1",
			  ISC_R_SUCCESS },
			{ "a.test.", 3600, dns_rdatatype_a, "192.0.2.255",
			  ISC_R_SUCCESS },
		};

		dns_db_currentversion(db, &version);

		for (size_t i = 0; i < ARRAY_SIZE(vectors); i++) {
			result = dns_test_existrr(db, version, vectors[i].name,
						  vectors[i].type,
						  vectors[i].rdatastr);
			assert_int_equal(result, vectors[i].result);
		}

		dns_db_closeversion(db, &version, false);
	}

	{
		dns_test_vector_t vectors[] = {
			{ "a.test.", 300, dns_rdatatype_a, "192.0.2.254",
			  ISC_R_SUCCESS },
		};

		dns_db_newversion(db, &version);

		for (size_t i = 0; i < ARRAY_SIZE(vectors); i++) {
			result = dns_test_addrr(db, version, vectors[i].name,
						vectors[i].ttl, vectors[i].type,
						vectors[i].rdatastr, options);
			assert_int_equal(result, vectors[i].result);
		}

		dns_db_closeversion(db, &version, true);
	}

	{
		dns_test_vector_t vectors[] = {
			{ "a.test.", 3600, dns_rdatatype_a, "192.0.2.1",
			  ISC_R_SUCCESS },
			{ "a.test.", 3600, dns_rdatatype_a, "192.0.2.254",
			  ISC_R_SUCCESS },
			{ "a.test.", 3600, dns_rdatatype_a, "192.0.2.255",
			  ISC_R_SUCCESS },
		};

		dns_db_currentversion(db, &version);

		for (size_t i = 0; i < ARRAY_SIZE(vectors); i++) {
			result = dns_test_existrr(db, version, vectors[i].name,
						  vectors[i].type,
						  vectors[i].rdatastr);
			assert_int_equal(result, vectors[i].result);
		}

		dns_db_closeversion(db, &version, false);
	}

	dns_db_detach(&db);
	isc_loopmgr_shutdown(loopmgr);
}

ISC_LOOP_TEST_IMPL(addrdataset_exactttl) {
	dns_db_t *db = NULL;
	dns_dbversion_t *version = NULL;
	isc_result_t result;
	dns_fixedname_t forigin;
	dns_name_t *origin = dns_fixedname_initname(&forigin);
	unsigned int options = DNS_DBADD_MERGE | DNS_DBADD_EXACTTTL;

	dns_test_namefromstring("test.", &forigin);

	result = dns_db_create(mctx, ZONEDB_DEFAULT, origin, dns_dbtype_zone,
			       dns_rdataclass_in, 0, NULL, &db);
	assert_int_equal(result, ISC_R_SUCCESS);

	{
		dns_test_vector_t vectors[] = {
			{ "a.test.", 3600, dns_rdatatype_a, "192.0.2.1",
			  ISC_R_SUCCESS },
			{ "a.test.", 600, dns_rdatatype_a, "192.0.2.1",
			  DNS_R_NOTEXACT },
			{ "a.test.", 3600, dns_rdatatype_a, "192.0.2.255",
			  ISC_R_SUCCESS },
		};

		dns_db_newversion(db, &version);

		for (size_t i = 0; i < ARRAY_SIZE(vectors); i++) {
			result = dns_test_addrr(db, version, vectors[i].name,
						vectors[i].ttl, vectors[i].type,
						vectors[i].rdatastr, options);
			assert_int_equal(result, vectors[i].result);
		}

		dns_db_closeversion(db, &version, true);
	}

	{
		dns_test_vector_t vectors[] = {
			{ "a.test.", 3600, dns_rdatatype_a, "192.0.2.1",
			  ISC_R_SUCCESS },
			{ "a.test.", 3600, dns_rdatatype_a, "192.0.2.255",
			  ISC_R_SUCCESS },
		};

		dns_db_currentversion(db, &version);

		for (size_t i = 0; i < ARRAY_SIZE(vectors); i++) {
			result = dns_test_existrr(db, version, vectors[i].name,
						  vectors[i].type,
						  vectors[i].rdatastr);
			assert_int_equal(result, vectors[i].result);
		}

		dns_db_closeversion(db, &version, false);
	}

	{
		dns_test_vector_t vectors[] = {
			{ "a.test.", 300, dns_rdatatype_a, "192.0.2.254",
			  DNS_R_NOTEXACT },
		};

		dns_db_newversion(db, &version);

		for (size_t i = 0; i < ARRAY_SIZE(vectors); i++) {
			result = dns_test_addrr(db, version, vectors[i].name,
						vectors[i].ttl, vectors[i].type,
						vectors[i].rdatastr, options);
			assert_int_equal(result, vectors[i].result);
		}

		dns_db_closeversion(db, &version, true);
	}

	{
		dns_test_vector_t vectors[] = {
			{ "a.test.", 3600, dns_rdatatype_a, "192.0.2.1",
			  ISC_R_SUCCESS },
			{ "a.test.", 3600, dns_rdatatype_a, "192.0.2.254",
			  ISC_R_NOTFOUND },
			{ "a.test.", 3600, dns_rdatatype_a, "192.0.2.255",
			  ISC_R_SUCCESS },
		};

		dns_db_currentversion(db, &version);

		for (size_t i = 0; i < ARRAY_SIZE(vectors); i++) {
			result = dns_test_existrr(db, version, vectors[i].name,
						  vectors[i].type,
						  vectors[i].rdatastr);
			assert_int_equal(result, vectors[i].result);
		}

		dns_db_closeversion(db, &version, false);
	}

	dns_db_detach(&db);
	isc_loopmgr_shutdown(loopmgr);
}

/*
 * RFC 5737:
 * - 192.0.2.0/24 (TEST-NET-1)
 * - 198.51.100.0/24 (TEST-NET-2)
 * - 203.0.113.0/24 (TEST-NET-3)
 *
 * RFC 3849
 * - 2001:DB8::/32
 *
 * RFC 9637
 * - 3fff::/20
 */

ISC_LOOP_TEST_IMPL(addrdataset_merge) {
	dns_db_t *db = NULL;
	dns_dbversion_t *version = NULL;
	isc_result_t result;
	dns_fixedname_t forigin;
	dns_name_t *origin = dns_fixedname_initname(&forigin);

	dns_test_namefromstring("test.", &forigin);

	result = dns_db_create(mctx, ZONEDB_DEFAULT, origin, dns_dbtype_zone,
			       dns_rdataclass_in, 0, NULL, &db);
	assert_int_equal(result, ISC_R_SUCCESS);

	{
		dns_test_vector_t vectors[] = {
			{ "a.test.", 3600, dns_rdatatype_a, "192.0.2.1",
			  ISC_R_SUCCESS },
			{ "a.test.", 3600, dns_rdatatype_a, "192.0.2.255",
			  ISC_R_SUCCESS },
			{ "a.test.", 3600, dns_rdatatype_a, "198.51.100.0",
			  ISC_R_SUCCESS },
			{ "a.test.", 3600, dns_rdatatype_a, "198.51.100.1",
			  ISC_R_SUCCESS },
			{ "a.test.", 3600, dns_rdatatype_a, "203.0.113.53",
			  ISC_R_SUCCESS },
			{ "b.test.", 3600, dns_rdatatype_aaaa, "2001:db8::1",
			  ISC_R_SUCCESS },
			{ "b.test.", 3600, dns_rdatatype_aaaa, "2001:db8:53::1",
			  ISC_R_SUCCESS },
			{ "b.test.", 3600, dns_rdatatype_aaaa,
			  "2001:db8:53::10", ISC_R_SUCCESS },
			{ "b.test.", 3600, dns_rdatatype_aaaa, "3fff:53::53",
			  ISC_R_SUCCESS },
			{ "b.test.", 3600, dns_rdatatype_aaaa, "3fff:100::1",
			  ISC_R_SUCCESS },
		};

		dns_db_newversion(db, &version);

		for (size_t i = 0; i < ARRAY_SIZE(vectors); i++) {
			result = dns_test_addrr(db, version, vectors[i].name,
						vectors[i].ttl, vectors[i].type,
						vectors[i].rdatastr,
						DNS_DBADD_MERGE);
			assert_int_equal(result, vectors[i].result);
		}

		dns_db_closeversion(db, &version, true);
	}

	{
		dns_test_vector_t vectors[] = {
			{ "a.test.", 3600, dns_rdatatype_a, "192.0.2.1",
			  ISC_R_SUCCESS },
			{ "a.test.", 3600, dns_rdatatype_a, "192.0.2.255",
			  ISC_R_SUCCESS },
			{ "a.test.", 3600, dns_rdatatype_a, "198.51.100.0",
			  ISC_R_SUCCESS },
			{ "a.test.", 3600, dns_rdatatype_a, "198.51.100.1",
			  ISC_R_SUCCESS },
			{ "a.test.", 3600, dns_rdatatype_a, "203.0.113.53",
			  ISC_R_SUCCESS },
			{ "b.test.", 3600, dns_rdatatype_aaaa, "2001:DB8::1",
			  ISC_R_SUCCESS },
			{ "b.test.", 3600, dns_rdatatype_aaaa, "2001:DB8:53::1",
			  ISC_R_SUCCESS },
			{ "b.test.", 3600, dns_rdatatype_aaaa,
			  "2001:DB8:53::10", ISC_R_SUCCESS },
			{ "b.test.", 3600, dns_rdatatype_aaaa, "3fff:53::53",
			  ISC_R_SUCCESS },
			{ "b.test.", 3600, dns_rdatatype_aaaa, "3fff:100::1",
			  ISC_R_SUCCESS },
		};

		dns_db_currentversion(db, &version);

		for (size_t i = 0; i < ARRAY_SIZE(vectors); i++) {
			result = dns_test_existrr(db, version, vectors[i].name,
						  vectors[i].type,
						  vectors[i].rdatastr);
			assert_int_equal(result, vectors[i].result);
		}

		dns_db_closeversion(db, &version, false);
	}

	dns_db_detach(&db);
	isc_loopmgr_shutdown(loopmgr);
}

ISC_LOOP_TEST_IMPL(addrdataset_rollback) {
	dns_db_t *db = NULL;
	dns_dbversion_t *version = NULL;
	isc_result_t result;
	dns_fixedname_t forigin;
	dns_name_t *origin = dns_fixedname_initname(&forigin);
	unsigned int options = DNS_DBADD_MERGE;

	dns_test_namefromstring("test.", &forigin);

	result = dns_db_create(mctx, ZONEDB_DEFAULT, origin, dns_dbtype_zone,
			       dns_rdataclass_in, 0, NULL, &db);
	assert_int_equal(result, ISC_R_SUCCESS);

	{
		dns_test_vector_t vectors[] = {
			{ "a.test.", 3600, dns_rdatatype_a, "192.0.2.1",
			  ISC_R_SUCCESS },
			{ "a.test.", 3600, dns_rdatatype_a, "192.0.2.255",
			  ISC_R_SUCCESS },
		};

		dns_db_newversion(db, &version);

		for (size_t i = 0; i < ARRAY_SIZE(vectors); i++) {
			result = dns_test_addrr(db, version, vectors[i].name,
						vectors[i].ttl, vectors[i].type,
						vectors[i].rdatastr, options);
			assert_int_equal(result, vectors[i].result);
		}

		dns_db_closeversion(db, &version, false);
	}

	{
		dns_test_vector_t vectors[] = {
			{ "a.test.", 3600, dns_rdatatype_a, "192.0.2.1",
			  ISC_R_NOTFOUND },
			{ "a.test.", 3600, dns_rdatatype_a, "192.0.2.255",
			  ISC_R_NOTFOUND },
		};

		dns_db_currentversion(db, &version);

		for (size_t i = 0; i < ARRAY_SIZE(vectors); i++) {
			result = dns_test_existrr(db, version, vectors[i].name,
						  vectors[i].type,
						  vectors[i].rdatastr);
			assert_int_equal(result, vectors[i].result);
		}

		dns_db_closeversion(db, &version, false);
	}

	{
		dns_test_vector_t vectors[] = {
			{ "a.test.", 3600, dns_rdatatype_a, "192.0.2.254",
			  ISC_R_SUCCESS },
		};

		dns_db_newversion(db, &version);

		for (size_t i = 0; i < ARRAY_SIZE(vectors); i++) {
			result = dns_test_addrr(db, version, vectors[i].name,
						vectors[i].ttl, vectors[i].type,
						vectors[i].rdatastr, options);
			assert_int_equal(result, vectors[i].result);
		}

		dns_db_closeversion(db, &version, true);
	}

	{
		dns_test_vector_t vectors[] = {
			{ "a.test.", 3600, dns_rdatatype_a, "192.0.2.1",
			  ISC_R_NOTFOUND },
			{ "a.test.", 3600, dns_rdatatype_a, "192.0.2.254",
			  ISC_R_SUCCESS },
			{ "a.test.", 3600, dns_rdatatype_a, "192.0.2.255",
			  ISC_R_NOTFOUND },
		};

		dns_db_currentversion(db, &version);

		for (size_t i = 0; i < ARRAY_SIZE(vectors); i++) {
			result = dns_test_existrr(db, version, vectors[i].name,
						  vectors[i].type,
						  vectors[i].rdatastr);
			assert_int_equal(result, vectors[i].result);
		}

		dns_db_closeversion(db, &version, false);
	}

	dns_db_detach(&db);
	isc_loopmgr_shutdown(loopmgr);
}

ISC_LOOP_TEST_IMPL(addrdataset_ent) {
	dns_db_t *db = NULL;
	dns_dbversion_t *version = NULL;
	isc_result_t result;
	dns_fixedname_t forigin;
	dns_name_t *origin = dns_fixedname_initname(&forigin);
	unsigned int options = DNS_DBADD_MERGE;

	dns_test_namefromstring("test.", &forigin);

	result = dns_db_create(mctx, ZONEDB_DEFAULT, origin, dns_dbtype_zone,
			       dns_rdataclass_in, 0, NULL, &db);
	assert_int_equal(result, ISC_R_SUCCESS);

	{
		dns_test_vector_t vectors[] = {
			{ "a.a.test.", 3600, dns_rdatatype_a, "192.0.2.1",
			  ISC_R_SUCCESS },
		};

		dns_db_newversion(db, &version);

		for (size_t i = 0; i < ARRAY_SIZE(vectors); i++) {
			result = dns_test_addrr(db, version, vectors[i].name,
						vectors[i].ttl, vectors[i].type,
						vectors[i].rdatastr, options);
			assert_int_equal(result, vectors[i].result);
		}

		dns_db_closeversion(db, &version, true);
	}

	{
		dns_test_vector_t vectors[] = {
			{ "a.test.", 0, dns_rdatatype_a, NULL, ISC_R_NOTFOUND },
			{ "a.a.test.", 3600, dns_rdatatype_a, "192.0.2.1",
			  ISC_R_SUCCESS },
		};

		dns_db_currentversion(db, &version);

		for (size_t i = 0; i < ARRAY_SIZE(vectors); i++) {
			result = dns_test_existrr(db, version, vectors[i].name,
						  vectors[i].type,
						  vectors[i].rdatastr);
			assert_int_equal(result, vectors[i].result);
		}

		dns_db_closeversion(db, &version, false);
	}

	{
		dns_test_vector_t vectors[] = {
			{ "a.test.", 3600, dns_rdatatype_a, "192.0.2.254",
			  ISC_R_SUCCESS },
		};

		dns_db_newversion(db, &version);

		for (size_t i = 0; i < ARRAY_SIZE(vectors); i++) {
			result = dns_test_addrr(db, version, vectors[i].name,
						vectors[i].ttl, vectors[i].type,
						vectors[i].rdatastr, options);
			assert_int_equal(result, vectors[i].result);
		}

		dns_db_closeversion(db, &version, true);
	}

	{
		dns_test_vector_t vectors[] = {
			{ "a.a.test.", 3600, dns_rdatatype_a, "192.0.2.1",
			  ISC_R_SUCCESS },
			{ "a.test.", 3600, dns_rdatatype_a, "192.0.2.254",
			  ISC_R_SUCCESS },
		};

		dns_db_currentversion(db, &version);

		for (size_t i = 0; i < ARRAY_SIZE(vectors); i++) {
			result = dns_test_existrr(db, version, vectors[i].name,
						  vectors[i].type,
						  vectors[i].rdatastr);
			assert_int_equal(result, vectors[i].result);
		}

		dns_db_closeversion(db, &version, false);
	}

	dns_db_detach(&db);
	isc_loopmgr_shutdown(loopmgr);
}

ISC_LOOP_TEST_IMPL(cname_and_others) {
	dns_db_t *db = NULL;
	dns_dbversion_t *version = NULL;
	isc_result_t result;
	dns_fixedname_t forigin;
	dns_name_t *origin = dns_fixedname_initname(&forigin);
	unsigned int options = 0;

	dns_test_namefromstring("test.", &forigin);

	result = dns_db_create(mctx, ZONEDB_DEFAULT, origin, dns_dbtype_zone,
			       dns_rdataclass_in, 0, NULL, &db);
	assert_int_equal(result, ISC_R_SUCCESS);

	{
		dns_test_vector_t vectors[] = {
			{ "a.test.", 3600, dns_rdatatype_a, "192.0.2.1",
			  ISC_R_SUCCESS },
			{ "a.test.", 3600, dns_rdatatype_cname, "b.test.",
			  DNS_R_CNAMEANDOTHER },
			{ "b.test.", 3600, dns_rdatatype_cname, "a.test.",
			  ISC_R_SUCCESS },
			{ "b.test.", 3600, dns_rdatatype_a, "192.0.2.2",
			  DNS_R_CNAMEANDOTHER },
			/*
			 * The KEY, SIG, NSEC and RRSIG can co-exist with the
			 * CNAME in the same node.
			 */
			{ "c.test.", 3600, dns_rdatatype_cname, "a.test.",
			  ISC_R_SUCCESS },
			{ "c.test.", 3600, dns_rdatatype_nsec, "a.test. CNAME",
			  ISC_R_SUCCESS },
			{ "c.test.", 3600, dns_rdatatype_rrsig,
			  "NSEC 13 2 600 20250304053636 20250202052633 906 "
			  "test. "
			  "+whsJNg8KTjTAxlf9hXwKgRnbcwuyKY2+"
			  "Rcmf2UPI4tjMUuiacyw3USF "
			  "3ZkAs0vfZB+m0vk4kUyMbBHp46kGZQ==",
			  ISC_R_SUCCESS },
			{ "c.test.", 3600, dns_rdatatype_key,
			  "0 3 157 mGcDSCx/fF121GOVJlITLg==", ISC_R_SUCCESS },
			{ "c.test.", 3600, dns_rdatatype_sig,
			  "NXT 1 3 3600 20000102030405 19961211100908 2143 "
			  "foo.example.nil. "
			  "MxFcby9k/yvedMfQgKzhH5er0Mu/vILz45IkskceFGgiWCn/"
			  "GxHhai6V "
			  "AuHAoNUz4YoU1tVfSCSqQYn6//"
			  "11U6Nld80jEeC8aTrO+KKmCaY=",
			  ISC_R_SUCCESS },
		};

		dns_db_newversion(db, &version);

		for (size_t i = 0; i < ARRAY_SIZE(vectors); i++) {
			result = dns_test_addrr(db, version, vectors[i].name,
						vectors[i].ttl, vectors[i].type,
						vectors[i].rdatastr, options);
			assert_int_equal(result, vectors[i].result);
		}

		dns_db_closeversion(db, &version, true);
	}

	{
		/*
		 * This deserves an explanation.  If there's a CNAME at the node
		 * added after the A record, it will trump the A and return the
		 * CNAME.  If the order is different, the CNAME will happily
		 * coexist with the A record, because the A record will be
		 * returned first.
		 */
		dns_test_vector_t vectors[] = {
			{ "a.test.", 0, dns_rdatatype_a, "192.168.2.1",
			  ISC_R_NOTFOUND },
			{ "a.test.", 3600, dns_rdatatype_cname, "b.test.",
			  ISC_R_SUCCESS },
			{ "b.test.", 3600, dns_rdatatype_cname, "a.test.",
			  ISC_R_SUCCESS },
			{ "b.test.", 3600, dns_rdatatype_a, "192.0.2.2",
			  ISC_R_SUCCESS },
			{ "c.test.", 3600, dns_rdatatype_cname, "a.test.",
			  ISC_R_SUCCESS },
			{ "c.test.", 3600, dns_rdatatype_nsec, "a.test. CNAME",
			  ISC_R_SUCCESS },
			{ "c.test.", 3600, dns_rdatatype_rrsig,
			  "NSEC 13 2 600 20250304053636 20250202052633 906 "
			  "test. "
			  "+whsJNg8KTjTAxlf9hXwKgRnbcwuyKY2+"
			  "Rcmf2UPI4tjMUuiacyw3USF "
			  "3ZkAs0vfZB+m0vk4kUyMbBHp46kGZQ==",
			  ISC_R_SUCCESS },
			{ "c.test.", 3600, dns_rdatatype_key,
			  "0 3 157 mGcDSCx/fF121GOVJlITLg==", ISC_R_SUCCESS },
			{ "c.test.", 3600, dns_rdatatype_sig,
			  "NXT 1 3 3600 20000102030405 19961211100908 2143 "
			  "foo.example.nil. "
			  "MxFcby9k/yvedMfQgKzhH5er0Mu/vILz45IkskceFGgiWCn/"
			  "GxHhai6V "
			  "AuHAoNUz4YoU1tVfSCSqQYn6//"
			  "11U6Nld80jEeC8aTrO+KKmCaY=",
			  ISC_R_SUCCESS },
		};

		dns_db_currentversion(db, &version);

		for (size_t i = 0; i < ARRAY_SIZE(vectors); i++) {
			result = dns_test_existrr(db, version, vectors[i].name,
						  vectors[i].type,
						  vectors[i].rdatastr);
			assert_int_equal(result, vectors[i].result);
		}

		dns_db_closeversion(db, &version, false);
	}

	dns_db_detach(&db);
	isc_loopmgr_shutdown(loopmgr);
}

ISC_LOOP_TEST_IMPL(wildcard) {
	dns_db_t *db = NULL;
	dns_dbversion_t *version = NULL;
	isc_result_t result;
	dns_fixedname_t forigin;
	dns_name_t *origin = dns_fixedname_initname(&forigin);
	unsigned int options = 0;

	/*
	 * Only following options are applicable for qpzonedb:
	 * - DNS_DBFIND_FORCENSEC3
	 * - DNS_DBFIND_NOWILD
	 * - DNS_DBFIND_GLUEOK
	 */

	dns_test_namefromstring("test.", &forigin);

	result = dns_db_create(mctx, ZONEDB_DEFAULT, origin, dns_dbtype_zone,
			       dns_rdataclass_in, 0, NULL, &db);
	assert_int_equal(result, ISC_R_SUCCESS);

	{
		dns_test_vector_t vectors[] = {
			{ "test.", 3600, dns_rdatatype_soa, ". . 0 0 0 0 0",
			  ISC_R_SUCCESS },
			{ "test.", 3600, dns_rdatatype_ns, "ns1.test.",
			  ISC_R_SUCCESS },
			{ "test.", 3600, dns_rdatatype_ns, "ns2.test.",
			  ISC_R_SUCCESS },
			{ "ns1.test.", 3600, dns_rdatatype_ns, "203.0.113.1",
			  ISC_R_SUCCESS },
			{ "ns2.test.", 3600, dns_rdatatype_ns, "203.0.113.2",
			  ISC_R_SUCCESS },
		};

		dns_db_newversion(db, &version);

		for (size_t i = 0; i < ARRAY_SIZE(vectors); i++) {
			result = dns_test_addrr(db, version, vectors[i].name,
						vectors[i].ttl, vectors[i].type,
						vectors[i].rdatastr, options);
			assert_int_equal(result, vectors[i].result);
		}

		dns_db_closeversion(db, &version, true);
	}

	{
		dns_test_vector_t vectors[] = {
			{ "*.test.", 3600, dns_rdatatype_a, "192.0.2.1",
			  ISC_R_SUCCESS },
		};

		dns_db_newversion(db, &version);

		for (size_t i = 0; i < ARRAY_SIZE(vectors); i++) {
			result = dns_test_addrr(db, version, vectors[i].name,
						vectors[i].ttl, vectors[i].type,
						vectors[i].rdatastr, options);
			assert_int_equal(result, vectors[i].result);
		}

		dns_db_closeversion(db, &version, true);
	}

	{
		dns_test_vector_t vectors[] = {
			{ "test.", 0, dns_rdatatype_a, "192.168.2.1",
			  DNS_R_NXRRSET },
			{ "*.test.", 0, dns_rdatatype_a, "192.168.2.1",
			  ISC_R_SUCCESS },
			{ "a.test.", 0, dns_rdatatype_a, "192.168.2.1",
			  ISC_R_SUCCESS },
			{ "www.a.test.", 0, dns_rdatatype_a, "192.168.2.1",
			  ISC_R_SUCCESS },
		};

		dns_db_currentversion(db, &version);

		for (size_t i = 0; i < ARRAY_SIZE(vectors); i++) {
			dns_fixedname_t fname, ffound;
			dns_name_t *name = dns_fixedname_initname(&fname);
			dns_name_t *found = dns_fixedname_initname(&ffound);
			dns_rdataset_t rdataset, sigrdataset;
			dns_dbnode_t *node = NULL;

			dns_rdataset_init(&rdataset);
			dns_rdataset_init(&sigrdataset);

			dns_test_namefromstring(vectors[i].name, &fname);

			result = dns_db_find(db, name, version, vectors[i].type,
					     options, 0, &node, found,
					     &rdataset, &sigrdataset);
			if (node != NULL) {
				dns_db_detachnode(db, &node);
			}
			if (dns_rdataset_isassociated(&rdataset)) {
				dns_rdataset_disassociate(&rdataset);
			}
			if (dns_rdataset_isassociated(&sigrdataset)) {
				dns_rdataset_disassociate(&sigrdataset);
			}

			assert_int_equal(result, vectors[i].result);
		}

		dns_db_closeversion(db, &version, false);
	}

	dns_db_detach(&db);
	isc_loopmgr_shutdown(loopmgr);
}

ISC_TEST_LIST_START
ISC_TEST_ENTRY_CUSTOM(addrdataset, setup_managers, teardown_managers)
ISC_TEST_ENTRY_CUSTOM(addrdataset_merge, setup_managers, teardown_managers)
ISC_TEST_ENTRY_CUSTOM(addrdataset_exact, setup_managers, teardown_managers)
ISC_TEST_ENTRY_CUSTOM(addrdataset_exactttl, setup_managers, teardown_managers)
ISC_TEST_ENTRY_CUSTOM(addrdataset_rollback, setup_managers, teardown_managers)
ISC_TEST_ENTRY_CUSTOM(addrdataset_ent, setup_managers, teardown_managers)
ISC_TEST_ENTRY_CUSTOM(cname_and_others, setup_managers, teardown_managers)
ISC_TEST_ENTRY_CUSTOM(wildcard, setup_managers, teardown_managers)
ISC_TEST_LIST_END

ISC_TEST_MAIN
