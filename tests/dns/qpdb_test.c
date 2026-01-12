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
#include <isc/util.h>

#include <dns/lib.h>
#include <dns/rdatalist.h>
#include <dns/rdataset.h>
#include <dns/rdatastruct.h>
#define KEEP_BEFORE

/* Include the main file */

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wshadow"
#include "qpcache.c"
#pragma GCC diagnostic pop

#include <tests/dns.h>

/* Set to true (or use -v option) for verbose output */
static bool verbose = false;

/*
 * Add to a cache DB 'db' an rdataset of type 'rtype' at a name
 * <idx>.example.com. The rdataset would contain one data, and rdata_len is
 * its length. 'rtype' is supposed to be some private type whose data can be
 * arbitrary (and it doesn't matter in this test).
 */
static void
overmempurge_addrdataset(dns_db_t *db, isc_stdtime_t now, int idx,
			 dns_rdatatype_t rtype, size_t rdata_len,
			 bool longname) {
	isc_result_t result;
	dns_rdata_t rdata;
	dns_dbnode_t *node = NULL;
	dns_rdatalist_t rdatalist;
	dns_rdataset_t rdataset;
	dns_fixedname_t fname;
	dns_name_t *name;
	char namebuf[DNS_NAME_FORMATSIZE];
	unsigned char rdatabuf[65535] = { 0 }; /* large enough for any valid
						  RDATA */

	REQUIRE(rdata_len <= sizeof(rdatabuf));

	if (longname) {
		/*
		 * Build a longest possible name (in wire format) that would
		 * result in a new rbt node with the long name data.
		 */
		snprintf(namebuf, sizeof(namebuf),
			 "%010d.%010dabcdef%010dabcdef%010dabcdef%010dabcde."
			 "%010dabcdef%010dabcdef%010dabcdef%010dabcde."
			 "%010dabcdef%010dabcdef%010dabcdef%010dabcde."
			 "%010dabcdef%010dabcdef%010dabcdef01.",
			 idx, idx, idx, idx, idx, idx, idx, idx, idx, idx, idx,
			 idx, idx, idx, idx, idx);
	} else {
		snprintf(namebuf, sizeof(namebuf), "%d.example.com.", idx);
	}
	dns_test_namefromstring(namebuf, &fname);
	name = dns_fixedname_name(&fname);

	result = dns_db_findnode(db, name, true, &node);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_non_null(node);

	dns_rdata_init(&rdata);
	rdata.length = rdata_len;
	rdata.data = rdatabuf;
	rdata.rdclass = dns_rdataclass_in;
	rdata.type = rtype;

	dns_rdatalist_init(&rdatalist);
	rdatalist.rdclass = dns_rdataclass_in;
	rdatalist.type = rtype;
	rdatalist.ttl = 3600;
	ISC_LIST_APPEND(rdatalist.rdata, &rdata, link);

	dns_rdataset_init(&rdataset);
	dns_rdatalist_tordataset(&rdatalist, &rdataset);

	result = dns_db_addrdataset(db, node, NULL, now, &rdataset, 0, NULL);
	assert_int_equal(result, ISC_R_SUCCESS);

	dns_db_detachnode(&node);
}

static void
cleanup_all_deadnodes(dns_db_t *db) {
	qpcache_t *qpdb = (qpcache_t *)db;
	qpcache_ref(qpdb);
	for (uint16_t locknum = 0; locknum < qpdb->buckets_count; locknum++) {
		cleanup_deadnodes(qpdb, locknum);
	}
	qpcache_unref(qpdb);
}

ISC_LOOP_TEST_IMPL(overmempurge_bigrdata) {
	size_t maxcache = 2097152U; /* 2MB - same as DNS_CACHE_MINSIZE */
	size_t hiwater = maxcache - (maxcache >> 3); /* borrowed from cache.c */
	size_t lowater = maxcache - (maxcache >> 2); /* ditto */
	isc_result_t result;
	dns_db_t *db = NULL;
	isc_mem_t *mctx = NULL;
	isc_stdtime_t now = isc_stdtime_now();
	size_t i;

	isc_mem_create("test", &mctx);

	result = dns_db_create(mctx, CACHEDB_DEFAULT, dns_rootname,
			       dns_dbtype_cache, dns_rdataclass_in, 0, NULL,
			       &db);
	assert_int_equal(result, ISC_R_SUCCESS);

	isc_mem_setwater(mctx, hiwater, lowater);

	/*
	 * Add cache entries with minimum size of data until 'overmem'
	 * condition is triggered.
	 * This should eventually happen, but we also limit the number of
	 * iteration to avoid an infinite loop in case something gets wrong.
	 */
	for (i = 0; !isc_mem_isovermem(mctx) && i < (maxcache / 10); i++) {
		overmempurge_addrdataset(db, now, i, 50053, 0, false);
	}
	assert_true(isc_mem_isovermem(mctx));

	/*
	 * Then try to add the same number of entries, each has very large data.
	 * 'overmem purge' should keep the total cache size from exceeding
	 * the 'hiwater' mark too much. So we should be able to assume the
	 * cache size doesn't reach the "max".
	 */
	while (i-- > 0) {
		overmempurge_addrdataset(db, now, i, 50054, 65535, false);
		cleanup_all_deadnodes(db);
		if (verbose) {
			print_message("# inuse: %zd max: %zd\n",
				      isc_mem_inuse(mctx), maxcache);
		}
		assert_true(isc_mem_inuse(mctx) < maxcache);
	}

	dns_db_detach(&db);
	isc_mem_detach(&mctx);
	isc_loopmgr_shutdown();
}

ISC_LOOP_TEST_IMPL(overmempurge_longname) {
	size_t maxcache = 2097152U; /* 2MB - same as DNS_CACHE_MINSIZE */
	size_t hiwater = maxcache - (maxcache >> 3); /* borrowed from cache.c */
	size_t lowater = maxcache - (maxcache >> 2); /* ditto */
	isc_result_t result;
	dns_db_t *db = NULL;
	isc_mem_t *mctx = NULL;
	isc_stdtime_t now = isc_stdtime_now();
	size_t i;

	isc_mem_create("test", &mctx);

	result = dns_db_create(mctx, CACHEDB_DEFAULT, dns_rootname,
			       dns_dbtype_cache, dns_rdataclass_in, 0, NULL,
			       &db);
	assert_int_equal(result, ISC_R_SUCCESS);

	isc_mem_setwater(mctx, hiwater, lowater);

	/*
	 * Add cache entries with minimum size of data until 'overmem'
	 * condition is triggered.
	 * This should eventually happen, but we also limit the number of
	 * iteration to avoid an infinite loop in case something gets wrong.
	 */
	for (i = 0; !isc_mem_isovermem(mctx) && i < (maxcache / 10); i++) {
		overmempurge_addrdataset(db, now, i, 50053, 0, false);
	}
	assert_true(isc_mem_isovermem(mctx));

	/*
	 * Then try to add the same number of entries, each has very long name.
	 * 'overmem purge' should keep the total cache size from not exceeding
	 * the 'hiwater' mark too much. So we should be able to assume the cache
	 * size doesn't reach the "max".
	 */
	while (i-- > 0) {
		overmempurge_addrdataset(db, now, i, 50054, 0, true);
		cleanup_all_deadnodes(db);
		if (verbose) {
			print_message("# inuse: %zd max: %zd\n",
				      isc_mem_inuse(mctx), maxcache);
		}
		assert_true(isc_mem_inuse(mctx) < maxcache);
	}

	dns_db_detach(&db);
	isc_mem_detach(&mctx);
	isc_loopmgr_shutdown();
}

static void
insertrr(dns_db_t *db, isc_stdtime_t now, const char *namestr, int trust_a,
	 int trust_aaaa) {
	isc_result_t result;
	dns_fixedname_t fname;
	dns_dbnode_t *node = NULL;

	dns_test_namefromstring(namestr, &fname);
	result = dns_db_findnode(db, dns_fixedname_name(&fname), true, &node);
	assert_int_equal(result, ISC_R_SUCCESS);

	const dns_rdatatype_t types[] = { dns_rdatatype_ns, dns_rdatatype_a,
					  dns_rdatatype_aaaa };
	for (size_t i = 0; i < ARRAY_SIZE(types); i++) {
		dns_rdata_t rdata;
		dns_rdatalist_t rdatalist;
		size_t rdatalistttl = 3600;
		dns_rdataset_t rdataset;

		if (types[i] == dns_rdatatype_a && trust_a == -1) {
			continue;
		}

		if (types[i] == dns_rdatatype_aaaa && trust_aaaa == -1) {
			continue;
		}

		dns_rdata_init(&rdata);
		rdata.type = types[i];
		rdata.rdclass = dns_rdataclass_in;

		dns_rdatalist_init(&rdatalist);
		rdatalist.rdclass = dns_rdataclass_in;
		rdatalist.type = types[i];
		rdatalist.ttl = rdatalistttl;
		ISC_LIST_APPEND(rdatalist.rdata, &rdata, link);

		dns_rdataset_init(&rdataset);
		dns_rdatalist_tordataset(&rdatalist, &rdataset);

		switch (types[i]) {
		case dns_rdatatype_ns:
			rdataset.trust = dns_trust_glue;
			break;
		case dns_rdatatype_a:
			rdataset.trust = trust_a;
			break;
		case dns_rdatatype_aaaa:
			rdataset.trust = trust_aaaa;
			break;
		default:
			UNREACHABLE();
		}

		result = dns_db_addrdataset(db, node, NULL, now, &rdataset, 0,
					    NULL);
		assert_int_equal(result, ISC_R_SUCCESS);
	}

	dns_db_detachnode(&node);
}

typedef struct {
	const char *name;

	/* -1 means no A RR is added. Otherwise, holds a dns_trust_t. */
	int trust_a;

	/* -1 means no AAAA RR is added. Otherwise, holds a dns_trust_t. */
	int trust_aaaa;

	/* Do not add the DB node */
	bool readonly;
} findzonecut_glue_test_t;

const findzonecut_glue_test_t gluestest[] = {
	/* No glues */
	{ "example1.com", -1, -1 },

	/* A/AAAA glues, all trusted */
	{ "example2.com", dns_trust_glue, dns_trust_glue },

	/*
	 * Do not walk the qpchain up for the glues, only take the glues the
	 * from the found NS node.
	 */
	{ "foo.example2.com", -1, -1 },

	/*
	 * "bar.example2.com" is not addded to the DB, so findzonecut flow will
	 * go to the parent node, "example2.com", and get the glues from
	 * "example2.com".
	 */
	{ "bar.example2.com", dns_trust_glue, dns_trust_glue, true },

	/* Ignore A/AAAA glues below the dns_trust_glue trust level. */
	{ "example3.com", dns_trust_additional, dns_trust_secure },

	/* A only glue, and trusted */
	{ "example4.com", dns_trust_glue, -1 }
};

ISC_LOOP_TEST_IMPL(findzonecut_glues) {
	isc_result_t result;
	dns_db_t *db = NULL;
	isc_mem_t *mctx = NULL;
	isc_stdtime_t now = isc_stdtime_now();

	isc_mem_create("test", &mctx);

	result = dns_db_create(mctx, CACHEDB_DEFAULT, dns_rootname,
			       dns_dbtype_cache, dns_rdataclass_in, 0, NULL,
			       &db);
	assert_int_equal(result, ISC_R_SUCCESS);

	for (size_t i = 0; i < ARRAY_SIZE(gluestest); i++) {
		const findzonecut_glue_test_t *glue = gluestest + i;

		if (glue->readonly) {
			continue;
		}

		insertrr(db, now, glue->name, glue->trust_a, glue->trust_aaaa);
	}

	for (size_t i = 0; i < ARRAY_SIZE(gluestest); i++) {
		const findzonecut_glue_test_t *glue = gluestest + i;
		dns_dbnode_t *node = NULL;
		dns_fixedname_t fname, ffoundname;
		dns_name_t *foundname = dns_fixedname_initname(&ffoundname);
		dns_rdataset_t ns, glue_a, glue_aaaa;

		dns_rdataset_init(&ns);
		dns_rdataset_init(&glue_a);
		dns_rdataset_init(&glue_aaaa);
		dns_test_namefromstring(glue->name, &fname);
		result = dns_db_findzonecut(db, dns_fixedname_name(&fname), 0,
					    now, &node, foundname, NULL, &ns,
					    NULL, &glue_a, &glue_aaaa);
		assert_int_equal(result, ISC_R_SUCCESS);
		assert_true(dns_rdataset_isassociated(&ns));

		assert_true((glue->trust_a < dns_trust_glue &&
			     !dns_rdataset_isassociated(&glue_a)) ||
			    (glue->trust_a >= dns_trust_glue &&
			     dns_rdataset_isassociated(&glue_a)));

		assert_true((glue->trust_aaaa < dns_trust_glue &&
			     !dns_rdataset_isassociated(&glue_aaaa)) ||
			    (glue->trust_aaaa >= dns_trust_glue &&
			     dns_rdataset_isassociated(&glue_aaaa)));

		dns_rdataset_cleanup(&ns);
		dns_rdataset_cleanup(&glue_a);
		dns_rdataset_cleanup(&glue_aaaa);
	}

	dns_db_detach(&db);
	isc_mem_detach(&mctx);
	isc_loopmgr_shutdown();
}

ISC_TEST_LIST_START
ISC_TEST_ENTRY_CUSTOM(overmempurge_bigrdata, setup_managers, teardown_managers)
ISC_TEST_ENTRY_CUSTOM(overmempurge_longname, setup_managers, teardown_managers)
ISC_TEST_ENTRY_CUSTOM(findzonecut_glues, setup_managers, teardown_managers)
ISC_TEST_LIST_END

ISC_TEST_MAIN
