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
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define UNIT_TESTING
#include <cmocka.h>

/*
 * Mock isc_stdtime_now() as it makes testing easier (to compare
 * generated/expected deleg data).
 */
static uint32_t stdtime_now = 100;

static uint32_t
isc_stdtime_now(void) {
	return stdtime_now;
}

#include <isc/lib.h>
#include <isc/list.h>
#include <isc/netaddr.h>
#include <isc/stdtime.h>

#include <dns/deleg.h>
#include <dns/fixedname.h>
#include <dns/lib.h>
#include <dns/name.h>

/*
 * Because of the mock above.
 */
#include "../dns/deleg.c"

#include <tests/isc.h>

static void
shutdownloop(ISC_ATTR_UNUSED void *arg) {
	isc_loopmgr_shutdown();
}

static void
shutdowntest(dns_delegdb_t **db) {
	dns_deleg_shutdown(db);
	shutdownloop(NULL);
}

static void
rundelegtest(isc_job_cb testcb) {
	isc_loopmgr_create(isc_g_mctx, 1);

	isc_loop_setup(isc_loop_main(), testcb, NULL);
	isc_loopmgr_run();

	isc_loopmgr_destroy();
}

static void
addnamedeleg(const char *addrstr, dns_delegset_t *delegset, dns_deleg_t *deleg,
	     void (*fn)(dns_delegset_t *, dns_deleg_t *, const dns_name_t *)) {
	dns_fixedname_t fname;
	dns_name_t *name = dns_fixedname_initname(&fname);

	dns_name_fromstring(name, addrstr, NULL, 0, NULL);
	fn(delegset, deleg, name);
}

static void
addipdeleg(unsigned int af, const char *addrstr, dns_delegset_t *delegset,
	   dns_deleg_t *deleg) {
	isc_netaddr_t addr = { .family = af };

	assert_true(af == AF_INET || af == AF_INET6);
	assert_int_equal(inet_pton(af, addrstr, &addr.type), 1);
	dns_deleg_addaddr(delegset, deleg, &addr);
}

static void
writedb(dns_delegdb_t *db, const char *zonecutstr, dns_ttl_t expire,
	dns_delegset_t **delegsetp) {
	dns_fixedname_t fzonecut;
	dns_name_t *zonecut = dns_fixedname_initname(&fzonecut);

	dns_name_fromstring(zonecut, zonecutstr, NULL, 0, NULL);
	dns_deleg_writeset(db, zonecut, expire, delegsetp);
	assert_null(*delegsetp);
}

static isc_result_t
lookupdb(dns_delegdb_t *db, const char *namestr, isc_stdtime_t now,
	 unsigned int options, const char *expectedzcstr,
	 dns_delegset_t **delegsetp) {
	isc_result_t result;
	dns_fixedname_t fname, fexpectedzc, fzonecut;
	dns_name_t *name = dns_fixedname_initname(&fname),
		   *expectedzc = dns_fixedname_initname(&fexpectedzc),
		   *zonecut = dns_fixedname_initname(&fzonecut);

	dns_name_fromstring(expectedzc, expectedzcstr, NULL, 0, NULL);
	dns_name_fromstring(name, namestr, NULL, 0, NULL);
	result = dns_deleg_lookup(db, name, now, options, zonecut, NULL,
				  delegsetp);

	if (result == ISC_R_SUCCESS) {
		assert_non_null(*delegsetp);
		assert_true(dns_name_equal(zonecut, expectedzc));
	} else {
		assert_null(*delegsetp);
	}

	return result;
}

static void
dumpdb(dns_delegdb_t *db, const char *namestr, isc_stdtime_t now,
       isc_buffer_t *b) {
	dns_fixedname_t fname;
	dns_name_t *name = dns_fixedname_initname(&fname);

	dns_name_fromstring(name, namestr, NULL, 0, NULL);
	dns_deleg_dump(db, name, now, b);
}

static void
basictests(ISC_ATTR_UNUSED void *arg) {
	isc_result_t result;
	dns_delegdb_t *db = NULL;
	dns_deleg_t *deleg = NULL;
	dns_delegset_t *delegset = NULL;
	isc_stdtime_t now = isc_stdtime_now();
	isc_buffer_t b;
	char bdata[2048];

	isc_buffer_init(&b, bdata, sizeof(bdata));
	dns_deleg_init(&db);
	assert_non_null(db);

	/*
	 * A non expired delegation for foo. zonecut
	 */
	dns_deleg_allocset(db, &delegset);
	dns_deleg_allocdeleg(delegset, &deleg);
	assert_non_null(deleg);

	addnamedeleg("ns.foo.", delegset, deleg, dns_deleg_addns);
	addipdeleg(AF_INET, "1.2.3.4", delegset, deleg);
	addipdeleg(AF_INET6, "1111:2222:3333::4444", delegset, deleg);
	deleg = NULL;

	dns_deleg_allocdeleg(delegset, &deleg);
	assert_non_null(deleg);
	addnamedeleg("ns.example.", delegset, deleg, dns_deleg_addns);
	deleg = NULL;
	writedb(db, "foo.", 30, &delegset);

	result = lookupdb(db, "baz.bar.gee.", 0, 0, "", &delegset);
	assert_int_equal(result, ISC_R_NOTFOUND);

	result = lookupdb(db, "baz.bar.foo.", 0, 0, "foo.", &delegset);
	assert_int_equal(result, ISC_R_SUCCESS);
	dns_delegset_detach(&delegset);

	const char expected_foodeleg[] =
		"foo. DELEG 30"
		"\n\tserver-ipv4=\n\t\t1.2.3.4"
		"\n\tserver-ipv6=\n\t\t1111:2222:3333::4444"
		"\n\tserver-name=\n\t\tns.foo.\n"
		"foo. DELEG 30"
		"\n\tserver-name=\n\t\tns.example.";
	dumpdb(db, "foo.", 0, &b);
	assert_string_equal(bdata, expected_foodeleg);
	dumpdb(db, "idonotknowthis.foo.", 0, &b);
	assert_string_equal(bdata, expected_foodeleg);

	/*
	 * A non expired delegation for bar.foo. zonecut
	 */
	dns_deleg_allocset(db, &delegset);
	dns_deleg_allocdeleg(delegset, &deleg);
	assert_non_null(deleg);

	addnamedeleg("ns.bar.foo.", delegset, deleg, dns_deleg_addns);
	addnamedeleg("ns2.bar.foo.", delegset, deleg, dns_deleg_addns);
	addipdeleg(AF_INET, "8.9.10.11", delegset, deleg);
	addipdeleg(AF_INET, "9.9.10.11", delegset, deleg);
	addipdeleg(AF_INET6, "ACDC::ACDC", delegset, deleg);
	addipdeleg(AF_INET6, "ABBA::ABBA", delegset, deleg);
	addnamedeleg("delegns.gee.", delegset, deleg, dns_deleg_adddelegi);
	addnamedeleg("delegns2.gee.", delegset, deleg, dns_deleg_adddelegi);
	writedb(db, "bar.foo.", 25, &delegset);
	deleg = NULL;

	result = lookupdb(db, "baz.bar.gee.", 0, 0, "", &delegset);
	assert_int_equal(result, ISC_R_NOTFOUND);

	result = lookupdb(db, "baz.bar.foo.", 0, 0, "bar.foo.", &delegset);
	assert_int_equal(result, ISC_R_SUCCESS);
	dns_delegset_detach(&delegset);

	const char expected_barfoodeleg[] =
		"bar.foo. DELEG 25"
		"\n\tserver-ipv4=\n\t\t8.9.10.11,\n\t\t9.9.10.11"
		"\n\tserver-ipv6=\n\t\tacdc::acdc,\n\t\tabba::abba"
		"\n\tserver-name=\n\t\tns.bar.foo.,\n\t\tns2.bar.foo."
		"\n\tinclude-delegi=\n\t\tdelegns.gee.,\n\t\tdelegns2.gee.";
	dumpdb(db, "bar.foo.", 0, &b);
	assert_string_equal(bdata, expected_barfoodeleg);
	dumpdb(db, "i.really.donotknowthis.bar.foo.", 0, &b);
	assert_string_equal(bdata, expected_barfoodeleg);

	/*
	 * A expired delegation for bar.stuff. zonecut
	 */
	dns_deleg_allocset(db, &delegset);
	dns_deleg_allocdeleg(delegset, &deleg);
	assert_non_null(deleg);

	addnamedeleg("ns.bar.stuff.", delegset, deleg, dns_deleg_addns);
	addipdeleg(AF_INET6, "1111::2222", delegset, deleg);
	writedb(db, "bar.stuff.", 10, &delegset);
	deleg = NULL;

	result = lookupdb(db, "baz.bar.stuff.", now + 10, 0, "", &delegset);
	assert_int_equal(result, ISC_R_NOTFOUND);

	/*
	 * But, if we ask for a date before its expiration, it is visible. And
	 * it is possible to dump it as well. But of course the dump when
	 * expired won't get anythig.
	 */
	result = lookupdb(db, "baz.bar.stuff.", now + 9, 0, "bar.stuff.",
			  &delegset);
	assert_int_equal(result, ISC_R_SUCCESS);
	dns_delegset_detach(&delegset);
	dumpdb(db, "baz.bar.stuff.", now + 9, &b);
	assert_string_equal(bdata, "bar.stuff. DELEG 1"
				   "\n\tserver-ipv6="
				   "\n\t\t1111::2222"
				   "\n\tserver-name="
				   "\n\t\tns.bar.stuff.");
	dumpdb(db, "bar.bar.stuff.", now + 10, &b);
	assert_true(isc_buffer_usedlength(&b) == 1);
	assert_string_equal(bdata, "");

	/*
	 * A non expired delegation for bar.stuff. zonecut replace the expired
	 * one
	 */
	dns_deleg_allocset(db, &delegset);
	dns_deleg_allocdeleg(delegset, &deleg);
	assert_non_null(deleg);

	addnamedeleg("ns.bar.stuff.", delegset, deleg, dns_deleg_addns);
	addipdeleg(AF_INET6, "1111::3333", delegset, deleg);
	writedb(db, "bar.stuff.", 2, &delegset);
	deleg = NULL;

	result = lookupdb(db, "stuff.", 0, 0, "", &delegset);
	assert_int_equal(result, ISC_R_NOTFOUND);

	result = lookupdb(db, "idonotknowthis.at.all.stuff.", 0, 0, "",
			  &delegset);
	assert_int_equal(result, ISC_R_NOTFOUND);

	result = lookupdb(db, "baz.bar.stuff.", 0, 0, "bar.stuff.", &delegset);
	assert_int_equal(result, ISC_R_SUCCESS);
	dns_delegset_detach(&delegset);

	const char expected_barstuffdeleg[] =
		"bar.stuff. DELEG 2"
		"\n\tserver-ipv6=\n\t\t1111::3333"
		"\n\tserver-name=\n\t\tns.bar.stuff.";
	dumpdb(db, "bar.stuff.", 0, &b);
	assert_string_equal(bdata, expected_barstuffdeleg);
	dumpdb(db, "idonotknowthis.bar.stuff.", 0, &b);
	assert_string_equal(bdata, expected_barstuffdeleg);

	/*
	 * Dump API just returns a buffer with used=0 if a zonecut is provided
	 * but not closest zonecut is found.
	 */
	dumpdb(db, "idonotknowthis.at.all.stuff.", 0, &b);
	assert_true(isc_buffer_usedlength(&b) == 1);
	assert_string_equal(bdata, "");

	/*
	 * Dump API returns the whole DB if no zonecut is provided
	 */
	char expected_wholedb[2048] = { 0 };
	sprintf(expected_wholedb, "%s\n%s\n%s", expected_foodeleg,
		expected_barfoodeleg, expected_barstuffdeleg);
	dns_deleg_dump(db, NULL, 0, &b);
	assert_string_equal(bdata, expected_wholedb);
	assert_true(isc_buffer_usedlength(&b) > 0);

	/*
	 * Dump in the "future", everything is seen as expired
	 */
	isc_buffer_clear(&b);
	dns_deleg_dump(db, NULL, now + 300, &b);
	assert_int_equal(isc_buffer_usedlength(&b), 1);
	assert_string_equal(bdata, "");

	shutdowntest(&db);
}

static void
ttl0tests(ISC_ATTR_UNUSED void *arg) {
	isc_result_t result;
	dns_delegdb_t *db = NULL;
	dns_deleg_t *deleg = NULL;
	dns_delegset_t *delegset = NULL;
	isc_stdtime_t now = isc_stdtime_now();
	isc_buffer_t b;
	char bdata[2048];

	isc_buffer_init(&b, bdata, sizeof(bdata));
	dns_deleg_init(&db);
	assert_non_null(db);

	dns_deleg_allocset(db, &delegset);
	dns_deleg_allocdeleg(delegset, &deleg);
	assert_non_null(deleg);

	addnamedeleg("ns.bar.stuff.", delegset, deleg, dns_deleg_addns);
	addipdeleg(AF_INET6, "1111::2222", delegset, deleg);
	writedb(db, "bar.stuff.", 0, &delegset);
	deleg = NULL;

	result = lookupdb(db, "baz.bar.stuff.", now, 0, "bar.stuff.",
			  &delegset);
	assert_int_equal(result, ISC_R_SUCCESS);
	dns_delegset_detach(&delegset);

	result = lookupdb(db, "baz.bar.stuff.", now + 1, 0, "", &delegset);
	assert_int_equal(result, ISC_R_NOTFOUND);

	shutdowntest(&db);
}

static void
noexacttests(ISC_ATTR_UNUSED void *arg) {
	isc_result_t result;
	dns_delegdb_t *db = NULL;
	dns_deleg_t *deleg = NULL;
	dns_delegset_t *delegset = NULL;
	isc_stdtime_t now = isc_stdtime_now();
	isc_buffer_t b;
	char bdata[2048];

	isc_buffer_init(&b, bdata, sizeof(bdata));
	dns_deleg_init(&db);
	assert_non_null(db);

	struct {
		const char *name;
		const char *expected;
		const char *noexactexpected;
		dns_ttl_t ttl;
	} zonecuts[] = {
		{ "stuff.", "stuff.", "stuff.", 30 },
		{ "foo.stuff.", "foo.stuff.", "stuff.", 30 },
		{ "expired.foo.stuff.", "foo.stuff.", "foo.stuff.", 1 },
		{ "bar.expired.foo.stuff.", "bar.expired.foo.stuff.",
		  "foo.stuff.", 30 },
		{ "baz.bar.expired.foo.stuff.", "baz.bar.expired.foo.stuff.",
		  "bar.expired.foo.stuff.", 30 }
	};

	for (size_t i = 0; i < ARRAY_SIZE(zonecuts); i++) {
		dns_deleg_allocset(db, &delegset);
		dns_deleg_allocdeleg(delegset, &deleg);
		addipdeleg(AF_INET6, "1111::1111", delegset, deleg);
		writedb(db, zonecuts[i].name, zonecuts[i].ttl, &delegset);
		deleg = NULL;
	}

	for (size_t i = 0; i < ARRAY_SIZE(zonecuts); i++) {
		result = lookupdb(db, zonecuts[i].name, now + 1, 0,
				  zonecuts[i].expected, &delegset);
		assert_int_equal(result, ISC_R_SUCCESS);
		dns_delegset_detach(&delegset);

		result = lookupdb(db, zonecuts[i].name, now + 1,
				  DNS_DBFIND_NOEXACT,
				  zonecuts[i].noexactexpected, &delegset);
		assert_int_equal(result, ISC_R_SUCCESS);
		dns_delegset_detach(&delegset);
	}

	result = lookupdb(db, "gee.expired.foo.stuff.", now + 1, 0,
			  "foo.stuff.", &delegset);
	assert_int_equal(result, ISC_R_SUCCESS);
	dns_delegset_detach(&delegset);

	shutdowntest(&db);
}

static void
deletetests(ISC_ATTR_UNUSED void *arg) {
	isc_result_t result;
	dns_delegdb_t *db = NULL;
	dns_deleg_t *deleg = NULL;
	dns_delegset_t *delegset = NULL;
	dns_fixedname_t fname;
	dns_name_t *name = dns_fixedname_initname(&fname);

	dns_deleg_init(&db);
	assert_non_null(db);

	dns_deleg_allocset(db, &delegset);
	dns_deleg_allocdeleg(delegset, &deleg);
	addipdeleg(AF_INET6, "1111::2222", delegset, deleg);
	writedb(db, "stuff.", 10, &delegset);
	deleg = NULL;

	dns_deleg_allocset(db, &delegset);
	dns_deleg_allocdeleg(delegset, &deleg);
	addipdeleg(AF_INET6, "1111::2222", delegset, deleg);
	writedb(db, "baz.stuff.", 10, &delegset);
	deleg = NULL;

	dns_deleg_allocset(db, &delegset);
	dns_deleg_allocdeleg(delegset, &deleg);
	addipdeleg(AF_INET6, "1111::2222", delegset, deleg);
	writedb(db, "bar.baz.stuff.", 10, &delegset);
	deleg = NULL;

	dns_deleg_allocset(db, &delegset);
	dns_deleg_allocdeleg(delegset, &deleg);
	addipdeleg(AF_INET6, "1111::2222", delegset, deleg);
	writedb(db, "foo.bar.baz.stuff.", 10, &delegset);
	deleg = NULL;

	dns_name_fromstring(name, "foo.", NULL, 0, NULL);
	result = dns_deleg_delete(db, name, false);
	assert_int_equal(result, ISC_R_NOTFOUND);
	result = dns_deleg_delete(db, name, true);
	assert_int_equal(result, ISC_R_NOTFOUND);

	dns_name_fromstring(name, "gee.foo.bar.stuff.", NULL, 0, NULL);
	result = dns_deleg_delete(db, name, false);
	assert_int_equal(result, ISC_R_NOTFOUND);

	dns_name_fromstring(name, "foo.bar.baz.stuff.", NULL, 0, NULL);
	result = dns_deleg_delete(db, name, false);
	assert_int_equal(result, ISC_R_SUCCESS);

	dns_name_fromstring(name, "foo.bar.baz.stuff.", NULL, 0, NULL);
	result = dns_deleg_delete(db, name, false);
	assert_int_equal(result, ISC_R_NOTFOUND);

	dns_name_fromstring(name, "baz.stuff.", NULL, 0, NULL);
	result = dns_deleg_delete(db, name, false);
	assert_int_equal(result, ISC_R_SUCCESS);

	result = lookupdb(db, "bar.baz.stuff.", 5, 0, "bar.baz.stuff.",
			  &delegset);
	assert_int_equal(result, ISC_R_SUCCESS);
	dns_delegset_detach(&delegset);

	dns_name_fromstring(name, "stuff.", NULL, 0, NULL);
	result = dns_deleg_delete(db, name, true);
	assert_int_equal(result, ISC_R_SUCCESS);

	dns_name_fromstring(name, "stuff.", NULL, 0, NULL);
	result = dns_deleg_delete(db, name, false);
	assert_int_equal(result, ISC_R_NOTFOUND);

	dns_name_fromstring(name, "bar.baz.stuff.", NULL, 0, NULL);
	result = dns_deleg_delete(db, name, false);
	assert_int_equal(result, ISC_R_NOTFOUND);

	result = lookupdb(db, "bar.baz.stuff.", 5, 0, "bar.baz.stuff.",
			  &delegset);
	assert_int_equal(result, ISC_R_NOTFOUND);

	/*
	 * Let's add stuff. back and query bar.baz.stuff. again. Because the
	 * node is NULL, it should go up until it finds stuff.
	 */
	dns_deleg_allocset(db, &delegset);
	dns_deleg_allocdeleg(delegset, &deleg);
	addipdeleg(AF_INET6, "1111::2222", delegset, deleg);
	writedb(db, "stuff.", 10, &delegset);
	deleg = NULL;

	result = lookupdb(db, "bar.baz.stuff.", 5, 0, "stuff.", &delegset);
	assert_int_equal(result, ISC_R_SUCCESS);
	dns_delegset_detach(&delegset);

	shutdowntest(&db);
}

static void
maintenancetests(ISC_ATTR_UNUSED void *arg) {
	dns_delegdb_t *db = NULL;
	dns_deleg_t *deleg = NULL;
	dns_delegset_t *delegset = NULL;
	isc_stdtime_t now = isc_stdtime_now();
	dns_fixedname_t fname;
	dns_name_t *name = dns_fixedname_initname(&fname);
	isc_result_t result;

	dns_deleg_init(&db);
	assert_non_null(db);

	/*
	 * A valid record
	 */
	dns_deleg_allocset(db, &delegset);
	dns_deleg_allocdeleg(delegset, &deleg);
	addipdeleg(AF_INET6, "1111::2222", delegset, deleg);
	writedb(db, "baz.", 300, &delegset);
	deleg = NULL;

	/*
	 * An expired record
	 */
	dns_deleg_allocset(db, &delegset);
	dns_deleg_allocdeleg(delegset, &deleg);

	assert_int_in_range(isc_mem_inuse(db->mctx), 500, 2000);

	for (size_t i = 0; i < 9999; i++) {
		addipdeleg(AF_INET6, "1111::2222", delegset, deleg);
	}

	assert_int_in_range(isc_mem_inuse(db->mctx), 400000, 410000);

	writedb(db, "stuff.", 10, &delegset);
	deleg = NULL;
	stdtime_now += 10;

	/*
	 * A deleted record
	 */
	dns_deleg_allocset(db, &delegset);
	dns_deleg_allocdeleg(delegset, &deleg);

	for (size_t i = 0; i < 9999; i++) {
		addipdeleg(AF_INET6, "1111::2222", delegset, deleg);
	}

	writedb(db, "bar.", 30, &delegset);
	deleg = NULL;

	assert_int_in_range(isc_mem_inuse(db->mctx), 800000, 810000);

	dns_name_fromstring(name, "bar.", NULL, 0, NULL);
	(void)dns_deleg_delete(db, name, true);

	/*
	 * Bar delegset is immediately detached (hence, deleted). Although the
	 * node remains in memory.
	 *
	 * Stuff node and delegset remain in memory, because the expiration is
	 * not a condition for immediate delegset detach (there is no pro-active
	 * detection of it).
	 */
	assert_int_in_range(isc_mem_inuse(db->mctx), 400000, 410000);

	dns_deleg_maintenance(db);

	/*
	 * Bar internal node and stuff (internal node and delegset) are now
	 * freed from memory.
	 *
	 * rcu_barrier() is needed to kick off QP reclamation flow (and run the
	 * detaching functions from the DB nodes).
	 */
	rcu_barrier();
	assert_int_in_range(isc_mem_inuse(db->mctx), 500, 2000);

	/*
	 * baz. is still there
	 */
	result = lookupdb(db, "baz.", now, 0, "baz.", &delegset);
	assert_int_equal(result, ISC_R_SUCCESS);
	dns_delegset_detach(&delegset);

	shutdowntest(&db);
}

ISC_RUN_TEST_IMPL(dns_deleg_basictests) { rundelegtest(basictests); }
ISC_RUN_TEST_IMPL(dns_deleg_ttl0tests) { rundelegtest(ttl0tests); }
ISC_RUN_TEST_IMPL(dns_deleg_noexacttests) { rundelegtest(noexacttests); }
ISC_RUN_TEST_IMPL(dns_deleg_deletetests) { rundelegtest(deletetests); }
ISC_RUN_TEST_IMPL(dns_deleg_maintenancetests) {
	rundelegtest(maintenancetests);
}

ISC_TEST_LIST_START
ISC_TEST_ENTRY(dns_deleg_basictests)
ISC_TEST_ENTRY(dns_deleg_ttl0tests)
ISC_TEST_ENTRY(dns_deleg_noexacttests)
ISC_TEST_ENTRY(dns_deleg_deletetests)
ISC_TEST_ENTRY(dns_deleg_maintenancetests)
ISC_TEST_LIST_END

ISC_TEST_MAIN
