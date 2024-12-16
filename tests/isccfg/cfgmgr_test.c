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

#include <pthread.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdlib.h>

#define UNIT_TESTING
#include <cmocka.h>

#include <isccfg/cfgmgr.h>

#include <tests/isc.h>

#define INIT		 SUCCESS(cfgmgr_init(mctx, "/tmp/named-cfgmgr-lmdb"))
#define SUCCESS(result)	 assert_int_equal(result, ISC_R_SUCCESS)
#define NOTFOUND(result) assert_int_equal(result, ISC_R_NOTFOUND)
#define NOTBOUND(result) assert_int_equal(result, ISC_R_NOTBOUND)

ISC_RUN_TEST_IMPL(cfgmgr_rw) {
	cfgmgr_val_t val1;
	cfgmgr_val_t val2;

	INIT;
	NOTFOUND(cfgmgr_open("foo"));
	SUCCESS(cfgmgr_newclause("foo"));

	val1 = (cfgmgr_val_t){ .type = UINT32, .data.uint32 = 4058304 };
	SUCCESS(cfgmgr_setval("prop1", &val1));
	SUCCESS(cfgmgr_getval("prop1", &val2));
	assert_int_equal(val2.type, UINT32);
	assert_int_equal(val2.data.uint32, 4058304);

	val1 = (cfgmgr_val_t){ .type = NONE };
	SUCCESS(cfgmgr_setval("prop3", &val1));
	SUCCESS(cfgmgr_getval("prop3", &val2));
	assert_int_equal(val2.type, NONE);

	val1 = (cfgmgr_val_t){ .type = BOOL, .data.boolean = true };
	SUCCESS(cfgmgr_setval("prop2", &val1));
	SUCCESS(cfgmgr_getval("prop2", &val2));
	assert_int_equal(val2.type, BOOL);
	assert_int_equal(val2.data.boolean, true);

	val1 = (cfgmgr_val_t){ .type = BOOL, .data.boolean = false };
	SUCCESS(cfgmgr_setval("anotherprop", &val1));
	SUCCESS(cfgmgr_getval("anotherprop", &val2));
	assert_int_equal(val2.type, BOOL);
	assert_int_equal(val2.data.boolean, false);

	/*
	 * Let's check and adding other properties didn't affect the
	 * ones added previously
	 */
	SUCCESS(cfgmgr_getval("prop3", &val2));
	assert_int_equal(val2.type, NONE);

	SUCCESS(cfgmgr_getval("prop1", &val2));
	assert_int_equal(val2.type, UINT32);
	assert_int_equal(val2.data.uint32, 4058304);

	SUCCESS(cfgmgr_getval("prop2", &val2));
	assert_int_equal(val2.type, BOOL);
	assert_int_equal(val2.data.boolean, true);

	/*
	 * Non existent property - it doesn't not mutate val.
	 */
	NOTFOUND(cfgmgr_getval("prop4", &val2));
	assert_int_equal(val2.type, BOOL);
	assert_int_equal(val2.data.boolean, true);

	NOTFOUND(cfgmgr_getval("p", &val2));
	assert_int_equal(val2.type, BOOL);
	assert_int_equal(val2.data.boolean, true);

	SUCCESS(cfgmgr_close());

	SUCCESS(cfgmgr_open("foo"));

	/*
	 * Everything still there when closing and re-opening
	 * (read-only) the clause
	 */
	SUCCESS(cfgmgr_getval("prop3", &val2));
	assert_int_equal(val2.type, NONE);

	SUCCESS(cfgmgr_getval("prop1", &val2));
	assert_int_equal(val2.type, UINT32);
	assert_int_equal(val2.data.uint32, 4058304);

	SUCCESS(cfgmgr_getval("prop2", &val2));
	assert_int_equal(val2.type, BOOL);
	assert_int_equal(val2.data.boolean, true);

	SUCCESS(cfgmgr_close());

	NOTBOUND(cfgmgr_close());

	/*
	 * Adding other clause (intentionally with a different name,
	 * but a common prefix in the name - those are still different
	 * clauses
	 */
	SUCCESS(cfgmgr_newclause("foo1"));
	val1 = (cfgmgr_val_t){ .type = UINT32, .data.uint32 = 1234 };
	SUCCESS(cfgmgr_setval("prop1", &val1));
	SUCCESS(cfgmgr_getval("prop1", &val2));
	assert_int_equal(val2.type, UINT32);
	assert_int_equal(val2.data.uint32, 1234);

	val1 = (cfgmgr_val_t){ .type = NONE };
	SUCCESS(cfgmgr_setval("somestuff", &val1));
	SUCCESS(cfgmgr_getval("somestuff", &val2));
	assert_int_equal(val2.type, NONE);

	/*
	 * Make sure we don't mixes clause properties
	 */
	NOTFOUND(cfgmgr_getval("prop2", &val2));
	NOTFOUND(cfgmgr_getval("prop3", &val2));
	SUCCESS(cfgmgr_close());

	/*
	 * let's reopen rw this time
	 */
	SUCCESS(cfgmgr_openrw("foo"));
	SUCCESS(cfgmgr_getval("prop1", &val2));
	assert_int_equal(val2.type, UINT32);
	assert_int_equal(val2.data.uint32, 4058304);
	SUCCESS(cfgmgr_getval("prop2", &val2));
	assert_int_equal(val2.type, BOOL);
	assert_int_equal(val2.data.boolean, true);
	SUCCESS(cfgmgr_close());

	SUCCESS(cfgmgr_openrw("foo1"));
	SUCCESS(cfgmgr_getval("prop1", &val2));
	assert_int_equal(val2.type, UINT32);
	assert_int_equal(val2.data.uint32, 1234);
	SUCCESS(cfgmgr_getval("somestuff", &val2));
	assert_int_equal(val2.type, NONE);

	/*
	 * because we used openrw, we can do that
	 */
	val1.type = UINT32;
	val1.data.uint32 = 999;
	SUCCESS(cfgmgr_setval("somestuff2", &val1));
	SUCCESS(cfgmgr_getval("somestuff2", &val2));
	assert_int_equal(val2.type, UINT32);
	assert_int_equal(val2.data.uint32, 999);

	SUCCESS(cfgmgr_close());

	cfgmgr_deinit();
}

ISC_RUN_TEST_IMPL(cfgmgr_parseid) {
	cfgmgr_val_t val;

	/*
	 * Excercise the fact that even if properties/clause names are
	 * number, this doesn't confuse the id parser (in particular,
	 * validates the usage of strtoul is correct). This also
	 * exercise the nested clause and repeatable clauses with such
	 * odd names
	 */
	INIT;
	SUCCESS(cfgmgr_newclause("123"));
	val = (cfgmgr_val_t){ .type = UINT32, .data.uint32 = 666666 };
	SUCCESS(cfgmgr_setval("123123", &val));
	SUCCESS(cfgmgr_newclause("456"));
	val = (cfgmgr_val_t){ .type = UINT32, .data.uint32 = 777777 };
	SUCCESS(cfgmgr_setval("456456", &val));
	SUCCESS(cfgmgr_close());
	SUCCESS(cfgmgr_newclause("456"));
	val = (cfgmgr_val_t){ .type = UINT32, .data.uint32 = 888888 };
	SUCCESS(cfgmgr_setval("456456", &val));
	SUCCESS(cfgmgr_close());
	val = (cfgmgr_val_t){ .type = UINT32, .data.uint32 = 9999 };
	SUCCESS(cfgmgr_setval("456456", &val));
	SUCCESS(cfgmgr_close());

	SUCCESS(cfgmgr_open("123"));
	SUCCESS(cfgmgr_getval("123123", &val));
	assert_int_equal(val.type, UINT32);
	assert_int_equal(val.data.uint32, 666666);
	SUCCESS(cfgmgr_getval("456456", &val));
	assert_int_equal(val.type, UINT32);
	assert_int_equal(val.data.uint32, 9999);

	bool found_777777 = false;
	bool found_888888 = false;

	SUCCESS(cfgmgr_open("456"));
	SUCCESS(cfgmgr_getval("456456", &val));
	assert_int_equal(val.type, UINT32);
	if (val.data.uint32 == 777777) {
		found_777777 = true;
	} else if (val.data.uint32 == 888888) {
		found_888888 = true;
	} else {
		REQUIRE(false);
	}

	SUCCESS(cfgmgr_nextclause());
	SUCCESS(cfgmgr_getval("456456", &val));
	assert_int_equal(val.type, UINT32);
	if (val.data.uint32 == 777777) {
		found_777777 = true;
	} else if (val.data.uint32 == 888888) {
		found_888888 = true;
	} else {
		REQUIRE(false);
	}

	assert_true(found_777777);
	assert_true(found_888888);

	SUCCESS(cfgmgr_close());
	SUCCESS(cfgmgr_close());

	cfgmgr_deinit();
}

ISC_RUN_TEST_IMPL(cfgmgr_override) {
	cfgmgr_val_t val1;
	cfgmgr_val_t val2;

	INIT;
	SUCCESS(cfgmgr_newclause("foo"));

	val1 = (cfgmgr_val_t){ .type = UINT32, .data.uint32 = 4058304 };
	SUCCESS(cfgmgr_setval("prop1", &val1));
	SUCCESS(cfgmgr_getval("prop1", &val2));
	assert_int_equal(val2.type, UINT32);
	assert_int_equal(val2.data.uint32, 4058304);

	val1 = (cfgmgr_val_t){ .type = UINT32, .data.uint32 = 666 };
	SUCCESS(cfgmgr_setval("prop1", &val1));
	SUCCESS(cfgmgr_getval("prop1", &val2));
	assert_int_equal(val2.type, UINT32);
	assert_int_equal(val2.data.uint32, 666);

	val1 = (cfgmgr_val_t){ .type = BOOL, .data.boolean = false };
	SUCCESS(cfgmgr_setval("prop1", &val1));
	SUCCESS(cfgmgr_getval("prop1", &val2));
	assert_int_equal(val2.type, BOOL);
	assert_int_equal(val2.data.boolean, false);

	val1 = (cfgmgr_val_t){ .type = BOOL, .data.boolean = true };
	SUCCESS(cfgmgr_setval("prop1", &val1));
	SUCCESS(cfgmgr_getval("prop1", &val2));
	assert_int_equal(val2.type, BOOL);
	assert_int_equal(val2.data.boolean, true);

	SUCCESS(cfgmgr_close());

	cfgmgr_deinit();
}

ISC_RUN_TEST_IMPL(cfgmgr_rw_string) {
	cfgmgr_val_t val1;
	cfgmgr_val_t val2;

	INIT;
	SUCCESS(cfgmgr_newclause("foo"));

	val1 = (cfgmgr_val_t){ .type = STRING, .data.string = "hey there!" };
	SUCCESS(cfgmgr_setval("prop1", &val1));
	SUCCESS(cfgmgr_getval("prop1", &val2));
	assert_int_equal(val2.type, STRING);
	assert_string_equal(val2.data.string, "hey there!");

	val1 = (cfgmgr_val_t){
		.type = STRING,
		.data.string = "hey there! hey there!hey there!hey there!hey "
			       "there!hey there!hey there!hey there!hey "
			       "there!hey there!hey there!hey there!hey "
			       "there!hey there!hey there!hey there!hey "
			       "there!hey there!hey there!hey there!hey "
			       "there!hey there!hey there!hey there!hey "
			       "there!hey there!hey there!hey there!hey "
			       "there!hey there!hey there!hey there!hey "
			       "there!hey there!hey there!hey there!"
	};
	SUCCESS(cfgmgr_setval("prop1", &val1));
	SUCCESS(cfgmgr_getval("prop1", &val2));
	assert_int_equal(val2.type, STRING);
	assert_string_equal(
		val2.data.string,
		"hey there! hey there!hey there!hey there!hey there!hey "
		"there!hey there!hey there!hey there!hey there!hey there!hey "
		"there!hey there!hey there!hey there!hey there!hey there!hey "
		"there!hey there!hey there!hey there!hey there!hey there!hey "
		"there!hey there!hey there!hey there!hey there!hey there!hey "
		"there!hey there!hey there!hey there!hey there!hey there!hey "
		"there!");

	val1 = (cfgmgr_val_t){ .type = STRING,
			       .data.string = "foobarbaz stuff" };
	SUCCESS(cfgmgr_setval("shorterstring", &val1));
	SUCCESS(cfgmgr_getval("shorterstring", &val2));
	assert_int_equal(val2.type, STRING);
	assert_string_equal(val2.data.string, "foobarbaz stuff");

	SUCCESS(cfgmgr_close());

	cfgmgr_deinit();
}

ISC_RUN_TEST_IMPL(cfgmgr_list) {
	cfgmgr_val_t val;

	INIT;
	SUCCESS(cfgmgr_newclause("foo"));

	val = (cfgmgr_val_t){ .type = STRING, .data.string = "lst1" };
	SUCCESS(cfgmgr_setnextlistval("proplist", &val));
	val.data.string = "lst2";
	SUCCESS(cfgmgr_setnextlistval("proplist", &val));
	val.data.string = "lst3";
	SUCCESS(cfgmgr_setnextlistval("proplist", &val));
	val.data.string = "lst4";
	SUCCESS(cfgmgr_setnextlistval("proplist", &val));

	val.data.string = "otherpropval";
	SUCCESS(cfgmgr_setval("otherprop", &val));

	val.data.string = "zzzval";
	SUCCESS(cfgmgr_setval("zzz", &val));
	SUCCESS(cfgmgr_close());

	SUCCESS(cfgmgr_open("foo"));

	SUCCESS(cfgmgr_getval("proplist", &val));
	assert_int_equal(val.type, STRING);
	assert_string_equal(val.data.string, "lst1");

	/*
	 * calling it again, we stick to the head
	 */
	SUCCESS(cfgmgr_getval("proplist", &val));
	assert_int_equal(val.type, STRING);
	assert_string_equal(val.data.string, "lst1");

	/*
	 * now we're moving on...
	 */
	SUCCESS(cfgmgr_getnextlistval(&val));
	assert_int_equal(val.type, STRING);
	assert_string_equal(val.data.string, "lst2");

	SUCCESS(cfgmgr_getnextlistval(&val));
	assert_int_equal(val.type, STRING);
	assert_string_equal(val.data.string, "lst3");

	SUCCESS(cfgmgr_getnextlistval(&val));
	assert_int_equal(val.type, STRING);
	assert_string_equal(val.data.string, "lst4");

	assert_int_equal(cfgmgr_getnextlistval(&val), ISC_R_NOMORE);
	assert_int_equal(cfgmgr_getnextlistval(&val), ISC_R_NOMORE);

	/*
	 * and start from the begining again
	 */
	SUCCESS(cfgmgr_getval("proplist", &val));
	assert_int_equal(val.type, STRING);
	assert_string_equal(val.data.string, "lst1");

	/*
	 * move on in the list but re-start again
	 */
	SUCCESS(cfgmgr_getnextlistval(&val));
	assert_int_equal(val.type, STRING);
	assert_string_equal(val.data.string, "lst2");
	SUCCESS(cfgmgr_getval("proplist", &val));
	assert_int_equal(val.type, STRING);
	assert_string_equal(val.data.string, "lst1");

	/*
	 * calling after reading a non-list property
	 */
	SUCCESS(cfgmgr_getval("zzz", &val));
	assert_int_equal(cfgmgr_getnextlistval(&val), ISC_R_NOMORE);

	SUCCESS(cfgmgr_close());
	cfgmgr_deinit();
}

ISC_RUN_TEST_IMPL(cfgmgr_repeatable_clauses) {
	cfgmgr_val_t val1;
	cfgmgr_val_t val2;

	INIT;
	SUCCESS(cfgmgr_newclause("view"));
	SUCCESS(cfgmgr_setval("p1", &(cfgmgr_val_t){ .type = STRING,
						     .data.string = "view1 p1 "
								    "val" }));
	SUCCESS(cfgmgr_setval(
		"p2", &(cfgmgr_val_t){ .type = BOOL, .data.boolean = false }));
	SUCCESS(cfgmgr_close());

	SUCCESS(cfgmgr_newclause("view"));
	SUCCESS(cfgmgr_setval("p1", &(cfgmgr_val_t){ .type = STRING,
						     .data.string = "view2 p2 "
								    "val" }));
	SUCCESS(cfgmgr_setval(
		"p2", &(cfgmgr_val_t){ .type = BOOL, .data.boolean = true }));
	SUCCESS(cfgmgr_close());

	SUCCESS(cfgmgr_open("view"));
	SUCCESS(cfgmgr_getval("p2", &val2));
	assert_int_equal(val2.type, BOOL);

	if (val2.data.boolean) {
		SUCCESS(cfgmgr_getval("p1", &val1));
		assert_int_equal(val1.type, STRING);
		assert_string_equal(val1.data.string, "view2 p2 val");
	} else {
		SUCCESS(cfgmgr_getval("p1", &val1));
		assert_int_equal(val1.type, STRING);
		assert_string_equal(val1.data.string, "view1 p1 val");
	}

	SUCCESS(cfgmgr_nextclause());

	SUCCESS(cfgmgr_getval("p2", &val2));
	assert_int_equal(val2.type, BOOL);

	if (val2.data.boolean) {
		SUCCESS(cfgmgr_getval("p1", &val1));
		assert_int_equal(val1.type, STRING);
		assert_string_equal(val1.data.string, "view2 p2 val");
	} else {
		SUCCESS(cfgmgr_getval("p1", &val1));
		assert_int_equal(val1.type, STRING);
		assert_string_equal(val1.data.string, "view1 p1 val");
	}

	assert_int_equal(cfgmgr_nextclause(), ISC_R_NOMORE);
	SUCCESS(cfgmgr_close());
	cfgmgr_deinit();
}

ISC_RUN_TEST_IMPL(cfgmgr_nested_clauses) {
	cfgmgr_val_t val;

	/*
	 * Let's start by writting then reading
	 * foo { bar { baz { gee: none; }; }; };
	 */
	INIT;
	SUCCESS(cfgmgr_newclause("foo"));
	SUCCESS(cfgmgr_newclause("bar"));
	SUCCESS(cfgmgr_newclause("baz"));
	val.type = NONE;
	SUCCESS(cfgmgr_setval("gee", &val));
	SUCCESS(cfgmgr_close());
	SUCCESS(cfgmgr_close());
	SUCCESS(cfgmgr_close());
	NOTBOUND(cfgmgr_close());
	SUCCESS(cfgmgr_open("foo"));
	SUCCESS(cfgmgr_open("bar"));
	SUCCESS(cfgmgr_open("baz"));
	val.type = UINT32;
	SUCCESS(cfgmgr_getval("gee", &val));
	assert_int_equal(val.type, NONE);
	SUCCESS(cfgmgr_close());
	SUCCESS(cfgmgr_close());
	SUCCESS(cfgmgr_close());

	/*
	 * then let's delete bar and add some properties in foo and
	 * another nested clause
	 */
	SUCCESS(cfgmgr_openrw("foo"));
	SUCCESS(cfgmgr_open("bar"));
	SUCCESS(cfgmgr_delclause());
	SUCCESS(cfgmgr_newclause("foonewsubclause"));
	val = (cfgmgr_val_t){ .type = STRING, .data.string = "abc" };
	SUCCESS(cfgmgr_setval("propsubclause", &val));
	SUCCESS(cfgmgr_close());
	val = (cfgmgr_val_t){ .type = STRING, .data.string = "propfooval" };
	SUCCESS(cfgmgr_setval("propfoo", &val));
	SUCCESS(cfgmgr_close());

	NOTBOUND(cfgmgr_close());

	SUCCESS(cfgmgr_open("foo"));
	SUCCESS(cfgmgr_getval("propfoo", &val));
	assert_int_equal(val.type, STRING);
	assert_string_equal(val.data.string, "propfooval");
	NOTFOUND(cfgmgr_open("bar"));
	SUCCESS(cfgmgr_open("foonewsubclause"));
	SUCCESS(cfgmgr_getval("propsubclause", &val));
	assert_int_equal(val.type, STRING);
	assert_string_equal(val.data.string, "abc");
	SUCCESS(cfgmgr_close());
	SUCCESS(cfgmgr_close());

	/*
	 * Let's mix nested and repeatable clauses
	 */
	SUCCESS(cfgmgr_openrw("foo"));
	SUCCESS(cfgmgr_newclause("foonewsubclause"));

	bool abc_found = false;
	bool def_found = false;

	val = (cfgmgr_val_t){ .type = STRING, .data.string = "def" };
	SUCCESS(cfgmgr_setval("propsubclause", &val));
	SUCCESS(cfgmgr_close());
	SUCCESS(cfgmgr_close());
	NOTBOUND(cfgmgr_close());

	val.data.string = NULL;
	SUCCESS(cfgmgr_open("foo"));
	SUCCESS(cfgmgr_open("foonewsubclause"));
	SUCCESS(cfgmgr_getval("propsubclause", &val));
	assert_int_equal(val.type, STRING);
	if (strncmp(val.data.string, "abc", 3) == 0) {
		abc_found = true;
	} else if (strncmp(val.data.string, "def", 3) == 0) {
		def_found = true;
	} else {
		REQUIRE(false);
	}

	SUCCESS(cfgmgr_nextclause());
	SUCCESS(cfgmgr_getval("propsubclause", &val));
	assert_int_equal(val.type, STRING);
	if (strncmp(val.data.string, "abc", 3) == 0) {
		abc_found = true;
	} else if (strncmp(val.data.string, "def", 3) == 0) {
		def_found = true;
	} else {
		REQUIRE(false);
	}

	assert_true(abc_found);
	assert_true(def_found);
	SUCCESS(cfgmgr_close());
	SUCCESS(cfgmgr_close());

	cfgmgr_deinit();
}

ISC_RUN_TEST_IMPL(cfgmgr_delete) {
	cfgmgr_val_t val;

	/*
	 * foo is not found because nothing has been written in there
	 */
	INIT;
	SUCCESS(cfgmgr_newclause("foo"));
	SUCCESS(cfgmgr_close());
	NOTFOUND(cfgmgr_open("foo"));

	SUCCESS(cfgmgr_newclause("foo"));
	val = (cfgmgr_val_t){ .type = NONE };
	SUCCESS(cfgmgr_setval("prop1", &val));
	val = (cfgmgr_val_t){ .type = STRING, .data.string = "prop2val" };
	SUCCESS(cfgmgr_setval("prop2", &val));
	SUCCESS(cfgmgr_close());

	SUCCESS(cfgmgr_open("foo"));
	SUCCESS(cfgmgr_getval("prop1", &val));
	SUCCESS(cfgmgr_getval("prop2", &val));
	SUCCESS(cfgmgr_close());

	/*
	 * let's delete prop1 and add a list as prop3
	 */
	SUCCESS(cfgmgr_openrw("foo"));
	SUCCESS(cfgmgr_setval("prop1", NULL));
	val = (cfgmgr_val_t){ .type = UINT32, .data.uint32 = 123 };
	SUCCESS(cfgmgr_setnextlistval("prop3", &val));
	val = (cfgmgr_val_t){ .type = UINT32, .data.uint32 = 456 };
	SUCCESS(cfgmgr_setnextlistval("prop3", &val));
	SUCCESS(cfgmgr_close());

	SUCCESS(cfgmgr_open("foo"));
	NOTFOUND(cfgmgr_getval("prop1", &val));
	SUCCESS(cfgmgr_getval("prop2", &val));
	assert_int_equal(val.type, STRING);
	assert_string_equal(val.data.string, "prop2val");
	SUCCESS(cfgmgr_getval("prop3", &val));
	assert_int_equal(val.type, UINT32);
	assert_int_equal(val.data.uint32, 123);
	SUCCESS(cfgmgr_getnextlistval(&val));
	assert_int_equal(val.type, UINT32);
	assert_int_equal(val.data.uint32, 456);
	SUCCESS(cfgmgr_close());

	/*
	 * let's delete prop2 and prop3, the whole close disappears
	 */
	SUCCESS(cfgmgr_openrw("foo"));
	SUCCESS(cfgmgr_setval("prop2", NULL));
	SUCCESS(cfgmgr_setval("prop3", NULL));
	SUCCESS(cfgmgr_close());
	NOTFOUND(cfgmgr_open("foo"));

	/*
	 * let's now delete a clause in one go (w/o explicitely
	 * deleting its properties. Another clause exists as well, it
	 * is not deleted.
	 */
	SUCCESS(cfgmgr_newclause("foo"));
	val = (cfgmgr_val_t){ .type = NONE };
	SUCCESS(cfgmgr_setval("prop1", &val));
	val = (cfgmgr_val_t){ .type = STRING, .data.string = "prop2val" };
	SUCCESS(cfgmgr_setval("prop2", &val));
	val = (cfgmgr_val_t){ .type = UINT32, .data.uint32 = 123 };
	SUCCESS(cfgmgr_setnextlistval("prop3", &val));
	val = (cfgmgr_val_t){ .type = UINT32, .data.uint32 = 456 };
	SUCCESS(cfgmgr_setnextlistval("prop3", &val));
	SUCCESS(cfgmgr_close());

	SUCCESS(cfgmgr_newclause("fooo"));
	val = (cfgmgr_val_t){ .type = NONE };
	SUCCESS(cfgmgr_setval("prop1", &val));
	val = (cfgmgr_val_t){ .type = STRING, .data.string = "prop2val" };
	SUCCESS(cfgmgr_setval("prop2", &val));
	val = (cfgmgr_val_t){ .type = UINT32, .data.uint32 = 123 };
	SUCCESS(cfgmgr_setnextlistval("prop3", &val));
	val = (cfgmgr_val_t){ .type = UINT32, .data.uint32 = 456 };
	SUCCESS(cfgmgr_setnextlistval("prop3", &val));
	SUCCESS(cfgmgr_close());

	SUCCESS(cfgmgr_openrw("foo"));
	SUCCESS(cfgmgr_getval("prop1", &val));
	SUCCESS(cfgmgr_getval("prop2", &val));
	SUCCESS(cfgmgr_getval("prop3", &val));
	SUCCESS(cfgmgr_delclause());
	NOTFOUND(cfgmgr_open("foo"));

	SUCCESS(cfgmgr_open("fooo"));
	SUCCESS(cfgmgr_getval("prop1", &val));
	SUCCESS(cfgmgr_getval("prop2", &val));

	SUCCESS(cfgmgr_getval("prop3", &val));
	assert_int_equal(val.type, UINT32);
	assert_int_equal(val.data.uint32, 123);
	SUCCESS(cfgmgr_getnextlistval(&val));
	assert_int_equal(val.type, UINT32);
	assert_int_equal(val.data.uint32, 456);
	assert_int_equal(cfgmgr_getnextlistval(&val), ISC_R_NOMORE);
	SUCCESS(cfgmgr_close());

	cfgmgr_deinit();
}

static void *
cfgmgr_threads_worker(void *arg) {
	sem_t *sems = arg;

	/*
	 * This one open ro, so won't block
	 */
	cfgmgr_open("foo");
	sem_wait(&sems[0]);
	sem_post(&sems[1]);
	cfgmgr_close();

	return NULL;
}

ISC_RUN_TEST_IMPL(cfgmgr_threads) {
	pthread_t thread;
	sem_t sems[2];

	INIT;
	REQUIRE(sem_init(&sems[0], 0, 0) == 0);
	REQUIRE(sem_init(&sems[1], 0, 0) == 0);
	SUCCESS(cfgmgr_newclause("foo"));
	SUCCESS(cfgmgr_setval("p", &(cfgmgr_val_t){ .type = NONE }));
	cfgmgr_close();

	REQUIRE(pthread_create(&thread, 0, cfgmgr_threads_worker, &sems) == 0);
	SUCCESS(cfgmgr_openrw("foo"));
	REQUIRE(sem_post(&sems[0]) == 0);
	REQUIRE(sem_wait(&sems[1]) == 0);
	cfgmgr_close();
	REQUIRE(pthread_join(thread, NULL) == 0);

	cfgmgr_deinit();
}

ISC_TEST_LIST_START
ISC_TEST_ENTRY(cfgmgr_rw)
ISC_TEST_ENTRY(cfgmgr_override)
ISC_TEST_ENTRY(cfgmgr_rw_string)
ISC_TEST_ENTRY(cfgmgr_list)
ISC_TEST_ENTRY(cfgmgr_delete)
ISC_TEST_ENTRY(cfgmgr_repeatable_clauses)
ISC_TEST_ENTRY(cfgmgr_nested_clauses)
ISC_TEST_ENTRY(cfgmgr_threads)
ISC_TEST_ENTRY(cfgmgr_parseid)
ISC_TEST_LIST_END
ISC_TEST_MAIN
