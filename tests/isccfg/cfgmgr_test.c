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

#define TEST_DBPATH "/tmp/named-cfgmgr-lmdb"

ISC_RUN_TEST_IMPL(isc_cfgmgr_rw) {
	isc_result_t result;
	isc_cfgmgr_val_t val1;
	isc_cfgmgr_val_t val2 = { .type = ISC_CFGMGR_UNDEFINED };

	result = isc_cfgmgr_init(mctx, TEST_DBPATH);
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_cfgmgr_open("foo");
	assert_int_equal(result, ISC_R_NOTFOUND);

	result = isc_cfgmgr_newclause("foo");
	assert_int_equal(result, ISC_R_SUCCESS);

	val1 = (isc_cfgmgr_val_t){ .type = ISC_CFGMGR_UINT32,
				   .uint32 = 4058304 };
	result = isc_cfgmgr_setval("prop1", &val1);
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_cfgmgr_getval("prop1", &val2);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_int_equal(val2.type, ISC_CFGMGR_UINT32);
	assert_int_equal(val2.uint32, 4058304);

	val1 = (isc_cfgmgr_val_t){ .type = ISC_CFGMGR_NONE };
	result = isc_cfgmgr_setval("prop3", &val1);
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_cfgmgr_getval("prop3", &val2);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_int_equal(val2.type, ISC_CFGMGR_NONE);

	val1 = (isc_cfgmgr_val_t){ .type = ISC_CFGMGR_BOOLEAN,
				   .boolean = true };
	result = isc_cfgmgr_setval("prop2", &val1);
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_cfgmgr_getval("prop2", &val2);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_int_equal(val2.type, ISC_CFGMGR_BOOLEAN);
	assert_int_equal(val2.boolean, true);

	val1 = (isc_cfgmgr_val_t){ .type = ISC_CFGMGR_BOOLEAN,
				   .boolean = false };
	result = isc_cfgmgr_setval("anotherprop", &val1);
	assert_int_equal(result, ISC_R_SUCCESS);

	val2.type = ISC_CFGMGR_UNDEFINED;
	result = isc_cfgmgr_getval("anotherprop", &val2);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_int_equal(val2.type, ISC_CFGMGR_BOOLEAN);
	assert_int_equal(val2.boolean, false);

	/*
	 * Let's check and adding other properties didn't affect the
	 * ones added previously
	 */
	result = isc_cfgmgr_getval("prop3", &val2);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_int_equal(val2.type, ISC_CFGMGR_NONE);

	result = isc_cfgmgr_getval("prop1", &val2);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_int_equal(val2.type, ISC_CFGMGR_UINT32);
	assert_int_equal(val2.uint32, 4058304);

	result = isc_cfgmgr_getval("prop2", &val2);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_int_equal(val2.type, ISC_CFGMGR_BOOLEAN);
	assert_int_equal(val2.boolean, true);

	/*
	 * Non existent property - it doesn't not mutate val.
	 */
	result = isc_cfgmgr_getval("prop4", &val2);
	assert_int_equal(result, ISC_R_NOTFOUND);
	assert_int_equal(val2.type, ISC_CFGMGR_BOOLEAN);
	assert_int_equal(val2.boolean, true);

	result = isc_cfgmgr_getval("p", &val2);
	assert_int_equal(result, ISC_R_NOTFOUND);
	assert_int_equal(val2.type, ISC_CFGMGR_BOOLEAN);
	assert_int_equal(val2.boolean, true);

	result = isc_cfgmgr_close();
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_cfgmgr_open("foo");
	assert_int_equal(result, ISC_R_SUCCESS);

	/*
	 * Everything still there when closing and re-opening
	 * (read-only) the clause
	 */
	result = isc_cfgmgr_getval("prop3", &val2);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_int_equal(val2.type, ISC_CFGMGR_NONE);

	result = isc_cfgmgr_getval("prop1", &val2);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_int_equal(val2.type, ISC_CFGMGR_UINT32);
	assert_int_equal(val2.uint32, 4058304);

	result = isc_cfgmgr_getval("prop2", &val2);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_int_equal(val2.type, ISC_CFGMGR_BOOLEAN);
	assert_int_equal(val2.boolean, true);

	result = isc_cfgmgr_close();
	assert_int_equal(result, ISC_R_SUCCESS);

	/*
	 * Adding other clause (intentionally with a different name,
	 * but a common prefix in the name - those are still different
	 * clauses
	 */
	result = isc_cfgmgr_newclause("foo1");
	assert_int_equal(result, ISC_R_SUCCESS);

	val1 = (isc_cfgmgr_val_t){ .type = ISC_CFGMGR_UINT32, .uint32 = 1234 };
	result = isc_cfgmgr_setval("prop1", &val1);
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_cfgmgr_getval("prop1", &val2);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_int_equal(val2.type, ISC_CFGMGR_UINT32);
	assert_int_equal(val2.uint32, 1234);

	val1 = (isc_cfgmgr_val_t){ .type = ISC_CFGMGR_NONE };
	result = isc_cfgmgr_setval("somestuff", &val1);
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_cfgmgr_getval("somestuff", &val2);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_int_equal(val2.type, ISC_CFGMGR_NONE);

	/*
	 * Make sure we don't mixes clause properties
	 */
	result = isc_cfgmgr_getval("prop2", &val2);
	assert_int_equal(result, ISC_R_NOTFOUND);

	result = isc_cfgmgr_getval("prop3", &val2);
	assert_int_equal(result, ISC_R_NOTFOUND);

	result = isc_cfgmgr_close();
	assert_int_equal(result, ISC_R_SUCCESS);

	/*
	 * let's reopen rw this time
	 */
	result = isc_cfgmgr_openrw("foo");
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_cfgmgr_getval("prop1", &val2);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_int_equal(val2.type, ISC_CFGMGR_UINT32);
	assert_int_equal(val2.uint32, 4058304);

	result = isc_cfgmgr_getval("prop2", &val2);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_int_equal(val2.type, ISC_CFGMGR_BOOLEAN);
	assert_int_equal(val2.boolean, true);

	result = isc_cfgmgr_close();
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_cfgmgr_openrw("foo1");
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_cfgmgr_getval("prop1", &val2);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_int_equal(val2.type, ISC_CFGMGR_UINT32);
	assert_int_equal(val2.uint32, 1234);

	result = isc_cfgmgr_getval("somestuff", &val2);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_int_equal(val2.type, ISC_CFGMGR_NONE);

	/*
	 * because we used openrw, we can do that
	 */
	val1 = (isc_cfgmgr_val_t){ .type = ISC_CFGMGR_UINT32, .uint32 = 999 };
	result = isc_cfgmgr_setval("somestuff2", &val1);
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_cfgmgr_getval("somestuff2", &val2);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_int_equal(val2.type, ISC_CFGMGR_UINT32);
	assert_int_equal(val2.uint32, 999);

	result = isc_cfgmgr_close();
	assert_int_equal(result, ISC_R_SUCCESS);

	isc_cfgmgr_deinit();
}

ISC_RUN_TEST_IMPL(isc_cfgmgr_parseid) {
	isc_result_t result;
	isc_cfgmgr_val_t val;

	/*
	 * Excercise the fact that even if properties/clause names are
	 * number, this doesn't confuse the id parser (in particular,
	 * validates the usage of strtoul is correct). This also
	 * exercise the nested clause and repeatable clauses with such
	 * odd names
	 */
	result = isc_cfgmgr_init(mctx, TEST_DBPATH);
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_cfgmgr_newclause("123");
	assert_int_equal(result, ISC_R_SUCCESS);

	val = (isc_cfgmgr_val_t){ .type = ISC_CFGMGR_UINT32, .uint32 = 666666 };
	result = isc_cfgmgr_setval("123123", &val);
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_cfgmgr_newclause("456");
	assert_int_equal(result, ISC_R_SUCCESS);

	val = (isc_cfgmgr_val_t){ .type = ISC_CFGMGR_UINT32, .uint32 = 777777 };
	result = isc_cfgmgr_setval("456456", &val);
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_cfgmgr_close();
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_cfgmgr_newclause("456");
	assert_int_equal(result, ISC_R_SUCCESS);

	val = (isc_cfgmgr_val_t){ .type = ISC_CFGMGR_UINT32, .uint32 = 888888 };
	result = isc_cfgmgr_setval("456456", &val);
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_cfgmgr_close();
	assert_int_equal(result, ISC_R_SUCCESS);

	val = (isc_cfgmgr_val_t){ .type = ISC_CFGMGR_UINT32, .uint32 = 9999 };
	result = isc_cfgmgr_setval("456456", &val);
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_cfgmgr_close();
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_cfgmgr_open("123");
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_cfgmgr_getval("123123", &val);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_int_equal(val.type, ISC_CFGMGR_UINT32);
	assert_int_equal(val.uint32, 666666);

	result = isc_cfgmgr_getval("456456", &val);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_int_equal(val.type, ISC_CFGMGR_UINT32);
	assert_int_equal(val.uint32, 9999);

	/*
	 * Because of the internal randomly generated id for each
	 * clause and the lexicographical order of LMDB, we don't know
	 * which one will be first, hance this little "danse" to
	 * figure out which one we get
	 */
	bool found_777777 = false;
	bool found_888888 = false;

	result = isc_cfgmgr_open("456");
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_cfgmgr_getval("456456", &val);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_int_equal(val.type, ISC_CFGMGR_UINT32);
	if (val.uint32 == 777777) {
		found_777777 = true;
	} else if (val.uint32 == 888888) {
		found_888888 = true;
	} else {
		assert_true(false);
	}

	result = isc_cfgmgr_nextclause();
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_cfgmgr_getval("456456", &val);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_int_equal(val.type, ISC_CFGMGR_UINT32);
	if (val.uint32 == 777777) {
		found_777777 = true;
	} else if (val.uint32 == 888888) {
		found_888888 = true;
	} else {
		assert_true(false);
	}

	assert_true(found_777777);
	assert_true(found_888888);

	result = isc_cfgmgr_close();
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_cfgmgr_close();
	assert_int_equal(result, ISC_R_SUCCESS);

	isc_cfgmgr_deinit();
}

ISC_RUN_TEST_IMPL(isc_cfgmgr_override) {
	isc_result_t result;
	isc_cfgmgr_val_t val1;
	isc_cfgmgr_val_t val2;

	result = isc_cfgmgr_init(mctx, TEST_DBPATH);
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_cfgmgr_newclause("foo");
	assert_int_equal(result, ISC_R_SUCCESS);

	val1 = (isc_cfgmgr_val_t){ .type = ISC_CFGMGR_UINT32,
				   .uint32 = 4058304 };
	result = isc_cfgmgr_setval("prop1", &val1);
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_cfgmgr_getval("prop1", &val2);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_int_equal(val2.type, ISC_CFGMGR_UINT32);
	assert_int_equal(val2.uint32, 4058304);

	val1 = (isc_cfgmgr_val_t){ .type = ISC_CFGMGR_UINT32, .uint32 = 666 };
	result = isc_cfgmgr_setval("prop1", &val1);
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_cfgmgr_getval("prop1", &val2);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_int_equal(val2.type, ISC_CFGMGR_UINT32);
	assert_int_equal(val2.uint32, 666);

	val1 = (isc_cfgmgr_val_t){ .type = ISC_CFGMGR_BOOLEAN,
				   .boolean = false };
	result = isc_cfgmgr_setval("prop1", &val1);
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_cfgmgr_getval("prop1", &val2);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_int_equal(val2.type, ISC_CFGMGR_BOOLEAN);
	assert_int_equal(val2.boolean, false);

	val1 = (isc_cfgmgr_val_t){ .type = ISC_CFGMGR_BOOLEAN,
				   .boolean = true };
	result = isc_cfgmgr_setval("prop1", &val1);
	assert_int_equal(result, ISC_R_SUCCESS);

	val2.type = ISC_CFGMGR_UNDEFINED;
	result = isc_cfgmgr_getval("prop1", &val2);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_int_equal(val2.type, ISC_CFGMGR_BOOLEAN);
	assert_int_equal(val2.boolean, true);

	result = isc_cfgmgr_close();
	assert_int_equal(result, ISC_R_SUCCESS);

	isc_cfgmgr_deinit();
}

ISC_RUN_TEST_IMPL(isc_cfgmgr_rw_string) {
	isc_result_t result;
	isc_cfgmgr_val_t val1;
	isc_cfgmgr_val_t val2 = { .type = ISC_CFGMGR_UNDEFINED };

	result = isc_cfgmgr_init(mctx, TEST_DBPATH);
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_cfgmgr_newclause("foo");
	assert_int_equal(result, ISC_R_SUCCESS);

	val1 = (isc_cfgmgr_val_t){ .type = ISC_CFGMGR_STRING,
				   .string = "hey there!" };
	result = isc_cfgmgr_setval("prop1", &val1);
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_cfgmgr_getval("prop1", &val2);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_int_equal(val2.type, ISC_CFGMGR_STRING);
	assert_string_equal(val2.string, "hey there!");

	val1 = (isc_cfgmgr_val_t){
		.type = ISC_CFGMGR_STRING,
		.string = "hey there! hey there!hey there!hey there!hey "
			  "there!hey there!hey there!hey there!hey "
			  "there!hey there!hey there!hey there!hey "
			  "there!hey there!hey there!hey there!hey "
			  "there!hey there!hey there!hey there!hey "
			  "there!hey there!hey there!hey there!hey "
			  "there!hey there!hey there!hey there!hey "
			  "there!hey there!hey there!hey there!hey "
			  "there!hey there!hey there!hey there!"
	};
	result = isc_cfgmgr_setval("prop1", &val1);
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_cfgmgr_getval("prop1", &val2);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_int_equal(val2.type, ISC_CFGMGR_STRING);
	assert_string_equal(
		val2.string,
		"hey there! hey there!hey there!hey there!hey there!hey "
		"there!hey there!hey there!hey there!hey there!hey there!hey "
		"there!hey there!hey there!hey there!hey there!hey there!hey "
		"there!hey there!hey there!hey there!hey there!hey there!hey "
		"there!hey there!hey there!hey there!hey there!hey there!hey "
		"there!hey there!hey there!hey there!hey there!hey there!hey "
		"there!");

	val1 = (isc_cfgmgr_val_t){ .type = ISC_CFGMGR_STRING,
				   .string = "foobarbaz stuff" };
	result = isc_cfgmgr_setval("shorterstring", &val1);
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_cfgmgr_getval("shorterstring", &val2);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_int_equal(val2.type, ISC_CFGMGR_STRING);
	assert_string_equal(val2.string, "foobarbaz stuff");

	result = isc_cfgmgr_close();
	assert_int_equal(result, ISC_R_SUCCESS);

	isc_cfgmgr_deinit();
}

ISC_RUN_TEST_IMPL(isc_cfgmgr_list) {
	isc_result_t result;
	isc_cfgmgr_val_t val;

	result = isc_cfgmgr_init(mctx, TEST_DBPATH);
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_cfgmgr_newclause("foo");
	assert_int_equal(result, ISC_R_SUCCESS);

	val = (isc_cfgmgr_val_t){ .type = ISC_CFGMGR_STRING, .string = "lst1" };
	result = isc_cfgmgr_setnextlistval("proplist", &val);
	assert_int_equal(result, ISC_R_SUCCESS);

	val.string = "lst2";
	result = isc_cfgmgr_setnextlistval("proplist", &val);
	assert_int_equal(result, ISC_R_SUCCESS);

	val.string = "lst3";
	result = isc_cfgmgr_setnextlistval("proplist", &val);
	assert_int_equal(result, ISC_R_SUCCESS);

	val.string = "lst4";
	result = isc_cfgmgr_setnextlistval("proplist", &val);
	assert_int_equal(result, ISC_R_SUCCESS);

	val.string = "otherpropval";
	result = isc_cfgmgr_setval("otherprop", &val);
	assert_int_equal(result, ISC_R_SUCCESS);

	val.string = "zzzval";
	result = isc_cfgmgr_setval("zzz", &val);
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_cfgmgr_close();
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_cfgmgr_open("foo");
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_cfgmgr_getval("proplist", &val);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_int_equal(val.type, ISC_CFGMGR_STRING);
	assert_string_equal(val.string, "lst1");

	/*
	 * calling it again, we stick to the head
	 */
	result = isc_cfgmgr_getval("proplist", &val);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_int_equal(val.type, ISC_CFGMGR_STRING);
	assert_string_equal(val.string, "lst1");

	/*
	 * now we're moving on...
	 */
	result = isc_cfgmgr_getnextlistval(&val);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_int_equal(val.type, ISC_CFGMGR_STRING);
	assert_string_equal(val.string, "lst2");

	result = isc_cfgmgr_getnextlistval(&val);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_int_equal(val.type, ISC_CFGMGR_STRING);
	assert_string_equal(val.string, "lst3");

	result = isc_cfgmgr_getnextlistval(&val);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_int_equal(val.type, ISC_CFGMGR_STRING);
	assert_string_equal(val.string, "lst4");

	result = isc_cfgmgr_getnextlistval(&val);
	assert_int_equal(result, ISC_R_NOMORE);

	result = isc_cfgmgr_getnextlistval(&val);
	assert_int_equal(result, ISC_R_NOMORE);

	/*
	 * and start from the begining again
	 */
	result = isc_cfgmgr_getval("proplist", &val);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_int_equal(val.type, ISC_CFGMGR_STRING);
	assert_string_equal(val.string, "lst1");

	/*
	 * move on in the list but re-start again
	 */
	result = isc_cfgmgr_getnextlistval(&val);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_int_equal(val.type, ISC_CFGMGR_STRING);
	assert_string_equal(val.string, "lst2");

	result = isc_cfgmgr_getval("proplist", &val);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_int_equal(val.type, ISC_CFGMGR_STRING);
	assert_string_equal(val.string, "lst1");

	/*
	 * calling after reading a non-list property
	 */
	result = isc_cfgmgr_getval("zzz", &val);
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_cfgmgr_getnextlistval(&val);
	assert_int_equal(result, ISC_R_NOMORE);

	result = isc_cfgmgr_close();
	assert_int_equal(result, ISC_R_SUCCESS);

	isc_cfgmgr_deinit();
}

ISC_RUN_TEST_IMPL(isc_cfgmgr_repeatable_clauses) {
	isc_result_t result;
	isc_cfgmgr_val_t val1;
	isc_cfgmgr_val_t val2 = { .type = ISC_CFGMGR_UNDEFINED };

	result = isc_cfgmgr_init(mctx, TEST_DBPATH);
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_cfgmgr_newclause("view");
	assert_int_equal(result, ISC_R_SUCCESS);

	val1 = (isc_cfgmgr_val_t){ .type = ISC_CFGMGR_STRING,
				   .string = "view1 p1 val" };
	result = isc_cfgmgr_setval("p1", &val1);
	assert_int_equal(result, ISC_R_SUCCESS);

	val1 = (isc_cfgmgr_val_t){ .type = ISC_CFGMGR_BOOLEAN,
				   .boolean = false };
	result = isc_cfgmgr_setval("p2", &val1);
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_cfgmgr_close();
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_cfgmgr_newclause("view");
	assert_int_equal(result, ISC_R_SUCCESS);

	val1 = (isc_cfgmgr_val_t){ .type = ISC_CFGMGR_STRING,
				   .string = "view2 p2 val" };
	result = isc_cfgmgr_setval("p1", &val1);
	assert_int_equal(result, ISC_R_SUCCESS);

	val1 = (isc_cfgmgr_val_t){ .type = ISC_CFGMGR_BOOLEAN,
				   .boolean = true };
	result = isc_cfgmgr_setval("p2", &val1);
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_cfgmgr_close();
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_cfgmgr_open("view");
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_cfgmgr_getval("p2", &val2);
	assert_int_equal(val2.type, ISC_CFGMGR_BOOLEAN);

	val1.type = ISC_CFGMGR_UNDEFINED;
	if (val2.boolean) {
		result = isc_cfgmgr_getval("p1", &val1);
		assert_int_equal(result, ISC_R_SUCCESS);
		assert_int_equal(val1.type, ISC_CFGMGR_STRING);
		assert_string_equal(val1.string, "view2 p2 val");
	} else {
		result = isc_cfgmgr_getval("p1", &val1);
		assert_int_equal(result, ISC_R_SUCCESS);
		assert_int_equal(val1.type, ISC_CFGMGR_STRING);
		assert_string_equal(val1.string, "view1 p1 val");
	}

	result = isc_cfgmgr_nextclause();
	assert_int_equal(result, ISC_R_SUCCESS);

	val2.type = ISC_CFGMGR_UNDEFINED;
	result = isc_cfgmgr_getval("p2", &val2);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_int_equal(val2.type, ISC_CFGMGR_BOOLEAN);

	val1.type = ISC_CFGMGR_UNDEFINED;
	if (val2.boolean) {
		result = isc_cfgmgr_getval("p1", &val1);
		assert_int_equal(result, ISC_R_SUCCESS);
		assert_int_equal(val1.type, ISC_CFGMGR_STRING);
		assert_string_equal(val1.string, "view2 p2 val");
	} else {
		result = isc_cfgmgr_getval("p1", &val1);
		assert_int_equal(result, ISC_R_SUCCESS);
		assert_int_equal(val1.type, ISC_CFGMGR_STRING);
		assert_string_equal(val1.string, "view1 p1 val");
	}

	result = isc_cfgmgr_nextclause();
	assert_int_equal(result, ISC_R_NOMORE);

	result = isc_cfgmgr_close();
	assert_int_equal(result, ISC_R_SUCCESS);

	isc_cfgmgr_deinit();
}

ISC_RUN_TEST_IMPL(isc_cfgmgr_nested_clauses) {
	isc_result_t result;
	isc_cfgmgr_val_t val;

	/*
	 * Let's start by writting then reading
	 * foo { bar { baz { gee: none; }; }; };
	 */
	result = isc_cfgmgr_init(mctx, TEST_DBPATH);
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_cfgmgr_newclause("foo");
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_cfgmgr_newclause("bar");
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_cfgmgr_newclause("baz");
	assert_int_equal(result, ISC_R_SUCCESS);

	val.type = ISC_CFGMGR_NONE;
	result = isc_cfgmgr_setval("gee", &val);
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_cfgmgr_close();
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_cfgmgr_close();
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_cfgmgr_close();
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_cfgmgr_open("foo");
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_cfgmgr_open("bar");
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_cfgmgr_open("baz");
	assert_int_equal(result, ISC_R_SUCCESS);

	val.type = ISC_CFGMGR_UNDEFINED;
	result = isc_cfgmgr_getval("gee", &val);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_int_equal(val.type, ISC_CFGMGR_NONE);

	result = isc_cfgmgr_close();
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_cfgmgr_close();
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_cfgmgr_close();
	assert_int_equal(result, ISC_R_SUCCESS);

	/*
	 * then let's delete bar and add some properties in foo and
	 * another nested clause
	 */
	result = isc_cfgmgr_openrw("foo");
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_cfgmgr_open("bar");
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_cfgmgr_delclause();
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_cfgmgr_newclause("foonewsubclause");
	assert_int_equal(result, ISC_R_SUCCESS);

	val = (isc_cfgmgr_val_t){ .type = ISC_CFGMGR_STRING, .string = "abc" };
	result = isc_cfgmgr_setval("propsubclause", &val);
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_cfgmgr_close();
	assert_int_equal(result, ISC_R_SUCCESS);

	val = (isc_cfgmgr_val_t){ .type = ISC_CFGMGR_STRING,
				  .string = "propfooval" };
	result = isc_cfgmgr_setval("propfoo", &val);
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_cfgmgr_close();
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_cfgmgr_open("foo");
	assert_int_equal(result, ISC_R_SUCCESS);

	val.type = ISC_CFGMGR_UNDEFINED;
	result = isc_cfgmgr_getval("propfoo", &val);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_int_equal(val.type, ISC_CFGMGR_STRING);
	assert_string_equal(val.string, "propfooval");

	result = isc_cfgmgr_open("bar");
	assert_int_equal(result, ISC_R_NOTFOUND);

	result = isc_cfgmgr_open("foonewsubclause");
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_cfgmgr_getval("propsubclause", &val);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_int_equal(val.type, ISC_CFGMGR_STRING);
	assert_string_equal(val.string, "abc");

	result = isc_cfgmgr_close();
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_cfgmgr_close();
	assert_int_equal(result, ISC_R_SUCCESS);

	/*
	 * Let's mix nested and repeatable clauses
	 */
	result = isc_cfgmgr_openrw("foo");
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_cfgmgr_newclause("foonewsubclause");
	assert_int_equal(result, ISC_R_SUCCESS);

	bool abc_found = false;
	bool def_found = false;

	val = (isc_cfgmgr_val_t){ .type = ISC_CFGMGR_STRING, .string = "def" };
	result = isc_cfgmgr_setval("propsubclause", &val);
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_cfgmgr_close();
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_cfgmgr_close();
	assert_int_equal(result, ISC_R_SUCCESS);

	val = (isc_cfgmgr_val_t){ .type = ISC_CFGMGR_UNDEFINED, .string = NULL };
	result = isc_cfgmgr_open("foo");
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_cfgmgr_open("foonewsubclause");
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_cfgmgr_getval("propsubclause", &val);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_int_equal(val.type, ISC_CFGMGR_STRING);
	if (strncmp(val.string, "abc", 3) == 0) {
		abc_found = true;
	} else if (strncmp(val.string, "def", 3) == 0) {
		def_found = true;
	} else {
		assert_true(false);
	}

	result = isc_cfgmgr_nextclause();
	assert_int_equal(result, ISC_R_SUCCESS);

	val = (isc_cfgmgr_val_t){ .type = ISC_CFGMGR_UNDEFINED, .string = NULL };
	result = isc_cfgmgr_getval("propsubclause", &val);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_int_equal(val.type, ISC_CFGMGR_STRING);
	if (strncmp(val.string, "abc", 3) == 0) {
		abc_found = true;
	} else if (strncmp(val.string, "def", 3) == 0) {
		def_found = true;
	} else {
		assert_true(false);
	}

	assert_true(abc_found);
	assert_true(def_found);

	result = isc_cfgmgr_close();
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_cfgmgr_close();
	assert_int_equal(result, ISC_R_SUCCESS);

	isc_cfgmgr_deinit();
}

ISC_RUN_TEST_IMPL(isc_cfgmgr_delete) {
	isc_result_t result;
	isc_cfgmgr_val_t val;

	result = isc_cfgmgr_init(mctx, TEST_DBPATH);
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_cfgmgr_newclause("foo");
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_cfgmgr_close();
	assert_int_equal(result, ISC_R_SUCCESS);

	/*
	 * foo is not found because properties has been written in the
	 * clause.
	 */
	result = isc_cfgmgr_open("foo");
	assert_int_equal(result, ISC_R_NOTFOUND);

	result = isc_cfgmgr_newclause("foo");
	assert_int_equal(result, ISC_R_SUCCESS);

	val = (isc_cfgmgr_val_t){ .type = ISC_CFGMGR_NONE };
	result = isc_cfgmgr_setval("prop1", &val);
	assert_int_equal(result, ISC_R_SUCCESS);

	val = (isc_cfgmgr_val_t){ .type = ISC_CFGMGR_STRING,
				  .string = "prop2val" };
	result = isc_cfgmgr_setval("prop2", &val);
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_cfgmgr_close();
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_cfgmgr_open("foo");
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_cfgmgr_getval("prop1", &val);
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_cfgmgr_getval("prop2", &val);
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_cfgmgr_close();
	assert_int_equal(result, ISC_R_SUCCESS);

	/*
	 * let's delete prop1 and add a list as prop3
	 */
	result = isc_cfgmgr_openrw("foo");
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_cfgmgr_setval("prop1", NULL);
	assert_int_equal(result, ISC_R_SUCCESS);

	val = (isc_cfgmgr_val_t){ .type = ISC_CFGMGR_UINT32, .uint32 = 123 };
	result = isc_cfgmgr_setnextlistval("prop3", &val);
	assert_int_equal(result, ISC_R_SUCCESS);

	val = (isc_cfgmgr_val_t){ .type = ISC_CFGMGR_UINT32, .uint32 = 456 };
	result = isc_cfgmgr_setnextlistval("prop3", &val);
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_cfgmgr_close();
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_cfgmgr_open("foo");
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_cfgmgr_getval("prop1", &val);
	assert_int_equal(result, ISC_R_NOTFOUND);

	result = isc_cfgmgr_getval("prop2", &val);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_int_equal(val.type, ISC_CFGMGR_STRING);
	assert_string_equal(val.string, "prop2val");

	result = isc_cfgmgr_getval("prop3", &val);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_int_equal(val.type, ISC_CFGMGR_UINT32);
	assert_int_equal(val.uint32, 123);

	result = isc_cfgmgr_getnextlistval(&val);
	assert_int_equal(result, ISC_R_SUCCESS);
	;
	assert_int_equal(val.type, ISC_CFGMGR_UINT32);
	assert_int_equal(val.uint32, 456);

	result = isc_cfgmgr_close();
	assert_int_equal(result, ISC_R_SUCCESS);

	/*
	 * let's delete prop2 and prop3, the whole close disappears
	 */
	result = isc_cfgmgr_openrw("foo");
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_cfgmgr_setval("prop2", NULL);
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_cfgmgr_setval("prop3", NULL);
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_cfgmgr_close();
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_cfgmgr_open("foo");
	assert_int_equal(result, ISC_R_NOTFOUND);

	/*
	 * let's now delete a clause in one go (w/o explicitely
	 * deleting its properties. Another clause exists as well, it
	 * is not deleted.
	 */
	result = isc_cfgmgr_newclause("foo");
	assert_int_equal(result, ISC_R_SUCCESS);

	val = (isc_cfgmgr_val_t){ .type = ISC_CFGMGR_NONE };
	result = isc_cfgmgr_setval("prop1", &val);
	assert_int_equal(result, ISC_R_SUCCESS);

	val = (isc_cfgmgr_val_t){ .type = ISC_CFGMGR_STRING,
				  .string = "prop2val" };
	result = isc_cfgmgr_setval("prop2", &val);
	assert_int_equal(result, ISC_R_SUCCESS);

	val = (isc_cfgmgr_val_t){ .type = ISC_CFGMGR_UINT32, .uint32 = 123 };
	result = isc_cfgmgr_setnextlistval("prop3", &val);
	assert_int_equal(result, ISC_R_SUCCESS);

	val = (isc_cfgmgr_val_t){ .type = ISC_CFGMGR_UINT32, .uint32 = 456 };
	result = isc_cfgmgr_setnextlistval("prop3", &val);
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_cfgmgr_close();
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_cfgmgr_newclause("fooo");
	assert_int_equal(result, ISC_R_SUCCESS);

	val = (isc_cfgmgr_val_t){ .type = ISC_CFGMGR_NONE };
	result = isc_cfgmgr_setval("prop1", &val);
	assert_int_equal(result, ISC_R_SUCCESS);

	val = (isc_cfgmgr_val_t){ .type = ISC_CFGMGR_STRING,
				  .string = "prop2val" };
	result = isc_cfgmgr_setval("prop2", &val);
	assert_int_equal(result, ISC_R_SUCCESS);

	val = (isc_cfgmgr_val_t){ .type = ISC_CFGMGR_UINT32, .uint32 = 123 };
	result = isc_cfgmgr_setnextlistval("prop3", &val);
	assert_int_equal(result, ISC_R_SUCCESS);

	val = (isc_cfgmgr_val_t){ .type = ISC_CFGMGR_UINT32, .uint32 = 456 };
	result = isc_cfgmgr_setnextlistval("prop3", &val);
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_cfgmgr_close();
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_cfgmgr_openrw("foo");
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_cfgmgr_getval("prop1", &val);
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_cfgmgr_getval("prop2", &val);
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_cfgmgr_getval("prop3", &val);
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_cfgmgr_delclause();
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_cfgmgr_open("foo");
	assert_int_equal(result, ISC_R_NOTFOUND);

	result = isc_cfgmgr_open("fooo");
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_cfgmgr_getval("prop1", &val);
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_cfgmgr_getval("prop2", &val);
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_cfgmgr_getval("prop3", &val);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_int_equal(val.type, ISC_CFGMGR_UINT32);
	assert_int_equal(val.uint32, 123);

	result = isc_cfgmgr_getnextlistval(&val);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_int_equal(val.type, ISC_CFGMGR_UINT32);
	assert_int_equal(val.uint32, 456);

	result = isc_cfgmgr_getnextlistval(&val);
	assert_int_equal(result, ISC_R_NOMORE);

	result = isc_cfgmgr_close();
	assert_int_equal(result, ISC_R_SUCCESS);

	isc_cfgmgr_deinit();
}

static void *
cfgmgr_threads_worker(void *arg) {
	isc_result_t result;
	sem_t *sems = arg;

	/*
	 * This one open ro, so won't block
	 */
	result = isc_cfgmgr_open("foo");
	assert_int_equal(result, ISC_R_SUCCESS);

	sem_wait(&sems[0]);
	sem_post(&sems[1]);

	result = isc_cfgmgr_close();
	assert_int_equal(result, ISC_R_SUCCESS);

	return NULL;
}

ISC_RUN_TEST_IMPL(isc_cfgmgr_threads) {
	isc_result_t result;
	pthread_t thread;
	sem_t sems[2];

	result = isc_cfgmgr_init(mctx, TEST_DBPATH);
	assert_int_equal(result, ISC_R_SUCCESS);

	REQUIRE(sem_init(&sems[0], 0, 0) == 0);
	REQUIRE(sem_init(&sems[1], 0, 0) == 0);

	result = isc_cfgmgr_newclause("foo");
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_cfgmgr_setval(
		"p", &(isc_cfgmgr_val_t){ .type = ISC_CFGMGR_NONE });
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_cfgmgr_close();
	assert_int_equal(result, ISC_R_SUCCESS);

	REQUIRE(pthread_create(&thread, 0, cfgmgr_threads_worker, &sems) == 0);

	result = isc_cfgmgr_openrw("foo");
	assert_int_equal(result, ISC_R_SUCCESS);

	REQUIRE(sem_post(&sems[0]) == 0);
	REQUIRE(sem_wait(&sems[1]) == 0);

	result = isc_cfgmgr_close();
	assert_int_equal(result, ISC_R_SUCCESS);

	REQUIRE(pthread_join(thread, NULL) == 0);

	isc_cfgmgr_deinit();
}

ISC_TEST_LIST_START
ISC_TEST_ENTRY(isc_cfgmgr_rw)
ISC_TEST_ENTRY(isc_cfgmgr_override)
ISC_TEST_ENTRY(isc_cfgmgr_rw_string)
ISC_TEST_ENTRY(isc_cfgmgr_list)
ISC_TEST_ENTRY(isc_cfgmgr_delete)
ISC_TEST_ENTRY(isc_cfgmgr_repeatable_clauses)
ISC_TEST_ENTRY(isc_cfgmgr_nested_clauses)
ISC_TEST_ENTRY(isc_cfgmgr_threads)
ISC_TEST_ENTRY(isc_cfgmgr_parseid)
ISC_TEST_LIST_END
ISC_TEST_MAIN
