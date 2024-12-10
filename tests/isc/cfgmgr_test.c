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

#include <isc/cfgmgr.h>

#include "../../lib/isc/cfgmgr.c"

#include <tests/isc.h>

#define TEST_DBPATH "/tmp/named-cfgmgr-lmdb"

static void
cfgmgrtest_running_ready(void) {
	isc_result_t result;

	result = isc_cfgmgr_init(mctx, TEST_DBPATH);
	assert_int_equal(result, ISC_R_SUCCESS);

	isc_cfgmgr_mode(ISC_CFGMGR_MODEBUILTIN);
	result = isc_cfgmgr_rwtxn();
	assert_int_equal(result, ISC_R_SUCCESS);
	result = isc_cfgmgr_commit();
	assert_int_equal(result, ISC_R_SUCCESS);

	isc_cfgmgr_mode(ISC_CFGMGR_MODEUSER);
	result = isc_cfgmgr_rwtxn();
	assert_int_equal(result, ISC_R_SUCCESS);
	result = isc_cfgmgr_commit();
	assert_int_equal(result, ISC_R_SUCCESS);

	isc_cfgmgr_mode(ISC_CFGMGR_MODERUNNING);
}

ISC_RUN_TEST_IMPL(isc_cfgmgr_assertions) {
	isc_cfgmgr_val_t dummyval;
	isc_result_t result;

	/*
	 * Invalid cfgmgr initialization
	 */
	expect_assert_failure(isc_cfgmgr_init(NULL, TEST_DBPATH));
	expect_assert_failure(isc_cfgmgr_init(mctx, NULL));
	expect_assert_failure(isc_cfgmgr_read("/foo", &dummyval));
	expect_assert_failure(isc_cfgmgr_write("/foo", &dummyval));
	expect_assert_failure(isc_cfgmgr_delete("/foo/"));
	expect_assert_failure(isc_cfgmgr_txn());
	expect_assert_failure(isc_cfgmgr_closetxn());
	expect_assert_failure(isc_cfgmgr_rwtxn());
	expect_assert_failure(isc_cfgmgr_commit());
	expect_assert_failure(isc_cfgmgr_rollback());
	expect_assert_failure(isc_cfgmgr_deinit());

	/*
	 * operations which must be used under transaction
	 */
	(void)isc_cfgmgr_init(mctx, TEST_DBPATH);
	expect_assert_failure(isc_cfgmgr_read("/foo", &dummyval));
	expect_assert_failure(isc_cfgmgr_write("/foo", &dummyval));
	expect_assert_failure(isc_cfgmgr_delete("/foo/"));
	expect_assert_failure(isc_cfgmgr_commit());
	expect_assert_failure(isc_cfgmgr_rollback());

	/*
	 * Opening a transaction on a running mode (default) won't work until
	 * builtin and user mode has been set up first.
	 */
	expect_assert_failure(isc_cfgmgr_txn());
	expect_assert_failure(isc_cfgmgr_rwtxn());

	/*
	 * Similarly, setting mode running or user won't work until the builtin
	 * is first initialized.
	 */
	expect_assert_failure(isc_cfgmgr_mode(ISC_CFGMGR_MODERUNNING));
	expect_assert_failure(isc_cfgmgr_mode(ISC_CFGMGR_MODEUSER));

	/*
	 * ... And builtin mode can be only open as rwtxn, as there is nothing
	 * to be read yet!
	 */
	isc_cfgmgr_mode(ISC_CFGMGR_MODEBUILTIN);
	expect_assert_failure(isc_cfgmgr_txn());

	isc_cfgmgr_mode(ISC_CFGMGR_MODEBUILTIN);
	result = isc_cfgmgr_rwtxn();
	assert_int_equal(result, ISC_R_SUCCESS);

	/*
	 * but if a rollback is done, it's back to square 0
	 */
	isc_cfgmgr_rollback();
	expect_assert_failure(isc_cfgmgr_mode(ISC_CFGMGR_MODERUNNING));
	expect_assert_failure(isc_cfgmgr_mode(ISC_CFGMGR_MODEUSER));
	expect_assert_failure(isc_cfgmgr_txn());

	/*
	 * So now let's initialize builtin mode for real.
	 */
	isc_cfgmgr_mode(ISC_CFGMGR_MODEBUILTIN);
	result = isc_cfgmgr_rwtxn();
	assert_int_equal(result, ISC_R_SUCCESS);
	result = isc_cfgmgr_commit();
	assert_int_equal(result, ISC_R_SUCCESS);

	/*
	 * Now builtin gets initialized, and it's possible to move to user mode
	 * (but still not running). It's also not possible to open a rw
	 * transaction in builtin anymore.
	 */
	expect_assert_failure(isc_cfgmgr_rwtxn());
	isc_cfgmgr_txn();
	isc_cfgmgr_closetxn();

	expect_assert_failure(isc_cfgmgr_mode(ISC_CFGMGR_MODERUNNING));
	isc_cfgmgr_mode(ISC_CFGMGR_MODEBUILTIN);
	isc_cfgmgr_mode(ISC_CFGMGR_MODEUSER);
	expect_assert_failure(isc_cfgmgr_txn());

	result = isc_cfgmgr_rwtxn();
	assert_int_equal(result, ISC_R_SUCCESS);
	result = isc_cfgmgr_commit();
	assert_int_equal(result, ISC_R_SUCCESS);

	/*
	 * Now user mode is initialized. Running mode can be used. (And it's
	 * still possible to open read only txn on builtin or user)
	 */
	isc_cfgmgr_mode(ISC_CFGMGR_MODEUSER);
	isc_cfgmgr_txn();
	isc_cfgmgr_closetxn();
	expect_assert_failure(isc_cfgmgr_rwtxn());

	isc_cfgmgr_mode(ISC_CFGMGR_MODEBUILTIN);
	isc_cfgmgr_txn();
	isc_cfgmgr_closetxn();
	expect_assert_failure(isc_cfgmgr_rwtxn());

	isc_cfgmgr_mode(ISC_CFGMGR_MODERUNNING);
	isc_cfgmgr_txn();
	isc_cfgmgr_closetxn();
	result = isc_cfgmgr_rwtxn();
	assert_int_equal(result, ISC_R_SUCCESS);
	result = isc_cfgmgr_commit();
	assert_int_equal(result, ISC_R_SUCCESS);

	isc_cfgmgr_deinit();

	/*
	 * can't write on read-only transaction
	 */
	cfgmgrtest_running_ready();

	result = isc_cfgmgr_rwtxn();
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_cfgmgr_write(
		"/foo/bar", &(isc_cfgmgr_val_t){ .type = ISC_CFGMGR_NONE });
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_cfgmgr_write(
		"/foo/subfoo/subfoobar",
		&(isc_cfgmgr_val_t){ .type = ISC_CFGMGR_NONE });
	assert_int_equal(result, ISC_R_SUCCESS);

	assert_int_equal(isc_cfgmgr_commit(), ISC_R_SUCCESS);

	assert_int_equal(isc_cfgmgr_txn(), ISC_R_SUCCESS);
	expect_assert_failure(isc_cfgmgr_write(
		"/foo/bar", &(isc_cfgmgr_val_t){ .type = ISC_CFGMGR_NONE }));
	expect_assert_failure(isc_cfgmgr_write(
		"/foo/baz", &(isc_cfgmgr_val_t){ .type = ISC_CFGMGR_NONE }));

	expect_assert_failure(isc_cfgmgr_write(
		"/foo/subfoo/subfoobar",
		&(isc_cfgmgr_val_t){ .type = ISC_CFGMGR_NONE }));

	/*
	 * _commit and _rollback are reserved for rw txn
	 */
	expect_assert_failure(isc_cfgmgr_commit());
	expect_assert_failure(isc_cfgmgr_rollback());
	isc_cfgmgr_closetxn();

	isc_cfgmgr_deinit();

	/*
	 * reading values parameters
	 */
	cfgmgrtest_running_ready();

	result = isc_cfgmgr_rwtxn();
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_cfgmgr_write(
		"/foo/bar", &(isc_cfgmgr_val_t){ .type = ISC_CFGMGR_NONE });
	assert_int_equal(result, ISC_R_SUCCESS);
	expect_assert_failure(isc_cfgmgr_read("bar", NULL));

	/*
	 * _closetxn is reserved for rotxn
	 */
	expect_assert_failure(isc_cfgmgr_closetxn());
	result = isc_cfgmgr_commit();
	assert_int_equal(result, ISC_R_SUCCESS);

	isc_cfgmgr_deinit();
	expect_assert_failure(isc_cfgmgr_deinit());
}

ISC_RUN_TEST_IMPL(isc_cfgmgr_rw) {
	isc_result_t result;
	isc_cfgmgr_val_t val1;
	isc_cfgmgr_val_t val2 = { .type = ISC_CFGMGR_UNDEFINED };

	cfgmgrtest_running_ready();

	result = isc_cfgmgr_rwtxn();
	assert_int_equal(result, ISC_R_SUCCESS);

	val1 = (isc_cfgmgr_val_t){ .type = ISC_CFGMGR_UINT32,
				   .uint32 = 4058304 };
	result = isc_cfgmgr_write("/foo/prop1", &val1);
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_cfgmgr_read("/foo/prop1", &val2);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_int_equal(val2.type, ISC_CFGMGR_UINT32);
	assert_int_equal(val2.uint32, 4058304);

	val1 = (isc_cfgmgr_val_t){ .type = ISC_CFGMGR_NONE };
	result = isc_cfgmgr_write("/foo/prop3", &val1);
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_cfgmgr_read("/foo/prop3", &val2);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_int_equal(val2.type, ISC_CFGMGR_NONE);

	val1 = (isc_cfgmgr_val_t){ .type = ISC_CFGMGR_BOOLEAN,
				   .boolean = true };
	result = isc_cfgmgr_write("/foo/prop2", &val1);
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_cfgmgr_read("/foo/prop2", &val2);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_int_equal(val2.type, ISC_CFGMGR_BOOLEAN);
	assert_int_equal(val2.boolean, true);

	val1 = (isc_cfgmgr_val_t){ .type = ISC_CFGMGR_BOOLEAN,
				   .boolean = false };
	result = isc_cfgmgr_write("/foo/anotherprop", &val1);
	assert_int_equal(result, ISC_R_SUCCESS);

	val2.type = ISC_CFGMGR_UNDEFINED;
	result = isc_cfgmgr_read("/foo/anotherprop", &val2);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_int_equal(val2.type, ISC_CFGMGR_BOOLEAN);
	assert_int_equal(val2.boolean, false);

	/*
	 * Let's check and adding other properties didn't affect the
	 * ones added previously
	 */
	result = isc_cfgmgr_read("/foo/prop3", &val2);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_int_equal(val2.type, ISC_CFGMGR_NONE);

	result = isc_cfgmgr_read("/foo/prop1", &val2);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_int_equal(val2.type, ISC_CFGMGR_UINT32);
	assert_int_equal(val2.uint32, 4058304);

	result = isc_cfgmgr_read("/foo/prop2", &val2);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_int_equal(val2.type, ISC_CFGMGR_BOOLEAN);
	assert_int_equal(val2.boolean, true);

	/*
	 * Non existent property - it doesn't not mutate val.
	 */
	result = isc_cfgmgr_read("/foo/prop4", &val2);
	assert_int_equal(result, ISC_R_NOTFOUND);
	assert_int_equal(val2.type, ISC_CFGMGR_BOOLEAN);
	assert_int_equal(val2.boolean, true);

	result = isc_cfgmgr_read("/foo/p", &val2);
	assert_int_equal(result, ISC_R_NOTFOUND);
	assert_int_equal(val2.type, ISC_CFGMGR_BOOLEAN);
	assert_int_equal(val2.boolean, true);

	result = isc_cfgmgr_commit();
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_cfgmgr_txn();
	assert_int_equal(result, ISC_R_SUCCESS);

	/*
	 * Everything still there when closing and re-opening
	 * (read-only) the node
	 */
	result = isc_cfgmgr_read("/foo/prop3", &val2);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_int_equal(val2.type, ISC_CFGMGR_NONE);

	result = isc_cfgmgr_read("/foo/prop1", &val2);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_int_equal(val2.type, ISC_CFGMGR_UINT32);
	assert_int_equal(val2.uint32, 4058304);

	result = isc_cfgmgr_read("/foo/prop2", &val2);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_int_equal(val2.type, ISC_CFGMGR_BOOLEAN);
	assert_int_equal(val2.boolean, true);

	isc_cfgmgr_closetxn();

	/*
	 * Adding other node, intentionally with a different name,
	 * but a common prefix in the name, those are still different
	 * nodes
	 */
	result = isc_cfgmgr_rwtxn();
	assert_int_equal(result, ISC_R_SUCCESS);

	val1 = (isc_cfgmgr_val_t){ .type = ISC_CFGMGR_UINT32, .uint32 = 1234 };
	result = isc_cfgmgr_write("/foo1/prop1", &val1);
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_cfgmgr_read("/foo1/prop1", &val2);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_int_equal(val2.type, ISC_CFGMGR_UINT32);
	assert_int_equal(val2.uint32, 1234);

	val1 = (isc_cfgmgr_val_t){ .type = ISC_CFGMGR_NONE };
	result = isc_cfgmgr_write("/foo1/somestuff", &val1);
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_cfgmgr_read("/foo1/somestuff", &val2);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_int_equal(val2.type, ISC_CFGMGR_NONE);

	/*
	 * Make sure we don't mixes nodes properties
	 */
	result = isc_cfgmgr_read("/foo1/prop2", &val2);
	assert_int_equal(result, ISC_R_NOTFOUND);

	result = isc_cfgmgr_read("/foo1/prop3", &val2);
	assert_int_equal(result, ISC_R_NOTFOUND);

	result = isc_cfgmgr_commit();
	assert_int_equal(result, ISC_R_SUCCESS);

	/*
	 * let's reopen rw this time
	 */
	result = isc_cfgmgr_rwtxn();
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_cfgmgr_read("/foo/prop1", &val2);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_int_equal(val2.type, ISC_CFGMGR_UINT32);
	assert_int_equal(val2.uint32, 4058304);

	result = isc_cfgmgr_read("/foo/prop2", &val2);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_int_equal(val2.type, ISC_CFGMGR_BOOLEAN);
	assert_int_equal(val2.boolean, true);

	result = isc_cfgmgr_commit();
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_cfgmgr_rwtxn();
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_cfgmgr_read("/foo1/prop1", &val2);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_int_equal(val2.type, ISC_CFGMGR_UINT32);
	assert_int_equal(val2.uint32, 1234);

	result = isc_cfgmgr_read("/foo1/somestuff", &val2);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_int_equal(val2.type, ISC_CFGMGR_NONE);

	/*
	 * because we used openrw, we can do that
	 */
	val1 = (isc_cfgmgr_val_t){ .type = ISC_CFGMGR_UINT32, .uint32 = 999 };
	result = isc_cfgmgr_write("/foo1/somestuff2", &val1);
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_cfgmgr_read("/foo1/somestuff2", &val2);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_int_equal(val2.type, ISC_CFGMGR_UINT32);
	assert_int_equal(val2.uint32, 999);

	result = isc_cfgmgr_commit();
	assert_int_equal(result, ISC_R_SUCCESS);

	/*
	 * removing a non-existent value returns ISC_R_NOTFOUND
	 */
	result = isc_cfgmgr_rwtxn();
	assert_int_equal(result, ISC_R_SUCCESS);
	result = isc_cfgmgr_delete("/i-do-not-exists/");
	assert_int_equal(result, ISC_R_NOTFOUND);
	result = isc_cfgmgr_write("/i-do-not-exists-either", NULL);
	assert_int_equal(result, ISC_R_NOTFOUND);
	isc_cfgmgr_rollback();

	/*
	 * read/write/del API path must be absolutes
	 */
	result = isc_cfgmgr_rwtxn();
	assert_int_equal(result, ISC_R_SUCCESS);
	expect_assert_failure(isc_cfgmgr_write("foo/bar", &val2));
	expect_assert_failure(isc_cfgmgr_read("foo/bar", &val2));
	expect_assert_failure(isc_cfgmgr_delete("foo/"));
	expect_assert_failure(isc_cfgmgr_delete("/foo"));
	isc_cfgmgr_rollback();

	/*
	 * No errors, so empty last error message
	 */
	assert_string_equal(isc_cfgmgr_lasterror(), "");

	isc_cfgmgr_deinit();
}

ISC_RUN_TEST_IMPL(isc_cfgmgr_rollback) {
	isc_cfgmgr_val_t val;

	cfgmgrtest_running_ready();

	assert_int_equal(isc_cfgmgr_rwtxn(), ISC_R_SUCCESS);
	val = (isc_cfgmgr_val_t){ .type = ISC_CFGMGR_UINT32, .uint32 = 42 };
	assert_int_equal(isc_cfgmgr_write("/foo/prop", &val), ISC_R_SUCCESS);
	assert_int_equal(isc_cfgmgr_commit(), ISC_R_SUCCESS);

	assert_int_equal(isc_cfgmgr_rwtxn(), ISC_R_SUCCESS);
	val = (isc_cfgmgr_val_t){ .type = ISC_CFGMGR_UINT32, .uint32 = 9999 };
	assert_int_equal(isc_cfgmgr_write("/foo/prop", &val), ISC_R_SUCCESS);
	val.uint32 = 0;
	assert_int_equal(isc_cfgmgr_read("/foo/prop", &val), ISC_R_SUCCESS);
	assert_int_equal(val.type, ISC_CFGMGR_UINT32);
	/*
	 * value is 9999 as newly updated in this transaction
	 */
	assert_int_equal(val.uint32, 9999);
	isc_cfgmgr_rollback();

	assert_int_equal(isc_cfgmgr_txn(), ISC_R_SUCCESS);
	assert_int_equal(isc_cfgmgr_read("/foo/prop", &val), ISC_R_SUCCESS);
	assert_int_equal(val.type, ISC_CFGMGR_UINT32);
	/*
	 * value is not 9999 anymore, because previous transaction been reverted
	 */
	assert_int_equal(val.uint32, 42);
	isc_cfgmgr_closetxn();

	isc_cfgmgr_deinit();
}

ISC_RUN_TEST_IMPL(isc_cfgmgr_override) {
	isc_result_t result;
	isc_cfgmgr_val_t val1;
	isc_cfgmgr_val_t val2;

	cfgmgrtest_running_ready();

	result = isc_cfgmgr_rwtxn();
	assert_int_equal(result, ISC_R_SUCCESS);

	val1 = (isc_cfgmgr_val_t){ .type = ISC_CFGMGR_UINT32,
				   .uint32 = 4058304 };
	result = isc_cfgmgr_write("/foo/prop1", &val1);
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_cfgmgr_read("/foo/prop1", &val2);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_int_equal(val2.type, ISC_CFGMGR_UINT32);
	assert_int_equal(val2.uint32, 4058304);

	val1 = (isc_cfgmgr_val_t){ .type = ISC_CFGMGR_UINT32, .uint32 = 666 };
	result = isc_cfgmgr_write("/foo/prop1", &val1);
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_cfgmgr_read("/foo/prop1", &val2);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_int_equal(val2.type, ISC_CFGMGR_UINT32);
	assert_int_equal(val2.uint32, 666);

	val1 = (isc_cfgmgr_val_t){ .type = ISC_CFGMGR_BOOLEAN,
				   .boolean = false };
	result = isc_cfgmgr_write("/foo/prop1", &val1);
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_cfgmgr_read("/foo/prop1", &val2);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_int_equal(val2.type, ISC_CFGMGR_BOOLEAN);
	assert_int_equal(val2.boolean, false);

	val1 = (isc_cfgmgr_val_t){ .type = ISC_CFGMGR_BOOLEAN,
				   .boolean = true };
	result = isc_cfgmgr_write("/foo/prop1", &val1);
	assert_int_equal(result, ISC_R_SUCCESS);

	val2.type = ISC_CFGMGR_UNDEFINED;
	result = isc_cfgmgr_read("/foo/prop1", &val2);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_int_equal(val2.type, ISC_CFGMGR_BOOLEAN);
	assert_int_equal(val2.boolean, true);

	result = isc_cfgmgr_commit();
	assert_int_equal(result, ISC_R_SUCCESS);

	isc_cfgmgr_deinit();
}

ISC_RUN_TEST_IMPL(isc_cfgmgr_rw_string) {
	isc_result_t result;
	isc_cfgmgr_val_t val1;
	isc_cfgmgr_val_t val2 = { .type = ISC_CFGMGR_UNDEFINED };

	cfgmgrtest_running_ready();

	result = isc_cfgmgr_rwtxn();
	assert_int_equal(result, ISC_R_SUCCESS);

	val1 = (isc_cfgmgr_val_t){ .type = ISC_CFGMGR_STRING,
				   .string = "hey there!" };
	result = isc_cfgmgr_write("/foo/prop1", &val1);
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_cfgmgr_read("/foo/prop1", &val2);
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
	result = isc_cfgmgr_write("/foo/prop1", &val1);
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_cfgmgr_read("/foo/prop1", &val2);
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
	result = isc_cfgmgr_write("/foo/shorterstring", &val1);
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_cfgmgr_read("/foo/shorterstring", &val2);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_int_equal(val2.type, ISC_CFGMGR_STRING);
	assert_string_equal(val2.string, "foobarbaz stuff");

	result = isc_cfgmgr_commit();
	assert_int_equal(result, ISC_R_SUCCESS);

	isc_cfgmgr_deinit();
}

static void
cfgmgrtest_ref_attach(void *ptr) {
	char *str = ptr;
	size_t len = strlen(str);

	strcpy(str + len, "-attached");
}

static void
cfgmgrtest_ref_detach(void *ptr) {
	char *str = ptr;
	size_t len = strlen(str);

	strcpy(str + len, "-detached");
}

ISC_RUN_TEST_IMPL(isc_cfgmgr_rw_ptr) {
	isc_result_t result;
	isc_cfgmgr_val_t val;
	char *ptr = NULL;

	ptr = isc_mem_get(mctx, 32);
	sprintf(ptr, "foobarbaz");

	cfgmgrtest_running_ready();

	/*
	 * Add a reference (so it's immediately attached) but the transaction
	 * gets rolled back so the reference is detached after the rollback.
	 */
	result = isc_cfgmgr_rwtxn();
	assert_int_equal(result, ISC_R_SUCCESS);

	val = (isc_cfgmgr_val_t){ .type = ISC_CFGMGR_REF,
				  .ptr = ptr,
				  .attach = cfgmgrtest_ref_attach,
				  .detach = cfgmgrtest_ref_detach };
	result = isc_cfgmgr_write("/foo/thestraddr", &val);
	assert_int_equal(result, ISC_R_SUCCESS);

	assert_string_equal(ptr, "foobarbaz-attached");
	isc_cfgmgr_rollback();
	assert_string_equal(ptr, "foobarbaz-attached-detached");

	/*
	 * Add a reference and the transaction is commited, so the reference is
	 * attached and not detached.
	 */
	strcpy(ptr, "foobarbaz");
	result = isc_cfgmgr_rwtxn();
	assert_int_equal(result, ISC_R_SUCCESS);

	val = (isc_cfgmgr_val_t){ .type = ISC_CFGMGR_REF,
				  .ptr = ptr,
				  .attach = cfgmgrtest_ref_attach,
				  .detach = cfgmgrtest_ref_detach };
	result = isc_cfgmgr_write("/foo/thestraddr", &val);
	assert_int_equal(result, ISC_R_SUCCESS);

	assert_string_equal(ptr, "foobarbaz-attached");
	isc_cfgmgr_commit();
	assert_string_equal(ptr, "foobarbaz-attached");

	val = (isc_cfgmgr_val_t){};
	result = isc_cfgmgr_txn();
	assert_int_equal(result, ISC_R_SUCCESS);
	result = isc_cfgmgr_read("/foo/thestraddr", &val);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_int_equal(val.type, ISC_CFGMGR_REF);
	assert_ptr_equal(val.ptr, ptr);
	isc_cfgmgr_closetxn();

	/*
	 * reference get removed but transaction rolledback, it's not detached
	 */
	strcpy(ptr, "foobarbaz");
	result = isc_cfgmgr_rwtxn();
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_cfgmgr_write("/foo/thestraddr", NULL);
	assert_int_equal(result, ISC_R_SUCCESS);

	assert_string_equal(ptr, "foobarbaz");
	isc_cfgmgr_rollback();
	assert_string_equal(ptr, "foobarbaz");

	/*
	 * reference get removed and transaction commit with success, it's
	 * detached
	 */
	strcpy(ptr, "foobarbaz");
	result = isc_cfgmgr_rwtxn();
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_cfgmgr_write("/foo/thestraddr", NULL);
	assert_int_equal(result, ISC_R_SUCCESS);

	assert_string_equal(ptr, "foobarbaz");
	isc_cfgmgr_commit();
	assert_string_equal(ptr, "foobarbaz-detached");

	/*
	 * reference is added then replaced, it's then attached but immediately
	 * detached
	 */
	strcpy(ptr, "foobarbaz");
	result = isc_cfgmgr_rwtxn();
	assert_int_equal(result, ISC_R_SUCCESS);

	val = (isc_cfgmgr_val_t){ .type = ISC_CFGMGR_REF,
				  .ptr = ptr,
				  .attach = cfgmgrtest_ref_attach,
				  .detach = cfgmgrtest_ref_detach };
	result = isc_cfgmgr_write("/foo/thestraddr", &val);
	assert_int_equal(result, ISC_R_SUCCESS);

	val = (isc_cfgmgr_val_t){ .type = ISC_CFGMGR_UINT32, .uint32 = 44 };
	result = isc_cfgmgr_write("/foo/thestraddr", &val);
	assert_int_equal(result, ISC_R_SUCCESS);

	assert_string_equal(ptr, "foobarbaz-attached");
	isc_cfgmgr_commit();
	assert_string_equal(ptr, "foobarbaz-attached-detached");

	/*
	 * reference is added then replaced, but there is no attach/detachd
	 * functions provided
	 */
	strcpy(ptr, "foobarbaz");
	result = isc_cfgmgr_rwtxn();
	assert_int_equal(result, ISC_R_SUCCESS);

	val = (isc_cfgmgr_val_t){ .type = ISC_CFGMGR_REF,
				  .ptr = ptr,
				  .attach = NULL,
				  .detach = NULL };
	result = isc_cfgmgr_write("/foo/thestraddr", &val);
	assert_int_equal(result, ISC_R_SUCCESS);

	val = (isc_cfgmgr_val_t){ .type = ISC_CFGMGR_UINT32, .uint32 = 44 };
	result = isc_cfgmgr_write("/foo/thestraddr", &val);
	assert_int_equal(result, ISC_R_SUCCESS);

	assert_string_equal(ptr, "foobarbaz");
	isc_cfgmgr_commit();
	assert_string_equal(ptr, "foobarbaz");

	isc_cfgmgr_deinit();
	isc_mem_put(mctx, ptr, 32);
}

ISC_RUN_TEST_IMPL(isc_cfgmgr_nested_nodes) {
	isc_result_t result;
	isc_cfgmgr_val_t val;

	cfgmgrtest_running_ready();

	/*
	 * Let's start by writting then reading
	 * foo { bar { baz { gee: none; }; }; };
	 */
	result = isc_cfgmgr_rwtxn();
	assert_int_equal(result, ISC_R_SUCCESS);

	val.type = ISC_CFGMGR_NONE;
	result = isc_cfgmgr_write("/foo/bar/baz/gee", &val);
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_cfgmgr_commit();
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_cfgmgr_txn();
	assert_int_equal(result, ISC_R_SUCCESS);

	val.type = ISC_CFGMGR_UNDEFINED;
	result = isc_cfgmgr_read("/foo/bar/baz/gee", &val);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_int_equal(val.type, ISC_CFGMGR_NONE);

	isc_cfgmgr_closetxn();

	/*
	 * then let's delete bar and add some properties in foo and
	 * another nested node
	 */
	result = isc_cfgmgr_rwtxn();
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_cfgmgr_delete("/foo/bar/");
	assert_int_equal(result, ISC_R_SUCCESS);

	val = (isc_cfgmgr_val_t){ .type = ISC_CFGMGR_STRING, .string = "abc" };
	result = isc_cfgmgr_write("/foo/foonewsubnode/propsubnode", &val);
	assert_int_equal(result, ISC_R_SUCCESS);

	val = (isc_cfgmgr_val_t){ .type = ISC_CFGMGR_STRING,
				  .string = "propfooval" };
	result = isc_cfgmgr_write("/foo/propfoo", &val);
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_cfgmgr_commit();
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_cfgmgr_txn();
	assert_int_equal(result, ISC_R_SUCCESS);

	val.type = ISC_CFGMGR_UNDEFINED;
	result = isc_cfgmgr_read("/foo/propfoo", &val);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_int_equal(val.type, ISC_CFGMGR_STRING);
	assert_string_equal(val.string, "propfooval");

	result = isc_cfgmgr_read("/foo/foonewsubnode/propsubnode", &val);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_int_equal(val.type, ISC_CFGMGR_STRING);
	assert_string_equal(val.string, "abc");

	isc_cfgmgr_closetxn();

	isc_cfgmgr_deinit();
}

ISC_RUN_TEST_IMPL(isc_cfgmgr_delete) {
	isc_result_t result;
	isc_cfgmgr_val_t val;

	cfgmgrtest_running_ready();

	result = isc_cfgmgr_rwtxn();
	assert_int_equal(result, ISC_R_SUCCESS);

	val = (isc_cfgmgr_val_t){ .type = ISC_CFGMGR_NONE };
	result = isc_cfgmgr_write("/foo/prop1", &val);
	assert_int_equal(result, ISC_R_SUCCESS);

	val = (isc_cfgmgr_val_t){ .type = ISC_CFGMGR_STRING,
				  .string = "prop2val" };
	result = isc_cfgmgr_write("/foo/prop2", &val);
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_cfgmgr_read("/foo/prop1", &val);
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_cfgmgr_read("/foo/prop2", &val);
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_cfgmgr_write("/foo/prop1", NULL);
	assert_int_equal(result, ISC_R_SUCCESS);

	val = (isc_cfgmgr_val_t){ .type = ISC_CFGMGR_NONE };
	result = isc_cfgmgr_write("/foo/prop3", &val);
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_cfgmgr_read("/foo/prop1", &val);
	assert_int_equal(result, ISC_R_NOTFOUND);

	result = isc_cfgmgr_read("/foo/prop2", &val);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_int_equal(val.type, ISC_CFGMGR_STRING);
	assert_string_equal(val.string, "prop2val");

	result = isc_cfgmgr_read("/foo/prop3", &val);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_int_equal(val.type, ISC_CFGMGR_NONE);

	val = (isc_cfgmgr_val_t){ .type = ISC_CFGMGR_NONE };
	result = isc_cfgmgr_write("/gee/prop", &val);
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_cfgmgr_read("/gee/prop", &val);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_int_equal(val.type, ISC_CFGMGR_NONE);

	/*
	 * let's delete prop2 and prop3
	 */
	result = isc_cfgmgr_write("/foo/prop2", NULL);
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_cfgmgr_write("/foo/prop3", NULL);
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_cfgmgr_read("/foo/prop2", &val);
	assert_int_equal(result, ISC_R_NOTFOUND);

	result = isc_cfgmgr_read("/foo/prop3", &val);
	assert_int_equal(result, ISC_R_NOTFOUND);

	/*
	 * let's now delete a node in one go (w/o explicitely
	 * deleting its properties as well as its subnode. Another node exists
	 * as well, it is not deleted.
	 */
	val = (isc_cfgmgr_val_t){ .type = ISC_CFGMGR_NONE };
	result = isc_cfgmgr_write("/foo/prop1", &val);
	assert_int_equal(result, ISC_R_SUCCESS);

	val = (isc_cfgmgr_val_t){ .type = ISC_CFGMGR_STRING,
				  .string = "prop2val" };
	result = isc_cfgmgr_write("/foo/prop2", &val);
	assert_int_equal(result, ISC_R_SUCCESS);

	val = (isc_cfgmgr_val_t){ .type = ISC_CFGMGR_NONE };
	result = isc_cfgmgr_write("/foo/subfoo/prop1", &val);
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_cfgmgr_read("/foo/prop1", &val);
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_cfgmgr_read("/foo/prop2", &val);
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_cfgmgr_read("/foo/subfoo/prop1", &val);
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_cfgmgr_delete("/foo/subfoo/");
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_cfgmgr_read("/foo/prop1", &val);
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_cfgmgr_read("/foo/prop2", &val);
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_cfgmgr_read("/foo/subfoo/prop1", &val);
	assert_int_equal(result, ISC_R_NOTFOUND);

	result = isc_cfgmgr_delete("/foo/");
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_cfgmgr_read("/foo/prop1", &val);
	assert_int_equal(result, ISC_R_NOTFOUND);

	result = isc_cfgmgr_read("/foo/prop2", &val);
	assert_int_equal(result, ISC_R_NOTFOUND);

	result = isc_cfgmgr_read("/gee/prop", &val);
	assert_int_equal(result, ISC_R_SUCCESS);

	isc_cfgmgr_rollback();
	isc_cfgmgr_deinit();
}

static void *
cfgmgr_threads_worker(void *arg) {
	isc_result_t result;
	sem_t *sems = arg;

	/*
	 * This one open ro, so won't block
	 */
	result = isc_cfgmgr_txn();
	assert_int_equal(result, ISC_R_SUCCESS);

	sem_wait(&sems[0]);
	sem_post(&sems[1]);

	isc_cfgmgr_closetxn();

	return NULL;
}

ISC_RUN_TEST_IMPL(isc_cfgmgr_threads) {
	isc_result_t result;
	pthread_t thread;
	sem_t sems[2];

	cfgmgrtest_running_ready();

	REQUIRE(sem_init(&sems[0], 0, 0) == 0);
	REQUIRE(sem_init(&sems[1], 0, 0) == 0);

	result = isc_cfgmgr_rwtxn();
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_cfgmgr_write(
		"/foo/p", &(isc_cfgmgr_val_t){ .type = ISC_CFGMGR_NONE });
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_cfgmgr_commit();
	assert_int_equal(result, ISC_R_SUCCESS);

	REQUIRE(pthread_create(&thread, 0, cfgmgr_threads_worker, &sems) == 0);

	result = isc_cfgmgr_rwtxn();
	assert_int_equal(result, ISC_R_SUCCESS);

	REQUIRE(sem_post(&sems[0]) == 0);
	REQUIRE(sem_wait(&sems[1]) == 0);

	result = isc_cfgmgr_commit();
	assert_int_equal(result, ISC_R_SUCCESS);

	REQUIRE(pthread_join(thread, NULL) == 0);

	isc_cfgmgr_deinit();
}

// ISC_RUN_TEST_IMPL(isc_cfgmgr_validationtest) {
//	isc_result_t result;
//	isc_cfgmgr_val_t val;
//
//	/*
//	 * foo clause is mandatory and non-repeatable, it has one property prop1
//	 * (string, mandatory)
//	 */
//	const isc_cfgmgr_prop_t prop1 = { "prop1", false, ISC_CFGMGR_STRING };
//	const isc_cfgmgr_prop_t prop2 = { "prop2", true, ISC_CFGMGR_UINT32 };
//	const isc_cfgmgr_prop_t *foo_props[] = { &prop1, &prop2, NULL };
//	const isc_cfgmgr_clause_t foo = { "foo", false, false, NULL,
//					  foo_props };
//
//	/*
//	 * bar clause is optional and repratable, it has one property prop3
//	 * (string, mandatory), another prop4 (string, optional)
//	 */
//	const isc_cfgmgr_prop_t prop3 = { "prop3", false, ISC_CFGMGR_STRING };
//	const isc_cfgmgr_prop_t prop4 = { "prop4", true, ISC_CFGMGR_STRING };
//	const isc_cfgmgr_prop_t *bar_props[] = { &prop3, &prop4, NULL };
//	const isc_cfgmgr_clause_t bar = { "bar", true, true, NULL, bar_props };
//
//	const isc_cfgmgr_clause_t *format[] = { &foo, &bar, NULL };
//
//	result = isc_cfgmgr_init(mctx, TEST_DBPATH, format);
//	assert_int_equal(result, ISC_R_SUCCESS);
//
//	result = isc_cfgmgr_rwtransaction();
//	assert_int_equal(result, ISC_R_SUCCESS);
//
//	/*
//	 * let's add just the mandatory property to foo first
//	 */
//	isc_cfgmgr_newclause("foo");
//	val = (isc_cfgmgr_val_t){ .type = ISC_CFGMGR_STRING, .string = "ab" };
//	result = isc_cfgmgr_write("prop1", &val);
//	assert_int_equal(result, ISC_R_SUCCESS);
//	isc_cfgmgr_close();
//
//	/*
//	 * two instances of bar as it's a repeatable clause
//	 */
//	val = (isc_cfgmgr_val_t){ .type = ISC_CFGMGR_STRING, .string = "cd" };
//	isc_cfgmgr_newclause("bar");
//	result = isc_cfgmgr_write("prop3", &val);
//	assert_int_equal(result, ISC_R_SUCCESS);
//	isc_cfgmgr_close();
//
//	isc_cfgmgr_newclause("bar");
//	val.string = "ef";
//	result = isc_cfgmgr_write("prop4", &val);
//	assert_int_equal(result, ISC_R_SUCCESS);
//	isc_cfgmgr_close();
//
//	/*
//	 * validation fails, as the second instance of bar doesn't have the
//	 * mandatory property prop3. (the first instance doesn't have prop4, but
//	 * it doesn't matter as it's optional)
//	 */
//	result = isc_cfgmgr_commit();
//	assert_int_equal(result, ISC_R_NOTFOUND);
//	assert_string_equal(isc_cfgmgr_lasterror(),
//			    "mandatory property bar.prop3 is missing");
//
//	/*
//	 * another attempt, with only foo
//	 */
//	result = isc_cfgmgr_rwtransaction();
//	assert_int_equal(result, ISC_R_SUCCESS);
//
//	isc_cfgmgr_newclause("foo");
//
//	val = (isc_cfgmgr_val_t){ .type = ISC_CFGMGR_UINT32, .uint32 = 42 };
//	result = isc_cfgmgr_write("prop1", &val);
//	assert_int_equal(result, ISC_R_SUCCESS);
//
//	/*
//	 * validation fails here as well, because the type of prop1 is wrong
//	 */
//	result = isc_cfgmgr_commit();
//	assert_int_equal(result, ISC_R_UNEXPECTED);
//	assert_string_equal(isc_cfgmgr_lasterror(),
//			    "property foo.prop1 has wrong type. given uint32, "
//			    "expected string");
//
//	/*
//	 * validation fails again, because foo is not repeatable
//	 */
//	result = isc_cfgmgr_rwtransaction();
//	assert_int_equal(result, ISC_R_SUCCESS);
//
//	isc_cfgmgr_newclause("foo");
//	val = (isc_cfgmgr_val_t){ .type = ISC_CFGMGR_STRING, .string = "b" };
//	result = isc_cfgmgr_write("prop1", &val);
//	assert_int_equal(result, ISC_R_SUCCESS);
//	isc_cfgmgr_close();
//
//	isc_cfgmgr_newclause("foo");
//	val = (isc_cfgmgr_val_t){ .type = ISC_CFGMGR_STRING, .string = "b" };
//	result = isc_cfgmgr_write("prop1", &val);
//	assert_int_equal(result, ISC_R_SUCCESS);
//	isc_cfgmgr_close();
//
//	result = isc_cfgmgr_commit();
//	assert_int_equal(result, ISC_R_MULTIPLE);
//	assert_string_equal(isc_cfgmgr_lasterror(),
//			    "clause foo is repeated but it's not repeatable");
//
//	/*
//	 * validation fails again, becuase foo is mandatory clause but not
//	 * provided
//	 */
//	result = isc_cfgmgr_rwtransaction();
//	assert_int_equal(result, ISC_R_SUCCESS);
//
//	isc_cfgmgr_newclause("bar");
//	val = (isc_cfgmgr_val_t){ .type = ISC_CFGMGR_STRING, .string = "b" };
//	result = isc_cfgmgr_write("prop3", &val);
//	assert_int_equal(result, ISC_R_SUCCESS);
//
//	result = isc_cfgmgr_commit();
//	assert_int_equal(result, ISC_R_NOTFOUND);
//	assert_string_equal(isc_cfgmgr_lasterror(),
//			    "mandatory clause foo is missing");
//
//	/*
//	 * Test validation of subclauses. Now bar is a mandatory child clause of
//	 * foo.
//	 */
//	const isc_cfgmgr_clause_t bar2 = { "bar", false, true, NULL,
//					   bar_props };
//	const isc_cfgmgr_clause_t *foo2subclauses[] = { &bar2, NULL };
//	const isc_cfgmgr_clause_t foo2 = { "foo", false, false, foo2subclauses,
//					   foo_props };
//	const isc_cfgmgr_clause_t *format2[] = { &foo2, NULL };
//
//	isc_cfgmgr_deinit();
//	result = isc_cfgmgr_init(mctx, TEST_DBPATH, format2);
//	assert_int_equal(result, ISC_R_SUCCESS);
//
//	result = isc_cfgmgr_rwtransaction();
//	assert_int_equal(result, ISC_R_SUCCESS);
//
//	isc_cfgmgr_newclause("foo");
//	val = (isc_cfgmgr_val_t){ .type = ISC_CFGMGR_STRING, .string = "b" };
//	result = isc_cfgmgr_write("prop1", &val);
//	assert_int_equal(result, ISC_R_SUCCESS);
//
//	/*
//	 * validation fails because bar subclause is missing from foo
//	 */
//	result = isc_cfgmgr_commit();
//	assert_int_equal(result, ISC_R_NOTFOUND);
//	assert_string_equal(isc_cfgmgr_lasterror(),
//			    "mandatory clause foo.bar is missing");
//
//	/*
//	 * Let's try again... This time it fails because of a missing mandatory
//	 * property in bar
//	 */
//	result = isc_cfgmgr_rwtransaction();
//	assert_int_equal(result, ISC_R_SUCCESS);
//
//	isc_cfgmgr_newclause("foo");
//	val = (isc_cfgmgr_val_t){ .type = ISC_CFGMGR_STRING, .string = "b" };
//	result = isc_cfgmgr_write("prop1", &val);
//	assert_int_equal(result, ISC_R_SUCCESS);
//
//	isc_cfgmgr_newclause("bar");
//	val = (isc_cfgmgr_val_t){ .type = ISC_CFGMGR_STRING, .string = "b" };
//	result = isc_cfgmgr_write("prop4", &val);
//	assert_int_equal(result, ISC_R_SUCCESS);
//
//	result = isc_cfgmgr_commit();
//	assert_int_equal(result, ISC_R_NOTFOUND);
//	assert_string_equal(isc_cfgmgr_lasterror(),
//			    "mandatory property foo.bar.prop3 is missing");
//
//	/*
//	 * And again... This time validation passes.
//	 */
//	result = isc_cfgmgr_rwtransaction();
//	assert_int_equal(result, ISC_R_SUCCESS);
//
//	isc_cfgmgr_newclause("foo");
//	val = (isc_cfgmgr_val_t){ .type = ISC_CFGMGR_STRING, .string = "b" };
//	result = isc_cfgmgr_write("prop1", &val);
//	assert_int_equal(result, ISC_R_SUCCESS);
//
//	isc_cfgmgr_newclause("bar");
//	val = (isc_cfgmgr_val_t){ .type = ISC_CFGMGR_STRING, .string = "b" };
//	result = isc_cfgmgr_write("prop3", &val);
//	assert_int_equal(result, ISC_R_SUCCESS);
//
//	result = isc_cfgmgr_commit();
//	assert_int_equal(result, ISC_R_SUCCESS);
//
//	isc_cfgmgr_deinit();
// }

static void
foreach_labeldown(void *state, const char *name) {
	isc_buffer_t *b = state;

	isc_buffer_printf(b, ">%s", name);
}

static void
foreach_labelup(void *state) {
	isc_buffer_t *b = state;

	isc_buffer_printf(b, "<");
}

static void
foreach_prop(void *state, const char *name, const isc_cfgmgr_val_t *val) {
	isc_buffer_t *b = state;

	isc_buffer_printf(b, "%s=", name);
	switch (val->type) {
	case ISC_CFGMGR_UINT32:
		isc_buffer_printf(b, "%u ", val->uint32);
		break;
	case ISC_CFGMGR_STRING:
		isc_buffer_printf(b, "%s ", val->string);
		break;
	default:
		UNREACHABLE();
	}
}

ISC_RUN_TEST_IMPL(isc_cfgmgr_foreach) {
	isc_result_t result;
	isc_cfgmgr_val_t val;

	cfgmgrtest_running_ready();

	result = isc_cfgmgr_rwtxn();
	assert_int_equal(result, ISC_R_SUCCESS);

	val = (isc_cfgmgr_val_t){ .type = ISC_CFGMGR_UINT32, .uint32 = 42 };
	result = isc_cfgmgr_write("/bar/propbar1", &val);
	assert_int_equal(result, ISC_R_SUCCESS);
	val = (isc_cfgmgr_val_t){ .type = ISC_CFGMGR_STRING,
				  .string = "barstr" };
	result = isc_cfgmgr_write("/bar/another-stuff", &val);
	assert_int_equal(result, ISC_R_SUCCESS);

	val = (isc_cfgmgr_val_t){ .type = ISC_CFGMGR_STRING,
				  .string = "foo2str" };
	result = isc_cfgmgr_write("/foo/foo2/another-foo-stuff", &val);
	assert_int_equal(result, ISC_R_SUCCESS);

	val = (isc_cfgmgr_val_t){ .type = ISC_CFGMGR_UINT32, .uint32 = 123 };
	result = isc_cfgmgr_write("/foo/foo1/foo11/fooprop", &val);
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_cfgmgr_write("/foo/foo1/foo12/prop", &val);
	val = (isc_cfgmgr_val_t){ .type = ISC_CFGMGR_UINT32, .uint32 = 456 };
	result = isc_cfgmgr_write("/foo/foo1/foo12/fooprop", &val);
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_cfgmgr_write("/foo/foo1/foo13/prop", &val);
	val = (isc_cfgmgr_val_t){ .type = ISC_CFGMGR_UINT32, .uint32 = 789 };
	result = isc_cfgmgr_write("/foo/foo1/foo13/fooprop", &val);
	assert_int_equal(result, ISC_R_SUCCESS);

	isc_buffer_t b;
	char data[512];
	data[0] = 0;

	isc_buffer_init(&b, data, sizeof(data));
	isc_cfgmgr_foreach("/bar/", 0, &b, foreach_prop, foreach_labeldown,
			   foreach_labelup);
	assert_string_equal(b.base, "another-stuff=barstr propbar1=42 ");

	isc_buffer_init(&b, data, sizeof(data));
	isc_cfgmgr_foreach("/foo/foo1/", 0, &b, NULL, foreach_labeldown,
			   foreach_labelup);
	assert_string_equal(b.base, ">foo11<>foo12<>foo13<");

	isc_cfgmgr_rollback();
	isc_cfgmgr_deinit();
}

typedef struct isc__cfgmgr_dump isc__cfgmgr_dump_t;
struct isc__cfgmgr_dump {
	size_t indent;
	size_t lvl;
	isc_buffer_t buffer;
	char data[4096];
};

static void
dump_prop(void *state, const char *name, const isc_cfgmgr_val_t *val) {
	isc__cfgmgr_dump_t *dump = state;

	for (size_t i = 0; i < dump->lvl * dump->indent; i++) {
		isc_buffer_putstr(&dump->buffer, " ");
	}

	isc_buffer_printf(&dump->buffer, "%s ", name);
	switch (val->type) {
	case ISC_CFGMGR_UINT32:
		isc_buffer_printf(&dump->buffer, "%u", val->uint32);
		break;
	case ISC_CFGMGR_STRING:
		isc_buffer_printf(&dump->buffer, "%s", val->string);
		break;
	default:
		UNREACHABLE();
	}
	isc_buffer_putstr(&dump->buffer, ";\n");
}

static void
dump_labeldown(void *state, const char *label) {
	isc__cfgmgr_dump_t *dump = state;

	for (size_t i = 0; i < dump->lvl * dump->indent; i++) {
		isc_buffer_putstr(&dump->buffer, " ");
	}

	isc_buffer_printf(&dump->buffer, "%s {\n", label);

	dump->lvl++;
}

static void
dump_labelup(void *state) {
	isc__cfgmgr_dump_t *dump = state;

	dump->lvl--;

	for (size_t i = 0; i < dump->lvl * dump->indent; i++) {
		isc_buffer_putstr(&dump->buffer, " ");
	}
	isc_buffer_printf(&dump->buffer, "};\n");
}

static void
cmpdump(isc_cfgmgr_mode_t mode, const char *expected) {
	isc__cfgmgr_dump_t dump = {
		.lvl = 0,
		.indent = 2,
	};
	isc_buffer_init(&dump.buffer, dump.data, sizeof(dump.data));
	dump.data[0] = 0;

	isc_cfgmgr_mode(mode);
	isc_cfgmgr_txn();
	isc_cfgmgr_foreach("/", 0, &dump, dump_prop, dump_labeldown,
			   dump_labelup);
	assert_string_equal(dump.buffer.base, expected);
	isc_cfgmgr_closetxn();
}

ISC_RUN_TEST_IMPL(isc_cfgmgr_dumptests) {
	isc_result_t result;
	isc_cfgmgr_val_t val;

	cfgmgrtest_running_ready();

	result = isc_cfgmgr_rwtxn();
	assert_int_equal(result, ISC_R_SUCCESS);

	val = (isc_cfgmgr_val_t){ .type = ISC_CFGMGR_UINT32, .uint32 = 42 };
	result = isc_cfgmgr_write("/bar/propbar1", &val);
	assert_int_equal(result, ISC_R_SUCCESS);
	val = (isc_cfgmgr_val_t){ .type = ISC_CFGMGR_STRING,
				  .string = "barstr" };
	result = isc_cfgmgr_write("/bar/another-stuff", &val);
	assert_int_equal(result, ISC_R_SUCCESS);

	val = (isc_cfgmgr_val_t){ .type = ISC_CFGMGR_REF,
				  .ptr = (void *)0xdeadcafebeef };
	result = isc_cfgmgr_write("/bar/addr1", &val);
	assert_int_equal(result, ISC_R_SUCCESS);

	val = (isc_cfgmgr_val_t){ .type = ISC_CFGMGR_STRING,
				  .string = "foo2str" };
	result = isc_cfgmgr_write("/foo/foo2/another-foo-stuff", &val);
	assert_int_equal(result, ISC_R_SUCCESS);

	val = (isc_cfgmgr_val_t){ .type = ISC_CFGMGR_UINT32, .uint32 = 123 };
	result = isc_cfgmgr_write("/foo/foo1/foo11/fooprop", &val);
	assert_int_equal(result, ISC_R_SUCCESS);

	val = (isc_cfgmgr_val_t){ .type = ISC_CFGMGR_UINT32, .uint32 = 123 };
	result = isc_cfgmgr_write("/foo/foo1/foo12/prop", &val);
	assert_int_equal(result, ISC_R_SUCCESS);
	val = (isc_cfgmgr_val_t){ .type = ISC_CFGMGR_UINT32, .uint32 = 456 };
	result = isc_cfgmgr_write("/foo/foo1/foo12/fooprop", &val);
	assert_int_equal(result, ISC_R_SUCCESS);

	val = (isc_cfgmgr_val_t){ .type = ISC_CFGMGR_UINT32, .uint32 = 123 };
	result = isc_cfgmgr_write("/foo/foo1/foo13/prop", &val);
	assert_int_equal(result, ISC_R_SUCCESS);
	val = (isc_cfgmgr_val_t){ .type = ISC_CFGMGR_UINT32, .uint32 = 789 };
	result = isc_cfgmgr_write("/foo/foo1/foo13/fooprop", &val);
	assert_int_equal(result, ISC_R_SUCCESS);

	isc_cfgmgr_commit();

	cmpdump(ISC_CFGMGR_MODERUNNING, "bar {\n"
					"  another-stuff barstr;\n"
					"  propbar1 42;\n"
					"};\n"
					"foo {\n"
					"  foo1 {\n"
					"    foo11 {\n"
					"      fooprop 123;\n"
					"    };\n"
					"    foo12 {\n"
					"      fooprop 456;\n"
					"      prop 123;\n"
					"    };\n"
					"    foo13 {\n"
					"      fooprop 789;\n"
					"      prop 123;\n"
					"    };\n"
					"  };\n"
					"  foo2 {\n"
					"    another-foo-stuff foo2str;\n"
					"  };\n"
					"};\n");

	result = isc_cfgmgr_rwtxn();
	assert_int_equal(result, ISC_R_SUCCESS);
	/*
	 * Now delete foo, and recreate it with foo14 child. The dump shouldn't
	 * show anything about foo11, foo12 nor foo13 not foo1 or foo2 as they
	 * been recursively deleted. And non related props aren't deleted.
	 * Note this covers some gaps of delete tests - but it's way easier to
	 * test those gaps with dump config
	 */
	result = isc_cfgmgr_delete("/foo/");
	assert_int_equal(result, ISC_R_SUCCESS);

	val = (isc_cfgmgr_val_t){ .type = ISC_CFGMGR_UINT32, .uint32 = 987 };
	result = isc_cfgmgr_write("/foo/propfoo", &val);
	assert_int_equal(result, ISC_R_SUCCESS);

	val = (isc_cfgmgr_val_t){ .type = ISC_CFGMGR_UINT32, .uint32 = 654 };
	result = isc_cfgmgr_write("/foo/foo14/anotherpropfoo14", &val);
	assert_int_equal(result, ISC_R_SUCCESS);

	isc_cfgmgr_commit();
	cmpdump(ISC_CFGMGR_MODERUNNING, "bar {\n"
					"  another-stuff barstr;\n"
					"  propbar1 42;\n"
					"};\n"
					"foo {\n"
					"  foo14 {\n"
					"    anotherpropfoo14 654;\n"
					"  };\n"
					"  propfoo 987;\n"
					"};\n");

	isc_cfgmgr_deinit();
}

ISC_RUN_TEST_IMPL(isc_cfgmgr_materialziation_options) {
	isc_result_t result;
	isc_cfgmgr_val_t val;

	result = isc_cfgmgr_init(mctx, TEST_DBPATH);
	assert_int_equal(result, ISC_R_SUCCESS);

	isc_cfgmgr_mode(ISC_CFGMGR_MODEBUILTIN);
	result = isc_cfgmgr_rwtxn();
	assert_int_equal(result, ISC_R_SUCCESS);

	val = (isc_cfgmgr_val_t){ .type = ISC_CFGMGR_UINT32, .uint32 = 1111 };
	result = isc_cfgmgr_write("/options/sub/prop1", &val);
	assert_int_equal(result, ISC_R_SUCCESS);

	val = (isc_cfgmgr_val_t){ .type = ISC_CFGMGR_UINT32, .uint32 = 1 };
	result = isc_cfgmgr_write("/options/prop1", &val);
	assert_int_equal(result, ISC_R_SUCCESS);

	val = (isc_cfgmgr_val_t){ .type = ISC_CFGMGR_UINT32, .uint32 = 2 };
	result = isc_cfgmgr_write("/options/prop2", &val);
	assert_int_equal(result, ISC_R_SUCCESS);

	val = (isc_cfgmgr_val_t){ .type = ISC_CFGMGR_UINT32, .uint32 = 3 };
	result = isc_cfgmgr_write("/options/prop3", &val);
	assert_int_equal(result, ISC_R_SUCCESS);

	val = (isc_cfgmgr_val_t){ .type = ISC_CFGMGR_UINT32, .uint32 = 11 };
	result = isc_cfgmgr_write("/options/subopts1/propsubopts1", &val);
	assert_int_equal(result, ISC_R_SUCCESS);

	val = (isc_cfgmgr_val_t){ .type = ISC_CFGMGR_UINT32, .uint32 = 12 };
	result = isc_cfgmgr_write("/options/subopts1/subopts2/propsubopts2",
				  &val);
	assert_int_equal(result, ISC_R_SUCCESS);

	val = (isc_cfgmgr_val_t){ .type = ISC_CFGMGR_UINT32, .uint32 = 333 };
	result = isc_cfgmgr_write("/options/subopts1/subopts2/prop3", &val);
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_cfgmgr_commit();
	assert_int_equal(result, ISC_R_SUCCESS);

	isc_cfgmgr_mode(ISC_CFGMGR_MODEUSER);
	result = isc_cfgmgr_rwtxn();
	assert_int_equal(result, ISC_R_SUCCESS);

	val = (isc_cfgmgr_val_t){ .type = ISC_CFGMGR_UINT32, .uint32 = 222 };
	result = isc_cfgmgr_write("/options/prop2", &val);
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_cfgmgr_commit();
	assert_int_equal(result, ISC_R_SUCCESS);

	isc_cfgmgr_mode(ISC_CFGMGR_MODERUNNING);
	result = isc_cfgmgr_rwtxn();
	assert_int_equal(result, ISC_R_SUCCESS);

	val = (isc_cfgmgr_val_t){ .type = ISC_CFGMGR_UINT32, .uint32 = 31 };
	result = isc_cfgmgr_write("/options/prop1", &val);
	assert_int_equal(result, ISC_R_SUCCESS);

	val = (isc_cfgmgr_val_t){ .type = ISC_CFGMGR_UINT32, .uint32 = 34 };
	result = isc_cfgmgr_write("/options/prop4", &val);
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_cfgmgr_commit();
	assert_int_equal(result, ISC_R_SUCCESS);

	cmpdump(ISC_CFGMGR_MODEBUILTIN, "options {\n"
					"  prop1 1;\n"
					"  prop2 2;\n"
					"  prop3 3;\n"
					"  sub {\n"
					"    prop1 1111;\n"
					"  };\n"
					"  subopts1 {\n"
					"    propsubopts1 11;\n"
					"    subopts2 {\n"
					"      prop3 333;\n"
					"      propsubopts2 12;\n"
					"    };\n"
					"  };\n"
					"};\n");

	cmpdump(ISC_CFGMGR_MODERUNNING, "options {\n"
					"  prop1 31;\n"
					"  prop2 222;\n"
					"  prop3 3;\n"
					"  prop4 34;\n"
					"  sub {\n"
					"    prop1 1111;\n"
					"  };\n"
					"  subopts1 {\n"
					"    propsubopts1 11;\n"
					"    subopts2 {\n"
					"      prop3 333;\n"
					"      propsubopts2 12;\n"
					"    };\n"
					"  };\n"
					"};\n");

	isc_cfgmgr_deinit();
}

ISC_RUN_TEST_IMPL(isc_cfgmgr_materialization) {
	isc_result_t result;
	isc_cfgmgr_val_t val;

	result = isc_cfgmgr_init(mctx, TEST_DBPATH);
	assert_int_equal(result, ISC_R_SUCCESS);

	isc_cfgmgr_mode(ISC_CFGMGR_MODEBUILTIN);
	result = isc_cfgmgr_rwtxn();
	assert_int_equal(result, ISC_R_SUCCESS);

	val = (isc_cfgmgr_val_t){ .type = ISC_CFGMGR_UINT32, .uint32 = 1 };
	result = isc_cfgmgr_write("/options/prop1", &val);
	assert_int_equal(result, ISC_R_SUCCESS);

	val = (isc_cfgmgr_val_t){ .type = ISC_CFGMGR_UINT32, .uint32 = 2 };
	result = isc_cfgmgr_write("/options/prop2", &val);
	assert_int_equal(result, ISC_R_SUCCESS);

	val = (isc_cfgmgr_val_t){ .type = ISC_CFGMGR_UINT32, .uint32 = 3 };
	result = isc_cfgmgr_write("/options/prop3", &val);
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_cfgmgr_commit();
	assert_int_equal(result, ISC_R_SUCCESS);

	isc_cfgmgr_mode(ISC_CFGMGR_MODEUSER);
	result = isc_cfgmgr_rwtxn();
	assert_int_equal(result, ISC_R_SUCCESS);

	val = (isc_cfgmgr_val_t){ .type = ISC_CFGMGR_UINT32, .uint32 = 21 };
	result = isc_cfgmgr_write("/options/prop2", &val);
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_cfgmgr_commit();
	assert_int_equal(result, ISC_R_SUCCESS);

	isc_cfgmgr_mode(ISC_CFGMGR_MODERUNNING);
	result = isc_cfgmgr_rwtxn();
	assert_int_equal(result, ISC_R_SUCCESS);

	val = (isc_cfgmgr_val_t){ .type = ISC_CFGMGR_UINT32, .uint32 = 1991 };
	result = isc_cfgmgr_write("/views/fooview/propspecific", &val);
	assert_int_equal(result, ISC_R_SUCCESS);

	val = (isc_cfgmgr_val_t){ .type = ISC_CFGMGR_UINT32, .uint32 = 991 };
	result = isc_cfgmgr_write("/views/fooview/prop2", &val);
	assert_int_equal(result, ISC_R_SUCCESS);

	val = (isc_cfgmgr_val_t){ .type = ISC_CFGMGR_UINT32, .uint32 = 661 };
	result = isc_cfgmgr_write("/views/fooview/zones/foo.org/prop1", &val);
	assert_int_equal(result, ISC_R_SUCCESS);

	val = (isc_cfgmgr_val_t){ .type = ISC_CFGMGR_UINT32, .uint32 = 662 };
	result = isc_cfgmgr_write("/views/barview/zones/bar.org/prop1", &val);
	assert_int_equal(result, ISC_R_SUCCESS);

	val = (isc_cfgmgr_val_t){ .type = ISC_CFGMGR_UINT32, .uint32 = 663 };
	result = isc_cfgmgr_write("/views/barview/zones/baz.org/prop1", &val);
	assert_int_equal(result, ISC_R_SUCCESS);

	val = (isc_cfgmgr_val_t){ .type = ISC_CFGMGR_STRING, .string = "abc" };
	result = isc_cfgmgr_write("/views/barview/zones/baz.org/sub3/sub3prop",
				  &val);
	assert_int_equal(result, ISC_R_SUCCESS);

	val = (isc_cfgmgr_val_t){ .type = ISC_CFGMGR_UINT32, .uint32 = 31 };
	result = isc_cfgmgr_write("/options/prop1", &val);
	assert_int_equal(result, ISC_R_SUCCESS);

	val = (isc_cfgmgr_val_t){ .type = ISC_CFGMGR_UINT32, .uint32 = 34 };
	result = isc_cfgmgr_write("/options/prop4", &val);
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_cfgmgr_commit();
	assert_int_equal(result, ISC_R_SUCCESS);

	cmpdump(ISC_CFGMGR_MODEBUILTIN, "options {\n"
					"  prop1 1;\n"
					"  prop2 2;\n"
					"  prop3 3;\n"
					"};\n");

	cmpdump(ISC_CFGMGR_MODEUSER, "options {\n"
				     "  prop2 21;\n"
				     "};\n");

	cmpdump(ISC_CFGMGR_MODERUNNING, "options {\n"
					"  prop1 31;\n"
					"  prop2 21;\n"
					"  prop3 3;\n"
					"  prop4 34;\n"
					"};\n"
					"views {\n"
					"  barview {\n"
					"    zones {\n"
					"      bar.org {\n"
					"        prop1 662;\n"
					"      };\n"
					"      baz.org {\n"
					"        prop1 663;\n"
					"        sub3 {\n"
					"          sub3prop abc;\n"
					"        };\n"
					"      };\n"
					"    };\n"
					"  };\n"
					"  fooview {\n"
					"    prop2 991;\n"
					"    propspecific 1991;\n"
					"    zones {\n"
					"      foo.org {\n"
					"        prop1 661;\n"
					"      };\n"
					"    };\n"
					"  };\n"
					"};\n");

	/*
	 * Adding nested properties in views (running) gets visible on
	 * zones. Also overriding user sub properties.
	 */
	result = isc_cfgmgr_rwtxn();
	assert_int_equal(result, ISC_R_SUCCESS);

	val = (isc_cfgmgr_val_t){ .type = ISC_CFGMGR_STRING, .string = "abc" };
	result = isc_cfgmgr_write("/views/barview/sub3/sub3prop", &val);
	assert_int_equal(result, ISC_R_SUCCESS);

	val = (isc_cfgmgr_val_t){ .type = ISC_CFGMGR_STRING, .string = "def" };
	result = isc_cfgmgr_write("/views/barview/sub1/sub1prop2", &val);
	assert_int_equal(result, ISC_R_SUCCESS);

	val = (isc_cfgmgr_val_t){ .type = ISC_CFGMGR_STRING,
				  .string = "stuff00" };
	result = isc_cfgmgr_write("/options/sub1/sub1prop2", &val);
	assert_int_equal(result, ISC_R_SUCCESS);

	val = (isc_cfgmgr_val_t){ .type = ISC_CFGMGR_STRING,
				  .string = "stuff22" };
	result = isc_cfgmgr_write("/options/sub2/sub2prop", &val);
	assert_int_equal(result, ISC_R_SUCCESS);

	/*
	 * Delete running mode property materialized from builtin.
	 */
	result = isc_cfgmgr_write("/options/prop3", NULL);
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_cfgmgr_commit();
	assert_int_equal(result, ISC_R_SUCCESS);

	cmpdump(ISC_CFGMGR_MODERUNNING, "options {\n"
					"  prop1 31;\n"
					"  prop2 21;\n"
					"  prop4 34;\n"
					"  sub1 {\n"
					"    sub1prop2 stuff00;\n"
					"  };\n"
					"  sub2 {\n"
					"    sub2prop stuff22;\n"
					"  };\n"
					"};\n"
					"views {\n"
					"  barview {\n"
					"    sub1 {\n"
					"      sub1prop2 def;\n"
					"    };\n"
					"    sub3 {\n"
					"      sub3prop abc;\n"
					"    };\n"
					"    zones {\n"
					"      bar.org {\n"
					"        prop1 662;\n"
					"      };\n"
					"      baz.org {\n"
					"        prop1 663;\n"
					"        sub3 {\n"
					"          sub3prop abc;\n"
					"        };\n"
					"      };\n"
					"    };\n"
					"  };\n"
					"  fooview {\n"
					"    prop2 991;\n"
					"    propspecific 1991;\n"
					"    zones {\n"
					"      foo.org {\n"
					"        prop1 661;\n"
					"      };\n"
					"    };\n"
					"  };\n"
					"};\n");
	isc_cfgmgr_deinit();
}

ISC_RUN_TEST_IMPL(isc_cfgmgr_inheritance) {
	isc_result_t result;
	isc_cfgmgr_val_t val = { .type = ISC_CFGMGR_STRING };

	cfgmgrtest_running_ready();

	result = isc_cfgmgr_rwtxn();
	assert_int_equal(result, ISC_R_SUCCESS);

	val.string = "optionsprop1";
	result = isc_cfgmgr_write("/options/prop1", &val);
	assert_int_equal(result, ISC_R_SUCCESS);

	val.string = "optionsprop2";
	result = isc_cfgmgr_write("/options/prop2", &val);
	assert_int_equal(result, ISC_R_SUCCESS);

	val.string = "optionsprop3";
	result = isc_cfgmgr_write("/options/prop3", &val);
	assert_int_equal(result, ISC_R_SUCCESS);

	val.string = "optionssubprop1";
	result = isc_cfgmgr_write("/options/sub/prop1", &val);
	assert_int_equal(result, ISC_R_SUCCESS);

	val.string = "optionssubprop2";
	result = isc_cfgmgr_write("/options/sub/prop2", &val);
	assert_int_equal(result, ISC_R_SUCCESS);

	val.string = "optionssubprop3";
	result = isc_cfgmgr_write("/options/sub/prop3", &val);
	assert_int_equal(result, ISC_R_SUCCESS);

	val.string = "v1prop1";
	result = isc_cfgmgr_write("/views/v1/prop1", &val);
	assert_int_equal(result, ISC_R_SUCCESS);

	val.string = "v1subprop1";
	result = isc_cfgmgr_write("/views/v1/sub/prop1", &val);
	assert_int_equal(result, ISC_R_SUCCESS);

	val.string = "z1prop2";
	result = isc_cfgmgr_write("/views/v1/zones/z1/prop2", &val);
	assert_int_equal(result, ISC_R_SUCCESS);

	val.string = "z1subprop2";
	result = isc_cfgmgr_write("/views/v1/zones/z1/sub/prop2", &val);
	assert_int_equal(result, ISC_R_SUCCESS);

	val = (isc_cfgmgr_val_t){};
	result = isc_cfgmgr_read("/views/v1/prop1", &val);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_int_equal(val.type, ISC_CFGMGR_STRING);
	assert_string_equal(val.string, "v1prop1");

	val = (isc_cfgmgr_val_t){};
	result = isc_cfgmgr_read("/views/v1/prop2", &val);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_int_equal(val.type, ISC_CFGMGR_STRING);
	assert_string_equal(val.string, "optionsprop2");

	val = (isc_cfgmgr_val_t){};
	result = isc_cfgmgr_read("/views/v1/prop3", &val);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_int_equal(val.type, ISC_CFGMGR_STRING);
	assert_string_equal(val.string, "optionsprop3");

	val = (isc_cfgmgr_val_t){};
	result = isc_cfgmgr_read("/views/v1/sub/prop1", &val);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_int_equal(val.type, ISC_CFGMGR_STRING);
	assert_string_equal(val.string, "v1subprop1");

	val = (isc_cfgmgr_val_t){};
	result = isc_cfgmgr_read("/views/v1/sub/prop2", &val);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_int_equal(val.type, ISC_CFGMGR_STRING);
	assert_string_equal(val.string, "optionssubprop2");

	val = (isc_cfgmgr_val_t){};
	result = isc_cfgmgr_read("/views/v1/sub/prop3", &val);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_int_equal(val.type, ISC_CFGMGR_STRING);
	assert_string_equal(val.string, "optionssubprop3");

	val = (isc_cfgmgr_val_t){};
	result = isc_cfgmgr_read("/views/v1/zones/z1/prop1", &val);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_int_equal(val.type, ISC_CFGMGR_STRING);
	assert_string_equal(val.string, "v1prop1");

	val = (isc_cfgmgr_val_t){};
	result = isc_cfgmgr_read("/views/v1/zones/z1/prop2", &val);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_int_equal(val.type, ISC_CFGMGR_STRING);
	assert_string_equal(val.string, "z1prop2");

	val = (isc_cfgmgr_val_t){};
	result = isc_cfgmgr_read("/views/v1/zones/z1/prop3", &val);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_int_equal(val.type, ISC_CFGMGR_STRING);
	assert_string_equal(val.string, "optionsprop3");

	val = (isc_cfgmgr_val_t){};
	result = isc_cfgmgr_read("/views/v1/zones/z1/sub/prop1", &val);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_int_equal(val.type, ISC_CFGMGR_STRING);
	assert_string_equal(val.string, "v1subprop1");

	val = (isc_cfgmgr_val_t){};
	result = isc_cfgmgr_read("/views/v1/zones/z1/sub/prop2", &val);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_int_equal(val.type, ISC_CFGMGR_STRING);
	assert_string_equal(val.string, "z1subprop2");

	val = (isc_cfgmgr_val_t){};
	result = isc_cfgmgr_read("/views/v1/zones/z1/sub/prop3", &val);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_int_equal(val.type, ISC_CFGMGR_STRING);
	assert_string_equal(val.string, "optionssubprop3");

	(void)isc_cfgmgr_commit();
	isc_cfgmgr_deinit();
}

ISC_TEST_LIST_START
ISC_TEST_ENTRY(isc_cfgmgr_assertions)
ISC_TEST_ENTRY(isc_cfgmgr_rw)
ISC_TEST_ENTRY(isc_cfgmgr_rollback)
ISC_TEST_ENTRY(isc_cfgmgr_override)
ISC_TEST_ENTRY(isc_cfgmgr_rw_string)
ISC_TEST_ENTRY(isc_cfgmgr_rw_ptr)
ISC_TEST_ENTRY(isc_cfgmgr_inheritance)
ISC_TEST_ENTRY(isc_cfgmgr_foreach)
ISC_TEST_ENTRY(isc_cfgmgr_delete)
ISC_TEST_ENTRY(isc_cfgmgr_nested_nodes)
ISC_TEST_ENTRY(isc_cfgmgr_materialziation_options)
ISC_TEST_ENTRY(isc_cfgmgr_materialization)
ISC_TEST_ENTRY(isc_cfgmgr_dumptests)
ISC_TEST_ENTRY(isc_cfgmgr_threads)
// ISC_TEST_ENTRY(isc_cfgmgr_validationtest)
ISC_TEST_LIST_END
ISC_TEST_MAIN
