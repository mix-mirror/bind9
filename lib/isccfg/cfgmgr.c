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

#include <lmdb.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include <isc/list.h>
#include <isc/mem.h>
#include <isc/thread.h>
#include <isc/util.h>

#include <isccfg/cfgmgr.h>

#define DBPATH "/tmp/lmdb-exp"

/*
 * See MDB_MAXKEYSIZE documentation, but not accessible as defined in
 * internal implementation. Having key with longer size won't work
 * with LMDB. The value is 511 by default.
 */
#define BUFLEN 511

typedef struct openedclause openedclause_t;
struct openedclause {
	char *name;
	unsigned long id;
	ISC_LINK(openedclause_t) link;
};
typedef ISC_LIST(openedclause_t) openedclauses_t;

typedef struct {
	openedclauses_t openedclauses;
	char *prefix;
	char *buffer;
	MDB_cursor *cursor;
	MDB_txn *txn;
	bool readonly;
} context_t;

static isc_mem_t *mctx = NULL;
static MDB_env *env = NULL;
static thread_local context_t ctx =
	(context_t){ .openedclauses = ISC_LIST_INITIALIZER,
		     .prefix = NULL,
		     .buffer = NULL,
		     .cursor = NULL,
		     .txn = NULL,
		     .readonly = false };

static unsigned long
parseid(const char *dbkey) {
	unsigned long id = 0;
	size_t idstarts;
	size_t idends;
	size_t keylen;

	REQUIRE(ctx.buffer != NULL);
	REQUIRE(dbkey != NULL);

	/*
	 * starts checking after the prefix dot delimiter, i.e.  if
	 * prefix is "foo" then the key will be "foo.1235..." so the
	 * start of the id (character 1) is at character index 4
	 */
	idstarts = strlen(ctx.buffer);
	idends = idstarts;
	INSIST(idstarts > 0 && idends == idstarts);
	INSIST(ctx.buffer[idstarts - 1] == '.');
	keylen = strlen(dbkey);

	/*
	 * Cutting the key form the dot after the identifier
	 */
	REQUIRE(keylen > idends);
	while (dbkey[idends] != '.') {
		idends++;
		INSIST(keylen > idends);
	}

	/*
	 * strtoul will stops as soon as it doesn't encounder a
	 * non-digit number, so no need to get an extra buffer, copy
	 * the dbkey and add a null byte after the last digit.
	 */
	id = strtoul(dbkey + idstarts, NULL, 10);
	ENSURE(id > 0);
	return id;
}

isc_result_t
cfgmgr_init(void) {
	int result = ISC_R_SUCCESS;
	char dbname[BUFLEN];
	char dblockname[BUFLEN];
	uint32_t random;

	REQUIRE(ISC_LIST_EMPTY(ctx.openedclauses));
	REQUIRE(ctx.prefix == NULL);
	REQUIRE(ctx.buffer == NULL);
	REQUIRE(ctx.cursor == NULL);
	REQUIRE(ctx.txn == NULL);
	REQUIRE(mctx == NULL);
	REQUIRE(env == NULL);

	isc_mem_create(&mctx);
	INSIST(mctx != NULL);

	result = mdb_env_create(&env);
	if (result != 0) {
		result = ISC_R_FAILURE;
		goto cleanup;
	}

	/*
	 * Using MDB_NOSYNC as it avoid force disk flush after a
	 * transaction. It's quicker and in our case we don't need it
	 * as we delete the only link to the inode right away (so disk
	 * corruption doesn't matter: as soon as the process is dead,
	 * the disk data is dead as well)
	 */
	random = arc4random();
	REQUIRE(snprintf(dbname, BUFLEN, "%s-%u", DBPATH, random) < BUFLEN);
	REQUIRE(snprintf(dblockname, BUFLEN, "%s-%u-lock", DBPATH, random) <
		BUFLEN);
	result = mdb_env_open(env, dbname, MDB_NOSYNC | MDB_NOSUBDIR, 0600);
	if (result != 0) {
		result = ISC_R_FAILURE;
		goto cleanup;
	}

	remove(dbname);
	remove(dblockname);

	ENSURE(env != NULL);
	goto out;

cleanup:
	if (env != NULL) {
		mdb_env_close(env);
		env = NULL;
	}

out:
	return result;
}

void
cfgmgr_deinit(void) {
	/*
	 * Well, I'm on the fence about those context checks... It's
	 * good to have, but because they thread specific, it doesn't
	 * means there isn't a thread somewhere which haven't released
	 * its opened clauses and not the one calling cfgmgr_deinit,
	 * then we'll leak those - even if unlikely as this function
	 * should be call late in shutdown flow. (That said it's just
	 * an extra clue, because destroying the context will assert
	 * anyway, as some memory would not be released yet).
	 */
	REQUIRE(ISC_LIST_EMPTY(ctx.openedclauses));
	REQUIRE(ctx.prefix == NULL);
	REQUIRE(ctx.buffer == NULL);
	REQUIRE(ctx.cursor == NULL);
	REQUIRE(ctx.txn == NULL);
	REQUIRE(env != NULL);
	REQUIRE(mctx != NULL);
	mdb_env_close(env);
	env = NULL;
	isc_mem_destroy(&mctx);
	ENSURE(mctx == NULL);
}

static void
buildkey(const char *name, bool trailingdot) {
	size_t written;
	const char *prefix = ISC_LIST_EMPTY(ctx.openedclauses) ? ""
							       : ctx.prefix;
	const char *dot = trailingdot ? "." : "";

	REQUIRE(ctx.buffer != NULL);
	written = snprintf(ctx.buffer, BUFLEN, "%s%s%s", prefix, name, dot);
	INSIST(written <= BUFLEN);
}

static isc_result_t
open_findclause(const char *name, unsigned long *id) {
	isc_result_t result = ISC_R_SUCCESS;
	MDB_val dbkey;
	size_t dotpos = 0;

	REQUIRE(name != NULL);
	REQUIRE(ctx.buffer != NULL);
	REQUIRE(ctx.txn != NULL);
	REQUIRE(ctx.cursor != NULL);

	buildkey(name, true);
	dotpos = strlen(ctx.buffer) - 1;
	dbkey = (MDB_val){ .mv_size = strlen(ctx.buffer) + 1,
			   .mv_data = (char *)ctx.buffer };

	/*
	 * Let's use LMDB prefix search because the first clause
	 * key/val won't just have the "name.id" prefix, but also the
	 * id and the first property name (so "name.id.prop").
	 */
	if (mdb_cursor_get(ctx.cursor, &dbkey, NULL, MDB_SET_RANGE) != 0) {
		result = ISC_R_NOTFOUND;
		goto out;
	}

	/*
	 * LMDB found a key which starts by "prefix", so let's make
	 * sure it's actually the same prefix by checking the found
	 * key has an immediate leading dot
	 */
	if (dbkey.mv_size <= dotpos || ((char *)dbkey.mv_data)[dotpos] != '.') {
		result = ISC_R_NOTFOUND;
		goto out;
	}

	/*
	 * We found the clause. Let's extract its ID
	 */
	*id = parseid(dbkey.mv_data);

out:
	return result;
}

static void
updateprefix(void) {
	size_t written = 0;

	REQUIRE(ctx.prefix != NULL);

	if (ISC_LIST_EMPTY(ctx.openedclauses)) {
		return;
	}

	for (openedclause_t *clause = ISC_LIST_TAIL(ctx.openedclauses);
	     clause != NULL; clause = ISC_LIST_PREV(clause, link))
	{
		written += snprintf(ctx.prefix + written, BUFLEN - written,
				    "%s.%zu.", clause->name, clause->id);
		INSIST(written <= BUFLEN);
	}
}

static void
pushclause(const char *name, unsigned long id) {
	openedclause_t *clause = isc_mem_get(mctx, sizeof(*clause));

	*clause = (openedclause_t){
		.name = isc_mem_allocate(mctx, strlen(name) + 1), .id = id
	};
	strcpy(clause->name, name);
	ENSURE(clause->id > 0);
	ISC_LIST_PREPEND(ctx.openedclauses, clause, link);
	updateprefix();
}

static void
freectx(void) {
	REQUIRE(ctx.buffer != NULL && ctx.prefix != NULL);

	isc_mem_free(mctx, ctx.buffer);
	ctx.buffer = NULL;
	isc_mem_free(mctx, ctx.prefix);
	ctx.prefix = NULL;
	ctx.txn = NULL;
	ctx.cursor = NULL;
}

static isc_result_t
starttransaction(bool readonly) {
	isc_result_t result = ISC_R_SUCCESS;
	MDB_dbi dbi;

	REQUIRE(env != NULL);
	REQUIRE(ctx.prefix == NULL);
	REQUIRE(ctx.buffer == NULL);
	REQUIRE(ctx.txn == NULL);
	REQUIRE(ctx.cursor == NULL);

	if (mdb_txn_begin(env, NULL, readonly ? MDB_RDONLY : 0, &ctx.txn) != 0)
	{
		result = ISC_R_FAILURE;
		goto cleanup;
	}
	INSIST(ctx.txn != NULL);

	if (mdb_dbi_open(ctx.txn, NULL, MDB_CREATE | MDB_DUPSORT, &dbi) != 0) {
		result = ISC_R_FAILURE;
		goto cleanup;
	}

	if (mdb_cursor_open(ctx.txn, dbi, &ctx.cursor) != 0) {
		result = ISC_R_FAILURE;
		goto cleanup;
	}
	INSIST(ctx.cursor != NULL);
	ctx.readonly = readonly;
	ctx.buffer = isc_mem_allocate(mctx, BUFLEN);
	ctx.prefix = isc_mem_allocate(mctx, BUFLEN);
	goto out;

cleanup:
	if (ctx.txn) {
		mdb_txn_abort(ctx.txn);
		freectx();
	}
	ENSURE(ctx.buffer == NULL && ctx.prefix == NULL);

out:
	return result;
}

static isc_result_t
open_toplevel(const char *name, bool readonly) {
	isc_result_t result = ISC_R_SUCCESS;
	unsigned long id = 0;

	REQUIRE(env != NULL);
	REQUIRE(name != NULL);
	REQUIRE(ISC_LIST_EMPTY(ctx.openedclauses));
	REQUIRE(ctx.prefix == NULL);
	REQUIRE(ctx.buffer == NULL);
	REQUIRE(ctx.txn == NULL);
	REQUIRE(ctx.cursor == NULL);

	/*
	 * We're opening a clause at top-level, so let's start a
	 * transaction
	 */
	result = starttransaction(readonly);
	if (result != ISC_R_SUCCESS) {
		goto cleanup;
	}

	/*
	 * Now let's try to find the clause...
	 */
	result = open_findclause(name, &id);
	if (result != ISC_R_SUCCESS) {
		goto cleanup;
	}

	/*
	 * The clause is found, let's enqueue the clause in
	 * context. the clause is now opened
	 */
	pushclause(name, id);
	goto out;

cleanup:
	if (ctx.txn) {
		mdb_txn_abort(ctx.txn);
		freectx();
	}

out:
	return result;
}

static isc_result_t
open_nested(const char *name) {
	isc_result_t result = ISC_R_SUCCESS;
	unsigned long id = 0;

	REQUIRE(env != NULL);
	REQUIRE(name != NULL);
	REQUIRE(ISC_LIST_EMPTY(ctx.openedclauses) == false);
	REQUIRE(ctx.prefix != NULL);
	REQUIRE(ctx.buffer != NULL);
	REQUIRE(ctx.txn != NULL);
	REQUIRE(ctx.cursor != NULL);

	result = open_findclause(name, &id);
	if (result != ISC_R_SUCCESS) {
		goto out;
	}

	pushclause(name, id);

out:
	return result;
}

isc_result_t
cfgmgr_openrw(const char *name) {
	return open_toplevel(name, false);
}

isc_result_t
cfgmgr_open(const char *name) {
	return ISC_LIST_EMPTY(ctx.openedclauses) ? open_toplevel(name, true)
						 : open_nested(name);
}

static void
popclause(void) {
	REQUIRE(env != NULL);
	REQUIRE(ISC_LIST_EMPTY(ctx.openedclauses) == false);

	openedclause_t *clause = ISC_LIST_HEAD(ctx.openedclauses);
	ISC_LIST_UNLINK(ctx.openedclauses, clause, link);
	isc_mem_free(mctx, clause->name);
	isc_mem_put(mctx, clause, sizeof(*clause));
	updateprefix();
}

isc_result_t
cfgmgr_close(void) {
	isc_result_t result = ISC_R_SUCCESS;

	REQUIRE(env != NULL);

	if (ISC_LIST_EMPTY(ctx.openedclauses)) {
		REQUIRE(ctx.prefix == NULL);
		REQUIRE(ctx.buffer == NULL);
		REQUIRE(ctx.txn == NULL);
		REQUIRE(ctx.cursor == NULL);
		result = ISC_R_NOTBOUND;
		goto out;
	}

	popclause();

	if (ISC_LIST_EMPTY(ctx.openedclauses)) {
		mdb_cursor_close(ctx.cursor);
		if (mdb_txn_commit(ctx.txn) != 0) {
			result = ISC_R_FAILURE;
		}
		freectx();
	}

out:
	return result;
}

isc_result_t
cfgmgr_delclause(void) {
	MDB_val dbkey;

	REQUIRE(env != NULL);
	REQUIRE(ISC_LIST_EMPTY(ctx.openedclauses) == false);
	REQUIRE(ctx.prefix != NULL);
	REQUIRE(ctx.buffer != NULL);
	REQUIRE(ctx.txn != NULL);
	REQUIRE(ctx.cursor != NULL);
	REQUIRE(ctx.readonly == false);

	dbkey = (MDB_val){ .mv_size = strlen(ctx.prefix) + 1,
			   .mv_data = ctx.prefix };
	do {
		/*
		 * even though the key is modified by mdb_cursor_get
		 * on each run (and is the exact current key) we're
		 * good: MDB_SET_RANGE of the current key will point
		 * to the next one with the same prefix as soon it
		 * gets deleted
		 */
		int mdbres = mdb_cursor_get(ctx.cursor, &dbkey, NULL,
					    MDB_SET_RANGE);
		if (mdbres == MDB_NOTFOUND) {
			break;
		}

		if (strncmp(ctx.prefix, dbkey.mv_data, strlen(ctx.prefix)) != 0)
		{
			break;
		}

		/*
		 * NDB_NODUPDATA not strictly needed here, but we
		 * avoid extra iterations if there are lists in the
		 * clause
		 */
		REQUIRE(mdb_cursor_del(ctx.cursor, MDB_NODUPDATA) == 0);
	} while (1);

	return cfgmgr_close();
}

isc_result_t
cfgmgr_newclause(const char *name) {
	isc_result_t result = ISC_R_SUCCESS;

	REQUIRE(name != NULL);
	REQUIRE(env != NULL);

	if (ctx.txn == NULL || ctx.cursor == NULL) {
		result = starttransaction(false);
	}

	if (result == ISC_R_SUCCESS) {
		INSIST(ctx.txn != NULL);
		INSIST(ctx.buffer != NULL);
		INSIST(ctx.cursor != NULL);
		INSIST(ctx.readonly == false);
		pushclause(name, arc4random());
		INSIST(ctx.prefix != NULL);
	}

	return result;
}

isc_result_t
cfgmgr_nextclause(void) {
	isc_result_t result = ISC_R_SUCCESS;
	MDB_val dbkey;
	unsigned long id;
	size_t idstarts = 0;
	size_t written = 0;

	REQUIRE(env != NULL);
	REQUIRE(ISC_LIST_EMPTY(ctx.openedclauses) == false);
	REQUIRE(ctx.prefix != NULL);
	REQUIRE(ctx.buffer != NULL);
	REQUIRE(ctx.txn != NULL);
	REQUIRE(ctx.cursor != NULL);

	/*
	 * Let's pick the very next id (even if doesn't exists) of the
	 * current clause
	 */
	id = ISC_LIST_HEAD(ctx.openedclauses)->id + 1;

	/*
	 * Variant of updateprefix, but this time we put a incremented
	 * key for the currently opened clause. We also keep track of
	 * when the current clause id starts.
	 */
	for (openedclause_t *clause = ISC_LIST_TAIL(ctx.openedclauses);
	     clause != NULL; clause = ISC_LIST_PREV(clause, link))
	{
		bool last = ISC_LIST_PREV(clause, link) == NULL;

		if (last) {
			idstarts = written + strlen(clause->name) + 1;
		}
		written += snprintf(ctx.buffer + written, BUFLEN - written,
				    "%s.%zu.", clause->name,
				    last ? id : clause->id);
		INSIST(written <= BUFLEN);
	}
	INSIST(idstarts > 0);
	dbkey = (MDB_val){ .mv_size = strlen(ctx.buffer) + 1,
			   .mv_data = ctx.buffer };

	/*
	 * Looking for similar prefix name but with a bigger
	 * id. Thanks for LMDB sort and MDB_SET_RANGE, we'll bump to
	 * the first key/val of the next clause of the same type
	 */
	if (mdb_cursor_get(ctx.cursor, &dbkey, NULL, MDB_SET_RANGE) != 0) {
		result = ISC_R_NOMORE;
		goto out;
	}

	/*
	 * Let's check if next found clause is same name
	 */
	REQUIRE(idstarts < BUFLEN);
	if (strncmp(ctx.buffer, dbkey.mv_data, idstarts) != 0) {
		result = ISC_R_NOMORE;
		goto out;
	}

	/*
	 * Gets the actual id of the next clause (so let's get rid of
	 * the fake id part from the prefix). Instead of pop/push a
	 * new clause, let's simply replace the id and update the
	 * prefix.
	 */
	ctx.buffer[idstarts] = 0;
	ISC_LIST_HEAD(ctx.openedclauses)->id = parseid(dbkey.mv_data);
	updateprefix();

out:
	return result;
}

static isc_result_t
getval(const char *name, cfgmgr_val_t *value) {
	isc_result_t result = ISC_R_SUCCESS;
	MDB_val dbkey;
	MDB_val dbval;
	const int opt = name == NULL ? MDB_NEXT_DUP : MDB_SET;

	REQUIRE(env != NULL);
	REQUIRE(ISC_LIST_EMPTY(ctx.openedclauses) == false);
	REQUIRE(ctx.prefix != NULL);
	REQUIRE(ctx.buffer != NULL);
	REQUIRE(ctx.txn != NULL);
	REQUIRE(ctx.cursor != NULL);
	REQUIRE(value != NULL);

	if (name != NULL) {
		buildkey(name, false);
	}
	dbkey = (MDB_val){ .mv_size = name == NULL ? 0 : strlen(ctx.buffer) + 1,
			   .mv_data = name == NULL ? NULL : ctx.buffer };
	if (mdb_cursor_get(ctx.cursor, &dbkey, &dbval, opt) != 0) {
		result = opt == MDB_NEXT_DUP ? ISC_R_NOMORE : ISC_R_NOTFOUND;
		goto out;
	}

	memcpy(value, dbval.mv_data, sizeof(*value));
	if (value->type == STRING) {
		value->data.string = ((char *)dbval.mv_data) +
				     sizeof(value->type);
	}

out:
	return result;
}

isc_result_t
cfgmgr_getval(const char *name, cfgmgr_val_t *value) {
	return getval(name, value);
}

isc_result_t
cfgmgr_getnextlistval(cfgmgr_val_t *value) {
	return getval(NULL, value);
}

static isc_result_t
setval(const char *name, const cfgmgr_val_t *value, bool list) {
	isc_result_t result = ISC_R_SUCCESS;
	MDB_val dbkey;
	MDB_val dbval;

	REQUIRE(env != NULL);
	REQUIRE(ISC_LIST_EMPTY(ctx.openedclauses) == false);
	REQUIRE(ctx.prefix != NULL);
	REQUIRE(ctx.buffer != NULL);
	REQUIRE(ctx.txn != NULL);
	REQUIRE(ctx.cursor != NULL);
	REQUIRE(ctx.readonly == false);
	REQUIRE(name != NULL);
	REQUIRE(value != NULL || (value == NULL && list == false));

	buildkey(name, false);
	dbkey = (MDB_val){ .mv_size = strlen(ctx.buffer) + 1,
			   .mv_data = ctx.buffer };
	if (value == NULL) {
		if (mdb_cursor_get(ctx.cursor, &dbkey, NULL, MDB_SET) ==
		    MDB_NOTFOUND)
		{
			result = ISC_R_NOTFOUND;
			goto out;
		}

		REQUIRE(mdb_cursor_del(ctx.cursor, MDB_NODUPDATA) == 0);
		goto out;
	}

	if (value->type == STRING) {
		dbval.mv_size = sizeof(*value) + strlen(value->data.string) + 1;
		dbval.mv_data = isc_mem_allocate(mctx, dbval.mv_size);
		memcpy(dbval.mv_data, value, sizeof(value->type));
		strcpy(((char *)dbval.mv_data) + sizeof(value->type),
		       value->data.string);
	} else {
		dbval = (MDB_val){ .mv_size = sizeof(*value),
				   /*
				    * LMDB won't modify the mv_data buffer but
				    * its API is designed w/o the const buffer.
				    */
				   .mv_data = (void *)value };
	}

	if (list == false) {
		/*
		 * Can't use MDB_NOOVERWRITE as it would override the
		 * data if the key/value already exists. Making a
		 * value copy ahead just in case is likely more
		 * expensive than an extra lookup
		 */
		if (mdb_cursor_get(ctx.cursor, &dbkey, NULL, MDB_SET) !=
		    MDB_NOTFOUND)
		{
			REQUIRE(mdb_cursor_del(ctx.cursor, 0) == 0);
		}
	}

	REQUIRE(mdb_cursor_put(ctx.cursor, &dbkey, &dbval, 0) == 0);
	if (value->type == STRING) {
		isc_mem_free(mctx, dbval.mv_data);
	}

out:
	return result;
}

isc_result_t
cfgmgr_setval(const char *name, const cfgmgr_val_t *value) {
	return setval(name, value, false);
}

isc_result_t
cfgmgr_setnextlistval(const char *name, const cfgmgr_val_t *value) {
	return setval(name, value, true);
}
