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
#include <isc/random.h>
#include <isc/thread.h>
#include <isc/util.h>

#include <isccfg/cfgmgr.h>

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

static isc_mem_t *isc__cfgmgr_mctx = NULL;
static MDB_env *isc__cfgmgr_env = NULL;
static thread_local context_t isc__cfgmgr_ctx =
	(context_t){ .openedclauses = ISC_LIST_INITIALIZER,
		     .prefix = NULL,
		     .buffer = NULL,
		     .cursor = NULL,
		     .txn = NULL,
		     .readonly = false };

static unsigned long
isc__cfgmgr_parseid(const char *dbkey) {
	unsigned long id = 0;
	size_t idstarts;
	size_t idends;
	size_t keylen;

	REQUIRE(isc__cfgmgr_ctx.buffer != NULL);
	REQUIRE(dbkey != NULL);

	/*
	 * starts checking after the prefix dot delimiter, i.e.  if
	 * prefix is "foo" then the key will be "foo.1235..." so the
	 * start of the id (character 1) is at character index 4
	 */
	idstarts = strlen(isc__cfgmgr_ctx.buffer);
	INSIST(idstarts > 0 && isc__cfgmgr_ctx.buffer[idstarts - 1] == '.');
	idends = idstarts;

	/*
	 * Cutting the key form the dot after the identifier
	 */
	keylen = strlen(dbkey);
	REQUIRE(keylen > idends);
	while (dbkey[idends] != '.') {
		idends++;
		INSIST(keylen > idends);
	}

	/*
	 * strtoul stops as soon as it doesn't encounter a non-digit
	 * number, so no need to get an extra buffer, copy the dbkey
	 * and add a null byte after the last digit.
	 */
	id = strtoul(dbkey + idstarts, NULL, 10);
	ENSURE(id > 0);
	return id;
}

isc_result_t
isc_cfgmgr_init(isc_mem_t *mctx, const char *dbpath) {
	int result = ISC_R_SUCCESS;
	char dbname[BUFLEN];
	char dblockname[BUFLEN];
	uint32_t random;

	REQUIRE(ISC_LIST_EMPTY(isc__cfgmgr_ctx.openedclauses));
	REQUIRE(isc__cfgmgr_ctx.prefix == NULL);
	REQUIRE(isc__cfgmgr_ctx.buffer == NULL);
	REQUIRE(isc__cfgmgr_ctx.cursor == NULL);
	REQUIRE(isc__cfgmgr_ctx.txn == NULL);
	REQUIRE(isc__cfgmgr_mctx == NULL);
	REQUIRE(isc__cfgmgr_env == NULL);
	REQUIRE(mctx != NULL);

	isc_mem_attach(mctx, &isc__cfgmgr_mctx);
	INSIST(isc__cfgmgr_mctx != NULL);

	result = mdb_env_create(&isc__cfgmgr_env);
	if (result != 0) {
		result = ISC_R_FAILURE;
		goto cleanup;
	}

	INSIST(isc__cfgmgr_env != NULL);
	random = isc_random32();
	REQUIRE(snprintf(dbname, BUFLEN, "%s-%u", dbpath, random) < BUFLEN);
	REQUIRE(snprintf(dblockname, BUFLEN, "%s-%u-lock", dbpath, random) <
		BUFLEN);

	/*
	 * Using MDB_NOSYNC as it avoids force disk flush after a
	 * transaction. It's quicker and in our case we don't need it
	 * as we delete the only link to the inode right away (so disk
	 * corruption doesn't matter: as soon as the process is dead,
	 * the disk data is dead as well)
	 */
	result = mdb_env_open(isc__cfgmgr_env, dbname,
			      MDB_NOSYNC | MDB_NOSUBDIR, 0600);
	if (result != 0) {
		result = ISC_R_FAILURE;
		goto cleanup;
	}

	remove(dbname);
	remove(dblockname);

	goto out;

cleanup:
	if (isc__cfgmgr_env != NULL) {
		mdb_env_close(isc__cfgmgr_env);
		isc__cfgmgr_env = NULL;
	}

out:
	return result;
}

void
isc_cfgmgr_deinit(void) {
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
	REQUIRE(ISC_LIST_EMPTY(isc__cfgmgr_ctx.openedclauses));
	REQUIRE(isc__cfgmgr_ctx.prefix == NULL);
	REQUIRE(isc__cfgmgr_ctx.buffer == NULL);
	REQUIRE(isc__cfgmgr_ctx.cursor == NULL);
	REQUIRE(isc__cfgmgr_ctx.txn == NULL);
	REQUIRE(isc__cfgmgr_mctx != NULL);
	REQUIRE(isc__cfgmgr_env != NULL);
	mdb_env_close(isc__cfgmgr_env);
	isc__cfgmgr_env = NULL;
	isc_mem_detach(&isc__cfgmgr_mctx);
	INSIST(isc__cfgmgr_mctx == NULL);
}

static void
isc__cfgmgr_buildkey(const char *name, bool trailingdot) {
	size_t written;
	const char *prefix = ISC_LIST_EMPTY(isc__cfgmgr_ctx.openedclauses)
				     ? ""
				     : isc__cfgmgr_ctx.prefix;
	const char *dot = trailingdot ? "." : "";

	REQUIRE(isc__cfgmgr_ctx.buffer != NULL);
	written = snprintf(isc__cfgmgr_ctx.buffer, BUFLEN, "%s%s%s", prefix,
			   name, dot);
	INSIST(written <= BUFLEN);
}

static isc_result_t
isc__cfgmgr_findclause(const char *name, unsigned long *id) {
	isc_result_t result = ISC_R_SUCCESS;
	MDB_val dbkey;
	size_t dotpos = 0;

	REQUIRE(name != NULL);
	REQUIRE(isc__cfgmgr_ctx.buffer != NULL);
	REQUIRE(isc__cfgmgr_ctx.txn != NULL);
	REQUIRE(isc__cfgmgr_ctx.cursor != NULL);

	isc__cfgmgr_buildkey(name, true);
	dotpos = strlen(isc__cfgmgr_ctx.buffer) - 1;
	dbkey = (MDB_val){ .mv_size = strlen(isc__cfgmgr_ctx.buffer) + 1,
			   .mv_data = (char *)isc__cfgmgr_ctx.buffer };

	/*
	 * Let's use LMDB prefix search because the first clause
	 * key/val won't just have the "name.id" prefix, but also the
	 * id and the first property name (so "name.id.prop").
	 */
	if (mdb_cursor_get(isc__cfgmgr_ctx.cursor, &dbkey, NULL,
			   MDB_SET_RANGE) != 0)
	{
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
	*id = isc__cfgmgr_parseid(dbkey.mv_data);

out:
	return result;
}

static void
isc__cfgmgr_updateprefix(void) {
	size_t written = 0;

	REQUIRE(isc__cfgmgr_ctx.prefix != NULL);

	if (ISC_LIST_EMPTY(isc__cfgmgr_ctx.openedclauses)) {
		return;
	}

	for (openedclause_t *clause =
		     ISC_LIST_TAIL(isc__cfgmgr_ctx.openedclauses);
	     clause != NULL; clause = ISC_LIST_PREV(clause, link))
	{
		written += snprintf(isc__cfgmgr_ctx.prefix + written,
				    BUFLEN - written, "%s.%zu.", clause->name,
				    clause->id);
		INSIST(written <= BUFLEN);
	}
}

static void
isc__cfgmgr_pushclause(const char *name, unsigned long id) {
	openedclause_t *clause = isc_mem_get(isc__cfgmgr_mctx, sizeof(*clause));

	*clause = (openedclause_t){
		.name = isc_mem_allocate(isc__cfgmgr_mctx, strlen(name) + 1),
		.id = id,
		.link = ISC_LINK_INITIALIZER,
	};
	strcpy(clause->name, name);
	ENSURE(clause->id > 0);
	ISC_LIST_PREPEND(isc__cfgmgr_ctx.openedclauses, clause, link);
	isc__cfgmgr_updateprefix();
}

static void
isc__cfgmgr_freectx(void) {
	REQUIRE(isc__cfgmgr_ctx.buffer != NULL &&
		isc__cfgmgr_ctx.prefix != NULL);

	isc_mem_free(isc__cfgmgr_mctx, isc__cfgmgr_ctx.buffer);
	isc_mem_free(isc__cfgmgr_mctx, isc__cfgmgr_ctx.prefix);
	isc__cfgmgr_ctx.txn = NULL;
	isc__cfgmgr_ctx.cursor = NULL;
}

static isc_result_t
isc__cfgmgr_starttransaction(bool readonly) {
	MDB_dbi dbi;

	REQUIRE(isc__cfgmgr_env != NULL);
	REQUIRE(isc__cfgmgr_ctx.prefix == NULL);
	REQUIRE(isc__cfgmgr_ctx.buffer == NULL);
	REQUIRE(isc__cfgmgr_ctx.txn == NULL);
	REQUIRE(isc__cfgmgr_ctx.cursor == NULL);

	if (mdb_txn_begin(isc__cfgmgr_env, NULL, readonly ? MDB_RDONLY : 0,
			  &isc__cfgmgr_ctx.txn) != 0)
	{
		goto failure;
	}
	INSIST(isc__cfgmgr_ctx.txn != NULL);

	if (mdb_dbi_open(isc__cfgmgr_ctx.txn, NULL, MDB_CREATE | MDB_DUPSORT,
			 &dbi) != 0)
	{
		goto failure;
	}

	if (mdb_cursor_open(isc__cfgmgr_ctx.txn, dbi,
			    &isc__cfgmgr_ctx.cursor) != 0)
	{
		goto failure;
	}
	INSIST(isc__cfgmgr_ctx.cursor != NULL);
	isc__cfgmgr_ctx.readonly = readonly;
	isc__cfgmgr_ctx.buffer = isc_mem_allocate(isc__cfgmgr_mctx, BUFLEN);
	isc__cfgmgr_ctx.prefix = isc_mem_allocate(isc__cfgmgr_mctx, BUFLEN);

	return ISC_R_SUCCESS;

failure:
	if (isc__cfgmgr_ctx.txn) {
		mdb_txn_abort(isc__cfgmgr_ctx.txn);
		isc__cfgmgr_freectx();
	}
	ENSURE(isc__cfgmgr_ctx.buffer == NULL &&
	       isc__cfgmgr_ctx.prefix == NULL);

	return ISC_R_FAILURE;
}

static isc_result_t
isc__cfgmgr_opentoplevel(const char *name, bool readonly) {
	isc_result_t result = ISC_R_SUCCESS;
	unsigned long id = 0;

	REQUIRE(isc__cfgmgr_env != NULL);
	REQUIRE(name != NULL);
	REQUIRE(ISC_LIST_EMPTY(isc__cfgmgr_ctx.openedclauses));
	REQUIRE(isc__cfgmgr_ctx.prefix == NULL);
	REQUIRE(isc__cfgmgr_ctx.buffer == NULL);
	REQUIRE(isc__cfgmgr_ctx.txn == NULL);
	REQUIRE(isc__cfgmgr_ctx.cursor == NULL);

	/*
	 * We're opening a clause at top-level, so let's start a
	 * transaction
	 */
	result = isc__cfgmgr_starttransaction(readonly);
	if (result != ISC_R_SUCCESS) {
		goto cleanup;
	}

	/*
	 * Now let's try to find the clause...
	 */
	result = isc__cfgmgr_findclause(name, &id);
	if (result != ISC_R_SUCCESS) {
		goto cleanup;
	}

	/*
	 * The clause is found, let's enqueue the clause in
	 * context. the clause is now opened
	 */
	isc__cfgmgr_pushclause(name, id);
	goto out;

cleanup:
	if (isc__cfgmgr_ctx.txn) {
		mdb_txn_abort(isc__cfgmgr_ctx.txn);
		isc__cfgmgr_freectx();
	}

out:
	return result;
}

static isc_result_t
isc__cfgmgr_opennested(const char *name) {
	isc_result_t result = ISC_R_SUCCESS;
	unsigned long id = 0;

	REQUIRE(isc__cfgmgr_env != NULL);
	REQUIRE(name != NULL);
	REQUIRE(ISC_LIST_EMPTY(isc__cfgmgr_ctx.openedclauses) == false);
	REQUIRE(isc__cfgmgr_ctx.prefix != NULL);
	REQUIRE(isc__cfgmgr_ctx.buffer != NULL);
	REQUIRE(isc__cfgmgr_ctx.txn != NULL);
	REQUIRE(isc__cfgmgr_ctx.cursor != NULL);

	result = isc__cfgmgr_findclause(name, &id);
	if (result != ISC_R_SUCCESS) {
		goto out;
	}

	isc__cfgmgr_pushclause(name, id);

out:
	return result;
}

isc_result_t
isc_cfgmgr_openrw(const char *name) {
	return isc__cfgmgr_opentoplevel(name, false);
}

isc_result_t
isc_cfgmgr_open(const char *name) {
	if (ISC_LIST_EMPTY(isc__cfgmgr_ctx.openedclauses)) {
		return isc__cfgmgr_opentoplevel(name, true);
	}

	return isc__cfgmgr_opennested(name);
}

static void
popclause(void) {
	REQUIRE(isc__cfgmgr_env != NULL);
	REQUIRE(ISC_LIST_EMPTY(isc__cfgmgr_ctx.openedclauses) == false);

	openedclause_t *clause = ISC_LIST_HEAD(isc__cfgmgr_ctx.openedclauses);
	ISC_LIST_UNLINK(isc__cfgmgr_ctx.openedclauses, clause, link);
	isc_mem_free(isc__cfgmgr_mctx, clause->name);
	isc_mem_put(isc__cfgmgr_mctx, clause, sizeof(*clause));
	isc__cfgmgr_updateprefix();
}

isc_result_t
isc_cfgmgr_close(void) {
	isc_result_t result = ISC_R_SUCCESS;

	REQUIRE(isc__cfgmgr_env != NULL);
	REQUIRE(ISC_LIST_EMPTY(isc__cfgmgr_ctx.openedclauses) == false);
	REQUIRE(isc__cfgmgr_ctx.prefix != NULL);
	REQUIRE(isc__cfgmgr_ctx.buffer != NULL);
	REQUIRE(isc__cfgmgr_ctx.txn != NULL);
	REQUIRE(isc__cfgmgr_ctx.cursor != NULL);

	popclause();
	if (ISC_LIST_EMPTY(isc__cfgmgr_ctx.openedclauses)) {
		mdb_cursor_close(isc__cfgmgr_ctx.cursor);
		if (mdb_txn_commit(isc__cfgmgr_ctx.txn) != 0) {
			result = ISC_R_FAILURE;
		}
		isc__cfgmgr_freectx();
	}

	return result;
}

isc_result_t
isc_cfgmgr_delclause(void) {
	MDB_val dbkey;

	REQUIRE(isc__cfgmgr_env != NULL);
	REQUIRE(ISC_LIST_EMPTY(isc__cfgmgr_ctx.openedclauses) == false);
	REQUIRE(isc__cfgmgr_ctx.prefix != NULL);
	REQUIRE(isc__cfgmgr_ctx.buffer != NULL);
	REQUIRE(isc__cfgmgr_ctx.txn != NULL);
	REQUIRE(isc__cfgmgr_ctx.cursor != NULL);
	REQUIRE(isc__cfgmgr_ctx.readonly == false);

	dbkey = (MDB_val){ .mv_size = strlen(isc__cfgmgr_ctx.prefix) + 1,
			   .mv_data = isc__cfgmgr_ctx.prefix };
	do {
		/*
		 * even though the key is modified by mdb_cursor_get
		 * on each run (and is the exact current key) we're
		 * good: MDB_SET_RANGE of the current key will point
		 * to the next one with the same prefix as soon it
		 * gets deleted
		 */
		int mdbres = mdb_cursor_get(isc__cfgmgr_ctx.cursor, &dbkey,
					    NULL, MDB_SET_RANGE);
		if (mdbres == MDB_NOTFOUND) {
			break;
		}

		if (strncmp(isc__cfgmgr_ctx.prefix, dbkey.mv_data,
			    strlen(isc__cfgmgr_ctx.prefix)) != 0)
		{
			break;
		}

		/*
		 * NDB_NODUPDATA not strictly needed here, but we
		 * avoid extra iterations if there are lists in the
		 * clause
		 */
		REQUIRE(mdb_cursor_del(isc__cfgmgr_ctx.cursor, MDB_NODUPDATA) ==
			0);
	} while (1);

	return isc_cfgmgr_close();
}

isc_result_t
isc_cfgmgr_newclause(const char *name) {
	isc_result_t result = ISC_R_SUCCESS;

	REQUIRE(name != NULL);
	REQUIRE(isc__cfgmgr_env != NULL);

	if (isc__cfgmgr_ctx.txn == NULL || isc__cfgmgr_ctx.cursor == NULL) {
		result = isc__cfgmgr_starttransaction(false);
	}

	if (result == ISC_R_SUCCESS) {
		INSIST(isc__cfgmgr_ctx.txn != NULL);
		INSIST(isc__cfgmgr_ctx.buffer != NULL);
		INSIST(isc__cfgmgr_ctx.cursor != NULL);
		INSIST(isc__cfgmgr_ctx.readonly == false);
		isc__cfgmgr_pushclause(name, isc_random32());
		INSIST(isc__cfgmgr_ctx.prefix != NULL);
	}

	return result;
}

isc_result_t
isc_cfgmgr_nextclause(void) {
	isc_result_t result = ISC_R_SUCCESS;
	MDB_val dbkey;
	unsigned long id;
	size_t idstarts = 0;
	size_t written = 0;

	REQUIRE(isc__cfgmgr_env != NULL);
	REQUIRE(ISC_LIST_EMPTY(isc__cfgmgr_ctx.openedclauses) == false);
	REQUIRE(isc__cfgmgr_ctx.prefix != NULL);
	REQUIRE(isc__cfgmgr_ctx.buffer != NULL);
	REQUIRE(isc__cfgmgr_ctx.txn != NULL);
	REQUIRE(isc__cfgmgr_ctx.cursor != NULL);

	/*
	 * Let's pick the very next id (even if doesn't exists) of the
	 * current clause
	 */
	id = ISC_LIST_HEAD(isc__cfgmgr_ctx.openedclauses)->id + 1;

	/*
	 * Variant of updateprefix, but this time we put a incremented
	 * key for the currently opened clause. We also keep track of
	 * when the current clause id starts.
	 */
	for (openedclause_t *clause =
		     ISC_LIST_TAIL(isc__cfgmgr_ctx.openedclauses);
	     clause != NULL; clause = ISC_LIST_PREV(clause, link))
	{
		bool last = ISC_LIST_PREV(clause, link) == NULL;

		if (last) {
			idstarts = written + strlen(clause->name) + 1;
		}
		written += snprintf(isc__cfgmgr_ctx.buffer + written,
				    BUFLEN - written, "%s.%zu.", clause->name,
				    last ? id : clause->id);
		INSIST(written <= BUFLEN);
	}
	INSIST(idstarts > 0);
	dbkey = (MDB_val){ .mv_size = strlen(isc__cfgmgr_ctx.buffer) + 1,
			   .mv_data = isc__cfgmgr_ctx.buffer };

	/*
	 * Looking for similar prefix name but with a bigger
	 * id. Thanks for LMDB sort and MDB_SET_RANGE, we'll bump to
	 * the first key/val of the next clause of the same type
	 */
	if (mdb_cursor_get(isc__cfgmgr_ctx.cursor, &dbkey, NULL,
			   MDB_SET_RANGE) != 0)
	{
		result = ISC_R_NOMORE;
		goto out;
	}

	/*
	 * Let's check if next found clause is same name
	 */
	REQUIRE(idstarts < BUFLEN);
	if (strncmp(isc__cfgmgr_ctx.buffer, dbkey.mv_data, idstarts) != 0) {
		result = ISC_R_NOMORE;
		goto out;
	}

	/*
	 * Gets the actual id of the next clause (so let's get rid of
	 * the fake id part from the prefix). Instead of pop/push a
	 * new clause, let's simply replace the id and update the
	 * prefix.
	 */
	isc__cfgmgr_ctx.buffer[idstarts] = 0;
	ISC_LIST_HEAD(isc__cfgmgr_ctx.openedclauses)->id =
		isc__cfgmgr_parseid(dbkey.mv_data);
	isc__cfgmgr_updateprefix();

out:
	return result;
}

static isc_result_t
isc__cfgmgr_getval(const char *name, isc_cfgmgr_val_t *value) {
	isc_result_t result = ISC_R_SUCCESS;
	MDB_val dbkey;
	MDB_val dbval;
	const int opt = name == NULL ? MDB_NEXT_DUP : MDB_SET;

	REQUIRE(isc__cfgmgr_env != NULL);
	REQUIRE(ISC_LIST_EMPTY(isc__cfgmgr_ctx.openedclauses) == false);
	REQUIRE(isc__cfgmgr_ctx.prefix != NULL);
	REQUIRE(isc__cfgmgr_ctx.buffer != NULL);
	REQUIRE(isc__cfgmgr_ctx.txn != NULL);
	REQUIRE(isc__cfgmgr_ctx.cursor != NULL);
	REQUIRE(value != NULL);

	if (name != NULL) {
		isc__cfgmgr_buildkey(name, false);
	}
	dbkey = (MDB_val){
		.mv_size = name == NULL ? 0
					: strlen(isc__cfgmgr_ctx.buffer) + 1,
		.mv_data = name == NULL ? NULL : isc__cfgmgr_ctx.buffer
	};
	if (mdb_cursor_get(isc__cfgmgr_ctx.cursor, &dbkey, &dbval, opt) != 0) {
		result = opt == MDB_NEXT_DUP ? ISC_R_NOMORE : ISC_R_NOTFOUND;
		goto out;
	}

	memcpy(value, dbval.mv_data, sizeof(*value));
	if (value->type == ISC_CFGMGR_STRING) {
		value->string = ((char *)dbval.mv_data) + sizeof(value->type);
	}
	INSIST(value->type != ISC_CFGMGR_UNKNOWN);

out:
	return result;
}

isc_result_t
isc_cfgmgr_getval(const char *name, isc_cfgmgr_val_t *value) {
	return isc__cfgmgr_getval(name, value);
}

isc_result_t
isc_cfgmgr_getnextlistval(isc_cfgmgr_val_t *value) {
	return isc__cfgmgr_getval(NULL, value);
}

static isc_result_t
isc__cfgmgr_setval(const char *name, const isc_cfgmgr_val_t *value, bool list) {
	isc_result_t result = ISC_R_SUCCESS;
	MDB_val dbkey;
	MDB_val dbval;

	REQUIRE(isc__cfgmgr_env != NULL);
	REQUIRE(ISC_LIST_EMPTY(isc__cfgmgr_ctx.openedclauses) == false);
	REQUIRE(isc__cfgmgr_ctx.prefix != NULL);
	REQUIRE(isc__cfgmgr_ctx.buffer != NULL);
	REQUIRE(isc__cfgmgr_ctx.txn != NULL);
	REQUIRE(isc__cfgmgr_ctx.cursor != NULL);
	REQUIRE(isc__cfgmgr_ctx.readonly == false);
	REQUIRE(name != NULL);
	REQUIRE((value != NULL && value->type != ISC_CFGMGR_UNKNOWN) ||
		(value == NULL && list == false));

	isc__cfgmgr_buildkey(name, false);
	dbkey = (MDB_val){ .mv_size = strlen(isc__cfgmgr_ctx.buffer) + 1,
			   .mv_data = isc__cfgmgr_ctx.buffer };
	if (value == NULL) {
		if (mdb_cursor_get(isc__cfgmgr_ctx.cursor, &dbkey, NULL,
				   MDB_SET) == MDB_NOTFOUND)
		{
			result = ISC_R_NOTFOUND;
			goto out;
		}

		REQUIRE(mdb_cursor_del(isc__cfgmgr_ctx.cursor, MDB_NODUPDATA) ==
			0);
		goto out;
	}

	if (value->type == ISC_CFGMGR_STRING) {
		dbval.mv_size = sizeof(*value) + strlen(value->string) + 1;
		dbval.mv_data = isc_mem_allocate(isc__cfgmgr_mctx,
						 dbval.mv_size);
		memcpy(dbval.mv_data, value, sizeof(value->type));
		strcpy(((char *)dbval.mv_data) + sizeof(value->type),
		       value->string);
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
		if (mdb_cursor_get(isc__cfgmgr_ctx.cursor, &dbkey, NULL,
				   MDB_SET) != MDB_NOTFOUND)
		{
			REQUIRE(mdb_cursor_del(isc__cfgmgr_ctx.cursor, 0) == 0);
		}
	}

	REQUIRE(mdb_cursor_put(isc__cfgmgr_ctx.cursor, &dbkey, &dbval, 0) == 0);
	if (value->type == ISC_CFGMGR_STRING) {
		isc_mem_free(isc__cfgmgr_mctx, dbval.mv_data);
	}

out:
	return result;
}

isc_result_t
isc_cfgmgr_setval(const char *name, const isc_cfgmgr_val_t *value) {
	return isc__cfgmgr_setval(name, value, false);
}

isc_result_t
isc_cfgmgr_setnextlistval(const char *name, const isc_cfgmgr_val_t *value) {
	return isc__cfgmgr_setval(name, value, true);
}
