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

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include <lmdb.h>

#include <isc/buffer.h>
#include <isc/cfgmgr.h>
#include <isc/list.h>
#include <isc/mem.h>
#include <isc/random.h>
#include <isc/thread.h>
#include <isc/util.h>

/*
 * See MDB_MAXKEYSIZE documentation, but not accessible as defined in
 * internal implementation. Having key with longer size won't work
 * with LMDB. The value is 511 by default. So this is used to specify LMDB
 * buffer key sizes, as well random temporary buffers when needed.
 */
#define BUFLEN 511

/*
 * Enough room to support big enough error message, especially if there are long
 * domain names in the key
 */
#define LASTERRORLEN 4092

/*
 * Used to list the reference objects to be detached after a rollback (if the
 * object has been added during the transaction) or after the object has been
 * removed/replaced and after a successfully commited transaction.
 */
typedef struct detachref detachref_t;
struct detachref {
	void *ptr;
	void (*detachonsuccess)(void *ptr);
	void (*detachonrollback)(void *ptr);
	ISC_LINK(detachref_t) link;
};

typedef ISC_LIST(detachref_t) detachrefs_t;
static thread_local detachrefs_t isc__cfgmgr_refstodetach;

typedef struct {
	MDB_cursor *builtincursor;
	MDB_cursor *usercursor;
	MDB_cursor *runningcursor;
	MDB_dbi builtindbi;
	MDB_dbi userdbi;
	MDB_dbi runningdbi;
	MDB_txn *txn;
	bool readonly;
	isc_cfgmgr_mode_t mode;
} context_t;

/*
 * No need for atomic: those can be written only early in cfgmgr lifecycle,
 * where only one thread is involved.
 */
static bool isc__cfgmgr_builtininitialized = false;
static bool isc__cfgmgr_userinitialized = false;

static isc_mem_t *isc__cfgmgr_mctx = NULL;
static MDB_env *isc__cfgmgr_env = NULL;
static thread_local context_t isc__cfgmgr_ctx = (context_t){};

/*
 * lasterror is not in the context_t object because it must outlives a
 * transaction (i.e. a commit error occurs, the context is flushed, but user
 * still needs to know what was the error)
 */
static thread_local char isc__cfgmgr_lasterror[LASTERRORLEN];

/*
 * isc_cfgmgr_foreach API is not re-entrant (it was previously, by using its own
 * MDB cursor, but it doesn't seems needed so far).
 */
static thread_local bool isc__cfgmgr_pendingforeach = false;

#define isc__cfgmgr_snprintf(b, blen, fmt, ...) \
	REQUIRE(snprintf(b, blen, fmt, __VA_ARGS__) < (int)blen)

static bool
isc__cfgmgr_openlmdbcursor(const char *dbname, MDB_cursor **cursor,
			   MDB_dbi *dbi, bool readonly) {
	int result;

	result = mdb_dbi_open(isc__cfgmgr_ctx.txn, dbname,
			      readonly ? 0 : MDB_CREATE, dbi);
	if (result != 0) {
		return false;
	}

	result = mdb_cursor_open(isc__cfgmgr_ctx.txn, *dbi, cursor);
	if (result != 0) {
		return false;
	}

	INSIST(*cursor != NULL);
	return true;
}

static void
isc__cfgmgr_closelmdbcursors(void) {
	mdb_cursor_close(isc__cfgmgr_ctx.builtincursor);
	isc__cfgmgr_ctx.builtincursor = NULL;

	mdb_cursor_close(isc__cfgmgr_ctx.usercursor);
	isc__cfgmgr_ctx.usercursor = NULL;

	mdb_cursor_close(isc__cfgmgr_ctx.runningcursor);
	isc__cfgmgr_ctx.runningcursor = NULL;
}

static bool
isc__cfgmgr_startlmdbtransaction(bool readonly) {
	if (mdb_txn_begin(isc__cfgmgr_env, NULL, readonly ? MDB_RDONLY : 0,
			  &isc__cfgmgr_ctx.txn) != 0)
	{
		return false;
	}

	INSIST(isc__cfgmgr_ctx.txn != NULL);

	if (!isc__cfgmgr_openlmdbcursor(
		    "builtin", &isc__cfgmgr_ctx.builtincursor,
		    &isc__cfgmgr_ctx.builtindbi, readonly) ||
	    !isc__cfgmgr_openlmdbcursor("user", &isc__cfgmgr_ctx.usercursor,
					&isc__cfgmgr_ctx.userdbi, readonly) ||
	    !isc__cfgmgr_openlmdbcursor("running",
					&isc__cfgmgr_ctx.runningcursor,
					&isc__cfgmgr_ctx.runningdbi, readonly))
	{
		isc__cfgmgr_closelmdbcursors();
		mdb_txn_abort(isc__cfgmgr_ctx.txn);
		isc__cfgmgr_ctx.txn = NULL;

		return false;
	}

	return true;
}

isc_result_t
isc_cfgmgr_init(isc_mem_t *mctx, const char *dbpath) {
	int result = ISC_R_SUCCESS;
	char dbname[BUFLEN];
	char dblockname[BUFLEN];
	uint32_t random;
	bool persist = getenv("NAMED_CFGMGR_PERSIST") != NULL;
	uint32_t openflags = MDB_NOSUBDIR;

	REQUIRE(isc__cfgmgr_mctx == NULL);
	REQUIRE(isc__cfgmgr_env == NULL);
	REQUIRE(mctx != NULL);
	REQUIRE(dbpath != NULL);
	REQUIRE(!isc__cfgmgr_builtininitialized);
	REQUIRE(!isc__cfgmgr_userinitialized);

	/*
	 * Validate assumptions used when reading/writting data.
	 */
	REQUIRE(sizeof(bool) == sizeof(uint8_t));
	REQUIRE(sizeof(isc_cfgmgr_type_t) == sizeof(uint8_t));

	isc_mem_attach(mctx, &isc__cfgmgr_mctx);
	INSIST(isc__cfgmgr_mctx != NULL);

	result = mdb_env_create(&isc__cfgmgr_env);
	if (result != 0) {
		result = ISC_R_FAILURE;
		goto cleanup;
	}

	INSIST(isc__cfgmgr_env != NULL);
	random = isc_random32();

	/*
	 * Because LMDB also create a <dbname>-lock file, we also need
	 * to build it (even if not passed to LMDB itself) so we can
	 * immediately delete it
	 */
	isc__cfgmgr_snprintf(dbname, BUFLEN, "%s-%" PRIu32, dbpath, random);
	isc__cfgmgr_snprintf(dblockname, BUFLEN, "%s-%" PRIu32 "-lock", dbpath,
			     random);

	result = mdb_env_set_maxdbs(isc__cfgmgr_env, 3);
	if (result != 0) {
		result = ISC_R_FAILURE;
		goto cleanup;
	}

	/*
	 * Using MDB_NOSYNC as it avoids force disk flush after a
	 * transaction. It's quicker and in our case we don't need it
	 * as we delete the only link to the inode right away (so disk
	 * corruption doesn't matter: as soon as the process is dead,
	 * the disk data is dead as well)
	 */
	if (!persist) {
		openflags |= MDB_NOSYNC;
	}
	result = mdb_env_open(isc__cfgmgr_env, dbname, openflags, 0600);
	if (result != 0) {
		result = ISC_R_FAILURE;
		goto cleanup;
	}

	if (!persist) {
		remove(dbname);
		remove(dblockname);
	}

	goto out;

cleanup:
	if (isc__cfgmgr_env != NULL) {
		mdb_env_close(isc__cfgmgr_env);
		isc__cfgmgr_env = NULL;
	}

out:
	isc__cfgmgr_ctx.txn = NULL;
	return result;
}

static void
isc__cfgmgr_requirenotxn(void) {
	REQUIRE(isc__cfgmgr_env != NULL);
	REQUIRE(isc__cfgmgr_ctx.txn == NULL);
	REQUIRE(isc__cfgmgr_ctx.builtincursor == NULL);
	REQUIRE(isc__cfgmgr_ctx.usercursor == NULL);
	REQUIRE(isc__cfgmgr_ctx.runningcursor == NULL);
}

void
isc_cfgmgr_deinit(void) {
	/*
	 * This won't guard agains't opened transaction on a different thread,
	 * so there is still a risk of leak that wouldn't be caught here. Though
	 * a crash would likely come quickly after as using LMDB object when the
	 * environment is closed lead to SIGSEGV (according to the doc).
	 */
	isc__cfgmgr_requirenotxn();

	REQUIRE(isc__cfgmgr_mctx != NULL);
	REQUIRE(isc__cfgmgr_env != NULL);

	mdb_env_close(isc__cfgmgr_env);
	isc__cfgmgr_env = NULL;

	isc_mem_detach(&isc__cfgmgr_mctx);
	INSIST(isc__cfgmgr_mctx == NULL);

	isc__cfgmgr_builtininitialized = false;
	isc__cfgmgr_userinitialized = false;
}

static MDB_cursor *
isc__cfgmgr_dbcursor(void) {
	switch (isc__cfgmgr_ctx.mode) {
	case ISC_CFGMGR_MODEBUILTIN:
		return isc__cfgmgr_ctx.builtincursor;
	case ISC_CFGMGR_MODEUSER:
		return isc__cfgmgr_ctx.usercursor;
	case ISC_CFGMGR_MODERUNNING:
		return isc__cfgmgr_ctx.runningcursor;
	}

	UNREACHABLE();
}

static isc_result_t
isc__cfgmgr_dbget(MDB_cursor *cursor, const char *k, void **v, size_t *vlen) {
	isc_result_t result = ISC_R_NOTFOUND;
	MDB_val dbk = { .mv_size = strlen(k) + 1, .mv_data = (void *)k };
	MDB_val dbv = {};

	REQUIRE(v != NULL && *v == NULL);
	REQUIRE(vlen != NULL);

	if (mdb_cursor_get(cursor, &dbk, &dbv, MDB_SET) == MDB_SUCCESS) {
		*(void **)v = dbv.mv_data;
		*vlen = dbv.mv_size;
		result = ISC_R_SUCCESS;
	}

	return result;
}

static isc_result_t
isc__cfgmgr_dbput(MDB_cursor *cursor, const char *k, void *v, size_t vlen) {
	MDB_val dbk = { .mv_size = strlen(k) + 1, .mv_data = (void *)k };
	MDB_val dbv = { .mv_size = vlen, .mv_data = v };

	if (mdb_cursor_put(cursor, &dbk, &dbv, 0) == MDB_SUCCESS) {
		return ISC_R_SUCCESS;
	}
	return ISC_R_FAILURE;
}

static void
isc__cfgmgr_dbdel(MDB_cursor *cursor) {
	REQUIRE(mdb_cursor_del(cursor, 0) == MDB_SUCCESS);
}

static isc_result_t
isc__cfgmgr_dbgetnext(MDB_cursor *cursor, const char *path,
		      bool (*cb)(void *state, const char *nextkey,
				 size_t nextkeylen, const void *nextval,
				 size_t nextvallen),
		      void *state) {
	int result = ISC_R_NOTFOUND;
	size_t pathlen = strlen(path);
	MDB_val dbk = { .mv_data = (char *)path, .mv_size = pathlen };
	MDB_val dbv = {};
	int flag = MDB_SET_RANGE;

	while (mdb_cursor_get(cursor, &dbk, &dbv, flag) == MDB_SUCCESS) {
		/*
		 * Cursor is now off the range of the path, it's over.
		 */
		if (strncmp(dbk.mv_data, path, pathlen) != 0) {
			break;
		}

		flag = MDB_NEXT;
		result = ISC_R_SUCCESS;
		if (!cb(state, dbk.mv_data, dbk.mv_size, dbv.mv_data,
			dbv.mv_size))
		{
			break;
		}
	}

	return result;
}

static void
isc__cfgmgr_rollbacklmdbtxn(void) {
	isc__cfgmgr_closelmdbcursors();
	mdb_txn_abort(isc__cfgmgr_ctx.txn);
	isc__cfgmgr_ctx.txn = NULL;
}

static void
isc__cfgmgr_setlasterror(const char *fmt, ...) {
	va_list ap;

	va_start(ap, fmt);
	REQUIRE(vsnprintf(isc__cfgmgr_lasterror, BUFLEN, fmt, ap) < BUFLEN);
	va_end(ap);
}

static void
isc__cfgmgr_requiretxn(void) {
	REQUIRE(isc__cfgmgr_env != NULL);
	REQUIRE(isc__cfgmgr_ctx.txn != NULL);
	REQUIRE(isc__cfgmgr_ctx.builtincursor != NULL);
	REQUIRE(isc__cfgmgr_ctx.usercursor != NULL);
	REQUIRE(isc__cfgmgr_ctx.runningcursor != NULL);
}

static void
isc__cfgmgr_requirerotxn(void) {
	isc__cfgmgr_requiretxn();
	REQUIRE(isc__cfgmgr_ctx.readonly);
}

static void
isc__cfgmgr_requirerwtxn(void) {
	isc__cfgmgr_requiretxn();
	REQUIRE(!isc__cfgmgr_ctx.readonly);
}

void
isc_cfgmgr_mode(isc_cfgmgr_mode_t mode) {
	isc__cfgmgr_requirenotxn();

	REQUIRE(isc__cfgmgr_builtininitialized ||
		mode == ISC_CFGMGR_MODEBUILTIN);
	REQUIRE(isc__cfgmgr_userinitialized || mode == ISC_CFGMGR_MODEBUILTIN ||
		mode == ISC_CFGMGR_MODEUSER);

	isc__cfgmgr_ctx.mode = mode;
}

static isc_result_t
isc__cfgmgr_opentransaction(bool readonly) {
	isc__cfgmgr_requirenotxn();
	isc__cfgmgr_setlasterror("");

	if (!isc__cfgmgr_startlmdbtransaction(readonly)) {
		return ISC_R_FAILURE;
	}

	isc__cfgmgr_ctx.readonly = readonly;

	if (readonly) {
		isc__cfgmgr_requirerotxn();
	} else {
		isc__cfgmgr_requirerwtxn();
		ISC_LIST_INIT(isc__cfgmgr_refstodetach);
	}

	return ISC_R_SUCCESS;
}

isc_result_t
isc_cfgmgr_txn(void) {
	REQUIRE(isc__cfgmgr_builtininitialized);
	REQUIRE(isc__cfgmgr_ctx.mode == ISC_CFGMGR_MODEBUILTIN ||
		isc__cfgmgr_userinitialized);

	return isc__cfgmgr_opentransaction(true);
}

void
isc_cfgmgr_closetxn(void) {
	isc__cfgmgr_requirerotxn();
	isc__cfgmgr_rollbacklmdbtxn();
	isc__cfgmgr_requirenotxn();
}

isc_result_t
isc_cfgmgr_rwtxn(void) {
	if (!isc__cfgmgr_builtininitialized) {
		REQUIRE(isc__cfgmgr_ctx.mode == ISC_CFGMGR_MODEBUILTIN);
	} else if (!isc__cfgmgr_userinitialized) {
		REQUIRE(isc__cfgmgr_ctx.mode == ISC_CFGMGR_MODEUSER);
	} else {
		REQUIRE(isc__cfgmgr_ctx.mode == ISC_CFGMGR_MODERUNNING);
	}
	return isc__cfgmgr_opentransaction(false);
}

static bool
isc__cfgmgr_materialize_cb(void *state, const char *nextkey, size_t nextkeylen,
			   const void *nextval, size_t nextvallen) {
	UNUSED(state);
	UNUSED(nextkeylen);
	REQUIRE(isc__cfgmgr_dbput(isc__cfgmgr_ctx.runningcursor, nextkey,
				  (void *)nextval,
				  nextvallen) == ISC_R_SUCCESS);
	return true;
}

static void
isc__cfgmgr_materialize(void) {
	isc__cfgmgr_dbgetnext(isc__cfgmgr_ctx.builtincursor, "/",
			      isc__cfgmgr_materialize_cb, NULL);
	isc__cfgmgr_dbgetnext(isc__cfgmgr_ctx.usercursor, "/",
			      isc__cfgmgr_materialize_cb, NULL);
}

static void
isc__cfgmgr_detachrefs(bool commitsuccess) {
	ISC_LIST_FOREACH(isc__cfgmgr_refstodetach, ref, link) {
		REQUIRE(ref->ptr);

		if (commitsuccess && ref->detachonsuccess) {
			ref->detachonsuccess(ref->ptr);
		} else if (!commitsuccess && ref->detachonrollback) {
			ref->detachonrollback(ref->ptr);
		}

		isc_mem_put(isc__cfgmgr_mctx, ref, sizeof(*ref));
	}
}

isc_result_t
isc_cfgmgr_commit(void) {
	isc_result_t result = ISC_R_SUCCESS;

	isc__cfgmgr_requirerwtxn();

	/* TODO: configuration validation would occurs here */

	/*
	 * Materialization of builtin and user mode into the running mode needs
	 * to occurs when commiting the user mode - as this is now the running
	 * mode will be usable.
	 */
	if (isc__cfgmgr_ctx.mode == ISC_CFGMGR_MODEUSER) {
		isc__cfgmgr_materialize();
	}

	isc__cfgmgr_closelmdbcursors();
	if (mdb_txn_commit(isc__cfgmgr_ctx.txn) != 0) {
		isc__cfgmgr_setlasterror("configuration database error");
		result = ISC_R_FAILURE;
	}
	isc__cfgmgr_ctx.txn = NULL;

	if (isc__cfgmgr_ctx.mode == ISC_CFGMGR_MODEBUILTIN) {
		isc__cfgmgr_builtininitialized = true;
	} else if (isc__cfgmgr_ctx.mode == ISC_CFGMGR_MODEUSER) {
		isc__cfgmgr_userinitialized = true;
	}

	isc__cfgmgr_requirenotxn();
	isc__cfgmgr_detachrefs(result == ISC_R_SUCCESS);
	return result;
}

void
isc_cfgmgr_rollback(void) {
	isc__cfgmgr_requirerwtxn();
	isc__cfgmgr_rollbacklmdbtxn();
	isc__cfgmgr_requirenotxn();
	isc__cfgmgr_detachrefs(false);
}

static size_t
isc__cfgmgr_valuesz(const isc_cfgmgr_val_t *value) {
	size_t sz = sizeof(value->type);

	sz += sizeof(isc_cfgmgr_mode_t);
	switch (value->type) {
	case ISC_CFGMGR_UNDEFINED:
		UNREACHABLE();
	case ISC_CFGMGR_STRING:
		sz += strlen(value->string) + 1;
		break;
	case ISC_CFGMGR_BOOLEAN:
		sz += sizeof(value->boolean);
		break;
	case ISC_CFGMGR_NONE:
		break;
	case ISC_CFGMGR_SOCKADDR:
		sz += sizeof(value->sockaddr);
		break;
	case ISC_CFGMGR_UINT32:
		sz += sizeof(value->uint32);
		break;
	case ISC_CFGMGR_REF:
		/*
		 * Slightly oversized here, as isc_buffer_t takes only 6 bytes
		 * (which is fine as AMD64 store 64bits address on 48 bits).
		 */
		sz += sizeof(uint64_t) * 2;
		break;
	}

	return sz;
}

static void
isc__cfgmgr_requirevalidpath(const char *path, bool hastrailing,
			     bool hasnottrailing) {
	REQUIRE(path != NULL);
	REQUIRE(path[0] == '/');
	REQUIRE(!(hastrailing && hasnottrailing));

	if (hastrailing) {
		REQUIRE(path[strlen(path) - 1] == '/');
	}

	if (hasnottrailing) {
		REQUIRE(path[strlen(path) - 1] != '/');
	}
}

static isc_result_t
isc__cfgmgr_inherit(const char *path, isc_cfgmgr_val_t *value) {
	isc_result_t result = ISC_R_NOTFOUND;
	char viewname[BUFLEN];
	char newpath[BUFLEN];
	const char *p1;
	const char *p2;
	char views[] = "/views/";
	size_t viewslen = sizeof(views) - 1;
	char zones[] = "/zones/";
	size_t zoneslen = sizeof(zones) - 1;

	/* path starts with /views/, p1 points to the view name */
	if (strncmp(views, path, viewslen)) {
		goto out;
	}
	p1 = path + viewslen;
	INSIST(*p1 != 0);

	/* p2 points after the view name */
	p2 = strchr(p1, '/');

	/*
	 * /views/ must be used only to put view instances, so it has to be a
	 * view name, it can't be a leaf
	 */
	INSIST(p2 != NULL);
	*(stpncpy(viewname, p1, p2 - p1)) = 0;

	/*
	 * if p2 is not /zones/, then it's an inheritance of a view prop to the
	 * options
	 */
	if (strncmp(zones, p2, zoneslen)) {
		isc__cfgmgr_snprintf(newpath, sizeof(newpath), "/options/%s",
				     p2 + 1);
		goto read;
	}

	/*
	 * p2 is /zones/. Set the begining of the zone name to p1 and the end of
	 * the zone name of p2. Similarly to /views/, /zones/ must be used only
	 * to put zone instances, so the next label must be a zone name and
	 * can't be a leaf
	 */
	p1 = p2 + zoneslen;
	p2 = strchr(p1 + 1, '/');
	INSIST(*p2 != 0);
	isc__cfgmgr_snprintf(newpath, sizeof(newpath), "/views/%s/%s", viewname,
			     p2 + 1);

read:
	result = isc_cfgmgr_read(newpath, value);
out:
	return result;
}


isc_result_t
isc_cfgmgr_read(const char *path, isc_cfgmgr_val_t *value) {
	isc_result_t result = ISC_R_SUCCESS;
	isc_buffer_t b;
	isc_region_t r;
	void *dbval = NULL;
	size_t dbvalsz = 0;

	isc__cfgmgr_requiretxn();
	isc__cfgmgr_requirevalidpath(path, false, true);
	REQUIRE(value != NULL);

	result = isc__cfgmgr_dbget(isc__cfgmgr_dbcursor(), path, &dbval,
				   &dbvalsz);
	if (result != ISC_R_SUCCESS) {
		result = isc__cfgmgr_inherit(path, value);
		goto out;
	}

	isc_buffer_init(&b, dbval, dbvalsz);
	isc_buffer_add(&b, dbvalsz);

	value->type = isc_buffer_getuint8(&b);
	switch (value->type) {
	case ISC_CFGMGR_UNDEFINED:
		UNREACHABLE();
	case ISC_CFGMGR_STRING:
		isc_buffer_remainingregion(&b, &r);
		value->string = (const char *)r.base;
		break;
	case ISC_CFGMGR_BOOLEAN:
		value->boolean = isc_buffer_getuint8(&b);
		break;
	case ISC_CFGMGR_NONE:
		break;
	case ISC_CFGMGR_SOCKADDR:
		isc_buffer_remainingregion(&b, &r);
		memmove(&value->sockaddr, r.base, r.length);
		break;
	case ISC_CFGMGR_UINT32:
		value->uint32 = isc_buffer_getuint32(&b);
		break;
	case ISC_CFGMGR_REF:
		value->ptr = (void *)isc_buffer_getuint48(&b);
		break;
	}

out:
	return result;
}

isc_result_t
isc_cfgmgr_write(const char *path, const isc_cfgmgr_val_t *value) {
	isc_result_t result = ISC_R_SUCCESS;
	isc_buffer_t b;
	isc_region_t r;
	unsigned char *dbval = NULL;
	size_t dbvalsz;
	void *bdata;
	size_t bdatalen;
	MDB_cursor *dbcursor;

	isc__cfgmgr_requirerwtxn();
	isc__cfgmgr_requirevalidpath(path, false, true);

	dbcursor = isc__cfgmgr_dbcursor();

	result = isc__cfgmgr_dbget(dbcursor, path, (void **)&dbval, &dbvalsz);
	if (result == ISC_R_SUCCESS && *dbval == ISC_CFGMGR_REF) {
		/*
		 * See below: each cfgmgr values _always_ starts with
		 * the value type.
		 */
		detachref_t *ref;
		void *ptr;
		void (*detach)(void *);

		isc_buffer_init(&b, dbval, dbvalsz);
		isc_buffer_add(&b, dbvalsz);

		/*
		 * skip the type
		 */
		(void)isc_buffer_getuint8(&b);

		ptr = (void *)isc_buffer_getuint48(&b);
		detach = (void *)isc_buffer_getuint48(&b);

		/*
		 * Schedule the previous value to be detached from cfgmgr.
		 */
		if (detach) {
			ref = isc_mem_get(isc__cfgmgr_mctx, sizeof(*ref));
			*ref = (detachref_t){ .ptr = ptr,
					       .detachonsuccess = detach,
					       .link = ISC_LINK_INITIALIZER };
			ISC_LIST_APPEND(isc__cfgmgr_refstodetach, ref, link);
		}
	}

	/*
	 * In principle, only `value == NULL` should be needed here. However, we
	 * could imagine the delete API for a reference would take a valid
	 * `value` with a valid `detach` callback, but a NULL `ptr`. This would
	 * avoid having to store the detach functions in cfgmgr (so
	 * responsabiliy would be from the caller to pass those callback when
	 * adding the value in cfgmgr, and removing it)
	 *
	 * For now, let's accept both usage (`dns_view_setacl` actually does
	 * that: passing a non NULL `value` but a NULL `ptr`), and settle down
	 * on the right thing to do once we have more use cases.
	 */
	if (value == NULL ||
	    (value->type == ISC_CFGMGR_REF && value->ptr == NULL))
	{
		if (result == ISC_R_SUCCESS) {
			isc__cfgmgr_dbdel(dbcursor);
		}
		goto out;
	}

	REQUIRE(value->type != ISC_CFGMGR_UNDEFINED);
	if (value->type == ISC_CFGMGR_REF) {
		REQUIRE(value->ptr != NULL);

		/*
		 * The ref type is designed to provide a consistent view
		 * of computed configuration options (i.e., dns_acl_t) - It
		 * doesn't make sense to add then in builtin or user mode (even
		 * though they might be created at that point). They'll be used
		 * only for the running mode.
		 */
		dbcursor = isc__cfgmgr_ctx.runningcursor;

		/*
		 * As soon as cfgmgr knows about a ref value, it needs to attach
		 * it, because the caller doesn't always know when the
		 * transaction is over, and wouldn't be able to manually attach
		 * it in case of success or detach it in case of
		 * rollback/failure. (which cfgmgr takes care of).
		 */
		if (value->attach) {
			value->attach(value->ptr);
		}

		if (value->detach) {
			detachref_t *ref = isc_mem_get(isc__cfgmgr_mctx,
						       sizeof(*ref));
			*ref = (detachref_t){ .ptr = value->ptr,
					      .detachonrollback = value->detach,
					      .link = ISC_LINK_INITIALIZER };
			ISC_LIST_APPEND(isc__cfgmgr_refstodetach, ref, link);
		}
	}

	bdatalen = isc__cfgmgr_valuesz(value);
	bdata = isc_mem_get(isc__cfgmgr_mctx, bdatalen);
	isc_buffer_init(&b, bdata, bdatalen);

	isc_buffer_putuint8(&b, value->type);
	switch (value->type) {
	case ISC_CFGMGR_UNDEFINED:
		UNREACHABLE();
	case ISC_CFGMGR_STRING:
		r.base = (unsigned char *)value->string;
		r.length = strlen(value->string) + 1;
		isc_buffer_copyregion(&b, &r);
		break;
	case ISC_CFGMGR_BOOLEAN:
		isc_buffer_putuint8(&b, value->boolean);
		break;
	case ISC_CFGMGR_NONE:
		break;
	case ISC_CFGMGR_SOCKADDR:
		r.base = (unsigned char *)&value->sockaddr;
		r.length = sizeof(value->sockaddr);
		isc_buffer_copyregion(&b, &r);
		break;
	case ISC_CFGMGR_UINT32:
		isc_buffer_putuint32(&b, value->uint32);
		break;
	case ISC_CFGMGR_REF:
		isc_buffer_putuint48(&b, (uint64_t)value->ptr);
		isc_buffer_putuint48(&b, (uint64_t)value->detach);
		break;
	}

	result = isc__cfgmgr_dbput(dbcursor, path, bdata, bdatalen);
	isc_mem_put(isc__cfgmgr_mctx, bdata, bdatalen);

out:
	return result;
}

static bool
isc__cfgmgr_delete_cb(void *state, const char *nextkey, size_t nextkeylen,
		      const void *nextval, size_t nextvallen) {
	UNUSED(state);
	UNUSED(nextkey);
	UNUSED(nextkeylen);
	UNUSED(nextval);
	UNUSED(nextvallen);
	isc__cfgmgr_dbdel(isc__cfgmgr_dbcursor());
	return true;
}

isc_result_t
isc_cfgmgr_delete(const char *path) {
	isc__cfgmgr_requirerwtxn();
	isc__cfgmgr_requirevalidpath(path, true, false);

	return isc__cfgmgr_dbgetnext(isc__cfgmgr_dbcursor(), path,
				     isc__cfgmgr_delete_cb, NULL);
}

typedef struct {
	const char *path;
	size_t pathlen;
	size_t maxdepth;
	const char *prevkey;
	size_t prevpathlen;
	void *state;
	void (*property)(void *state, const char *name,
			 const isc_cfgmgr_val_t *value);
	void (*labeldown)(void *state, const char *label);
	void (*labelup)(void *state);
	char b[BUFLEN];
	size_t pendinglabelup;
} isc__cfgmgr_foreach_ctx_t;

static bool
isc__cfgmgr_foreach_cb(void *state, const char *nextkey, size_t nextkeylen,
		       const void *nextval, size_t nextvallen) {
	isc__cfgmgr_foreach_ctx_t *ctx = state;
	size_t depth = 0;
	size_t pdiffstarts = 0;
	size_t i = 0;
	size_t nextpathlen = 0;
	isc_cfgmgr_val_t value;
	size_t propnamestarts = 0;
	char *bend;

	UNUSED(nextvallen);
	REQUIRE(nextkey != NULL && nextkeylen > 2);
	REQUIRE(nextkey[nextkeylen - 1] == 0);
	REQUIRE(nextkey[nextkeylen - 2] != '/');

	/*
	 * See isc_cfgmgr_write: each cfgmgr values _always_ starts with
	 * the value type. If the value if a reference, it must be
	 * excluded from the foreach listing because this is not a user
	 * configuration option.
	 */
	bool skipref = getenv("NAMED_CFGMGR_FOREACH_REF") == NULL;
	if ((*(unsigned char *)nextval) == ISC_CFGMGR_REF && skipref) {
		goto nextkey;
	}

	/*
	 * Extract the leaf by finding the index where the path
	 * terminates and also bails out early if the labels goes too
	 * keep.
	 */
	while (i < nextkeylen) {
		if (nextkey[i] == '/') {
			nextpathlen = i;
			propnamestarts = i + 1;
			depth++;
		}

		if (ctx->maxdepth > 0 && depth == ctx->maxdepth) {
			goto nextkey;
		}

		i++;
	}

	/*
	 * Find common path prefix by walking labels forward until a
	 * difference is found between the two paths.
	 */
	pdiffstarts = ctx->pathlen;
	if (ctx->prevkey != NULL) {
		i = ctx->pathlen;

		while (i <= ctx->prevpathlen && i <= nextpathlen &&
		       ctx->prevkey[i] == nextkey[i])
		{
			if (ctx->prevkey[i] == '/') {
				pdiffstarts = i + 1;
			}
			i++;
		}
	}

	/*
	 * Walk labels backwards until the path prefix is reached.
	 * Extract each intermediate labels.
	 */
	if (ctx->prevkey != NULL && ctx->labelup != NULL) {
		i = ctx->prevpathlen;
		while (i > pdiffstarts) {
			if (ctx->prevkey[i] == '/') {
				ctx->labelup(ctx->state);
				ctx->pendinglabelup--;
			}

			if (i == 0) {
				break;
			}
			i--;
		}
	}

	/*
	 * Walk labels forward until the path prefix is reached. Extract
	 * each intermediate labels. If this is the first key being
	 * processed (no prevkey) then walk forward strart from the path
	 * prefix.
	 */
	if (ctx->labeldown != NULL) {
		size_t labelstarts = pdiffstarts;

		i = pdiffstarts + 1;
		while (i <= nextpathlen) {
			if (nextkey[i] == '/') {
				bend = stpncpy(ctx->b, nextkey + labelstarts,
					       i - labelstarts);
				*bend = 0;
				labelstarts = i + 1;
				ctx->labeldown(ctx->state, ctx->b);
				ctx->pendinglabelup++;
			}
			i++;
		}
	}

	if (ctx->property != NULL) {
		REQUIRE(isc_cfgmgr_read(nextkey, &value) == ISC_R_SUCCESS);
		strcpy(ctx->b, nextkey + propnamestarts);
		ctx->property(ctx->state, ctx->b, &value);
	}

nextkey:
	ctx->prevpathlen = nextpathlen;
	ctx->prevkey = nextkey;
	return true;
}

void
isc_cfgmgr_foreach(const char *path, size_t maxdepth, void *state,
		   void (*property)(void *state, const char *name,
				    const isc_cfgmgr_val_t *value),
		   void (*labeldown)(void *state, const char *label),
		   void (*labelup)(void *state)) {
	isc__cfgmgr_foreach_ctx_t ctx = { .path = path,
					  .pathlen = strlen(path),
					  .maxdepth = maxdepth,
					  .state = state,
					  .property = property,
					  .labeldown = labeldown,
					  .labelup = labelup };

	isc__cfgmgr_requiretxn();
	isc__cfgmgr_requirevalidpath(path, true, false);
	REQUIRE(isc__cfgmgr_pendingforeach == false);

	isc__cfgmgr_pendingforeach = true;
	isc__cfgmgr_dbgetnext(isc__cfgmgr_dbcursor(), path,
			      isc__cfgmgr_foreach_cb, &ctx);
	while (ctx.pendinglabelup > 0 && labelup) {
		labelup(state);
		ctx.pendinglabelup--;
	}
	isc__cfgmgr_pendingforeach = false;
}

const char *
isc_cfgmgr_lasterror(void) {
	return isc__cfgmgr_lasterror;
}
