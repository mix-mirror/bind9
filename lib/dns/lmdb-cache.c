/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * SPDX-License-Identifier: MPL-2.0
 */

#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <lmdb.h>

#include <isc/file.h>
#include <isc/mem.h>
#include <isc/mutex.h>
#include <isc/urcu.h>
#include <isc/util.h>

#include <dns/result.h>

#include "lmdb-cache_p.h"

#define LMDBCACHE_MAGIC ISC_MAGIC('L', 'M', 'D', 'C')
#define LMDBTXN_MAGIC   ISC_MAGIC('L', 'M', 'D', 'T')
#define LMDBITER_MAGIC  ISC_MAGIC('L', 'M', 'D', 'I')
#define LMDBCHAIN_MAGIC ISC_MAGIC('L', 'M', 'D', 'H')

typedef struct lmdb_value {
	uintptr_t pval;
	uint32_t ival;
} lmdb_value_t;

typedef struct lmdb_change lmdb_change_t;
struct lmdb_change {
	lmdb_change_t *next;
	lmdb_value_t value;
};

struct dns_lmdbcache {
	unsigned int magic;
	isc_mem_t *mctx;
	MDB_env *env;
	MDB_dbi dbi;
	MDB_dbi rrsets;
	char *path;
	const dns_qpmethods_t *methods;
	void *uctx;
	isc_mutex_t lock;
	unsigned int snapshots;
	lmdb_change_t *retired;
	unsigned char rrhand[sizeof(dns_qpkey_t) + sizeof(uint32_t)];
	size_t rrhand_length;
};

struct dns_lmdbtxn {
	unsigned int magic;
	dns_lmdbcache_t *cache;
	MDB_txn *txn;
	bool readonly;
	bool rcu_locked;
	lmdb_change_t *inserted;
	lmdb_change_t *deleted;
};

struct dns_lmdbsnap {
	dns_lmdbtxn_t txn;
};

static isc_result_t
lmdb_result(int status) {
	switch (status) {
	case MDB_SUCCESS:
		return ISC_R_SUCCESS;
	case MDB_NOTFOUND:
		return ISC_R_NOTFOUND;
	case MDB_KEYEXIST:
		return ISC_R_EXISTS;
	case ENOMEM:
		return ISC_R_NOMEMORY;
	case ENOSPC:
	case MDB_MAP_FULL:
		return ISC_R_NOSPACE;
	default:
		return ISC_R_FAILURE;
	}
}

static void
set_value(const MDB_val *data, void **pvalp, uint32_t *ivalp) {
	REQUIRE(data->mv_size == sizeof(lmdb_value_t));
	lmdb_value_t value;
	memmove(&value, data->mv_data, sizeof(value));
	SET_IF_NOT_NULL(pvalp, (void *)value.pval);
	SET_IF_NOT_NULL(ivalp, value.ival);
}

static MDB_val
make_key(const dns_name_t *name, dns_namespace_t space, dns_qpkey_t key) {
	size_t len = dns_qpkey_fromname(key, name, space);
	return (MDB_val){ .mv_size = len, .mv_data = key };
}

typedef unsigned char lmdb_rrkey_t[sizeof(dns_qpkey_t) + sizeof(uint32_t)];

static MDB_val
make_rrkey(const dns_name_t *name, dns_namespace_t space,
	   dns_typepair_t typepair, lmdb_rrkey_t key) {
	dns_qpkey_t namekey;
	size_t len = dns_qpkey_fromname(namekey, name, space);
	memmove(key, namekey, len);

	/* Network byte order keeps typepairs ordered and avoids alignment
	 * assumptions when LMDB compares keys. */
	key[len++] = (uint8_t)(typepair >> 24);
	key[len++] = (uint8_t)(typepair >> 16);
	key[len++] = (uint8_t)(typepair >> 8);
	key[len++] = (uint8_t)typepair;
	return (MDB_val){ .mv_size = len, .mv_data = key };
}

static uint64_t
hash_rrkey(const void *data, size_t length) {
	const uint8_t *key = data;
	uint64_t hash = UINT64_C(1469598103934665603);
	for (size_t i = 0; i < length; i++) {
		hash ^= key[i];
		hash *= UINT64_C(1099511628211);
	}
	hash ^= hash >> 32;
	return hash & ~UINT64_C(1);
}

uint64_t
dns_lmdb_rrsethash(const dns_name_t *name, dns_namespace_t space,
		   dns_typepair_t typepair) {
	lmdb_rrkey_t keybuf;
	MDB_val key = make_rrkey(name, space, typepair, keybuf);
	return hash_rrkey(key.mv_data, key.mv_size);
}

static lmdb_change_t *
new_change(dns_lmdbtxn_t *txn, const lmdb_value_t *value) {
	lmdb_change_t *change = isc_mem_get(txn->cache->mctx, sizeof(*change));
	*change = (lmdb_change_t){ .value = *value };
	return change;
}

static void
free_changes(dns_lmdbcache_t *cache, lmdb_change_t **listp, bool detach) {
	lmdb_change_t *change = *listp;
	while (change != NULL) {
		lmdb_change_t *next = change->next;
		if (detach) {
			cache->methods->detach(cache->uctx,
					       (void *)change->value.pval,
					       change->value.ival);
		}
		isc_mem_put(cache->mctx, change, sizeof(*change));
		change = next;
	}
	*listp = NULL;
}

static void
retire_changes(dns_lmdbcache_t *cache, lmdb_change_t **listp) {
	lmdb_change_t *list = *listp;
	if (list == NULL) {
		return;
	}

	/* Regular lookups protect the pointer-to-node handoff with QSBR. */
	synchronize_rcu();

	LOCK(&cache->lock);
	if (cache->snapshots == 0) {
		UNLOCK(&cache->lock);
		free_changes(cache, &list, true);
	} else {
		lmdb_change_t *tail = list;
		while (tail->next != NULL) {
			tail = tail->next;
		}
		tail->next = cache->retired;
		cache->retired = list;
		UNLOCK(&cache->lock);
	}
	*listp = NULL;
}

void
dns_lmdbcache_create(isc_mem_t *mctx, const dns_qpmethods_t *methods,
		     void *uctx, dns_lmdbcache_t **cachep) {
	REQUIRE(mctx != NULL);
	REQUIRE(methods != NULL);
	REQUIRE(cachep != NULL && *cachep == NULL);

	dns_lmdbcache_t *cache = isc_mem_get(mctx, sizeof(*cache));
	*cache = (dns_lmdbcache_t){
		.magic = LMDBCACHE_MAGIC,
		.methods = methods,
		.uctx = uctx,
	};
	isc_mem_attach(mctx, &cache->mctx);
	isc_mutex_init(&cache->lock);

	char template[] = "/tmp/bind-lmdb-cache-XXXXXX";
	int fd = mkstemp(template);
	RUNTIME_CHECK(fd >= 0);
	RUNTIME_CHECK(close(fd) == 0);
	cache->path = isc_mem_strdup(mctx, template);

	RUNTIME_CHECK(mdb_env_create(&cache->env) == MDB_SUCCESS);
	/* Sparse virtual mapping; cache contents are disposable. */
	RUNTIME_CHECK(mdb_env_set_mapsize(cache->env, (size_t)16 << 30) ==
		      MDB_SUCCESS);
	RUNTIME_CHECK(mdb_env_set_maxreaders(cache->env, 1024) == MDB_SUCCESS);
	RUNTIME_CHECK(mdb_env_set_maxdbs(cache->env, 2) == MDB_SUCCESS);
	unsigned int flags = MDB_NOSUBDIR | MDB_NOTLS | MDB_WRITEMAP |
			     MDB_MAPASYNC;
	RUNTIME_CHECK(mdb_env_open(cache->env, cache->path, flags, 0600) ==
		      MDB_SUCCESS);

	MDB_txn *txn = NULL;
	RUNTIME_CHECK(mdb_txn_begin(cache->env, NULL, 0, &txn) == MDB_SUCCESS);
	RUNTIME_CHECK(mdb_dbi_open(txn, "nodes", MDB_CREATE, &cache->dbi) ==
		      MDB_SUCCESS);
	RUNTIME_CHECK(mdb_dbi_open(txn, "rrsets", MDB_CREATE, &cache->rrsets) ==
		      MDB_SUCCESS);
	RUNTIME_CHECK(mdb_txn_commit(txn) == MDB_SUCCESS);
	*cachep = cache;
}

void
dns_lmdbcache_destroy(dns_lmdbcache_t **cachep) {
	REQUIRE(cachep != NULL && *cachep != NULL);
	dns_lmdbcache_t *cache = *cachep;
	REQUIRE(ISC_MAGIC_VALID(cache, LMDBCACHE_MAGIC));

	/* Release the index's reference to every remaining node. */
	MDB_txn *txn = NULL;
	MDB_cursor *cursor = NULL;
	if (mdb_txn_begin(cache->env, NULL, MDB_RDONLY, &txn) == MDB_SUCCESS &&
	    mdb_cursor_open(txn, cache->dbi, &cursor) == MDB_SUCCESS)
	{
		MDB_val key, data;
		for (int status = mdb_cursor_get(cursor, &key, &data, MDB_FIRST);
		     status == MDB_SUCCESS;
		     status = mdb_cursor_get(cursor, &key, &data, MDB_NEXT))
		{
			lmdb_value_t value;
			memmove(&value, data.mv_data, sizeof(value));
			cache->methods->detach(cache->uctx, (void *)value.pval,
					       value.ival);
		}
	}
	if (cursor != NULL) {
		mdb_cursor_close(cursor);
	}
	if (txn != NULL) {
		mdb_txn_abort(txn);
	}
	free_changes(cache, &cache->retired, true);

	mdb_dbi_close(cache->env, cache->dbi);
	mdb_dbi_close(cache->env, cache->rrsets);
	mdb_env_close(cache->env);
	(void)unlink(cache->path);
	char *lockpath = isc_mem_get(cache->mctx, strlen(cache->path) + 6);
	sprintf(lockpath, "%s-lock", cache->path);
	(void)unlink(lockpath);
	isc_mem_put(cache->mctx, lockpath, strlen(cache->path) + 6);
	isc_mem_free(cache->mctx, cache->path);
	isc_mutex_destroy(&cache->lock);
	cache->magic = 0;
	isc_mem_t *mctx = cache->mctx;
	isc_mem_put(mctx, cache, sizeof(*cache));
	isc_mem_detach(&mctx);
	*cachep = NULL;
}

static dns_lmdbtxn_t *
begin_txn(dns_lmdbcache_t *cache, bool readonly, bool rcu) {
	dns_lmdbtxn_t *txn = isc_mem_get(cache->mctx, sizeof(*txn));
	*txn = (dns_lmdbtxn_t){
		.magic = LMDBTXN_MAGIC,
		.cache = cache,
		.readonly = readonly,
		.rcu_locked = rcu,
	};
	if (rcu) {
		rcu_read_lock();
	}
	RUNTIME_CHECK(mdb_txn_begin(cache->env, NULL,
				    readonly ? MDB_RDONLY : 0, &txn->txn) ==
		      MDB_SUCCESS);
	return txn;
}

void
dns_lmdbcache_query(dns_lmdbcache_t *cache, dns_lmdbtxn_t **txnp) {
	REQUIRE(txnp != NULL && *txnp == NULL);
	*txnp = begin_txn(cache, true, false);
}

void
dns_lmdbtxn_destroy(dns_lmdbcache_t *cache, dns_lmdbtxn_t **txnp) {
	REQUIRE(txnp != NULL && *txnp != NULL);
	dns_lmdbtxn_t *txn = *txnp;
	REQUIRE(txn->cache == cache && txn->readonly);
	mdb_txn_abort(txn->txn);
	if (txn->rcu_locked) {
		rcu_read_unlock();
	}
	txn->magic = 0;
	isc_mem_put(cache->mctx, txn, sizeof(*txn));
	*txnp = NULL;
}

void
dns_lmdbcache_write(dns_lmdbcache_t *cache, dns_lmdbtxn_t **txnp) {
	REQUIRE(txnp != NULL && *txnp == NULL);
	*txnp = begin_txn(cache, false, false);
}

void
dns_lmdbcache_commit(dns_lmdbcache_t *cache, dns_lmdbtxn_t **txnp) {
	REQUIRE(txnp != NULL && *txnp != NULL);
	dns_lmdbtxn_t *txn = *txnp;
	REQUIRE(txn->cache == cache && !txn->readonly);
	int status = mdb_txn_commit(txn->txn);
	if (status == MDB_SUCCESS) {
		free_changes(cache, &txn->inserted, false);
		retire_changes(cache, &txn->deleted);
	} else {
		free_changes(cache, &txn->inserted, true);
		free_changes(cache, &txn->deleted, false);
	}
	txn->magic = 0;
	isc_mem_put(cache->mctx, txn, sizeof(*txn));
	*txnp = NULL;
	RUNTIME_CHECK(status == MDB_SUCCESS);
}

isc_result_t
dns_lmdbcache_clear(dns_lmdbtxn_t *txn) {
	REQUIRE(!txn->readonly);

	/* Preserve the node DB's ownership accounting across mdb_drop(). */
	MDB_cursor *cursor = NULL;
	int status = mdb_cursor_open(txn->txn, txn->cache->dbi, &cursor);
	if (status != MDB_SUCCESS) {
		return lmdb_result(status);
	}
	MDB_val key, data;
	for (status = mdb_cursor_get(cursor, &key, &data, MDB_FIRST);
	     status == MDB_SUCCESS;
	     status = mdb_cursor_get(cursor, &key, &data, MDB_NEXT))
	{
		lmdb_value_t value;
		memmove(&value, data.mv_data, sizeof(value));
		lmdb_change_t *change = new_change(txn, &value);
		change->next = txn->deleted;
		txn->deleted = change;
	}
	mdb_cursor_close(cursor);
	if (status != MDB_NOTFOUND) {
		return lmdb_result(status);
	}

	status = mdb_drop(txn->txn, txn->cache->dbi, 0);
	if (status == MDB_SUCCESS) {
		status = mdb_drop(txn->txn, txn->cache->rrsets, 0);
	}
	if (status == MDB_SUCCESS) {
		txn->cache->rrhand_length = 0;
	}
	return lmdb_result(status);
}

void
dns_lmdbcache_snapshot(dns_lmdbcache_t *cache, dns_lmdbsnap_t **snapp) {
	REQUIRE(snapp != NULL && *snapp == NULL);
	dns_lmdbsnap_t *snap = isc_mem_get(cache->mctx, sizeof(*snap));
	LOCK(&cache->lock);
	cache->snapshots++;
	UNLOCK(&cache->lock);
	snap->txn = (dns_lmdbtxn_t){
		.magic = LMDBTXN_MAGIC,
		.cache = cache,
		.readonly = true,
	};
	RUNTIME_CHECK(mdb_txn_begin(cache->env, NULL, MDB_RDONLY,
				    &snap->txn.txn) == MDB_SUCCESS);
	*snapp = snap;
}

void
dns_lmdbsnap_destroy(dns_lmdbcache_t *cache, dns_lmdbsnap_t **snapp) {
	REQUIRE(snapp != NULL && *snapp != NULL);
	dns_lmdbsnap_t *snap = *snapp;
	mdb_txn_abort(snap->txn.txn);
	lmdb_change_t *retired = NULL;
	LOCK(&cache->lock);
	INSIST(cache->snapshots > 0);
	if (--cache->snapshots == 0) {
		retired = cache->retired;
		cache->retired = NULL;
	}
	UNLOCK(&cache->lock);
	free_changes(cache, &retired, true);
	isc_mem_put(cache->mctx, snap, sizeof(*snap));
	*snapp = NULL;
}

dns_lmdbtxn_t *
dns_lmdbsnap_txn(dns_lmdbsnap_t *snap) {
	return &snap->txn;
}

isc_result_t
dns_lmdb_getname(dns_lmdbtxn_t *txn, const dns_name_t *name,
		 dns_namespace_t space, void **pvalp, uint32_t *ivalp) {
	dns_qpkey_t keybuf;
	MDB_val key = make_key(name, space, keybuf), data;
	int status = mdb_get(txn->txn, txn->cache->dbi, &key, &data);
	if (status == MDB_SUCCESS) {
		set_value(&data, pvalp, ivalp);
	}
	return lmdb_result(status);
}

static void
iter_position(dns_lmdbtxn_t *txn, dns_lmdbiter_t *iter, const MDB_val *search) {
	*iter = (dns_lmdbiter_t){
		.magic = LMDBITER_MAGIC,
		.txn = txn,
	};
	MDB_cursor *cursor = NULL;
	RUNTIME_CHECK(mdb_cursor_open(txn->txn, txn->cache->dbi, &cursor) ==
		      MDB_SUCCESS);
	iter->cursor = cursor;
	MDB_val key = *search, data;
	int status = mdb_cursor_get(cursor, &key, &data, MDB_SET_RANGE);
	if (status == MDB_NOTFOUND) {
		status = mdb_cursor_get(cursor, &key, &data, MDB_LAST);
	} else if (status == MDB_SUCCESS &&
		   (key.mv_size != search->mv_size ||
		    memcmp(key.mv_data, search->mv_data, key.mv_size) != 0))
	{
		status = mdb_cursor_get(cursor, &key, &data, MDB_PREV);
	}
	iter->positioned = status == MDB_SUCCESS;
}

isc_result_t
dns_lmdb_lookup(dns_lmdbtxn_t *txn, const dns_name_t *name,
		dns_namespace_t space, dns_lmdbiter_t *iter,
		dns_lmdbchain_t *chain, void **pvalp, uint32_t *ivalp) {
	dns_qpkey_t keybuf;
	MDB_val fullkey = make_key(name, space, keybuf);
	if (iter != NULL) {
		iter_position(txn, iter, &fullkey);
	}
	dns_lmdbchain_t localchain = { 0 };
	if (chain == NULL) {
		chain = &localchain;
	}
	*chain = (dns_lmdbchain_t){ .magic = LMDBCHAIN_MAGIC };
	bool exact = false;

	/* QP keys encode labels root-first, so every label boundary is an
	 * exact ancestor key. */
	for (size_t len = 2; len <= fullkey.mv_size; len++) {
		if (keybuf[len - 1] != keybuf[1]) {
			continue;
		}
		MDB_val key = { .mv_size = len, .mv_data = keybuf }, data;
		if (mdb_get(txn->txn, txn->cache->dbi, &key, &data) != MDB_SUCCESS) {
			continue;
		}
		INSIST(chain->len < DNS_NAME_MAXLABELS);
		lmdb_value_t value;
		memmove(&value, data.mv_data, sizeof(value));
		chain->chain[chain->len++] = (typeof(chain->chain[0])){
			.pval = (void *)value.pval,
			.ival = value.ival,
		};
		exact = len == fullkey.mv_size;
	}
	if (chain->len == 0) {
		return ISC_R_NOTFOUND;
	}
	void *pval = chain->chain[chain->len - 1].pval;
	uint32_t ival = chain->chain[chain->len - 1].ival;
	SET_IF_NOT_NULL(pvalp, pval);
	SET_IF_NOT_NULL(ivalp, ival);
	return exact ? ISC_R_SUCCESS : DNS_R_PARTIALMATCH;
}

isc_result_t
dns_lmdb_insert(dns_lmdbtxn_t *txn, void *pval, uint32_t ival) {
	REQUIRE(!txn->readonly);
	dns_qpkey_t keybuf;
	size_t keylen = txn->cache->methods->makekey(
		keybuf, txn->cache->uctx, pval, ival);
	MDB_val key = { .mv_size = keylen, .mv_data = keybuf };
	lmdb_value_t value = { .pval = (uintptr_t)pval, .ival = ival };
	MDB_val data = { .mv_size = sizeof(value), .mv_data = &value };
	int status = mdb_put(txn->txn, txn->cache->dbi, &key, &data,
			     MDB_NOOVERWRITE);
	if (status == MDB_SUCCESS) {
		txn->cache->methods->attach(txn->cache->uctx, pval, ival);
		lmdb_change_t *change = new_change(txn, &value);
		change->next = txn->inserted;
		txn->inserted = change;
	}
	return lmdb_result(status);
}

isc_result_t
dns_lmdb_deletename(dns_lmdbtxn_t *txn, const dns_name_t *name,
		    dns_namespace_t space, void **pvalp, uint32_t *ivalp) {
	REQUIRE(!txn->readonly);
	dns_qpkey_t keybuf;
	MDB_val key = make_key(name, space, keybuf), data;
	int status = mdb_get(txn->txn, txn->cache->dbi, &key, &data);
	if (status != MDB_SUCCESS) {
		return lmdb_result(status);
	}
	lmdb_value_t value;
	memmove(&value, data.mv_data, sizeof(value));
	status = mdb_del(txn->txn, txn->cache->dbi, &key, NULL);
	if (status == MDB_SUCCESS) {
		SET_IF_NOT_NULL(pvalp, (void *)value.pval);
		SET_IF_NOT_NULL(ivalp, value.ival);
		lmdb_change_t *change = new_change(txn, &value);
		change->next = txn->deleted;
		txn->deleted = change;
	}
	return lmdb_result(status);
}

isc_result_t
dns_lmdb_getrrset(dns_lmdbtxn_t *txn, const dns_name_t *name,
		  dns_namespace_t space, dns_typepair_t typepair,
		  isc_region_t *value) {
	lmdb_rrkey_t keybuf;
	MDB_val key = make_rrkey(name, space, typepair, keybuf), data;
	int status = mdb_get(txn->txn, txn->cache->rrsets, &key, &data);
	if (status == MDB_SUCCESS) {
		INSIST(data.mv_size <= UINT_MAX);
		*value = (isc_region_t){
			.base = data.mv_data,
			.length = data.mv_size,
		};
	}
	return lmdb_result(status);
}

isc_result_t
dns_lmdb_putrrset(dns_lmdbtxn_t *txn, const dns_name_t *name,
		  dns_namespace_t space, dns_typepair_t typepair,
		  const isc_region_t *value, bool replace) {
	REQUIRE(!txn->readonly);
	lmdb_rrkey_t keybuf;
	MDB_val key = make_rrkey(name, space, typepair, keybuf);
	MDB_val data = { .mv_size = value->length, .mv_data = value->base };
	int status = mdb_put(txn->txn, txn->cache->rrsets, &key, &data,
			     replace ? 0 : MDB_NOOVERWRITE);
	return lmdb_result(status);
}

isc_result_t
dns_lmdb_deleterrset(dns_lmdbtxn_t *txn, const dns_name_t *name,
		     dns_namespace_t space, dns_typepair_t typepair) {
	REQUIRE(!txn->readonly);
	lmdb_rrkey_t keybuf;
	MDB_val key = make_rrkey(name, space, typepair, keybuf);
	int status = mdb_del(txn->txn, txn->cache->rrsets, &key, NULL);
	return lmdb_result(status);
}

isc_result_t
dns_lmdb_deleteallrrsets(dns_lmdbtxn_t *txn, const dns_name_t *name,
			 dns_namespace_t space) {
	REQUIRE(!txn->readonly);
	dns_qpkey_t prefixbuf;
	MDB_val prefix = make_key(name, space, prefixbuf);
	MDB_cursor *cursor = NULL;
	int status = mdb_cursor_open(txn->txn, txn->cache->rrsets, &cursor);
	if (status != MDB_SUCCESS) {
		return lmdb_result(status);
	}

	MDB_val key = prefix, data;
	status = mdb_cursor_get(cursor, &key, &data, MDB_SET_RANGE);
	bool deleted = false;
	while (status == MDB_SUCCESS &&
	       key.mv_size == prefix.mv_size + sizeof(uint32_t) &&
	       memcmp(key.mv_data, prefix.mv_data, prefix.mv_size) == 0)
	{
		status = mdb_cursor_del(cursor, 0);
		if (status != MDB_SUCCESS) {
			break;
		}
		deleted = true;
		status = mdb_cursor_get(cursor, &key, &data, MDB_NEXT);
	}
	mdb_cursor_close(cursor);
	return status == MDB_SUCCESS || status == MDB_NOTFOUND
		       ? (deleted ? ISC_R_SUCCESS : ISC_R_NOTFOUND)
		       : lmdb_result(status);
}

isc_result_t
dns_lmdb_foreachrrset(dns_lmdbtxn_t *txn, const dns_name_t *name,
		      dns_namespace_t space, dns_lmdb_rrset_cb_t cb,
		      void *arg) {
	dns_qpkey_t prefixbuf;
	MDB_val prefix = make_key(name, space, prefixbuf);
	MDB_cursor *cursor = NULL;
	int status = mdb_cursor_open(txn->txn, txn->cache->rrsets, &cursor);
	if (status != MDB_SUCCESS) {
		return lmdb_result(status);
	}

	MDB_val key = prefix, data;
	status = mdb_cursor_get(cursor, &key, &data, MDB_SET_RANGE);
	isc_result_t result = ISC_R_NOTFOUND;
	while (status == MDB_SUCCESS &&
	       key.mv_size == prefix.mv_size + sizeof(uint32_t) &&
	       memcmp(key.mv_data, prefix.mv_data, prefix.mv_size) == 0)
	{
		const uint8_t *suffix = (const uint8_t *)key.mv_data + prefix.mv_size;
		dns_typepair_t typepair = ((dns_typepair_t)suffix[0] << 24) |
					  ((dns_typepair_t)suffix[1] << 16) |
					  ((dns_typepair_t)suffix[2] << 8) |
					  suffix[3];
		INSIST(data.mv_size <= UINT_MAX);
		isc_region_t value = {
			.base = data.mv_data,
			.length = data.mv_size,
		};
		result = cb(typepair, &value, arg);
		if (result != ISC_R_SUCCESS) {
			break;
		}
		status = mdb_cursor_get(cursor, &key, &data, MDB_NEXT);
	}
	mdb_cursor_close(cursor);
	return result;
}

bool
dns_lmdb_hasrrsets(dns_lmdbtxn_t *txn, const dns_name_t *name,
		   dns_namespace_t space) {
	dns_qpkey_t prefixbuf;
	MDB_val prefix = make_key(name, space, prefixbuf);
	MDB_cursor *cursor = NULL;
	if (mdb_cursor_open(txn->txn, txn->cache->rrsets, &cursor) !=
	    MDB_SUCCESS)
	{
		return false;
	}
	MDB_val key = prefix, data;
	int status = mdb_cursor_get(cursor, &key, &data, MDB_SET_RANGE);
	bool found = status == MDB_SUCCESS &&
		     key.mv_size == prefix.mv_size + sizeof(uint32_t) &&
		     memcmp(key.mv_data, prefix.mv_data, prefix.mv_size) == 0;
	mdb_cursor_close(cursor);
	return found;
}

isc_result_t
dns_lmdb_sweeprrsets(dns_lmdbtxn_t *txn, size_t budget,
		     dns_lmdb_sweep_cb_t cb, void *arg, size_t *deletedp) {
	REQUIRE(!txn->readonly);
	REQUIRE(cb != NULL);
	MDB_cursor *cursor = NULL;
	int status = mdb_cursor_open(txn->txn, txn->cache->rrsets, &cursor);
	if (status != MDB_SUCCESS) {
		return lmdb_result(status);
	}

	size_t visited = 0, deleted = 0;
	MDB_val key = {
		.mv_size = txn->cache->rrhand_length,
		.mv_data = txn->cache->rrhand,
	};
	MDB_val data;
	if (key.mv_size == 0) {
		status = mdb_cursor_get(cursor, &key, &data, MDB_FIRST);
	} else {
		status = mdb_cursor_get(cursor, &key, &data, MDB_SET_RANGE);
		if (status == MDB_SUCCESS &&
		    key.mv_size == txn->cache->rrhand_length &&
		    memcmp(key.mv_data, txn->cache->rrhand, key.mv_size) == 0)
		{
			status = mdb_cursor_get(cursor, &key, &data, MDB_NEXT);
		}
	}
	while (status == MDB_SUCCESS && visited++ < budget) {
		INSIST(key.mv_size <= sizeof(txn->cache->rrhand));
		memmove(txn->cache->rrhand, key.mv_data, key.mv_size);
		txn->cache->rrhand_length = key.mv_size;
		INSIST(data.mv_size <= UINT_MAX);
		isc_region_t value = {
			.base = data.mv_data,
			.length = data.mv_size,
		};
		if (cb(hash_rrkey(key.mv_data, key.mv_size), &value, arg)) {
			status = mdb_cursor_del(cursor, 0);
			if (status != MDB_SUCCESS) {
				break;
			}
			deleted++;
		}
		status = mdb_cursor_get(cursor, &key, &data, MDB_NEXT);
	}
	if (status == MDB_NOTFOUND) {
		txn->cache->rrhand_length = 0;
	}
	mdb_cursor_close(cursor);
	SET_IF_NOT_NULL(deletedp, deleted);
	return status == MDB_SUCCESS || status == MDB_NOTFOUND
		       ? ISC_R_SUCCESS
		       : lmdb_result(status);
}

isc_result_t
dns_lmdb_predecessor(dns_lmdbtxn_t *txn, const dns_name_t *name,
		     dns_namespace_t space, dns_typepair_t typepair,
		     dns_name_t *foundname, isc_region_t *value) {
	lmdb_rrkey_t searchbuf;
	MDB_val search = make_rrkey(name, space, typepair, searchbuf);
	MDB_cursor *cursor = NULL;
	int status = mdb_cursor_open(txn->txn, txn->cache->rrsets, &cursor);
	if (status != MDB_SUCCESS) {
		return lmdb_result(status);
	}
	MDB_val key = search, data;
	status = mdb_cursor_get(cursor, &key, &data, MDB_SET_RANGE);
	if (status == MDB_NOTFOUND) {
		status = mdb_cursor_get(cursor, &key, &data, MDB_LAST);
	} else if (status == MDB_SUCCESS) {
		status = mdb_cursor_get(cursor, &key, &data, MDB_PREV);
	}
	isc_result_t result = ISC_R_NOTFOUND;
	if (status == MDB_SUCCESS && key.mv_size > sizeof(uint32_t)) {
		size_t name_length = key.mv_size - sizeof(uint32_t);
		dns_namespace_t foundspace;
		dns_qpkey_t namekey;
		if (name_length < sizeof(namekey)) {
			memmove(namekey, key.mv_data, name_length);
			namekey[name_length] = namekey[1];
			dns_qpkey_toname(namekey, name_length, foundname,
					   &foundspace);
			if (foundspace == space) {
				INSIST(data.mv_size <= UINT_MAX);
				*value = (isc_region_t){
					.base = data.mv_data,
					.length = data.mv_size,
				};
				result = ISC_R_SUCCESS;
			}
		}
	}
	mdb_cursor_close(cursor);
	return result;
}

void
dns_lmdbiter_init(dns_lmdbtxn_t *txn, dns_lmdbiter_t *iter) {
	*iter = (dns_lmdbiter_t){ .magic = LMDBITER_MAGIC, .txn = txn };
	MDB_cursor *cursor = NULL;
	RUNTIME_CHECK(mdb_cursor_open(txn->txn, txn->cache->dbi, &cursor) ==
		      MDB_SUCCESS);
	iter->cursor = cursor;
}

static isc_result_t
iter_get(dns_lmdbiter_t *iter, MDB_cursor_op op, void **pvalp,
	 uint32_t *ivalp) {
	REQUIRE(ISC_MAGIC_VALID(iter, LMDBITER_MAGIC));
	MDB_val key, data;
	int status = mdb_cursor_get(iter->cursor, &key, &data, op);
	iter->positioned = status == MDB_SUCCESS;
	if (status == MDB_SUCCESS) {
		set_value(&data, pvalp, ivalp);
		return ISC_R_SUCCESS;
	}
	return status == MDB_NOTFOUND ? ISC_R_NOMORE : lmdb_result(status);
}

isc_result_t
dns_lmdbiter_next(dns_lmdbiter_t *iter, void **pvalp, uint32_t *ivalp) {
	return iter_get(iter, iter->positioned ? MDB_NEXT : MDB_FIRST, pvalp,
			ivalp);
}

isc_result_t
dns_lmdbiter_prev(dns_lmdbiter_t *iter, void **pvalp, uint32_t *ivalp) {
	return iter_get(iter, iter->positioned ? MDB_PREV : MDB_LAST, pvalp,
			ivalp);
}

isc_result_t
dns_lmdbiter_current(dns_lmdbiter_t *iter, void **pvalp, uint32_t *ivalp) {
	if (!iter->positioned) {
		return ISC_R_FAILURE;
	}
	return iter_get(iter, MDB_GET_CURRENT, pvalp, ivalp);
}

unsigned int
dns_lmdbchain_length(dns_lmdbchain_t *chain) {
	REQUIRE(ISC_MAGIC_VALID(chain, LMDBCHAIN_MAGIC));
	return chain->len;
}

void
dns_lmdbchain_node(dns_lmdbchain_t *chain, unsigned int level, void **pvalp,
		   uint32_t *ivalp) {
	REQUIRE(ISC_MAGIC_VALID(chain, LMDBCHAIN_MAGIC));
	REQUIRE(level < chain->len);
	SET_IF_NOT_NULL(pvalp, chain->chain[level].pval);
	SET_IF_NOT_NULL(ivalp, chain->chain[level].ival);
}

dns_qp_memusage_t
dns_lmdbtxn_memusage(dns_lmdbtxn_t *txn) {
	MDB_stat stat = { 0 };
	RUNTIME_CHECK(mdb_stat(txn->txn, txn->cache->rrsets, &stat) ==
		      MDB_SUCCESS);
	return (dns_qp_memusage_t){
		.uctx = txn->cache->uctx,
		.leaves = stat.ms_entries,
		.live = stat.ms_entries,
		.used = stat.ms_entries,
		.node_size = 0,
		.bytes = (stat.ms_branch_pages + stat.ms_leaf_pages +
			  stat.ms_overflow_pages) *
			 stat.ms_psize,
	};
}

dns_qp_memusage_t
dns_lmdbcache_memusage(dns_lmdbcache_t *cache) {
	dns_lmdbtxn_t *txn = NULL;
	dns_lmdbcache_query(cache, &txn);
	dns_qp_memusage_t usage = dns_lmdbtxn_memusage(txn);
	dns_lmdbtxn_destroy(cache, &txn);
	return usage;
}
