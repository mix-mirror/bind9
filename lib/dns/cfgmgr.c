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

#include <dns/cfgmgr.h>
#include <dns/qp.h>

#include <isc/buffer.h>
#include <isc/list.h>
#include <isc/mem.h>
#include <isc/random.h>
#include <isc/thread.h>
#include <isc/util.h>

#include "qp_p.h"

/*
 * List of keys, used when deleting a cfgmgr sub-tree.
 */
typedef struct cfgmgr_qpkeylink cfgmgr_qpkeylink_t;
struct cfgmgr_qpkeylink {
	size_t klen;
	dns_qpkey_t *key;
	ISC_LINK(cfgmgr_qpkeylink_t) link;
};
typedef ISC_LIST(cfgmgr_qpkeylink_t) cfgmgr_qpkeylist_t;

/*
 * Enough room to support big enough error message, especially if there are long
 * domain names in the key
 */
#define LASTERRORLEN 4092

/*
 * Thread shared cfgmgr data
 *
 * No need for atomic: those can be written only early in cfgmgr lifecycle,
 * where only one thread is involved.
 */
static bool cfgmgr_builtininitialized = false;
static bool cfgmgr_userinitialized = false;
static isc_mem_t *cfgmgr_mctx = NULL;
static dns_qpmulti_t *cfgmgr_builtindb = NULL;
static dns_qpmulti_t *cfgmgr_userdb = NULL;
static dns_qpmulti_t *cfgmgr_runningdb = NULL;

/*
 * Thread local cfgmgr data
 */
static thread_local char cfgmgr_lasterror[LASTERRORLEN];
static thread_local bool cfgmgr_pendingforeach = false;
static thread_local dns_cfgmgr_mode_t cfgmgr_mode = DNS_CFGMGR_MODERUNNING;

typedef struct {
	/*
	 * Those are exclusive, see REQUIRE_*TXN() macros
	 */
	dns_qpread_t read;
	dns_qp_t *write;

	/*
	 * Indicates which DB has a currently opened transaction. NULL
	 * if no transactions are currently opened
	 */
	dns_qpmulti_t *db;
} cfgmgr_txn_t;

/*
 * Reflect the transaction state from the public API of cfgmgr. Except for one
 * internal case (materialization) which is handled directly in
 * `cfgmgr_materialize()`, there can be only one transaction at the time on a
 * given thread.
 */
static thread_local cfgmgr_txn_t cfgmgr_txn = {};

#define cfgmgr_snprintf(b, blen, fmt, ...) \
	REQUIRE(snprintf(b, blen, fmt, __VA_ARGS__) < (int)blen)

/*
 * Internal representation of a cfgmgr qp node
 */
#define CFGMGR_QPNODE_MAGIC ISC_MAGIC('C', 'F', 'G', 'M')
#define REQUIRE_VALID_CFGMGR_QPNODE(n) \
	REQUIRE(ISC_MAGIC_VALID(n, CFGMGR_QPNODE_MAGIC))

/*
 * TODO: since there is a dedicated api for ref, there could be 2 separate node
 * types (one for the ref, an other for the rest, which could simplify the
 * struct (smaller) and make the API simpler (i.e. not having the _REF type in
 * the write/read API)
 */
typedef struct {
	unsigned int magic;
	isc_refcount_t references;
	isc_mem_t *mctx;
	dns_qpkey_t key;
	size_t klen;
	dns_cfgmgr_type_t type;
	union {
		char *string;
		bool boolean;
		isc_sockaddr_t sockaddr;
		uint32_t uint32;
		void *ptr;
	};

	/*
	 * Detach function called when the cfgmgr_qpnode_t get destroyed and the
	 * type is a reference (ptr field)
	 */
	void (*detachptr)(void *ptr);
} cfgmgr_qpnode_t;

static void
cfgmgr_qpnode_destroy(cfgmgr_qpnode_t *node) {
	REQUIRE_VALID_CFGMGR_QPNODE(node);

	switch (node->type) {
	case DNS_CFGMGR_REF:
		if (node->detachptr != NULL) {
			node->detachptr(node->ptr);
		}
		break;
	case DNS_CFGMGR_STRING:
		isc_mem_free(node->mctx, node->string);
		break;
	default:
		break;
	}

	isc_mem_putanddetach(&node->mctx, node, sizeof(*node));
}

static inline void
cfgmgr_qpnode_attach(cfgmgr_qpnode_t *ptr, cfgmgr_qpnode_t **ptrp)
	__attribute__((unused));
#ifdef DNS_CFGMGR_TRACE
ISC_REFCOUNT_STATIC_TRACE_IMPL(cfgmgr_qpnode, cfgmgr_qpnode_destroy);
#else
ISC_REFCOUNT_STATIC_IMPL(cfgmgr_qpnode, cfgmgr_qpnode_destroy);
#endif

/*
 * Function used to attach/detach cfgmgr entries as well as building their key
 */
static void
cfgmgr_attach(void *uctx, void *pval, uint32_t ival) {
	cfgmgr_qpnode_t *node = pval;

	UNUSED(uctx);
	UNUSED(ival);
	REQUIRE_VALID_CFGMGR_QPNODE(node);

	cfgmgr_qpnode_ref(node);
}

static void
cfgmgr_detach(void *uctx, void *pval, uint32_t ival) {
	cfgmgr_qpnode_t *node = pval;

	UNUSED(uctx);
	UNUSED(ival);
	REQUIRE_VALID_CFGMGR_QPNODE(node);

	cfgmgr_qpnode_unref(node);
}

static size_t
cfgmgr_makekey(dns_qpkey_t key, void *uctx, void *pval, uint32_t ival) {
	cfgmgr_qpnode_t *node = pval;

	UNUSED(uctx);
	UNUSED(ival);
	REQUIRE_VALID_CFGMGR_QPNODE(node);

	memmove(key, node->key, sizeof(dns_qpkey_t));
	return node->klen;
}

#define SYMB_NAME(name) #name

static void
cfgmgr_triename(void *uctx, char *buf, size_t size) {
	if (uctx == &cfgmgr_builtindb) {
		cfgmgr_snprintf(buf, size, "%s", SYMB_NAME(cfgmgr_builtindb));
	} else if (uctx == &cfgmgr_userdb) {
		cfgmgr_snprintf(buf, size, "%s", SYMB_NAME(cfgmgr_userdb));
	} else if (uctx == &cfgmgr_runningdb) {
		cfgmgr_snprintf(buf, size, "%s", SYMB_NAME(cfgmgr_runningdb));
	} else {
		UNREACHABLE();
	}
}

static dns_qpmethods_t cfgmgr_qpmethods = { .attach = cfgmgr_attach,
					    .detach = cfgmgr_detach,
					    .makekey = cfgmgr_makekey,
					    .triename = cfgmgr_triename };

#define REQUIRE_INITIALIZED()              \
	REQUIRE(cfgmgr_builtindb != NULL); \
	REQUIRE(cfgmgr_userdb != NULL);    \
	REQUIRE(cfgmgr_runningdb != NULL);

#define REQUIRE_NO_TXN()                     \
	REQUIRE_INITIALIZED();               \
	REQUIRE(cfgmgr_txn.db == NULL);      \
	REQUIRE(cfgmgr_txn.read.magic == 0); \
	REQUIRE(cfgmgr_txn.write == NULL);

#define REQUIRE_TXN()          \
	REQUIRE_INITIALIZED(); \
	REQUIRE(cfgmgr_txn.db != NULL);

#define REQUIRE_RWTXN()                      \
	REQUIRE_INITIALIZED();               \
	REQUIRE_TXN();                       \
	REQUIRE(cfgmgr_txn.read.magic == 0); \
	REQUIRE(cfgmgr_txn.write != NULL);

void
dns_cfgmgr_init(isc_mem_t *mctx) {
	REQUIRE(mctx != NULL);
	REQUIRE(!cfgmgr_builtininitialized);
	REQUIRE(!cfgmgr_userinitialized);
	REQUIRE(cfgmgr_mctx == NULL);
	REQUIRE(cfgmgr_builtindb == NULL);
	REQUIRE(cfgmgr_userdb == NULL);
	REQUIRE(cfgmgr_runningdb == NULL);

	isc_mem_attach(mctx, &cfgmgr_mctx);
	INSIST(cfgmgr_mctx != NULL);

	dns_qpmulti_create(mctx, &cfgmgr_qpmethods, &cfgmgr_builtindb,
			   &cfgmgr_builtindb);
	INSIST(cfgmgr_builtindb != NULL);

	dns_qpmulti_create(mctx, &cfgmgr_qpmethods, &cfgmgr_userdb,
			   &cfgmgr_userdb);
	INSIST(cfgmgr_userdb != NULL);

	dns_qpmulti_create(mctx, &cfgmgr_qpmethods, &cfgmgr_runningdb,
			   &cfgmgr_runningdb);
	INSIST(cfgmgr_runningdb != NULL);

	/*
	 * TODO: probably a wrong choice, it is needed to go through builtin
	 * then user first anyway.
	 */
	cfgmgr_mode = DNS_CFGMGR_MODERUNNING;

	REQUIRE_NO_TXN();
}

void
dns_cfgmgr_deinit(void) {
	REQUIRE(cfgmgr_mctx != NULL);
	REQUIRE(cfgmgr_builtindb != NULL);
	REQUIRE(cfgmgr_userdb != NULL);
	REQUIRE(cfgmgr_runningdb != NULL);

	/*
	 * This won't guard agains't opened transaction on a different thread,
	 * so there is still a risk of leak that wouldn't be caught here. A
	 * possible approach could be to have a shared atomic number counting
	 * the number of current transaction and checking it's 0 here.
	 */
	REQUIRE_NO_TXN();

	dns_qpmulti_destroy(&cfgmgr_builtindb);
	INSIST(cfgmgr_builtindb == NULL);

	dns_qpmulti_destroy(&cfgmgr_userdb);
	INSIST(cfgmgr_userdb == NULL);

	dns_qpmulti_destroy(&cfgmgr_runningdb);
	INSIST(cfgmgr_runningdb == NULL);

	isc_mem_detach(&cfgmgr_mctx);
	INSIST(cfgmgr_mctx == NULL);

	cfgmgr_builtininitialized = false;
	cfgmgr_userinitialized = false;
}

void
dns_cfgmgr_mode(dns_cfgmgr_mode_t mode) {
	REQUIRE_NO_TXN();

	REQUIRE(cfgmgr_builtininitialized || mode == DNS_CFGMGR_MODEBUILTIN);
	REQUIRE(cfgmgr_userinitialized || mode == DNS_CFGMGR_MODEBUILTIN ||
		mode == DNS_CFGMGR_MODEUSER);

	cfgmgr_mode = mode;
}

static void
cfgmgr_setlasterror(const char *fmt, ...) {
	va_list ap;
	size_t len = sizeof(cfgmgr_lasterror);

	va_start(ap, fmt);
	REQUIRE(vsnprintf(cfgmgr_lasterror, len, fmt, ap) < (int)len);
	va_end(ap);
}

static void
cfgmgr_setdbtxn(void) {
	switch (cfgmgr_mode) {
	case DNS_CFGMGR_MODEBUILTIN:
		cfgmgr_txn.db = cfgmgr_builtindb;
		break;
	case DNS_CFGMGR_MODEUSER:
		cfgmgr_txn.db = cfgmgr_userdb;
		break;
	case DNS_CFGMGR_MODERUNNING:
		cfgmgr_txn.db = cfgmgr_runningdb;
		break;
	default:
		UNREACHABLE();
	}
}

void
dns_cfgmgr_txn(void) {
	/*
	 * Question: qp doc says that an isc_qpread_t must be on the stack,
	 * though the way I understand it, it doesn't matter as soon as the
	 * transaction occurs synchronously (i.e. in the same uv tick)... So
	 * this should be good to implement cfgmgr read transaction that way
	 * (storing the qpread on the static thread data)?
	 */
	REQUIRE_NO_TXN();
	REQUIRE(cfgmgr_builtininitialized);
	REQUIRE(cfgmgr_mode == DNS_CFGMGR_MODEBUILTIN ||
		cfgmgr_userinitialized);

	cfgmgr_setlasterror("");
	cfgmgr_setdbtxn();
	dns_qpmulti_query(cfgmgr_txn.db, &cfgmgr_txn.read);
}

void
dns_cfgmgr_rwtxn(void) {
	REQUIRE_NO_TXN();

	if (!cfgmgr_builtininitialized) {
		REQUIRE(cfgmgr_mode == DNS_CFGMGR_MODEBUILTIN);
	} else if (!cfgmgr_userinitialized) {
		REQUIRE(cfgmgr_mode == DNS_CFGMGR_MODEUSER);
	} else {
		REQUIRE(cfgmgr_mode == DNS_CFGMGR_MODERUNNING);
	}

	cfgmgr_setlasterror("");
	cfgmgr_setdbtxn();
	dns_qpmulti_update(cfgmgr_txn.db, &cfgmgr_txn.write);

	REQUIRE_RWTXN();
}

void
dns_cfgmgr_closetxn(void) {
	REQUIRE_TXN();
	REQUIRE(cfgmgr_txn.read.magic != 0);
	REQUIRE(cfgmgr_txn.write == NULL);

	dns_qpread_destroy(cfgmgr_txn.db, &cfgmgr_txn.read);
	cfgmgr_txn.db = NULL;

	REQUIRE_NO_TXN();
}

static void
cfgmgr_qpinsertoverride(dns_qp_t *qp, cfgmgr_qpnode_t *n) {
	isc_result_t result;

	result = dns_qp_insert(qp, n, 0);
	if (result == ISC_R_EXISTS) {
		result = dns_qp_deletekey(qp, n->key, n->klen, NULL, NULL);
		INSIST(result == ISC_R_SUCCESS);
		result = dns_qp_insert(qp, n, 0);
	}
	INSIST(result == ISC_R_SUCCESS);
}

static void
cfgmgr_materialize(void) {
	dns_qpiter_t it;
	dns_qp_t *wrunning = NULL;
	void *vnode = NULL;

	REQUIRE(cfgmgr_txn.write != NULL &&
		(cfgmgr_txn.db == cfgmgr_builtindb ||
		 cfgmgr_txn.db == cfgmgr_userdb));

	dns_qpmulti_update(cfgmgr_runningdb, &wrunning);
	dns_qpiter_init(cfgmgr_txn.write, &it);

	while (dns_qpiter_next(&it, NULL, &vnode, NULL) == ISC_R_SUCCESS) {
		/*
		 * Materialization occurs first from builtin into running, then
		 * from user to running. In the second case, it might need to
		 * override properties also found in builtin db.
		 */
		cfgmgr_qpinsertoverride(wrunning, vnode);
	}

	dns_qpmulti_commit(cfgmgr_runningdb, &wrunning);
}

isc_result_t
dns_cfgmgr_commit(void) {
	isc_result_t result = ISC_R_SUCCESS;

	REQUIRE_RWTXN();

	/*
	 * TODO: configuration validation would occurs here. And two possible
	 * outcomes: whether the configuration is good, and we continue, or the
	 * configuration is wrong and result is set to an error, the qp
	 * transaction is rollback-ed.
	 */

	if (cfgmgr_mode == DNS_CFGMGR_MODEBUILTIN) {
		cfgmgr_materialize();
		cfgmgr_builtininitialized = true;
	} else if (cfgmgr_mode == DNS_CFGMGR_MODEUSER) {
		cfgmgr_materialize();
		cfgmgr_userinitialized = true;
	}

	dns_qp_compact(cfgmgr_txn.write, DNS_QPGC_NOW);
	dns_qpmulti_commit(cfgmgr_txn.db, &cfgmgr_txn.write);
	cfgmgr_txn.db = NULL;

	REQUIRE_NO_TXN();

	return result;
}

void
dns_cfgmgr_rollback(void) {
	REQUIRE_RWTXN();

	dns_qpmulti_rollback(cfgmgr_txn.db, &cfgmgr_txn.write);
	cfgmgr_txn.db = NULL;

	REQUIRE_NO_TXN();
}

static bool
cfgmgr_prefixmatches(const dns_qpkey_t key1, size_t klen1,
		     const dns_qpkey_t key2, size_t klen2) {
	if (klen1 > klen2) {
		return false;
	}

	return memcmp(key1, key2, klen1) == 0;
}

inline static uint8_t
cfgmgr_keyfrompath_byte(uint8_t input) {
	if (input >= 'A' && input <= 'Z') {
		input += 'a' - 'A';
	}

	return dns_qp_bits_for_byte[input];
}

static void
cfgmgr_keyfrompath(const char *path, size_t pathlen, bool hastrailing,
		   bool hasnotrailing, dns_qpkey_t key, size_t *klen) {
	size_t i = 0;

	REQUIRE(path != NULL);
	REQUIRE(path[0] == '/');
	REQUIRE(!(hastrailing && hasnotrailing));

	if (hastrailing) {
		REQUIRE(path[pathlen - 1] == '/');
	}

	if (hasnotrailing) {
		REQUIRE(path[pathlen - 1] != '/');
	}

	while (i < pathlen) {
		key[i] = cfgmgr_keyfrompath_byte(path[i]);
		i++;
	}

	ENSURE(i < sizeof(dns_qpkey_t));
	*klen = i;
}

void
dns_cfgmgr_delete(const char *path) {
	dns_qpiter_t it;
	isc_result_t result;
	dns_qpkey_t key;
	size_t klen;
	cfgmgr_qpnode_t *node;
	cfgmgr_qpkeylist_t keylist = ISC_LIST_INITIALIZER;
	bool firstmatch = false;

	REQUIRE_RWTXN();

	cfgmgr_keyfrompath(path, strlen(path), true, false, key, &klen);

	/*
	 * qp-trie lookup function doesn't enable to find the closest children,
	 * but the closest ancestor instead. (which sometimes doesn't exists, or
	 * it the root). As a work around this lineary iterates over the whole
	 * db until it finds the first children of the given key.
	 *
	 * Then, because we can't mutate the DB while the iterator is in use, we
	 * build a list of keys to be deleted. It's slow, but because this
	 * occurs duing a write transaction, it doesn't really matter if it
	 * takes 3ms or 3seconds: the server keeps running in meantime.
	 */
	dns_qpiter_init(cfgmgr_txn.write, &it);
	while (dns_qpiter_next(&it, NULL, (void **)&node, NULL) ==
	       ISC_R_SUCCESS)
	{
		cfgmgr_qpkeylink_t *klink;

		if (!cfgmgr_prefixmatches(key, klen, node->key,
					  node->klen))
		{
			if (firstmatch) {
				/*
				 * First key which doesn't match the prefix
				 * (lexicographically after), we're done
				 * grabbing the key to be deleted. (we're in a
				 * different cfgmgr sub-tree)
				 */
				break;
			}

			continue;
		}

		firstmatch = true;
		klink = isc_mem_get(cfgmgr_mctx, sizeof(*klink));
		*klink = (cfgmgr_qpkeylink_t){ .key = &node->key,
					       .klen = node->klen,
					       .link = ISC_LINK_INITIALIZER };

		ISC_LIST_APPEND(keylist, klink, link);
	}

	ISC_LIST_FOREACH (keylist, klink, link) {
		result = dns_qp_deletekey(cfgmgr_txn.write, *klink->key,
					  klink->klen, NULL, NULL);
		INSIST(result == ISC_R_SUCCESS);
		isc_mem_put(cfgmgr_mctx, klink, sizeof(*klink));
	}
}

static void
cfgmgr_delete_singlevalue(const char *path) {
	dns_qpkey_t key;
	size_t klen;

	cfgmgr_keyfrompath(path, strlen(path), false, false, key, &klen);
	(void)dns_qp_deletekey(cfgmgr_txn.write, key, klen, NULL, NULL);
}

void
dns_cfgmgr_write(const char *path, const dns_cfgmgr_val_t *value) {
	cfgmgr_qpnode_t *node = NULL;

	REQUIRE_RWTXN();

	if (value == NULL ||
	    (value->type == DNS_CFGMGR_REF && value->ptr == NULL))
	{
		cfgmgr_delete_singlevalue(path);
		return;
	}

	node = isc_mem_get(cfgmgr_mctx, sizeof(*node));
	*node = (cfgmgr_qpnode_t){ .magic = CFGMGR_QPNODE_MAGIC,
				   .type = value->type,
				   .references = ISC_REFCOUNT_INITIALIZER(1) };
	isc_mem_attach(cfgmgr_mctx, &node->mctx);
	cfgmgr_keyfrompath(path, strlen(path), false, true, node->key,
			   &node->klen);

	switch (value->type) {
	case DNS_CFGMGR_STRING: {
		size_t slen = strlen(value->string) + 1;

		node->string = isc_mem_allocate(cfgmgr_mctx, slen);
		strncpy(node->string, value->string, slen);
		break;
	}
	case DNS_CFGMGR_BOOLEAN:
		node->boolean = value->boolean;
		break;
	case DNS_CFGMGR_NONE:
		break;
	case DNS_CFGMGR_SOCKADDR:
		node->sockaddr = value->sockaddr;
		break;
	case DNS_CFGMGR_UINT32:
		node->uint32 = value->uint32;
		break;
	case DNS_CFGMGR_REF:
		node->ptr = value->ptr;
		node->detachptr = value->detach;
		if (value->attach != NULL) {
			ENSURE(value->detach != NULL);
			value->attach(value->ptr);
		}
		break;
	case DNS_CFGMGR_UNDEFINED:
		UNREACHABLE();
	}

	cfgmgr_qpinsertoverride(cfgmgr_txn.write, node);
	cfgmgr_qpnode_detach(&node);
}

static dns_qpreadable_t
cfgmgr_qpreadable(void) {
	dns_qpreadable_t qpr;

	if (cfgmgr_txn.write != NULL) {
		qpr.qpt = cfgmgr_txn.write;
		INSIST(cfgmgr_txn.read.magic == 0);
	} else if (cfgmgr_txn.read.magic != 0) {
		qpr.qpr = &cfgmgr_txn.read;
	} else {
		UNREACHABLE();
	}

	return qpr;
}

isc_result_t
dns_cfgmgr_read(const char *path, dns_cfgmgr_val_t *value);

static isc_result_t
cfgmgr_inherit(const char *path, dns_cfgmgr_val_t *value) {
	char viewname[DNS_QP_MAXKEY];
	char newpath[DNS_QP_MAXKEY];
	const char *p1;
	const char *p2;
	char views[] = "/views/";
	size_t viewslen = sizeof(views) - 1;
	char zones[] = "/zones/";
	size_t zoneslen = sizeof(zones) - 1;

	/* path starts with /views/, p1 points to the view name */
	if (strncmp(views, path, viewslen)) {
		return ISC_R_NOTFOUND;
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

	if (strncmp(zones, p2, zoneslen)) {
		/*
		 * if p2 is not /zones/, then it's an inheritance of a view prop
		 * to the options
		 */
		cfgmgr_snprintf(newpath, sizeof(newpath), "/options/%s",
				p2 + 1);
	} else {
		/*
		 * p2 is /zones/. Set the begining of the zone name to p1 and
		 * the end of the zone name of p2. Similarly to /views/, /zones/
		 * must be used only to put zone instances, so the next label
		 * must be a zone name and can't be a leaf
		 */
		p1 = p2 + zoneslen;
		p2 = strchr(p1 + 1, '/');
		INSIST(*p2 != 0);
		cfgmgr_snprintf(newpath, sizeof(newpath), "/views/%s/%s",
				viewname, p2 + 1);
	}

	return dns_cfgmgr_read(newpath, value);
}

static void
cfgmgr_valuefromnode(const cfgmgr_qpnode_t *node, dns_cfgmgr_val_t *value) {
	value->type = node->type;
	switch (node->type) {
	case DNS_CFGMGR_STRING:
		value->string = node->string;
		break;
	case DNS_CFGMGR_BOOLEAN:
		value->boolean = node->boolean;
		break;
	case DNS_CFGMGR_NONE:
		break;
	case DNS_CFGMGR_SOCKADDR:
		value->sockaddr = node->sockaddr;
		break;
	case DNS_CFGMGR_UINT32:
		value->uint32 = node->uint32;
		break;
	case DNS_CFGMGR_REF:
		value->ptr = node->ptr;
		break;
	case DNS_CFGMGR_UNDEFINED:
		UNREACHABLE();
	}
}

isc_result_t
dns_cfgmgr_read(const char *path, dns_cfgmgr_val_t *value) {
	isc_result_t result;
	dns_qpkey_t key;
	size_t klen;
	void *vnode = NULL;

	REQUIRE_TXN();
	REQUIRE(value != NULL);

	cfgmgr_keyfrompath(path, strlen(path), false, true, key, &klen);
	result = dns_qp_getkey(cfgmgr_qpreadable(), key, klen, &vnode, NULL);
	if (result != ISC_R_SUCCESS) {
		return cfgmgr_inherit(path, value);
	}

	INSIST(vnode != NULL);
	cfgmgr_valuefromnode(vnode, value);

	return result;
}

static void
cfgmgr_refkey(const void *owner, const char *path, dns_qpkey_t key,
	      size_t *klen) {
	size_t i = 0;
	constexpr char hex[] = "0123456789ABCDEF";
	uintptr_t ownernum = (uintptr_t)owner;

	/*
	 * Build an "unique" identifier based on the resversed ASCII
	 * representation of the owner pointer
	 */
	for (size_t j = 0; j < sizeof(owner); j++) {
		key[i++] = cfgmgr_keyfrompath_byte(hex[ownernum & 0xF]);
		ownernum >>= 4;
	}

	for (size_t j = 0; path[j] != 0; j++) {
		key[i++] = cfgmgr_keyfrompath_byte(path[j]);
	}

	*klen = i;
}

void
dns_cfgmgr_setref(const void *owner, const char *path, void *ptr,
		  void (*attach)(void *ptr), void (*detach)(void *ptr)) {
	cfgmgr_qpnode_t *node = NULL;
	dns_cfgmgr_val_t val = {
		.type = DNS_CFGMGR_REF,
		.ptr = ptr,
		.attach = attach,
		.detach = detach
	};

	REQUIRE_RWTXN();
	REQUIRE(attach != NULL);
	REQUIRE(detach != NULL);

	if (ptr == NULL) {
		dns_qpkey_t key;
		size_t klen;

		cfgmgr_refkey(owner, path, key, &klen);
		(void)dns_qp_deletekey(cfgmgr_txn.write, key, klen, NULL, NULL);
		return;
	}

	attach(ptr);
	node = isc_mem_get(cfgmgr_mctx, sizeof(*node));
	*node = (cfgmgr_qpnode_t){ .magic = CFGMGR_QPNODE_MAGIC,
				   .type = val.type,
				   .ptr = ptr,
				   .detachptr = detach, 
				   .references = ISC_REFCOUNT_INITIALIZER(1) };
	cfgmgr_refkey(owner, path, node->key, &node->klen);
	isc_mem_attach(cfgmgr_mctx, &node->mctx);

	cfgmgr_qpinsertoverride(cfgmgr_txn.write, node);
	cfgmgr_qpnode_detach(&node);
}

isc_result_t
dns_cfgmgr_getref(const void *owner, const char *path, void **ptr) {
	isc_result_t result;
	dns_qpkey_t key;
	size_t klen;
	cfgmgr_qpnode_t *node = NULL;

	REQUIRE_TXN();
	REQUIRE(ptr != NULL && *ptr == NULL);

	cfgmgr_refkey(owner, path, key, &klen);
	result = dns_qp_getkey(cfgmgr_qpreadable(), key, klen, (void **)&node,
			       NULL);
	if (result != ISC_R_SUCCESS) {
		return result;
	}

	if (node->type != DNS_CFGMGR_REF) {
		return ISC_R_NOTFOUND;
	}

	*ptr = node->ptr;

	return ISC_R_SUCCESS;
}

typedef struct {
	dns_qpkey_t prefixkey;
	size_t prefixklen;
	dns_qpkey_t prevkey;
	size_t prevklen;
	size_t maxdepth;
	bool firstmatch;
	size_t pendinglabelup;
	void *state;
	void (*property)(void *state, const char *name,
			 const dns_cfgmgr_val_t *value);
	void (*labeldown)(void *state, const char *label);
	void (*labelup)(void *state);
} cfgmgr_foreach_ctx_t;

static bool
cfgmgr_foreach_node(cfgmgr_foreach_ctx_t *ctx, cfgmgr_qpnode_t *node) {
	size_t depth = 0;
	size_t pdiffstarts = 0;
	size_t i = 0;
	dns_cfgmgr_val_t value;
	size_t propnamestarts = 0;
	const dns_qpshift_t sep = dns_qp_bits_for_byte['/'];

	bool skipref = getenv("NAMED_CFGMGR_FOREACH_REF") == NULL;
	if (node->type == DNS_CFGMGR_REF && skipref) {
		return true;
	}

	/*
	 * Skip keys before the closest child of the looked up prefix. Once we
	 * found at least one child, any key which doesn't match the prefix
	 * means we're in a different cfgmgr sub-tree and we're done.
	 */
	if (!cfgmgr_prefixmatches(ctx->prefixkey, ctx->prefixklen, node->key,
				  node->klen))
	{
		return !ctx->firstmatch;
	}
	ctx->firstmatch = true;

	/*
	 * Extract the leaf by finding the index where the path
	 * terminates and also bails out early if the labels goes too
	 * deep.
	 */
	while (i < node->klen) {
		if (node->key[i] == sep) {
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
	pdiffstarts = ctx->prefixklen;
	if (ctx->prevklen > 0) {
		i = ctx->prefixklen;
		while (i < ctx->prevklen && i < node->klen &&
		       ctx->prevkey[i] == node->key[i])
		{
			if (ctx->prevkey[i] == sep) {
				pdiffstarts = i + 1;
			}
			i++;
		}
	}

	/*
	 * Walk labels backwards until the path prefix is reached.
	 * Extract each intermediate labels.
	 */
	if (ctx->prevklen > 0 && ctx->labelup != NULL) {
		i = ctx->prevklen;
		while (i > pdiffstarts) {
			if (ctx->prevkey[i] == sep) {
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

		i = pdiffstarts; 
		while (i < node->klen) {
			if (node->key[i] == sep) {
				char label[DNS_QP_MAXKEY];
				dns_qpshift_t *start = node->key + labelstarts;
				size_t max = i - labelstarts;
				size_t j = 0;

				while (j < max) {
					size_t bit = start[j];

					label[j] = dns_qp_byte_for_bit[bit];
					j++;
				}
				label[j] = 0;
				INSIST(j < DNS_QP_MAXKEY);

				labelstarts = i + 1;
				ctx->labeldown(ctx->state, label);
				ctx->pendinglabelup++;
			}
			i++;
		}
	}

	if (ctx->property != NULL) {
		char label[DNS_QP_MAXKEY];
		dns_qpshift_t *start = node->key + propnamestarts;
		size_t max = node->klen - propnamestarts;
		size_t j = 0;

		while (j < max) {
			size_t bit = start[j];

			label[j] = dns_qp_byte_for_bit[bit];
			j++;
		}
		label[j] = 0;
		INSIST(j < DNS_QP_MAXKEY);

		cfgmgr_valuefromnode(node, &value);
		ctx->property(ctx->state, label, &value);
	}

nextkey:
	ctx->prevklen = node->klen;
	memmove(ctx->prevkey, node->key, sizeof(node->key));
	return true;
}

void
dns_cfgmgr_foreach(const char *path, size_t maxdepth, void *state,
		   void (*property)(void *state, const char *name,
				    const dns_cfgmgr_val_t *value),
		   void (*labeldown)(void *state, const char *label),
		   void (*labelup)(void *state)) {
	dns_qpiter_t it;
	void *vnode = NULL;
	cfgmgr_foreach_ctx_t ctx = {
		.maxdepth = maxdepth,
		.state = state,
		.property = property,
		.labeldown = labeldown,
		.labelup = labelup,
	};
	size_t pathlen = strlen(path);

	REQUIRE_TXN();

	/*
	 * dns_cfgmgr_foreach is not re-rentrant
	 */
	REQUIRE(cfgmgr_pendingforeach == false);
	cfgmgr_pendingforeach = true;

	cfgmgr_keyfrompath(path, pathlen, true, false, ctx.prefixkey,
			   &ctx.prefixklen);

	/*
	 * Same problem than with dns_cfgmgr_delete(): qp-trie lookup
	 * function doesn't enable to find the closest children, but the closest
	 * ancestor instead. (which sometimes doesn't exists, or it the root).
	 *
	 * This is a bit more critical than dns_cfgmgr_delete() as this API
	 * might be used for reading (so needs to be quick). Hopefully this API
	 * would be used _only_ when initializing views, zones (so in a wirte
	 * context). And never otherwise. (In which case we might consider some
	 * custom things, i.e. storing separately a list of zones or view in
	 * cfgmgr).
	 */
	dns_qpiter_init(cfgmgr_qpreadable(), &it);
	while (dns_qpiter_next(&it, NULL, &vnode, NULL) == ISC_R_SUCCESS) {
		if (!cfgmgr_foreach_node(&ctx, vnode)) {
			break;
		}
	}

	if (labelup != NULL) {
		while (ctx.pendinglabelup > 0) {
			labelup(state);
			ctx.pendinglabelup--;
		}
	}

	cfgmgr_pendingforeach = false;
}

const char *
dns_cfgmgr_lasterror(void) {
	return cfgmgr_lasterror;
}
