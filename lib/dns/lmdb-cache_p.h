/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * SPDX-License-Identifier: MPL-2.0
 */

#pragma once

#include <stdbool.h>
#include <stdint.h>

#include <dns/name.h>
#include <dns/qp.h>
#include <dns/types.h>

typedef struct dns_lmdbcache dns_lmdbcache_t;
typedef struct dns_lmdbtxn dns_lmdbtxn_t;
typedef struct dns_lmdbsnap dns_lmdbsnap_t;

typedef struct dns_lmdbiter {
	unsigned int magic;
	dns_lmdbtxn_t *txn;
	void *cursor;
	bool positioned;
} dns_lmdbiter_t;

typedef struct dns_lmdbchain {
	unsigned int magic;
	unsigned int len;
	struct {
		void *pval;
		uint32_t ival;
	} chain[DNS_NAME_MAXLABELS];
} dns_lmdbchain_t;

void
dns_lmdbcache_create(isc_mem_t *mctx, const dns_qpmethods_t *methods,
		     void *uctx, dns_lmdbcache_t **cachep);

void
dns_lmdbcache_destroy(dns_lmdbcache_t **cachep);

void
dns_lmdbcache_query(dns_lmdbcache_t *cache, dns_lmdbtxn_t **txnp);

void
dns_lmdbtxn_destroy(dns_lmdbcache_t *cache, dns_lmdbtxn_t **txnp);

void
dns_lmdbcache_write(dns_lmdbcache_t *cache, dns_lmdbtxn_t **txnp);

void
dns_lmdbcache_commit(dns_lmdbcache_t *cache, dns_lmdbtxn_t **txnp);

void
dns_lmdbcache_snapshot(dns_lmdbcache_t *cache, dns_lmdbsnap_t **snapp);

void
dns_lmdbsnap_destroy(dns_lmdbcache_t *cache, dns_lmdbsnap_t **snapp);

dns_lmdbtxn_t *
dns_lmdbsnap_txn(dns_lmdbsnap_t *snap);

isc_result_t
dns_lmdb_getname(dns_lmdbtxn_t *txn, const dns_name_t *name,
		 dns_namespace_t space, void **pvalp, uint32_t *ivalp);

isc_result_t
dns_lmdb_lookup(dns_lmdbtxn_t *txn, const dns_name_t *name,
		dns_namespace_t space, dns_lmdbiter_t *iter,
		dns_lmdbchain_t *chain, void **pvalp, uint32_t *ivalp);

isc_result_t
dns_lmdb_insert(dns_lmdbtxn_t *txn, void *pval, uint32_t ival);

isc_result_t
dns_lmdb_deletename(dns_lmdbtxn_t *txn, const dns_name_t *name,
		    dns_namespace_t space, void **pvalp, uint32_t *ivalp);

void
dns_lmdbiter_init(dns_lmdbtxn_t *txn, dns_lmdbiter_t *iter);

isc_result_t
dns_lmdbiter_next(dns_lmdbiter_t *iter, void **pvalp, uint32_t *ivalp);

isc_result_t
dns_lmdbiter_prev(dns_lmdbiter_t *iter, void **pvalp, uint32_t *ivalp);

isc_result_t
dns_lmdbiter_current(dns_lmdbiter_t *iter, void **pvalp, uint32_t *ivalp);

unsigned int
dns_lmdbchain_length(dns_lmdbchain_t *chain);

void
dns_lmdbchain_node(dns_lmdbchain_t *chain, unsigned int level, void **pvalp,
		   uint32_t *ivalp);

dns_qp_memusage_t
dns_lmdbcache_memusage(dns_lmdbcache_t *cache);
