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

#if __STDC_VERSION__ < 202311L
#define auto __auto_type
#endif

#include <stdint.h>

#include <ngtcp2/ngtcp2.h>

#include <isc/hash.h>
#include <isc/magic.h>
#include <isc/mem.h>
#include <isc/quic.h>
#include <isc/random.h>
#include <isc/refcount.h>
#include <isc/region.h>
#include <isc/types.h>
#include <isc/urcu.h>
#include <isc/util.h>

typedef struct cid_map_entry cid_map_entry_t;

struct cid_map_entry {
	isc_tid_t tid;
	isc_quic_conn_t *conn;
	ngtcp2_cid inner;
	struct cds_lfht_node node;
};

struct isc_quic_cid {
	ngtcp2_cid inner;
};

struct isc_quic_cid_map {
	uint32_t magic;
	isc_refcount_t references;
	isc_mem_t *mctx;
	struct cds_lfht *ht;
};

constexpr uint32_t cid_map_magic = ISC_MAGIC('Q', 'C', 'M', 'p');
constexpr unsigned long cid_map_init_size = 1 << 4;
constexpr unsigned long cid_map_min_size = 1 << 5;

static int
cid_map_entry_match(struct cds_lfht_node *ht_node, const void *key0) {
	const cid_map_entry_t *entry = caa_container_of(ht_node,
							cid_map_entry_t, node);
	const isc_constregion_t *key = key0;

	return (entry->inner.datalen == key->length) &&
	       (memcmp(entry->inner.data, key->base, entry->inner.datalen) ==
		0);
}

static cid_map_entry_t *
cid_map_lookup(struct cds_lfht *ht, uint32_t hashval, isc_constregion_t *key) {
	struct cds_lfht_iter iter;

	cds_lfht_lookup(ht, hashval, cid_map_entry_match, key, &iter);

	return cds_lfht_entry(cds_lfht_iter_get_node(&iter), cid_map_entry_t,
			      node);
}

static void
cid_map_destroy(isc_quic_cid_map_t *map) {
	REQUIRE(map->magic == cid_map_magic);

	map->magic = 0x00;

	struct cds_lfht_iter iter;
	cid_map_entry_t *entry = NULL;
	cds_lfht_for_each_entry(map->ht, &iter, entry, node) {
		INSIST(!cds_lfht_del(map->ht, &entry->node));
		isc_mem_put(map->mctx, entry, sizeof(*entry));
	}
	RUNTIME_CHECK(!cds_lfht_destroy(map->ht, NULL));

	isc_mem_putanddetach(&map->mctx, map, sizeof(*map));
}

isc_quic_cid_t *
isc_quic_cid_random_new(size_t length, isc_mem_t *mctx) {
	isc_quic_cid_t *cid = isc_mem_get(mctx, sizeof(*cid));
	cid->inner.datalen = length;
	isc_random_buf(cid->inner.data, length);
	return cid;
}

isc_constregion_t
isc_quic_cid_bytes(isc_quic_cid_t *cid) {
	REQUIRE(cid != NULL);
	return (isc_constregion_t){ cid->inner.data, cid->inner.datalen };
}

void
isc_quic_cid_destroy(isc_mem_t *mctx, isc_quic_cid_t **cidp) {
	REQUIRE(cidp != NULL && *cidp != NULL);
	isc_mem_put(mctx, *cidp, sizeof(**cidp));
	*cidp = NULL;
}

ISC_REFCOUNT_IMPL(isc_quic_cid_map, cid_map_destroy);

void
isc_quic_cid_map_create(isc_mem_t *mctx, isc_quic_cid_map_t **mapp) {
	isc_quic_cid_map_t *map;
	struct cds_lfht *ht;

	REQUIRE(mapp != NULL && *mapp == NULL);

	ht = cds_lfht_new(cid_map_init_size, cid_map_min_size, 0,
			  CDS_LFHT_AUTO_RESIZE | CDS_LFHT_ACCOUNTING, NULL);
	INSIST(ht != NULL);

	map = isc_mem_get(mctx, sizeof(*map));
	*map = (isc_quic_cid_map_t){
		.magic = cid_map_magic,
		.references = ISC_REFCOUNT_INITIALIZER(1),
		.mctx = isc_mem_ref(mctx),
		.ht = ht,
	};

	*mapp = map;
}

isc_result_t
isc_quic_cid_map_find(isc_quic_cid_map_t *map, isc_constregion_t cid_bytes,
		      isc_quic_conn_t **connp, isc_tid_t *tidp) {
	isc_result_t result = ISC_R_NOTFOUND;

	REQUIRE(map != NULL && map->magic == cid_map_magic);
	REQUIRE(cid_bytes.base != NULL &&
		cid_bytes.length >= NGTCP2_MIN_CIDLEN &&
		cid_bytes.length <= NGTCP2_MAX_CIDLEN);

	rcu_read_lock();
	struct cds_lfht *ht = rcu_dereference(map->ht);
	uint32_t hashval = isc_hash32(cid_bytes.base, cid_bytes.length, false);

	cid_map_entry_t *entry = cid_map_lookup(ht, hashval, &cid_bytes);

	if (entry != NULL && !cds_lfht_is_node_deleted(&entry->node)) {
		result = ISC_R_SUCCESS;
		SET_IF_NOT_NULL(connp, entry->conn);
		SET_IF_NOT_NULL(tidp, entry->tid);
	}
	rcu_read_unlock();

	return result;
}

isc_result_t
isc_quic_cid_map_add(isc_quic_cid_map_t *map, isc_quic_cid_t *cid,
		     isc_quic_conn_t *conn) {
	REQUIRE(cid != NULL);
	isc_constregion_t bytes = { cid->inner.data, cid->inner.datalen };
	return isc_quic_cid_map_add_bytes(map, bytes, conn);
}

isc_result_t
isc_quic_cid_map_add_bytes(isc_quic_cid_map_t *map, isc_constregion_t cid_bytes,
			   isc_quic_conn_t *conn) {
	cid_map_entry_t *entry;

	REQUIRE(map != NULL && map->magic == cid_map_magic);
	REQUIRE(cid_bytes.base != NULL && conn != NULL);

	entry = isc_mem_get(map->mctx, sizeof(*entry));
	entry->tid = isc_tid();
	entry->inner.datalen = cid_bytes.length;
	memmove(entry->inner.data, cid_bytes.base, cid_bytes.length);
	entry->conn = conn;

	auto hashval = isc_hash32(cid_bytes.base, cid_bytes.length, false);

	rcu_read_lock();
	struct cds_lfht *ht = rcu_dereference(map->ht);
	struct cds_lfht_node *node = cds_lfht_add_unique(
		ht, hashval, cid_map_entry_match, &cid_bytes, &entry->node);
	rcu_read_unlock();

	if (node != &entry->node) {
		isc_mem_put(map->mctx, entry, sizeof(*entry));
		return ISC_R_EXISTS;
	}

	return ISC_R_SUCCESS;
}

isc_result_t
isc_quic_cid_map_remove(isc_quic_cid_map_t *map, isc_quic_cid_t *cid) {
	REQUIRE(map != NULL && map->magic == cid_map_magic);
	REQUIRE(cid != NULL);

	isc_constregion_t key = { cid->inner.data, cid->inner.datalen };
	uint32_t hashval = isc_hash32(cid->inner.data, cid->inner.datalen,
				      false);

	rcu_read_lock();
	struct cds_lfht *ht = rcu_dereference(map->ht);
	cid_map_entry_t *entry = cid_map_lookup(ht, hashval, &key);
	if (entry != NULL) {
		RUNTIME_CHECK(!cds_lfht_del(ht, &entry->node));
	}
	rcu_read_unlock();

	/* free outside RCU */
	if (entry != NULL) {
		isc_mem_put(map->mctx, entry, sizeof(*entry));
		return ISC_R_SUCCESS;
	}

	return ISC_R_NOTFOUND;
}
