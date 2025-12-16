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

#include <isc/mutex.h>
#include <isc/ngtcp2_utils.h>
#include <isc/quic.h>
#include <isc/random.h>
#include <isc/urcu.h>

#define QUIC_CID_MAP_SIZE (1 << 13)

#define QUIC_CID_MAP_MAGIC	    ISC_MAGIC('Q', 'C', 'M', 'P')
#define VALID_QUIC_CID_MAP_MAGIC(t) ISC_MAGIC_VALID(t, QUIC_CID_MAP_MAGIC)

typedef struct isc_quic_cid_map_entry {
	isc_mem_t *mctx;
	isc_quic_cid_t *cid;
	isc_quic_session_t *session;
	isc_tid_t tid;

	ISC_LINK(struct isc_quic_cid_map_entry) link;
	struct cds_lfht_node node;
	struct rcu_head head;
} isc_quic_cid_map_entry_t;

struct isc_quic_cid_map {
	unsigned int magic;
	isc_refcount_t references;
	isc_mem_t *mctx;

	struct cds_lfht *cid_entries;
	struct rcu_head head;
};

void
isc_quic_cid_map_create(isc_mem_t *mctx, isc_quic_cid_map_t **pmap) {
	REQUIRE(mctx != NULL);
	REQUIRE(pmap != NULL && *pmap == NULL);

	isc_quic_cid_map_t *restrict new_map = isc_mem_cget(mctx, 1,
							    sizeof(*new_map));

	isc_refcount_init(&new_map->references, 1);

	isc_mem_attach(mctx, &new_map->mctx);

	new_map->cid_entries =
		cds_lfht_new(QUIC_CID_MAP_SIZE, QUIC_CID_MAP_SIZE, 0,
			     CDS_LFHT_AUTO_RESIZE | CDS_LFHT_ACCOUNTING, NULL);
	RUNTIME_CHECK(new_map->cid_entries != NULL);

	new_map->magic = QUIC_CID_MAP_MAGIC;
	*pmap = new_map;
}

void
isc_quic_cid_map_attach(isc_quic_cid_map_t *restrict source,
			isc_quic_cid_map_t **targetp) {
	REQUIRE(VALID_QUIC_CID_MAP_MAGIC(source));
	REQUIRE(targetp != NULL && *targetp == NULL);

	isc_refcount_increment(&source->references);

	*targetp = source;
}

static void
cid_map_entry_free_cb(struct rcu_head *ht_head) {
	isc_quic_cid_map_entry_t *restrict entry =
		caa_container_of(ht_head, isc_quic_cid_map_entry_t, head);
	isc_quic_cid_detach(&entry->cid);
	isc_quic_session_detach(&entry->session);
	isc_mem_putanddetach(&entry->mctx, entry, sizeof(*entry));
}

static inline void
cid_map_entry_free(const bool immediately, isc_quic_cid_map_entry_t **entryp) {
	isc_quic_cid_map_entry_t *restrict entry = *entryp;

	if (immediately) {
		cid_map_entry_free_cb(&entry->head);
	} else {
		call_rcu(&entry->head, cid_map_entry_free_cb);
	}
	*entryp = NULL;
}

static void
cid_map_free_cb(struct rcu_head *ht_head) {
	isc_quic_cid_map_t *restrict map =
		caa_container_of(ht_head, isc_quic_cid_map_t, head);
	struct cds_lfht *ht = rcu_dereference(map->cid_entries);
	ISC_LIST(isc_quic_cid_map_entry_t) dellist = ISC_LIST_INITIALIZER;
	isc_quic_cid_map_entry_t *restrict entry = NULL;
	struct cds_lfht_iter iter = { 0 };

	cds_lfht_for_each_entry(ht, &iter, entry, node) {
		ISC_LIST_APPEND(dellist, entry, link);
	}

	ISC_LIST_FOREACH (dellist, elem, link) {
		RUNTIME_CHECK(!cds_lfht_del(ht, &elem->node));
	}

	ISC_LIST_FOREACH (dellist, elem, link) {
		ISC_LIST_UNLINK(dellist, elem, link);
		cid_map_entry_free(true, &elem);
	}

	RUNTIME_CHECK(!cds_lfht_destroy(ht, NULL));
	rcu_assign_pointer(map->cid_entries, NULL);

	/* We need to acquire a memory barrier here */
	(void)isc_refcount_current(&map->references);
	map->magic = 0;
	isc_mem_putanddetach(&map->mctx, map, sizeof(*map));
}

void
isc_quic_cid_map_detach(isc_quic_cid_map_t **mapp) {
	isc_quic_cid_map_t *restrict map = NULL;

	map = *mapp;
	*mapp = NULL;

	REQUIRE(VALID_QUIC_CID_MAP_MAGIC(map));

	if (isc_refcount_decrement(&map->references) > 1) {
		return;
	}

	call_rcu(&map->head, cid_map_free_cb);
}

static int
cid_map_entry_match_cb(struct cds_lfht_node *ht_node,
		       const isc_region_t *restrict cid) {
	isc_quic_cid_map_entry_t *restrict entry =
		caa_container_of(ht_node, isc_quic_cid_map_entry_t, node);
	isc_region_t entry_cid = { 0 };

	isc_quic_cid_data(entry->cid, &entry_cid);

	return (entry_cid.length == cid->length) &&
	       memcmp(cid->base, entry_cid.base, entry_cid.length) == 0;
}

static inline isc_quic_cid_map_entry_t *
cid_map_entry_lookup(struct cds_lfht *ht, uint32_t hash,
		     const isc_region_t *restrict cid) {
	isc_quic_cid_map_entry_t *restrict found_entry = NULL;
	struct cds_lfht_iter iter = { 0 };
	struct cds_lfht_node *restrict found_node = NULL;

	if (hash == 0) {
		hash = isc_hash32(cid->base, cid->length, false);
	}

	cds_lfht_lookup(ht, hash, (cds_lfht_match_fct)cid_map_entry_match_cb,
			(void *)cid, &iter);
	found_node = cds_lfht_iter_get_node(&iter);
	if (found_node != NULL) {
		found_entry = caa_container_of(found_node,
					       isc_quic_cid_map_entry_t, node);
	}

	return found_entry;
}

isc_result_t
isc_quic_cid_map_find(const isc_quic_cid_map_t *restrict map,
		      const isc_region_t *restrict cid_data,
		      isc_quic_session_t **sessionp, isc_tid_t *restrict tidp) {
	REQUIRE(VALID_QUIC_CID_MAP_MAGIC(map));
	REQUIRE(sessionp != NULL && *sessionp == NULL);
	REQUIRE(tidp != NULL);

	isc_result_t result;

	rcu_read_lock();
	struct cds_lfht *ht = rcu_dereference(map->cid_entries);

	isc_quic_cid_map_entry_t *restrict entry =
		cid_map_entry_lookup(ht, 0, cid_data);

	if (entry == NULL) {
		result = ISC_R_NOTFOUND;
	} else {
		result = ISC_R_SUCCESS;

		isc_quic_session_attach(entry->session, sessionp);
		*tidp = entry->tid;
	}

	rcu_read_unlock();

	return result;
}

isc_result_t
isc_quic_cid_map_add(isc_quic_cid_map_t *restrict map,
		     isc_quic_cid_t *restrict cid,
		     isc_quic_session_t *restrict session,
		     const isc_tid_t tid) {
	REQUIRE(VALID_QUIC_CID_MAP_MAGIC(map));
	REQUIRE(cid != NULL);
	REQUIRE(session != NULL);

	isc_quic_cid_map_entry_t *new_entry = NULL;
	isc_region_t cid_data = { 0 };
	isc_result_t result = ISC_R_SUCCESS;

	new_entry = isc_mem_get(map->mctx, sizeof(*new_entry));

	*new_entry = (isc_quic_cid_map_entry_t){ .tid = tid,
						 .link = ISC_LINK_INITIALIZER };
	cds_lfht_node_init(&new_entry->node);

	isc_quic_cid_data(cid, &cid_data);

	const uint32_t hash = isc_hash32(cid_data.base, cid_data.length, false);

	rcu_read_lock();
	struct cds_lfht *ht = rcu_dereference(map->cid_entries);
	struct cds_lfht_node *ret = cds_lfht_add_unique(
		ht, hash, (cds_lfht_match_fct)cid_map_entry_match_cb, &cid_data,
		&new_entry->node);
	isc_mem_attach(map->mctx, &new_entry->mctx);
	isc_quic_session_attach(session, &new_entry->session);
	isc_quic_cid_attach(cid, &new_entry->cid);

	if (ret != &new_entry->node) {
		/* the key is present in the map */
		cid_map_entry_free(true, &new_entry);
		result = ISC_R_EXISTS;
	}
	rcu_read_unlock();

	return result;
}

static inline uint32_t
cid_map_generate_buf(struct cds_lfht *ht, void *restrict buf,
		     const size_t buflen) {
	uint32_t hash = 0;
	for (;;) {
		isc_random_buf(buf, buflen);

		isc_region_t cid_data = { .base = buf, .length = buflen };
		hash = isc_hash32(cid_data.base, cid_data.length, false);

		isc_quic_cid_map_entry_t *restrict entry =
			cid_map_entry_lookup(ht, hash, &cid_data);
		if (entry == NULL) {
			break;
		}
	}

	return hash;
}

void
isc_quic_cid_map_gen_unique(isc_quic_cid_map_t *restrict map,
			    isc_quic_session_t *restrict session,
			    const isc_tid_t tid, const size_t cidlen,
			    isc_quic_cid_t **cidp) {
	REQUIRE(VALID_QUIC_CID_MAP_MAGIC(map));
	REQUIRE(session != NULL);
	REQUIRE(cidlen >= NGTCP2_MIN_CIDLEN && cidlen <= NGTCP2_MAX_CIDLEN);
	REQUIRE(cidp != NULL && *cidp == NULL);

	rcu_read_lock();
	struct cds_lfht *ht = rcu_dereference(map->cid_entries);
	ngtcp2_cid ngcid;
	isc_region_t cid_data = { 0 };
	const uint32_t hash = cid_map_generate_buf(ht, ngcid.data, cidlen);
	ngcid.datalen = cidlen;

	isc_ngtcp2_cid_region(&ngcid, &cid_data);

	isc_quic_cid_map_entry_t *restrict new_entry =
		isc_mem_get(map->mctx, sizeof(*new_entry));

	*new_entry = (isc_quic_cid_map_entry_t){ .tid = tid,
						 .link = ISC_LINK_INITIALIZER };
	cds_lfht_node_init(&new_entry->node);

	isc_mem_attach(map->mctx, &new_entry->mctx);
	isc_quic_session_attach(session, &new_entry->session);
	isc_quic_cid_create(map->mctx, &cid_data, &new_entry->cid);

	struct cds_lfht_node *ret = cds_lfht_add_unique(
		ht, hash, (cds_lfht_match_fct)cid_map_entry_match_cb, &cid_data,
		&new_entry->node);
	RUNTIME_CHECK(ret == &new_entry->node);

	isc_quic_cid_attach(new_entry->cid, cidp);
	rcu_read_unlock();
}

void
isc_quic_cid_map_gen_unique_buf(const isc_quic_cid_map_t *restrict map,
				void *restrict cidbuf, const size_t cidlen) {
	REQUIRE(VALID_QUIC_CID_MAP_MAGIC(map));
	REQUIRE(cidbuf != NULL);
	REQUIRE(cidlen >= NGTCP2_MIN_CIDLEN && cidlen <= NGTCP2_MAX_CIDLEN);

	rcu_read_lock();
	struct cds_lfht *ht = rcu_dereference(map->cid_entries);
	(void)cid_map_generate_buf(ht, cidbuf, cidlen);
	rcu_read_unlock();
}

void
isc_quic_cid_map_remove(isc_quic_cid_map_t *restrict map,
			const isc_quic_cid_t *restrict cid) {
	REQUIRE(VALID_QUIC_CID_MAP_MAGIC(map));
	REQUIRE(cid != NULL);

	isc_region_t cid_data = { 0 };

	isc_quic_cid_data(cid, &cid_data);

	const uint32_t hash = isc_hash32(cid_data.base, cid_data.length, false);

	rcu_read_lock();
	struct cds_lfht *ht = rcu_dereference(map->cid_entries);
	isc_quic_cid_map_entry_t *entry = cid_map_entry_lookup(ht, hash,
							       &cid_data);

	if (entry != NULL) {
		RUNTIME_CHECK(!cds_lfht_del(ht, &entry->node));
		rcu_read_unlock();
		cid_map_entry_free(false, &entry);
	} else {
		rcu_read_unlock();
	}
}
