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

#include <stdint.h>

#include <isc/buffer.h>
#include <isc/list.h>
#include <isc/mutex.h>
#include <isc/ngtcp2_crypto.h>
#include <isc/quic.h>
#include <isc/sockaddr.h>

#define QUIC_TOKEN_CACHE_INDEX_SIZE (1 << 8)

#define QUIC_TOKEN_CACHE_MAGIC ISC_MAGIC('Q', 'r', 'T', 'c')
#define VALID_QUIC_TOKEN_CACHE_MAGIC(t) \
	ISC_MAGIC_VALID(t, QUIC_TOKEN_CACHE_MAGIC)

typedef struct isc_quic_token_cache_entry {
	isc_mem_t *mctx;

	isc_sockaddr_t peer;
	uint8_t token_data[ISC_NGTCP2_CRYPTO_MAX_REGULAR_TOKEN_LEN * 2];
	isc_buffer_t token_buf;

	struct cds_list_head list_node;
	struct cds_lfht_node hash_node;
	struct rcu_head head;
} isc_quic_token_cache_entry_t;

struct isc_quic_token_cache {
	uint32_t magic;
	isc_refcount_t references;
	isc_mem_t *mctx;
	isc_mutex_t write_lock;

	size_t max_size;
	struct cds_lfht *idx;
	struct cds_list_head queue;
	size_t size;

	struct rcu_head head;
};

void
isc_quic_token_cache_create(isc_mem_t *mctx, const size_t max_size,
			    isc_quic_token_cache_t **pcache) {
	REQUIRE(mctx != NULL);
	REQUIRE(max_size > 0);
	REQUIRE(pcache != NULL && *pcache == NULL);

	isc_quic_token_cache_t *restrict new_cache =
		isc_mem_get(mctx, sizeof(*new_cache));

	*new_cache = (isc_quic_token_cache_t){
		.max_size = max_size,
	};

	isc_refcount_init(&new_cache->references, 1);

	isc_mem_attach(mctx, &new_cache->mctx);

	new_cache->idx = cds_lfht_new(
		QUIC_TOKEN_CACHE_INDEX_SIZE, QUIC_TOKEN_CACHE_INDEX_SIZE, 0,
		CDS_LFHT_AUTO_RESIZE | CDS_LFHT_ACCOUNTING, NULL);
	RUNTIME_CHECK(new_cache->idx != NULL);

	CDS_INIT_LIST_HEAD(&new_cache->queue);

	isc_mutex_init(&new_cache->write_lock);

	new_cache->magic = QUIC_TOKEN_CACHE_MAGIC;
	*pcache = new_cache;
}

void
isc_quic_token_cache_attach(isc_quic_token_cache_t *source,
			    isc_quic_token_cache_t **ptarget) {
	REQUIRE(VALID_QUIC_TOKEN_CACHE_MAGIC(source));
	REQUIRE(ptarget != NULL && *ptarget == NULL);

	isc_refcount_increment(&source->references);

	*ptarget = source;
}

static void
quic_token_cache_entry_free_cb(struct rcu_head *entry_head) {
	isc_quic_token_cache_entry_t *restrict entry = caa_container_of(
		entry_head, isc_quic_token_cache_entry_t, head);

	isc_buffer_clearmctx(&entry->token_buf);
	isc_mem_putanddetach(&entry->mctx, entry, sizeof(*entry));
}

static void
quic_token_cache_entry_free(const bool immediately,
			    isc_quic_token_cache_entry_t *restrict entry) {
	if (immediately) {
		quic_token_cache_entry_free_cb(&entry->head);
		return;
	}

	call_rcu(&entry->head, quic_token_cache_entry_free_cb);
}

static void
quic_token_cache_free_cb(struct rcu_head *cache_head) {
	isc_quic_token_cache_t *restrict cache =
		caa_container_of(cache_head, isc_quic_token_cache_t, head);

	LOCK(&cache->write_lock);

	struct cds_lfht *ht = rcu_dereference(cache->idx);
	isc_quic_token_cache_entry_t *restrict entry, *restrict p;

	cds_list_for_each_entry_safe(entry, p, &cache->queue, list_node) {
		cds_list_del(&entry->list_node);
		RUNTIME_CHECK(!cds_lfht_del(ht, &entry->hash_node));
		quic_token_cache_entry_free(true, entry);
	}

	RUNTIME_CHECK(!cds_lfht_destroy(ht, NULL));
	rcu_assign_pointer(cache->idx, NULL);
	cache->size = 0;

	UNLOCK(&cache->write_lock);

	isc_mutex_destroy(&cache->write_lock);

	/* We need to acquire a memory barrier here */
	(void)isc_refcount_current(&cache->references);
	cache->magic = 0;
	isc_mem_putanddetach(&cache->mctx, cache, sizeof(*cache));
}

void
isc_quic_token_cache_detach(isc_quic_token_cache_t **pcache) {
	isc_quic_token_cache_t *restrict cache = NULL;

	cache = *pcache;
	*pcache = NULL;

	REQUIRE(VALID_QUIC_TOKEN_CACHE_MAGIC(cache));

	if (isc_refcount_decrement(&cache->references) > 1) {
		return;
	}

	call_rcu(&cache->head, quic_token_cache_free_cb);
}

static int
quic_token_cache_entry_match_cb(struct cds_lfht_node *ht_node,
				const isc_sockaddr_t *restrict remote_peer) {
	isc_quic_token_cache_entry_t *restrict entry = caa_container_of(
		ht_node, isc_quic_token_cache_entry_t, hash_node);

	return isc_sockaddr_equal(&entry->peer, remote_peer);
}

static inline isc_quic_token_cache_entry_t *
quic_token_cache_entry_lookup(struct cds_lfht *ht, uint32_t hash,
			      const isc_sockaddr_t *restrict remote_peer) {
	isc_quic_token_cache_entry_t *restrict found_entry = NULL;
	struct cds_lfht_iter iter = { 0 };
	struct cds_lfht_node *restrict found_node = NULL;

	if (hash == 0) {
		hash = isc_sockaddr_hash(remote_peer, false);
	}

	cds_lfht_lookup(ht, hash,
			(cds_lfht_match_fct)quic_token_cache_entry_match_cb,
			(void *)remote_peer, &iter);

	found_node = cds_lfht_iter_get_node(&iter);
	if (found_node != NULL) {
		found_entry = caa_container_of(
			found_node, isc_quic_token_cache_entry_t, hash_node);
	}

	return found_entry;
}

isc_result_t
isc_quic_token_cache_reuse(isc_quic_token_cache_t *restrict cache,
			   const isc_sockaddr_t *restrict remote_peer,
			   isc_quic_session_t *restrict session) {
	REQUIRE(VALID_QUIC_TOKEN_CACHE_MAGIC(cache));
	REQUIRE(remote_peer != NULL);
	REQUIRE(session != NULL);

	isc_result_t result;

	rcu_read_lock();
	struct cds_lfht *ht = rcu_dereference(cache->idx);

	isc_quic_token_cache_entry_t *restrict entry =
		quic_token_cache_entry_lookup(ht, 0, remote_peer);

	if (entry == NULL) {
		result = ISC_R_NOTFOUND;
	} else {
		isc_region_t token = { 0 };
		result = ISC_R_SUCCESS;

		isc_buffer_usedregion(&entry->token_buf, &token);
		isc_quic_session_set_regular_token(session, &token);
	}
	rcu_read_unlock();

	return result;
}

void
isc_quic_token_cache_keep(isc_quic_token_cache_t *restrict cache,
			  const isc_sockaddr_t *restrict remote_peer,
			  const isc_region_t *token_data) {
	REQUIRE(VALID_QUIC_TOKEN_CACHE_MAGIC(cache));
	REQUIRE(remote_peer != NULL);
	REQUIRE(token_data != NULL && token_data->base != NULL &&
		token_data->length > 0);

	LOCK(&cache->write_lock);
	rcu_read_lock();
	struct cds_lfht *ht = rcu_dereference(cache->idx);

	isc_quic_token_cache_entry_t *restrict entry =
		quic_token_cache_entry_lookup(ht, 0, remote_peer);

	if (entry != NULL) {
		/* update the token with a more recent one */
		isc_buffer_clear(&entry->token_buf);
		isc_buffer_putmem(&entry->token_buf, token_data->base,
				  token_data->length);

		cds_list_del_init(&entry->list_node);
		cds_list_add(&entry->list_node, &cache->queue);
	} else {
		/* remove the oldest entry from the cache if full */
		if (cache->size == cache->max_size) {
			INSIST(!cds_list_empty(&cache->queue));
			struct cds_list_head *list_tail = cache->queue.prev;
			isc_quic_token_cache_entry_t *restrict oldentry =
				cds_list_entry(list_tail,
					       isc_quic_token_cache_entry_t,
					       list_node);

			cds_list_del(&oldentry->list_node);
			cds_lfht_del(ht, &oldentry->hash_node);
			quic_token_cache_entry_free(false, oldentry);
			cache->size--;
		}
		/* time to allocate a new entry */
		INSIST(cache->size < cache->max_size);

		entry = isc_mem_get(cache->mctx, sizeof(*entry));
		*entry = (isc_quic_token_cache_entry_t){ .peer = *remote_peer };

		isc_mem_attach(cache->mctx, &entry->mctx);
		ISC_LINK_INIT_TYPE(&entry->peer, link, isc_sockaddr_t);
		isc_buffer_init(&entry->token_buf, &entry->token_data,
				sizeof(entry->token_data));
		isc_buffer_setmctx(&entry->token_buf, cache->mctx);
		isc_buffer_putmem(&entry->token_buf, token_data->base,
				  token_data->length);
		CDS_INIT_LIST_HEAD(&entry->list_node);
		cds_lfht_node_init(&entry->hash_node);

		cds_list_add(&entry->list_node, &cache->queue);

		uint32_t hash = isc_sockaddr_hash(remote_peer, false);
		struct cds_lfht_node *ret = cds_lfht_add_unique(
			ht, hash,
			(cds_lfht_match_fct)quic_token_cache_entry_match_cb,
			remote_peer, &entry->hash_node);
		RUNTIME_CHECK(ret == &entry->hash_node);

		cache->size++;
	}
	rcu_read_unlock();
	UNLOCK(&cache->write_lock);
}
