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

#include <isc/async.h>
#include <isc/barrier.h>
#include <isc/loop.h>
#include <isc/ngtcp2_crypto.h>
#include <isc/ngtcp2_utils.h>
#include <isc/quic.h>
#include <isc/random.h>
#include <isc/timer.h>
#include <isc/urcu.h>

#define QUIC_SM_MAGIC	       ISC_MAGIC('Q', 's', 'M', 'g')
#define VALID_QUIC_SM_MAGIC(t) ISC_MAGIC_VALID(t, QUIC_SM_MAGIC)

typedef struct isc_quic_session_entry {
	isc_mem_t *mctx;
	isc_tid_t current_tid;
	isc_quic_sm_t *pmgr;
	isc_quic_session_t *session;
	isc_timer_t *expiry_timer;
	isc_timer_t *close_timer;
	struct cds_list_head list_node;
	struct rcu_head head;
} isc_quic_session_entry_t;

struct isc_quic_sm {
	uint32_t magic;
	isc_refcount_t references;
	isc_mem_t *mctx;
	isc_mutex_t write_lock;

	bool is_server;

	struct cds_list_head *lists;
	size_t nworkers;
	size_t total_count;

	isc_barrier_t barrier;

	isc_tlsctx_t *tlsctx;
	isc_tlsctx_client_session_cache_t *client_sess_cache;
	isc_quic_session_interface_t session_inteface;
	isc_quic_sm_interface_t sm_interface;
	void *sm_cbarg;

	uint8_t secret[ISC_NGTCP2_CRYPTO_STATIC_SECRET_LEN];

	uint32_t handshake_timeout_ms;
	uint32_t idle_timeout_ms;
	size_t max_uni_streams;
	size_t max_bidi_streams;

	uint32_t orig_client_chosen_version;
	uint32_t available_versions_list_storage[8];
	isc_buffer_t available_versions;

	isc_quic_cid_map_t *src_cids;
	isc_quic_cid_map_t *dst_cids;
	isc_quic_token_cache_t *token_cache;
	struct rcu_head head;
};

static void
quic_sm_entry_free(const bool immediately,
		   isc_quic_session_entry_t *restrict entry);

static uint64_t
quic_sm_sess_get_current_ts_cb(void *restrict cbarg) {
	UNUSED(cbarg);
	return isc_time_monotonic();
}

static void
quic_sm_on_expiry_timer(isc_quic_session_entry_t *restrict sess_entry,
			const isc_result_t expiry_result,
			isc_quic_out_pkt_t *restrict out_pkt) {
	isc_region_t pkt_data = { 0 };
	bool ret = true;
	if (out_pkt->pktsz > 0) {
		pkt_data = out_pkt->pktbuf;
		pkt_data.length = out_pkt->pktsz;
	}
	if (sess_entry->pmgr != NULL) {
		ret = sess_entry->pmgr->sm_interface.on_expiry_timer(
			sess_entry->pmgr, sess_entry->session, expiry_result,
			&out_pkt->local, &out_pkt->peer, &pkt_data,
			sess_entry->pmgr->sm_cbarg);
	}
	if (ret) {
		isc_quic_session_update_expiry_timer(sess_entry->session);
	} else {
		isc_quic_session_finish(sess_entry->session);
	}
}

static void
quic_sm_sess_on_expiry_timer_cb(void *restrict cbarg) {
	isc_quic_session_entry_t *restrict sess_entry =
		(isc_quic_session_entry_t *)cbarg;
	uint8_t out_pkt_data[NGTCP2_MAX_UDP_PAYLOAD_SIZE];
	isc_quic_out_pkt_t out_pkt;

	if (sess_entry->pmgr != NULL) {
		INSIST(VALID_QUIC_SM_MAGIC(sess_entry->pmgr));
	}

	isc_quic_out_pkt_init(&out_pkt, out_pkt_data, sizeof(out_pkt_data));

	isc_result_t result =
		isc_quic_session_on_expiry_timer(sess_entry->session, &out_pkt);
	quic_sm_on_expiry_timer(sess_entry, result, &out_pkt);
}

static void
quic_sm_sess_expiry_timer_start_cb(isc_quic_session_t *restrict session,
				   const uint32_t timeout_ms, void *cbarg) {
	isc_quic_session_entry_t *restrict sess_entry =
		(isc_quic_session_entry_t *)cbarg;
	REQUIRE(VALID_QUIC_SM_MAGIC(sess_entry->pmgr));
	REQUIRE(sess_entry->session == session);

	if (timeout_ms == 0) {
		isc_async_run(isc_loop(), quic_sm_sess_on_expiry_timer_cb,
			      sess_entry);
		return;
	}

	isc_time_t timeout = {
		.seconds = timeout_ms / MS_PER_SEC,
		.nanoseconds = (timeout_ms % MS_PER_SEC) * NS_PER_MS,
	};

	if (sess_entry->expiry_timer == NULL) {
		isc_timer_create(isc_loop(), quic_sm_sess_on_expiry_timer_cb,
				 sess_entry, &sess_entry->expiry_timer);
	}

	isc_timer_start(sess_entry->expiry_timer, isc_timertype_once, &timeout);
}

static void
quic_sm_sess_expiry_timer_stop_cb(isc_quic_session_t *restrict session,
				  void *cbarg) {
	isc_quic_session_entry_t *restrict sess_entry =
		(isc_quic_session_entry_t *)cbarg;

	REQUIRE(VALID_QUIC_SM_MAGIC(sess_entry->pmgr));
	REQUIRE(sess_entry->session == session);

	if (sess_entry->expiry_timer != NULL) {
		isc_timer_stop(sess_entry->expiry_timer);
	}
}

static bool
quic_sm_sess_gen_unique_cid_cb(isc_quic_session_t *restrict session,
			       const size_t cidlen, const bool source,
			       void *cbarg, isc_quic_cid_t **restrict pcid) {
	isc_quic_session_entry_t *restrict sess_entry =
		(isc_quic_session_entry_t *)cbarg;

	REQUIRE(VALID_QUIC_SM_MAGIC(sess_entry->pmgr));
	REQUIRE(sess_entry->session == session);

	isc_quic_cid_map_gen_unique(source ? sess_entry->pmgr->src_cids
					   : sess_entry->pmgr->dst_cids,
				    session, isc_tid(), cidlen, pcid);

	return true;
}

static bool
quic_sm_sess_assoc_conn_cid_cb(isc_quic_session_t *restrict session,
			       isc_region_t *restrict cid_data,
			       const bool source, void *cbarg,
			       isc_quic_cid_t **restrict pcid) {
	isc_quic_session_entry_t *restrict sess_entry =
		(isc_quic_session_entry_t *)cbarg;
	isc_quic_cid_t *new_cid = NULL;

	REQUIRE(VALID_QUIC_SM_MAGIC(sess_entry->pmgr));
	REQUIRE(sess_entry->session == session);

	isc_quic_cid_create(sess_entry->mctx, cid_data, &new_cid);

	isc_result_t result =
		isc_quic_cid_map_add(source ? sess_entry->pmgr->src_cids
					    : sess_entry->pmgr->dst_cids,
				     new_cid, session, isc_tid());

	if (result == ISC_R_SUCCESS) {
		*pcid = new_cid;
	} else {
		isc_quic_cid_detach(&new_cid);
	}
	return result == ISC_R_SUCCESS;
}

static void
quic_sm_sess_deassoc_conn_cid_cb(isc_quic_session_t *restrict session,
				 const bool source, void *cbarg,
				 isc_quic_cid_t **restrict pcid) {
	isc_quic_session_entry_t *restrict sess_entry =
		(isc_quic_session_entry_t *)cbarg;

	REQUIRE(VALID_QUIC_SM_MAGIC(sess_entry->pmgr));
	REQUIRE(sess_entry->session == session);

	isc_quic_cid_map_remove(source ? sess_entry->pmgr->src_cids
				       : sess_entry->pmgr->dst_cids,
				*pcid);

	isc_quic_cid_detach(pcid);
}

static bool
quic_sm_sess_on_new_regular_token_cb(isc_quic_session_t *restrict session,
				     isc_region_t *restrict token_data,
				     isc_sockaddr_t *restrict local,
				     const isc_sockaddr_t *restrict peer,
				     void *cbarg) {
	isc_quic_session_entry_t *restrict sess_entry =
		(isc_quic_session_entry_t *)cbarg;

	REQUIRE(session != NULL);
	REQUIRE(token_data != NULL);
	REQUIRE(peer != NULL);
	REQUIRE(VALID_QUIC_SM_MAGIC(sess_entry->pmgr));
	REQUIRE(sess_entry->session == session);

	UNUSED(local);

	INSIST(!sess_entry->pmgr->is_server);

	if (sess_entry->pmgr->token_cache != NULL) {
		isc_quic_token_cache_keep(sess_entry->pmgr->token_cache, peer,
					  token_data);
	}

	return true;
}

static bool
quic_sm_sess_on_handshake_cb(isc_quic_session_t *session, void *cbarg) {
	isc_quic_session_entry_t *restrict sess_entry =
		(isc_quic_session_entry_t *)cbarg;

	REQUIRE(VALID_QUIC_SM_MAGIC(sess_entry->pmgr));
	REQUIRE(sess_entry->session == session);

	return sess_entry->pmgr->sm_interface.on_handshake(
		sess_entry->pmgr, session, sess_entry->pmgr->sm_cbarg);
}

static bool
quic_sm_sess_on_remote_stream_open_cb(isc_quic_session_t *session,
				      const int64_t stream_id, void *cbarg) {
	isc_quic_session_entry_t *restrict sess_entry =
		(isc_quic_session_entry_t *)cbarg;

	REQUIRE(VALID_QUIC_SM_MAGIC(sess_entry->pmgr));
	REQUIRE(sess_entry->session == session);

	return sess_entry->pmgr->sm_interface.on_remote_stream_open(
		sess_entry->pmgr, session, stream_id,
		sess_entry->pmgr->sm_cbarg);
}

static bool
quic_sm_sess_on_remote_stream_close_cb(isc_quic_session_t *session,
				       const int64_t streamd_id,
				       const bool app_error_set,
				       const uint64_t app_error_code,
				       void *cbarg, void *stream_user_data) {
	isc_quic_session_entry_t *restrict sess_entry =
		(isc_quic_session_entry_t *)cbarg;

	REQUIRE(VALID_QUIC_SM_MAGIC(sess_entry->pmgr));
	REQUIRE(sess_entry->session == session);

	return sess_entry->pmgr->sm_interface.on_stream_close(
		sess_entry->pmgr, session, streamd_id, app_error_set,
		app_error_code, cbarg, stream_user_data);
}

static bool
quic_sm_sess_on_recv_stream_data_cb(isc_quic_session_t *session,
				    const int64_t stream_id, const bool fin,
				    const uint64_t offset,
				    const isc_region_t *restrict data,
				    void *cbarg, void *user_stream_data) {
	isc_quic_session_entry_t *restrict sess_entry =
		(isc_quic_session_entry_t *)cbarg;

	REQUIRE(VALID_QUIC_SM_MAGIC(sess_entry->pmgr));
	REQUIRE(sess_entry->session == session);

	return sess_entry->pmgr->sm_interface.on_recv_stream_data(
		sess_entry->pmgr, session, stream_id, fin, offset, data,
		sess_entry->pmgr->sm_cbarg, user_stream_data);
}

static void
quic_sm_sess_on_close_timer_cb(void *restrict cbarg) {
	isc_quic_session_entry_t *restrict sess_entry =
		(isc_quic_session_entry_t *)cbarg;

	REQUIRE(VALID_QUIC_SM_MAGIC(sess_entry->pmgr));

	isc_quic_session_finish(sess_entry->session);

	sess_entry->pmgr->sm_interface.on_conn_close(
		sess_entry->pmgr, sess_entry->session,
		sess_entry->pmgr->sm_cbarg);

	LOCK(&sess_entry->pmgr->write_lock);
	cds_list_del(&sess_entry->list_node);
	sess_entry->pmgr->total_count--;
	UNLOCK(&sess_entry->pmgr->write_lock);

	if (sess_entry->close_timer != NULL) {
		isc_timer_async_destroy(&sess_entry->close_timer);
	}
	quic_sm_entry_free(false, sess_entry);
}

static void
quic_sm_sess_on_conn_close_cb(isc_quic_session_t *session,
			      const uint32_t closing_timeout_ms,
			      const bool ver_neg, void *cbarg) {
	isc_quic_session_entry_t *restrict sess_entry =
		(isc_quic_session_entry_t *)cbarg;

	REQUIRE(VALID_QUIC_SM_MAGIC(sess_entry->pmgr));
	REQUIRE(sess_entry->session == session);

	if (sess_entry->expiry_timer != NULL) {
		isc_timer_stop(sess_entry->expiry_timer);
	}

	if (ver_neg || closing_timeout_ms == 0) {
		quic_sm_sess_on_close_timer_cb(cbarg);
		return;
	}

	isc_time_t timeout = {
		.seconds = closing_timeout_ms / MS_PER_SEC,
		.nanoseconds = (closing_timeout_ms % MS_PER_SEC) * NS_PER_MS,
	};

	isc_timer_create(isc_loop(), quic_sm_sess_on_close_timer_cb, sess_entry,
			 &sess_entry->close_timer);

	isc_timer_start(sess_entry->close_timer, isc_timertype_once, &timeout);
}

void
isc_quic_sm_create(isc_mem_t *mctx, const size_t nworkers, isc_tlsctx_t *tlsctx,
		   isc_tlsctx_client_session_cache_t *client_sess_cache,
		   isc_quic_sm_interface_t *restrict cb, void *cbarg,
		   const uint32_t handshake_timeout_ms,
		   const uint32_t idle_timeout_ms, const size_t max_uni_streams,
		   const size_t max_bidi_streams,
		   const uint32_t client_chosen_version,
		   const uint32_t *available_versions,
		   const size_t available_versions_len, const bool is_server,
		   const size_t client_token_cache_size, isc_quic_sm_t **mgrp) {
	isc_quic_sm_t *mgr = NULL;

	REQUIRE(mctx != NULL);
	REQUIRE(tlsctx != NULL);
	REQUIRE(cb != NULL);
	REQUIRE(handshake_timeout_ms > 0);
	REQUIRE(idle_timeout_ms > 0);
	REQUIRE(max_uni_streams > 0 || max_bidi_streams > 0);
	REQUIRE(client_token_cache_size == 0 || !is_server);

	mgr = isc_mem_get(mctx, sizeof(*mgr));
	*mgr = (isc_quic_sm_t){
		.is_server = is_server,
		.sm_cbarg = cbarg,
		.handshake_timeout_ms = handshake_timeout_ms,
		.idle_timeout_ms = idle_timeout_ms,
		.max_uni_streams = max_uni_streams,
		.max_bidi_streams = max_bidi_streams,
		.orig_client_chosen_version = client_chosen_version,
		.nworkers = nworkers,
	};

	isc_refcount_init(&mgr->references, 1);
	isc_mem_attach(mctx, &mgr->mctx);
	isc_tlsctx_attach(tlsctx, &mgr->tlsctx);
	if (!is_server && client_sess_cache != NULL) {
		isc_tlsctx_client_session_cache_attach(client_sess_cache,
						       &mgr->client_sess_cache);
	}

	isc_buffer_init(&mgr->available_versions,
			mgr->available_versions_list_storage,
			sizeof(mgr->available_versions_list_storage));
	isc_buffer_setmctx(&mgr->available_versions, mctx);

	mgr->lists = isc_mem_get(mctx, nworkers * sizeof(mgr->lists[0]));
	for (size_t i = 0; i < nworkers; i++) {
		CDS_INIT_LIST_HEAD(&mgr->lists[i]);
	}

	if (available_versions != NULL && available_versions_len > 0) {
		/* Copy the supported versions list */
		isc_buffer_putmem(&mgr->available_versions,
				  (const uint8_t *)available_versions,
				  available_versions_len *
					  sizeof(*available_versions));
	}

	isc_quic_cid_map_create(mctx, &mgr->src_cids);
	isc_quic_cid_map_create(mctx, &mgr->dst_cids);

	if (!is_server && client_token_cache_size > 0) {
		isc_quic_token_cache_create(mctx, client_token_cache_size,
					    &mgr->token_cache);
	}

	mgr->session_inteface = (isc_quic_session_interface_t){
		.get_current_ts = quic_sm_sess_get_current_ts_cb,
		.expiry_timer_start = quic_sm_sess_expiry_timer_start_cb,
		.expiry_timer_stop = quic_sm_sess_expiry_timer_stop_cb,
		.gen_unique_cid = quic_sm_sess_gen_unique_cid_cb,
		.assoc_conn_cid = quic_sm_sess_assoc_conn_cid_cb,
		.deassoc_conn_cid = quic_sm_sess_deassoc_conn_cid_cb,
		.on_handshake = quic_sm_sess_on_handshake_cb,
		.on_new_regular_token = quic_sm_sess_on_new_regular_token_cb,
		.on_remote_stream_open = quic_sm_sess_on_remote_stream_open_cb,
		.on_stream_close = quic_sm_sess_on_remote_stream_close_cb,
		.on_recv_stream_data = quic_sm_sess_on_recv_stream_data_cb,
		.on_conn_close = quic_sm_sess_on_conn_close_cb,
	};

	INSIST(cb->on_handshake != NULL);
	INSIST(cb->on_expiry_timer != NULL);
	INSIST(cb->on_remote_stream_open != NULL);
	INSIST(cb->on_stream_close != NULL);
	INSIST(cb->on_recv_stream_data != NULL);
	INSIST(cb->on_conn_close != NULL);

	mgr->sm_interface = *cb;
	mgr->sm_cbarg = cbarg;

	isc_random_buf(mgr->secret, sizeof(mgr->secret));

	isc_mutex_init(&mgr->write_lock);
	isc_barrier_init(&mgr->barrier, nworkers);

	mgr->magic = QUIC_SM_MAGIC;
	*mgrp = mgr;
}

void
isc_quic_sm_attach(isc_quic_sm_t *source, isc_quic_sm_t **targetp) {
	REQUIRE(VALID_QUIC_SM_MAGIC(source));
	REQUIRE(targetp != NULL && *targetp == NULL);

	isc_refcount_increment(&source->references);

	*targetp = source;
}

static void
quic_sm_entry_free_cb(struct rcu_head *entry_head) {
	isc_quic_session_entry_t *restrict entry =
		caa_container_of(entry_head, isc_quic_session_entry_t, head);

	if (entry->session != NULL) {
		isc_quic_session_detach(&entry->session);
	}

	isc_mem_putanddetach(&entry->mctx, entry, sizeof(*entry));
}

static void
quic_sm_entry_free(const bool immediately,
		   isc_quic_session_entry_t *restrict entry) {
	if (immediately) {
		quic_sm_entry_free_cb(&entry->head);
		return;
	}

	call_rcu(&entry->head, quic_sm_entry_free_cb);
}

static void
quic_sm_free_cb(struct rcu_head *cache_head) {
	isc_quic_sm_t *restrict mgr = caa_container_of(cache_head,
						       isc_quic_sm_t, head);

	LOCK(&mgr->write_lock);

	for (int32_t i = 0; i < (isc_tid_t)mgr->nworkers; i++) {
		isc_quic_session_entry_t *restrict entry = NULL, *restrict p =
									 NULL;
		cds_list_for_each_entry_safe(entry, p, &mgr->lists[i],
					     list_node)
		{
			cds_list_del(&entry->list_node);
			quic_sm_entry_free(true, entry);
		}
	}

	isc_mem_put(mgr->mctx, mgr->lists,
		    sizeof(mgr->lists[0]) * mgr->nworkers);

	mgr->total_count = 0;
	isc_buffer_clearmctx(&mgr->available_versions);
	UNLOCK(&mgr->write_lock);

	isc_mutex_destroy(&mgr->write_lock);
	isc_barrier_destroy(&mgr->barrier);

	/* We need to acquire a memory barrier here */
	(void)isc_refcount_current(&mgr->references);
	mgr->magic = 0;
	isc_mem_putanddetach(&mgr->mctx, mgr, sizeof(*mgr));
}

void
isc_quic_sm_detach(isc_quic_sm_t **targetp) {
	isc_quic_sm_t *restrict mgr = *targetp;

	REQUIRE(VALID_QUIC_SM_MAGIC(mgr));

	*targetp = NULL;

	if (isc_refcount_decrement(&mgr->references) > 1) {
		return;
	}

	isc_quic_sm_finish(mgr, isc_tid());

	call_rcu(&mgr->head, quic_sm_free_cb);
}

static isc_quic_session_entry_t *
quic_sm_alloc_entry(isc_quic_sm_t *mgr, const isc_tid_t current_tid) {
	REQUIRE(VALID_QUIC_SM_MAGIC(mgr));

	isc_quic_session_entry_t *restrict entry = NULL;

	entry = isc_mem_get(mgr->mctx, sizeof(*entry));
	*entry = (isc_quic_session_entry_t){
		.current_tid = current_tid,
	};

	isc_mem_attach(mgr->mctx, &entry->mctx);
	isc_quic_sm_attach(mgr, &entry->pmgr);

	CDS_INIT_LIST_HEAD(&entry->list_node);

	return entry;
}

isc_result_t
isc_quic_sm_connect(isc_quic_sm_t *restrict mgr, const isc_tid_t current_tid,
		    const isc_sockaddr_t *restrict local,
		    const isc_sockaddr_t *restrict peer,
		    const char *sni_hostname, isc_quic_out_pkt_t *out_pkt,
		    isc_quic_session_t **sessionp) {
	isc_quic_session_t *session = NULL;

	REQUIRE(VALID_QUIC_SM_MAGIC(mgr));
	REQUIRE(!mgr->is_server);
	REQUIRE(local != NULL);
	REQUIRE(peer != NULL);
	REQUIRE(sni_hostname == NULL || *sni_hostname != '\0');
	REQUIRE(out_pkt != NULL);
	REQUIRE(sessionp != NULL && *sessionp == NULL);

	isc_quic_session_entry_t *new_entry = quic_sm_alloc_entry(mgr,
								  current_tid);
	isc_region_t secret = { .base = mgr->secret,
				.length = sizeof(mgr->secret) };
	isc_region_t versions = { 0 };

	isc_buffer_usedregion(&mgr->available_versions, &versions);

	isc_quic_session_create(
		mgr->mctx, mgr->tlsctx, sni_hostname, mgr->client_sess_cache,
		&mgr->session_inteface, new_entry, local, peer,
		mgr->handshake_timeout_ms, mgr->idle_timeout_ms,
		mgr->max_uni_streams, mgr->max_bidi_streams,
		mgr->orig_client_chosen_version, (uint32_t *)versions.base,
		versions.length / sizeof(uint32_t), &secret, false, NULL,
		&session);

	isc_quic_session_attach(session, &new_entry->session);

	if (mgr->token_cache != NULL) {
		(void)isc_quic_token_cache_reuse(mgr->token_cache, peer,
						 session);
	}

	LOCK(&mgr->write_lock);
	cds_list_add(&new_entry->list_node, &mgr->lists[current_tid]);
	mgr->total_count++;
	UNLOCK(&mgr->write_lock);

	isc_result_t result = isc_quic_session_connect(session, out_pkt);

	if (result != ISC_R_SUCCESS) {
		LOCK(&mgr->write_lock);
		cds_list_del(&new_entry->list_node);
		mgr->total_count--;
		UNLOCK(&mgr->write_lock);
		quic_sm_entry_free(true, new_entry);
		isc_quic_session_detach(&session);
	} else {
		*sessionp = session;
	}

	return result;
}

isc_result_t
isc_quic_sm_route_pkt(isc_quic_sm_t *restrict mgr, const isc_tid_t current_tid,
		      const bool server_over_quota,
		      const isc_region_t *restrict pkt,
		      const isc_sockaddr_t *restrict local,
		      const isc_sockaddr_t *restrict peer,
		      isc_quic_out_pkt_t *restrict out_pkt,
		      bool *restrict new_connp,
		      isc_tid_t *restrict session_tidp,
		      isc_quic_session_t **sessionp) {
	REQUIRE(VALID_QUIC_SM_MAGIC(mgr));
	REQUIRE(pkt != NULL && pkt->base != NULL && pkt->length > 0);
	REQUIRE(local != NULL);
	REQUIRE(peer != NULL);
	REQUIRE(out_pkt != NULL);
	REQUIRE(new_connp != NULL && *new_connp == false);
	REQUIRE(session_tidp != NULL && *session_tidp < 0);
	REQUIRE(sessionp != NULL && *sessionp == NULL);

	isc_quic_session_t *found_session = NULL;
	isc_tid_t found_tid = 0;
	uint8_t token_odcid_data[ISC_NGTCP2_MAX_POSSIBLE_CID_LENGTH];
	isc_buffer_t token_odcid_buf;
	isc_region_t token_odcid;
	bool token_verified = false;
	bool new_conn = false;

	uint32_t version = 0;
	bool is_long = false;
	isc_region_t scid = { 0 }, dcid = { 0 };

	isc_result_t result = isc_ngtcp2_decode_pkt_header(
		pkt, isc_ngtcp2_get_short_pkt_dcidlen(!mgr->is_server),
		&is_long, &scid, &dcid, &version);

	if (result != ISC_R_SUCCESS) {
		return result;
	}

	isc_buffer_init(&token_odcid_buf, token_odcid_data,
			sizeof(token_odcid_data));

	const uint64_t ts = isc_time_monotonic();
	isc_region_t secret = { .base = mgr->secret,
				.length = sizeof(mgr->secret) };
	isc_region_t versions = { 0 };

	isc_buffer_usedregion(&mgr->available_versions, &versions);

	if (mgr->is_server) {
		result = isc_quic_route_pkt(
			pkt, mgr->src_cids, &secret, (uint32_t *)versions.base,
			versions.length / sizeof(uint32_t), local, peer, &dcid,
			&scid, version, true, server_over_quota,
			isc_ngtcp2_make_duration(0, mgr->handshake_timeout_ms),
			ts, &found_session, &found_tid, &token_odcid_buf,
			out_pkt);
	} else {
		result = isc_quic_route_pkt(pkt, mgr->src_cids, NULL, NULL, 0,
					    local, peer, &dcid, &scid, version,
					    false, false, 0, ts, &found_session,
					    &found_tid, NULL, NULL);
	}

	isc_quic_session_entry_t *new_entry = NULL;

	if (result == ISC_R_SUCCESS) {
		INSIST(out_pkt->pktsz == 0);
	} else if (result == ISC_R_NOTFOUND && out_pkt->pktsz == 0 &&
		   mgr->is_server &&
		   isc_ngtcp2_pkt_header_is_long(pkt->base, pkt->length))
	{
		new_entry = quic_sm_alloc_entry(mgr, current_tid);
		isc_buffer_usedregion(&token_odcid_buf, &token_odcid);
		token_verified = true;

		isc_quic_session_create(
			mgr->mctx, mgr->tlsctx, NULL, mgr->client_sess_cache,
			&mgr->session_inteface, new_entry, local, peer,
			mgr->handshake_timeout_ms, mgr->idle_timeout_ms,
			mgr->max_uni_streams, mgr->max_bidi_streams,
			mgr->orig_client_chosen_version,
			(uint32_t *)versions.base,
			versions.length / sizeof(uint32_t), &secret, true, NULL,
			&found_session);

		isc_quic_session_attach(found_session, &new_entry->session);
		found_tid = current_tid;
		new_conn = true;

		LOCK(&mgr->write_lock);
		cds_list_add(&new_entry->list_node, &mgr->lists[current_tid]);
		mgr->total_count++;
		UNLOCK(&mgr->write_lock);
		result = ISC_R_SUCCESS;
	}

	if (out_pkt->pktsz == 0 && result == ISC_R_SUCCESS &&
	    current_tid == found_tid)
	{
		result = isc_quic_session_read_pkt(
			found_session, local, peer, version, &dcid, &scid,
			token_verified, &token_odcid, pkt, out_pkt);
	}

	if (result == ISC_R_SUCCESS) {
		isc_quic_session_update_expiry_timer(found_session);
		*sessionp = found_session;
		*session_tidp = found_tid;
		*new_connp = new_conn;
	} else {
		if (new_entry != NULL) {
			LOCK(&mgr->write_lock);
			cds_list_del(&new_entry->list_node);
			mgr->total_count--;
			UNLOCK(&mgr->write_lock);
			quic_sm_entry_free(true, new_entry);
		}

		if (found_session != NULL) {
			isc_quic_session_detach(&found_session);
		}
	}

	return result;
}

static void
quic_sm_finish_worker_job(void *arg) {
	isc_tid_t tid = isc_tid();
	isc_quic_sm_t *restrict mgr = (isc_quic_sm_t *)arg;
	isc_quic_session_entry_t *restrict entry = NULL, *restrict p = NULL;

	cds_list_for_each_entry_safe(entry, p, &mgr->lists[tid], list_node) {
		isc_quic_session_finish(entry->session);

		if (entry->expiry_timer != NULL) {
			isc_timer_stop(entry->expiry_timer);
			isc_timer_destroy(&entry->expiry_timer);
		}

		if (entry->close_timer != NULL) {
			isc_timer_stop(entry->close_timer);
			isc_timer_destroy(&entry->close_timer);
		}

		if (entry->pmgr != NULL) {
			isc_quic_sm_detach(&entry->pmgr);
		}
	}

	isc_barrier_wait(&mgr->barrier);
}

static void
quic_sm_finish_worker(isc_quic_sm_t *restrict mgr, const isc_tid_t current_tid,
		      const isc_tid_t worker_tid) {
	INSIST(worker_tid >= 0);

	if (current_tid == worker_tid) {
		quic_sm_finish_worker_job(mgr);
	} else {
		isc_async_run(isc_loop_get(worker_tid),
			      quic_sm_finish_worker_job, mgr);
	}
}

void
isc_quic_sm_finish(isc_quic_sm_t *restrict mgr, const isc_tid_t current_tid) {
	REQUIRE(VALID_QUIC_SM_MAGIC(mgr));

	for (int32_t i = 0; i < (isc_tid_t)mgr->nworkers; i++) {
		if (i == current_tid) {
			continue;
		}

		quic_sm_finish_worker(mgr, current_tid, i);
	}

	quic_sm_finish_worker(mgr, current_tid, current_tid);
}

bool
isc_quic_sm_is_server(isc_quic_sm_t *restrict mgr) {
	REQUIRE(VALID_QUIC_SM_MAGIC(mgr));

	return mgr->is_server;
}
