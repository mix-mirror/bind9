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

#include <unistd.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

#include <isc/random.h>

#include "quic_session.h"

/* define to see QUIC session callback tracing information */
#undef QUIC_SESSION_TRACE_CB

#ifdef QUIC_SESSION_TRACE_CB

#if defined(__linux__)
#include <syscall.h>
#define gettid() (uint32_t)syscall(SYS_gettid)
#else
#define gettid() (uint32_t)pthread_self()
#endif

#define QUIC_SESSION_LOG(format, ...)                                         \
	fprintf(stderr, "%" PRIu32 ":%s:%u:%s():" format, gettid(), __FILE__, \
		__LINE__, __func__, __VA_ARGS__)
#else
#define QUIC_SESSION_LOG(format, ...)
#endif

#define QUIC_SESSION_CB_TRACE() QUIC_SESSION_LOG("%s", "\n")

#define STATELESS_CLOSE_COUNT (25)

#define MAX_VERSION_NEGOTIATION_ATTEMPTS (3)

#define STREAMS_POOL_SIZE (64)
#define SENDS_POOL_SIZE	  (96)

typedef enum isc_quic_states {
	ISC_QUIC_ST_INITIAL,
	ISC_QUIC_ST_VERSION_NEGOTIATION, /* server only */
	ISC_QUIC_ST_ADDRESS_VALIDATION,	 /* server only */
	ISC_QUIC_ST_HANDSHAKE,
	ISC_QUIC_ST_CONNECTED,
	ISC_QUIC_ST_CLOSING,
	ISC_QUIC_ST_DRAINING,
	ISC_QUIC_ST_CLOSED,
	ISC_QUIC_ST_TERMINATED,

	ISC_QUIC_ST_UNEXPECTED
} isc_quic_states_t;

typedef enum isc_quic_state_event {
	/* client specific */
	ISC_QUIC_EV_INITIAL_PACKET_SENT,
	ISC_QUIC_EV_VERSION_ACCEPTED,
	ISC_QUIC_EV_STATELESS_RESET_RECEIVED,

	/* server specific */
	ISC_QUIC_EV_VALID_REGULAR_TOKEN_RECEIVED,
	ISC_QUIC_EV_INVALID_REGULAR_TOKEN_RECEIVED,
	ISC_QUIC_EV_NO_REGULAR_TOKEN_RECEIVED,
	ISC_QUIC_EV_VERSION_MISMATCH,
	ISC_QUIC_EV_VALID_RETRY_TOKEN_RECEIVED,
	ISC_QUIC_EV_INVALID_RETRY_TOKEN_RECEIVED,

	/* common */
	ISC_QUIC_EV_SELECT_COMPATIBLE_VERSION,
	ISC_QUIC_EV_HANDSHAKE_COMPLETE,
	ISC_QUIC_EV_HANDSHAKE_FAILURE,
	ISC_QUIC_EV_CLOSE_INITIATED,
	ISC_QUIC_EV_TIMEOUT,

	/* special - processed regardless of the current state */
	ISC_QUIC_EV_DROP,
	ISC_QUIC_EV_FATAL_ERROR,

	ISC_QUIC_EV_NONE
} isc_quic_state_event_t;

static inline void
quic_session_deassoc_all_cids(isc_quic_session_t *restrict session,
			      const bool keep_rcid);

static isc__quic_stream_data_t *
quic_session_lookup_stream(isc_quic_session_t *restrict session,
			   const int64_t stream_id);

static void
quic_session_track_stream(isc_quic_session_t *restrict session,
			  const int64_t stream_id, void *stream_user_data);

static void
quic_session_stream_call_pending_callbacks(isc_quic_session_t *restrict session,
					   const int64_t stream_id,
					   const isc_result_t result);

static void
quic_session_call_pending_callbacks(isc_quic_session_t *restrict session,
				    const isc_result_t result);

static void
quic_session_untrack_stream(isc_quic_session_t *restrict session,
			    const int64_t stream_id);

static void
quic_session_untrack_all_streams(isc_quic_session_t *restrict session);

static inline isc_result_t
quic_session_process_event(isc_quic_session_t *restrict session,
			   const isc_quic_state_event_t event,
			   isc_quic_out_pkt_t *restrict out_pkt);

static inline void
quic_session_write_close(isc_quic_session_t *restrict session,
			 isc_quic_out_pkt_t *restrict out_pkt);

static inline void
quic_session_drop(isc_quic_session_t *restrict session,
		  const uint32_t close_timeout_ms, const bool ver_neg);

ISC_ATTR_UNUSED static void
validate_quic_streams(isc_quic_session_t *restrict session) {
	isc__quic_stream_data_t *current = NULL;
	for (current = ISC_LIST_HEAD(session->streams.list); current != NULL;
	     current = ISC_LIST_NEXT(current, stream_link))
	{
		RUNTIME_CHECK(VALID_QUIC_STREAM(current));
		isc__quic_stream_data_t *stream =
			quic_session_lookup_stream(session, current->stream_id);
		RUNTIME_CHECK(stream == current);
	}
}

void
isc_quic_out_pkt_init(isc_quic_out_pkt_t *restrict out_pkt, uint8_t *buf,
		      const size_t buflen) {
	REQUIRE(out_pkt != NULL);
	REQUIRE(buf != NULL);
	REQUIRE(buflen >= NGTCP2_MAX_UDP_PAYLOAD_SIZE);

	*out_pkt = (isc_quic_out_pkt_t){
		.pktbuf = { .base = buf, .length = buflen },
	};
}

static inline isc_quic_states_t
common_process_event(const isc_quic_states_t state,
		     const isc_quic_state_event_t event) {
	isc_quic_states_t new_state = ISC_QUIC_ST_UNEXPECTED;
	switch (state) {
	case ISC_QUIC_ST_HANDSHAKE:
		switch (event) {
		case ISC_QUIC_EV_SELECT_COMPATIBLE_VERSION:
			new_state = ISC_QUIC_ST_INITIAL;
			break;
		case ISC_QUIC_EV_HANDSHAKE_COMPLETE:
			new_state = ISC_QUIC_ST_CONNECTED;
			break;
		case ISC_QUIC_EV_HANDSHAKE_FAILURE:
		case ISC_QUIC_EV_STATELESS_RESET_RECEIVED:
			new_state = ISC_QUIC_ST_CLOSED;
			break;
		default:
			break;
		};
		break;
	case ISC_QUIC_ST_CONNECTED:
		switch (event) {
		case ISC_QUIC_EV_CLOSE_INITIATED:
			new_state = ISC_QUIC_ST_CLOSING;
			break;
		case ISC_QUIC_EV_STATELESS_RESET_RECEIVED:
			new_state = ISC_QUIC_ST_CLOSED;
			break;
		default:
			break;
		};
		break;
	case ISC_QUIC_ST_CLOSING:
		switch (event) {
		case ISC_QUIC_EV_TIMEOUT:
			new_state = ISC_QUIC_ST_DRAINING;
			break;
		case ISC_QUIC_EV_STATELESS_RESET_RECEIVED:
			new_state = ISC_QUIC_ST_CLOSED;
			break;
		default:
			break;
		};
		break;
	case ISC_QUIC_ST_DRAINING:
		switch (event) {
		case ISC_QUIC_EV_STATELESS_RESET_RECEIVED:
			new_state = ISC_QUIC_ST_CLOSED;
			break;
		default:
			break;
		};
		break;
	case ISC_QUIC_ST_CLOSED:
		break;
	default:
		break;
	}

	return new_state;
}

static inline isc_quic_states_t
client_process_event(const isc_quic_states_t state,
		     const isc_quic_state_event_t event) {
	isc_quic_states_t new_state = ISC_QUIC_ST_UNEXPECTED;
	switch (state) {
	case ISC_QUIC_ST_INITIAL:
		switch (event) {
		case ISC_QUIC_EV_SELECT_COMPATIBLE_VERSION:
		case ISC_QUIC_EV_INITIAL_PACKET_SENT:
			new_state = ISC_QUIC_ST_INITIAL;
			break;
		case ISC_QUIC_EV_VERSION_ACCEPTED:
			new_state = ISC_QUIC_ST_HANDSHAKE;
			break;
		default:
			break;
		};
		break;
	default:
		new_state = common_process_event(state, event);
		break;
	}
	return new_state;
}

static inline isc_quic_states_t
server_process_event(const isc_quic_states_t state,
		     const isc_quic_state_event_t event) {
	isc_quic_states_t new_state = ISC_QUIC_ST_UNEXPECTED;
	switch (state) {
	case ISC_QUIC_ST_INITIAL:
		switch (event) {
		case ISC_QUIC_EV_VALID_RETRY_TOKEN_RECEIVED:
		case ISC_QUIC_EV_VALID_REGULAR_TOKEN_RECEIVED:
			new_state = ISC_QUIC_ST_HANDSHAKE;
			break;
		case ISC_QUIC_EV_INVALID_RETRY_TOKEN_RECEIVED:
			new_state = ISC_QUIC_ST_CLOSED;
			break;
		case ISC_QUIC_EV_NO_REGULAR_TOKEN_RECEIVED:
		case ISC_QUIC_EV_INVALID_REGULAR_TOKEN_RECEIVED:
			new_state = ISC_QUIC_ST_ADDRESS_VALIDATION;
			break;
		case ISC_QUIC_EV_VERSION_MISMATCH:
			new_state = ISC_QUIC_ST_VERSION_NEGOTIATION;
			break;
		default:
			break;
		};
		break;
	case ISC_QUIC_ST_VERSION_NEGOTIATION:
		switch (event) {
		case ISC_QUIC_EV_SELECT_COMPATIBLE_VERSION:
			new_state = ISC_QUIC_ST_INITIAL;
			break;
		default:
			break;
		};
		break;
	case ISC_QUIC_ST_ADDRESS_VALIDATION:
		switch (event) {
		case ISC_QUIC_EV_VALID_RETRY_TOKEN_RECEIVED:
			new_state = ISC_QUIC_ST_HANDSHAKE;
			break;
		case ISC_QUIC_EV_INVALID_RETRY_TOKEN_RECEIVED:
			new_state = ISC_QUIC_ST_CLOSED;
			break;
		default:
			break;
		};
		break;
	default:
		new_state = common_process_event(state, event);
		break;
	}
	return new_state;
}

static inline isc_quic_states_t
quic_state_transition(const bool client, const isc_quic_states_t state,
		      const isc_quic_state_event_t event) {
	/*
	 * Special ("shortcutted") events processed regardless of the
	 * current state.
	 */
	switch (event) {
	case ISC_QUIC_EV_FATAL_ERROR:
		return ISC_QUIC_ST_TERMINATED;
	case ISC_QUIC_EV_DROP:
		return ISC_QUIC_ST_CLOSED;
	default:
		break;
	};

	if (!client) {
		return server_process_event(state, event);
	}

	return client_process_event(state, event);
}

static inline void
quic_session_keep_client_tls_session(isc_quic_session_t *restrict session) {
	if (session->is_server) {
		return;
	}

	if (session->client_sess_cache != NULL && session->tls != NULL &&
	    session->client_sess_saved == false)
	{
		isc_sockaddr_t peer = isc_quic_session_peeraddr(session);
		(void)SSL_set_shutdown(session->tls, SSL_SENT_SHUTDOWN);
		isc_tlsctx_client_session_cache_keep_sockaddr(
			session->client_sess_cache, &peer, session->tls);
		session->client_sess_saved = true;
	}
}

void
isc_quic_session_set_regular_token(isc_quic_session_t *restrict session,
				   const isc_region_t *regular_token) {
	REQUIRE(VALID_QUIC_SESSION(session));
	REQUIRE(!session->is_server);
	REQUIRE(regular_token->base != NULL && regular_token->length > 0);

	if (session->state != ISC_QUIC_ST_INITIAL) {
		return;
	}

	isc_buffer_clear(&session->regular_token);
	isc_buffer_putmem(&session->regular_token, regular_token->base,
			  regular_token->length);
}

void
isc_quic_session_create(
	isc_mem_t *mctx, isc_tlsctx_t *tlsctx, const char *sni_hostname,
	isc_tlsctx_client_session_cache_t *client_sess_cache,
	const isc_quic_session_interface_t *restrict cb, void *cbarg,
	const isc_sockaddr_t *restrict local,
	const isc_sockaddr_t *restrict peer,
	const uint32_t handshake_timeout_ms, const uint32_t idle_timeout_ms,
	const size_t max_uni_streams, const size_t max_bidi_streams,
	const uint32_t client_chosen_version,
	const uint32_t *available_versions, const size_t available_versions_len,
	const isc_region_t *secret, const bool is_server,
	const isc_region_t *regular_token, isc_quic_session_t **sessionp) {
	isc_quic_session_t *session = NULL;

	REQUIRE(mctx != NULL);
	REQUIRE(tlsctx != NULL);
	REQUIRE(cb != NULL);
	REQUIRE(handshake_timeout_ms > 0);
	REQUIRE(idle_timeout_ms > 0);
	REQUIRE(max_uni_streams > 0 || max_bidi_streams > 0);
	REQUIRE(local != NULL && peer != NULL);
	REQUIRE(secret != NULL && secret->base != NULL && secret->length > 0);
	REQUIRE(regular_token == NULL ||
		(!is_server && regular_token->base != NULL &&
		 regular_token->length > 0));
	REQUIRE(sessionp != NULL && *sessionp == NULL);

	session = isc_mem_get(mctx, sizeof(*session));
	*session = (isc_quic_session_t){
		.is_server = is_server,
		.state = ISC_QUIC_ST_INITIAL,
		.handshake_timeout =
			isc_ngtcp2_make_duration(0, handshake_timeout_ms),
		.idle_timeout = isc_ngtcp2_make_duration(0, idle_timeout_ms),
		.max_uni_streams = max_uni_streams,
		.max_bidi_streams = max_bidi_streams,
		.orig_client_chosen_version = client_chosen_version,
		.negotiated_version = client_chosen_version,
		.streams.list = ISC_LIST_INITIALIZER,
		.sends.queue = ISC_LIST_INITIALIZER,
	};
	isc_refcount_init(&session->references, 1);
	isc_mem_attach(mctx, &session->mctx);
	isc_tlsctx_attach(tlsctx, &session->tlsctx);

	if (!is_server && client_sess_cache != NULL) {
		INSIST(tlsctx == isc_tlsctx_client_session_cache_getctx(
					 client_sess_cache));
		isc_tlsctx_client_session_cache_attach(
			client_sess_cache, &session->client_sess_cache);
	}

	if (!is_server && sni_hostname != NULL) {
		session->sni_hostname = isc_mem_strdup(mctx, sni_hostname);
	}

	isc_ngtcp2_path_storage_init(&session->path_st, local, peer);
	session->path = &session->path_st.path;

	isc_ngtcp2_mem_init(&session->mem, mctx);

	isc_buffer_init(&session->available_versions,
			session->available_versions_list_storage,
			sizeof(session->available_versions_list_storage));
	isc_buffer_setmctx(&session->available_versions, mctx);

	if (available_versions != NULL && available_versions_len > 0) {
		/* Copy the supported versions list */
		isc_buffer_putmem(&session->available_versions,
				  (const uint8_t *)available_versions,
				  available_versions_len *
					  sizeof(*available_versions));
	}

	isc_buffer_init(&session->secret, session->secret_storage,
			sizeof(session->secret_storage));
	isc_buffer_setmctx(&session->secret, mctx);

	isc_buffer_putmem(&session->secret, secret->base, secret->length);

	if (!is_server) {
		isc_buffer_init(&session->regular_token, session->tokenbuf,
				sizeof(session->tokenbuf));
		isc_buffer_setmctx(&session->regular_token, mctx);

		if (regular_token != NULL) {
			isc_quic_session_set_regular_token(session,
							   regular_token);
		}
	}

	ngtcp2_ccerr_default(&session->conn_err);

	isc_ht_init(&session->streams.idx, mctx, 1, ISC_HT_CASE_SENSITIVE);

	isc_mempool_create(mctx, sizeof(isc__quic_send_req_t),
			   is_server ? "QUIC_SRV_SENDS" : "QUIC_CLT_SENDS",
			   &session->sends.pool);
	isc_mempool_setfreemax(session->sends.pool, SENDS_POOL_SIZE);

	isc_mempool_create(mctx, sizeof(isc__quic_stream_data_t),
			   is_server ? "QUIC_SRV_STRMS" : "QUIC_CLT_STRMS",
			   &session->streams.pool);
	isc_mempool_setfreemax(session->streams.pool, STREAMS_POOL_SIZE);

	isc_ht_init(&session->dst_cids.idx, mctx, 1, ISC_HT_CASE_SENSITIVE);
	isc_ht_init(&session->src_cids.idx, mctx, 1, ISC_HT_CASE_SENSITIVE);

	INSIST(cb->get_current_ts != NULL);
	INSIST(cb->expiry_timer_start != NULL);
	INSIST(cb->expiry_timer_stop != NULL);
	INSIST(cb->gen_unique_cid != NULL);
	INSIST(cb->assoc_conn_cid != NULL);
	INSIST(cb->deassoc_conn_cid != NULL);
	INSIST(cb->on_handshake != NULL);
	INSIST(cb->on_remote_stream_open != NULL);
	INSIST(cb->on_stream_close != NULL);
	INSIST(cb->on_recv_stream_data != NULL);
	INSIST(cb->on_conn_close != NULL);

	session->cb = *cb;
	session->cbarg = cbarg;

	session->magic = QUIC_SESSION_MAGIC;
	*sessionp = session;
}

void
isc_quic_session_attach(isc_quic_session_t *restrict source,
			isc_quic_session_t **targetp) {
	REQUIRE(VALID_QUIC_SESSION(source));
	REQUIRE(targetp != NULL && *targetp == NULL);

	isc_refcount_increment(&source->references);

	*targetp = source;
}

void
isc_quic_session_finish(isc_quic_session_t *session) {
	REQUIRE(VALID_QUIC_SESSION(session));
	if (session->fin) {
		quic_session_deassoc_all_cids(session, false);
	}
	quic_session_drop(session, 0, false);
}

void
isc_quic_session_detach(isc_quic_session_t **sessionp) {
	isc_quic_session_t *session = NULL;

	REQUIRE(sessionp != NULL);

	session = *sessionp;
	*sessionp = NULL;

	REQUIRE(VALID_QUIC_SESSION(session));

	if (isc_refcount_decrement(&session->references) > 1) {
		return;
	}

	isc_quic_session_finish(session);

	INSIST(ISC_LIST_EMPTY(session->streams.list));
	INSIST(isc_ht_count(session->streams.idx) == 0);
	INSIST(ISC_LIST_EMPTY(session->sends.queue));

	if (session->tlsctx != NULL) {
		isc_tlsctx_free(&session->tlsctx);
	}

	if (session->client_sess_cache != NULL) {
		INSIST(!session->is_server);
		isc_tlsctx_client_session_cache_detach(
			&session->client_sess_cache);
	}

	if (session->sni_hostname != NULL) {
		isc_mem_free(session->mctx, session->sni_hostname);
	}

	isc_buffer_clearmctx(&session->available_versions);
	isc_buffer_invalidate(&session->available_versions);

	isc_buffer_clearmctx(&session->secret);
	isc_buffer_invalidate(&session->secret);

	if (!session->is_server) {
		isc_buffer_clearmctx(&session->regular_token);
		isc_buffer_invalidate(&session->regular_token);
	}

	isc_ht_destroy(&session->dst_cids.idx);
	isc_ht_destroy(&session->src_cids.idx);

	isc_mempool_destroy(&session->streams.pool);
	isc_mempool_destroy(&session->sends.pool);

	/* We need to acquire a memory barrier here */
	(void)isc_refcount_current(&session->references);
	session->magic = 0;
	isc_mem_putanddetach(&session->mctx, session, sizeof(*session));
}

static inline isc_quic_cid_t *
quic_session_gen_new_cid(isc_quic_session_t *restrict session,
			 const bool source, const size_t cidlen) {
	isc_quic_cid_t *new_cid = NULL;
	isc_quic_session_cids_t *restrict cids = source ? &session->src_cids
							: &session->dst_cids;

	session->cb.gen_unique_cid(session, cidlen, source, session->cbarg,
				   &new_cid);
	isc_result_t result = isc_ht_add(cids->idx, new_cid->cid.data, cidlen,
					 (void *)new_cid);
	RUNTIME_CHECK(result == ISC_R_SUCCESS);
	ISC_LIST_APPEND(cids->list, new_cid, local_link);
	cids->count++;

	return new_cid;
}

static inline isc_quic_cid_t *
quic_session_assoc_cid(isc_quic_session_t *restrict session,
		       const uint8_t *data, const size_t cidlen,
		       const bool source) {
	isc_result_t result;
	isc_quic_cid_t *cid = NULL;
	isc_region_t cid_data;

	isc_quic_session_cids_t *restrict cids = source ? &session->src_cids
							: &session->dst_cids;

	result = isc_ht_find(cids->idx, data, cidlen, (void **)&cid);
	if (result == ISC_R_SUCCESS) {
		INSIST(cid != NULL);
		return cid;
	}

	cid_data = (isc_region_t){ .base = (uint8_t *)data,
				   .length = (unsigned int)cidlen };

	bool ret = session->cb.assoc_conn_cid(session, &cid_data, source,
					      session->cbarg, &cid);
	if (ret) {
		result = isc_ht_add(cids->idx, data, cidlen, (void *)cid);
		RUNTIME_CHECK(result == ISC_R_SUCCESS);
		ISC_LIST_APPEND(cids->list, cid, local_link);
		cids->count++;
	}

	return ret ? cid : NULL;
}

static inline void
quic_session_deassoc_all_cids(isc_quic_session_t *restrict session,
			      const bool keep_rcid) {
	REQUIRE(VALID_QUIC_SESSION(session));

	isc_quic_session_cids_t *restrict allcids[] = { &session->src_cids,
							&session->dst_cids };

	for (size_t i = 0; i < sizeof(allcids) / sizeof(allcids[0]); i++) {
		isc_quic_session_cids_t *restrict cids = allcids[i];
		const bool source = cids == &session->src_cids;
		if (!ISC_LIST_EMPTY(cids->list)) {
			isc_quic_cid_t *current = NULL, *next = NULL;
			for (current = ISC_LIST_HEAD(cids->list);
			     current != NULL; current = next)
			{
				next = ISC_LIST_NEXT(current, local_link);
				if (keep_rcid && session->rcid != NULL &&
				    current == session->rcid)
				{
					continue;
				}
				ISC_LIST_UNLINK(cids->list, current,
						local_link);

				isc_result_t result = isc_ht_delete(
					cids->idx, current->cid.data,
					current->cid.datalen);
				RUNTIME_CHECK(result == ISC_R_SUCCESS);
				session->cb.deassoc_conn_cid(session, source,
							     session->cbarg,
							     &current);
				cids->count--;
			}
		}
	}

	if (session->initial_scid != NULL) {
		isc_quic_cid_detach(&session->initial_scid);
	}

	if (session->initial_dcid != NULL) {
		isc_quic_cid_detach(&session->initial_dcid);
	}

	if (session->odcid != NULL) {
		isc_quic_cid_detach(&session->odcid);
	}

	if (session->rcid != NULL && !keep_rcid) {
		isc_quic_cid_detach(&session->rcid);
	}

	if (!keep_rcid) {
		INSIST(ISC_LIST_EMPTY(session->src_cids.list));
		INSIST(session->src_cids.count == 0);
		INSIST(isc_ht_count(session->src_cids.idx) == 0);
	} else if (session->rcid != NULL) {
		INSIST(session->src_cids.count == 1);
		INSIST(isc_ht_count(session->src_cids.idx) == 1);
	}

	INSIST(ISC_LIST_EMPTY(session->dst_cids.list));
	INSIST(session->dst_cids.count == 0);
	INSIST(isc_ht_count(session->dst_cids.idx) == 0);
}

static inline ngtcp2_tstamp
quic_session_update_timestamp(isc_quic_session_t *restrict session) {
	REQUIRE(VALID_QUIC_SESSION(session));

	session->ts = session->cb.get_current_ts(session->cbarg);

	return session->ts;
}

static inline ngtcp2_tstamp
quic_session_get_timestamp(isc_quic_session_t *restrict session) {
	REQUIRE(VALID_QUIC_SESSION(session));

	return session->ts;
}

static int
remote_stream_open_cb(ngtcp2_conn *conn, int64_t stream_id, void *user_data) {
	isc_quic_session_t *session = (isc_quic_session_t *)user_data;

	QUIC_SESSION_CB_TRACE();

	REQUIRE(VALID_QUIC_SESSION(session));
	REQUIRE(session->conn == conn);

	quic_session_track_stream(session, stream_id, NULL);

	bool ret = session->cb.on_remote_stream_open(session, stream_id,
						     session->cbarg);
	if (!ret) {
		quic_session_untrack_stream(session, stream_id);
		(void)ngtcp2_conn_shutdown_stream(conn, 0, stream_id,
						  NGTCP2_INTERNAL_ERROR);
	}

	return 0;
}

static int
quic_session_stream_close_cb(ngtcp2_conn *conn, uint32_t flags,
			     int64_t stream_id, uint64_t app_error_code,
			     void *user_data, void *stream_user_data) {
	isc_quic_session_t *session = (isc_quic_session_t *)user_data;
	const bool app_error_set =
		(flags & NGTCP2_STREAM_CLOSE_FLAG_APP_ERROR_CODE_SET) != 0;
	bool ret = false;
	isc__quic_stream_data_t *stream = NULL;

	QUIC_SESSION_CB_TRACE();

	REQUIRE(VALID_QUIC_SESSION(session));
	REQUIRE(session->conn == conn);

	stream = quic_session_lookup_stream(session, stream_id);
	if (stream == NULL) {
		return 0;
	}

	INSIST(stream_id == stream->stream_id);
	INSIST(stream_user_data == stream_user_data);

	quic_session_stream_call_pending_callbacks(session, stream_id,
						   ISC_R_CANCELED);

	stream->close_cb_called = true;
	ret = session->cb.on_stream_close(session, stream_id, app_error_set,
					  app_error_code, session->cbarg,
					  stream_user_data);

	quic_session_untrack_stream(session, stream_id);

	return ret ? 0 : NGTCP2_ERR_CALLBACK_FAILURE;
}

static int
quic_session_acked_stream_data_offset_cb(ngtcp2_conn *conn, int64_t stream_id,
					 uint64_t offset, uint64_t datalen,
					 void *user_data,
					 void *stream_user_data) {
	isc_quic_session_t *session = (isc_quic_session_t *)user_data;
	isc__quic_stream_data_t *stream = NULL;
	isc__quic_send_req_t *req = NULL;

	QUIC_SESSION_CB_TRACE();

	REQUIRE(VALID_QUIC_SESSION(session));
	REQUIRE(session->conn == conn);

	UNUSED(offset);
	UNUSED(stream_user_data);

	/* sometimes ACKs arrive for closed streams */
	stream = quic_session_lookup_stream(session, stream_id);
	if (stream == NULL || datalen == 0) {
		return 0;
	}

	req = ISC_LIST_HEAD(stream->sends.queue);
	isc_buffer_forward(&req->data, datalen);
	if (isc_buffer_remaininglength(&req->data) > 0 ||
	    isc_buffer_availablelength(&req->data) > 0)
	{
		return 0;
	}

	/* the send request is fully fulfilled */
	ISC_LIST_DEQUEUE(stream->sends.queue, req, stream_link);
	INSIST(stream->sends.queue_len > 0);
	stream->sends.queue_len--;
	ISC_LIST_UNLINK(session->sends.queue, req, conn_link);
	INSIST(session->sends.queue_len > 0);
	session->sends.queue_len--;

	req->cb(session, stream->stream_id, ISC_R_SUCCESS, req->cbarg,
		stream->stream_user_data);
	isc_mempool_put(session->sends.pool, req);

	return 0;
}

static int
quic_session_recv_stream_data_cb(ngtcp2_conn *conn, uint32_t flags,
				 int64_t stream_id, uint64_t offset,
				 const uint8_t *data, size_t datalen,
				 void *user_data, void *stream_user_data) {
	isc_quic_session_t *restrict session = (isc_quic_session_t *)user_data;
	bool fin = false;
	isc_region_t received_data = (isc_region_t){
		.base = (uint8_t *)data, .length = (unsigned int)datalen
	};

	QUIC_SESSION_CB_TRACE();

	REQUIRE(VALID_QUIC_SESSION(session));
	REQUIRE(session->conn == conn);

	ngtcp2_conn_extend_max_stream_offset(session->conn, stream_id, datalen);
	ngtcp2_conn_extend_max_offset(session->conn, datalen);

	isc__quic_stream_data_t *stream = quic_session_lookup_stream(session,
								     stream_id);
	if (stream == NULL) {
		return 0;
	}

	if (flags != NGTCP2_STREAM_DATA_FLAG_NONE) {
		fin = (flags & NGTCP2_STREAM_DATA_FLAG_FIN) != 0;
	}
	bool ret = session->cb.on_recv_stream_data(
		session, stream_id, fin, offset,
		data != NULL ? &received_data : NULL, session->cbarg,
		stream_user_data);
	if (!ret) {
		quic_session_untrack_stream(session, stream_id);
		(void)ngtcp2_conn_shutdown_stream(conn, 0, stream_id,
						  NGTCP2_INTERNAL_ERROR);
	}

	return 0;
}

static int
quic_session_handshake_completed_cb(ngtcp2_conn *conn, void *user_data) {
	isc_quic_session_t *restrict session = (isc_quic_session_t *)user_data;
	isc_result_t result = ISC_R_FAILURE;

	QUIC_SESSION_CB_TRACE();

	REQUIRE(VALID_QUIC_SESSION(session));
	REQUIRE(session->conn == conn);

	session->hs_confirmed = (ngtcp2_conn_is_server(conn) != 0);
	bool hs_status = session->cb.on_handshake(session, session->cbarg);
	result = quic_session_process_event(
		session,
		hs_status ? ISC_QUIC_EV_HANDSHAKE_COMPLETE
			  : ISC_QUIC_EV_HANDSHAKE_FAILURE,
		NULL);

	return result == ISC_R_SUCCESS ? 0 : NGTCP2_ERR_CALLBACK_FAILURE;
}

static int
quic_client_handshake_confirmed_cb(ngtcp2_conn *conn, void *user_data) {
	isc_quic_session_t *restrict session = (isc_quic_session_t *)user_data;

	QUIC_SESSION_CB_TRACE();

	REQUIRE(VALID_QUIC_SESSION(session));
	REQUIRE(session->conn == conn);

	session->hs_confirmed = true;
	session->negotiated_version = ngtcp2_conn_get_negotiated_version(conn);

	return 0;
}

static int
quic_session_get_new_connection_id_cb(ngtcp2_conn *conn, ngtcp2_cid *cid,
				      uint8_t *token, size_t cidlen,
				      void *user_data) {
	isc_quic_session_t *restrict session = (isc_quic_session_t *)user_data;
	isc_quic_cid_t *new_cid = NULL;

	QUIC_SESSION_CB_TRACE();

	REQUIRE(VALID_QUIC_SESSION(session));
	REQUIRE(session->conn == conn);

	new_cid = quic_session_gen_new_cid(session, true, cidlen);

	isc_ngtcp2_copy_cid(cid, &new_cid->cid);

	if (session->is_server) {
		isc_region_t secret = { 0 };

		isc_buffer_usedregion(&session->secret, &secret);

		isc_result_t result =
			isc_ngtcp2_crypto_generate_stateless_reset_token(
				token, NGTCP2_STATELESS_RESET_TOKENLEN,
				secret.base, secret.length, cid);

		if (result != ISC_R_SUCCESS) {
			return NGTCP2_ERR_CALLBACK_FAILURE;
		}
	}

	return 0;
}

static int
quic_session_remove_connection_id_cb(ngtcp2_conn *conn,
				     const ngtcp2_cid *cid_data,
				     void *user_data) {
	isc_quic_session_t *restrict session = (isc_quic_session_t *)user_data;
	isc_quic_cid_t *cid = NULL;

	QUIC_SESSION_CB_TRACE();

	REQUIRE(VALID_QUIC_SESSION(session));
	REQUIRE(session->conn == conn);

	isc_result_t result = isc_ht_find(session->src_cids.idx, cid_data->data,
					  cid_data->datalen, (void **)&cid);
	if (result != ISC_R_SUCCESS) {
		return 0;
	}

	INSIST(cid != NULL);

	ISC_LIST_UNLINK(session->src_cids.list, cid, local_link);

	result = isc_ht_delete(session->src_cids.idx, cid->cid.data,
			       cid->cid.datalen);
	RUNTIME_CHECK(result == ISC_R_SUCCESS);

	session->cb.deassoc_conn_cid(session, true, session->cbarg, &cid);
	session->src_cids.count--;

	return 0;
}

static int
quic_session_recv_version_negotiation_cb(ngtcp2_conn *conn,
					 const ngtcp2_pkt_hd *hd,
					 const uint32_t *sv, size_t nsv,
					 void *user_data) {
	isc_quic_session_t *restrict session = (isc_quic_session_t *)user_data;
	isc_result_t result = ISC_R_FAILURE;

	QUIC_SESSION_CB_TRACE();

	REQUIRE(VALID_QUIC_SESSION(session));
	REQUIRE(session->conn == conn);

	UNUSED(hd);

	if (session->ver_neg_count >= MAX_VERSION_NEGOTIATION_ATTEMPTS) {
		return NGTCP2_ERR_CALLBACK_FAILURE;
	}

	session->ver_neg_count++;

	isc_region_t available_versions = { 0 };
	isc_buffer_usedregion(&session->available_versions,
			      &available_versions);

	uint32_t *versions = (uint32_t *)available_versions.base;
	size_t verlen = available_versions.length / sizeof(uint32_t);

	const uint32_t negotiated = isc_ngtcp2_select_version(
		session->orig_client_chosen_version, versions, verlen, sv, nsv);

	if (negotiated != 0) {
		session->negotiated_version = negotiated;
		result = ISC_R_SUCCESS;
	} else {
		result = quic_session_process_event(
			session, ISC_QUIC_EV_FATAL_ERROR, NULL);
	}

	session->write_after_read = true;

	return result == ISC_R_SUCCESS ? 0 : NGTCP2_ERR_CALLBACK_FAILURE;
}

static int
quic_session_recv_new_token_cb(ngtcp2_conn *conn, const uint8_t *token,
			       size_t tokenlen, void *user_data) {
	isc_quic_session_t *restrict session = (isc_quic_session_t *)user_data;
	int ret = 0;

	QUIC_SESSION_CB_TRACE();

	REQUIRE(VALID_QUIC_SESSION(session));
	REQUIRE(session->conn == conn);
	REQUIRE(tokenlen > 0);

	UNUSED(conn);

	isc_buffer_clear(&session->regular_token);
	isc_buffer_putmem(&session->regular_token, token, tokenlen);

	if (session->cb.on_new_regular_token != NULL) {
		isc_sockaddr_t local = { 0 }, peer = { 0 };
		isc_region_t token_data = { 0 };

		isc_buffer_usedregion(&session->regular_token, &token_data);
		isc_ngtcp2_path_getaddrs(session->path, &local, &peer);
		const bool cbret = session->cb.on_new_regular_token(
			session, &token_data, &local, &peer, session->cbarg);
		if (!cbret) {
			ret = NGTCP2_ERR_CALLBACK_FAILURE;
		}
	}

	return ret;
}

static int
quic_session_path_validation_cb(ngtcp2_conn *conn, uint32_t flags,
				const ngtcp2_path *path,
				const ngtcp2_path *old_path,
				ngtcp2_path_validation_result res,
				void *user_data) {
	isc_quic_session_t *restrict session = (isc_quic_session_t *)user_data;

	QUIC_SESSION_CB_TRACE();

	REQUIRE(VALID_QUIC_SESSION(session));
	REQUIRE(session->conn == conn);

	UNUSED(old_path);

	if (!session->is_server) {
		INSIST(session->path_migrations > 0);
		session->path_migrations--;
	}

	if (res != NGTCP2_PATH_VALIDATION_RESULT_SUCCESS) {
		return 0;
	}

	ngtcp2_path_storage_init(&session->path_st, path->local.addr,
				 path->local.addrlen, path->remote.addr,
				 path->remote.addrlen, NULL);
	session->write_after_read = true;

	if (!session->is_server ||
	    !(flags & NGTCP2_PATH_VALIDATION_FLAG_NEW_TOKEN))
	{
		return 0;
	}

	uint8_t token[ISC_NGTCP2_CRYPTO_MAX_REGULAR_TOKEN_LEN];
	const ngtcp2_tstamp now = quic_session_get_timestamp(session);
	isc_region_t secret = { 0 };

	isc_buffer_usedregion(&session->secret, &secret);

	const ssize_t toklen = isc_ngtcp2_crypto_generate_regular_token(
		token, sizeof(token), secret.base, secret.length,
		path->remote.addr, path->remote.addrlen, now);

	if (toklen < 0) {
		return NGTCP2_ERR_CALLBACK_FAILURE;
	} else {
		int ret = ngtcp2_conn_submit_new_token(session->conn, token,
						       toklen);
		if (ret != 0) {
			return NGTCP2_ERR_CALLBACK_FAILURE;
		}
	}

	return 0;
}

static int
quic_session_recv_stateless_reset_cb(ngtcp2_conn *conn,
				     const ngtcp2_pkt_stateless_reset *sr,
				     void *user_data) {
	isc_quic_session_t *restrict session = (isc_quic_session_t *)user_data;

	QUIC_SESSION_CB_TRACE();

	REQUIRE(session->conn == conn);

	UNUSED(sr);

	const isc_result_t result = quic_session_process_event(
		session, ISC_QUIC_EV_STATELESS_RESET_RECEIVED, NULL);
	if (result != ISC_R_CANCELED) {
		return NGTCP2_ERR_CALLBACK_FAILURE;
	}

	return 0;
}

static void
quic_session_init(isc_quic_session_t *restrict session,
		  const ngtcp2_cid *restrict scid,
		  const ngtcp2_cid *restrict dcid,
		  const ngtcp2_cid *restrict odcid,
		  const ngtcp2_cid *restrict rcid) {
	ngtcp2_callbacks callbacks = {
		.get_new_connection_id = quic_session_get_new_connection_id_cb,
		.remove_connection_id = quic_session_remove_connection_id_cb,
		.stream_open = remote_stream_open_cb,
		.stream_close = quic_session_stream_close_cb,
		.acked_stream_data_offset =
			quic_session_acked_stream_data_offset_cb,
		.recv_stream_data = quic_session_recv_stream_data_cb,
		.handshake_completed = quic_session_handshake_completed_cb,
		.handshake_confirmed = quic_client_handshake_confirmed_cb,
		.path_validation = quic_session_path_validation_cb,
		.recv_version_negotiation =
			quic_session_recv_version_negotiation_cb,
		.recv_new_token = quic_session_recv_new_token_cb,
		.recv_stateless_reset = quic_session_recv_stateless_reset_cb,
	};
	ngtcp2_settings settings = { 0 };
	ngtcp2_transport_params transp_params = { 0 };
	int ret = 0;
	isc_region_t available_versions = { 0 };
	uint32_t *versions = NULL;
	size_t verlen = 0;

	REQUIRE(VALID_QUIC_SESSION(session));

	isc_ngtcp2_crypto_set_crypto_callbacks(&callbacks);

	ngtcp2_settings_default(&settings);

	const size_t initial_max_stream_data = (UINT16_MAX + sizeof(uint16_t)) *
					       100;
	const size_t max_stream_data = initial_max_stream_data * 100;
	const size_t max_conn_data = max_stream_data + max_stream_data / 2;

	const size_t max_stream_congestion_window = max_stream_data * 2;
	const size_t max_congestion_window = max_conn_data * 2;

	settings.initial_ts = quic_session_update_timestamp(session);
	settings.handshake_timeout = session->handshake_timeout;
	settings.max_tx_udp_payload_size = NGTCP2_MAX_UDP_PAYLOAD_SIZE;
	settings.max_window = max_congestion_window;
	settings.max_stream_window = max_stream_congestion_window;
	settings.no_pmtud = !session->is_server;
	settings.cc_algo = NGTCP2_CC_ALGO_CUBIC;

	isc_buffer_usedregion(&session->available_versions,
			      &available_versions);

	versions = (uint32_t *)available_versions.base;
	verlen = available_versions.length / sizeof(uint32_t);

	if (available_versions.length > 0 && session->is_server) {
		settings.preferred_versions = versions;
		settings.preferred_versionslen = verlen;
	}

	if (session->orig_client_chosen_version != 0 && !session->is_server) {
		settings.original_version = session->orig_client_chosen_version;
		if (available_versions.length > 0) {
			INSIST(isc_ngtcp2_is_version_available(
				session->orig_client_chosen_version, versions,
				verlen));
			settings.preferred_versions = versions;
			settings.preferred_versionslen = verlen;
		}
	}

	if (!session->is_server) {
		isc_region_t token = { 0 };
		isc_buffer_usedregion(&session->regular_token, &token);

		if (token.length > 0) {
			settings.token = token.base;
			settings.tokenlen = token.length;
			settings.token_type = NGTCP2_TOKEN_TYPE_NEW_TOKEN;
		}
	}

	ngtcp2_transport_params_default(&transp_params);

	transp_params.initial_max_streams_uni = session->max_uni_streams;
	transp_params.initial_max_streams_bidi = session->max_bidi_streams;
	transp_params.initial_max_stream_data_bidi_local =
		initial_max_stream_data;
	transp_params.initial_max_stream_data_bidi_remote =
		initial_max_stream_data;
	transp_params.initial_max_stream_data_uni = initial_max_stream_data;
	transp_params.initial_max_data = max_conn_data;
	transp_params.max_idle_timeout = session->idle_timeout;
	transp_params.grease_quic_bit = !session->is_server;

	if (session->is_server) {
		isc_result_t result = ISC_R_FAILURE;
		isc_region_t secret = { 0 };
		if (odcid != NULL) {
			transp_params.original_dcid = *odcid;
			transp_params.original_dcid_present = true;
		}

		if (rcid != NULL) {
			transp_params.retry_scid = *rcid;
			transp_params.retry_scid_present = true;
		}

		isc_buffer_usedregion(&session->secret, &secret);

		result = isc_ngtcp2_crypto_generate_stateless_reset_token(
			transp_params.stateless_reset_token,
			sizeof(transp_params.stateless_reset_token),
			secret.base, secret.length, scid);

		RUNTIME_CHECK(result == ISC_R_SUCCESS);
	}

	/* quic_session_untrack_all_streams(session); */

	if (session->conn != NULL) {
		ngtcp2_conn_del(session->conn);
		session->conn = NULL;
	}

	if (session->tls != NULL) {
		isc_tls_free(&session->tls);
	}
	session->tls = isc_tls_create_quic(session->tlsctx);

	if (session->is_server) {
		SSL_set_accept_state(session->tls);
		ret = ngtcp2_conn_server_new(
			&session->conn, dcid, scid, session->path,
			session->negotiated_version, &callbacks, &settings,
			&transp_params, &session->mem, (void *)session);
	} else {
		if (session->sni_hostname != NULL) {
			(void)SSL_set_tlsext_host_name(session->tls,
						       session->sni_hostname);
		}

		if (session->client_sess_cache != NULL) {
			isc_sockaddr_t peer =
				isc_quic_session_peeraddr(session);
			isc_tlsctx_client_session_cache_reuse_sockaddr(
				session->client_sess_cache, &peer,
				session->tls);
		}

		SSL_set_connect_state(session->tls);
		ret = ngtcp2_conn_client_new(
			&session->conn, dcid, scid, session->path,
			session->negotiated_version, &callbacks, &settings,
			&transp_params, &session->mem, (void *)session);
	}

	isc_ngtcp2_crypto_bind_conn_tls(session->conn, session->tls);

	RUNTIME_CHECK(ret == 0);
}

static void
quic_session_update_send_time(isc_quic_session_t *restrict session) {
	REQUIRE(VALID_QUIC_SESSION(session));

	ngtcp2_conn_update_pkt_tx_time(session->conn,
				       quic_session_get_timestamp(session));
}

static ssize_t
quic_session_send_pending(isc_quic_session_t *restrict session,
			  isc_quic_out_pkt_t *restrict out_pkt,
			  const size_t max_pkt_len) {
	ssize_t written = 0;
	ngtcp2_tstamp ts = 0;
	ngtcp2_pkt_info pi = { 0 };
	ngtcp2_path_storage ps = { 0 };

	REQUIRE(VALID_QUIC_SESSION(session));
	REQUIRE(out_pkt != NULL && out_pkt->pktbuf.base != NULL &&
		out_pkt->pktbuf.length > 0 && out_pkt->pktsz == 0);
	REQUIRE(max_pkt_len > 0 && max_pkt_len <= out_pkt->pktbuf.length);

	ngtcp2_path_storage_zero(&ps);

	ts = quic_session_get_timestamp(session);
	written = ngtcp2_conn_write_pkt(session->conn, &ps.path, &pi,
					out_pkt->pktbuf.base, max_pkt_len, ts);

	if (written < 0) {
		ngtcp2_ccerr_set_liberr(&session->conn_err, written, NULL, 0);
		return written;
	}

	if (written > 0) {
		isc_ngtcp2_path_getaddrs(&ps.path, &out_pkt->local,
					 &out_pkt->peer);
		session->sent_before_expiry += (size_t)written;
	}

	if (written >= 0) {
		quic_session_update_send_time(session);
	}

	return written;
}

static inline void
quic_session_drop(isc_quic_session_t *restrict session,
		  const uint32_t close_timeout_ms, const bool ver_neg) {
	if (session->fin) {
		return;
	}
	session->fin = true;
	quic_session_untrack_all_streams(session);

	if (session->timer_running) {
		session->cb.expiry_timer_stop(session, session->cbarg);
		session->timer_running = false;
	}

	/*
	 * Try to save the TLS session only if at least a connection
	 * attempt was made.
	 */
	if (session->conn != NULL && session->tls != NULL) {
		quic_session_keep_client_tls_session(session);
		isc_tls_free(&session->tls);
	}

	if (session->conn != NULL) {
		ngtcp2_conn_del(session->conn);
		session->conn = NULL;
	}

	if (close_timeout_ms == 0) {
		quic_session_deassoc_all_cids(session, false);
		if (session->close_msg != NULL) {
			isc_buffer_free(&session->close_msg);
		}
	}

	session->path_migrations = 0;
	session->cb.on_conn_close(session, close_timeout_ms, ver_neg,
				  session->cbarg);
}

static inline uint32_t
quic_session_close_timeout(const isc_quic_session_t *restrict session) {
	return (ngtcp2_conn_get_pto(session->conn) / NGTCP2_MILLISECONDS) * 3;
}

static inline ssize_t
quic_session_write_stateless_reset(isc_quic_session_t *restrict session,
				   const size_t last_read_pkt_size,
				   const ngtcp2_cid *cid,
				   isc_quic_out_pkt_t *restrict out_pkt) {
	ssize_t written = 0;
	isc_region_t secret = { 0 };

	session->resetting = true;

	if (session->close_reset_count >= STATELESS_CLOSE_COUNT) {
		return 0;
	}

	session->close_reset_count++;

	isc_buffer_usedregion(&session->secret, &secret);

	written = isc_ngtcp2_crypto_write_stateless_reset_pkt(
		out_pkt->pktbuf.base, out_pkt->pktbuf.length,
		last_read_pkt_size, secret.base, secret.length, cid);

	if (written > 0) {
		isc_ngtcp2_path_getaddrs(session->path, &out_pkt->local,
					 &out_pkt->peer);
		out_pkt->pktsz = written;
	}

	if (session->conn != NULL) {
		const uint32_t close_timeout =
			quic_session_close_timeout(session);

		quic_session_drop(session, close_timeout, false);
	}

	return written;
}

static inline void
quic_session_write_close(isc_quic_session_t *restrict session,
			 isc_quic_out_pkt_t *restrict out_pkt) {
	ngtcp2_pkt_info pi = { 0 };
	ngtcp2_path_storage ps = { 0 };
	ssize_t written = 0;
	uint8_t out_msg[NGTCP2_MAX_UDP_PAYLOAD_SIZE];

	if (session->conn == NULL ||
	    ngtcp2_conn_in_closing_period(session->conn) ||
	    ngtcp2_conn_in_draining_period(session->conn))
	{
		return;
	}

	session->close_reset_count++;
	INSIST(session->close_reset_count < STATELESS_CLOSE_COUNT);

	ngtcp2_path_storage_zero(&ps);

	written = ngtcp2_conn_write_connection_close(
		session->conn, &ps.path, &pi, out_msg, sizeof(out_msg),
		&session->conn_err, quic_session_get_timestamp(session));

	session->closing = true;

	const uint32_t close_timeout = quic_session_close_timeout(session);

	if (written > 0) {
		isc_buffer_allocate(session->mctx, &session->close_msg,
				    written);
		isc_buffer_putmem(session->close_msg, out_msg, written);
		isc_ngtcp2_path_getaddrs(&ps.path, &session->close_local,
					 &session->close_peer);

		if (out_pkt != NULL) {
			INSIST(written <= (ssize_t)out_pkt->pktbuf.length);
			memmove(out_pkt->pktbuf.base, out_msg, written);
			out_pkt->pktsz = written;
			out_pkt->local = session->close_local;
			out_pkt->peer = session->close_peer;
		}
	}

	quic_session_drop(session, close_timeout, false);

	return;
}

static inline isc_result_t
process_quic_common_state(isc_quic_session_t *restrict session,
			  isc_quic_out_pkt_t *restrict out_pkt) {
	isc_result_t result = ISC_R_FAILURE;

	switch (session->state) {
	case ISC_QUIC_ST_HANDSHAKE: {
		session->write_after_read = true;
		if (session->is_server) {
			uint8_t token[ISC_NGTCP2_CRYPTO_MAX_REGULAR_TOKEN_LEN];
			const ngtcp2_tstamp now =
				quic_session_get_timestamp(session);
			const ngtcp2_path *path =
				ngtcp2_conn_get_path(session->conn);
			isc_region_t secret = { 0 };

			isc_buffer_usedregion(&session->secret, &secret);

			const ssize_t toklen =
				isc_ngtcp2_crypto_generate_regular_token(
					token, sizeof(token), secret.base,
					secret.length, path->remote.addr,
					path->remote.addrlen, now);

			if (toklen < 0) {
				result = ISC_R_FAILURE;
			} else {
				int ret = ngtcp2_conn_submit_new_token(
					session->conn, token, toklen);
				if (ret == 0) {
					result = ISC_R_SUCCESS;
				}
			}
		} else {
			result = ISC_R_SUCCESS;
		}
	} break;
	case ISC_QUIC_ST_CONNECTED: {
		INSIST(out_pkt == NULL);
		session->write_after_read = true;
		result = ISC_R_SUCCESS;
	} break;
	case ISC_QUIC_ST_CLOSING:
		INSIST(out_pkt != NULL);
		INSIST(out_pkt->pktbuf.base != NULL &&
		       out_pkt->pktbuf.length >= NGTCP2_MAX_UDP_PAYLOAD_SIZE);

		if (session->hs_confirmed) {
			quic_session_write_close(session, out_pkt);
		} else {
			(void)quic_session_write_stateless_reset(
				session, session->last_read_pkt_size,
				&session->last_read_pkt_dcid, out_pkt);
		}

		result = ISC_R_SUCCESS;
		break;
	case ISC_QUIC_ST_TERMINATED:
		quic_session_drop(session, 0, false);
		result = ISC_R_FAILURE;
		break;
	case ISC_QUIC_ST_CLOSED:
		quic_session_drop(session, 0, false);
		result = ISC_R_CANCELED;
		break;
	default:
		UNREACHABLE();
		quic_session_drop(session, 0, false);
		result = ISC_R_UNEXPECTED;
		break;
	};

	return result;
}

static inline isc_result_t
process_quic_client_state(isc_quic_session_t *restrict session,
			  isc_quic_out_pkt_t *restrict out_pkt) {
	ssize_t written = 0;
	isc_result_t result = ISC_R_FAILURE;
	switch (session->state) {
	case ISC_QUIC_ST_INITIAL: {
		isc_quic_cid_t *scid = NULL, *dcid = NULL;

		INSIST(out_pkt != NULL);
		INSIST(out_pkt->pktbuf.base != NULL &&
		       out_pkt->pktbuf.length >= NGTCP2_MAX_UDP_PAYLOAD_SIZE);

		if (session->initial_scid == NULL) {
			scid = quic_session_gen_new_cid(session, true,
							NGTCP2_MAX_CIDLEN);
			isc_quic_cid_attach(scid, &session->initial_scid);
		}

		if (session->initial_dcid == NULL) {
			dcid = quic_session_gen_new_cid(session, false,
							NGTCP2_MAX_CIDLEN);
			isc_quic_cid_attach(dcid, &session->initial_dcid);
		}

		quic_session_init(session, &session->initial_scid->cid,
				  &session->initial_dcid->cid, NULL, NULL);

		written = quic_session_send_pending(session, out_pkt,
						    out_pkt->pktbuf.length);
		if (written > 0) {
			result = ISC_R_SUCCESS;
			out_pkt->pktsz = written;
		}
	} break;
	default:
		result = process_quic_common_state(session, out_pkt);
		break;
	};

	return result;
}

static inline isc_result_t
process_quic_server_state(isc_quic_session_t *restrict session,
			  isc_quic_out_pkt_t *restrict out_pkt) {
	ssize_t written = 0;
	isc_result_t result = ISC_R_FAILURE;

	switch (session->state) {
	case ISC_QUIC_ST_INITIAL:
		quic_session_deassoc_all_cids(session, false);
		if (session->initial_scid != NULL) {
			isc_quic_cid_detach(&session->initial_scid);
		}

		if (session->initial_dcid != NULL) {
			isc_quic_cid_detach(&session->initial_dcid);
		}

		if (session->odcid != NULL) {
			isc_quic_cid_detach(&session->odcid);
		}
		result = ISC_R_SUCCESS;
		break;
	case ISC_QUIC_ST_VERSION_NEGOTIATION: {
		INSIST(out_pkt != NULL);
		INSIST(out_pkt->pktbuf.base != NULL &&
		       out_pkt->pktbuf.length >= NGTCP2_MAX_UDP_PAYLOAD_SIZE);

		isc_region_t available_versions = { 0 };
		isc_buffer_usedregion(&session->available_versions,
				      &available_versions);
		written = ngtcp2_pkt_write_version_negotiation(
			out_pkt->pktbuf.base, out_pkt->pktbuf.length,
			isc_random8(), session->initial_dcid->cid.data,
			session->initial_dcid->cid.datalen,
			session->initial_scid->cid.data,
			session->initial_scid->cid.datalen,
			(uint32_t *)available_versions.base,
			available_versions.length / sizeof(uint32_t));
		if (written > 0) {
			out_pkt->pktsz = written;
			isc_ngtcp2_path_getaddrs(session->path, &out_pkt->local,
						 &out_pkt->peer);
			result = ISC_R_SUCCESS;
		}
		quic_session_drop(session, 0, true);
		session->fin = false;
		quic_session_deassoc_all_cids(session, false);
	} break;
	case ISC_QUIC_ST_ADDRESS_VALIDATION: {
		isc_quic_cid_t *rcid = NULL;
		isc_region_t secret = { 0 };
		uint8_t tokenbuf[ISC_NGTCP2_CRYPTO_MAX_RETRY_TOKEN_LEN] = { 0 };

		INSIST(out_pkt != NULL);
		INSIST(out_pkt->pktbuf.base != NULL &&
		       out_pkt->pktbuf.length >= NGTCP2_MAX_UDP_PAYLOAD_SIZE);

		rcid = quic_session_gen_new_cid(session, true,
						ISC_QUIC_SERVER_SCID_LEN);

		isc_quic_cid_attach(rcid, &session->rcid);

		isc_buffer_usedregion(&session->secret, &secret);

		size_t token_len = isc_ngtcp2_crypto_generate_retry_token(
			tokenbuf, sizeof(tokenbuf), secret.base, secret.length,
			session->negotiated_version, session->path->remote.addr,
			session->path->remote.addrlen, &rcid->cid,
			&session->odcid->cid,
			quic_session_get_timestamp(session));

		if (token_len == 0) {
			result = ISC_R_FAILURE;
			break;
		}

		written = isc_ngtcp2_crypto_write_retry(
			out_pkt->pktbuf.base, out_pkt->pktbuf.length,
			session->negotiated_version,
			&session->initial_dcid->cid, &rcid->cid,
			&session->odcid->cid, tokenbuf, token_len);

		if (written >= 0) {
			out_pkt->pktsz = written;
			isc_ngtcp2_path_getaddrs(session->path, &out_pkt->local,
						 &out_pkt->peer);
			result = ISC_R_SUCCESS;
		}
	} break;
	default:
		result = process_quic_common_state(session, out_pkt);
		break;
	};

	return result;
}

static inline isc_result_t
process_quic_state(isc_quic_session_t *restrict session,
		   isc_quic_out_pkt_t *restrict out_pkt) {
	if (session->is_server) {
		return process_quic_server_state(session, out_pkt);
	}

	return process_quic_client_state(session, out_pkt);
}

/*
 * The function `quic_session_process_event()` acts as the central
 * dispatcher for the QUIC session's state machine.
 *
 * This function is the heart of the framework's state management. The entire
 * lifecycle of a QUIC connection is modeled as a Finite State Machine (FSM),
 * where the session's current state is defined by `isc_quic_states_t`.
 * Transitions between these states are not arbitrary; they are driven by
 * specific, well-defined "events" represented by the `isc_quic_state_event_t`
 * enumeration.
 *
 * An event is a logical abstraction of a significant occurrence, such as
 * receiving a particular type of packet, an API function like
 * `isc_quic_session_shutdown()` being called, or an internal timer firing.
 * Instead of scattering state-checking logic throughout the codebase, other
 * functions determine the logical event that has occurred and then delegate all
 * further action to this single function.
 *
 * The process is a deterministic, two-step operation:
 * 1.  **State Transition**: The function first calls `quic_state_transition()`,
 * which takes the current state and the incoming event to calculate the new
 * state for the session.
 * 2.  **State Action**: It then immediately calls `process_quic_state()` with
 * the *new* state. This second function is responsible for executing the
 * actions associated with entering that new state, which may include generating
 * a specific type of packet (e.g., a Retry packet, a CONNECTION_CLOSE frame),
 *     modifying timers, or preparing to send application data.
 *
 * By centralizing all state transitions through this single dispatcher, the
 * framework ensures that the FSM is handled consistently and correctly, making
 * the behavior of the session predictable and easier to debug.
 */
static inline isc_result_t
quic_session_process_event(isc_quic_session_t *restrict session,
			   const isc_quic_state_event_t event,
			   isc_quic_out_pkt_t *restrict out_pkt) {
	REQUIRE(VALID_QUIC_SESSION(session));

	session->state = quic_state_transition(!session->is_server,
					       session->state, event);
	return process_quic_state(session, out_pkt);
}

isc_result_t
isc_quic_session_connect(isc_quic_session_t *restrict session,
			 isc_quic_out_pkt_t *restrict out_pkt) {
	REQUIRE(VALID_QUIC_SESSION(session));
	REQUIRE(out_pkt != NULL && out_pkt->pktbuf.base != NULL &&
		out_pkt->pktbuf.length >= NGTCP2_MAX_UDP_PAYLOAD_SIZE &&
		out_pkt->pktsz == 0);
	REQUIRE(!session->is_server);

	ERR_clear_error();
	(void)quic_session_update_timestamp(session);

	return quic_session_process_event(
		session, ISC_QUIC_EV_INITIAL_PACKET_SENT, out_pkt);
}

isc_result_t
isc_quic_session_update_localaddr(isc_quic_session_t *restrict session,
				  const isc_sockaddr_t *restrict local) {
	REQUIRE(VALID_QUIC_SESSION(session));
	REQUIRE(local != NULL);
	REQUIRE(!session->is_server);

	isc_sockaddr_t path_local = { 0 }, path_remote = { 0 };

	if (!session->hs_confirmed || session->conn == NULL || session->fin ||
	    session->closing || session->shuttingdown)
	{
		return ISC_R_UNEXPECTED;
	}

	isc_ngtcp2_path_getaddrs(ngtcp2_conn_get_path(session->conn),
				 &path_local, &path_remote);

	if (isc_sockaddr_equal(local, &path_local)) {
		return ISC_R_SUCCESS;
	}

	ngtcp2_path_storage new_path = { 0 };

	isc_ngtcp2_path_storage_init(&new_path, local, &path_remote);

	const uint64_t ts = quic_session_update_timestamp(session);
	ERR_clear_error();
	int ret = ngtcp2_conn_initiate_immediate_migration(session->conn,
							   &new_path.path, ts);
	switch (ret) {
	case 0:
		session->path_migrations++;
		return ISC_R_SUCCESS;
	case NGTCP2_ERR_INVALID_STATE:
	case NGTCP2_ERR_CONN_ID_BLOCKED:
		return ISC_R_UNEXPECTED;
	default:
		return ISC_R_FAILURE;
	}

	UNREACHABLE();
}

bool
isc_quic_session_path_migrating(isc_quic_session_t *restrict session) {
	REQUIRE(VALID_QUIC_SESSION(session));
	REQUIRE(!session->is_server);

	return session->path_migrations > 0 && !session->closing;
}

void
isc_quic_session_update_expiry_timer(isc_quic_session_t *restrict session) {
	ngtcp2_tstamp now = 0, expiry = 0;
	uint32_t timeout;

	REQUIRE(VALID_QUIC_SESSION(session));

	if (session->conn == NULL) {
		return;
	}

	expiry = ngtcp2_conn_get_expiry(session->conn);

	if ((expiry == session->last_expiry && session->timer_running) ||
	    expiry == UINT64_MAX)
	{
		return;
	}

	now = quic_session_update_timestamp(session);
	if (session->timer_running) {
		session->timer_running = false;
		session->cb.expiry_timer_stop(session, session->cbarg);
	}
	session->last_expiry = expiry;

	if (expiry > now) {
		timeout = (uint32_t)((expiry - now) / NGTCP2_MILLISECONDS);
		session->cb.expiry_timer_start(session, timeout,
					       session->cbarg);
		session->timer_running = true;
	} else {
		session->cb.expiry_timer_start(session, 0, session->cbarg);
	}
}

static inline size_t
get_max_send_pkt_len(isc_quic_session_t *restrict session,
		     const size_t send_quantum, const size_t out_pkt_buf_len) {
	size_t max_pkt_len = 0;

	max_pkt_len =
		ISC_MIN(ngtcp2_conn_get_max_tx_udp_payload_size(session->conn),
			out_pkt_buf_len);

	max_pkt_len = ISC_MIN(
		ngtcp2_conn_get_path_max_tx_udp_payload_size(session->conn),
		max_pkt_len);

	max_pkt_len = ISC_MIN(send_quantum - session->sent_before_expiry,
			      max_pkt_len);

	return max_pkt_len;
}

/*
 * Writes data from active streams into a single outgoing QUIC packet.
 *
 * This function orchestrates the process of taking queued application data from
 * multiple streams and writing it into a provided packet buffer. It implements
 * a fair, round-robin scheduling approach to ensure no single stream starves
 * the others.
 *
 * The core of its complexity lies in the interaction with
 * ngtcp2_conn_write_stream(), which has a non-trivial API. This function must
 * handle various return codes that indicate transient states (like being
 * blocked by flow or congestion control) rather than fatal errors.
 */
static ssize_t
quic_session_write_streams_pkt(isc_quic_session_t *restrict session,
			       isc_quic_out_pkt_t *restrict out_pkt,
			       const size_t out_pkt_buf_len) {
	ssize_t written = 0, last_written = 0;
	/* Flag to track if any data has been successfully written. */
	bool sentp = false;

	INSIST(out_pkt_buf_len <= out_pkt->pktbuf.length);

	/*
	 * If there are no active streams with pending data, there is nothing to
	 * do. session->streams.list contains all streams (open, half-closed).
	 * session->sends.queue contains all pending send requests across all
	 * streams.
	 */
	if (ISC_LIST_EMPTY(session->streams.list) ||
	    ISC_LIST_EMPTY(session->sends.queue))
	{
		return written;
	}

	/*
	 * We are going to process streams in a round-robin fashion to ensure
	 * fairness. We iterate through the list of streams, attempt to write
	 * data from each, and move the processed stream to the end of the list.
	 */
	ngtcp2_pkt_info pi = { 0 };
	ngtcp2_path_storage ps = { 0 };
	const ngtcp2_tstamp ts = quic_session_get_timestamp(session);

	/*
	 * This temporary list will hold streams that have been processed in
	 * this cycle. They will be appended back to the main list at the end to
	 * maintain the round-robin order.
	 */
	isc__quic_stream_data_t *current = NULL, *next = NULL;
	quic_stream_list_t processed_list = ISC_LIST_INITIALIZER;

	ngtcp2_path_storage_zero(&ps);

	for (current = ISC_LIST_HEAD(session->streams.list); current != NULL;
	     current = next)
	{
		ssize_t user_data_written = 0;
		/*
		 * NGTCP2_WRITE_STREAM_FLAG_MORE tells ngtcp2 that we might try
		 * to write data from other streams into this same packet. This
		 * allows ngtcp2 to intelligently batch STREAM frames.
		 */
		uint32_t flags = NGTCP2_WRITE_STREAM_FLAG_MORE;
		int32_t stream_id = -1;
		isc_region_t available_data = { 0 };
		isc__quic_send_req_t *req = NULL;

		/*
		 * If we have no more data to send across all streams, we can
		 * stop.
		 */
		if (session->sends.pending_data == 0) {
			break;
		}

		next = ISC_LIST_NEXT(current, stream_link);

		/* Check for connection-level flow control. */
		if (ngtcp2_conn_get_max_data_left(session->conn) > 0) {
			/*
			 * If this specific stream has no pending data, skip it.
			 */
			if (ISC_LIST_EMPTY(current->sends.queue) ||
			    current->sends.pending_data == 0)
			{
				continue;
			}
			req = ISC_LIST_HEAD(current->sends.queue);

			isc_buffer_availableregion(&req->data, &available_data);
			if (available_data.length == 0) {
				continue;
			}

			/*
			 * If this is the last piece of data for this stream,
			 * set the FIN flag.
			 */
			if (req->fin) {
				flags |= NGTCP2_WRITE_STREAM_FLAG_FIN;
			}

			stream_id = current->stream_id;

			/*
			 * Move the current stream out of the main list and into
			 * our temporary processed list. This is the core of the
			 * round-robin scheduling.
			 */
			ISC_LIST_UNLINK(session->streams.list, current,
					stream_link);
			ISC_LIST_APPEND(processed_list, current, stream_link);
		}

		if (stream_id < 0) {
			/*
			 * No stream was eligible to write at the connection
			 * level.
			 */
			break;
		} else if (ngtcp2_conn_get_max_stream_data_left(session->conn,
								stream_id) <= 0)
		{
			/*
			 * This specific stream is blocked by stream-level flow
			 * control, so we continue to the next stream.
			 */
			continue;
		}

		/*
		 * This is the critical call to the underlying ngtcp2 library.
		 * It attempts to write data from a single stream into the
		 * packet buffer. The return value and the `user_data_written`
		 * output parameter must be handled carefully, as they encode
		 * many different states.
		 */
		written = ngtcp2_conn_write_stream(
			session->conn, &ps.path, &pi, out_pkt->pktbuf.base,
			out_pkt_buf_len, &user_data_written, flags, stream_id,
			available_data.base, available_data.length, ts);

		if (written < 0) {
			switch (written) {
				/*
				 * These are non-fatal, transient error codes.
				 * They generally mean we are blocked by flow
				 * control, congestion control, or some other
				 * temporary condition. We should simply move on
				 * and try the next stream.
				 */
			case NGTCP2_ERR_STREAM_NOT_FOUND:
			case NGTCP2_ERR_STREAM_ID_BLOCKED:
			case NGTCP2_ERR_STREAM_DATA_BLOCKED:
				/* Congestion control */
				continue;
			case NGTCP2_ERR_STREAM_SHUT_WR: {
				/*
				 * The stream has been shut for writing by the
				 * local application, but there might be pending
				 * data that was sent and is awaiting
				 * acknowledgment. We need to cancel any further
				 * pending sends for this stream.
				 */
				bool ack_expected =
					(isc_buffer_length(&req->data) !=
					 isc_buffer_availablelength(
						 &req->data)) &&
					(isc_buffer_usedlength(&req->data) > 0);

				if (ack_expected) {
					/*
					 * Temporarily remove the request to
					 * cancel others.
					 */
					ISC_LIST_DEQUEUE(current->sends.queue,
							 req, stream_link);
					ISC_LIST_UNLINK(session->sends.queue,
							req, conn_link);
				}
				quic_session_stream_call_pending_callbacks(
					session, stream_id, ISC_R_SHUTTINGDOWN);
				if (ack_expected) {
					/* Put it back to wait for the ACK. */
					ISC_LIST_PREPEND(current->sends.queue,
							 req, stream_link);
					ISC_LIST_APPEND(session->sends.queue,
							req, conn_link);
				}
				continue;
			}
			case NGTCP2_ERR_WRITE_MORE:
				/*
				 * This is a special signal from ngtcp2. It
				 * means it has successfully written some data
				 * (`user_data_written` will be > 0) but it
				 * wants to buffer more data from *other*
				 * streams before finalizing the packet. We must
				 * not break the loop.
				 */
				INSIST(user_data_written > 0);
				INSIST(req != NULL);

				isc_buffer_add(&req->data, user_data_written);
				session->sends.pending_data -=
					user_data_written;
				current->sends.pending_data -=
					user_data_written;
				/* Mark that we've written something. */
				sentp = true;
				/* Crucially, continue to the next stream. */
				continue;
			default:
				ngtcp2_ccerr_set_liberr(&session->conn_err,
							written, NULL, 0);
				last_written = written;
				goto exit;
			}
		} else if (user_data_written > 0) {
			/*
			 * Success: some or all of the data was written into the
			 * packet buffer. Update our internal tracking of
			 * pending data.
			 */
			INSIST(req != NULL);
			isc_buffer_add(&req->data, user_data_written);
			session->sends.pending_data -= user_data_written;
			current->sends.pending_data -= user_data_written;
			/* Mark that we've written something. */
			sentp = true;
		}

		if (written > 0) {
			last_written = written;
			break;
		} else if (written == 0) {
			/*
			 * A return of 0 means the packet buffer is full or we
			 * are blocked by congestion control. We cannot write
			 * any more data in this packet.
			 */
			break;
		}
	}

	/*
	 * After iterating through all streams, if we've written any data
	 * (`sentp` is true), we may need to make a final call to
	 * ngtcp2_conn_write_stream. This call, with a stream_id of -1, tells
	 * ngtcp2 to finalize the packet, adding any pending ACK frames or other
	 * control frames.
	 */
	switch (written) {
	/*
	 * If the last operation was a "soft" error, we still need to
	 * finalize.
	 */
	case NGTCP2_ERR_STREAM_NOT_FOUND:
	case NGTCP2_ERR_STREAM_ID_BLOCKED:
	case NGTCP2_ERR_STREAM_DATA_BLOCKED:
	case NGTCP2_ERR_STREAM_SHUT_WR:
	case NGTCP2_ERR_WRITE_MORE:
		if (sentp) {
			written = ngtcp2_conn_write_stream(
				session->conn, &ps.path, &pi,
				out_pkt->pktbuf.base, out_pkt_buf_len, NULL, 0,
				-1, NULL, 0, ts);
			if (written > 0) {
				last_written = written;
			} else if (written < 0) {
				last_written = written;
			}
		} else {
			INSIST(last_written == 0);
			written = 0;
		}
		break;
	}

exit:
	/*
	 * Append the list of processed streams back to the main list. Since we
	 * were taking from the head and appending here, and now append this
	 * entire list to the tail of the main list, we achieve the round-robin
	 * effect.
	 */
	ISC_LIST_APPENDLIST(session->streams.list, processed_list, stream_link);
	if (last_written > 0) {
		/*
		 * If we successfully wrote a packet, record the path it is
		 * for.
		 */
		isc_ngtcp2_path_getaddrs(&ps.path, &out_pkt->local,
					 &out_pkt->peer);
	}

	return last_written;
}

static inline void
quic_session_write_close_pkt(isc_quic_session_t *restrict session,
			     isc_quic_out_pkt_t *restrict out_pkt) {
	if (session->close_msg != NULL) {
		isc_region_t close_pkt = { 0 };

		session->close_reset_count++;

		if (session->close_reset_count > STATELESS_CLOSE_COUNT) {
			return;
		}

		isc_buffer_usedregion(session->close_msg, &close_pkt);

		memmove(out_pkt->pktbuf.base, close_pkt.base,
			ISC_MIN(close_pkt.length, out_pkt->pktbuf.length));
		out_pkt->pktsz = (ssize_t)close_pkt.length;
		out_pkt->local = session->close_local;
		out_pkt->peer = session->close_peer;
	}
}

static isc_result_t
quic_session_write_pkt(isc_quic_session_t *restrict session,
		       isc_quic_out_pkt_t *restrict out_pkt) {
	isc_result_t result = ISC_R_SUCCESS;
	ssize_t written = 0;

	ERR_clear_error();

	if (session->resetting) {
		(void)quic_session_write_stateless_reset(
			session, session->last_read_pkt_size,
			&session->last_read_pkt_dcid, out_pkt);
		return ISC_R_SUCCESS;
	} else if (session->conn == NULL) {
		return ISC_R_SUCCESS;
	}

	const size_t send_quantum = ngtcp2_conn_get_send_quantum(session->conn);

	if (session->sent_before_expiry >= send_quantum) {
		return result;
	}

	const size_t max_pkt_len = get_max_send_pkt_len(session, send_quantum,
							out_pkt->pktbuf.length);

	if (max_pkt_len == 0) {
		return ISC_R_SUCCESS;
	}

	written = quic_session_send_pending(session, out_pkt, max_pkt_len);
	switch (written) {
	case 0:
		/* Alles gut! */
		result = ISC_R_SUCCESS;
		break;
	case NGTCP2_ERR_DRAINING:
	case NGTCP2_ERR_CLOSING:
		result = ISC_R_SHUTTINGDOWN;
		quic_session_call_pending_callbacks(session, result);
		return result;
	default:
		if (written < 0) {
			result = quic_session_process_event(
				session, ISC_QUIC_EV_FATAL_ERROR, out_pkt);
			return result;
		} else {
			INSIST(written > 0);
			out_pkt->pktsz = written;
			result = ISC_R_SUCCESS;
			return result;
		}
		break;
	}

	written = quic_session_write_streams_pkt(session, out_pkt, max_pkt_len);
	switch (written) {
	case 0:
		/* Alles gut! */
		result = ISC_R_SUCCESS;
		break;
	case NGTCP2_ERR_DRAINING:
	case NGTCP2_ERR_CLOSING:
		result = ISC_R_SHUTTINGDOWN;
		quic_session_call_pending_callbacks(session, result);
		break;
	default:
		if (written < 0) {
			result = quic_session_process_event(
				session, ISC_QUIC_EV_FATAL_ERROR, out_pkt);
			break;
		} else {
			INSIST(written > 0);
			session->sent_before_expiry += (size_t)written;
			out_pkt->pktsz = written;
			result = ISC_R_SUCCESS;
		}
		break;
	}

	if (result == ISC_R_SUCCESS) {
		if (written >= 0) {
			quic_session_update_send_time(session);
		}
	}

	return result;
}

isc_result_t
isc_quic_session_write_pkt(isc_quic_session_t *restrict session,
			   isc_quic_out_pkt_t *restrict out_pkt) {
	REQUIRE(VALID_QUIC_SESSION(session));
	REQUIRE(out_pkt != NULL && out_pkt->pktbuf.base != NULL &&
		out_pkt->pktbuf.length >= NGTCP2_MAX_UDP_PAYLOAD_SIZE &&
		out_pkt->pktsz == 0);

	(void)quic_session_update_timestamp(session);

	return quic_session_write_pkt(session, out_pkt);
}

isc_result_t
isc_quic_session_on_expiry_timer(isc_quic_session_t *restrict session,
				 isc_quic_out_pkt_t *restrict out_pkt) {
	int ret = 0;
	isc_result_t result = ISC_R_SUCCESS;
	REQUIRE(VALID_QUIC_SESSION(session));
	REQUIRE(out_pkt != NULL && out_pkt->pktbuf.base != NULL &&
		out_pkt->pktbuf.length >= NGTCP2_MAX_UDP_PAYLOAD_SIZE &&
		out_pkt->pktsz == 0);

	if (session->conn == NULL) {
		return ISC_R_UNEXPECTED;
	}

	ERR_clear_error();

	if (session->conn != NULL) {
		ret = ngtcp2_conn_handle_expiry(
			session->conn, quic_session_update_timestamp(session));
	}

	session->sent_before_expiry = 0;
	if (session->timer_running) {
		session->timer_running = false;
		session->cb.expiry_timer_stop(session, session->cbarg);
	}

	if (ret == NGTCP2_ERR_IDLE_CLOSE) {
		result = quic_session_process_event(session, ISC_QUIC_EV_DROP,
						    out_pkt);
		return result;
	} else if (ret == NGTCP2_ERR_HANDSHAKE_TIMEOUT) {
		result = quic_session_process_event(
			session, ISC_QUIC_EV_TIMEOUT, out_pkt);
		return result;
	}

	return quic_session_write_pkt(session, out_pkt);
}

static isc__quic_stream_data_t *
quic_session_lookup_stream(isc_quic_session_t *restrict session,
			   const int64_t stream_id) {
	REQUIRE(VALID_QUIC_SESSION(session));

	isc__quic_stream_data_t *stream = NULL;
	isc_result_t result = isc_ht_find(session->streams.idx,
					  (uint8_t *)&stream_id,
					  sizeof(stream_id), (void **)&stream);
	if (result != ISC_R_SUCCESS) {
		return NULL;
	}

	RUNTIME_CHECK(VALID_QUIC_STREAM(stream));

	INSIST(ISC_LINK_LINKED(stream, stream_link));
	INSIST(stream->stream_id == stream_id);

	return stream;
}

static void
quic_session_track_stream(isc_quic_session_t *restrict session,
			  const int64_t stream_id, void *stream_user_data) {
	isc__quic_stream_data_t *stream = NULL;
	REQUIRE(VALID_QUIC_SESSION(session));

	stream = quic_session_lookup_stream(session, stream_id);
	RUNTIME_CHECK(stream == NULL);

	stream = (isc__quic_stream_data_t *)isc_mempool_get(
		session->streams.pool);

	*stream = (isc__quic_stream_data_t){
		.magic = QUIC_STREAM_MAGIC,
		.stream_id = stream_id,
		.stream_user_data = stream_user_data,
		.stream_link = ISC_LINK_INITIALIZER,
		.sends.queue = ISC_LIST_INITIALIZER,
	};

	ISC_LIST_APPEND(session->streams.list, stream, stream_link);

	isc_result_t result = isc_ht_add(session->streams.idx,
					 (const uint8_t *)&stream->stream_id,
					 sizeof(stream->stream_id), stream);

	RUNTIME_CHECK(result == ISC_R_SUCCESS);
}

static void
quic_session_stream_call_pending_callbacks(isc_quic_session_t *restrict session,
					   const int64_t stream_id,
					   const isc_result_t result) {
	REQUIRE(VALID_QUIC_SESSION(session));

	isc__quic_stream_data_t *stream = quic_session_lookup_stream(session,
								     stream_id);

	if (stream == NULL) {
		return;
	}
	if (!ISC_LIST_EMPTY(stream->sends.queue)) {
		isc__quic_send_req_t *current = NULL, *next = NULL;
		for (current = ISC_LIST_HEAD(stream->sends.queue);
		     current != NULL; current = next)
		{
			next = ISC_LIST_NEXT(current, stream_link);
			ISC_LIST_DEQUEUE(stream->sends.queue, current,
					 stream_link);
			INSIST(stream->sends.queue_len > 0);
			stream->sends.queue_len--;
			ISC_LIST_UNLINK(session->sends.queue, current,
					conn_link);
			INSIST(session->sends.queue_len > 0);
			session->sends.queue_len--;

			current->cb(session, stream->stream_id, result,
				    current->cbarg, stream->stream_user_data);
			isc_mempool_put(session->sends.pool, current);
		}
	}
}

static void
quic_session_call_pending_callbacks(isc_quic_session_t *restrict session,
				    const isc_result_t result) {
	REQUIRE(VALID_QUIC_SESSION(session));
	if (!ISC_LIST_EMPTY(session->streams.list)) {
		isc__quic_stream_data_t *current = NULL, *next = NULL;
		for (current = ISC_LIST_HEAD(session->streams.list);
		     current != NULL; current = next)
		{
			quic_session_stream_call_pending_callbacks(
				session, current->stream_id, result);
		}
	}
}

static void
quic_session_untrack_stream(isc_quic_session_t *restrict session,
			    const int64_t stream_id) {
	REQUIRE(VALID_QUIC_SESSION(session));

	isc__quic_stream_data_t *stream = quic_session_lookup_stream(session,
								     stream_id);

	if (stream == NULL) {
		return;
	}

	quic_session_stream_call_pending_callbacks(session, stream_id,
						   ISC_R_CANCELED);

	if (!stream->close_cb_called) {
		stream->close_cb_called = true;
		(void)session->cb.on_stream_close(
			session, stream_id, true, NGTCP2_INTERNAL_ERROR,
			session->cbarg, stream->stream_user_data);
	}

	ISC_LIST_UNLINK(session->streams.list, stream, stream_link);

	isc_result_t result = isc_ht_delete(
		session->streams.idx, (uint8_t *)&stream_id, sizeof(stream_id));

	RUNTIME_CHECK(result == ISC_R_SUCCESS);

	stream->magic = 0;
	isc_mempool_put(session->streams.pool, stream);
}

static void
quic_session_untrack_all_streams(isc_quic_session_t *restrict session) {
	REQUIRE(VALID_QUIC_SESSION(session));
	if (!ISC_LIST_EMPTY(session->streams.list)) {
		isc__quic_stream_data_t *current = NULL, *next = NULL;
		for (current = ISC_LIST_HEAD(session->streams.list);
		     current != NULL; current = next)
		{
			next = ISC_LIST_NEXT(current, stream_link);
			quic_session_untrack_stream(session,
						    current->stream_id);
		}
	}

	INSIST(ISC_LIST_EMPTY(session->streams.list));
	INSIST(isc_ht_count(session->streams.idx) == 0);
	INSIST(ISC_LIST_EMPTY(session->sends.queue));
}

isc_result_t
isc_quic_session_open_stream(isc_quic_session_t *restrict session,
			     const bool bidi, void *stream_user_data,
			     int64_t *restrict pstream_id) {
	REQUIRE(VALID_QUIC_SESSION(session));
	REQUIRE(pstream_id != NULL);

	int ret = 0;
	isc_result_t result = ISC_R_SUCCESS;

	ERR_clear_error();

	if (bidi) {
		ret = ngtcp2_conn_open_bidi_stream(session->conn, pstream_id,
						   stream_user_data);
	} else {
		ret = ngtcp2_conn_open_uni_stream(session->conn, pstream_id,
						  stream_user_data);
	}

	if (ret != 0) {
		result = ISC_R_FAILURE;
	} else {
		quic_session_track_stream(session, *pstream_id,
					  stream_user_data);
	}

	return result;
}

isc_result_t
isc_quic_session_set_stream_user_data(isc_quic_session_t *restrict session,
				      const int64_t stream_id,
				      void *stream_user_data) {
	REQUIRE(VALID_QUIC_SESSION(session));

	int ret = 0;
	isc_result_t result = ISC_R_SUCCESS;

	isc__quic_stream_data_t *stream = quic_session_lookup_stream(session,
								     stream_id);
	if (stream == NULL) {
		return ISC_R_NOTFOUND;
	}

	ret = ngtcp2_conn_set_stream_user_data(session->conn, stream_id,
					       stream_user_data);

	if (ret != 0) {
		result = ISC_R_FAILURE;
	} else {
		stream->stream_user_data = stream_user_data;
	}

	return result;
}

void *
isc_quic_session_get_stream_user_data(isc_quic_session_t *restrict session,
				      const int64_t stream_id) {
	/*
	 * This functionality is not directly provided by ngtcp2
	 */
	REQUIRE(VALID_QUIC_SESSION(session));

	isc__quic_stream_data_t *stream = quic_session_lookup_stream(session,
								     stream_id);
	if (stream == NULL) {
		return NULL;
	}

	return stream->stream_user_data;
}

bool
isc_quic_session_is_bidi_stream(isc_quic_session_t *restrict session,
				const int64_t stream_id) {
	REQUIRE(VALID_QUIC_SESSION(session));

	isc__quic_stream_data_t *stream = quic_session_lookup_stream(session,
								     stream_id);
	if (stream == NULL) {
		return false;
	}

	return ngtcp2_is_bidi_stream(stream_id);
}

isc_result_t
isc_quic_session_send_data(isc_quic_session_t *restrict session,
			   const int64_t stream_id,
			   const isc_region_t *restrict data, const bool fin,
			   isc_quic_send_cb_t cb, void *cbarg) {
	REQUIRE(VALID_QUIC_SESSION(session));
	REQUIRE((data == NULL && fin) ||
		(data->length > 0 && data->base != NULL));
	REQUIRE(cb != NULL);

	isc__quic_stream_data_t *stream = quic_session_lookup_stream(session,
								     stream_id);

	if (stream == NULL || session->fin) {
		cb(session, -1, ISC_R_NOTFOUND, cbarg, NULL);
		return ISC_R_NOTFOUND;
	} else if (session->shuttingdown) {
		cb(session, -1, ISC_R_SHUTTINGDOWN, cbarg, NULL);
		return ISC_R_SHUTTINGDOWN;
	}

	if (stream->fin) {
		cb(session, stream_id, ISC_R_UNEXPECTED, cbarg,
		   stream->stream_user_data);
		return ISC_R_UNEXPECTED;
	}

	stream->fin = fin;

	isc__quic_send_req_t *send_req = isc_mempool_get(session->sends.pool);

	*send_req = (isc__quic_send_req_t){ .stream = stream,
					    .cb = cb,
					    .cbarg = cbarg,
					    .fin = fin,
					    .stream_link = ISC_LINK_INITIALIZER,
					    .conn_link = ISC_LINK_INITIALIZER };

	if (data != NULL) {
		isc_buffer_init(&send_req->data, data->base, data->length);
	}

	ISC_LIST_APPEND(session->sends.queue, send_req, conn_link);
	session->sends.queue_len++;
	session->sends.pending_data += data->length;
	ISC_LIST_APPEND(stream->sends.queue, send_req, stream_link);
	stream->sends.queue_len++;
	stream->sends.pending_data += data->length;

	return ISC_R_SUCCESS;
}

static inline int
quic_session_read_pkt(isc_quic_session_t *restrict session,
		      const isc_region_t *restrict pkt_data) {
	int ret = 0;
	ngtcp2_pkt_info pi = { 0 };
	REQUIRE(VALID_QUIC_SESSION(session));
	REQUIRE(pkt_data != NULL && pkt_data->length > 0 &&
		pkt_data->base != NULL);

	ret = ngtcp2_conn_read_pkt(session->conn, session->path, &pi,
				   pkt_data->base, pkt_data->length,
				   quic_session_get_timestamp(session));
	if (ret < 0) {
		ngtcp2_ccerr_set_liberr(&session->conn_err, ret, NULL, 0);
	} else {
		/*
		 * Track all source CIDs - per ngtcp2
		 * programming guidelines.
		 */
		size_t ncids = ngtcp2_conn_get_scid(session->conn, NULL);
		if (ncids > 0) {
			ngtcp2_cid tmp_cids_storage[16] = { 0 };
			isc_buffer_t cids_buf = { 0 };
			isc_region_t cids = { 0 };

			isc_buffer_init(&cids_buf, tmp_cids_storage,
					sizeof(tmp_cids_storage));
			isc_buffer_setmctx(&cids_buf, session->mctx);

			isc_buffer_reserve(&cids_buf,
					   ncids * sizeof(ngtcp2_cid));
			isc_buffer_add(&cids_buf, ncids * sizeof(ngtcp2_cid));

			isc_buffer_usedregion(&cids_buf, &cids);

			ncids = ngtcp2_conn_get_scid(session->conn,
						     (ngtcp2_cid *)cids.base);

			ngtcp2_cid *pcids = (ngtcp2_cid *)cids.base;
			for (size_t i = 0; i < ncids; i++) {
				(void)quic_session_assoc_cid(
					session, pcids[i].data,
					pcids[i].datalen, true);
			}

			isc_buffer_clearmctx(&cids_buf);
			isc_buffer_invalidate(&cids_buf);
		}
	}
	return ret;
}

static inline bool
quic_version_supported(isc_quic_session_t *restrict session,
		       const uint32_t version) {
	isc_region_t available_versions = { 0 };

	isc_buffer_usedregion(&session->available_versions,
			      &available_versions);

	return ngtcp2_is_supported_version(version) &&
	       !ngtcp2_is_reserved_version(version) &&
	       isc_ngtcp2_is_version_available(
		       version, (uint32_t *)available_versions.base,
		       available_versions.length / sizeof(uint32_t));
}

/*
 * Processes an incoming QUIC packet for a session.
 *
 * This is a central and highly complex function in the framework. It serves as
 * the primary entry point for all received network data. It is responsible for
 * parsing the packet in the context of the session's current state, driving the
 * state machine forward, and potentially generating an immediate response
 * packet (e.g., a Version Negotiation packet, a Retry packet, or an
 * acknowledgment).
 *
 * The function's behavior differs dramatically depending on whether the session
 * is a client or a server, and on its current state (e.g., initial connection,
 * handshake, established).
 */
isc_result_t
isc_quic_session_read_pkt(isc_quic_session_t *restrict session,
			  const isc_sockaddr_t *restrict local,
			  const isc_sockaddr_t *restrict peer,
			  const uint32_t version,
			  const isc_region_t *restrict pkt_dcid,
			  const isc_region_t *restrict pkt_scid,
			  const bool token_verified,
			  const isc_region_t *restrict retry_token_odcid,
			  const isc_region_t *restrict pkt_data,
			  isc_quic_out_pkt_t *restrict out_pkt) {
	isc_result_t result = ISC_R_SUCCESS;
	ngtcp2_cid dcid = { 0 }, scid = { 0 };
	ngtcp2_cid *pdcid = NULL, *pscid = NULL;
	ngtcp2_path current_path = { 0 };
	int ret = 0;
	ssize_t written = 0;

	REQUIRE(VALID_QUIC_SESSION(session));
	REQUIRE(local != NULL);
	REQUIRE(peer != NULL);
	REQUIRE(pkt_dcid != NULL && pkt_dcid->length > 0 &&
		pkt_dcid->base != NULL);
	REQUIRE(pkt_data != NULL && pkt_data->length > 0 &&
		pkt_data->base != NULL);
	REQUIRE(out_pkt != NULL && out_pkt->pktbuf.base != NULL &&
		out_pkt->pktbuf.length >= NGTCP2_MAX_UDP_PAYLOAD_SIZE &&
		out_pkt->pktsz == 0);

	/*
	 * Temporarily set the session's path context to the source/destination
	 * of the packet being processed. This is important for ngtcp2 to
	 * validate the path. We will restore it to the session's primary path
	 * at the end of the function.
	 */
	isc_ngtcp2_path_init(&current_path, local, peer);
	session->path = &current_path;
	session->last_read_pkt_size = pkt_data->length;

	/*
	 * For long header packets (used during the handshake), both SCID and
	 * DCID are present and required. Note the swap: from the server's
	 * perspective, the packet's DCID is its own SCID, and the packet's SCID
	 * is its new DCID.
	 */
	if (isc_ngtcp2_pkt_header_is_long(pkt_data->base, pkt_data->length)) {
		INSIST(pkt_scid != NULL && pkt_scid->length > 0 &&
		       pkt_scid->base != NULL);

		ngtcp2_cid_init(&dcid, pkt_dcid->base, pkt_dcid->length);
		ngtcp2_cid_init(&scid, pkt_scid->base, pkt_scid->length);
		session->last_read_pkt_dcid = dcid;
		pscid = &dcid;
		pdcid = &scid;
	} else {
		ngtcp2_cid_init(&dcid, pkt_dcid->base, pkt_dcid->length);
		session->last_read_pkt_dcid = dcid;
		pscid = &dcid;
	}

	(void)quic_session_update_timestamp(session);
	ERR_clear_error();

	/*
	 * If the session is already in a terminal state, we should not process
	 * new packets normally. Instead, we may need to re-send the close/reset
	 * message as per RFC 9000.
	 */
	if (session->closing) {
		if (isc_sockaddr_equal(local, &session->close_local) &&
		    isc_sockaddr_equal(peer, &session->close_peer))
		{
			quic_session_write_close_pkt(session, out_pkt);
		}
		return ISC_R_SUCCESS;
	} else if (session->resetting) {
		(void)quic_session_write_stateless_reset(
			session, pkt_data->length, &dcid, out_pkt);
		return ISC_R_SUCCESS;
	}

	/*
	 * Server pre-connection logic:
	 *
	 * This block handles the very first packets arriving at a server for a
	 * new connection, before an ngtcp2_conn object has been created.
	 */

	/*
	 * Case 1: Client is using a QUIC version the server does not support.
	 */
	if (session->is_server && session->conn == NULL &&
	    !quic_version_supported(session, version) &&
	    isc_ngtcp2_pkt_header_is_long(pkt_data->base, pkt_data->length))
	{
		/*
		 * Associate the CIDs from the packet with this session
		 * temporarily.
		 */
		quic_session_deassoc_all_cids(session, false);

		isc_quic_cid_t *cid = quic_session_assoc_cid(
			session, pscid->data, pscid->datalen, true);

		if (session->initial_scid != NULL) {
			isc_quic_cid_detach(&session->initial_scid);
		}

		isc_quic_cid_attach(cid, &session->initial_scid);

		cid = quic_session_assoc_cid(session, pdcid->data,
					     pdcid->datalen, false);

		if (session->initial_dcid != NULL) {
			isc_quic_cid_detach(&session->initial_dcid);
		}

		isc_quic_cid_attach(cid, &session->initial_dcid);

		/*
		 * Trigger the VERSION_MISMATCH event. This will transition the
		 * state machine and generate a Version Negotiation packet to be
		 * sent back to the client.
		 */
		result = quic_session_process_event(
			session, ISC_QUIC_EV_VERSION_MISMATCH, out_pkt);
		goto exit;

		/*
		 * Case 2: This is an Initial packet with a supported version.
		 * This is the main entry point for a new connection on the
		 * server.
		 */
	} else if (session->is_server && session->conn == NULL &&
		   isc_ngtcp2_pkt_header_is_long(pkt_data->base,
						 pkt_data->length))
	{
		ngtcp2_pkt_hd hd = { 0 };
		bool valid_retry_token_found = false;
		ngtcp2_cid odcid_data = { 0 };
		/*
		 * Default event: assume no token, which may require address
		 * validation.
		 */
		int ev = ISC_QUIC_EV_NO_REGULAR_TOKEN_RECEIVED;
		bool retry = true; /* Default action: send a Retry packet. */

		/*
		 * If we just sent a Version Negotiation, we must reset to the
		 * INITIAL state.
		 */
		if (session->state == ISC_QUIC_ST_VERSION_NEGOTIATION) {
			result = quic_session_process_event(
				session, ISC_QUIC_EV_SELECT_COMPATIBLE_VERSION,
				NULL);

			if (result != ISC_R_SUCCESS) {
				written = quic_session_write_stateless_reset(
					session, pkt_data->length, &scid,
					out_pkt);
				goto exit;
			}
		}

		/* Use ngtcp2 to parse the full Initial packet header. */
		ret = ngtcp2_accept(&hd, pkt_data->base, pkt_data->length);
		if (ret != 0) {
			/*
			 * Invalid header, stateless reset is the only option.
			 */
			written = quic_session_write_stateless_reset(
				session, pkt_data->length, &dcid, out_pkt);
			result = ISC_R_UNEXPECTED;
			goto exit;
		}

		/*
		 * Check for Retry or Regular tokens to validate the client's
		 * address and potentially bypass the Retry mechanism.
		 */
		if (hd.tokenlen > 0) {
			isc_region_t secret_data = { 0 };

			isc_buffer_usedregion(&session->secret, &secret_data);
			if (hd.token[0] == ISC_NGTCP2_CRYPTO_TOKEN_MAGIC_RETRY)
			{
				/*
				 * The client is responding to our Retry packet.
				 * Verify the token when necessary.
				 */
				if (token_verified &&
				    retry_token_odcid != NULL &&
				    retry_token_odcid->base != NULL &&
				    retry_token_odcid->length != 0)
				{
					result = ISC_R_SUCCESS;
					INSIST(retry_token_odcid->length <=
					       sizeof(odcid_data.data));
					memmove(odcid_data.data,
						retry_token_odcid->base,
						retry_token_odcid->length);
					odcid_data.datalen =
						retry_token_odcid->length;
				} else {
					result = isc_ngtcp2_crypto_verify_retry_token(
						&odcid_data, hd.token,
						hd.tokenlen, secret_data.base,
						secret_data.length, version,
						session->path->remote.addr,
						session->path->remote.addrlen,
						&dcid,
						session->handshake_timeout,
						quic_session_get_timestamp(
							session));
				}
				if (result == ISC_R_SUCCESS &&
				    (session->rcid == NULL ||
				     ngtcp2_cid_eq(&dcid, &session->rcid->cid)))
				{
					/*
					 * Token is valid. We can proceed with
					 * the handshake.
					 */
					valid_retry_token_found = true;
					retry = false;
					ev = ISC_QUIC_EV_VALID_RETRY_TOKEN_RECEIVED;
				} else {
					ev = ISC_QUIC_EV_INVALID_RETRY_TOKEN_RECEIVED;
				}

			} else if (hd.token[0] ==
				   ISC_NGTCP2_CRYPTO_TOKEN_MAGIC_REGULAR)
			{
				/*
				 * The client is presenting a token from a
				 * previous connection.
				 */
				if (token_verified) {
					result = ISC_R_SUCCESS;
				} else {
					result = isc_ngtcp2_crypto_verify_regular_token(
						hd.token, hd.tokenlen,
						secret_data.base,
						secret_data.length,
						session->path->remote.addr,
						session->path->remote.addrlen,
						ISC_QUIC_SESSION_REGULAR_TOKEN_VALIDITY_PERIOD,
						quic_session_get_timestamp(
							session));
				}
				if (result == ISC_R_SUCCESS) {
					/*
					 * Token is valid. We can proceed with
					 * the handshake.
					 */
					retry = false;
					ev = ISC_QUIC_EV_VALID_REGULAR_TOKEN_RECEIVED;
				} else {
					ev = ISC_QUIC_EV_INVALID_REGULAR_TOKEN_RECEIVED;
				}
			}
		}

		/*
		 * Now that we have context, manage the CIDs for this potential
		 * connection and initialize the ngtcp2_conn if the path is
		 * validated.
		 */

		/* The server chooses its own SCID */
		isc_quic_cid_t *cid = quic_session_gen_new_cid(
			session, true, ISC_QUIC_SERVER_SCID_LEN);

		if (cid == NULL) {
			written = quic_session_write_stateless_reset(
				session, pkt_data->length, &dcid, out_pkt);
			result = ISC_R_UNEXPECTED;
			goto exit;
		}

		isc_quic_cid_attach(cid, &session->initial_scid);

		/*
		 * Keep track of the DCID (SCID for server) from the original
		 * packet, too.
		 */
		cid = quic_session_assoc_cid(session, pscid->data,
					     pscid->datalen, true);

		if (cid == NULL) {
			(void)quic_session_process_event(
				session, ISC_QUIC_EV_FATAL_ERROR, out_pkt);
			result = ISC_R_UNEXPECTED;
			goto exit;
		}

		/*
		 * The token might have been generated before the connection was
		 * created.
		 */
		if (hd.tokenlen > 0 &&
		    hd.token[0] == ISC_NGTCP2_CRYPTO_TOKEN_MAGIC_RETRY &&
		    session->rcid == NULL)
		{
			isc_quic_cid_attach(cid, &session->rcid);
		}

		if (valid_retry_token_found) {
			cid = quic_session_assoc_cid(session, odcid_data.data,
						     odcid_data.datalen, true);
			if (cid == NULL) {
				(void)quic_session_process_event(
					session, ISC_QUIC_EV_FATAL_ERROR,
					out_pkt);
				result = ISC_R_UNEXPECTED;
				goto exit;
			}

			isc_quic_cid_attach(cid, &session->odcid);
		} else {
			isc_quic_cid_attach(cid, &session->odcid);
		}

		cid = quic_session_assoc_cid(session, pdcid->data,
					     pdcid->datalen, false);

		if (cid == NULL) {
			(void)quic_session_process_event(
				session, ISC_QUIC_EV_FATAL_ERROR, out_pkt);
			result = ISC_R_UNEXPECTED;
			goto exit;
		}

		isc_quic_cid_attach(cid, &session->initial_dcid);

		session->negotiated_version = hd.version;
		if (!retry) {
			/*
			 * If we are not sending a Retry, it means the client's
			 * address is trusted. We can now initialize the full
			 * ngtcp2 connection object.
			 */
			quic_session_init(session, &session->initial_scid->cid,
					  &session->initial_dcid->cid,
					  session->odcid != NULL
						  ? &session->odcid->cid
						  : NULL,
					  (valid_retry_token_found &&
					   session->rcid != NULL)
						  ? &session->rcid->cid
						  : NULL);
		}

		/*
		 * Trigger the state machine with the event determined by the
		 * token validation
		 */
		result = quic_session_process_event(session, ev, out_pkt);

		if (retry) {
			/*
			 * We sent a Retry packet, so discard the temporary
			 * state.
			 */
			quic_session_deassoc_all_cids(session, true);
		}

		/*
		 * If we generated a response packet (Retry/ServerInitial), we
		 * are done.
		 */
		if (out_pkt->pktsz == 0) {
			session->write_after_read = true;
		} else {
			goto exit;
		}
		/*
		 * Client logic:
		 * Handling the first packet from the server.
		 */
	} else if (!session->is_server &&
		   session->state == ISC_QUIC_ST_INITIAL &&
		   isc_ngtcp2_pkt_header_is_long(pkt_data->base,
						 pkt_data->length) &&
		   version != 0)
	{
		INSIST(session->conn != NULL);
		if (quic_version_supported(session, version)) {
			/*
			 * The server responded with a supported version. We can
			 * now move to the handshake phase.
			 */
			result = quic_session_process_event(
				session, ISC_QUIC_EV_VERSION_ACCEPTED, out_pkt);
		} else {
			/*
			 * Server responded with an unsupported version, which
			 * is a protocol error.
			 */
			result = quic_session_process_event(
				session, ISC_QUIC_EV_FATAL_ERROR, out_pkt);
			goto exit;
		}
	}

	if (result != ISC_R_SUCCESS) {
		(void)quic_session_process_event(
			session, ISC_QUIC_EV_FATAL_ERROR, out_pkt);
		goto exit;
	}

	/*
	 * Main packet processing:
	 *
	 * For all other cases (e.g., handshake packets, established connection
	 * packets), we hand off the data to the initialized ngtcp2_conn object.
	 */
	bool was_draining = false;
	bool was_closing = false;

	if (session->conn != NULL) {
		was_draining = ngtcp2_conn_in_draining_period(session->conn);
		was_closing = ngtcp2_conn_in_closing_period(session->conn);
	} else {
		result = ISC_R_SHUTTINGDOWN;
		goto exit;
	}

	/*
	 * This internal function is a thin wrapper around
	 * ngtcp2_conn_read_pkt().
	 */
	ret = quic_session_read_pkt(session, pkt_data);

	/* Interpret the result from ngtcp2 and update our state machine. */
	switch (ret) {
	case 0:
		/* Alles gut! */
		result = ISC_R_SUCCESS;
		break;
	case NGTCP2_ERR_DROP_CONN:
		(void)quic_session_process_event(session, ISC_QUIC_EV_DROP,
						 out_pkt);
		result = ISC_R_CANCELED;
		break;
	case NGTCP2_ERR_DRAINING:
		quic_session_call_pending_callbacks(session,
						    ISC_R_SHUTTINGDOWN);
		if (was_draining) {
			result = ISC_R_SHUTTINGDOWN;
		} else {
			result = ISC_R_SUCCESS;
		}
		break;
	case NGTCP2_ERR_CLOSING:
		quic_session_call_pending_callbacks(session,
						    ISC_R_SHUTTINGDOWN);
		if (was_closing) {
			result = ISC_R_SHUTTINGDOWN;
		} else {
			result = ISC_R_SUCCESS;
		}
		break;
	case NGTCP2_ERR_RECV_VERSION_NEGOTIATION:
		/*
		 * ngtcp2 has parsed a Version Negotiation packet and called our
		 * callback, which selected a new version. We now re-initialize
		 * the connection.
		 */
		if (quic_version_supported(session,
					   session->negotiated_version))
		{
			result = quic_session_process_event(
				session, ISC_QUIC_EV_SELECT_COMPATIBLE_VERSION,
				out_pkt);
		} else {
			result = ISC_R_FAILURE;
		}
		break;
	default:
		/* Any other error is considered fatal. */
		INSIST(ret < 0);
		result = quic_session_process_event(
			session, ISC_QUIC_EV_FATAL_ERROR, out_pkt);
		break;
	}

	/*
	 * If processing the packet requires an immediate response (like an
	 * ACK), the `write_after_read` flag will be set. We attempt to generate
	 * that response packet now.
	 */
	if (result == ISC_R_SUCCESS && session->conn != NULL &&
	    session->write_after_read && out_pkt->pktsz == 0)
	{
		written = quic_session_send_pending(session, out_pkt,
						    out_pkt->pktbuf.length);
		if (written < 0) {
			result = quic_session_process_event(
				session, ISC_QUIC_EV_FATAL_ERROR, out_pkt);
		} else if (written > 0) {
			out_pkt->pktsz = written;
		}
	}

exit:
	/* Restore the session's primary path context. */
	session->path = &session->path_st.path;
	session->write_after_read = false;

	return result;
}

isc_result_t
isc_quic_session_shutdown_stream(isc_quic_session_t *restrict session,
				 const int64_t stream_id, bool abrupt) {
	REQUIRE(VALID_QUIC_SESSION(session));
	isc__quic_stream_data_t *stream = quic_session_lookup_stream(session,
								     stream_id);

	(void)quic_session_update_timestamp(session);
	ERR_clear_error();

	if (stream == NULL) {
		return ISC_R_NOTFOUND;
	}

	int ret = ngtcp2_conn_shutdown_stream(session->conn, 0, stream_id,
					      abrupt ? NGTCP2_INTERNAL_ERROR
						     : NGTCP2_NO_ERROR);

	return ret == 0 ? ISC_R_SUCCESS : ISC_R_FAILURE;
}

isc_result_t
isc_quic_session_shutdown(isc_quic_session_t *restrict session,
			  isc_quic_out_pkt_t *restrict out_pkt) {
	REQUIRE(VALID_QUIC_SESSION(session));
	REQUIRE(out_pkt != NULL && out_pkt->pktbuf.base != NULL &&
		out_pkt->pktbuf.length >= NGTCP2_MAX_UDP_PAYLOAD_SIZE &&
		out_pkt->pktsz == 0);

	if (session->shuttingdown) {
		return ISC_R_UNEXPECTED;
	}

	session->shuttingdown = true;

	(void)quic_session_update_timestamp(session);
	ERR_clear_error();

	return quic_session_process_event(session, ISC_QUIC_EV_CLOSE_INITIATED,
					  out_pkt);
}

bool
isc_quic_session_is_server(isc_quic_session_t *restrict session) {
	REQUIRE(VALID_QUIC_SESSION(session));

	return session->is_server;
}

isc_sockaddr_t
isc_quic_session_peeraddr(isc_quic_session_t *restrict session) {
	isc_sockaddr_t peer = { 0 };
	const ngtcp2_path *path = NULL;

	REQUIRE(VALID_QUIC_SESSION(session));

	path = &session->path_st.path;
	if (session->conn != NULL) {
		path = ngtcp2_conn_get_path(session->conn);
	}

	isc_ngtcp2_path_getaddrs(path, NULL, &peer);

	return peer;
}

isc_sockaddr_t
isc_quic_session_localaddr(isc_quic_session_t *restrict session) {
	isc_sockaddr_t local = { 0 };
	const ngtcp2_path *path = NULL;

	REQUIRE(VALID_QUIC_SESSION(session));

	path = &session->path_st.path;
	if (session->conn != NULL) {
		path = ngtcp2_conn_get_path(session->conn);
	}

	isc_ngtcp2_path_getaddrs(path, &local, NULL);

	return local;
}

void
isc_quic_session_set_user_data(isc_quic_session_t *restrict session,
			       void *user_data) {
	REQUIRE(VALID_QUIC_SESSION(session));

	session->user_data = user_data;
}

void *
isc_quic_session_get_user_data(isc_quic_session_t *restrict session) {
	REQUIRE(VALID_QUIC_SESSION(session));

	return session->user_data;
}
