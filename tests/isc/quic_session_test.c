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

#include <errno.h>
#include <ngtcp2/ngtcp2.h>
#include <sched.h> /* IWYU pragma: keep */
#include <setjmp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

#define UNIT_TESTING
#include <cmocka.h>

#include <isc/buffer.h>
#include <isc/lib.h>
#include <isc/mem.h>
#include <isc/ngtcp2_crypto.h>
#include <isc/ngtcp2_utils.h>
#include <isc/os.h>
#include <isc/quic.h>
#include <isc/random.h>
#include <isc/time.h>
#include <isc/tls.h>

#include "../../lib/isc/quic/quic_session.h"

#include <tests/isc.h>

/* the unit test infrastructure */

#undef PRINT_DEBUG
#define TRACE_CALLBACKS

#define TEST_SERVER_PORT (9153)
#define TEST_CLIENT_PORT (9154)

#define MAX_STREAMS   (100)
#define MAX_SENDS     (50)
#define MAX_SEND_SIZE (UINT16_MAX + sizeof(uint16_t))
#define MAX_ITERATIONS                                 \
	((uint64_t)MAX_STREAMS * (uint64_t)MAX_SENDS * \
	 (uint64_t)(MAX_SEND_SIZE / 3))

#define INITIAL_TIMEOUT (isc_ngtcp2_make_duration(15, 0))

static isc_mem_t *mctx = NULL;

static isc_tlsctx_t *default_server_tlsctx = NULL;
static isc_tlsctx_t *default_client_tlsctx = NULL;

isc_tlsctx_client_session_cache_t *client_tlsctx_sess_cache = NULL;

static isc_tlsctx_t *server_tlsctx = NULL;
static isc_tlsctx_t *client_tlsctx = NULL;

static isc_sockaddr_t server_addr = { 0 };
static isc_sockaddr_t client_addr = { 0 };
static isc_sockaddr_t migrate_client_addr = { 0 };

static isc_quic_session_t *client_session = NULL;
static isc_quic_session_t *server_session = NULL;

static const uint32_t proto_preference_list_reversed[] = {
	NGTCP2_PROTO_VER_V1, NGTCP2_PROTO_VER_V2
};

static const size_t proto_preference_list_reversed_len =
	(sizeof(proto_preference_list_reversed) /
	 sizeof(proto_preference_list_reversed[0]));

static const uint32_t proto_preference_list_v1_only[] = { NGTCP2_PROTO_VER_V1 };
static const size_t proto_preference_list_v1_only_len = 1;

static const uint32_t proto_preference_list_v2_only[] = { NGTCP2_PROTO_VER_V2 };
static const size_t proto_preference_list_v2_only_len = 1;

static const uint32_t *server_proto_preference_list = NULL;
static size_t server_proto_preference_list_len = 0;

static const uint32_t *client_proto_preference_list = NULL;
static size_t client_proto_preference_list_len = 0;

static uint32_t client_chosen_version = NGTCP2_PROTO_VER_V1;

static uint8_t client_static_secret[ISC_NGTCP2_CRYPTO_STATIC_SECRET_LEN];
static uint8_t server_static_secret[ISC_NGTCP2_CRYPTO_STATIC_SECRET_LEN];

static uint64_t ts = 0;
static bool ts_set = false;

typedef struct quic_test_session_manager quic_test_session_manager_t;

typedef struct quic_stream_data {
	int64_t stream_id;
	quic_test_session_manager_t *sm;
	bool local;
	size_t sends;
	uint8_t bcounter_receive;
	uint8_t bcounter_send;
	isc_buffer_t *send_buf;
	ISC_LINK(struct quic_stream_data) link;
} quic_stream_data_t;

struct quic_test_session_manager {
	uint64_t timer_should_fire_at;
	uint64_t timeout;
	bool timer_running;

	bool manual;

	bool connection_started;
	bool hs_completed;

	/* ISC_LIST(isc_quic_cid_t) managed_cids; */
	isc_quic_cid_map_t *src_cids;
	ssize_t managed_src_cids_count;
	isc_quic_cid_map_t *dst_cids;
	ssize_t managed_dst_cids_count;

	isc_quic_token_cache_t *server_tokens;

	ISC_LIST(quic_stream_data_t) streams;
	size_t opened_streams;
	size_t total_opened_streams;
	int64_t last_stream_id;

	bool closed;
	uint32_t closing_timeout_ms;

	size_t successful_sends;
	size_t completed_sends;
	size_t started_sends;

	size_t receives;

	isc_sockaddr_t local;
	isc_sockaddr_t peer;

	quic_test_session_manager_t *peer_sm;

	isc_buffer_t *input;
	isc_buffer_t *output;

	uint64_t total_read_bytes;
	uint64_t total_written_bytes;
	uint64_t total_sent_bytes;

	uint64_t last_update_completed_sends;
};

static quic_test_session_manager_t client_sm;
static quic_test_session_manager_t server_sm;

static isc_result_t
quic_sm_open_stream(quic_test_session_manager_t *restrict sm,
		    isc_quic_session_t *session, const bool bidi,
		    int64_t *pstream_id);

static void
quic_sm_send_cb(isc_quic_session_t *restrict session, const int64_t stream_id,
		const isc_result_t result, void *cbarg,
		quic_stream_data_t *stream);

static void
vwarn(const char *fmt, va_list args) {
#ifdef PRINT_DEBUG
	vfprintf(stderr, fmt, args);
#else
	UNUSED(fmt);
	UNUSED(args);
#endif
}

static void
warn(const char *fmt, ...) {
	va_list args;

	va_start(args, fmt);
	vwarn(fmt, args);
	va_end(args);
}

static void
warnconn(isc_quic_session_t *sess, const char *fmt, ...) {
	va_list args;

	warn("%s: ", isc_quic_session_is_server(sess) ? "server" : "client");
	va_start(args, fmt);
	vwarn(fmt, args);
	va_end(args);
}

#if defined(PRINT_DEBUG) && defined(TRACE_CALLBACKS)
#define TRACE_CB_LOG(session, format, ...)                                    \
	warnconn(session, "%s:%u:%s():" format, __FILE__, __LINE__, __func__, \
		 __VA_ARGS__)
#else
#define TRACE_CB_LOG(session, format, ...) UNUSED(session)
#endif

#define TRACE_CB(session) TRACE_CB_LOG(session, "%s", "\n")

static inline void
fill_data_buf(uint8_t *restrict c, uint8_t *buf, size_t buflen) {
	for (size_t i = 0; i < buflen; i++) {
		*c += 1;
		buf[i] = *c;
	}
}

static inline bool
verify_data_buf(uint8_t *restrict c, uint8_t *buf, size_t buflen) {
	for (size_t i = 0; i < buflen; i++) {
		*c += 1;
		const uint8_t b = *c;
		if (buf[i] != b) {
			return false;
		}
	}
	return true;
}

static inline isc_buffer_t *
get_data_buf(quic_stream_data_t *stream) {
	isc_buffer_t *databuf = NULL;
	const size_t datalen = 1 + isc_random_uniform(MAX_SEND_SIZE);
	isc_region_t data = { 0 };

	if (stream->send_buf != NULL) {
		databuf = stream->send_buf;
		stream->send_buf = NULL;
		isc_buffer_clear(databuf);
		isc_buffer_reserve(databuf, datalen);
	} else {
		isc_buffer_allocate(mctx, &databuf, datalen);
	}

	/* printf("datalen: %zu\n", datalen); */
	isc_buffer_add(databuf, datalen);
	isc_buffer_usedregion(databuf, &data);

	fill_data_buf(&stream->bcounter_send, data.base, data.length);

	return databuf;
}

static inline void
free_data_buf(quic_stream_data_t *stream, isc_buffer_t **pdatabuf) {
	if (stream->send_buf == NULL) {
		stream->send_buf = *pdatabuf;
	} else {
		isc_buffer_free(pdatabuf);
	}
}

static void
quic_sm_init(quic_test_session_manager_t *sm,
	     const isc_sockaddr_t *restrict local,
	     const isc_sockaddr_t *restrict peer,
	     quic_test_session_manager_t *peer_sm) {
	*sm = (quic_test_session_manager_t){
		.local = *local,
		.peer = *peer,
		.streams = ISC_LIST_INITIALIZER,
		.peer_sm = peer_sm,
	};

	isc_quic_cid_map_create(mctx, &sm->src_cids);
	isc_quic_cid_map_create(mctx, &sm->dst_cids);
	isc_buffer_allocate(mctx, &sm->output, 4096);
}

static void
quic_sm_uninit(quic_test_session_manager_t *sm) {
	isc_quic_cid_map_detach(&sm->src_cids);
	isc_quic_cid_map_detach(&sm->dst_cids);

	if (!ISC_LIST_EMPTY(sm->streams)) {
		quic_stream_data_t *current = NULL, *next = NULL;
		for (current = ISC_LIST_HEAD(sm->streams); current != NULL;
		     current = next)
		{
			next = ISC_LIST_NEXT(current, link);

			ISC_LIST_DEQUEUE(sm->streams, current, link);
			isc_mem_put(mctx, current, sizeof(quic_stream_data_t));
			sm->opened_streams--;
			sm->total_opened_streams++;
		}
	}

	if (sm->server_tokens != NULL) {
		isc_quic_token_cache_detach(&sm->server_tokens);
	}

	isc_buffer_free(&sm->output);
}

static uint64_t
quic_sm_get_current_ts_cb(quic_test_session_manager_t *sm) {
	UNUSED(sm);

	if (ts_set) {
		ts_set = false;
	} else {
		ts += isc_ngtcp2_make_duration(0, 4 + isc_random_uniform(4));
	}

	return ts;
}

static void
quic_sm_set_next_ts(quic_test_session_manager_t *sm, uint64_t new_ts) {
	UNUSED(sm);

	ts = new_ts;
	ts_set = true;
}

static void
quic_sm_inc_ts(quic_test_session_manager_t *sm, uint64_t inc_ns) {
	UNUSED(sm);

	quic_sm_set_next_ts(sm, ts + inc_ns);
}

static void
quic_sm_timer_start_cb(isc_quic_session_t *restrict session,
		       const uint32_t timeout_ms,
		       quic_test_session_manager_t *sm) {
	TRACE_CB(session);
	if (timeout_ms != 0) {
		warnconn(session, "timeout: %" PRIu32 "\n", timeout_ms);
	} else {
		warnconn(session, "immediate timeout\n", timeout_ms);
	}

	sm->timer_running = true;
	sm->timeout = isc_ngtcp2_make_duration(0, timeout_ms);
	sm->timer_should_fire_at = ts + isc_ngtcp2_make_duration(0, timeout_ms);
}

static void
quic_sm_timer_stop_cb(isc_quic_session_t *restrict session,
		      quic_test_session_manager_t *sm) {
	TRACE_CB(session);
	warnconn(session, "stop timer\n");

	sm->timer_running = false;
}

static bool
quic_sm_assoc_conn_cid_cb(isc_quic_session_t *restrict session,
			  isc_region_t *restrict cid_data, const bool source,
			  quic_test_session_manager_t *sm,
			  isc_quic_cid_t **restrict pcid);

static bool
quic_sm_gen_unique_cid_cb(isc_quic_session_t *restrict session,
			  const size_t cidlen, const bool source,
			  quic_test_session_manager_t *sm,
			  isc_quic_cid_t **restrict pcid) {
	TRACE_CB(session);

	if (source) {
		isc_quic_cid_map_gen_unique(sm->src_cids, session, isc_tid(),
					    cidlen, pcid);
		sm->managed_src_cids_count++;
	} else {
		isc_quic_cid_map_gen_unique(sm->dst_cids, session, isc_tid(),
					    cidlen, pcid);
		sm->managed_dst_cids_count++;
	}

	return true;
}

static bool
quic_sm_on_handshake_cb(isc_quic_session_t *session,
			quic_test_session_manager_t *sm) {
	isc_result_t result = ISC_R_FAILURE;

	TRACE_CB(session);

	sm->hs_completed = true;
	warnconn(session, "handshake completed\n");

	if (sm->manual) {
		return true;
	}

	for (size_t i = 0; i < MAX_STREAMS; i++) {
		int64_t client_stream_id = -1;
		const bool bidi = isc_random_uniform(2) == 1;

		size_t limit =
			bidi ? ngtcp2_conn_get_streams_bidi_left(session->conn)
			     : ngtcp2_conn_get_streams_uni_left(session->conn);

		if (limit == 0) {
			continue;
		}

		result = quic_sm_open_stream(sm, session, bidi,
					     &client_stream_id);
		assert_true(result == ISC_R_SUCCESS);

		quic_stream_data_t *stream =
			isc_quic_session_get_stream_user_data(session,
							      client_stream_id);
		isc_buffer_t *databuf = get_data_buf(stream);
		isc_region_t data = { 0 };
		isc_buffer_usedregion(databuf, &data);

		result = isc_quic_session_send_data(
			session, client_stream_id, &data, false,
			(isc_quic_send_cb_t)quic_sm_send_cb, databuf);
		assert_true(result == ISC_R_SUCCESS);

		stream->sends++;
		stream->sm->started_sends++;
	}

	return true;
}

static bool
quic_sm_on_on_remote_stream_open_cb(isc_quic_session_t *session,
				    const int64_t stream_id,
				    quic_test_session_manager_t *sm) {
	quic_stream_data_t *stream = NULL;

	TRACE_CB(session);

	sm->last_stream_id = stream_id;
	sm->opened_streams++;
	sm->total_opened_streams++;

	stream = isc_mem_get(mctx, sizeof(*stream));

	*stream = (quic_stream_data_t){
		.stream_id = stream_id,
		.local = false,
		.link = ISC_LINK_INITIALIZER,
		.sm = sm,
	};

	ISC_LIST_APPEND(sm->streams, stream, link);

	isc_quic_session_set_stream_user_data(session, stream_id, stream);
	warnconn(session, "on remote stream open %" PRId32 "\n", stream_id);

	if (sm->manual) {
		return true;
	}

	return true;
}

static bool
quic_sm_on_stream_close_cb(isc_quic_session_t *session,
			   const int64_t streamd_id, const bool app_error_set,
			   const uint64_t app_error_code,
			   quic_test_session_manager_t *sm,
			   quic_stream_data_t *stream_data) {
	UNUSED(app_error_set);
	UNUSED(app_error_code);
	UNUSED(stream_data);

	TRACE_CB(session);

	INSIST(isc_quic_session_get_stream_user_data(session, streamd_id) ==
	       stream_data);

	if (stream_data->send_buf != NULL) {
		isc_buffer_free(&stream_data->send_buf);
	}

	ISC_LIST_UNLINK(sm->streams, stream_data, link);
	isc_mem_put(mctx, stream_data, sizeof(quic_stream_data_t));
	sm->opened_streams--;

	warnconn(session,
		 "on stream close: %" PRId32 " (error code %" PRIu64
		 ", opened streams: %zu)\n",
		 streamd_id, app_error_code, sm->opened_streams);

	if (sm->manual) {
		return true;
	}

	return true;
}

static bool
quic_sm_on_recv_stream_data_cb(isc_quic_session_t *session,
			       const int64_t stream_id, const bool fin,
			       const uint64_t offset,
			       const isc_region_t *restrict data,
			       quic_test_session_manager_t *sm,
			       quic_stream_data_t *stream_data) {
	UNUSED(offset);
	UNUSED(data);
	UNUSED(stream_data);

	TRACE_CB(session);

	INSIST(isc_quic_session_get_stream_user_data(session, stream_id) ==
	       stream_data);
	INSIST(stream_data->sm == sm);

	warnconn(session,
		 "on data recv: (stream: %" PRId64 ", fin: %s, offset: %" PRIu64
		 ", size: %zu)\n",
		 stream_id, fin ? "true" : "false", offset, data->length);

	if (data != NULL && data->length > 0 && !sm->manual) {
		bool ret = verify_data_buf(&stream_data->bcounter_receive,
					   data->base, data->length);

		assert_true(ret);
	}

	sm->receives++;

	if (fin) {
		isc_quic_session_shutdown_stream(session, stream_id, true);
	}

	if (sm->manual) {
		return true;
	}

	return true;
}

static void
quic_sm_on_conn_close_cb(isc_quic_session_t *session,
			 const uint32_t closing_timeout_ms, const bool ver_neg,
			 quic_test_session_manager_t *sm) {
	TRACE_CB(session);

	if (ver_neg) {
		return;
	}

	sm->closed = true;
	sm->closing_timeout_ms = closing_timeout_ms;

	warnconn(session, "connection close\n");

	if (sm->manual) {
		return;
	}
}

static bool
quic_sm_assoc_conn_cid_cb(isc_quic_session_t *restrict session,
			  isc_region_t *restrict cid_data, const bool source,
			  quic_test_session_manager_t *sm,
			  isc_quic_cid_t **restrict pcid) {
	isc_quic_cid_t *new_cid = NULL;

	TRACE_CB(session);

	UNUSED(source);

	isc_quic_cid_create(mctx, cid_data, &new_cid);

	if (source) {
		isc_quic_cid_map_add(sm->src_cids, new_cid, session, isc_tid());
		sm->managed_src_cids_count++;
	} else {
		isc_quic_cid_map_add(sm->dst_cids, new_cid, session, isc_tid());
		sm->managed_dst_cids_count++;
	}

	*pcid = new_cid;
	return true;
}

static void
quic_sm_deassoc_conn_cid(isc_quic_session_t *restrict session,
			 const bool source, quic_test_session_manager_t *sm,
			 isc_quic_cid_t **restrict pcid) {
	isc_quic_cid_t *cid = NULL;

	TRACE_CB(session);

	cid = *pcid;

	if (source /*&& sm->src_cids != NULL*/) {
		/* printf("sm->managed_src_cids_count: %zd\n", */
		/*        sm->managed_src_cids_count); */
		isc_quic_cid_map_remove(sm->src_cids, cid);
		sm->managed_src_cids_count--;
	} else /*if (sm->dst_cids != NULL)*/ {
		/* printf("sm->managed_dst_cids_count: %zd\n", */
		/*        sm->managed_dst_cids_count); */
		isc_quic_cid_map_remove(sm->dst_cids, cid);
		sm->managed_dst_cids_count--;
	}

	isc_quic_cid_detach(pcid);
}

static void
quic_sm_send_cb(isc_quic_session_t *restrict session, const int64_t stream_id,
		isc_result_t result, void *cbarg, quic_stream_data_t *stream) {
	isc_buffer_t *databuf = (isc_buffer_t *)cbarg;
	isc_region_t data = { 0 };
	uint64_t sent = 0;

	REQUIRE(session != NULL);

	TRACE_CB(session);

	if (databuf != NULL) {
		sent = isc_buffer_usedlength(databuf);
		free_data_buf(stream, &databuf);
	}

	warnconn(session, "send (stream: %" PRId64 ", result: %s)\n", stream_id,
		 isc_result_totext(result));

	stream->sm->completed_sends++;

	if (result == ISC_R_SUCCESS) {
		stream->sm->successful_sends++;
		stream->sm->total_sent_bytes += sent;
	} else {
		warnconn(session, "result: %s\n", isc_result_totext(result));
		return;
	}

	if (stream->sm->manual) {
		return;
	}

	if (stream->sends >= MAX_SENDS) {
		result = isc_quic_session_shutdown_stream(session, stream_id,
							  false);
		assert_true(result == ISC_R_SUCCESS);
		return;
	}

	stream->sends++;
	stream->sm->started_sends++;

	databuf = get_data_buf(stream);
	isc_buffer_usedregion(databuf, &data);

	result = isc_quic_session_send_data(
		session, stream_id, &data, stream->sends == MAX_SENDS,
		(isc_quic_send_cb_t)quic_sm_send_cb, databuf);
	assert_true(result == ISC_R_SUCCESS);
}

static bool
quic_sm_on_new_regular_token_cb(isc_quic_session_t *restrict session,
				isc_region_t *restrict token_data,
				isc_sockaddr_t *restrict local,
				const isc_sockaddr_t *restrict peer,
				quic_test_session_manager_t *sm) {
	REQUIRE(session != NULL);
	REQUIRE(token_data != NULL);
	REQUIRE(local != NULL);
	REQUIRE(peer != NULL);
	REQUIRE(sm != NULL);
	ngtcp2_path_storage pathst = { 0 };

	TRACE_CB(session);

	warnconn(session, "new regular token (size: %zu)\n",
		 token_data->length);

	if (sm->manual) {
		return true;
	}

	isc_ngtcp2_path_storage_init(&pathst, local, peer);

	isc_result_t result = isc_ngtcp2_crypto_verify_regular_token(
		token_data->base, token_data->length, server_static_secret,
		sizeof(server_static_secret), pathst.path.local.addr,
		pathst.path.local.addrlen,
		ISC_QUIC_SESSION_REGULAR_TOKEN_VALIDITY_PERIOD, ts);

	assert_true(result == ISC_R_SUCCESS);

	isc_quic_token_cache_keep(sm->server_tokens, peer, token_data);

	return true;
}

static void
dump_packet_data(isc_quic_session_t *restrict session,
		 isc_quic_out_pkt_t *restrict out_pkt) {
	char local[ISC_SOCKADDR_FORMATSIZE], peer[ISC_SOCKADDR_FORMATSIZE];

	isc_sockaddr_format(&out_pkt->local, local, sizeof(local));
	isc_sockaddr_format(&out_pkt->peer, peer, sizeof(peer));
	warnconn(session, "outgoing packet: %zd bytes, from: %s, to %s\n",
		 out_pkt->pktsz, local, peer);

	if (isc_quic_session_is_server(session)) {
		assert_true(isc_sockaddr_equal(&out_pkt->local, &server_addr));
	} else {
		assert_true(isc_sockaddr_equal(&out_pkt->local, &client_addr) ||
			    isc_sockaddr_equal(&out_pkt->local,
					       &migrate_client_addr));
	}
}

static isc_result_t
quic_sm_connect(quic_test_session_manager_t *restrict sm,
		isc_quic_session_t *restrict session) {
	uint8_t buf[NGTCP2_MAX_UDP_PAYLOAD_SIZE] = { 0 };
	isc_quic_out_pkt_t out_pkt;

	REQUIRE(session != NULL);
	REQUIRE(sm != NULL);

	TRACE_CB(session);

	isc_quic_out_pkt_init(&out_pkt, buf, sizeof(buf));

	isc_result_t result = isc_quic_session_connect(session, &out_pkt);

	if (out_pkt.pktsz > 0) {
		isc_buffer_putuint16(sm->output, (uint16_t)out_pkt.pktsz);
		isc_buffer_putmem(sm->output, buf, out_pkt.pktsz);
		sm->total_written_bytes += out_pkt.pktsz;
		isc_quic_session_update_expiry_timer(session);
		dump_packet_data(session, &out_pkt);
	}

	return result;
}

static isc_result_t
quic_sm_shutdown(quic_test_session_manager_t *restrict sm,
		 isc_quic_session_t *restrict session) {
	uint8_t buf[NGTCP2_MAX_UDP_PAYLOAD_SIZE] = { 0 };
	isc_quic_out_pkt_t out_pkt;

	REQUIRE(session != NULL);
	REQUIRE(sm != NULL);

	isc_quic_out_pkt_init(&out_pkt, buf, sizeof(buf));

	isc_result_t result = isc_quic_session_shutdown(session, &out_pkt);

	if (out_pkt.pktsz > 0) {
		isc_buffer_putuint16(sm->output, (uint16_t)out_pkt.pktsz);
		isc_buffer_putmem(sm->output, buf, out_pkt.pktsz);
		isc_quic_session_update_expiry_timer(session);
		sm->total_written_bytes += out_pkt.pktsz;
		dump_packet_data(session, &out_pkt);
	}

	return result;
}

static isc_result_t
quic_sm_write_packet(quic_test_session_manager_t *restrict sm,
		     isc_quic_session_t *restrict session, bool *wrote_pkt) {
	uint8_t buf[NGTCP2_MAX_UDP_PAYLOAD_SIZE] = { 0 };
	isc_quic_out_pkt_t out_pkt;

	REQUIRE(session != NULL);
	REQUIRE(sm != NULL);
	REQUIRE(wrote_pkt != NULL && *wrote_pkt == false);

	isc_quic_out_pkt_init(&out_pkt, buf, sizeof(buf));

	isc_result_t result = isc_quic_session_write_pkt(session, &out_pkt);

	if (out_pkt.pktsz > 0) {
		isc_buffer_putuint16(sm->output, (uint16_t)out_pkt.pktsz);
		isc_buffer_putmem(sm->output, buf, out_pkt.pktsz);
		isc_quic_session_update_expiry_timer(session);
		sm->total_written_bytes += out_pkt.pktsz;
		*wrote_pkt = true;
		dump_packet_data(session, &out_pkt);
	}

	return result;
}

static isc_result_t
quic_sm_on_expiry_timer(quic_test_session_manager_t *restrict sm,
			isc_quic_session_t *restrict session, bool *wrote_pkt) {
	uint8_t buf[NGTCP2_MAX_UDP_PAYLOAD_SIZE] = { 0 };
	isc_quic_out_pkt_t out_pkt;

	REQUIRE(session != NULL);
	REQUIRE(sm != NULL);
	REQUIRE(wrote_pkt != NULL && *wrote_pkt == false);

	isc_quic_out_pkt_init(&out_pkt, buf, sizeof(buf));
	isc_result_t result = isc_quic_session_on_expiry_timer(session,
							       &out_pkt);

	if (out_pkt.pktsz > 0) {
		isc_buffer_putuint16(sm->output, (uint16_t)out_pkt.pktsz);
		isc_buffer_putmem(sm->output, buf, out_pkt.pktsz);
		isc_quic_session_update_expiry_timer(session);
		sm->total_written_bytes += out_pkt.pktsz;
		*wrote_pkt = true;
		dump_packet_data(session, &out_pkt);
	}

	return result;
}

static isc_result_t
quic_sm_read_packet(quic_test_session_manager_t *restrict sm,
		    isc_quic_session_t *restrict session, bool *wrote_pkt) {
	uint16_t pkt_len = 0;
	isc_region_t pkt = { 0 };
	uint32_t version = 0;
	bool is_long = false;
	isc_region_t scid = { 0 }, dcid = { 0 };

	uint8_t buf[NGTCP2_MAX_UDP_PAYLOAD_SIZE] = { 0 };
	isc_quic_out_pkt_t out_pkt;

	REQUIRE(sm != NULL);
	REQUIRE(session != NULL);
	REQUIRE(wrote_pkt != NULL && *wrote_pkt == false);

	if (isc_buffer_remaininglength(sm->input) == 0) {
		return ISC_R_SUCCESS;
	}

	pkt_len = isc_buffer_getuint16(sm->input);
	isc_buffer_remainingregion(sm->input, &pkt);

	INSIST(pkt_len <= pkt.length);
	pkt.length = pkt_len;

	warnconn(session, "incoming packet: %zu bytes\n", pkt_len);

	isc_result_t result = isc_ngtcp2_decode_pkt_header(
		&pkt,
		isc_ngtcp2_get_short_pkt_dcidlen(
			!isc_quic_session_is_server(session)),
		&is_long, &scid, &dcid, &version);

	isc_buffer_forward(sm->input, pkt_len);
	sm->total_read_bytes += pkt_len;

	if (result != ISC_R_SUCCESS) {
		isc_buffer_trycompact(sm->input);
		return result;
	}

	isc_quic_out_pkt_init(&out_pkt, buf, sizeof(buf));

	isc_quic_session_t *found_session = NULL;
	isc_tid_t found_tid = 0;
	uint8_t token_odcid_data[ISC_NGTCP2_MAX_POSSIBLE_CID_LENGTH];
	isc_buffer_t token_odcid_buf;
	isc_region_t token_odcid;
	bool token_verified = false;

	isc_buffer_init(&token_odcid_buf, token_odcid_data,
			sizeof(token_odcid_data));

	if (isc_quic_session_is_server(session)) {
		isc_region_t server_secret = { .base = server_static_secret,
					       .length = sizeof(
						       server_static_secret) };
		result = isc_quic_route_pkt(
			&pkt, sm->src_cids, &server_secret,
			server_proto_preference_list,
			server_proto_preference_list_len, &sm->local, &sm->peer,
			&dcid, &scid, version, true, false, INITIAL_TIMEOUT, ts,
			&found_session, &found_tid, &token_odcid_buf, &out_pkt);
	} else {
		result = isc_quic_route_pkt(
			&pkt, sm->src_cids, NULL, NULL, 0, &sm->local,
			&sm->peer, &dcid, &scid, version, false, false, 0, ts,
			&found_session, &found_tid, NULL, NULL);
	}

	if (result == ISC_R_SUCCESS) {
		INSIST(out_pkt.pktsz == 0);
		INSIST(found_session == session);
		isc_quic_session_detach(&found_session);
	} else {
		if (result == ISC_R_NOTFOUND && out_pkt.pktsz == 0 &&
		    isc_quic_session_is_server(session))
		{
			isc_buffer_usedregion(&token_odcid_buf, &token_odcid);
			token_verified = true;
		}
		result = ISC_R_SUCCESS;
	}

	if (out_pkt.pktsz == 0) {
		result = isc_quic_session_read_pkt(
			session, &sm->local, &sm->peer, version, &dcid, &scid,
			token_verified, &token_odcid, &pkt, &out_pkt);

		isc_buffer_trycompact(sm->input);
		if (result == ISC_R_SUCCESS) {
			isc_quic_session_update_expiry_timer(session);
		}
	}

	if (out_pkt.pktsz > 0) {
		isc_buffer_putuint16(sm->output, (uint16_t)out_pkt.pktsz);
		isc_buffer_putmem(sm->output, buf, out_pkt.pktsz);
		isc_quic_session_update_expiry_timer(session);
		sm->total_written_bytes += out_pkt.pktsz;
		*wrote_pkt = true;
		dump_packet_data(session, &out_pkt);
	}

	return result;
}

static isc_result_t
quic_sm_update_client_address(quic_test_session_manager_t *restrict client_mgr,
			      isc_quic_session_t *restrict client_sess,
			      const isc_sockaddr_t *restrict client_address) {
	if (isc_sockaddr_equal(client_address, &client_mgr->local)) {
		isc_sockaddr_t local = isc_quic_session_localaddr(client_sess);
		INSIST(isc_sockaddr_equal(client_address,
					  &client_mgr->peer_sm->peer));
		INSIST(isc_sockaddr_equal(&local, client_address));
		return ISC_R_SUCCESS;
	}

	client_mgr->local = *client_address;
	client_mgr->peer_sm->peer = *client_address;

	return isc_quic_session_update_localaddr(client_sess, client_address);
}

static isc_result_t
quic_sm_change_client_address(quic_test_session_manager_t *restrict client_mgr,
			      isc_quic_session_t *restrict client_sess) {
	isc_sockaddr_t *addr = NULL;

	if (isc_sockaddr_equal(&client_addr, &client_mgr->local)) {
		addr = &migrate_client_addr;
	} else {
		addr = &client_addr;
	}

	return quic_sm_update_client_address(client_mgr, client_sess, addr);
}

static inline bool
quic_sm_try_consume_pkt(quic_test_session_manager_t *restrict sm) {
	uint16_t pkt_len = 0;
	isc_region_t pkt = { 0 };

	REQUIRE(sm != NULL);

	/* 3% of packets are getting lost */
	if (!(isc_random_uniform(100) < 3)) {
		return false;
	}

	if (isc_buffer_remaininglength(sm->input) == 0) {
		return false;
	}

	pkt_len = isc_buffer_getuint16(sm->input);
	isc_buffer_remainingregion(sm->input, &pkt);

	INSIST(pkt_len <= pkt.length);
	pkt.length = pkt_len;

	isc_buffer_forward(sm->input, pkt_len);
	isc_buffer_trycompact(sm->input);

	return true;
}

static isc_result_t
quic_sm_open_stream(quic_test_session_manager_t *restrict sm,
		    isc_quic_session_t *session, const bool bidi,
		    int64_t *pstream_id) {
	quic_stream_data_t *stream = NULL;

	isc_result_t result = isc_quic_session_open_stream(session, bidi, sm,
							   pstream_id);

	if (result != ISC_R_SUCCESS) {
		return result;
	}

	sm->opened_streams++;
	sm->last_stream_id = *pstream_id;

	stream = isc_mem_get(mctx, sizeof(*stream));

	*stream = (quic_stream_data_t){
		.stream_id = *pstream_id,
		.local = true,
		.link = ISC_LINK_INITIALIZER,
		.sm = sm,
	};

	ISC_LIST_APPEND(sm->streams, stream, link);

	isc_quic_session_set_stream_user_data(session, *pstream_id, stream);
	warnconn(session, "on local stream open %" PRId32 "\n", *pstream_id);

	return result;
}

static isc_quic_session_interface_t callbacks = {
	.get_current_ts =
		(isc_quic_get_current_ts_cb_t)quic_sm_get_current_ts_cb,
	.expiry_timer_start =
		(isc_quic_expiry_timer_start_cb_t)quic_sm_timer_start_cb,
	.expiry_timer_stop =
		(isc_quic_expiry_timer_stop_cb_t)quic_sm_timer_stop_cb,

	.gen_unique_cid =
		(isc_quic_gen_unique_cid_cb_t)quic_sm_gen_unique_cid_cb,
	.assoc_conn_cid =
		(isc_quic_assoc_conn_cid_cb_t)quic_sm_assoc_conn_cid_cb,
	.deassoc_conn_cid =
		(isc_quic_deassoc_conn_cid_cb_t)quic_sm_deassoc_conn_cid,

	.on_handshake = (isc_quic_on_handshake_cb_t)quic_sm_on_handshake_cb,
	.on_new_regular_token = (isc_quic_on_new_regular_token_cb_t)
		quic_sm_on_new_regular_token_cb,
	.on_remote_stream_open = (isc_quic_on_remote_stream_open_cb_t)
		quic_sm_on_on_remote_stream_open_cb,
	.on_stream_close =
		(isc_quic_on_stream_close_cb_t)quic_sm_on_stream_close_cb,
	.on_recv_stream_data = (isc_quic_on_recv_stream_data_cb_t)
		quic_sm_on_recv_stream_data_cb,
	.on_conn_close = (isc_quic_on_conn_close_cb_t)quic_sm_on_conn_close_cb
};

static isc_tlsctx_t *
create_quic_tls_context(const bool is_server,
			const isc_tls_quic_interface_t *iface) {
	isc_tlsctx_t *tlsctx = NULL;
	isc_result_t result;

	if (is_server) {
		result = isc_tlsctx_createserver(NULL, NULL, &tlsctx);
	} else {
		result = isc_tlsctx_createclient(&tlsctx);
	}

	if (result != ISC_R_SUCCESS) {
		return NULL;
	}

	isc_tlsctx_set_random_session_id_context(tlsctx);
	isc_tlsctx_quic_configure(tlsctx, iface);

	return tlsctx;
}

static int
quic_session_testset_setup(void **state) {
	int ret;
	struct in6_addr in6;

	UNUSED(state);

	isc_tls_quic_crypto_initialize();

	isc_mem_create("testctx", &mctx);

	server_tlsctx = default_server_tlsctx;
	client_tlsctx = default_client_tlsctx;

	isc_sockaddr_fromin6(&server_addr, &in6addr_loopback, TEST_SERVER_PORT);

	isc_sockaddr_fromin6(&client_addr, &in6addr_loopback, TEST_CLIENT_PORT);

	ret = inet_pton(AF_INET6, "2a03:dead:beef:34b5:7a18:f3c7:57dc:9ee1",
			&in6);
	if (ret != 1) {
		return -1;
	}
	isc_sockaddr_fromin6(&migrate_client_addr, &in6, 1);

	isc_random_buf((void *)server_static_secret,
		       sizeof(server_static_secret));
	isc_random_buf((void *)client_static_secret,
		       sizeof(client_static_secret));

	server_proto_preference_list = NULL;
	server_proto_preference_list_len = 0;
	isc_ngtcp2_get_default_quic_versions(&server_proto_preference_list,
					     &server_proto_preference_list_len);

	client_proto_preference_list = NULL;
	client_proto_preference_list_len = 0;
	isc_ngtcp2_get_default_quic_versions(&client_proto_preference_list,
					     &client_proto_preference_list_len);

	ts = isc_time_monotonic();
	ts_set = true;

	return 0;
}

static int
quic_session_testset_teardown(void **state) {
	UNUSED(state);

	isc_mem_detach(&mctx);

	isc_tls_quic_crypto_shutdown();

	return 0;
}

static int
quic_session_test_setup(void **state) {
	isc_region_t secret;
	UNUSED(state);

	default_server_tlsctx = create_quic_tls_context(
		true, isc_tls_get_default_quic_interface());

	if (default_server_tlsctx == NULL) {
		return -1;
	}

	default_client_tlsctx = create_quic_tls_context(
		false, isc_tls_get_default_quic_interface());

	if (default_client_tlsctx == NULL) {
		return -1;
	}

	isc_tlsctx_client_session_cache_create(
		mctx, default_client_tlsctx,
		ISC_TLSCTX_CLIENT_SESSION_CACHE_DEFAULT_SIZE,
		&client_tlsctx_sess_cache);

	quic_sm_init(&server_sm, &server_addr, &client_addr, &client_sm);

	secret.base = server_static_secret;
	secret.length = sizeof(server_static_secret);
	isc_quic_session_create(
		mctx, default_server_tlsctx, NULL, NULL, &callbacks, &server_sm,
		&server_addr, &client_addr, INITIAL_TIMEOUT, INITIAL_TIMEOUT,
		UINT16_MAX, UINT16_MAX, 0, server_proto_preference_list,
		server_proto_preference_list_len, &secret, true, NULL,
		&server_session);

	quic_sm_init(&client_sm, &client_addr, &server_addr, &server_sm);

	secret.base = client_static_secret;
	secret.length = sizeof(client_static_secret);
	isc_quic_session_create(
		mctx, default_client_tlsctx, "test.example.com",
		client_tlsctx_sess_cache, &callbacks, &client_sm, &client_addr,
		&server_addr, INITIAL_TIMEOUT, INITIAL_TIMEOUT, UINT16_MAX,
		UINT16_MAX, client_chosen_version, client_proto_preference_list,
		client_proto_preference_list_len, &secret, false, NULL,
		&client_session);

	isc_quic_token_cache_create(mctx, 300, &client_sm.server_tokens);

	client_sm.input = server_sm.output;
	server_sm.input = client_sm.output;

	return 0;
}

static int
quic_session_test_setup_server_v2_only(void **state) {
	server_proto_preference_list = proto_preference_list_v2_only;
	server_proto_preference_list_len = proto_preference_list_v2_only_len;

	return quic_session_test_setup(state);
}

static int
quic_session_test_setup_server_incompat_negotiation(void **state) {
	client_chosen_version = 0;
	client_proto_preference_list = proto_preference_list_reversed;
	client_proto_preference_list_len = proto_preference_list_reversed_len;

	return quic_session_test_setup(state);
}

static int
quic_session_test_setup_server_no_compatible(void **state) {
	client_chosen_version = 0;
	client_proto_preference_list = proto_preference_list_v1_only;
	client_proto_preference_list_len = proto_preference_list_v1_only_len;

	server_proto_preference_list = proto_preference_list_v2_only;
	server_proto_preference_list_len = proto_preference_list_v2_only_len;

	return quic_session_test_setup(state);
}

static int
quic_session_test_teardown(void **state) {
	UNUSED(state);

	if (client_session != NULL) {
		isc_quic_session_finish(client_session);
		assert_true(client_sm.managed_src_cids_count == 0);
		assert_true(client_sm.managed_dst_cids_count == 0);
		isc_quic_session_detach(&client_session);
	}

	quic_sm_uninit(&client_sm);

	if (server_session != NULL) {
		isc_quic_session_finish(server_session);
		assert_true(server_sm.managed_src_cids_count == 0);
		assert_true(server_sm.managed_dst_cids_count == 0);
		isc_quic_session_detach(&server_session);
	}

	quic_sm_uninit(&server_sm);

	isc_tlsctx_free(&default_client_tlsctx);
	isc_tlsctx_free(&default_server_tlsctx);

	isc_tlsctx_client_session_cache_detach(&client_tlsctx_sess_cache);

	server_proto_preference_list = NULL;
	server_proto_preference_list_len = 0;
	isc_ngtcp2_get_default_quic_versions(&server_proto_preference_list,
					     &server_proto_preference_list_len);

	client_proto_preference_list = NULL;
	client_proto_preference_list_len = 0;
	isc_ngtcp2_get_default_quic_versions(&client_proto_preference_list,
					     &client_proto_preference_list_len);

	client_chosen_version = NGTCP2_PROTO_VER_V1;

	return 0;
}

static bool
quic_sm_try_timer(quic_test_session_manager_t *restrict sm,
		  isc_quic_session_t *restrict session,
		  bool *restrict wrote_pkt) {
	isc_result_t result;

	if (sm->timer_running) {
		if (ts >= sm->timer_should_fire_at) {
			if (sm->timeout == 0) {
				sm->timer_running = false;
			}
			warnconn(session, "the expiry timer has fired\n");
			result = quic_sm_on_expiry_timer(sm, session,
							 wrote_pkt);
			if (result != ISC_R_SUCCESS &&
			    result != ISC_R_SHUTTINGDOWN &&
			    result != ISC_R_CANCELED && !wrote_pkt)
			{
				warnconn(session,
					 "I/O: expiry timer has "
					 "failed: %s\n",
					 isc_result_totext(result));
				return false;
			}
			if (*wrote_pkt) {
				warnconn(session, "wrote data on "
						  "expiry timer\n");
			}
		} else {
			quic_sm_inc_ts(sm, ISC_MAX(15 * NGTCP2_MILLISECONDS,
						   sm->timeout / 800));
		}
	}

	return true;
}

static inline bool
quic_path_is_migrating(quic_test_session_manager_t *restrict sm,
		       isc_quic_session_t *restrict sess) {
	if (!isc_quic_session_is_server(sess)) {
		return isc_quic_session_path_migrating(sess);
	}

	/*
	 * For a server it is an approximation, but seems to work well for the
	 * test purposes.
	 */
	if (sm->closed) {
		return false;
	}

	isc_sockaddr_t peer = isc_quic_session_peeraddr(sess);
	return !isc_sockaddr_equal(&peer, &sm->peer);
}

static bool
do_io(quic_test_session_manager_t *restrict sm,
      isc_quic_session_t *restrict session) {
	do {
		bool wrote_pkt = false;
		isc_result_t result;
		bool ret;
		errno = 0;

		if (sm->hs_completed && !quic_path_is_migrating(sm, session)) {
			quic_sm_try_consume_pkt(sm);
		}

		result = quic_sm_read_packet(sm, session, &wrote_pkt);
		if (result != ISC_R_SUCCESS && result != ISC_R_SHUTTINGDOWN) {
			warnconn(session, "I/O: read packet: %s\n",
				 isc_result_totext(result));
			return false;
		}

		if (wrote_pkt) {
			break;
		}

		wrote_pkt = false;
		if (!isc_quic_session_is_server(session) &&
		    !sm->connection_started)
		{
			sm->connection_started = true;
			result = quic_sm_connect(sm, session);
			wrote_pkt = true;
		} else {
			result = quic_sm_write_packet(sm, session, &wrote_pkt);
		}
		if (result != ISC_R_SUCCESS && result != ISC_R_SHUTTINGDOWN) {
			warnconn(session, "I/O: write packet: %s\n",
				 isc_result_totext(result));
			return false;
		}

		if (wrote_pkt) {
			break;
		}

		wrote_pkt = false;
		ret = quic_sm_try_timer(sm, session, &wrote_pkt);
		if (!ret) {
			return false;
		}

		if (wrote_pkt) {
			break;
		}
	} while (isc_buffer_remaininglength(sm->input) > 0);

	return true;
}

static inline size_t
get_sends_before_address_update(size_t total_sends) {
	size_t sends = (total_sends / 40);
	const size_t min_sends = 300;

	if (sends < min_sends) {
		sends = min_sends;
	}

	return sends;
}

static bool
client_server_loop(quic_test_session_manager_t *restrict client_mgr,
		   isc_quic_session_t *restrict client_sess,
		   quic_test_session_manager_t *restrict server_mgr,
		   isc_quic_session_t *restrict server_sess) {
	uint64_t i = 0;
	bool ret = true;
	isc_result_t result = ISC_R_SUCCESS;

	(void)isc_quic_token_cache_reuse(client_mgr->server_tokens,
					 &server_addr, client_sess);

	do {
		rcu_quiescent_state();
		if (!do_io(client_mgr, client_sess)) {
			ret = false;
			goto exit;
		}

		if (client_mgr->successful_sends == (MAX_SENDS * MAX_STREAMS) &&
		    server_mgr->successful_sends == (MAX_SENDS * MAX_STREAMS) &&
		    server_mgr->opened_streams == 0 &&
		    client_mgr->opened_streams == 0)
		{
			(void)quic_sm_shutdown(client_mgr, client_sess);
		} else if (client_mgr->hs_completed &&
			   server_mgr->hs_completed && !client_mgr->closed &&
			   !server_mgr->closed)
		{
			const size_t total_sends = MAX_SENDS * MAX_STREAMS;
			const size_t sends_before_update =
				get_sends_before_address_update(total_sends);

			/*
			 * Let's avoid migrations:
			 * 1. When there were not enough sends between
			 * migrations;
			 * 2. When close towards the end of the session;
			 * 3. When a migration is in progress.
			 */
			if ((client_mgr->completed_sends -
			     client_mgr->last_update_completed_sends) >=
				    sends_before_update &&
			    (total_sends - client_mgr->completed_sends) >
				    (total_sends / 10) &&
			    !quic_path_is_migrating(client_mgr, client_sess) &&
			    !quic_path_is_migrating(server_mgr, server_sess) &&
			    !server_mgr->closed && !client_mgr->closed)
			{
				client_mgr->last_update_completed_sends =
					client_mgr->completed_sends;
				/* puts("migration"); */
				/*
				 * to not mess with congestion control
				 */
				quic_sm_inc_ts(client_mgr, 0);
				result = quic_sm_change_client_address(
					client_mgr, client_sess);
				if (result != ISC_R_SUCCESS &&
				    result != ISC_R_UNEXPECTED)
				{
					ret = false;
					goto exit;
				}
			}
		}

		if (!do_io(server_mgr, server_sess)) {
			ret = false;
			goto exit;
		}

		i++;
	} while (i < MAX_ITERATIONS &&
		 (isc_buffer_remaininglength(client_mgr->output) ||
		  isc_buffer_remaininglength(server_mgr->output) ||
		  client_mgr->timer_running || server_mgr->timer_running));

	if (i >= MAX_ITERATIONS) {
		ret = false;
	}

	INSIST((client_mgr->started_sends - client_mgr->completed_sends) == 0);
	INSIST((server_mgr->started_sends - server_mgr->completed_sends) == 0);
	INSIST(server_mgr->opened_streams == 0);
	INSIST(client_mgr->opened_streams == 0);

exit:
	rcu_quiescent_state();
	return ret;
}

static inline void
verify_results(void) {
	/* fprintf(stderr, "client started sends: %zu\n",
	 * client_sm.started_sends); */
	/* fprintf(stderr, "server started sends: %zu\n",
	 * server_sm.started_sends); */
	/* fprintf(stderr, "client successful sends: %zu\n", */
	/* 	client_sm.successful_sends); */
	/* fprintf(stderr, "server successful sends: %zu\n", */
	/* 	server_sm.successful_sends); */
	/* fprintf(stderr, "client completed sends: %zu\n", */
	/* 	client_sm.completed_sends); */
	/* fprintf(stderr, "server completed sends: %zu\n", */
	/* 	server_sm.completed_sends); */
	/* fprintf(stderr, "client total opened streams: %zu\n", */
	/* 	client_sm.total_opened_streams); */
	/* fprintf(stderr, "server total opened streams: %zu\n", */
	/* 	server_sm.total_opened_streams); */
	/* fprintf(stderr, "client written: %zu\n",
	 * client_sm.total_written_bytes); */
	/* fprintf(stderr, "client read: %zu\n", client_sm.total_read_bytes); */
	/* fprintf(stderr, "server written: %zu\n",
	 * server_sm.total_written_bytes); */
	/* fprintf(stderr, "server read: %zu\n", server_sm.total_read_bytes); */

	assert_true(client_sm.hs_completed);
	assert_true(server_sm.hs_completed);
	assert_true(client_sm.total_opened_streams == MAX_STREAMS);
	assert_true(server_sm.total_opened_streams == MAX_STREAMS);
	assert_true(client_sm.completed_sends == MAX_SENDS * MAX_STREAMS);
	assert_true(server_sm.completed_sends == MAX_SENDS * MAX_STREAMS);
	assert_true(client_sm.successful_sends == MAX_SENDS * MAX_STREAMS);
	assert_true(server_sm.successful_sends == MAX_SENDS * MAX_STREAMS);
	/* some packets are "lost" on purpose */
	assert_true(server_sm.total_written_bytes >=
		    client_sm.total_read_bytes);
	assert_true(client_sm.total_written_bytes >=
		    server_sm.total_read_bytes);
}

ISC_RUN_TEST_IMPL(quic_session_conn_test) {
	bool ret = client_server_loop(&client_sm, client_session, &server_sm,
				      server_session);
	assert_true(ret);
	verify_results();
}

ISC_RUN_TEST_IMPL(quic_session_conn_test_regular_token) {
	uint8_t token[ISC_NGTCP2_CRYPTO_MAX_REGULAR_TOKEN_LEN];
	const ngtcp2_ssize toklen = isc_ngtcp2_crypto_generate_regular_token(
		token, sizeof(token), server_static_secret,
		sizeof(server_static_secret), client_session->path->remote.addr,
		client_session->path->remote.addrlen, ts);
	assert_true(toklen > 0);

	isc_region_t token_region = { .base = token, .length = toklen };

	isc_quic_token_cache_keep(client_sm.server_tokens, &server_addr,
				  &token_region);

	bool ret = client_server_loop(&client_sm, client_session, &server_sm,
				      server_session);
	assert_true(ret);
	verify_results();
}

ISC_RUN_TEST_IMPL(quic_session_conn_test_outdated_regular_token) {
	uint8_t token[ISC_NGTCP2_CRYPTO_MAX_REGULAR_TOKEN_LEN];
	const ngtcp2_ssize toklen = isc_ngtcp2_crypto_generate_regular_token(
		token, sizeof(token), server_static_secret,
		sizeof(server_static_secret), client_session->path->remote.addr,
		client_session->path->remote.addrlen, ts);
	assert_true(toklen > 0);

	isc_region_t token_region = { .base = token, .length = toklen };

	quic_sm_inc_ts(&server_sm,
		       ISC_QUIC_SESSION_REGULAR_TOKEN_VALIDITY_PERIOD * 2);

	isc_result_t result = isc_ngtcp2_crypto_verify_regular_token(
		token, toklen, server_static_secret,
		sizeof(server_static_secret), client_session->path->remote.addr,
		client_session->path->remote.addrlen,
		ISC_QUIC_SESSION_REGULAR_TOKEN_VALIDITY_PERIOD, ts);

	assert_false(result == ISC_R_SUCCESS);

	isc_quic_token_cache_keep(client_sm.server_tokens, &server_addr,
				  &token_region);

	bool ret = client_server_loop(&client_sm, client_session, &server_sm,
				      server_session);
	assert_true(ret);
	verify_results();
}

ISC_RUN_TEST_IMPL(quic_session_conn_version_neg_test) {
	bool ret = client_server_loop(&client_sm, client_session, &server_sm,
				      server_session);
	assert_true(ret);
	verify_results();
}

ISC_RUN_TEST_IMPL(quic_session_conn_incompatible_version_neg_test) {
	bool ret = client_server_loop(&client_sm, client_session, &server_sm,
				      server_session);
	assert_true(ret);
	verify_results();
}

ISC_RUN_TEST_IMPL(quic_session_conn_no_compatible_test) {
	bool ret = client_server_loop(&client_sm, client_session, &server_sm,
				      server_session);
	assert_false(ret);
}

ISC_TEST_LIST_START
ISC_TEST_ENTRY_CUSTOM(quic_session_conn_test, quic_session_test_setup,
		      quic_session_test_teardown)
ISC_TEST_ENTRY_CUSTOM(quic_session_conn_test_regular_token,
		      quic_session_test_setup, quic_session_test_teardown)
ISC_TEST_ENTRY_CUSTOM(quic_session_conn_test_outdated_regular_token,
		      quic_session_test_setup, quic_session_test_teardown)
ISC_TEST_ENTRY_CUSTOM(quic_session_conn_version_neg_test,
		      quic_session_test_setup_server_v2_only,
		      quic_session_test_teardown)
ISC_TEST_ENTRY_CUSTOM(quic_session_conn_incompatible_version_neg_test,
		      quic_session_test_setup_server_incompat_negotiation,
		      quic_session_test_teardown)
ISC_TEST_ENTRY_CUSTOM(quic_session_conn_no_compatible_test,
		      quic_session_test_setup_server_no_compatible,
		      quic_session_test_teardown)
ISC_TEST_LIST_END

ISC_TEST_MAIN_CUSTOM(quic_session_testset_setup, quic_session_testset_teardown);
