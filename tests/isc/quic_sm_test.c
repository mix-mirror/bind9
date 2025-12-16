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

#define UNIT_TESTING
#include <cmocka.h>

#include <isc/buffer.h>
#include <isc/lib.h>
#include <isc/loop.h>
#include <isc/mem.h>
#include <isc/quic.h>
#include <isc/timer.h>
#include <isc/tls.h>

#include "netmgr_common.h"

#include <tests/isc.h>

#define MAX_TOKEN_CACHE_SIZE (500)

#define MAX_STREAMS   (50)
#define MAX_SENDS     (25)
#define MAX_SEND_SIZE (4096)

static struct call_rcu_data *thread_call_rcu_data = NULL;

static isc_mem_t *mctx = NULL;

static const uint32_t proto_preference_list[] = { NGTCP2_PROTO_VER_V1,
						  NGTCP2_PROTO_VER_V2 };

static const size_t proto_preference_list_len =
	(sizeof(proto_preference_list) / sizeof(proto_preference_list[0]));

static isc_tlsctx_t *default_server_tlsctx = NULL;
static isc_tlsctx_t *default_client_tlsctx = NULL;
static isc_quic_sm_t *client_quic_sm = NULL;
static isc_quic_sm_t *server_quic_sm = NULL;

static atomic_int_fast64_t connect_attempts = 0;
static atomic_int_fast64_t conns_accepted = 0;
static atomic_int_fast64_t server_handshakes = 0;
static atomic_int_fast64_t client_handshakes = 0;
static atomic_int_fast64_t total_opened_streams = 0;
static atomic_int_fast64_t total_closed_streams = 0;
static atomic_int_fast64_t total_connections = 0;

typedef struct quic_session_user_data {
	size_t closed_streams;
	isc_nmhandle_t *handle;
	isc_quic_sm_t *mgr;
} quic_session_user_data_t;

typedef struct quic_io_req {
	isc_quic_session_t *session;
	isc_buffer_t *buf;
	isc_nmhandle_t *handle;
	isc_quic_sm_t *mgr;
} quic_io_req_t;

typedef struct udp_quic_stream_data {
	int64_t stream_id;
	isc_quic_sm_t *mgr;
	isc_mem_t *mctx;
	bool local;
	size_t sends;
	uint8_t bcounter_receive;
	uint8_t bcounter_send;
	isc_buffer_t *send_buf;

	size_t started_sends;
	size_t completed_sends;
	size_t successful_sends;
	size_t receives;
	uint64_t total_sent_bytes;
} udp_quic_stream_data_t;

static void
udp_quic_read_cb(isc_nmhandle_t *handle, isc_result_t eresult,
		 isc_region_t *pkt, void *cbarg);

static quic_session_user_data_t *
alloc_session_user_data(isc_nmhandle_t *handle, isc_quic_sm_t *mgr) {
	quic_session_user_data_t *data = isc_mem_cget(mctx, 1, sizeof(*data));
	isc_nmhandle_attach(handle, &data->handle);
	isc_quic_sm_attach(mgr, &data->mgr);
	return data;
}

static void
free_session_user_data(quic_session_user_data_t *data) {
	isc_nmhandle_detach(&data->handle);
	isc_quic_sm_detach(&data->mgr);
}

static quic_io_req_t *
alloc_quic_send_req_region(const isc_region_t *pkt, isc_nmhandle_t *handle,
			   isc_quic_session_t *session,
			   isc_region_t *out_region) {
	quic_io_req_t *req = isc_mem_cget(mctx, 1, sizeof(*req));

	if (session != NULL) {
		isc_quic_session_attach(session, &req->session);
	}

	isc_buffer_allocate(mctx, &req->buf, pkt->length);
	isc_buffer_putmem(req->buf, pkt->base, pkt->length);
	isc_nmhandle_attach(handle, &req->handle);
	isc_buffer_usedregion(req->buf, out_region);

	return req;
}

static quic_io_req_t *
alloc_quic_send_req(const isc_quic_out_pkt_t *out_pkt, isc_nmhandle_t *handle,
		    isc_quic_session_t *session, isc_region_t *out_region) {
	quic_io_req_t *req = NULL;
	isc_region_t out_pkt_data = { 0 };

	out_pkt_data = out_pkt->pktbuf;
	out_pkt_data.length = out_pkt->pktsz;

	req = alloc_quic_send_req_region(&out_pkt_data, handle, session,
					 out_region);

	return req;
}

static quic_io_req_t *
alloc_quic_reroute_req(isc_region_t *pkt, isc_nmhandle_t *handle,
		       isc_quic_sm_t *mgr, isc_quic_session_t *session) {
	quic_io_req_t *req = isc_mem_cget(mctx, 1, sizeof(*req));

	if (session != NULL) {
		isc_quic_session_attach(session, &req->session);
	}

	isc_buffer_allocate(mctx, &req->buf, pkt->length);
	isc_buffer_putmem(req->buf, pkt->base, pkt->length);
	isc_nmhandle_attach(handle, &req->handle);
	isc_quic_sm_attach(mgr, &req->mgr);

	return req;
}

static void
free_quic_io_req(quic_io_req_t *req) {
	isc_nmhandle_detach(&req->handle);
	isc_buffer_free(&req->buf);
	if (req->session != NULL) {
		isc_quic_session_detach(&req->session);
	}
	if (req->mgr != NULL) {
		isc_quic_sm_detach(&req->mgr);
	}
	isc_mem_put(mctx, req, sizeof(*req));
}

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
get_data_buf(udp_quic_stream_data_t *stream_data) {
	isc_buffer_t *databuf = NULL;
	const size_t datalen = 1 + isc_random_uniform(MAX_SEND_SIZE);
	isc_region_t data = { 0 };

	if (stream_data->send_buf != NULL) {
		databuf = stream_data->send_buf;
		stream_data->send_buf = NULL;
		isc_buffer_clear(databuf);
		isc_buffer_reserve(databuf, datalen);
	} else {
		isc_buffer_allocate(mctx, &databuf, datalen);
	}

	isc_buffer_add(databuf, datalen);
	isc_buffer_usedregion(databuf, &data);

	fill_data_buf(&stream_data->bcounter_send, data.base, data.length);

	return databuf;
}

static inline void
free_data_buf(udp_quic_stream_data_t *stream_data, isc_buffer_t **pdatabuf) {
	if (stream_data->send_buf == NULL) {
		stream_data->send_buf = *pdatabuf;
	} else {
		isc_buffer_free(pdatabuf);
	}
}

static udp_quic_stream_data_t *
udp_quic_stream_data_alloc(isc_quic_sm_t *mgr, const bool local,
			   const int64_t stream_id) {
	udp_quic_stream_data_t *stream_data = isc_mem_get(mctx,
							  sizeof(*stream_data));

	*stream_data = (udp_quic_stream_data_t){
		.local = local,
		.stream_id = stream_id,
	};

	isc_mem_attach(mctx, &stream_data->mctx);
	isc_quic_sm_attach(mgr, &stream_data->mgr);

	return stream_data;
}

static void
udp_quic_stream_data_free(udp_quic_stream_data_t *stream_data) {
	isc_quic_sm_detach(&stream_data->mgr);
	if (stream_data->send_buf != NULL) {
		isc_buffer_free(&stream_data->send_buf);
	}
	isc_mem_putanddetach(&stream_data->mctx, stream_data,
			     sizeof(*stream_data));
}

static void
udp_quic_send_cb(isc_nmhandle_t *handle, isc_result_t eresult, void *cbarg);

static size_t
quic_send_pending(isc_nmhandle_t *handle, isc_quic_session_t *session) {
	uint8_t out_pkt_buf[NGTCP2_MAX_UDP_PAYLOAD_SIZE];
	isc_quic_out_pkt_t out_pkt;

	isc_quic_out_pkt_init(&out_pkt, out_pkt_buf, sizeof(out_pkt_buf));

	(void)isc_quic_session_write_pkt(session, &out_pkt);

	if (out_pkt.pktsz != 0) {
		isc_region_t out_pkt_data;
		quic_io_req_t *new_req = alloc_quic_send_req(
			&out_pkt, handle, session, &out_pkt_data);
		isc_nm_send(handle, &out_pkt_data, udp_quic_send_cb, new_req);
		return out_pkt.pktsz;
	}

	return 0;
}

/* static void */
/* quic_send_pending_async_cb(isc_quic_session_t *session) { */
/* 	quic_session_user_data_t *session_data = */
/* 		isc_quic_session_get_user_data(session); */
/* 	quic_send_pending(session_data->handle, session); */
/* 	isc_quic_session_detach(&session); */
/* } */

/* static void */
/* quic_send_pending_async(isc_quic_session_t *session) { */
/* 	isc_quic_session_t *tmpsess = NULL; */
/* 	isc_quic_session_attach(session, &tmpsess); */
/* 	isc_async_run(isc_loop(), (isc_job_cb)quic_send_pending_async_cb, */
/* 		      session); */
/* } */

static void
udp_quic_send_cb(isc_nmhandle_t *handle, isc_result_t eresult, void *cbarg) {
	quic_io_req_t *req = (quic_io_req_t *)cbarg;

	assert_non_null(handle);
	assert_true(handle == req->handle);

	F();

	switch (eresult) {
	case ISC_R_NOCONN: {
		/* The kernel buffer is full. Retry.*/
		isc_region_t data = { 0 };
		isc_buffer_usedregion(req->buf, &data);
		isc_nm_send(handle, &data, udp_quic_send_cb, req);
		return;
	};
	case ISC_R_CANCELED:
	case ISC_R_CONNECTIONRESET:
	case ISC_R_EOF:
	case ISC_R_SHUTTINGDOWN:
		isc_nm_cancelread(handle);
		break;
	case ISC_R_SUCCESS:
		if (req->session) {
			(void)quic_send_pending(handle, req->session);
			isc_quic_session_update_expiry_timer(req->session);
		}
		break;
	default:
		fprintf(stderr, "%s(%p, %s, %p)\n", __func__, handle,
			isc_result_totext(eresult), cbarg);
		assert_int_equal(eresult, ISC_R_SUCCESS);
	}

	free_quic_io_req(req);
}

static void
udp_quic_send_shutdown_cb(isc_nmhandle_t *handle, isc_result_t eresult,
			  void *cbarg) {
	quic_io_req_t *req = (quic_io_req_t *)cbarg;
	if (req->session != NULL) {
		isc_quic_session_detach(&req->session);
	}
	udp_quic_send_cb(handle, eresult, cbarg);
	isc_loopmgr_shutdown();
}

static void
process_incoming_packet(isc_nmhandle_t *handle, isc_region_t *pkt,
			isc_quic_sm_t *mgr);

static void
process_rerouted_packet(quic_io_req_t *req) {
	isc_region_t pkt;

	isc_buffer_usedregion(req->buf, &pkt);
	process_incoming_packet(req->handle, &pkt, req->mgr);
	free_quic_io_req(req);
}

static void
process_incoming_packet(isc_nmhandle_t *handle, isc_region_t *pkt,
			isc_quic_sm_t *mgr) {
	isc_sockaddr_t local = isc_nmhandle_localaddr(handle),
		       peer = isc_nmhandle_peeraddr(handle);
	isc_quic_session_t *session = NULL;
	isc_tid_t session_tid = -1;
	uint8_t out_pkt_buf[NGTCP2_MAX_UDP_PAYLOAD_SIZE];
	isc_quic_out_pkt_t out_pkt;
	bool new_conn = false;

	if (pkt == NULL || pkt->length == 0) {
		return;
	}

	isc_quic_out_pkt_init(&out_pkt, out_pkt_buf, sizeof(out_pkt_buf));

	isc_result_t result = isc_quic_sm_route_pkt(
		mgr, isc_tid(), false, pkt, &local, &peer, &out_pkt, &new_conn,
		&session_tid, &session);

	if (result == ISC_R_SUCCESS && session_tid != isc_tid()) {
		quic_session_user_data_t *session_data =
			isc_quic_session_get_user_data(session);
		quic_io_req_t *req = alloc_quic_reroute_req(
			pkt, session_data->handle, mgr, session);
		isc_async_run(isc_loop_get(session_tid),
			      (isc_job_cb)process_rerouted_packet, req);
		goto done;
	}

	if (new_conn) {
		quic_session_user_data_t *session_data =
			alloc_session_user_data(handle, mgr);
		isc_quic_session_set_user_data(session, (void *)session_data);
		(void)atomic_fetch_add(&conns_accepted, 1);
		atomic_fetch_add(&total_connections, 1);
	}

	if (out_pkt.pktsz == 0 && session != NULL) {
		result = isc_quic_session_write_pkt(session, &out_pkt);
	}

	if (out_pkt.pktsz != 0) {
		isc_region_t out_pkt_data;
		quic_io_req_t *req = alloc_quic_send_req(
			&out_pkt, handle, session, &out_pkt_data);
		isc_nm_send(handle, &out_pkt_data, udp_quic_send_cb, req);
	}

done:
	/* Continue to listen */
	if (session != NULL) {
		isc_quic_session_detach(&session);
	}
}

static void
udp_quic_read_cb(isc_nmhandle_t *handle, isc_result_t eresult,
		 isc_region_t *pkt, void *cbarg) {
	isc_quic_sm_t *mgr = (isc_quic_sm_t *)cbarg;

	assert_non_null(handle);

	F();

	switch (eresult) {
	case ISC_R_TIMEDOUT:
		if (!isc_quic_sm_is_server(mgr)) {
			isc_nm_read(handle, udp_quic_read_cb, mgr);
		}
		break;
	case ISC_R_SUCCESS: {
		process_incoming_packet(handle, pkt, mgr);
		return;
	}
	case ISC_R_CANCELED:
	case ISC_R_CONNECTIONRESET:
	case ISC_R_EOF:
	case ISC_R_SHUTTINGDOWN:
		break;
	default:
		fprintf(stderr, "%s(%p, %s, %p)\n", __func__, handle,
			isc_result_totext(eresult), cbarg);
		assert_int_equal(eresult, ISC_R_SUCCESS);
	}
}

static void
udp_quic_stop_listening(void *arg ISC_ATTR_UNUSED) {
	stop_listening(arg);
}

static void
udp_quic_start_listening(uint32_t nworkers, isc_nm_recv_cb_t cb) {
	isc_result_t result = isc_nm_listenudp(nworkers, &udp_listen_addr, cb,
					       server_quic_sm, &listen_sock);

	assert_int_equal(result, ISC_R_SUCCESS);

	isc_loop_teardown(isc_loop_main(), udp_quic_stop_listening,
			  listen_sock);
}

static void
udp_quic_enqueue_connect(void *arg ISC_ATTR_UNUSED);

static void
udp_quic_connect_cb(isc_nmhandle_t *handle, isc_result_t eresult, void *cbarg) {
	F();

	isc_refcount_decrement(&active_cconnects);

	switch (eresult) {
	case ISC_R_SUCCESS: {
		isc_quic_sm_t *mgr = (isc_quic_sm_t *)cbarg;
		isc_nmhandle_t *outerhandle = NULL;
		isc_sockaddr_t local = isc_nmhandle_localaddr(handle),
			       peer = isc_nmhandle_peeraddr(handle);
		isc_quic_session_t *session = NULL;
		isc_tid_t session_tid = isc_tid();
		uint8_t out_pkt_buf[NGTCP2_MAX_UDP_PAYLOAD_SIZE];
		isc_quic_out_pkt_t out_pkt;

		isc_nmhandle_attach(handle, &outerhandle);

		isc_nmhandle_set_nonstop_read(handle, true);
		isc_nm_read(handle, udp_quic_read_cb, cbarg);

		isc_quic_out_pkt_init(&out_pkt, out_pkt_buf,
				      sizeof(out_pkt_buf));

		(void)isc_quic_sm_connect(mgr, session_tid, &local, &peer, NULL,
					  &out_pkt, &session);
		(void)atomic_fetch_add(&connect_attempts, 1);
		atomic_fetch_add(&total_connections, 1);

		quic_session_user_data_t *session_data =
			alloc_session_user_data(handle, mgr);
		isc_quic_session_set_user_data(session, (void *)session_data);

		if (out_pkt.pktsz != 0) {
			isc_region_t out_pkt_data;
			quic_io_req_t *req = alloc_quic_send_req(
				&out_pkt, handle, session, &out_pkt_data);
			isc_nmhandle_setwritetimeout(handle, T_IDLE);
			isc_nm_send(handle, &out_pkt_data, udp_quic_send_cb,
				    req);
		}

		/* Continue to listen */
		if (session != NULL) {
			isc_quic_session_detach(&session);
		}
	} break;
	case ISC_R_ADDRINUSE:
		/* Try again */
		udp_quic_enqueue_connect(NULL);
		break;
	case ISC_R_SHUTTINGDOWN:
	case ISC_R_CANCELED:
		break;
	default:
		fprintf(stderr, "%s(%p, %s, %p)\n", __func__, handle,
			isc_result_totext(eresult), cbarg);
		assert_int_equal(eresult, ISC_R_SUCCESS);
	}
}

static void
quic_udp_on_stop_cb(isc_quic_sm_t *sm) {
	if (sm == client_quic_sm) {
		client_quic_sm = NULL;
	} else if (sm == server_quic_sm) {
		server_quic_sm = NULL;
	}

	isc_quic_sm_finish(sm, isc_tid());
	isc_quic_sm_detach(&sm);
}

static void
quic_udp_on_stop(isc_quic_sm_t *sm) {
	isc_loop_teardown(isc_loop_main(), (isc_job_cb)quic_udp_on_stop_cb, sm);
}

static void
udp_quic_enqueue_connect(void *arg ISC_ATTR_UNUSED) {
	isc_sockaddr_t connect_addr;

	connect_addr = (isc_sockaddr_t){ .length = 0 };
	isc_sockaddr_fromin6(&connect_addr, &in6addr_loopback, 0);

	isc_refcount_increment0(&active_cconnects);

	isc_nm_udpconnect(&udp_connect_addr, &udp_listen_addr,
			  udp_quic_connect_cb, client_quic_sm, T_CONNECT);
}

ISC_LOOP_TEST_IMPL(quic_sm_recv_send_test) {
	udp_quic_start_listening(ISC_NM_LISTEN_ALL, udp_quic_read_cb);
	for (size_t i = 0; i < workers; i++) {
		isc_async_run(isc_loop_get(i), udp_quic_enqueue_connect,
			      client_quic_sm);
	}
	/* isc_async_run(isc_loop_get(0), udp_quic_enqueue_connect, */
	/* 	      client_quic_sm); */
}

static bool
quic_on_expiry_timer_cb(isc_quic_sm_t *restrict mgr,
			isc_quic_session_t *restrict session,
			const isc_result_t expiry_result,
			isc_sockaddr_t *restrict local,
			const isc_sockaddr_t *restrict peer,
			const isc_region_t *restrict pkt_data, void *cbarg) {
	UNUSED(mgr);
	UNUSED(expiry_result);
	UNUSED(local);
	UNUSED(peer);
	UNUSED(cbarg);

	quic_session_user_data_t *session_data =
		isc_quic_session_get_user_data(session);
	if (session_data == NULL) {
		return false;
	}

	if (expiry_result != ISC_R_SUCCESS) {
		isc_quic_session_finish(session);
		return false;
	}

	if (pkt_data != NULL && pkt_data->length > 0) {
		isc_region_t out_region;
		quic_io_req_t *req = alloc_quic_send_req_region(
			pkt_data, session_data->handle, session, &out_region);
		isc_nm_send(session_data->handle, &out_region, udp_quic_send_cb,
			    req);
	}

	/* while (quic_send_pending(handle, session) > 0) */
	/* 	; */

	/* quic_send_pending_async(session); */

	return true;
}

static void
udp_quic_shutdown_loopmgr_cb(void *arg) {
	UNUSED(arg);
	isc_loopmgr_shutdown();
}

static void
quic_shutdown_async_cb(isc_quic_session_t *session) {
	quic_session_user_data_t *session_data =
		isc_quic_session_get_user_data(session);

	int64_t total = atomic_fetch_sub(&total_connections, 1) - 1;

	if (session_data != NULL && session_data->handle != NULL) {
		uint8_t out_pkt_buf[NGTCP2_MAX_UDP_PAYLOAD_SIZE];
		isc_quic_out_pkt_t out_pkt;

		isc_quic_out_pkt_init(&out_pkt, out_pkt_buf,
				      sizeof(out_pkt_buf));

		isc_quic_session_shutdown(session, &out_pkt);

		isc_region_t out_region;
		quic_io_req_t *req = alloc_quic_send_req(
			&out_pkt, session_data->handle, session, &out_region);

		isc_nm_cb_t cb = udp_quic_send_cb;

		if (isc_quic_session_is_server(session)) {
			(void)atomic_fetch_sub(&conns_accepted, 1);
		} else {
			(void)atomic_fetch_sub(&connect_attempts, 1);
		}

		if (total == 0) {
			cb = udp_quic_send_shutdown_cb;
		}

		isc_nm_send(session_data->handle, &out_region, cb, req);

		/* if (!isc_quic_session_is_server(session) && */
		/*     atomic_fetch_sub(&connect_attempts, 1) == 0) */
		/* { */
		/* 	isc_async_run(isc_loop(), udp_quic_shutdown_loopmgr_cb,
		 */
		/* 		      NULL); */
		/* } */
	} else if (total == 0) {
		isc_async_run(isc_loop(), udp_quic_shutdown_loopmgr_cb, NULL);
	}

	isc_quic_session_detach(&session);
}

static void
udp_quic_stream_send_cb(isc_quic_session_t *restrict session,
			const int64_t stream_id, isc_result_t result,
			void *cbarg, udp_quic_stream_data_t *stream_data) {
	isc_buffer_t *databuf = (isc_buffer_t *)cbarg;
	isc_region_t data = { 0 };
	uint64_t sent = 0;

	REQUIRE(session != NULL);

	if (databuf != NULL) {
		sent = isc_buffer_usedlength(databuf);
		free_data_buf(stream_data, &databuf);
	}
	stream_data->completed_sends++;

	if (result == ISC_R_SUCCESS) {
		stream_data->successful_sends++;
		stream_data->total_sent_bytes += sent;
	} else {
		return;
	}

	if (stream_data->completed_sends >= MAX_SENDS) {
		if (stream_data->local) {
			result = isc_quic_session_shutdown_stream(
				session, stream_id, false);
			assert_true(result == ISC_R_SUCCESS);
		}
		return;
	}

	stream_data->sends++;
	stream_data->started_sends++;

	databuf = get_data_buf(stream_data);
	isc_buffer_usedregion(databuf, &data);

	result = isc_quic_session_send_data(
		session, stream_id, &data, stream_data->sends == MAX_SENDS,
		(isc_quic_send_cb_t)udp_quic_stream_send_cb, databuf);
	assert_true(result == ISC_R_SUCCESS);
}

static bool
quic_sm_on_handshake_cb(isc_quic_sm_t *restrict mgr,
			isc_quic_session_t *restrict session, void *cbarg) {
	UNUSED(mgr);
	UNUSED(session);
	UNUSED(cbarg);

	if (isc_quic_sm_is_server(mgr)) {
		atomic_fetch_add(&server_handshakes, 1);
	} else {
		atomic_fetch_add(&client_handshakes, 1);
	}

	for (size_t i = 0; i < MAX_STREAMS; i++) {
		int64_t stream_id = -1;
		const bool bidi = isc_random_uniform(2) == 1;

		isc_result_t result = isc_quic_session_open_stream(
			session, bidi, mgr, &stream_id);
		atomic_fetch_add(&total_opened_streams, 1);

		assert_true(result == ISC_R_SUCCESS);

		udp_quic_stream_data_t *stream_data =
			udp_quic_stream_data_alloc(mgr, true, stream_id);

		isc_quic_session_set_stream_user_data(session, stream_id,
						      stream_data);

		isc_buffer_t *databuf = get_data_buf(stream_data);
		isc_region_t data = { 0 };
		isc_buffer_usedregion(databuf, &data);

		result = isc_quic_session_send_data(
			session, stream_id, &data, false,
			(isc_quic_send_cb_t)udp_quic_stream_send_cb, databuf);
		assert_true(result == ISC_R_SUCCESS);

		stream_data->sends++;
		stream_data->started_sends++;
	}

	/* quic_send_pending_async(session); */

	return true;
}

static void
quic_on_conn_close_cb(isc_quic_sm_t *restrict mgr,
		      isc_quic_session_t *restrict session, void *cbarg) {
	UNUSED(mgr);
	UNUSED(cbarg);
	UNUSED(session);

	if (isc_quic_session_is_server(session)) {
		puts("closing server");
	} else {
		puts("closing client");
	}

	quic_session_user_data_t *session_data =
		isc_quic_session_get_user_data(session);

	if (session_data != NULL) {
		if (!isc_quic_sm_is_server(mgr)) {
			isc_nm_cancelread(session_data->handle);
			isc_nmhandle_close(session_data->handle);
		}
		free_session_user_data(session_data);
		isc_quic_session_set_user_data(session, NULL);
	}
}

static bool
quic_on_stream_close_cb(isc_quic_sm_t *restrict mgr,
			isc_quic_session_t *session, const int64_t streamd_id,
			const bool app_error_set, const uint64_t app_error_code,
			isc_quic_sm_t *mgrarg,
			udp_quic_stream_data_t *stream_data) {
	int64_t total = 0;
	UNUSED(app_error_set);
	UNUSED(app_error_code);
	UNUSED(stream_data);
	UNUSED(mgr);
	UNUSED(mgrarg);

	quic_session_user_data_t *session_data =
		isc_quic_session_get_user_data(session);

	INSIST(isc_quic_session_get_stream_user_data(session, streamd_id) ==
	       stream_data);

	if (stream_data->send_buf != NULL) {
		isc_buffer_free(&stream_data->send_buf);
	}

	session_data->closed_streams++;
	if (session_data->closed_streams == 2 * MAX_STREAMS) {
		isc_quic_session_t *tmpsess = NULL;
		isc_quic_session_attach(session, &tmpsess);
		isc_async_run(isc_loop(), (isc_job_cb)quic_shutdown_async_cb,
			      tmpsess);
	}

	if (stream_data->local) {
		total = atomic_fetch_add(&total_closed_streams, 1) + 1;
		printf("closed streams: %ld, opened streams: %ld, sends: %ld "
		       "(code %ld)\n",
		       total, total_opened_streams,
		       stream_data->completed_sends, app_error_code);
		INSIST(atomic_load(&total_opened_streams) >= total);

		/* if (total == (workers * MAX_STREAMS * 2)) { */
		/* 	isc_quic_session_t *tmpsess = NULL; */
		/* 	isc_quic_session_attach(session, &tmpsess); */
		/* 	isc_async_run(isc_loop(), */
		/* 		      (isc_job_cb)quic_shutdown_async_cb, */
		/* 		      tmpsess); */
		/* } */
	}

	udp_quic_stream_data_free(stream_data);

	return true;
}

static bool
quic_on_remote_stream_open_cb(isc_quic_sm_t *restrict mgr,
			      isc_quic_session_t *restrict session,
			      const int64_t stream_id, void *cbarg) {
	UNUSED(cbarg);

	udp_quic_stream_data_t *stream_data =
		udp_quic_stream_data_alloc(mgr, false, stream_id);

	isc_quic_session_set_stream_user_data(session, stream_id, stream_data);

	return true;
}

static bool
quic_sm_on_recv_stream_data_cb(isc_quic_sm_t *restrict mgr,
			       isc_quic_session_t *session,
			       const int64_t stream_id, const bool fin,
			       const uint64_t offset,
			       const isc_region_t *restrict data,
			       isc_quic_sm_t *mgrarg,
			       udp_quic_stream_data_t *stream_data) {
	UNUSED(offset);
	UNUSED(data);
	UNUSED(stream_data);
	UNUSED(mgrarg);

	INSIST(isc_quic_session_get_stream_user_data(session, stream_id) ==
	       stream_data);
	INSIST(stream_data->mgr == mgr);

	if (data != NULL && data->length > 0) {
		bool ret = verify_data_buf(&stream_data->bcounter_receive,
					   data->base, data->length);

		assert_true(ret);
	}

	stream_data->receives++;

	if (fin) {
		isc_quic_session_shutdown_stream(session, stream_id, true);
	}

	/* quic_send_pending_async(session); */

	return true;
}

static isc_quic_sm_interface_t callbacks = {
	.on_handshake = quic_sm_on_handshake_cb,
	.on_expiry_timer = quic_on_expiry_timer_cb,
	.on_conn_close = quic_on_conn_close_cb,
	.on_stream_close =
		(isc_quic_sm_on_stream_close_cb_t)quic_on_stream_close_cb,
	.on_remote_stream_open = quic_on_remote_stream_open_cb,
	.on_recv_stream_data = (isc_quic_sm_on_recv_stream_data_cb_t)
		quic_sm_on_recv_stream_data_cb,
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
quic_sm_test_setup(void **state) {
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

	int ret = setup_udp_test(state);
	if (ret != 0) {
		return ret;
	}

	isc_quic_sm_create(mctx, workers, default_client_tlsctx, NULL,
			   &callbacks, NULL, T_INIT, T_IDLE, UINT16_MAX,
			   UINT16_MAX, NGTCP2_PROTO_VER_V1,
			   proto_preference_list, proto_preference_list_len,
			   false, 0, &client_quic_sm);

	quic_udp_on_stop(client_quic_sm);

	isc_quic_sm_create(mctx, workers, default_server_tlsctx, NULL,
			   &callbacks, NULL, T_INIT, T_IDLE, UINT16_MAX,
			   UINT16_MAX, 0, proto_preference_list,
			   proto_preference_list_len, true, 0, &server_quic_sm);

	quic_udp_on_stop(server_quic_sm);

	atomic_store(&connect_attempts, 0);
	atomic_store(&conns_accepted, 0);
	atomic_store(&server_handshakes, 0);
	atomic_store(&client_handshakes, 0);
	atomic_store(&total_opened_streams, 0);

	return 0;
}

static int
quic_sm_test_teardown(void **state) {
	UNUSED(state);

	/* isc_quic_sm_finish(server_quic_sm, isc_tid()); */
	/* isc_quic_sm_finish(client_quic_sm, isc_tid()); */

	/* isc_quic_sm_detach(&server_quic_sm); */
	/* isc_quic_sm_detach(&client_quic_sm); */

	assert_true(server_quic_sm == NULL);
	assert_true(client_quic_sm == NULL);

	isc_tlsctx_free(&default_client_tlsctx);
	isc_tlsctx_free(&default_server_tlsctx);

	int ret = teardown_udp_test(state);
	if (ret != 0) {
		return ret;
	}

	return 0;
}

static int
quic_sm_testset_setup(void **state) {
	UNUSED(state);

	set_thread_call_rcu_data(thread_call_rcu_data);

	isc_tls_quic_crypto_initialize();

	isc_mem_create("testctx", &mctx);

	return 0;
}

static int
quic_sm_testset_teardown(void **state) {
	UNUSED(state);

	isc_mem_detach(&mctx);

	isc_tls_quic_crypto_shutdown();

	set_thread_call_rcu_data(NULL);

	return 0;
}

ISC_TEST_LIST_START
ISC_TEST_ENTRY_CUSTOM(quic_sm_recv_send_test, quic_sm_test_setup,
		      quic_sm_test_teardown)
ISC_TEST_LIST_END

ISC_TEST_MAIN_CUSTOM(quic_sm_testset_setup, quic_sm_testset_teardown);
