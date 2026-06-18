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

/* ! \file */

#include <inttypes.h>
#include <sched.h>  /* IWYU pragma: keep */
#include <setjmp.h> /* IWYU pragma: keep */
#include <stdarg.h>
#include <stddef.h>
#include <stdlib.h> /* IWYU pragma: keep */
#include <string.h> /* IWYU pragma: keep */

#define UNIT_TESTING
#include <cmocka.h>

#include <isc/lib.h>
#include <isc/mem.h>
#include <isc/pause.h>
#include <isc/quic.h>
#include <isc/random.h>
#include <isc/thread.h>
#include <isc/tid.h>
#include <isc/time.h>
#include <isc/tls.h>
#include <isc/types.h>
#include <isc/util.h>

#include <tests/isc.h>

typedef struct server_context {
	bool dead;
	bool write_close;
	isc_quic_conn_t *conn;
	isc_quic_cid_map_t *map;
	isc_tlsctx_t *tlsctx;
} server_context_t;

typedef struct client_context {
	bool dead;
	bool write_close;
	isc_quic_conn_t *conn;
	isc_quic_cid_map_t *map;
	isc_tlsctx_t *tlsctx;
} client_context_t;

typedef struct map_test_worker_state {
	isc_quic_cid_map_t *map;
	isc_quic_cid_t *cid[128];
} map_test_worker_state_t;

constexpr uint8_t alpn[] = { 0x03, 'u', 'w', 'u' };

static isc_sockaddr_t client_addr;
static isc_sockaddr_t server_addr;

static isc_nanosecs_t shim_clock = 0;

static int
global_setup(ISC_ATTR_UNUSED void **state) {
	isc_sockaddr_fromin6(&client_addr, &in6addr_loopback, 9901);
	isc_sockaddr_fromin6(&server_addr, &in6addr_loopback, 9900);
	return 0;
}

static isc_nanosecs_t
get_shim_clock(void) {
	isc_nanosecs_t current = shim_clock;
	shim_clock += 10;
	return current;
}

static void *
worker_map_test(void *arg) {
	map_test_worker_state_t *state = arg;
	isc_quic_cid_map_t *map = isc_quic_cid_map_ref(state->map);
	isc_quic_conn_t *conn = (void *)isc_g_mctx;
	isc_result_t result;

	for (size_t i = 0; i < ARRAY_SIZE(state->cid); i++) {
		state->cid[i] = isc_quic_cid_random_new(20, isc_g_mctx);

		result = isc_quic_cid_map_find(
			map, isc_quic_cid_bytes(state->cid[i]), NULL, NULL);
		assert_int_equal(result, ISC_R_NOTFOUND);

		result = isc_quic_cid_map_add(map, state->cid[i], conn);
		assert_int_equal(result, ISC_R_SUCCESS);

		result = isc_quic_cid_map_find(
			map, isc_quic_cid_bytes(state->cid[i]), NULL, NULL);
		assert_int_equal(result, ISC_R_SUCCESS);
	}

	isc_quic_cid_map_detach(&map);

	return NULL;
}

static void
client_init(client_context_t *client) {
	isc_quic_cid_map_t *map = NULL;
	isc_quic_conn_t *conn = NULL;
	isc_tlsctx_t *tlsctx = NULL;
	isc_result_t result;

	isc_quic_cid_map_create(isc_g_mctx, &map);

	result = isc_tlsctx_createclient(&tlsctx);
	assert_int_equal(result, ISC_R_SUCCESS);
	isc_tlsctx_set_random_session_id_context(tlsctx);

	const isc_quic_client_conn_options_t opts = {
		.sni = "test.example.com",
		.tlsctx = tlsctx,
		.local = &client_addr,
		.peer = &server_addr,
		.alpn = { alpn, sizeof(alpn) },
	};

	result = isc_quic_conn_client_create(isc_g_mctx, map, NULL, &opts,
					     get_shim_clock(), &conn);
	assert_int_equal(result, ISC_R_SUCCESS);

	*client = (client_context_t){
		.conn = conn,
		.map = map,
		.tlsctx = tlsctx,
	};
}

static void
client_deinit(client_context_t *client) {
	isc_quic_cid_map_detach(&client->map);
	isc_quic_conn_destroy(&client->conn);
	isc_tlsctx_free(&client->tlsctx);
}

static void
server_init(server_context_t *server, isc_constregion_t scid,
	    isc_constregion_t dcid) {
	isc_quic_cid_map_t *map = NULL;
	isc_quic_conn_t *conn = NULL;
	isc_tlsctx_t *tlsctx = NULL;
	isc_result_t result;

	isc_quic_cid_map_create(isc_g_mctx, &map);

	result = isc_tlsctx_createserver(NULL, NULL, &tlsctx);
	assert_int_equal(result, ISC_R_SUCCESS);
	isc_tlsctx_set_random_session_id_context(tlsctx);

	const isc_quic_server_conn_options_t opts = {
		.tlsctx = tlsctx,
		.local = &server_addr,
		.peer = &server_addr,
		.initial_dcid = dcid,
		.initial_scid = scid,
		.alpn = { alpn, sizeof(alpn) },
	};

	result = isc_quic_conn_server_create(isc_g_mctx, map, NULL, &opts,
					     get_shim_clock(), &conn);
	assert_int_equal(result, ISC_R_SUCCESS);

	*server = (server_context_t){
		.conn = conn,
		.map = map,
		.tlsctx = tlsctx,
	};
}

static void
server_deinit(server_context_t *server) {
	isc_quic_cid_map_detach(&server->map);
	isc_quic_conn_destroy(&server->conn);
	isc_tlsctx_free(&server->tlsctx);
}

static void
client_to_server_initial_io(server_context_t *server,
			    client_context_t *client) {
	isc_constregion_t scid, dcid;
	isc_result_t result;
	uint8_t buffer[1200];
	size_t len;

	len = 0;
	result = isc_quic_conn_pull_packet(client->conn, buffer, sizeof(buffer),
					   &len, get_shim_clock);
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_quic_packet_info_decode(
		&scid, &dcid, (isc_constregion_t){ buffer, len });
	assert_int_equal(result, ISC_R_SUCCESS);

	server_init(server, scid, dcid);

	result = isc_quic_conn_push_packet(server->conn,
					   (isc_constregion_t){ buffer, len },
					   get_shim_clock());
	assert_int_equal(result, ISC_R_SUCCESS);
}

static void
io_step(server_context_t *server, client_context_t *client) {
	isc_result_t result;
	uint8_t cbuf[1200];
	uint8_t sbuf[1200];
	size_t len;

	if (server->dead || client->dead) {
		return;
	}

	len = 0;
	switch (isc_quic_conn_handle_expiry(server->conn, get_shim_clock())) {
	case ISC_R_SUCCESS:
		isc_quic_conn_pull_packet(server->conn, sbuf, sizeof(sbuf),
					  &len, get_shim_clock);
		break;
	case ISC_R_CANCELED:
		server->write_close = true;
		FALLTHROUGH;
	case ISC_R_TIMEDOUT:
		server->dead = true;
		break;
	default:
		UNREACHABLE();
	}

	if (len != 0) {
		result = isc_quic_conn_push_packet(
			client->conn, (isc_constregion_t){ sbuf, len },
			get_shim_clock());
		assert_int_equal(result, ISC_R_SUCCESS);
	}

	switch (isc_quic_conn_handle_expiry(client->conn, get_shim_clock())) {
	case ISC_R_SUCCESS:
		break;
	case ISC_R_CANCELED:
		client->write_close = true;
		FALLTHROUGH;
	case ISC_R_TIMEDOUT:
		client->dead = true;
		break;
	default:
		UNREACHABLE();
	}

	len = 0;
	isc_quic_conn_pull_packet(client->conn, cbuf, sizeof(cbuf), &len,
				  get_shim_clock);
	if (len != 0) {
		result = isc_quic_conn_push_packet(
			server->conn, (isc_constregion_t){ cbuf, len },
			get_shim_clock());
		assert_int_equal(result, ISC_R_SUCCESS);
	}
}

ISC_RUN_TEST_IMPL(isc_quic_cid_map) {
	isc_tid_t head, rest;
	isc_quic_cid_t *cid;
	isc_result_t result;

	isc_quic_cid_map_t *map = NULL;
	isc_quic_cid_map_create(isc_g_mctx, &map);

	map_test_worker_state_t *states = isc_mem_cget(isc_g_mctx, workers,
						       sizeof(*states));

	isc_thread_t *threads = isc_mem_cget(isc_g_mctx, workers,
					     sizeof(*threads));
	for (size_t i = 0; i < workers; i++) {
		states[i].map = map;
		isc_thread_create(worker_map_test, &states[i], &threads[i]);
	}
	for (size_t i = 0; i < workers; i++) {
		isc_thread_join(threads[i], NULL);
	}
	isc_mem_cput(isc_g_mctx, threads, workers, sizeof(*threads));

	for (size_t i = 0; i < workers; i++) {
		cid = states[i].cid[0];
		result = isc_quic_cid_map_find(map, isc_quic_cid_bytes(cid),
					       NULL, &head);
		assert_int_equal(result, ISC_R_SUCCESS);
		isc_quic_cid_destroy(isc_g_mctx, &cid);

		for (size_t j = 1; j < ARRAY_SIZE(states[0].cid); j++) {
			cid = states[i].cid[j];
			result = isc_quic_cid_map_find(
				map, isc_quic_cid_bytes(cid), NULL, &rest);
			assert_int_equal(result, ISC_R_SUCCESS);
			assert_int_equal(head, rest);

			isc_quic_cid_destroy(isc_g_mctx, &cid);
		}
	}

	isc_mem_cput(isc_g_mctx, states, workers, sizeof(*states));

	isc_quic_cid_map_detach(&map);
}

ISC_RUN_TEST_IMPL(isc_quic_conn_perfect) {
	isc_quic_stream_data_t *data;
	client_context_t client;
	server_context_t server;
	isc_result_t result;
	uint8_t cbuf[1200];
	int64_t stream1_id, stream2_id;
	size_t len;

	client_init(&client);
	client_to_server_initial_io(&server, &client);

	while (!(isc_quic_conn_handshake_complete(client.conn) &&
		 isc_quic_conn_handshake_complete(server.conn)))
	{
		io_step(&server, &client);
	}

	assert_true(isc_quic_conn_handshake_complete(client.conn));
	assert_true(isc_quic_conn_handshake_complete(server.conn));

	stream1_id = -1;
	result = isc_quic_conn_open_bidi_stream(client.conn, &stream1_id,
						&server);
	assert_int_not_equal(stream1_id, -1);
	assert_int_equal(result, ISC_R_SUCCESS);

	stream2_id = -1;
	result = isc_quic_conn_open_bidi_stream(client.conn, &stream2_id,
						&server);
	assert_int_not_equal(stream2_id, -1);
	assert_int_equal(result, ISC_R_SUCCESS);

	uint8_t *wa = (uint8_t *)"hi!";

	result = isc_quic_conn_push_stream_data(client.conn, stream1_id, wa, 3);
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_quic_conn_push_stream_data(client.conn, stream1_id, wa, 3);
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_quic_conn_push_stream_data(client.conn, stream2_id, wa, 3);
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_quic_conn_pull_packet(client.conn, cbuf, sizeof(cbuf),
					   &len, get_shim_clock);
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_quic_conn_push_packet(server.conn,
					   (isc_constregion_t){ cbuf, len },
					   get_shim_clock());
	assert_int_equal(result, ISC_R_SUCCESS);

	data = NULL;
	result = isc_quic_conn_pull_stream_data(server.conn, &data);
	assert_int_equal(result, ISC_R_SUCCESS);

	isc_quic_stream_data_destroy(server.conn, &data);

	result = isc_quic_conn_shutdown_stream(server.conn, stream1_id, 0);
	assert_int_equal(result, ISC_R_SUCCESS);

	io_step(&server, &client);

	client_deinit(&client);
	server_deinit(&server);
}

ISC_TEST_LIST_START
ISC_TEST_ENTRY(isc_quic_cid_map)
ISC_TEST_ENTRY(isc_quic_conn_perfect)
ISC_TEST_LIST_END

ISC_TEST_MAIN_CUSTOM(global_setup, NULL);
