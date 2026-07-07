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

#include <inttypes.h>
#include <sched.h>  /* IWYU pragma: keep */
#include <setjmp.h> /* IWYU pragma: keep */
#include <stdarg.h>
#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>

#define UNIT_TESTING
#include <cmocka.h>

#include <isc/lib.h>
#include <isc/quic.h>
#include <isc/random.h>

#include <tests/isc.h>

typedef struct connection_context {
	bool dead;
	bool write_close;
	bool handshake_done;
	isc_quic_conn_t *conn;
	isc_quic_router_t *router;
	isc_tlsctx_t *tlsctx;
	isc_sockaddr_t *local;
} connection_context_t;

constexpr uint8_t client_dcid[] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
};

constexpr uint8_t unknown_cid[] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
};

constexpr uint8_t initial_frame_v1[1200] = {
	0xcd, 0x00, 0x00, 0x00, 0x01, 0x08, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
	0x06, 0x07, 0x05, 0x63, 0x5f, 0x63, 0x69, 0x64, 0x00, 0x41, 0x03, 0x98,
	0x1c, 0x36, 0xa7, 0xed, 0x78, 0x71, 0x6b, 0xe9, 0x71, 0x1b, 0xa4, 0x98,
	0xb7, 0xed, 0x86, 0x84, 0x43, 0xbb, 0x2e, 0x0c, 0x51, 0x4d, 0x4d, 0x84,
	0x8e, 0xad, 0xcc, 0x7a, 0x00, 0xd2, 0x5c, 0xe9, 0xf9, 0xaf, 0xa4, 0x83,
	0x97, 0x80, 0x88, 0xde, 0x83, 0x6b, 0xe6, 0x8c, 0x0b, 0x32, 0xa2, 0x45,
	0x95, 0xd7, 0x81, 0x3e, 0xa5, 0x41, 0x4a, 0x91, 0x99, 0x32, 0x9a, 0x6d,
	0x9f, 0x7f, 0x76, 0x0d, 0xd8, 0xbb, 0x24, 0x9b, 0xf3, 0xf5, 0x3d, 0x9a,
	0x77, 0xfb, 0xb7, 0xb3, 0x95, 0xb8, 0xd6, 0x6d, 0x78, 0x79, 0xa5, 0x1f,
	0xe5, 0x9e, 0xf9, 0x60, 0x1f, 0x79, 0x99, 0x8e, 0xb3, 0x56, 0x8e, 0x1f,
	0xdc, 0x78, 0x9f, 0x64, 0x0a, 0xca, 0xb3, 0x85, 0x8a, 0x82, 0xef, 0x29,
	0x30, 0xfa, 0x5c, 0xe1, 0x4b, 0x5b, 0x9e, 0xa0, 0xbd, 0xb2, 0x9f, 0x45,
	0x72, 0xda, 0x85, 0xaa, 0x3d, 0xef, 0x39, 0xb7, 0xef, 0xaf, 0xff, 0xa0,
	0x74, 0xb9, 0x26, 0x70, 0x70, 0xd5, 0x0b, 0x5d, 0x07, 0x84, 0x2e, 0x49,
	0xbb, 0xa3, 0xbc, 0x78, 0x7f, 0xf2, 0x95, 0xd6, 0xae, 0x3b, 0x51, 0x43,
	0x05, 0xf1, 0x02, 0xaf, 0xe5, 0xa0, 0x47, 0xb3, 0xfb, 0x4c, 0x99, 0xeb,
	0x92, 0xa2, 0x74, 0xd2, 0x44, 0xd6, 0x04, 0x92, 0xc0, 0xe2, 0xe6, 0xe2,
	0x12, 0xce, 0xf0, 0xf9, 0xe3, 0xf6, 0x2e, 0xfd, 0x09, 0x55, 0xe7, 0x1c,
	0x76, 0x8a, 0xa6, 0xbb, 0x3c, 0xd8, 0x0b, 0xbb, 0x37, 0x55, 0xc8, 0xb7,
	0xeb, 0xee, 0x32, 0x71, 0x2f, 0x40, 0xf2, 0x24, 0x51, 0x19, 0x48, 0x70,
	0x21, 0xb4, 0xb8, 0x4e, 0x15, 0x65, 0xe3, 0xca, 0x31, 0x96, 0x7a, 0xc8,
	0x60, 0x4d, 0x40, 0x32, 0x17, 0x0d, 0xec, 0x28, 0x0a, 0xee, 0xfa, 0x09,
	0x5d, 0x08, 0xb3, 0xb7, 0x24, 0x1e, 0xf6, 0x64, 0x6a, 0x6c, 0x86, 0xe5,
	0xc6, 0x2c, 0xe0, 0x8b, 0xe0, 0x99,
};

constexpr uint8_t initial_frame_reserved_version[1200] = {
	0xcd, 0x0A, 0x0A, 0x0A, 0x0A, 0x08, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
	0x06, 0x07, 0x05, 0x63, 0x5f, 0x63, 0x69, 0x64, 0x00, 0x41, 0x03, 0x98,
	0x1c, 0x36, 0xa7, 0xed, 0x78, 0x71, 0x6b, 0xe9, 0x71, 0x1b, 0xa4, 0x98,
	0xb7, 0xed, 0x86, 0x84, 0x43, 0xbb, 0x2e, 0x0c, 0x51, 0x4d, 0x4d, 0x84,
	0x8e, 0xad, 0xcc, 0x7a, 0x00, 0xd2, 0x5c, 0xe9, 0xf9, 0xaf, 0xa4, 0x83,
	0x97, 0x80, 0x88, 0xde, 0x83, 0x6b, 0xe6, 0x8c, 0x0b, 0x32, 0xa2, 0x45,
	0x95, 0xd7, 0x81, 0x3e, 0xa5, 0x41, 0x4a, 0x91, 0x99, 0x32, 0x9a, 0x6d,
	0x9f, 0x7f, 0x76, 0x0d, 0xd8, 0xbb, 0x24, 0x9b, 0xf3, 0xf5, 0x3d, 0x9a,
	0x77, 0xfb, 0xb7, 0xb3, 0x95, 0xb8, 0xd6, 0x6d, 0x78, 0x79, 0xa5, 0x1f,
	0xe5, 0x9e, 0xf9, 0x60, 0x1f, 0x79, 0x99, 0x8e, 0xb3, 0x56, 0x8e, 0x1f,
	0xdc, 0x78, 0x9f, 0x64, 0x0a, 0xca, 0xb3, 0x85, 0x8a, 0x82, 0xef, 0x29,
	0x30, 0xfa, 0x5c, 0xe1, 0x4b, 0x5b, 0x9e, 0xa0, 0xbd, 0xb2, 0x9f, 0x45,
	0x72, 0xda, 0x85, 0xaa, 0x3d, 0xef, 0x39, 0xb7, 0xef, 0xaf, 0xff, 0xa0,
	0x74, 0xb9, 0x26, 0x70, 0x70, 0xd5, 0x0b, 0x5d, 0x07, 0x84, 0x2e, 0x49,
	0xbb, 0xa3, 0xbc, 0x78, 0x7f, 0xf2, 0x95, 0xd6, 0xae, 0x3b, 0x51, 0x43,
	0x05, 0xf1, 0x02, 0xaf, 0xe5, 0xa0, 0x47, 0xb3, 0xfb, 0x4c, 0x99, 0xeb,
	0x92, 0xa2, 0x74, 0xd2, 0x44, 0xd6, 0x04, 0x92, 0xc0, 0xe2, 0xe6, 0xe2,
	0x12, 0xce, 0xf0, 0xf9, 0xe3, 0xf6, 0x2e, 0xfd, 0x09, 0x55, 0xe7, 0x1c,
	0x76, 0x8a, 0xa6, 0xbb, 0x3c, 0xd8, 0x0b, 0xbb, 0x37, 0x55, 0xc8, 0xb7,
	0xeb, 0xee, 0x32, 0x71, 0x2f, 0x40, 0xf2, 0x24, 0x51, 0x19, 0x48, 0x70,
	0x21, 0xb4, 0xb8, 0x4e, 0x15, 0x65, 0xe3, 0xca, 0x31, 0x96, 0x7a, 0xc8,
	0x60, 0x4d, 0x40, 0x32, 0x17, 0x0d, 0xec, 0x28, 0x0a, 0xee, 0xfa, 0x09,
	0x5d, 0x08, 0xb3, 0xb7, 0x24, 0x1e, 0xf6, 0x64, 0x6a, 0x6c, 0x86, 0xe5,
	0xc6, 0x2c, 0xe0, 0x8b, 0xe0, 0x99,
};

constexpr uint8_t stateless_reset_token[ISC_QUIC_STATELESS_TOKEN_LENGTH] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0xE,  0x0F,
};

constexpr uint8_t stateless_reset_packet[] = {
	0x40, 0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0x00, 0x01, 0x02, 0x03,
	0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0xE,  0x0F,
};

constexpr uint8_t alpn[] = { 0x03, 'U', 'w', 'U' };

constexpr isc_nanosecs_t idle_timeout = 300000000;

static isc_sockaddr_t client_addr[16];
static isc_sockaddr_t server_addr;

static isc_nanosecs_t shim_clock = 0;

static void
handshake_completed_cb(void *cbarg);
static const isc_quic_conn_callbacks_t callbacks = {
	.handshake_completed = handshake_completed_cb,
};

isc_nanosecs_t
isc_time_monotonic(void) {
	isc_nanosecs_t current = shim_clock;
	shim_clock += 7;
	return current;
}

static void
client_init(connection_context_t *client, size_t i) {
	isc_quic_router_t *router = NULL;
	isc_quic_conn_t *conn = NULL;
	isc_tlsctx_t *tlsctx = NULL;
	isc_result_t result;

	isc_quic_router_create(isc_g_mctx, &router);

	result = isc_tlsctx_createclient(&tlsctx);
	assert_int_equal(result, ISC_R_SUCCESS);
	isc_tlsctx_set_random_session_id_context(tlsctx);

	const isc_quic_client_options_t opts = {
		.tlsctx = tlsctx,
		.alpn = { .base = alpn, .length = sizeof(alpn) },
		.idle_timeout = idle_timeout,
	};

	result = isc_quic_conn_client_create(
		isc_g_mctx, router, &callbacks, client, &opts,
		"test.example.com", &client_addr[i], &server_addr, &conn);
	assert_int_equal(result, ISC_R_SUCCESS);

	*client = (connection_context_t){
		.conn = conn,
		.router = router,
		.tlsctx = tlsctx,
		.local = &client_addr[i],
	};
}

static void
client_deinit(connection_context_t *client) {
	isc_quic_router_detach(&client->router);
	isc_quic_conn_destroy(&client->conn);
	isc_tlsctx_free(&client->tlsctx);
}

static int
global_setup(void **state ISC_ATTR_UNUSED) {
	size_t i;

	isc_sockaddr_fromin6(&server_addr, &in6addr_loopback, 9900);

	for (i = 0; i < ARRAY_SIZE(client_addr); i++) {
		isc_sockaddr_fromin6(&client_addr[i], &in6addr_loopback,
				     9901 + i);
	}

	return 0;
}

static void
server_init(connection_context_t *server, isc_quic_router_t *router,
	    isc_constregion_t scid, isc_constregion_t dcid,
	    isc_sockaddr_t *peer) {
	isc_quic_conn_t *conn = NULL;
	isc_tlsctx_t *tlsctx = NULL;
	isc_result_t result;

	result = isc_tlsctx_createserver(NULL, NULL, &tlsctx);
	assert_int_equal(result, ISC_R_SUCCESS);
	isc_tlsctx_set_random_session_id_context(tlsctx);

	const isc_quic_server_options_t opts = {
		.tlsctx = tlsctx,
		.alpn = { .base = alpn, .length = sizeof(alpn) },
		.idle_timeout = idle_timeout,
	};

	result = isc_quic_conn_server_create(isc_g_mctx, router, &callbacks,
					     server, &opts, dcid, scid,
					     &server_addr, peer, &conn);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_non_null(conn);

	*server = (connection_context_t){
		.conn = conn,
		.router = router,
		.tlsctx = tlsctx,
	};
}

static void
server_deinit(connection_context_t *server) {
	isc_quic_router_detach(&server->router);
	isc_quic_conn_destroy(&server->conn);
	isc_tlsctx_free(&server->tlsctx);
}

static void
handshake_completed_cb(void *cbarg) {
	connection_context_t *context = cbarg;
	context->handshake_done = true;
}

static void
client_to_server_initial_io(connection_context_t *server,
			    connection_context_t *client) {
	isc_constregion_t scid, dcid;
	isc_quic_router_t *router = NULL;
	void *conn = NULL;
	isc_sockaddr_t from, to;
	isc_result_t result;
	uint8_t buffer[1200];
	size_t len;

	len = 0;
	result = isc_quic_conn_pull_packet(
		client->conn, (isc_region_t){ buffer, sizeof(buffer) }, &len,
		&from, &to);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_true(isc_sockaddr_compare(&from, client->local,
					 ISC_SOCKADDR_CMPADDR |
						 ISC_SOCKADDR_CMPPORT));
	assert_true(isc_sockaddr_compare(&to, &server_addr,
					 ISC_SOCKADDR_CMPADDR |
						 ISC_SOCKADDR_CMPPORT));

	// result = isc_quic_packet_info_decode(
	// 	&scid, &dcid, (isc_constregion_t){ buffer, len });
	// assert_int_equal(result, ISC_R_SUCCESS);

	isc_quic_router_create(isc_g_mctx, &router);

	result = isc_quic_router_handle_packet(
		router, (isc_constregion_t){ buffer, len }, NULL, &dcid, &scid,
		&conn);
	assert_int_equal(result, ISC_R_NOTFOUND);
	assert_non_null(dcid.base);
	assert_non_null(scid.base);

	server_init(server, router, scid, dcid, &from);

	result = isc_quic_conn_push_packet(server->conn,
					   (isc_constregion_t){ buffer, len },
					   &server_addr, client->local),
	assert_int_equal(result, ISC_R_SUCCESS);
}

static void
io_step(connection_context_t *server, connection_context_t *client) {
	isc_sockaddr_t from, to;
	isc_result_t result;
	uint8_t cbuf[1200];
	uint8_t sbuf[1200];
	size_t len;

	if (server->dead || client->dead) {
		return;
	}

	len = 0;
	switch (isc_quic_conn_handle_expiry(server->conn)) {
	case ISC_R_SUCCESS:
		isc_quic_conn_pull_packet(server->conn,
					  (isc_region_t){ sbuf, sizeof(sbuf) },
					  &len, &from, &to);
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
		assert_true(isc_sockaddr_compare(&from, &server_addr,
						 ISC_SOCKADDR_CMPADDR |
							 ISC_SOCKADDR_CMPPORT));
		assert_true(isc_sockaddr_compare(&to, client->local,
						 ISC_SOCKADDR_CMPADDR |
							 ISC_SOCKADDR_CMPPORT));

		result = isc_quic_conn_push_packet(
			client->conn, (isc_constregion_t){ sbuf, len },
			client->local, &server_addr);
		assert_int_equal(result, ISC_R_SUCCESS);
	}

	switch (isc_quic_conn_handle_expiry(client->conn)) {
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
	isc_quic_conn_pull_packet(client->conn,
				  (isc_region_t){ cbuf, sizeof(cbuf) }, &len,
				  &from, &to);
	if (len != 0) {
		assert_true(isc_sockaddr_compare(&from, client->local,
						 ISC_SOCKADDR_CMPADDR |
							 ISC_SOCKADDR_CMPPORT));
		assert_true(isc_sockaddr_compare(&to, &server_addr,
						 ISC_SOCKADDR_CMPADDR |
							 ISC_SOCKADDR_CMPPORT));
		result = isc_quic_conn_push_packet(
			server->conn, (isc_constregion_t){ cbuf, len },
			&server_addr, client->local);
		assert_int_equal(result, ISC_R_SUCCESS);
	}
}

ISC_RUN_TEST_IMPL(isc_quic_router_cid) {
	isc_quic_router_t *router = NULL;
	isc_constregion_t cid;
	isc_result_t result;
	void *value = NULL;

	isc_quic_router_create(isc_g_mctx, &router);

	cid = (isc_constregion_t){ client_dcid, sizeof(client_dcid) };
	result = isc_quic_router_add_cid(router, cid, router);
	assert_int_equal(result, ISC_R_SUCCESS);

	cid = (isc_constregion_t){ client_dcid, sizeof(client_dcid) };
	result = isc_quic_router_add_cid(router, cid, router);
	assert_int_equal(result, ISC_R_EXISTS);

	cid = (isc_constregion_t){ client_dcid, sizeof(client_dcid) };
	result = isc_quic_router_get_cid(router, cid, &value);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_ptr_equal(value, router);

	value = NULL;
	cid = (isc_constregion_t){ unknown_cid, sizeof(unknown_cid) };
	result = isc_quic_router_get_cid(router, cid, &value);
	assert_int_equal(result, ISC_R_NOTFOUND);

	cid = (isc_constregion_t){ unknown_cid, sizeof(unknown_cid) };
	result = isc_quic_router_add_cid(router, cid, router);
	assert_int_equal(result, ISC_R_SUCCESS);

	isc_quic_router_detach(&router);
}

ISC_RUN_TEST_IMPL(isc_quic_router_stateless_reset) {
	uint8_t token[ISC_QUIC_STATELESS_TOKEN_LENGTH];
	isc_quic_router_t *router = NULL;
	isc_result_t result;
	void *value = NULL;

	isc_quic_router_create(isc_g_mctx, &router);

	isc_random_buf(token, sizeof(token));

	result = isc_quic_router_get_stateless_reset(router, token, &value);
	assert_int_equal(result, ISC_R_NOTFOUND);

	result = isc_quic_router_add_stateless_reset(router, token, router);
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_quic_router_add_stateless_reset(router, token, router);
	assert_int_equal(result, ISC_R_EXISTS);

	result = isc_quic_router_get_stateless_reset(router, token, &value);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_ptr_equal(value, router);

	result = isc_quic_router_del_stateless_reset(router, token);
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_quic_router_get_stateless_reset(router, token, &value);
	assert_int_equal(result, ISC_R_NOTFOUND);

	result = isc_quic_router_del_stateless_reset(router, token);
	assert_int_equal(result, ISC_R_NOTFOUND);

	isc_quic_router_detach(&router);
}

ISC_RUN_TEST_IMPL(isc_quic_router_packet) {
	isc_quic_router_t *router = NULL;
	isc_quic_version_t version;
	isc_constregion_t dcid, scid;
	isc_result_t result;
	void *value = NULL;

	isc_quic_router_create(isc_g_mctx, &router);

	/* Initial CRYPTO frames MUST be 1200 bytes */
	result = isc_quic_router_handle_packet(
		router, (isc_constregion_t){ initial_frame_v1, 1199 }, &version,
		&dcid, &scid, &value);
	assert_int_equal(result, ISC_R_IGNORE);
	assert_int_equal(version, ISC_QUIC_VERSION_V1);

	/* Use reserved version 0x0A0A0A0A */
	result = isc_quic_router_handle_packet(
		router,
		(isc_constregion_t){ initial_frame_reserved_version, 1200 },
		&version, &dcid, &scid, &value);
	assert_int_equal(result, ISC_R_FAILURE);
	assert_int_equal(version, ISC_QUIC_VERSION_UNKNOWN);

	result = isc_quic_router_handle_packet(
		router, (isc_constregion_t){ initial_frame_v1, 1200 }, &version,
		&dcid, &scid, &value);
	assert_int_equal(result, ISC_R_NOTFOUND);
	assert_int_equal(version, ISC_QUIC_VERSION_V1);
	assert_int_equal(dcid.length, sizeof(client_dcid));
	assert_memory_equal(dcid.base, client_dcid, dcid.length);

	result = isc_quic_router_add_cid(router, dcid, router);
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_quic_router_handle_packet(
		router, (isc_constregion_t){ initial_frame_v1, 1200 }, &version,
		&dcid, &scid, &value);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_int_equal(version, ISC_QUIC_VERSION_V1);
	assert_ptr_equal(value, router);

	value = NULL;
	result = isc_quic_router_handle_packet(
		router, (isc_constregion_t){ initial_frame_v1, 500 }, &version,
		&dcid, &scid, &value);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_ptr_equal(value, router);

	result = isc_quic_router_del_cid(router, dcid);
	assert_int_equal(result, ISC_R_SUCCESS);

	value = NULL;
	result = isc_quic_router_handle_packet(
		router, (isc_constregion_t){ initial_frame_v1, 1200 }, &version,
		&dcid, &scid, &value);
	assert_int_equal(result, ISC_R_NOTFOUND);

	result = isc_quic_router_add_stateless_reset(
		router, stateless_reset_token, router);
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_quic_router_handle_packet(
		router,
		(isc_constregion_t){ stateless_reset_packet,
				     sizeof(stateless_reset_packet) },
		NULL, &dcid, &scid, &value);
	assert_int_equal(result, ISC_R_UNSET);

	isc_quic_router_detach(&router);
}

ISC_RUN_TEST_IMPL(isc_quic_conn_perfect) {
	connection_context_t client, server;
	isc_result_t result;
	uint8_t cbuf[1200];
	int64_t stream1_id, stream2_id;
	size_t len;

	client_init(&client, 0);
	client_to_server_initial_io(&server, &client);

	while (!client.handshake_done && !server.handshake_done) {
		io_step(&server, &client);
	}

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

	result = isc_quic_conn_pull_packet(client.conn,
					   (isc_region_t){ cbuf, sizeof(cbuf) },
					   &len, NULL, NULL);
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_quic_conn_push_packet(server.conn,
					   (isc_constregion_t){ cbuf, len },
					   &server_addr, client.local);
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_quic_conn_shutdown_stream(server.conn, stream1_id, 0);
	assert_int_equal(result, ISC_R_SUCCESS);

	io_step(&server, &client);

	client_deinit(&client);
	server_deinit(&server);
}

ISC_RUN_TEST_IMPL(isc_quic_conn_lost_packet) {
	connection_context_t client, server;
	isc_result_t result;
	uint8_t cbuf[1200];
	int64_t stream_id;
	size_t i, len;

	const char messages[4][4] = { "hi!", "uwu", "owo", "TwT" };

	client_init(&client, 0);
	client_to_server_initial_io(&server, &client);

	while (!client.handshake_done && !server.handshake_done) {
		io_step(&server, &client);
	}

	stream_id = -1;
	result = isc_quic_conn_open_bidi_stream(client.conn, &stream_id,
						&server);
	assert_int_not_equal(stream_id, -1);
	assert_int_equal(result, ISC_R_SUCCESS);

	io_step(&server, &client);

	/* lose this packet */
	isc_quic_conn_push_stream_data(client.conn, stream_id,
				       UNCONST(messages[0]),
				       sizeof(messages[0]));
	result = isc_quic_conn_pull_packet(client.conn,
					   (isc_region_t){ cbuf, sizeof(cbuf) },
					   &len, NULL, NULL);
	assert_int_equal(result, ISC_R_SUCCESS);

	for (i = 1; i < ARRAY_SIZE(messages); i++) {
		isc_quic_conn_push_stream_data(client.conn, stream_id,
					       UNCONST(messages[i]),
					       sizeof(messages[i]));

		io_step(&server, &client);
	}

	io_step(&server, &client);

	client_deinit(&client);
	server_deinit(&server);
}

ISC_TEST_LIST_START
ISC_TEST_ENTRY(isc_quic_router_cid)
ISC_TEST_ENTRY(isc_quic_router_stateless_reset)
ISC_TEST_ENTRY(isc_quic_router_packet)
ISC_TEST_ENTRY(isc_quic_conn_perfect)
ISC_TEST_ENTRY(isc_quic_conn_lost_packet)
ISC_TEST_LIST_END

ISC_TEST_MAIN_CUSTOM(global_setup, NULL);
