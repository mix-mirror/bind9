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
#include <stdbool.h>
#include <stdint.h>

#define UNIT_TESTING
#include <cmocka.h>

#include <isc/attributes.h>
#include <isc/buffer.h>
#include <isc/lib.h>
#include <isc/mem.h>
#include <isc/ngtcp2_crypto.h>
#include <isc/ngtcp2_utils.h>
#include <isc/overflow.h>
#include <isc/quic.h>
#include <isc/random.h>
#include <isc/tid.h>
#include <isc/time.h>
#include <isc/tls.h>

#include <tests/isc.h>

#define INITIAL_TIMEOUT (isc_ngtcp2_make_duration(15, 0))

#define NONDETERMINISTIC_FAILURE(entrypoint) \
	(monkey_wrench.entrypoint && (isc_random32() & 0x01))

typedef struct failure_injection_points failure_injection_points_t;
typedef struct session_info session_info_t;
typedef struct shim_manager shim_manager_t;
typedef struct state state_t;

typedef enum shim_type {
	SHIM_TYPE_INVALID = 0x00,
	SHIM_TYPE_SERVER = 0x01,
	SHIM_TYPE_CLIENT = 0x02,
} shim_type_t;

struct session_info {
	int64_t id;
	shim_type_t type;
	shim_manager_t *manager;
};

struct stream_info {
	int64_t id;
	shim_manager_t *manager;
};

struct shim_manager {
	bool closed;
	shim_type_t type;
	struct {
		bool active;
	} expiry;
	struct {
		isc_quic_cid_map_t *src;
		isc_quic_cid_map_t *dst;
	} cids;
	struct {
		isc_buffer_t *in;
		isc_buffer_t *out;
	} io;
	struct {
		bool started;
		bool completed;
	} handshake;
	struct {
		isc_sockaddr_t local;
		isc_sockaddr_t remote;
	} address;
	struct {
		const uint32_t *preferences;
		size_t len;
	} version;
	isc_tlsctx_t *tlsctx;
	isc_quic_session_t *session;
	uint8_t secret[ISC_NGTCP2_CRYPTO_STATIC_SECRET_LEN];
};

struct state {
	shim_manager_t *server;
	shim_manager_t *client;
};

struct failure_injection_points {
	bool server_to_client;
	bool client_to_server;
	bool timestamp;
};

constexpr in_port_t client_port = 9153;
constexpr in_port_t server_port = 9154;

ISC_ATTR_UNUSED static const uint32_t quic_version_v1_only[] = {
	NGTCP2_PROTO_VER_V1,
};

ISC_ATTR_UNUSED static const uint32_t quic_version_v2_only[] = {
	NGTCP2_PROTO_VER_V2,
};

static failure_injection_points_t monkey_wrench;
static uint64_t shim_clock;

static void
shim_manager_destroy(shim_manager_t **managerp) {
	shim_manager_t *manager;

	manager = *managerp;
	*managerp = NULL;

	isc_quic_session_finish(manager->session);
	isc_quic_session_detach(&manager->session);
	isc_tlsctx_free(&manager->tlsctx);
	isc_buffer_free(&manager->io.out);
	isc_buffer_free(&manager->io.in);
	isc_quic_cid_map_detach(&manager->cids.dst);
	isc_quic_cid_map_detach(&manager->cids.src);

	isc_mem_put(isc_g_mctx, manager, sizeof(*manager));
}

static uint64_t
shim_get_current_ts_cb(ISC_ATTR_UNUSED void *restrict cbarg) {
	// fprintf(stderr, "[EVENT] ts\n");
	shim_clock += isc_ngtcp2_make_duration(0, 4 + isc_random_uniform(4));
	if (NONDETERMINISTIC_FAILURE(timestamp)) {
		fprintf(stderr, "[MONKEY] timestamp\n");
		shim_clock += isc_ngtcp2_make_duration(1, 0);
	}

	return shim_clock;
}

static void
shim_expiry_timer_start_cb(isc_quic_session_t *restrict session,
			   const uint32_t timeout_ms, void *cbarg) {
	fprintf(stderr, "[EVENT] timer start\n");
	shim_manager_t *manager = cbarg;
	manager->expiry.active = true;
	UNUSED(session);
	UNUSED(timeout_ms);
}

static void
shim_expiry_timer_stop_cb(ISC_ATTR_UNUSED isc_quic_session_t *restrict session,
			  void *cbarg) {
	fprintf(stderr, "[EVENT] timer stop\n");
	shim_manager_t *manager = cbarg;
	manager->expiry.active = false;
}

static bool
shim_gen_unique_cid_cb(isc_quic_session_t *restrict session,
		       const size_t cidlen, const bool source,
		       void *restrict cbarg, isc_quic_cid_t **restrict pcid) {
	shim_manager_t *manager = cbarg;
	isc_tid_t tid = isc_tid();

	fprintf(stderr, "[EVENT] generating unique cid\n");

	if (source) {
		isc_quic_cid_map_gen_unique(manager->cids.src, session, tid,
					    cidlen, pcid);
	} else {
		isc_quic_cid_map_gen_unique(manager->cids.dst, session, tid,
					    cidlen, pcid);
	}

	return true;
}

static bool
shim_assoc_conn_cid_cb(isc_quic_session_t *restrict session,
		       isc_region_t *restrict cid_data, const bool source,
		       void *cbarg, isc_quic_cid_t **restrict pcid) {
	shim_manager_t *manager = cbarg;
	isc_quic_cid_map_t *map = NULL;
	isc_quic_cid_t *new = NULL;
	isc_tid_t tid = isc_tid();

	fprintf(stderr, "[EVENT] assoc conn cid\n");

	isc_quic_cid_create(isc_g_mctx, cid_data, &new);

	map = source ? manager->cids.src : manager->cids.dst;
	isc_quic_cid_map_add(map, new, session, tid);

	*pcid = new;
	return true;
}

static void
shim_deassoc_conn_cid_cb(ISC_ATTR_UNUSED isc_quic_session_t *restrict session,
			 const bool source, void *cbarg,
			 isc_quic_cid_t **restrict pcid) {
	shim_manager_t *manager = cbarg;
	isc_quic_cid_map_t *map = NULL;
	isc_quic_cid_t *cid;

	fprintf(stderr, "[EVENT] deassoc conn cid\n");

	cid = *pcid;
	map = source ? manager->cids.src : manager->cids.dst;
	isc_quic_cid_map_remove(map, cid);
	isc_quic_cid_detach(pcid);
}

static bool
shim_on_handshake_cb(isc_quic_session_t *restrict session, void *cbarg) {
	shim_manager_t *manager = cbarg;

	UNUSED(session);
	fprintf(stderr, "[EVENT] handshake\n");

	manager->handshake.completed = true;

	return true;
}

static bool
shim_on_new_regular_token_cb(
	ISC_ATTR_UNUSED isc_quic_session_t *restrict session,
	ISC_ATTR_UNUSED isc_region_t *restrict token_data,
	ISC_ATTR_UNUSED isc_sockaddr_t *restrict local,
	ISC_ATTR_UNUSED const isc_sockaddr_t *restrict peer,
	ISC_ATTR_UNUSED void *cbarg) {
	fprintf(stderr, "[EVENT] new regular token\n");
	return true;
}

static bool
shim_on_remote_stream_open_cb(
	ISC_ATTR_UNUSED isc_quic_session_t *restrict session,
	ISC_ATTR_UNUSED const int64_t stream_id, ISC_ATTR_UNUSED void *cbarg) {
	fprintf(stderr, "[EVENT] stream opened\n");
	return true;
}

static bool
shim_on_stream_close_cb(ISC_ATTR_UNUSED isc_quic_session_t *restrict session,
			ISC_ATTR_UNUSED const int64_t streamd_id,
			ISC_ATTR_UNUSED const bool app_error_set,
			ISC_ATTR_UNUSED const uint64_t app_error_code,
			ISC_ATTR_UNUSED void *cbarg,
			ISC_ATTR_UNUSED void *stream_user_data) {
	fprintf(stderr, "[EVENT] stream closed \n");
	return true;
}

static bool
shim_on_recv_stream_data_cb(isc_quic_session_t *session,
			    const int64_t stream_id, const bool fin,
			    const uint64_t offset, const isc_region_t *data,
			    void *cbarg, void *stream_user_data) {
	UNUSED(session);
	UNUSED(stream_id);
	UNUSED(fin);
	UNUSED(offset);
	UNUSED(data);
	UNUSED(cbarg);
	UNUSED(stream_user_data);
	fprintf(stderr, "[EVENT] stream data\n");

	return true;
}

static void
shim_on_conn_close_cb(isc_quic_session_t *session,
		      const uint32_t closing_timeout_ms, const bool ver_neg,
		      void *cbarg) {
	UNUSED(closing_timeout_ms);
	UNUSED(ver_neg);
	UNUSED(session);

	fprintf(stderr, "[EVENT] conn close\n");

	shim_manager_t *mgr = cbarg;
	mgr->closed = true;
}

static isc_quic_session_interface_t session_interface = {
	.get_current_ts = shim_get_current_ts_cb,
	.expiry_timer_start = shim_expiry_timer_start_cb,
	.expiry_timer_stop = shim_expiry_timer_stop_cb,
	.gen_unique_cid = shim_gen_unique_cid_cb,
	.assoc_conn_cid = shim_assoc_conn_cid_cb,
	.deassoc_conn_cid = shim_deassoc_conn_cid_cb,
	.on_handshake = shim_on_handshake_cb,
	.on_new_regular_token = shim_on_new_regular_token_cb,
	.on_remote_stream_open = shim_on_remote_stream_open_cb,
	.on_stream_close = shim_on_stream_close_cb,
	.on_recv_stream_data = shim_on_recv_stream_data_cb,
	.on_conn_close = shim_on_conn_close_cb,
};

static void
setup_prelude(state_t *state) {
	const isc_tls_quic_interface_t *tls_quic_interface =
		isc_tls_get_default_quic_interface();
	isc_sockaddr_t client_address, server_address;
	shim_manager_t *client, *server;

	isc_sockaddr_fromin6(&client_address, &in6addr_loopback, client_port);
	isc_sockaddr_fromin6(&server_address, &in6addr_loopback, server_port);

	server = isc_mem_get(isc_g_mctx, sizeof(*server));
	*server = (shim_manager_t) {
		.type = SHIM_TYPE_SERVER,
		.address = {
			.local = server_address,
			.remote = client_address,
		},
	};
	isc_quic_cid_map_create(isc_g_mctx, &server->cids.src);
	isc_quic_cid_map_create(isc_g_mctx, &server->cids.dst);
	isc_buffer_allocate(isc_g_mctx, &server->io.in, 4096);
	isc_buffer_allocate(isc_g_mctx, &server->io.out, 4096);
	isc_tlsctx_createserver(NULL, NULL, &server->tlsctx);
	isc_tlsctx_set_random_session_id_context(server->tlsctx);
	isc_tlsctx_quic_configure(server->tlsctx, tls_quic_interface);
	isc_random_buf(server->secret, sizeof(server->secret));
	isc_ngtcp2_get_default_quic_versions(&server->version.preferences,
					     &server->version.len);

	client = isc_mem_get(isc_g_mctx, sizeof(*client));
	*client = (shim_manager_t){
		.type = SHIM_TYPE_CLIENT,
		.address = {
			.local = client_address,
			.remote = server_address,
		},
	};
	isc_quic_cid_map_create(isc_g_mctx, &client->cids.src);
	isc_quic_cid_map_create(isc_g_mctx, &client->cids.dst);
	isc_buffer_allocate(isc_g_mctx, &client->io.in, 4096);
	isc_buffer_allocate(isc_g_mctx, &client->io.out, 4096);
	isc_tlsctx_createclient(&client->tlsctx);
	isc_tlsctx_set_random_session_id_context(client->tlsctx);
	isc_tlsctx_quic_configure(client->tlsctx, tls_quic_interface);
	isc_random_buf(client->secret, sizeof(client->secret));
	isc_ngtcp2_get_default_quic_versions(&client->version.preferences,
					     &client->version.len);

	*state = (state_t){
		.client = client,
		.server = server,
	};

	monkey_wrench = (failure_injection_points_t){ 0 };
	shim_clock = isc_time_monotonic();
}

static void
setup_epilog(state_t *state) {
	isc_region_t secret;

	secret = (isc_region_t){ state->server->secret,
				 sizeof(state->server->secret) };
	isc_quic_session_create(
		isc_g_mctx, state->server->tlsctx, NULL, NULL,
		&session_interface, state->server,
		&state->server->address.local, &state->server->address.remote,
		INITIAL_TIMEOUT, INITIAL_TIMEOUT, UINT16_MAX, UINT16_MAX, 0,
		state->server->version.preferences, state->server->version.len,
		&secret, true, NULL, &state->server->session);

	isc_quic_session_create(
		isc_g_mctx, state->client->tlsctx, NULL, NULL,
		&session_interface, state->client,
		&state->client->address.local, &state->client->address.remote,
		INITIAL_TIMEOUT, INITIAL_TIMEOUT, UINT16_MAX, UINT16_MAX, 0,
		state->server->version.preferences, state->server->version.len,
		&secret, false, NULL, &state->client->session);
}

static int
global_teardown(ISC_ATTR_UNUSED void **state) {
	isc_tls_quic_crypto_shutdown();
	return 0;
}

static void
transfer_packets(shim_manager_t *client, shim_manager_t *server) {
	isc_result_t result;
	isc_region_t packet;
	uint16_t len;

	for (;;) {
		result = isc_buffer_peekuint16(client->io.out, &len);
		if (result != ISC_R_SUCCESS) {
			break;
		}

		INSIST(len != 0);
		INSIST(len <= isc_buffer_usedlength(client->io.out));
		packet = (isc_region_t){
			.base = isc_buffer_current(client->io.out),
			.length = sizeof(len) + len,
		};

		if (!NONDETERMINISTIC_FAILURE(client_to_server)) {
			isc_buffer_copyregion(server->io.in, &packet);
		} else {
			fprintf(stderr, "[MONKEY] client to server fail\n");
		}

		isc_buffer_forward(client->io.out, sizeof(len) + len);
	}
	isc_buffer_clear(client->io.out);

	for (;;) {
		result = isc_buffer_peekuint16(server->io.out, &len);
		if (result != ISC_R_SUCCESS) {
			break;
		}

		INSIST(len != 0);
		INSIST(len <= isc_buffer_remaininglength(server->io.out));

		packet = (isc_region_t){
			.base = isc_buffer_current(server->io.out),
			.length = sizeof(len) + len,
		};

		if (!NONDETERMINISTIC_FAILURE(server_to_client)) {
			isc_buffer_copyregion(client->io.in, &packet);
		}

		isc_buffer_forward(server->io.out, sizeof(len) + len);
	}
	isc_buffer_clear(server->io.out);
}

static void
write_packet(shim_manager_t *manager) {
	uint8_t buffer[NGTCP2_MAX_UDP_PAYLOAD_SIZE];
	isc_quic_out_pkt_t out;
	isc_result_t result;

	isc_quic_out_pkt_init(&out, buffer, sizeof(buffer));

	result = isc_quic_session_write_pkt(manager->session, &out);
	if (result == ISC_R_SUCCESS && out.pktsz > 0) {
		isc_buffer_putuint16(manager->io.out, out.pktsz);
		isc_buffer_putmem(manager->io.out, buffer, out.pktsz);
		isc_quic_session_update_expiry_timer(manager->session);
	}
}

static void
read_packet(shim_manager_t *manager, isc_region_t *packet) {
	uint8_t token_odcid_data[ISC_NGTCP2_MAX_POSSIBLE_CID_LENGTH];
	isc_region_t token_odcid = { 0 }, secret, scid = { 0 }, dcid = { 0 };
	uint8_t buffer[NGTCP2_MAX_UDP_PAYLOAD_SIZE];
	isc_quic_session_t *found_session;
	isc_buffer_t token_odcid_buf;
	bool token_verified, is_long;
	isc_quic_out_pkt_t out;
	isc_result_t result;
	isc_tid_t found_tid;
	uint32_t version;
	size_t dcid_len;

	dcid_len = isc_ngtcp2_get_short_pkt_dcidlen(manager->type ==
						    SHIM_TYPE_CLIENT);
	result = isc_ngtcp2_decode_pkt_header(packet, dcid_len, &is_long, &scid,
					      &dcid, &version);

	assert_int_equal(result, ISC_R_SUCCESS);

	isc_quic_out_pkt_init(&out, buffer, sizeof(buffer));

	isc_buffer_init(&token_odcid_buf, token_odcid_data,
			sizeof(token_odcid_data));

	switch (manager->type) {
	case SHIM_TYPE_SERVER:
		secret = (isc_region_t){
			.base = manager->secret,
			.length = sizeof(manager->secret),
		};
		result = isc_quic_route_pkt(
			packet, manager->cids.src, &secret,
			manager->version.preferences, manager->version.len,
			&manager->address.local, &manager->address.remote,
			&dcid, &scid, version, true, false, INITIAL_TIMEOUT,
			shim_clock, &found_session, &found_tid,
			&token_odcid_buf, &out);
		break;
	case SHIM_TYPE_CLIENT:
		result = isc_quic_route_pkt(
			packet, manager->cids.src, NULL, NULL, 0,
			&manager->address.local, &manager->address.remote,
			&dcid, &scid, version, false, false, 0, shim_clock,
			&found_session, &found_tid, NULL, NULL);
		break;
	case SHIM_TYPE_INVALID:
		UNREACHABLE();
	}

	token_verified = false;

	switch (result) {
	case ISC_R_SUCCESS:
		assert_ptr_equal(manager->session, found_session);
		assert_int_equal(found_tid, isc_tid());
		isc_quic_session_detach(&found_session);
		break;
	case ISC_R_NOTFOUND:
		if (out.pktsz == 0 && manager->type == SHIM_TYPE_SERVER) {
			isc_buffer_usedregion(&token_odcid_buf, &token_odcid);
			token_verified = true;
		}
		break;
	default:
		UNREACHABLE();
	}

	if (out.pktsz == 0) {
		result = isc_quic_session_read_pkt(
			manager->session, &manager->address.local,
			&manager->address.remote, version, &dcid, &scid,
			token_verified, &token_odcid, packet, &out);

		if (result == ISC_R_SUCCESS) {
			isc_quic_session_update_expiry_timer(manager->session);
		}
	}

	if (out.pktsz > 0) {
		isc_buffer_putuint16(manager->io.out, out.pktsz);
		isc_buffer_putmem(manager->io.out, buffer, out.pktsz);
		isc_quic_session_update_expiry_timer(manager->session);
	}
}

static void
read_packets(shim_manager_t *manager) {
	isc_result_t result;
	isc_region_t packet;
	uint16_t len;

	for (;;) {
		result = isc_buffer_peekuint16(manager->io.in, &len);
		if (result != ISC_R_SUCCESS) {
			break;
		}

		isc_buffer_forward(manager->io.in, sizeof(len));

		packet = (isc_region_t){
			.base = isc_buffer_current(manager->io.in),
			.length = len,
		};

		read_packet(manager, &packet);

		isc_buffer_forward(manager->io.in, len);
	}

	isc_buffer_clear(manager->io.in);
}

static void
start_handshake(shim_manager_t *client) {
	uint8_t buffer[NGTCP2_MAX_UDP_PAYLOAD_SIZE];
	isc_quic_out_pkt_t packet;
	isc_result_t result;

	isc_quic_out_pkt_init(&packet, buffer, sizeof(buffer));
	result = isc_quic_session_connect(client->session, &packet);
	assert_int_equal(result, ISC_R_SUCCESS);
	isc_buffer_putuint16(client->io.out, packet.pktsz);
	isc_buffer_putmem(client->io.out, buffer, packet.pktsz);

	client->handshake.started = true;
}

static int
teardown(void **statep) {
	state_t *state = *statep;

	shim_manager_destroy(&state->client);
	shim_manager_destroy(&state->server);

	isc_mem_put(isc_g_mctx, state, sizeof(*state));

	return 0;
}

static int
setup_session_default(void **statep) {
	state_t *state = isc_mem_get(isc_g_mctx, sizeof(*state));

	setup_prelude(state);
	setup_epilog(state);

	*statep = state;

	return 0;
}

static int
setup_session_timestamp(void **statep) {
	state_t *state = isc_mem_get(isc_g_mctx, sizeof(*state));

	setup_prelude(state);
	monkey_wrench.timestamp = true;
	setup_epilog(state);

	*statep = state;

	return 0;
}

static int
setup_session_client_drop(void **statep) {
	state_t *state = isc_mem_get(isc_g_mctx, sizeof(*state));

	setup_prelude(state);
	monkey_wrench.client_to_server = true;
	setup_epilog(state);

	*statep = state;

	return 0;
}

static int
global_setup(ISC_ATTR_UNUSED void **state) {
	isc_tls_quic_crypto_initialize();
	return 0;
}

ISC_RUN_TEST_IMPL(session_handshake) {
	state_t *s = *state;
	shim_manager_t *server = s->server;
	shim_manager_t *client = s->client;

	start_handshake(client);
	while (!(client->handshake.completed && server->handshake.completed)) {
		transfer_packets(client, server);

		read_packets(client);
		read_packets(server);

		write_packet(client);
		write_packet(server);
	}

	assert_true(client->handshake.started);
	assert_true(server->handshake.completed);
}

ISC_RUN_TEST_IMPL(session_timestamp) {
	state_t *s = *state;
	shim_manager_t *server = s->server;
	shim_manager_t *client = s->client;

	start_handshake(client);
	while (!(client->handshake.completed && server->handshake.completed)) {
		transfer_packets(client, server);

		read_packets(client);
		read_packets(server);

		write_packet(client);
		write_packet(server);
	}
}

ISC_RUN_TEST_IMPL(session_client_drop) {
	state_t *s = *state;
	shim_manager_t *server = s->server;
	shim_manager_t *client = s->client;

	start_handshake(client);
	while (!(client->handshake.completed && server->handshake.completed)) {
		transfer_packets(client, server);

		read_packets(client);
		read_packets(server);

		write_packet(client);
		write_packet(server);
	}
}

ISC_TEST_LIST_START
ISC_TEST_ENTRY_CUSTOM(session_handshake, setup_session_default, teardown)
ISC_TEST_ENTRY_CUSTOM(session_timestamp, setup_session_timestamp, teardown)
ISC_TEST_ENTRY_CUSTOM(session_client_drop, setup_session_client_drop, teardown)
ISC_TEST_LIST_END

ISC_TEST_MAIN_CUSTOM(global_setup, global_teardown);
