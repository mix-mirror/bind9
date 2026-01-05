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

#define UNIT_TESTING
#include <cmocka.h>

#include <isc/attributes.h>
#include <isc/buffer.h>
#include <isc/lib.h>
#include <isc/mem.h>
#include <isc/ngtcp2_crypto.h>
#include <isc/quic.h>
#include <isc/random.h>
#include <isc/time.h>
#include <isc/tls.h>

#include <tests/isc.h>

typedef struct session_info session_info_t;
typedef struct shim_server shim_server_t;
typedef struct shim_client shim_client_t;

typedef enum shim_type {
	SHIM_TYPE_INVALID = 0x00,
	SHIM_TYPE_SERVER = 0x01,
	SHIM_TYPE_CLIENT = 0x02,
} shim_type_t;

typedef struct session_info {
	int64_t id;
	shim_type_t type;
} session_info_t;

typedef struct shim_manager {
	isc_tlsctx_t *tlsctx;
	isc_sockaddr_t address;
	uint8_t secret[ISC_NGTCP2_CRYPTO_STATIC_SECRET_LEN];
	isc_quic_session_t *session;
} shim_manager_t;

constexpr in_port_t client_port = 9153;
constexpr in_port_t server_port = 9154;

isc_nanosecs_t shim_clock;

static shim_manager_t client;
static shim_manager_t server;

static void
setup_prelude(void) {
	const isc_tls_quic_interface_t *tls_quic_interface =
		isc_tls_get_default_quic_interface();

	server = (shim_manager_t){ 0 };
	isc_tlsctx_createserver(NULL, NULL, &server.tlsctx);
	isc_tlsctx_set_random_session_id_context(server.tlsctx);
	isc_tlsctx_quic_configure(server.tlsctx, tls_quic_interface);
	isc_sockaddr_fromin6(&server.address, &in6addr_loopback, server_port);
	isc_random_buf(server.secret, sizeof(server.secret));

	client = (shim_manager_t){ 0 };
	isc_tlsctx_createclient(&client.tlsctx);
	isc_tlsctx_set_random_session_id_context(client.tlsctx);
	isc_tlsctx_quic_configure(client.tlsctx, tls_quic_interface);
	isc_sockaddr_fromin6(&client.address, &in6addr_loopback, client_port);
	isc_random_buf(client.secret, sizeof(client.secret));

	shim_clock = isc_time_monotonic();
}

static void
setup_epilog(void) {
	// isc_region_t secret;
	//
	// secret = (isc_region_t){ server.secret, sizeof(server.secret) };
	// isc_quic_session_create(isc_g_mctx, NULL, NULL, NULL, NULL, &server,
	// 			&server.address, &client.address, 1, 1,
	// 			UINT16_MAX, UINT16_MAX, 0, NULL, 2, &secret,
	// 			true, NULL, &server.session);
}

static int
teardown(ISC_ATTR_UNUSED void **state) {
	isc_tlsctx_free(&client.tlsctx);

	isc_tlsctx_free(&server.tlsctx);
	return 0;
}

static int
setup_session_simple(ISC_ATTR_UNUSED void **state) {
	setup_prelude();
	setup_epilog();
	return 0;
}

ISC_RUN_TEST_IMPL(session_simple) {}

ISC_TEST_LIST_START
ISC_TEST_ENTRY_CUSTOM(session_simple, setup_session_simple, teardown)
ISC_TEST_LIST_END

ISC_TEST_MAIN
