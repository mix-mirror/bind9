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

#include <sched.h> /* IWYU pragma: keep */
#include <setjmp.h>
#include <stdio.h>
#include <stdlib.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

#define UNIT_TESTING
#include <cmocka.h>

#include <isc/buffer.h>
#include <isc/lib.h>
#include <isc/mem.h>
#include <isc/netmgr.h>
#include <isc/ngtcp2_crypto.h>
#include <isc/ngtcp2_utils.h>
#include <isc/os.h>
#include <isc/random.h>
#include <isc/time.h>
#include <isc/tls.h>

#include "../../lib/isc/quic/quic-int.h"

#include <tests/isc.h>

#if (defined(HAVE_NATIVE_BORINGSSL_QUIC_API) && !defined(HAVE_LIBRESSL))
#define EXTRA_NATIVE_AND_COMPAT_TESTS
#endif

/* Enable this to print extensive debugging information while running tests */
#undef PRINT_DEBUG

#define TEST_SERVER_PORT (9153)
#define TEST_CLIENT_PORT (9154)

#define INITIAL_IO_BUFFER_SIZE (2048)
#define MAX_ITERATIONS	       (1000)

#define INITIAL_TIMEOUT (isc_ngtcp2_make_duration(15, 0))

#define INITIAL_CID_LEN (NGTCP2_MIN_INITIAL_DCIDLEN)

static isc_mem_t *mctx = NULL;

static isc_tlsctx_t *default_server_tlsctx = NULL;
static isc_tlsctx_t *default_client_tlsctx = NULL;

#ifdef EXTRA_NATIVE_AND_COMPAT_TESTS
static isc_tlsctx_t *native_server_tlsctx = NULL;
static isc_tlsctx_t *native_client_tlsctx = NULL;

static isc_tlsctx_t *compat_server_tlsctx = NULL;
static isc_tlsctx_t *compat_client_tlsctx = NULL;
#endif /* EXTRA_NATIVE_AND_COMPAT_TESTS */

static const char *ciphersuites = NULL;

static isc_tlsctx_t *server_tlsctx = NULL;
static isc_tlsctx_t *client_tlsctx = NULL;

typedef struct ngtcp2_data {
	bool is_server;
	isc_tls_t *tls;
	ngtcp2_mem mem;
	uint8_t secret[ISC_NGTCP2_CRYPTO_STATIC_SECRET_LEN];

	uint32_t client_orig_chosen_version;
	uint32_t negotiated_version;
	bool version_negotiation_received;

	const uint32_t *preferred_versions;
	size_t preferred_versions_len;

	ngtcp2_cid initial_src_cid;
	ngtcp2_cid initial_dst_cid;

	ngtcp2_cid last_src_cid;

	ngtcp2_cid retry_src_cid;

	isc_buffer_t *token;

	bool connected;
	bool accepted;

	bool retry_sent;
	bool retry_received;

	ngtcp2_conn *conn;
	ngtcp2_path_storage path;
	ngtcp2_path_storage migrate_path;
	int64_t stream;

	isc_buffer_t *input;
	isc_buffer_t *output;

	bool done;
	bool close;
	bool closed;
} ngtcp2_data_t;

static isc_sockaddr_t server_addr = { 0 };
static isc_sockaddr_t client_addr = { 0 };
static isc_sockaddr_t migrate_client_addr = { 0 };

static ngtcp2_tstamp current_time = 0;

static const uint8_t ping[] = { 'P', 'I', 'N', 'G' };
static const uint8_t pong[] = { 'P', 'O', 'N', 'G' };

static const uint32_t proto_preference_list[] = { NGTCP2_PROTO_VER_V2,
						  NGTCP2_PROTO_VER_V1 };
static const size_t proto_preference_list_len =
	(sizeof(proto_preference_list) / sizeof(proto_preference_list[0]));

static bool
read_packet(ngtcp2_data_t *conn_data);

static void
send_data(ngtcp2_data_t *conn_data, const uint8_t *buf, const size_t buflen,
	  const uint64_t ts);

static bool
write_packet(ngtcp2_data_t *conn_data, const isc_region_t *data);

static bool
write_retry(ngtcp2_data_t *conn_data, const uint32_t version,
	    const ngtcp2_addr *remote_addr, const ngtcp2_cid *dcid,
	    const ngtcp2_cid *scid, const ngtcp2_cid *orig_dcid);

static void
reconnect(ngtcp2_data_t *conn_data);

static bool
process_error(ngtcp2_data_t *conn_data, const long ret_code);

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
warnconn(ngtcp2_conn *conn, const char *fmt, ...) {
	va_list args;

	warn("%s: ", ngtcp2_conn_is_server(conn) ? "server" : "client");
	va_start(args, fmt);
	vwarn(fmt, args);
	va_end(args);
}

static inline ngtcp2_tstamp
get_next_ts(void) {
	/* simulate a time needed to send a packet - 4 to 15 millis */
	current_time += isc_ngtcp2_make_duration(0, 4 + isc_random_uniform(12));

	return current_time;
}

static int
get_new_connection_id_cb(ngtcp2_conn *conn, ngtcp2_cid *cid, uint8_t *token,
			 size_t cidlen, void *user_data) {
	ngtcp2_data_t *data = (ngtcp2_data_t *)user_data;
	isc_result_t result;

	isc_ngtcp2_gen_cid(cid, cidlen);

	isc_ngtcp2_copy_cid(&data->last_src_cid, cid);

	if (data->is_server) {
		result = isc_ngtcp2_crypto_generate_stateless_reset_token(
			token, NGTCP2_STATELESS_RESET_TOKENLEN, data->secret,
			sizeof(data->secret), cid);

		if (result != ISC_R_SUCCESS) {
			warnconn(conn, "cannot generate a new connection ID\n");
			return NGTCP2_ERR_CALLBACK_FAILURE;
		}
	}

	return 0;
}

static int
handshake_confirmed_cb(ngtcp2_conn *conn, void *user_data) {
	ngtcp2_data_t *data = (ngtcp2_data_t *)user_data;
	int ret = 0;

	UNUSED(conn);

	if (data->is_server) {
		return 0;
	}

	ret = ngtcp2_conn_initiate_migration(conn, &data->migrate_path.path,
					     get_next_ts());
	if (ret != 0) {
		warnconn(conn, "failed to initiate conn migration (code: %d)\n",
			 ret);
		return NGTCP2_ERR_CALLBACK_FAILURE;
	}

	if (!write_packet(data, NULL)) {
		return NGTCP2_ERR_CALLBACK_FAILURE;
	}

	data->path = data->migrate_path;

	return 0;
}

static int
handshake_completed_cb(ngtcp2_conn *conn, void *user_data) {
	ngtcp2_data_t *data = (ngtcp2_data_t *)user_data;
	int ret = 0;
	const uint32_t negotiated_version =
		ngtcp2_conn_get_negotiated_version(conn);
	const ngtcp2_transport_params *params = NULL;
	data->connected = true;
	data->negotiated_version = negotiated_version;

	warnconn(conn, "negotiated QUIC version: %" PRIx32 "\n",
		 negotiated_version);

	if (!data->is_server) {
		isc_region_t ping_data = { .base = (uint8_t *)ping,
					   .length = sizeof(ping) };

		ret = ngtcp2_conn_open_bidi_stream(conn, &data->stream, data);
		if (ret != 0) {
			warnconn(conn, "failed to open bidirectional stream\n");
			return NGTCP2_ERR_CALLBACK_FAILURE;
		}

		if (!write_packet(data, &ping_data)) {
			return NGTCP2_ERR_CALLBACK_FAILURE;
		} else {
			warnconn(conn, "wrote PING data\n");
		}
	} else {
		uint8_t token[ISC_NGTCP2_CRYPTO_MAX_REGULAR_TOKEN_LEN];
		const ngtcp2_tstamp now = get_next_ts();
		const ngtcp2_path *path = ngtcp2_conn_get_path(conn);
		const ngtcp2_ssize toklen =
			isc_ngtcp2_crypto_generate_regular_token(
				token, sizeof(token), data->secret,
				sizeof(data->secret), path->remote.addr,
				path->remote.addrlen, now);

		if (toklen < 0) {
			warnconn(conn,
				 "failed to generate regular token "
				 "(ret: %z)\n",
				 toklen);
			return NGTCP2_ERR_CALLBACK_FAILURE;
		}

		ret = ngtcp2_conn_submit_new_token(conn, token, toklen);
		if (ret != 0) {
			warnconn(conn,
				 "failed to submit regular token (ret: "
				 "%z)\n",
				 toklen);
			return NGTCP2_ERR_CALLBACK_FAILURE;
		}
	}
	params = ngtcp2_conn_get_remote_transport_params(conn);

	if (params->version_info_present) {
		warnconn(conn, "available remote versions size: %zu\n",
			 params->version_info.available_versionslen);

		if (data->is_server &&
		    params->version_info.available_versionslen > 0)
		{
			warnconn(conn,
				 "the client's most preferred version: %" PRIx32
				 "\n",
				 ntohl(*((uint32_t *)params->version_info
						 .available_versions)));
		}
	}

	return 0;
}

static int
stream_open_cb(ngtcp2_conn *conn, int64_t stream_id, void *user_data) {
	ngtcp2_data_t *data = (ngtcp2_data_t *)user_data;

	UNUSED(conn);

	data->stream = stream_id;

	assert_true(data->is_server);

	return 0;
}

static int
stream_close_cb(ngtcp2_conn *conn, uint32_t flags, int64_t stream_id,
		uint64_t app_error_code, void *user_data,
		void *stream_user_data) {
	ngtcp2_data_t *data = (ngtcp2_data_t *)user_data;

	UNUSED(conn);
	UNUSED(flags);
	UNUSED(app_error_code);
	UNUSED(stream_user_data);

	assert_true(stream_id == data->stream);

	data->stream = -1;
	data->close = !data->is_server;
	data->done = true;

	return 0;
}

static int
recv_stream_data_cb(ngtcp2_conn *conn, uint32_t flags, int64_t stream_id,
		    uint64_t offset, const uint8_t *data, size_t datalen,
		    void *user_data, void *stream_user_data) {
	ngtcp2_data_t *conn_data = (ngtcp2_data_t *)user_data;
	int ret = 0;

	UNUSED(flags);
	UNUSED(stream_user_data);
	UNUSED(offset);

	assert_true(stream_id == conn_data->stream);

	if (conn_data->is_server) {
		isc_region_t pong_data = { .base = (uint8_t *)pong,
					   .length = sizeof(pong) };

		assert_true(memcmp(data, ping, datalen) == 0);
		if (!write_packet(conn_data, &pong_data)) {
			return NGTCP2_ERR_CALLBACK_FAILURE;
		} else {
			warnconn(conn, "wrote PING response\n");
		}
	} else {
		assert_true(memcmp(data, pong, datalen) == 0);

		ret = ngtcp2_conn_shutdown_stream(conn, stream_id, 0,
						  NGTCP2_NO_ERROR);
		if (ret != 0) {
			warnconn(conn, "cannot shutdown a stream\n");

			return NGTCP2_ERR_CALLBACK_FAILURE;
		}

		if (!write_packet(conn_data, NULL)) {
			return NGTCP2_ERR_CALLBACK_FAILURE;
		}
	}

	return 0;
}

static int
acked_stream_data_offset_cb(ngtcp2_conn *conn, int64_t stream_id,
			    uint64_t offset, uint64_t datalen, void *user_data,
			    void *stream_user_data) {
	UNUSED(user_data);
	UNUSED(stream_user_data);
	warnconn(conn,
		 "ACKnowledged data: stream - %" PRId64 ", offset - %" PRIu64
		 ", datalen - %" PRIu64 "\n",
		 stream_id, offset, datalen);
	return 0;
}

static int
recv_version_negotiation_cb(ngtcp2_conn *conn, const ngtcp2_pkt_hd *hd,
			    const uint32_t *sv, size_t nsv, void *user_data) {
	ngtcp2_data_t *conn_data = (ngtcp2_data_t *)user_data;
	const uint32_t negotiated_version = isc_ngtcp2_select_version(
		conn_data->client_orig_chosen_version,
		conn_data->preferred_versions,
		conn_data->preferred_versions_len, sv, nsv);

	UNUSED(conn);
	UNUSED(hd);

	if (negotiated_version != 0) {
		conn_data->negotiated_version = negotiated_version;
		conn_data->version_negotiation_received = true;
		return 0;
	}

	return NGTCP2_ERR_CALLBACK_FAILURE;
}

static int
recv_new_token_cb(ngtcp2_conn *conn, const uint8_t *token, size_t tokenlen,
		  void *user_data) {
	bool regular;
	ngtcp2_data_t *conn_data = (ngtcp2_data_t *)user_data;

	UNUSED(conn);
	UNUSED(user_data);

	INSIST(tokenlen > 0);

	if (token[0] == ISC_NGTCP2_CRYPTO_TOKEN_MAGIC_REGULAR) {
		regular = true;
	} else {
		INSIST(token[0] == ISC_NGTCP2_CRYPTO_TOKEN_MAGIC_RETRY);
		regular = false;
	}
	warnconn(conn, "new %s token (size: %zu)\n",
		 regular ? "regular" : "retry", tokenlen);

	isc_buffer_clear(conn_data->token);
	isc_buffer_putmem(conn_data->token, token, tokenlen);

	return 0;
}

static int
recv_retry_cb(ngtcp2_conn *conn, const ngtcp2_pkt_hd *hd, void *user_data) {
	ngtcp2_data_t *conn_data = (ngtcp2_data_t *)user_data;
	const ngtcp2_callbacks *cbs =
		isc_ngtcp2_crypto_get_default_crypto_callbacks();

	warnconn(conn, "received retry\n");

	conn_data->retry_received = true;

	return cbs->recv_retry(conn, hd, user_data);
}

static int
path_validation_cb(ngtcp2_conn *conn, uint32_t flags, const ngtcp2_path *path,
		   const ngtcp2_path *old_path,
		   ngtcp2_path_validation_result res, void *user_data) {
	ngtcp2_data_t *conn_data = (ngtcp2_data_t *)user_data;

	UNUSED(conn);
	UNUSED(flags);
	UNUSED(path);
	UNUSED(old_path);
	UNUSED(user_data);

	assert_false(conn_data->is_server);
	assert_true(res == NGTCP2_PATH_VALIDATION_RESULT_SUCCESS);

	return 0;
}

static void
init_ngtcp2_conn(ngtcp2_data_t *data, const ngtcp2_path *path,
		 const ngtcp2_cid *src_cid, const ngtcp2_cid *dst_cid,
		 const ngtcp2_cid *orig_dcid, const bool is_server,
		 const uint64_t now_ts, const ngtcp2_cid *retry_src_cid,
		 const isc_region_t *token,
		 const ngtcp2_token_type token_type) {
	isc_result_t result = ISC_R_SUCCESS;
	isc_tls_t *tls = NULL;
	ngtcp2_callbacks callbacks = {
		.get_new_connection_id = get_new_connection_id_cb,
		.handshake_completed = handshake_completed_cb,
		.handshake_confirmed = handshake_confirmed_cb,
		.stream_open = stream_open_cb,
		.stream_close = stream_close_cb,
		.recv_stream_data = recv_stream_data_cb,
		.acked_stream_data_offset = acked_stream_data_offset_cb,
		.recv_version_negotiation = recv_version_negotiation_cb,
		.recv_new_token = recv_new_token_cb,
		.recv_retry = recv_retry_cb,
		.path_validation = path_validation_cb
	};
	ngtcp2_settings settings = { 0 };
	ngtcp2_transport_params transp_params = { 0 };
	int ret = 0;

	data->stream = -1;

	isc_ngtcp2_crypto_set_crypto_callbacks(&callbacks);
	ngtcp2_settings_default(&settings);

	settings.initial_ts = now_ts;
	settings.handshake_timeout = INITIAL_TIMEOUT;
	settings.max_tx_udp_payload_size = 1220;
	settings.no_pmtud = true;

	if (data->preferred_versions_len > 0 && is_server) {
		settings.preferred_versions = data->preferred_versions;
		settings.preferred_versionslen = data->preferred_versions_len;
	}

	if (data->client_orig_chosen_version != 0 && !is_server) {
		settings.original_version = data->client_orig_chosen_version;
		if (data->preferred_versions_len > 0) {
			INSIST(isc_ngtcp2_is_version_available(
				data->client_orig_chosen_version,
				data->preferred_versions,
				data->preferred_versions_len));
			settings.preferred_versions = data->preferred_versions;
			settings.preferred_versionslen =
				data->preferred_versions_len;
		}
	}

	if (token_type != NGTCP2_TOKEN_TYPE_UNKNOWN) {
		INSIST(token != NULL);
		settings.token = token->base;
		settings.tokenlen = token->length;
		settings.token_type = token_type;
	}

	ngtcp2_transport_params_default(&transp_params);
	transp_params.initial_max_streams_uni = 0;
	transp_params.initial_max_streams_bidi = (UINT16_MAX);
	transp_params.initial_max_stream_data_bidi_local =
		INITIAL_IO_BUFFER_SIZE;
	transp_params.initial_max_stream_data_bidi_remote =
		INITIAL_IO_BUFFER_SIZE;
	transp_params.initial_max_data = INITIAL_IO_BUFFER_SIZE;
	transp_params.max_idle_timeout = INITIAL_TIMEOUT;
	transp_params.grease_quic_bit = !is_server;

	if (is_server) {
		if (orig_dcid != NULL) {
			transp_params.original_dcid = *orig_dcid;
			transp_params.original_dcid_present = true;
		}

		if (retry_src_cid != NULL) {
			transp_params.retry_scid = *retry_src_cid;
			transp_params.retry_scid_present = true;
		}

		result = isc_ngtcp2_crypto_generate_stateless_reset_token(
			transp_params.stateless_reset_token,
			sizeof(transp_params.stateless_reset_token),
			data->secret, sizeof(data->secret), src_cid);
	}

	RUNTIME_CHECK(result == ISC_R_SUCCESS);

	isc_ngtcp2_mem_init(&data->mem, mctx);
	if (is_server) {
		tls = isc_tls_create_quic(server_tlsctx);
		SSL_set_accept_state(tls);

		ret = ngtcp2_conn_server_new(&data->conn, dst_cid, src_cid,
					     path, data->negotiated_version,
					     &callbacks, &settings,
					     &transp_params, &data->mem, data);
	} else {
		tls = isc_tls_create_quic(client_tlsctx);
		SSL_set_connect_state(tls);

		ret = ngtcp2_conn_client_new(&data->conn, dst_cid, src_cid,
					     path, data->negotiated_version,
					     &callbacks, &settings,
					     &transp_params, &data->mem, data);
	}

	RUNTIME_CHECK(ret == 0);

	if (ciphersuites != NULL) {
		SSL_set_ciphersuites(tls, ciphersuites);
	}

	isc_ngtcp2_crypto_bind_conn_tls(data->conn, tls);

	data->tls = tls;
}

static void
init_ngtcp2_data(ngtcp2_data_t *data, const uint32_t client_chosen_version,
		 const uint32_t *preferred_versions,
		 const size_t preferred_versions_len, const bool is_server) {
	*data = (ngtcp2_data_t){
		.is_server = is_server,
		.client_orig_chosen_version = client_chosen_version,
		.negotiated_version = client_chosen_version,
		.preferred_versions = preferred_versions,
		.preferred_versions_len = preferred_versions_len
	};

	(void)isc_buffer_allocate(mctx, &data->output, INITIAL_IO_BUFFER_SIZE);
	(void)isc_buffer_allocate(mctx, &data->token, INITIAL_IO_BUFFER_SIZE);

	isc_random_buf(data->secret, sizeof(data->secret));

	isc_ngtcp2_gen_cid(&data->initial_src_cid, INITIAL_CID_LEN);

	if (!is_server) {
		isc_ngtcp2_gen_cid(&data->initial_dst_cid, INITIAL_CID_LEN);
		isc_ngtcp2_path_storage_init(&data->path, &client_addr,
					     &server_addr);
		isc_ngtcp2_path_storage_init(&data->migrate_path,
					     &migrate_client_addr,
					     &server_addr);
		init_ngtcp2_conn(data, &data->path.path, &data->initial_src_cid,
				 &data->initial_dst_cid, NULL, false,
				 get_next_ts(), NULL, NULL,
				 NGTCP2_TOKEN_TYPE_UNKNOWN);
	} else {
		isc_ngtcp2_path_init(&data->path.path, &server_addr,
				     &client_addr);
	}
}

static void
clean_ngtcp2_data(ngtcp2_data_t *data) {
	if (data->output != NULL) {
		isc_buffer_free(&data->output);
	}

	if (data->token != NULL) {
		isc_buffer_free(&data->token);
	}

	if (data->tls != NULL) {
		isc_tls_free(&data->tls);
	}

	if (data->conn != NULL) {
		ngtcp2_conn_del(data->conn);
	}
}

static int
ngtcp2_integration_test_setup(void **state) {
	UNUSED(state);

	return 0;
}

static int
ngtcp2_integration_test_setup_TLS_AES_128_GCM_SHA256(void **state) {
	const int ret = ngtcp2_integration_test_setup(state);

	ciphersuites = "TLS_AES_128_GCM_SHA256";

	return ret;
}

static int
ngtcp2_integration_test_setup_TLS_AES_256_GCM_SHA384(void **state) {
	const int ret = ngtcp2_integration_test_setup(state);

	ciphersuites = "TLS_AES_256_GCM_SHA384";

	return ret;
}

static int
ngtcp2_integration_test_setup_TLS_CHACHA20_POLY1305_SHA256(void **state) {
	const int ret = ngtcp2_integration_test_setup(state);

	ciphersuites = "TLS_CHACHA20_POLY1305_SHA256";

	return ret;
}

#ifndef HAVE_LIBRESSL
static int
ngtcp2_integration_test_setup_TLS_AES_128_CCM_SHA256(void **state) {
	const int ret = ngtcp2_integration_test_setup(state);

	ciphersuites = "TLS_AES_128_CCM_SHA256";

	return ret;
}
#endif /* HAVE_LIBRESSL */

static int
ngtcp2_integration_test_setup_TLS_AES_128_CCM_8_SHA256(void **state) {
	const int ret = ngtcp2_integration_test_setup(state);

	ciphersuites = "TLS_AES_128_CCM_8_SHA256";

	return ret;
}

#ifdef EXTRA_NATIVE_AND_COMPAT_TESTS
static int
ngtcp2_integration_native_to_compat_test_setup(void **state) {
	const int ret = ngtcp2_integration_test_setup(state);

	client_tlsctx = native_client_tlsctx;
	server_tlsctx = compat_server_tlsctx;

	return ret;
}

static int
ngtcp2_integration_native_to_compat_test_setup_TLS_AES_128_GCM_SHA256(
	void **state) {
	const int ret = ngtcp2_integration_native_to_compat_test_setup(state);

	ciphersuites = "TLS_AES_128_GCM_SHA256";

	return ret;
}

static int
ngtcp2_integration_native_to_compat_test_setup_TLS_AES_256_GCM_SHA384(
	void **state) {
	const int ret = ngtcp2_integration_native_to_compat_test_setup(state);

	ciphersuites = "TLS_AES_256_GCM_SHA384";

	return ret;
}

static int
ngtcp2_integration_native_to_compat_test_setup_TLS_CHACHA20_POLY1305_SHA256(
	void **state) {
	const int ret = ngtcp2_integration_native_to_compat_test_setup(state);

	ciphersuites = "TLS_CHACHA20_POLY1305_SHA256";

	return ret;
}

#ifndef HAVE_LIBRESSL
static int
ngtcp2_integration_native_to_compat_test_setup_TLS_AES_128_CCM_SHA256(
	void **state) {
	const int ret = ngtcp2_integration_native_to_compat_test_setup(state);

	ciphersuites = "TLS_AES_128_CCM_SHA256";

	return ret;
}
#endif /* HAVE_LIBRESSL */

static int
ngtcp2_integration_native_to_compat_test_setup_TLS_AES_128_CCM_8_SHA256(
	void **state) {
	const int ret = ngtcp2_integration_native_to_compat_test_setup(state);

	ciphersuites = "TLS_AES_128_CCM_8_SHA256";

	return ret;
}

static int
ngtcp2_integration_compat_to_native_test_setup(void **state) {
	const int ret = ngtcp2_integration_test_setup(state);

	client_tlsctx = compat_client_tlsctx;
	server_tlsctx = native_server_tlsctx;

	return ret;
}

static int
ngtcp2_integration_compat_to_native_test_setup_TLS_AES_128_GCM_SHA256(
	void **state) {
	const int ret = ngtcp2_integration_compat_to_native_test_setup(state);

	ciphersuites = "TLS_AES_128_GCM_SHA256";

	return ret;
}

static int
ngtcp2_integration_compat_to_native_test_setup_TLS_AES_256_GCM_SHA384(
	void **state) {
	const int ret = ngtcp2_integration_compat_to_native_test_setup(state);

	ciphersuites = "TLS_AES_256_GCM_SHA384";

	return ret;
}

static int
ngtcp2_integration_compat_to_native_test_setup_TLS_CHACHA20_POLY1305_SHA256(
	void **state) {
	const int ret = ngtcp2_integration_compat_to_native_test_setup(state);

	ciphersuites = "TLS_CHACHA20_POLY1305_SHA256";

	return ret;
}

#ifndef HAVE_LIBRESSL
static int
ngtcp2_integration_compat_to_native_test_setup_TLS_AES_128_CCM_SHA256(
	void **state) {
	const int ret = ngtcp2_integration_compat_to_native_test_setup(state);

	ciphersuites = "TLS_AES_128_CCM_SHA256";

	return ret;
}
#endif /* HAVE_LIBRESSL */

static int
ngtcp2_integration_compat_to_native_test_setup_TLS_AES_128_CCM_8_SHA256(
	void **state) {
	const int ret = ngtcp2_integration_compat_to_native_test_setup(state);

	ciphersuites = "TLS_AES_128_CCM_8_SHA256";

	return ret;
}

#endif /* EXTRA_NATIVE_AND_COMPAT_TESTS */

static int
ngtcp2_integration_test_teardown(void **state) {
	UNUSED(state);

	server_tlsctx = default_server_tlsctx;
	client_tlsctx = default_client_tlsctx;
	ciphersuites = NULL;

	return 0;
}

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
ngtcp2_integration_setup(void **state) {
	int ret;
	struct in6_addr in6;

	UNUSED(state);

	isc_tls_quic_crypto_initialize();

	isc_mem_create("testctx", &mctx);

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

#ifdef EXTRA_NATIVE_AND_COMPAT_TESTS
	native_server_tlsctx = create_quic_tls_context(
		true, isc__tls_get_native_quic_interface());

	if (native_server_tlsctx == NULL) {
		return -1;
	}

	native_client_tlsctx = create_quic_tls_context(
		false, isc__tls_get_native_quic_interface());

	if (native_client_tlsctx == NULL) {
		return -1;
	}

	compat_server_tlsctx = create_quic_tls_context(
		true, isc__tls_get_compat_quic_interface());

	if (compat_server_tlsctx == NULL) {
		return -1;
	}

	compat_client_tlsctx = create_quic_tls_context(
		false, isc__tls_get_compat_quic_interface());

	if (compat_client_tlsctx == NULL) {
		return -1;
	}
#endif /* EXTRA_NATIVE_AND_COMPAT_TESTS */

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

	current_time = isc_time_monotonic();

	return 0;
}

static int
ngtcp2_integration_teardown(void **state) {
	UNUSED(state);

	isc_tlsctx_free(&default_client_tlsctx);
	isc_tlsctx_free(&default_server_tlsctx);

#ifdef EXTRA_NATIVE_AND_COMPAT_TESTS
	if (compat_server_tlsctx != NULL) {
		isc_tlsctx_free(&compat_server_tlsctx);
	}

	if (native_server_tlsctx != NULL) {
		isc_tlsctx_free(&native_server_tlsctx);
	}
#endif /* EXTRA_NATIVE_AND_COMPAT_TESTS */

	isc_mem_detach(&mctx);

	isc_tls_quic_crypto_shutdown();

	return 0;
}

static void
reconnect(ngtcp2_data_t *conn_data) {
	if (conn_data->tls != NULL) {
		isc_tls_free(&conn_data->tls);
		conn_data->tls = NULL;
	}

	if (conn_data->conn != NULL) {
		ngtcp2_conn_del(conn_data->conn);
		conn_data->conn = NULL;
	}

	conn_data->retry_received = false;

	init_ngtcp2_conn(conn_data, &conn_data->path.path,
			 &conn_data->initial_src_cid,
			 &conn_data->initial_dst_cid, NULL, false,
			 get_next_ts(), false, NULL, NGTCP2_TOKEN_TYPE_UNKNOWN);
}

static bool
process_error(ngtcp2_data_t *conn_data, const long ret_code) {
	switch (ret_code) {
	case 0:
		break;
	case NGTCP2_ERR_DRAINING:
	case NGTCP2_ERR_CLOSING:
		conn_data->done = true;
		isc_buffer_clear(conn_data->output);
		break;
	case NGTCP2_ERR_RECV_VERSION_NEGOTIATION:
		reconnect(conn_data);
		break;
	default:
		if (ret_code > 0) {
			break;
		}
		warn("error code: %zd\n", ret_code);
		return false;
	};

	return true;
}

static bool
read_packet(ngtcp2_data_t *conn_data) {
	uint32_t pkt_len = 0;
	isc_region_t pkt = { 0 };
	int ret = 0;
	ngtcp2_version_cid vc = { 0 };
	ngtcp2_cid scid = { 0 }, dcid = { 0 }, odcid = { 0 };
	ngtcp2_tstamp ts = get_next_ts();
	ngtcp2_pkt_info pi = { 0 };
	bool status = true;
	ngtcp2_cid *retry_src_cid = NULL;

	if (isc_buffer_remaininglength(conn_data->input) == 0) {
		return true;
	}

	pkt_len = isc_buffer_getuint32(conn_data->input);
	isc_buffer_remainingregion(conn_data->input, &pkt);

	INSIST(pkt_len <= pkt.length);

	if (pkt_len == 0) {
		status = false;
		goto finish;
	}

	if (pkt.length == 0) {
		status = false;
		goto finish;
	}

	pkt.length = pkt_len;

	ret = ngtcp2_pkt_decode_version_cid(&vc, pkt.base, pkt.length,
					    INITIAL_CID_LEN);
	isc_buffer_forward(conn_data->input, pkt_len);

	if (ret != 0) {
		status = false;
		goto finish;
	}

	if (vc.version != 0 &&
	    isc_ngtcp2_pkt_header_is_long(pkt.base, pkt.length))
	{
		warn("%s: read packet (packet size: %zu, version: %" PRIx32
		     ")\n",
		     conn_data->is_server ? "server" : "client", pkt.length,
		     vc.version);
	} else {
		warn("%s: read packet (packet size: %zu)\n",
		     conn_data->is_server ? "server" : "client", pkt.length);
	}

	ngtcp2_cid_init(&scid, vc.scid, vc.scidlen);
	ngtcp2_cid_init(&dcid, vc.dcid, vc.dcidlen);

	if (isc_ngtcp2_pkt_header_is_long(pkt.base, pkt.length) &&
	    conn_data->is_server && !conn_data->accepted &&
	    !(ngtcp2_is_supported_version(vc.version) ||
	      ngtcp2_is_reserved_version(vc.version)))
	{
		uint8_t pktbuf[INITIAL_IO_BUFFER_SIZE];
		ngtcp2_ssize pkt_size = ngtcp2_pkt_write_version_negotiation(
			pktbuf, sizeof(pktbuf), isc_random8(), scid.data,
			scid.datalen, dcid.data, dcid.datalen,
			proto_preference_list, proto_preference_list_len);

		if (pkt_size <= 0) {
			status = false;
			goto finish;
		}

		send_data(conn_data, pktbuf, pkt_size, get_next_ts());
		status = true;
		goto finish;
	} else if (conn_data->is_server && !conn_data->accepted) {
		ngtcp2_pkt_hd hd = { 0 };
		ret = ngtcp2_accept(&hd, pkt.base, pkt.length);
		if (ret != 0) {
			status = false;
			goto finish;
		}

		if (hd.tokenlen > 0) {
			isc_result_t result = ISC_R_SUCCESS;
			if (hd.token[0] == ISC_NGTCP2_CRYPTO_TOKEN_MAGIC_RETRY)
			{
				if (!conn_data->retry_sent) {
					status = false;
					goto finish;
				}
				result = isc_ngtcp2_crypto_verify_retry_token(
					&odcid, hd.token, hd.tokenlen,
					(const uint8_t *)conn_data->secret,
					sizeof(conn_data->secret), hd.version,
					(const ngtcp2_sockaddr *)conn_data->path
						.path.remote.addr,
					(const ngtcp2_socklen)conn_data->path
						.path.remote.addrlen,
					&dcid, INITIAL_TIMEOUT, ts);
				if (result == ISC_R_SUCCESS) {
					retry_src_cid =
						&conn_data->retry_src_cid;
				}
			} else {
				/*
				 * Note: regular tokens should have longer
				 * timeouts.
				 */
				result = isc_ngtcp2_crypto_verify_regular_token(
					hd.token, hd.tokenlen,
					(const uint8_t *)conn_data->secret,
					sizeof(conn_data->secret),
					(const ngtcp2_sockaddr *)conn_data->path
						.path.remote.addr,
					(const ngtcp2_socklen)conn_data->path
						.path.remote.addrlen,
					INITIAL_TIMEOUT, ts);
			}

			if (result != ISC_R_SUCCESS) {
				status = false;
				goto finish;
			}
		} else {
			odcid = dcid;
		}

		isc_ngtcp2_copy_cid(&conn_data->initial_dst_cid, &scid);

		conn_data->negotiated_version = vc.version;

		if (!conn_data->retry_sent) {
			isc_ngtcp2_gen_cid(&conn_data->retry_src_cid,
					   NGTCP2_MAX_CIDLEN);
			status = write_retry(conn_data, vc.version,
					     &conn_data->path.path.remote,
					     &scid, &conn_data->retry_src_cid,
					     &dcid);
			goto finish;
		}

		init_ngtcp2_conn(conn_data, &conn_data->path.path,
				 &conn_data->initial_src_cid,
				 &conn_data->initial_dst_cid, &odcid, true, ts,
				 retry_src_cid, NULL,
				 NGTCP2_TOKEN_TYPE_UNKNOWN);
		conn_data->accepted = true;
	}

	ret = ngtcp2_conn_read_pkt(conn_data->conn, &conn_data->path.path, &pi,
				   pkt.base, pkt_len, ts);

	if (!process_error(conn_data, ret)) {
		status = false;
		goto finish;
	}

	status = true;

finish:
	isc_buffer_trycompact(conn_data->input);
	return status;
}

static void
send_data(ngtcp2_data_t *conn_data, const uint8_t *buf, const size_t buflen,
	  const uint64_t ts) {
	warn("%s: write data (size: %zu)\n",
	     conn_data->is_server ? "server" : "client", buflen);
	isc_buffer_putuint32(conn_data->output, buflen);
	isc_buffer_putmem(conn_data->output, buf, (unsigned int)buflen);
	if (conn_data->conn != NULL) {
		ngtcp2_conn_update_pkt_tx_time(conn_data->conn, ts + 1);
	}
}

static bool
write_packet(ngtcp2_data_t *conn_data, const isc_region_t *data) {
	ngtcp2_pkt_info pi = { 0 };
	ngtcp2_ssize pdata_written = 0;
	ngtcp2_ssize written = 0;
	uint8_t buf[NGTCP2_MAX_UDP_PAYLOAD_SIZE] = { 0 };
	ngtcp2_tstamp ts = get_next_ts();

	if (conn_data->conn == NULL) {
		return true;
	}

	if (conn_data->connected && conn_data->stream != -1 && data != NULL) {
		written = ngtcp2_conn_write_stream(
			conn_data->conn, &conn_data->path.path, &pi, buf,
			sizeof(buf), &pdata_written, 0, conn_data->stream,
			data->base, data->length, ts);
		if (written > 0) {
			INSIST(pdata_written == (ssize_t)data->length);
		}
	} else {
		written = ngtcp2_conn_write_pkt(conn_data->conn,
						&conn_data->path.path, &pi, buf,
						sizeof(buf), ts);
	}

	if (!process_error(conn_data, written)) {
		return false;
	}

	if (written <= 0) {
		/* no data to write or congestion limited */
		return true;
	}

	send_data(conn_data, buf, (size_t)written, ts + 1);

	return true;
}

static bool
write_retry(ngtcp2_data_t *conn_data, const uint32_t version,
	    const ngtcp2_addr *remote_addr, const ngtcp2_cid *dcid,
	    const ngtcp2_cid *scid, const ngtcp2_cid *orig_dcid) {
	uint8_t retry_token_buf[ISC_NGTCP2_CRYPTO_MAX_RETRY_TOKEN_LEN];
	size_t token_len = 0;
	uint8_t pktbuf[INITIAL_IO_BUFFER_SIZE];
	uint8_t pktsize = 0;
	ngtcp2_tstamp ts = get_next_ts();

	conn_data->retry_sent = true;

	token_len = isc_ngtcp2_crypto_generate_retry_token(
		retry_token_buf, sizeof(retry_token_buf), conn_data->secret,
		sizeof(conn_data->secret), version, remote_addr->addr,
		remote_addr->addrlen, scid, orig_dcid, ts);

	if (token_len == 0) {
		return false;
	}

	pktsize = isc_ngtcp2_crypto_write_retry(pktbuf, sizeof(pktbuf), version,
						dcid, scid, orig_dcid,
						retry_token_buf, token_len);

	if (!process_error(conn_data, pktsize)) {
		return false;
	}

	if (pktsize <= 0) {
		/* no data to write or congestion limited */
		return true;
	}

	send_data(conn_data, pktbuf, pktsize, ts + 1);

	return true;
}

static bool
do_io(ngtcp2_data_t *conn_data) {
	UNUSED(conn_data);

	do {
		/* Read "BUGS" section for SSL_get_error() */
		ERR_clear_error();
		errno = 0;

		if (!read_packet(conn_data)) {
			return false;
		}

		if (!write_packet(conn_data, NULL)) {
			return false;
		}

		if (conn_data->close && !conn_data->closed) {
			ngtcp2_pkt_info pi = { 0 };
			ngtcp2_tstamp ts = get_next_ts();
			uint8_t buf[NGTCP2_MAX_UDP_PAYLOAD_SIZE] = { 0 };
			ngtcp2_ccerr cerr = { 0 };
			ngtcp2_ssize written =
				ngtcp2_conn_write_connection_close(
					conn_data->conn, &conn_data->path.path,
					&pi, buf, sizeof(buf), &cerr, ts);

			conn_data->closed = true;

			if (written <= 0) {
				return false;
			}

			send_data(conn_data, buf, written, ts);
		}

	} while (isc_buffer_remaininglength(conn_data->input) > 0);

	return true;
}

static bool
client_server_loop(const uint32_t client_chosen_version,
		   const uint32_t *client_preferred_versions,
		   const size_t client_preferred_versions_len,
		   const uint32_t *server_preferred_versions,
		   const size_t server_preferred_versions_len) {
	int i = 0;
	bool ret = true;
	static ngtcp2_data_t server_data = { 0 };
	static ngtcp2_data_t client_data = { 0 };

	init_ngtcp2_data(&client_data, client_chosen_version,
			 client_preferred_versions,
			 client_preferred_versions_len, false);
	init_ngtcp2_data(&server_data, 0, server_preferred_versions,
			 server_preferred_versions_len, true);

	client_data.input = server_data.output;
	server_data.input = client_data.output;

	do {
		if (!do_io(&client_data)) {
			ret = false;
			goto exit;
		}

		if (!do_io(&server_data)) {
			ret = false;
			goto exit;
		}

		i++;
	} while (i < MAX_ITERATIONS &&
		 (!client_data.done || !server_data.done ||
		  (isc_buffer_remaininglength(server_data.output) > 0) ||
		  (isc_buffer_remaininglength(client_data.output) > 0)));

	if (i >= MAX_ITERATIONS) {
		ret = false;
		goto exit;
	}

exit:
	clean_ngtcp2_data(&server_data);
	clean_ngtcp2_data(&client_data);

	return ret;
}

static void
connect_test(const bool expect) {
	bool ret = client_server_loop(
		NGTCP2_PROTO_VER_V1, proto_preference_list,
		proto_preference_list_len, proto_preference_list,
		proto_preference_list_len);
	assert_true(ret == expect);
}

static void
incompatible_version_negotiation_connect_test(const bool expect) {
	bool ret = client_server_loop(
		0, proto_preference_list, proto_preference_list_len,
		proto_preference_list, proto_preference_list_len);
	assert_true(ret == expect);
}

static void
QUICv1_connect_test(const bool expect) {
	uint32_t client_version[] = { NGTCP2_PROTO_VER_V1 };

	bool ret = client_server_loop(
		NGTCP2_PROTO_VER_V1, client_version,
		sizeof(client_version) / sizeof(client_version[0]),
		proto_preference_list, proto_preference_list_len);
	assert_true(ret == expect);
}

static void
QUICv2_connect_test(const bool expect) {
	uint32_t client_version[] = { NGTCP2_PROTO_VER_V2,
				      NGTCP2_PROTO_VER_V1 };

	bool ret = client_server_loop(
		NGTCP2_PROTO_VER_V2, client_version,
		sizeof(client_version) / sizeof(client_version[0]),
		proto_preference_list, proto_preference_list_len);
	assert_true(ret == expect);
}

ISC_RUN_TEST_IMPL(ngtcp2_integration_connect_test) { connect_test(true); }

ISC_RUN_TEST_IMPL(ngtcp2_integration_connect_TLS_AES_128_GCM_SHA256_test) {
	connect_test(true);
}

ISC_RUN_TEST_IMPL(ngtcp2_integration_connect_TLS_AES_256_GCM_SHA384_test) {
	connect_test(true);
}

ISC_RUN_TEST_IMPL(ngtcp2_integration_connect_TLS_CHACHA20_POLY1305_SHA256_test) {
	connect_test(true);
}

#ifndef HAVE_LIBRESSL
ISC_RUN_TEST_IMPL(ngtcp2_integration_connect_TLS_AES_128_CCM_SHA256_test) {
	connect_test(true);
}
#endif /* HAVE_LIBRESSL */

ISC_RUN_TEST_IMPL(
	ngtcp2_integration_connect_TLS_AES_128_CCM_8_SHA256_failure_test) {
	connect_test(false);
}

ISC_RUN_TEST_IMPL(
	ngtcp2_integration_incompatible_version_negotiation_connect_test) {
	incompatible_version_negotiation_connect_test(true);
}

ISC_RUN_TEST_IMPL(
	ngtcp2_integration_incompatible_version_negotiation_connect_TLS_AES_128_GCM_SHA256_test) {
	incompatible_version_negotiation_connect_test(true);
}

ISC_RUN_TEST_IMPL(
	ngtcp2_integration_incompatible_version_negotiation_connect_TLS_AES_256_GCM_SHA384_test) {
	incompatible_version_negotiation_connect_test(true);
}

ISC_RUN_TEST_IMPL(
	ngtcp2_integration_incompatible_version_negotiation_connect_TLS_CHACHA20_POLY1305_SHA256_test) {
	incompatible_version_negotiation_connect_test(true);
}

#ifndef HAVE_LIBRESSL
ISC_RUN_TEST_IMPL(
	ngtcp2_integration_incompatible_version_negotiation_connect_TLS_AES_128_CCM_SHA256_test) {
	incompatible_version_negotiation_connect_test(true);
}
#endif /* HAVE_LIBRESSL */

ISC_RUN_TEST_IMPL(
	ngtcp2_integration_incompatible_version_negotiation_connect_TLS_AES_128_CCM_8_SHA256_failure_test) {
	incompatible_version_negotiation_connect_test(false);
}

ISC_RUN_TEST_IMPL(ngtcp2_integration_QUICv1_connect_test) {
	QUICv1_connect_test(true);
}

ISC_RUN_TEST_IMPL(
	ngtcp2_integration_QUICv1_connect_TLS_AES_128_GCM_SHA256_test) {
	QUICv1_connect_test(true);
}

ISC_RUN_TEST_IMPL(
	ngtcp2_integration_QUICv1_connect_TLS_AES_256_GCM_SHA384_test) {
	QUICv1_connect_test(true);
}

ISC_RUN_TEST_IMPL(
	ngtcp2_integration_QUICv1_connect_TLS_CHACHA20_POLY1305_SHA256_test) {
	QUICv1_connect_test(true);
}

#ifndef HAVE_LIBRESSL
ISC_RUN_TEST_IMPL(
	ngtcp2_integration_QUICv1_connect_TLS_AES_128_CCM_SHA256_test) {
	QUICv1_connect_test(true);
}
#endif /* HAVE_LIBRESSL */

ISC_RUN_TEST_IMPL(
	ngtcp2_integration_QUICv1_connect_TLS_AES_128_CCM_8_SHA256_failure_test) {
	QUICv1_connect_test(false);
}

ISC_RUN_TEST_IMPL(ngtcp2_integration_QUICv2_connect_test) {
	QUICv2_connect_test(true);
}

ISC_RUN_TEST_IMPL(
	ngtcp2_integration_QUICv2_connect_TLS_AES_128_GCM_SHA256_test) {
	QUICv2_connect_test(true);
}

ISC_RUN_TEST_IMPL(
	ngtcp2_integration_QUICv2_connect_TLS_AES_256_GCM_SHA384_test) {
	QUICv2_connect_test(true);
}

ISC_RUN_TEST_IMPL(
	ngtcp2_integration_QUICv2_connect_TLS_CHACHA20_POLY1305_SHA256_test) {
	QUICv2_connect_test(true);
}

#ifndef HAVE_LIBRESSL
ISC_RUN_TEST_IMPL(
	ngtcp2_integration_QUICv2_connect_TLS_AES_128_CCM_SHA256_test) {
	QUICv2_connect_test(true);
}
#endif /* HAVE_LIBRESSL */

ISC_RUN_TEST_IMPL(
	ngtcp2_integration_QUICv2_connect_TLS_AES_128_CCM_8_SHA256_failure_test) {
	QUICv2_connect_test(false);
}

#ifdef EXTRA_NATIVE_AND_COMPAT_TESTS
ISC_RUN_TEST_IMPL(ngtcp2_integration_connect_native_to_compat_test) {
	connect_test(true);
}

ISC_RUN_TEST_IMPL(
	ngtcp2_integration_connect_native_to_compat_TLS_AES_128_GCM_SHA256_test) {
	connect_test(true);
}

ISC_RUN_TEST_IMPL(
	ngtcp2_integration_connect_native_to_compat_TLS_AES_256_GCM_SHA384_test) {
	connect_test(true);
}

ISC_RUN_TEST_IMPL(
	ngtcp2_integration_connect_native_to_compat_TLS_CHACHA20_POLY1305_SHA256_test) {
	connect_test(true);
}

#ifndef HAVE_LIBRESSL
ISC_RUN_TEST_IMPL(
	ngtcp2_integration_connect_native_to_compat_TLS_AES_128_CCM_SHA256_test) {
	connect_test(true);
}
#endif /* HAVE_LIBRESSL */

ISC_RUN_TEST_IMPL(
	ngtcp2_integration_connect_native_to_compat_TLS_AES_128_CCM_8_SHA256_failure_test) {
	connect_test(false);
}

ISC_RUN_TEST_IMPL(
	ngtcp2_integration_incompatible_version_negotiation_connect_native_to_compat_test) {
	incompatible_version_negotiation_connect_test(true);
}

ISC_RUN_TEST_IMPL(
	ngtcp2_integration_incompatible_version_negotiation_connect_native_to_compat_TLS_AES_128_GCM_SHA256_test) {
	incompatible_version_negotiation_connect_test(true);
}

ISC_RUN_TEST_IMPL(
	ngtcp2_integration_incompatible_version_negotiation_connect_native_to_compat_TLS_AES_256_GCM_SHA384_test) {
	incompatible_version_negotiation_connect_test(true);
}

ISC_RUN_TEST_IMPL(
	ngtcp2_integration_incompatible_version_negotiation_connect_native_to_compat_TLS_CHACHA20_POLY1305_SHA256_test) {
	incompatible_version_negotiation_connect_test(true);
}

#ifndef HAVE_LIBRESSL
ISC_RUN_TEST_IMPL(
	ngtcp2_integration_incompatible_version_negotiation_connect_native_to_compat_TLS_AES_128_CCM_SHA256_test) {
	incompatible_version_negotiation_connect_test(true);
}
#endif /* HAVE_LIBRESSL */

ISC_RUN_TEST_IMPL(
	ngtcp2_integration_incompatible_version_negotiation_connect_native_to_compat_TLS_AES_128_CCM_8_SHA256_failure_test) {
	incompatible_version_negotiation_connect_test(false);
}

ISC_RUN_TEST_IMPL(ngtcp2_integration_QUICv1_connect_native_to_compat_test) {
	QUICv1_connect_test(true);
}

ISC_RUN_TEST_IMPL(
	ngtcp2_integration_QUICv1_connect_native_to_compat_TLS_AES_128_GCM_SHA256_test) {
	QUICv1_connect_test(true);
}

ISC_RUN_TEST_IMPL(
	ngtcp2_integration_QUICv1_connect_native_to_compat_TLS_AES_256_GCM_SHA384_test) {
	QUICv1_connect_test(true);
}

ISC_RUN_TEST_IMPL(
	ngtcp2_integration_QUICv1_connect_native_to_compat_TLS_CHACHA20_POLY1305_SHA256_test) {
	QUICv1_connect_test(true);
}

#ifndef HAVE_LIBRESSL
ISC_RUN_TEST_IMPL(
	ngtcp2_integration_QUICv1_connect_native_to_compat_TLS_AES_128_CCM_SHA256_test) {
	QUICv1_connect_test(true);
}
#endif /* HAVE_LIBRESSL */

ISC_RUN_TEST_IMPL(
	ngtcp2_integration_QUICv1_connect_native_to_compat_TLS_AES_128_CCM_8_SHA256_failure_test) {
	QUICv1_connect_test(false);
}

ISC_RUN_TEST_IMPL(ngtcp2_integration_QUICv2_connect_native_to_compat_test) {
	QUICv2_connect_test(true);
}

ISC_RUN_TEST_IMPL(
	ngtcp2_integration_QUICv2_connect_native_to_compat_TLS_AES_128_GCM_SHA256_test) {
	QUICv2_connect_test(true);
}

ISC_RUN_TEST_IMPL(
	ngtcp2_integration_QUICv2_connect_native_to_compat_TLS_AES_256_GCM_SHA384_test) {
	QUICv2_connect_test(true);
}

ISC_RUN_TEST_IMPL(
	ngtcp2_integration_QUICv2_connect_native_to_compat_TLS_CHACHA20_POLY1305_SHA256_test) {
	QUICv2_connect_test(true);
}

#ifndef HAVE_LIBRESSL
ISC_RUN_TEST_IMPL(
	ngtcp2_integration_QUICv2_connect_native_to_compat_TLS_AES_128_CCM_SHA256_test) {
	QUICv2_connect_test(true);
}
#endif /* HAVE_LIBRESSL */

ISC_RUN_TEST_IMPL(
	ngtcp2_integration_QUICv2_connect_native_to_compat_TLS_AES_128_CCM_8_SHA256_failure_test) {
	QUICv2_connect_test(false);
}

ISC_RUN_TEST_IMPL(ngtcp2_integration_connect_compat_to_native_test) {
	connect_test(true);
}

ISC_RUN_TEST_IMPL(
	ngtcp2_integration_connect_compat_to_native_TLS_AES_128_GCM_SHA256_test) {
	connect_test(true);
}

ISC_RUN_TEST_IMPL(
	ngtcp2_integration_connect_compat_to_native_TLS_AES_256_GCM_SHA384_test) {
	connect_test(true);
}

ISC_RUN_TEST_IMPL(
	ngtcp2_integration_connect_compat_to_native_TLS_CHACHA20_POLY1305_SHA256_test) {
	connect_test(true);
}

#ifndef HAVE_LIBRESSL
ISC_RUN_TEST_IMPL(
	ngtcp2_integration_connect_compat_to_native_TLS_AES_128_CCM_SHA256_test) {
	connect_test(true);
}
#endif /* HAVE_LIBRESSL */

ISC_RUN_TEST_IMPL(
	ngtcp2_integration_connect_compat_to_native_TLS_AES_128_CCM_8_SHA256_failure_test) {
	connect_test(false);
}

ISC_RUN_TEST_IMPL(
	ngtcp2_integration_incompatible_version_negotiation_connect_compat_to_native_test) {
	incompatible_version_negotiation_connect_test(true);
}

ISC_RUN_TEST_IMPL(
	ngtcp2_integration_incompatible_version_negotiation_connect_compat_to_native_TLS_AES_128_GCM_SHA256_test) {
	incompatible_version_negotiation_connect_test(true);
}

ISC_RUN_TEST_IMPL(
	ngtcp2_integration_incompatible_version_negotiation_connect_compat_to_native_TLS_AES_256_GCM_SHA384_test) {
	incompatible_version_negotiation_connect_test(true);
}

ISC_RUN_TEST_IMPL(
	ngtcp2_integration_incompatible_version_negotiation_connect_compat_to_native_TLS_CHACHA20_POLY1305_SHA256_test) {
	incompatible_version_negotiation_connect_test(true);
}

#ifndef HAVE_LIBRESSL
ISC_RUN_TEST_IMPL(
	ngtcp2_integration_incompatible_version_negotiation_connect_compat_to_native_TLS_AES_128_CCM_SHA256_test) {
	incompatible_version_negotiation_connect_test(true);
}
#endif /* HAVE_LIBRESSL */

ISC_RUN_TEST_IMPL(
	ngtcp2_integration_incompatible_version_negotiation_connect_compat_to_native_TLS_AES_128_CCM_8_SHA256_failure_test) {
	incompatible_version_negotiation_connect_test(false);
}

ISC_RUN_TEST_IMPL(ngtcp2_integration_QUICv1_connect_compat_to_native_test) {
	QUICv1_connect_test(true);
}

ISC_RUN_TEST_IMPL(
	ngtcp2_integration_QUICv1_connect_compat_to_native_TLS_AES_128_GCM_SHA256_test) {
	QUICv1_connect_test(true);
}

ISC_RUN_TEST_IMPL(
	ngtcp2_integration_QUICv1_connect_compat_to_native_TLS_AES_256_GCM_SHA384_test) {
	QUICv1_connect_test(true);
}

ISC_RUN_TEST_IMPL(
	ngtcp2_integration_QUICv1_connect_compat_to_native_TLS_CHACHA20_POLY1305_SHA256_test) {
	QUICv1_connect_test(true);
}

#ifndef HAVE_LIBRESSL
ISC_RUN_TEST_IMPL(
	ngtcp2_integration_QUICv1_connect_compat_to_native_TLS_AES_128_CCM_SHA256_test) {
	QUICv1_connect_test(true);
}
#endif /* HAVE_LIBRESSL */

ISC_RUN_TEST_IMPL(
	ngtcp2_integration_QUICv1_connect_compat_to_native_TLS_AES_128_CCM_8_SHA256_failure_test) {
	QUICv1_connect_test(false);
}

ISC_RUN_TEST_IMPL(ngtcp2_integration_QUICv2_connect_compat_to_native_test) {
	QUICv2_connect_test(true);
}

ISC_RUN_TEST_IMPL(
	ngtcp2_integration_QUICv2_connect_compat_to_native_TLS_AES_128_GCM_SHA256_test) {
	QUICv2_connect_test(true);
}

ISC_RUN_TEST_IMPL(
	ngtcp2_integration_QUICv2_connect_compat_to_native_TLS_AES_256_GCM_SHA384_test) {
	QUICv2_connect_test(true);
}

ISC_RUN_TEST_IMPL(
	ngtcp2_integration_QUICv2_connect_compat_to_native_TLS_CHACHA20_POLY1305_SHA256_test) {
	QUICv2_connect_test(true);
}

#ifndef HAVE_LIBRESSL
ISC_RUN_TEST_IMPL(
	ngtcp2_integration_QUICv2_connect_compat_to_native_TLS_AES_128_CCM_SHA256_test) {
	QUICv2_connect_test(true);
}
#endif /* HAVE_LIBRESSL */

ISC_RUN_TEST_IMPL(
	ngtcp2_integration_QUICv2_connect_compat_to_native_TLS_AES_128_CCM_8_SHA256_failure_test) {
	QUICv2_connect_test(false);
}
#endif /* EXTRA_NATIVE_AND_COMPAT_TESTS */

ISC_RUN_TEST_IMPL(ngtcp2_integration_regular_and_retry_tokens_test) {
	isc_result_t result;
	uint8_t static_secret[ISC_NGTCP2_CRYPTO_STATIC_SECRET_LEN];
	ngtcp2_path_storage ps;
	ngtcp2_tstamp ts = 0;

	ngtcp2_cid scid;

	ngtcp2_cid dcid;

	ngtcp2_cid odcid;
	ngtcp2_cid odcid_token;

	uint8_t regular_token_buf[ISC_NGTCP2_CRYPTO_MAX_REGULAR_TOKEN_LEN];
	uint8_t retry_token_buf[ISC_NGTCP2_CRYPTO_MAX_RETRY_TOKEN_LEN];
	size_t token_len = 0;

	isc_ngtcp2_path_storage_init(&ps, &server_addr, &client_addr);

	isc_random_buf(static_secret, sizeof(static_secret));

	/* Generate CIDs. TODO: all of them must be unique, but oh well... */
	isc_ngtcp2_gen_cid(&scid, NGTCP2_MAX_CIDLEN);
	isc_ngtcp2_gen_cid(&dcid, NGTCP2_MAX_CIDLEN);
	isc_ngtcp2_gen_cid(&odcid, NGTCP2_MAX_CIDLEN);

	ts = get_next_ts();
	token_len = isc_ngtcp2_crypto_generate_regular_token(
		regular_token_buf, sizeof(regular_token_buf), static_secret,
		sizeof(static_secret), ps.path.remote.addr,
		ps.path.remote.addrlen, ts);
	assert_true(token_len > 0);
	assert_true(regular_token_buf[0] ==
		    ISC_NGTCP2_CRYPTO_TOKEN_MAGIC_REGULAR);

	result = isc_ngtcp2_crypto_verify_regular_token(
		regular_token_buf, token_len, static_secret,
		sizeof(static_secret), ps.path.remote.addr,
		ps.path.remote.addrlen, isc_ngtcp2_make_duration(30, 0),
		ts + isc_ngtcp2_make_duration(15, 0));
	assert_true(result == ISC_R_SUCCESS);

	result = isc_ngtcp2_crypto_verify_regular_token(
		regular_token_buf, token_len, static_secret,
		sizeof(static_secret), ps.path.remote.addr,
		ps.path.remote.addrlen, isc_ngtcp2_make_duration(30, 0),
		ts + isc_ngtcp2_make_duration(45, 0));
	assert_true(result != ISC_R_SUCCESS);

	ts = get_next_ts();
	token_len = isc_ngtcp2_crypto_generate_retry_token(
		retry_token_buf, sizeof(retry_token_buf), static_secret,
		sizeof(static_secret), NGTCP2_PROTO_VER_V1, ps.path.remote.addr,
		ps.path.remote.addrlen, &scid, &odcid, ts);
	assert_true(token_len > 0);
	assert_true(retry_token_buf[0] == ISC_NGTCP2_CRYPTO_TOKEN_MAGIC_RETRY);

	result = isc_ngtcp2_crypto_verify_retry_token(
		&odcid_token, retry_token_buf, token_len, static_secret,
		sizeof(static_secret), NGTCP2_PROTO_VER_V1, ps.path.remote.addr,
		ps.path.remote.addrlen, &scid, isc_ngtcp2_make_duration(30, 0),
		ts + isc_ngtcp2_make_duration(15, 0));
	assert_true(result == ISC_R_SUCCESS);
	assert_true(odcid.datalen == odcid_token.datalen);
	assert_true(memcmp(odcid.data, odcid_token.data, odcid.datalen) == 0);

	result = isc_ngtcp2_crypto_verify_retry_token(
		&odcid_token, retry_token_buf, token_len, static_secret,
		sizeof(static_secret), NGTCP2_PROTO_VER_V1, ps.path.remote.addr,
		ps.path.remote.addrlen, &scid, isc_ngtcp2_make_duration(30, 0),
		ts + isc_ngtcp2_make_duration(45, 0));
	assert_true(result != ISC_R_SUCCESS);
}

ISC_TEST_LIST_START
ISC_TEST_ENTRY_CUSTOM(ngtcp2_integration_connect_test,
		      ngtcp2_integration_test_setup,
		      ngtcp2_integration_test_teardown)

ISC_TEST_ENTRY_CUSTOM(ngtcp2_integration_connect_TLS_AES_128_GCM_SHA256_test,
		      ngtcp2_integration_test_setup_TLS_AES_128_GCM_SHA256,
		      ngtcp2_integration_test_teardown)

ISC_TEST_ENTRY_CUSTOM(ngtcp2_integration_connect_TLS_AES_256_GCM_SHA384_test,
		      ngtcp2_integration_test_setup_TLS_AES_256_GCM_SHA384,
		      ngtcp2_integration_test_teardown)

ISC_TEST_ENTRY_CUSTOM(
	ngtcp2_integration_connect_TLS_CHACHA20_POLY1305_SHA256_test,
	ngtcp2_integration_test_setup_TLS_CHACHA20_POLY1305_SHA256,
	ngtcp2_integration_test_teardown)

#ifndef HAVE_LIBRESSL
ISC_TEST_ENTRY_CUSTOM(ngtcp2_integration_connect_TLS_AES_128_CCM_SHA256_test,
		      ngtcp2_integration_test_setup_TLS_AES_128_CCM_SHA256,
		      ngtcp2_integration_test_teardown)
#endif /* HAVE_LIBRESSL */

ISC_TEST_ENTRY_CUSTOM(
	ngtcp2_integration_connect_TLS_AES_128_CCM_8_SHA256_failure_test,
	ngtcp2_integration_test_setup_TLS_AES_128_CCM_8_SHA256,
	ngtcp2_integration_test_teardown)

ISC_TEST_ENTRY_CUSTOM(
	ngtcp2_integration_incompatible_version_negotiation_connect_test,
	ngtcp2_integration_test_setup, ngtcp2_integration_test_teardown)

ISC_TEST_ENTRY_CUSTOM(
	ngtcp2_integration_incompatible_version_negotiation_connect_TLS_AES_128_GCM_SHA256_test,
	ngtcp2_integration_test_setup_TLS_AES_128_GCM_SHA256,
	ngtcp2_integration_test_teardown)

ISC_TEST_ENTRY_CUSTOM(
	ngtcp2_integration_incompatible_version_negotiation_connect_TLS_AES_256_GCM_SHA384_test,
	ngtcp2_integration_test_setup_TLS_AES_256_GCM_SHA384,
	ngtcp2_integration_test_teardown)

ISC_TEST_ENTRY_CUSTOM(
	ngtcp2_integration_incompatible_version_negotiation_connect_TLS_CHACHA20_POLY1305_SHA256_test,
	ngtcp2_integration_test_setup_TLS_CHACHA20_POLY1305_SHA256,
	ngtcp2_integration_test_teardown)

#ifndef HAVE_LIBRESSL
ISC_TEST_ENTRY_CUSTOM(
	ngtcp2_integration_incompatible_version_negotiation_connect_TLS_AES_128_CCM_SHA256_test,
	ngtcp2_integration_test_setup_TLS_AES_128_CCM_SHA256,
	ngtcp2_integration_test_teardown)
#endif /* HAVE_LIBRESSL */

ISC_TEST_ENTRY_CUSTOM(
	ngtcp2_integration_incompatible_version_negotiation_connect_TLS_AES_128_CCM_8_SHA256_failure_test,
	ngtcp2_integration_test_setup_TLS_AES_128_CCM_8_SHA256,
	ngtcp2_integration_test_teardown)

ISC_TEST_ENTRY_CUSTOM(ngtcp2_integration_QUICv1_connect_test,
		      ngtcp2_integration_test_setup,
		      ngtcp2_integration_test_teardown)

ISC_TEST_ENTRY_CUSTOM(
	ngtcp2_integration_QUICv1_connect_TLS_AES_128_GCM_SHA256_test,
	ngtcp2_integration_test_setup_TLS_AES_128_GCM_SHA256,
	ngtcp2_integration_test_teardown)

ISC_TEST_ENTRY_CUSTOM(
	ngtcp2_integration_QUICv1_connect_TLS_AES_256_GCM_SHA384_test,
	ngtcp2_integration_test_setup_TLS_AES_256_GCM_SHA384,
	ngtcp2_integration_test_teardown)

ISC_TEST_ENTRY_CUSTOM(
	ngtcp2_integration_QUICv1_connect_TLS_CHACHA20_POLY1305_SHA256_test,
	ngtcp2_integration_test_setup_TLS_CHACHA20_POLY1305_SHA256,
	ngtcp2_integration_test_teardown)

#ifndef HAVE_LIBRESSL
ISC_TEST_ENTRY_CUSTOM(
	ngtcp2_integration_QUICv1_connect_TLS_AES_128_CCM_SHA256_test,
	ngtcp2_integration_test_setup_TLS_AES_128_CCM_SHA256,
	ngtcp2_integration_test_teardown)
#endif /* HAVE_LIBRESSL */

ISC_TEST_ENTRY_CUSTOM(
	ngtcp2_integration_QUICv1_connect_TLS_AES_128_CCM_8_SHA256_failure_test,
	ngtcp2_integration_test_setup_TLS_AES_128_CCM_8_SHA256,
	ngtcp2_integration_test_teardown)

ISC_TEST_ENTRY_CUSTOM(ngtcp2_integration_QUICv2_connect_test,
		      ngtcp2_integration_test_setup,
		      ngtcp2_integration_test_teardown)

ISC_TEST_ENTRY_CUSTOM(
	ngtcp2_integration_QUICv2_connect_TLS_AES_128_GCM_SHA256_test,
	ngtcp2_integration_test_setup_TLS_AES_128_GCM_SHA256,
	ngtcp2_integration_test_teardown)

ISC_TEST_ENTRY_CUSTOM(
	ngtcp2_integration_QUICv2_connect_TLS_AES_256_GCM_SHA384_test,
	ngtcp2_integration_test_setup_TLS_AES_256_GCM_SHA384,
	ngtcp2_integration_test_teardown)

ISC_TEST_ENTRY_CUSTOM(
	ngtcp2_integration_QUICv2_connect_TLS_CHACHA20_POLY1305_SHA256_test,
	ngtcp2_integration_test_setup_TLS_CHACHA20_POLY1305_SHA256,
	ngtcp2_integration_test_teardown)

#ifndef HAVE_LIBRESSL
ISC_TEST_ENTRY_CUSTOM(
	ngtcp2_integration_QUICv2_connect_TLS_AES_128_CCM_SHA256_test,
	ngtcp2_integration_test_setup_TLS_AES_128_CCM_SHA256,
	ngtcp2_integration_test_teardown)
#endif /* HAVE_LIBRESSL */

ISC_TEST_ENTRY_CUSTOM(
	ngtcp2_integration_QUICv2_connect_TLS_AES_128_CCM_8_SHA256_failure_test,
	ngtcp2_integration_test_setup_TLS_AES_128_CCM_8_SHA256,
	ngtcp2_integration_test_teardown)

#ifdef EXTRA_NATIVE_AND_COMPAT_TESTS
ISC_TEST_ENTRY_CUSTOM(ngtcp2_integration_connect_native_to_compat_test,
		      ngtcp2_integration_native_to_compat_test_setup,
		      ngtcp2_integration_test_teardown)

ISC_TEST_ENTRY_CUSTOM(
	ngtcp2_integration_connect_native_to_compat_TLS_AES_128_GCM_SHA256_test,
	ngtcp2_integration_native_to_compat_test_setup_TLS_AES_128_GCM_SHA256,
	ngtcp2_integration_test_teardown)

ISC_TEST_ENTRY_CUSTOM(
	ngtcp2_integration_connect_native_to_compat_TLS_AES_256_GCM_SHA384_test,
	ngtcp2_integration_native_to_compat_test_setup_TLS_AES_256_GCM_SHA384,
	ngtcp2_integration_test_teardown)

ISC_TEST_ENTRY_CUSTOM(
	ngtcp2_integration_connect_native_to_compat_TLS_CHACHA20_POLY1305_SHA256_test,
	ngtcp2_integration_native_to_compat_test_setup_TLS_CHACHA20_POLY1305_SHA256,
	ngtcp2_integration_test_teardown)

#ifndef HAVE_LIBRESSL
ISC_TEST_ENTRY_CUSTOM(
	ngtcp2_integration_connect_native_to_compat_TLS_AES_128_CCM_SHA256_test,
	ngtcp2_integration_native_to_compat_test_setup_TLS_AES_128_CCM_SHA256,
	ngtcp2_integration_test_teardown)
#endif /* HAVE_LIBRESSL */

ISC_TEST_ENTRY_CUSTOM(
	ngtcp2_integration_connect_native_to_compat_TLS_AES_128_CCM_8_SHA256_failure_test,
	ngtcp2_integration_native_to_compat_test_setup_TLS_AES_128_CCM_8_SHA256,
	ngtcp2_integration_test_teardown)

ISC_TEST_ENTRY_CUSTOM(
	ngtcp2_integration_incompatible_version_negotiation_connect_native_to_compat_test,
	ngtcp2_integration_native_to_compat_test_setup,
	ngtcp2_integration_test_teardown)

ISC_TEST_ENTRY_CUSTOM(
	ngtcp2_integration_incompatible_version_negotiation_connect_native_to_compat_TLS_AES_128_GCM_SHA256_test,
	ngtcp2_integration_native_to_compat_test_setup_TLS_AES_128_GCM_SHA256,
	ngtcp2_integration_test_teardown)

ISC_TEST_ENTRY_CUSTOM(
	ngtcp2_integration_incompatible_version_negotiation_connect_native_to_compat_TLS_AES_256_GCM_SHA384_test,
	ngtcp2_integration_native_to_compat_test_setup_TLS_AES_256_GCM_SHA384,
	ngtcp2_integration_test_teardown)

ISC_TEST_ENTRY_CUSTOM(
	ngtcp2_integration_incompatible_version_negotiation_connect_native_to_compat_TLS_CHACHA20_POLY1305_SHA256_test,
	ngtcp2_integration_native_to_compat_test_setup_TLS_CHACHA20_POLY1305_SHA256,
	ngtcp2_integration_test_teardown)

#ifndef HAVE_LIBRESSL
ISC_TEST_ENTRY_CUSTOM(
	ngtcp2_integration_incompatible_version_negotiation_connect_native_to_compat_TLS_AES_128_CCM_SHA256_test,
	ngtcp2_integration_native_to_compat_test_setup_TLS_AES_128_CCM_SHA256,
	ngtcp2_integration_test_teardown)
#endif /* HAVE_LIBRESSL */

ISC_TEST_ENTRY_CUSTOM(
	ngtcp2_integration_incompatible_version_negotiation_connect_native_to_compat_TLS_AES_128_CCM_8_SHA256_failure_test,
	ngtcp2_integration_native_to_compat_test_setup_TLS_AES_128_CCM_8_SHA256,
	ngtcp2_integration_test_teardown)

ISC_TEST_ENTRY_CUSTOM(ngtcp2_integration_QUICv1_connect_native_to_compat_test,
		      ngtcp2_integration_native_to_compat_test_setup,
		      ngtcp2_integration_test_teardown)

ISC_TEST_ENTRY_CUSTOM(
	ngtcp2_integration_QUICv1_connect_native_to_compat_TLS_AES_128_GCM_SHA256_test,
	ngtcp2_integration_native_to_compat_test_setup_TLS_AES_128_GCM_SHA256,
	ngtcp2_integration_test_teardown)

ISC_TEST_ENTRY_CUSTOM(
	ngtcp2_integration_QUICv1_connect_native_to_compat_TLS_AES_256_GCM_SHA384_test,
	ngtcp2_integration_native_to_compat_test_setup_TLS_AES_256_GCM_SHA384,
	ngtcp2_integration_test_teardown)

ISC_TEST_ENTRY_CUSTOM(
	ngtcp2_integration_QUICv1_connect_native_to_compat_TLS_CHACHA20_POLY1305_SHA256_test,
	ngtcp2_integration_native_to_compat_test_setup_TLS_CHACHA20_POLY1305_SHA256,
	ngtcp2_integration_test_teardown)

#ifndef HAVE_LIBRESSL
ISC_TEST_ENTRY_CUSTOM(
	ngtcp2_integration_QUICv1_connect_native_to_compat_TLS_AES_128_CCM_SHA256_test,
	ngtcp2_integration_native_to_compat_test_setup_TLS_AES_128_CCM_SHA256,
	ngtcp2_integration_test_teardown)
#endif /* HAVE_LIBRESSL */

ISC_TEST_ENTRY_CUSTOM(
	ngtcp2_integration_QUICv1_connect_native_to_compat_TLS_AES_128_CCM_8_SHA256_failure_test,
	ngtcp2_integration_native_to_compat_test_setup_TLS_AES_128_CCM_8_SHA256,
	ngtcp2_integration_test_teardown)

ISC_TEST_ENTRY_CUSTOM(ngtcp2_integration_QUICv2_connect_native_to_compat_test,
		      ngtcp2_integration_native_to_compat_test_setup,
		      ngtcp2_integration_test_teardown)

ISC_TEST_ENTRY_CUSTOM(
	ngtcp2_integration_QUICv2_connect_native_to_compat_TLS_AES_128_GCM_SHA256_test,
	ngtcp2_integration_native_to_compat_test_setup_TLS_AES_128_GCM_SHA256,
	ngtcp2_integration_test_teardown)

ISC_TEST_ENTRY_CUSTOM(
	ngtcp2_integration_QUICv2_connect_native_to_compat_TLS_AES_256_GCM_SHA384_test,
	ngtcp2_integration_native_to_compat_test_setup_TLS_AES_256_GCM_SHA384,
	ngtcp2_integration_test_teardown)

ISC_TEST_ENTRY_CUSTOM(
	ngtcp2_integration_QUICv2_connect_native_to_compat_TLS_CHACHA20_POLY1305_SHA256_test,
	ngtcp2_integration_native_to_compat_test_setup_TLS_CHACHA20_POLY1305_SHA256,
	ngtcp2_integration_test_teardown)

#ifndef HAVE_LIBRESSL
ISC_TEST_ENTRY_CUSTOM(
	ngtcp2_integration_QUICv2_connect_native_to_compat_TLS_AES_128_CCM_SHA256_test,
	ngtcp2_integration_native_to_compat_test_setup_TLS_AES_128_CCM_SHA256,
	ngtcp2_integration_test_teardown)
#endif /* HAVE_LIBRESSL */

ISC_TEST_ENTRY_CUSTOM(
	ngtcp2_integration_QUICv2_connect_native_to_compat_TLS_AES_128_CCM_8_SHA256_failure_test,
	ngtcp2_integration_native_to_compat_test_setup_TLS_AES_128_CCM_8_SHA256,
	ngtcp2_integration_test_teardown)

ISC_TEST_ENTRY_CUSTOM(ngtcp2_integration_connect_compat_to_native_test,
		      ngtcp2_integration_compat_to_native_test_setup,
		      ngtcp2_integration_test_teardown)

ISC_TEST_ENTRY_CUSTOM(
	ngtcp2_integration_connect_compat_to_native_TLS_AES_128_GCM_SHA256_test,
	ngtcp2_integration_compat_to_native_test_setup_TLS_AES_128_GCM_SHA256,
	ngtcp2_integration_test_teardown)

ISC_TEST_ENTRY_CUSTOM(
	ngtcp2_integration_connect_compat_to_native_TLS_AES_256_GCM_SHA384_test,
	ngtcp2_integration_compat_to_native_test_setup_TLS_AES_256_GCM_SHA384,
	ngtcp2_integration_test_teardown)

ISC_TEST_ENTRY_CUSTOM(
	ngtcp2_integration_connect_compat_to_native_TLS_CHACHA20_POLY1305_SHA256_test,
	ngtcp2_integration_compat_to_native_test_setup_TLS_CHACHA20_POLY1305_SHA256,
	ngtcp2_integration_test_teardown)

#ifndef HAVE_LIBRESSL
ISC_TEST_ENTRY_CUSTOM(
	ngtcp2_integration_connect_compat_to_native_TLS_AES_128_CCM_SHA256_test,
	ngtcp2_integration_compat_to_native_test_setup_TLS_AES_128_CCM_SHA256,
	ngtcp2_integration_test_teardown)
#endif /* HAVE_LIBRESSL */

ISC_TEST_ENTRY_CUSTOM(
	ngtcp2_integration_connect_compat_to_native_TLS_AES_128_CCM_8_SHA256_failure_test,
	ngtcp2_integration_compat_to_native_test_setup_TLS_AES_128_CCM_8_SHA256,
	ngtcp2_integration_test_teardown)

ISC_TEST_ENTRY_CUSTOM(
	ngtcp2_integration_incompatible_version_negotiation_connect_compat_to_native_test,
	ngtcp2_integration_compat_to_native_test_setup,
	ngtcp2_integration_test_teardown)

ISC_TEST_ENTRY_CUSTOM(
	ngtcp2_integration_incompatible_version_negotiation_connect_compat_to_native_TLS_AES_128_GCM_SHA256_test,
	ngtcp2_integration_compat_to_native_test_setup_TLS_AES_128_GCM_SHA256,
	ngtcp2_integration_test_teardown)

ISC_TEST_ENTRY_CUSTOM(
	ngtcp2_integration_incompatible_version_negotiation_connect_compat_to_native_TLS_AES_256_GCM_SHA384_test,
	ngtcp2_integration_compat_to_native_test_setup_TLS_AES_256_GCM_SHA384,
	ngtcp2_integration_test_teardown)

ISC_TEST_ENTRY_CUSTOM(
	ngtcp2_integration_incompatible_version_negotiation_connect_compat_to_native_TLS_CHACHA20_POLY1305_SHA256_test,
	ngtcp2_integration_compat_to_native_test_setup_TLS_CHACHA20_POLY1305_SHA256,
	ngtcp2_integration_test_teardown)

#ifndef HAVE_LIBRESSL
ISC_TEST_ENTRY_CUSTOM(
	ngtcp2_integration_incompatible_version_negotiation_connect_compat_to_native_TLS_AES_128_CCM_SHA256_test,
	ngtcp2_integration_compat_to_native_test_setup_TLS_AES_128_CCM_SHA256,
	ngtcp2_integration_test_teardown)
#endif /* HAVE_LIBRESSL */

ISC_TEST_ENTRY_CUSTOM(
	ngtcp2_integration_incompatible_version_negotiation_connect_compat_to_native_TLS_AES_128_CCM_8_SHA256_failure_test,
	ngtcp2_integration_compat_to_native_test_setup_TLS_AES_128_CCM_8_SHA256,
	ngtcp2_integration_test_teardown)

ISC_TEST_ENTRY_CUSTOM(ngtcp2_integration_QUICv1_connect_compat_to_native_test,
		      ngtcp2_integration_compat_to_native_test_setup,
		      ngtcp2_integration_test_teardown)

ISC_TEST_ENTRY_CUSTOM(
	ngtcp2_integration_QUICv1_connect_compat_to_native_TLS_AES_128_GCM_SHA256_test,
	ngtcp2_integration_compat_to_native_test_setup_TLS_AES_128_GCM_SHA256,
	ngtcp2_integration_test_teardown)

ISC_TEST_ENTRY_CUSTOM(
	ngtcp2_integration_QUICv1_connect_compat_to_native_TLS_AES_256_GCM_SHA384_test,
	ngtcp2_integration_compat_to_native_test_setup_TLS_AES_256_GCM_SHA384,
	ngtcp2_integration_test_teardown)

ISC_TEST_ENTRY_CUSTOM(
	ngtcp2_integration_QUICv1_connect_compat_to_native_TLS_CHACHA20_POLY1305_SHA256_test,
	ngtcp2_integration_compat_to_native_test_setup_TLS_CHACHA20_POLY1305_SHA256,
	ngtcp2_integration_test_teardown)

#ifndef HAVE_LIBRESSL
ISC_TEST_ENTRY_CUSTOM(
	ngtcp2_integration_QUICv1_connect_compat_to_native_TLS_AES_128_CCM_SHA256_test,
	ngtcp2_integration_compat_to_native_test_setup_TLS_AES_128_CCM_SHA256,
	ngtcp2_integration_test_teardown)
#endif /* HAVE_LIBRESSL */

ISC_TEST_ENTRY_CUSTOM(
	ngtcp2_integration_QUICv1_connect_compat_to_native_TLS_AES_128_CCM_8_SHA256_failure_test,
	ngtcp2_integration_compat_to_native_test_setup_TLS_AES_128_CCM_8_SHA256,
	ngtcp2_integration_test_teardown)

ISC_TEST_ENTRY_CUSTOM(ngtcp2_integration_QUICv2_connect_compat_to_native_test,
		      ngtcp2_integration_compat_to_native_test_setup,
		      ngtcp2_integration_test_teardown)

ISC_TEST_ENTRY_CUSTOM(
	ngtcp2_integration_QUICv2_connect_compat_to_native_TLS_AES_128_GCM_SHA256_test,
	ngtcp2_integration_compat_to_native_test_setup_TLS_AES_128_GCM_SHA256,
	ngtcp2_integration_test_teardown)

ISC_TEST_ENTRY_CUSTOM(
	ngtcp2_integration_QUICv2_connect_compat_to_native_TLS_AES_256_GCM_SHA384_test,
	ngtcp2_integration_compat_to_native_test_setup_TLS_AES_256_GCM_SHA384,
	ngtcp2_integration_test_teardown)

ISC_TEST_ENTRY_CUSTOM(
	ngtcp2_integration_QUICv2_connect_compat_to_native_TLS_CHACHA20_POLY1305_SHA256_test,
	ngtcp2_integration_compat_to_native_test_setup_TLS_CHACHA20_POLY1305_SHA256,
	ngtcp2_integration_test_teardown)

#ifndef HAVE_LIBRESSL
ISC_TEST_ENTRY_CUSTOM(
	ngtcp2_integration_QUICv2_connect_compat_to_native_TLS_AES_128_CCM_SHA256_test,
	ngtcp2_integration_compat_to_native_test_setup_TLS_AES_128_CCM_SHA256,
	ngtcp2_integration_test_teardown)
#endif /* HAVE_LIBRESSL */

ISC_TEST_ENTRY_CUSTOM(
	ngtcp2_integration_QUICv2_connect_compat_to_native_TLS_AES_128_CCM_8_SHA256_failure_test,
	ngtcp2_integration_compat_to_native_test_setup_TLS_AES_128_CCM_8_SHA256,
	ngtcp2_integration_test_teardown)

#endif /* EXTRA_NATIVE_AND_COMPAT_TESTS */

ISC_TEST_ENTRY_CUSTOM(ngtcp2_integration_regular_and_retry_tokens_test,
		      ngtcp2_integration_test_setup,
		      ngtcp2_integration_test_teardown)
ISC_TEST_LIST_END

ISC_TEST_MAIN_CUSTOM(ngtcp2_integration_setup, ngtcp2_integration_teardown);
