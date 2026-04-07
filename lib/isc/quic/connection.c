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

#include <stddef.h>
#include <stdint.h>

#include <ngtcp2/ngtcp2.h>
#include <openssl/ssl.h>
// TODO(aydin) drop this
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_ossl.h>

#include <isc/bit.h>
#include <isc/hashmap.h>
#include <isc/list.h>
#include <isc/log.h>
#include <isc/magic.h>
#include <isc/mem.h>
#include <isc/quic.h>
#include <isc/random.h>
#include <isc/refcount.h>
#include <isc/region.h>
#include <isc/result.h>
#include <isc/sockaddr.h>
#include <isc/time.h>
#include <isc/tls.h>
#include <isc/types.h>
#include <isc/util.h>

#define QUIC_STREAM_LIMIT 16

#ifdef ISC_QUIC_STATE_CHECK
#define CHECK_STATE(conn, ...)                                         \
	({                                                             \
		__label__ out;                                         \
		quic_conn_state_t _allowed[] = { __VA_ARGS__ };        \
		for (size_t _i = 0; _i < ARRAY_SIZE(_allowed); _i++) { \
			if ((conn)->state == _allowed[_i]) {           \
				goto out;                              \
			}                                              \
		}                                                      \
		UNREACHABLE();                                         \
	out:;                                                          \
	})
#else /* ISC_QUIC_STATE_CHECK */
#define CHECK_STATE(actual, ...)
#endif /* ISC_QUIC_STATE_CHECK */

typedef struct quic_conn_state_node quic_conn_state_node_t;
typedef struct quic_stream quic_stream_t;

typedef isc_result_t (*pull_packet_fn)(isc_quic_conn_t *conn, uint8_t *out,
				       size_t len, size_t *written,
				       isc_nanosecs_t (*timestamp_fn)(void));

typedef enum quic_conn_state {
	QUIC_CONN_STATE_INVALID = 0x00,
	QUIC_CONN_STATE_HANDSHAKE = 0x01,
	QUIC_CONN_STATE_CONNECTED = 0x02,
	QUIC_CONN_STATE_CLOSED = 0x03,
	QUIC_CONN_STATE_TERMINATED = 0x04,
} quic_conn_state_t;

struct isc_quic_conn {
	uint32_t magic;
	quic_conn_state_t state;
	isc_quic_cid_map_t *cidmap;
	ngtcp2_crypto_ossl_ctx *ossl_ctx;
	ngtcp2_crypto_conn_ref crypto_ref;
	isc_quic_conn_callbacks_t *cb;
	void *cbarg;
	ISC_LIST(isc_quic_stream_data_t) incoming_stream_data;
	ISC_LIST(isc_quic_stream_data_t) outgoing_stream_data;
	ISC_LIST(quic_stream_t) streams;
	/*
	 * isc_mem_t is stored inside `mem.user_data`
	 */
	ngtcp2_mem mem;
	ngtcp2_path path;
	ngtcp2_ccerr ccerr;
	ngtcp2_conn *inner;
};

struct quic_conn_state_node {
	pull_packet_fn pull_packet;
};

struct quic_stream {
	int64_t id;
	size_t last_acked_offset;
	ISC_LIST(isc_quic_stream_data_t) ack_data;
	ISC_LINK(quic_stream_t) link;
};

constexpr uint32_t conn_magic = ISC_MAGIC('Q', 'U', 'I', 'c');

constexpr size_t initial_max_stream_data = 128 * 1024;

static const uint32_t preferred_versions[] = {
	NGTCP2_PROTO_VER_V2,
	NGTCP2_PROTO_VER_V1,
};

/*
 * `ngtcp2_callbacks` functions
 */

static void
rand_cb(uint8_t *dest, size_t destlen, const ngtcp2_rand_ctx *rand_ctx);

static int
get_new_connection_id_cb(ngtcp2_conn *ngconn, ngtcp2_cid *cid, uint8_t *token,
			 size_t cidlen, void *user_data);

static int
recv_stream_data_cb(ngtcp2_conn *ngconn, uint32_t flags, int64_t stream_id,
		    uint64_t offset, const uint8_t *data, size_t datalen,
		    void *user_data, void *stream_user_data);

static int
acked_stream_data_offset_cb(ngtcp2_conn *ngconn, int64_t stream_id,
			    uint64_t offset, uint64_t datalen, void *user_data,
			    void *stream_user_data);

static int
stream_open_cb(ngtcp2_conn *conn, int64_t stream_id, void *user_data);

static int
stream_close_cb(ngtcp2_conn *ngconn, uint32_t flags, int64_t stream_id,
		uint64_t app_error_code, void *user_data,
		void *stream_user_data);

static int
handshake_completed_cb(ngtcp2_conn *ngconn, void *user_data);

static int
get_path_challenge_data_cb(ngtcp2_conn *ngconn, uint8_t *data, void *user_data);

#if NGTCP2_VERSION_NUM >= 0x011600
static int
get_new_connection_id2_cb(ngtcp2_conn *ngconn, ngtcp2_cid *ngcid,
			  ngtcp2_stateless_reset_token *token, size_t cidlen,
			  void *user_data);

static int
get_path_challenge_data2_cb(ngtcp2_conn *ngconn,
			    ngtcp2_path_challenge_data *data, void *user_data);
#endif /* NGTCP2_VERSION_NUM >= 0x011600 */

static const ngtcp2_callbacks client_cb = {
	.client_initial = ngtcp2_crypto_client_initial_cb,
	.recv_crypto_data = ngtcp2_crypto_recv_crypto_data_cb,
	.handshake_completed = handshake_completed_cb,
	.encrypt = ngtcp2_crypto_encrypt_cb,
	.decrypt = ngtcp2_crypto_decrypt_cb,
	.hp_mask = ngtcp2_crypto_hp_mask_cb,
	.recv_stream_data = recv_stream_data_cb,
	.acked_stream_data_offset = acked_stream_data_offset_cb,
	.stream_open = stream_open_cb,
	.stream_close = stream_close_cb,
	.recv_retry = ngtcp2_crypto_recv_retry_cb,
	.rand = rand_cb,
	.get_new_connection_id = get_new_connection_id_cb,
	.update_key = ngtcp2_crypto_update_key_cb,
	.delete_crypto_aead_ctx = ngtcp2_crypto_delete_crypto_aead_ctx_cb,
	.delete_crypto_cipher_ctx = ngtcp2_crypto_delete_crypto_cipher_ctx_cb,
	.get_path_challenge_data = get_path_challenge_data_cb,
	.version_negotiation = ngtcp2_crypto_version_negotiation_cb,
#if NGTCP2_VERSION_NUM >= 0x011600
	.get_new_connection_id2 = get_new_connection_id2_cb,
	.get_path_challenge_data2 = get_path_challenge_data2_cb,
#endif /* NGTCP2_VERSION_NUM >= 0x011600 */
};

static const ngtcp2_callbacks server_cb = {
	.recv_client_initial = ngtcp2_crypto_recv_client_initial_cb,
	.recv_crypto_data = ngtcp2_crypto_recv_crypto_data_cb,
	.handshake_completed = handshake_completed_cb,
	.encrypt = ngtcp2_crypto_encrypt_cb,
	.decrypt = ngtcp2_crypto_decrypt_cb,
	.hp_mask = ngtcp2_crypto_hp_mask_cb,
	.recv_stream_data = recv_stream_data_cb,
	.acked_stream_data_offset = acked_stream_data_offset_cb,
	.stream_open = stream_open_cb,
	.stream_close = stream_close_cb,
	.rand = rand_cb,
	.get_new_connection_id = get_new_connection_id_cb,
	.update_key = ngtcp2_crypto_update_key_cb,
	.delete_crypto_aead_ctx = ngtcp2_crypto_delete_crypto_aead_ctx_cb,
	.delete_crypto_cipher_ctx = ngtcp2_crypto_delete_crypto_cipher_ctx_cb,
	.get_path_challenge_data = get_path_challenge_data_cb,
	.version_negotiation = ngtcp2_crypto_version_negotiation_cb,
#if NGTCP2_VERSION_NUM >= 0x011600
	.get_new_connection_id2 = get_new_connection_id2_cb,
	.get_path_challenge_data2 = get_path_challenge_data2_cb,
#endif /* NGTCP2_VERSION_NUM >= 0x011600 */
};

/*
 * isc_quic_conn_t state functions
 */

static isc_result_t
pull_packet_invalid(isc_quic_conn_t *conn, uint8_t *out, size_t len,
		    size_t *written, isc_nanosecs_t (*timestamp_fn)(void));

static isc_result_t
pull_packet_nodata(isc_quic_conn_t *conn, uint8_t *out, size_t len,
		   size_t *written, isc_nanosecs_t (*timestamp_fn)(void));

static isc_result_t
pull_packet_connected(isc_quic_conn_t *conn, uint8_t *out, size_t len,
		      size_t *written, isc_nanosecs_t (*timestamp_fn)(void));

static isc_result_t
pull_packet_closed(isc_quic_conn_t *conn, uint8_t *out, size_t len,
		   size_t *written, isc_nanosecs_t (*timestamp_fn)(void));

static isc_result_t
pull_packet_terminated(isc_quic_conn_t *conn, uint8_t *out, size_t len,
		       size_t *written, isc_nanosecs_t (*timestamp_fn)(void));

static quic_conn_state_node_t state_table[] = {
	[QUIC_CONN_STATE_INVALID] = { pull_packet_invalid },
	[QUIC_CONN_STATE_HANDSHAKE] = { pull_packet_nodata },
	[QUIC_CONN_STATE_CONNECTED] = { pull_packet_connected },
	[QUIC_CONN_STATE_CLOSED] = { pull_packet_closed },
	[QUIC_CONN_STATE_TERMINATED] = { pull_packet_terminated },
};

static isc_result_t
liberr_to_result(ngtcp2_ssize r) {
	switch (r) {
	case 0:
		return ISC_R_UNEXPECTEDEND;
	case NGTCP2_ERR_NOBUF:
		return ISC_R_NOSPACE;
	case NGTCP2_ERR_PROTO:
		return ISC_R_INVALIDPROTO;
	case NGTCP2_ERR_STREAM_IN_USE:
		return ISC_R_EXISTS;
	case NGTCP2_ERR_CRYPTO:
	case NGTCP2_ERR_DECRYPT:
		return ISC_R_CRYPTOFAILURE;
	case NGTCP2_ERR_NOMEM:
		return ISC_R_NOMEMORY;
		/*
	case NGTCP2_ERR_STREAM_NOT_FOUND:
		return ISC_R_NOTFOUND;
	case NGTCP2_ERR_PKT_NUM_EXHAUSTED:
		return ISC_R_NOMORE;
		*/
	default:
		return ISC_R_FAILURE;
	}
}

static isc_result_t
pull_packet_invalid(isc_quic_conn_t *conn ISC_ATTR_UNUSED,
		    uint8_t *out ISC_ATTR_UNUSED, size_t len ISC_ATTR_UNUSED,
		    size_t *written ISC_ATTR_UNUSED,
		    ISC_ATTR_UNUSED isc_nanosecs_t (*timestamp_fn)(void)) {
	UNREACHABLE();
}

static isc_result_t
pull_packet_nodata(isc_quic_conn_t *conn, uint8_t *out, size_t len,
		   size_t *written, isc_nanosecs_t (*timestamp_fn)(void)) {
	ngtcp2_ssize r;

	CHECK_STATE(conn, QUIC_CONN_STATE_HANDSHAKE, QUIC_CONN_STATE_CONNECTED);

	r = ngtcp2_conn_writev_stream(conn->inner, &conn->path, NULL, out, len,
				      NULL, NGTCP2_WRITE_STREAM_FLAG_NONE, -1,
				      NULL, 0, timestamp_fn());

	ngtcp2_conn_update_pkt_tx_time(conn->inner, timestamp_fn());

	if (r <= 0) {
		*written = 0;
		return liberr_to_result(r);
	}

	*written = r;
	return ISC_R_SUCCESS;
}

static isc_result_t
pull_packet_connected(isc_quic_conn_t *conn, uint8_t *out, size_t len,
		      size_t *written, isc_nanosecs_t (*timestamp_fn)(void)) {
	isc_quic_stream_data_t *data;
	isc_nanosecs_t timestamp;
	quic_stream_t *stream;
	ngtcp2_ssize r;
	int64_t stream_id;
	size_t total;
	ssize_t single;
	uint32_t flags;

	CHECK_STATE(conn, QUIC_CONN_STATE_CONNECTED);

	if (ISC_LIST_EMPTY(conn->outgoing_stream_data)) {
		return pull_packet_nodata(conn, out, len, written,
					  timestamp_fn);
	}

	timestamp = timestamp_fn();
	total = 0;
	flags = NGTCP2_WRITE_STREAM_FLAG_MORE;
	while (flags != 0x00) {
		data = ISC_LIST_HEAD(conn->outgoing_stream_data);

		if (ISC_LIST_NEXT(data, link) == NULL) {
			flags = 0x00;
		}

		stream_id = data->stream_id;
		r = ngtcp2_conn_write_stream(
			conn->inner, &conn->path, NULL, out, len, &single,
			flags, stream_id, data->bytes, data->length, timestamp);

		if (r < 0) {
			switch (r) {
			case NGTCP2_ERR_STREAM_DATA_BLOCKED:
				UNREACHABLE();
			case NGTCP2_ERR_WRITE_MORE:
				break;
			default:
				UNREACHABLE();
			}
		}

		ISC_LIST_UNLINK(conn->outgoing_stream_data, data, link);
		stream = ngtcp2_conn_get_stream_user_data(conn->inner,
							  stream_id);
		INSIST(stream != NULL);
		ISC_LIST_APPEND(stream->ack_data, data, link);

		if (r > 0) {
			total += r;
		}

		if (r == 0) {
			break;
		}
	}

	ngtcp2_conn_update_pkt_tx_time(conn->inner, timestamp_fn());

	*written = total;
	return ISC_R_SUCCESS;
}

static isc_result_t
pull_packet_closed(isc_quic_conn_t *conn, uint8_t *out, size_t len,
		   size_t *written, isc_nanosecs_t (*timestamp_fn)(void)) {
	ngtcp2_ssize r;

	CHECK_STATE(conn, QUIC_CONN_STATE_CLOSED);

	r = ngtcp2_conn_write_connection_close(conn->inner, &conn->path, NULL,
					       out, len, &conn->ccerr,
					       timestamp_fn());
	if (r <= 0) {
		*written = 0;
		return liberr_to_result(r);
	}

	*written = r;
	return ISC_R_SUCCESS;
}

static isc_result_t
pull_packet_terminated(isc_quic_conn_t *conn ISC_ATTR_UNUSED,
		       uint8_t *out ISC_ATTR_UNUSED, size_t len ISC_ATTR_UNUSED,
		       size_t *written,
		       ISC_ATTR_UNUSED isc_nanosecs_t (*timestamp_fn)(void)) {
	*written = 0;
	return ISC_R_COMPLETE;
}

static ngtcp2_conn *
get_conn(ngtcp2_crypto_conn_ref *conn_ref) {
	isc_quic_conn_t *conn = conn_ref->user_data;
	return conn->inner;
}

static int
recv_stream_data_cb(ngtcp2_conn *ngconn ISC_ATTR_UNUSED, uint32_t flags,
		    int64_t stream_id, uint64_t offset, const uint8_t *data,
		    size_t datalen, void *user_data,
		    void *stream_user_data ISC_ATTR_UNUSED) {
	isc_quic_stream_data_t *incoming;
	isc_quic_conn_t *conn = user_data;

	incoming = isc_mem_get(conn->mem.user_data,
			       STRUCT_FLEX_SIZE(incoming, bytes, datalen));
	*incoming = (isc_quic_stream_data_t){
		.finish = (flags & NGTCP2_STREAM_DATA_FLAG_FIN) != 0x00,
		.zerortt = (flags & NGTCP2_STREAM_DATA_FLAG_0RTT) != 0x00,
		.offset = offset,
		.stream_id = stream_id,
		.length = datalen,
		.link = ISC_LINK_INITIALIZER,
	};
	memcpy(incoming->bytes, data, datalen);

	ISC_LIST_APPEND(conn->incoming_stream_data, incoming, link);

	return 0;
}

static int
acked_stream_data_offset_cb(ngtcp2_conn *ngconn ISC_ATTR_UNUSED,
			    int64_t stream_id, uint64_t offset,
			    uint64_t datalen, void *user_data,
			    void *stream_user_data) {
	isc_quic_stream_data_t *data;
	quic_stream_t *stream = stream_user_data;

	data = ISC_LIST_HEAD(stream->ack_data);

	INSIST(stream->id == stream_id);

	stream->last_acked_offset = offset + datalen;

	if (offset + datalen < stream->last_acked_offset + data->length) {
		return 0;
	}

	ISC_LIST_UNLINK(stream->ack_data, data, link);
	isc_quic_stream_data_destroy(user_data, &data);

	return 0;
}

static int
stream_open_cb(ngtcp2_conn *ngconn, int64_t stream_id, void *user_data) {
	isc_quic_conn_t *conn = user_data;
	quic_stream_t *stream;
	isc_result_t result;

	if (conn->cb != NULL && conn->cb->stream_opened != NULL) {
		result = conn->cb->stream_opened(conn->cbarg, stream_id);
		if (result != ISC_R_SUCCESS) {
			return NGTCP2_ERR_CALLBACK_FAILURE;
		}
	}

	stream = isc_mem_get(conn->mem.user_data, sizeof(*stream));
	*stream = (quic_stream_t){
		.id = stream_id,
		.ack_data = ISC_LIST_INITIALIZER,
		.link = ISC_LINK_INITIALIZER,
	};

	if (ngtcp2_conn_set_stream_user_data(ngconn, stream_id, stream) != 0) {
		isc_mem_put(conn->mem.user_data, stream, sizeof(*stream));
		return NGTCP2_ERR_CALLBACK_FAILURE;
	}

	ISC_LIST_APPEND(conn->streams, stream, link);

	return 0;
}

static int
stream_close_cb(ngtcp2_conn *ngconn ISC_ATTR_UNUSED, uint32_t flags,
		int64_t stream_id, uint64_t app_error_code, void *user_data,
		void *stream_user_data) {
	isc_quic_conn_t *conn = user_data;
	quic_stream_t *stream = stream_user_data;
	isc_result_t result;

	ISC_LIST_FOREACH(stream->ack_data, data, link) {
		ISC_LIST_DEQUEUE(stream->ack_data, data, link);
		isc_mem_put(conn->mem.user_data, data,
			    STRUCT_FLEX_SIZE(data, bytes, data->length));
	}

	if (conn->cb != NULL && conn->cb->stream_closed != NULL) {
		result = conn->cb->stream_closed(
			conn->cbarg, stream_id,
			flags & NGTCP2_STREAM_CLOSE_FLAG_APP_ERROR_CODE_SET,
			app_error_code);
		if (result != ISC_R_SUCCESS) {
			return NGTCP2_ERR_CALLBACK_FAILURE;
		}
	}

	return 0;
}

static void
rand_cb(uint8_t *dest, size_t destlen,
	const ngtcp2_rand_ctx *rand_ctx ISC_ATTR_UNUSED) {
	isc_random_buf(dest, destlen);
}

static int
get_new_connection_id_cb(ngtcp2_conn *ngconn ISC_ATTR_UNUSED, ngtcp2_cid *ngcid,
			 uint8_t *token, size_t cidlen, void *user_data) {
	isc_quic_conn_t *conn = user_data;
	isc_result_t result;
	uint8_t buffer[NGTCP2_MAX_CIDLEN];

	isc_random_buf(token, NGTCP2_STATELESS_RESET_TOKENLEN);

	for (;;) {
		isc_random_buf(buffer, sizeof(buffer));
		result = isc_quic_cid_map_add_bytes(
			conn->cidmap, (isc_constregion_t){ buffer, cidlen },
			conn);
		if (result == ISC_R_SUCCESS) {
			ngcid->datalen = cidlen;
			memmove(ngcid->data, buffer, cidlen);
			return 0;
		}
	}

	UNREACHABLE();
}

static int
handshake_completed_cb(ngtcp2_conn *ngconn ISC_ATTR_UNUSED, void *user_data) {
	isc_quic_conn_t *conn = user_data;
	CHECK_STATE(conn, QUIC_CONN_STATE_HANDSHAKE);
	conn->state = QUIC_CONN_STATE_CONNECTED;
	return 0;
}

static int
get_path_challenge_data_cb(ngtcp2_conn *ngconn ISC_ATTR_UNUSED, uint8_t *data,
			   void *user_data ISC_ATTR_UNUSED) {
	isc_random_buf(data, NGTCP2_PATH_CHALLENGE_DATALEN);
	return 0;
}

#if NGTCP2_VERSION_NUM >= 0x011600
static int
get_new_connection_id2_cb(ngtcp2_conn *ngconn ISC_ATTR_UNUSED,
			  ngtcp2_cid *ngcid,
			  ngtcp2_stateless_reset_token *token, size_t cidlen,
			  void *user_data) {
	isc_quic_conn_t *conn = user_data;
	uint8_t buffer[NGTCP2_MAX_CIDLEN];
	isc_result_t result;

	isc_random_buf(token->data, sizeof(token->data));

	for (;;) {
		isc_random_buf(buffer, sizeof(buffer));
		result = isc_quic_cid_map_add_bytes(
			conn->cidmap, (isc_constregion_t){ buffer, cidlen },
			conn);
		if (result == ISC_R_SUCCESS) {
			ngcid->datalen = cidlen;
			memmove(ngcid->data, buffer, cidlen);
			return 0;
		}
	}

	UNREACHABLE();
}

static int
get_path_challenge_data2_cb(ngtcp2_conn *ngconn ISC_ATTR_UNUSED,
			    ngtcp2_path_challenge_data *data,
			    void *user_data ISC_ATTR_UNUSED) {
	isc_random_buf(data->data, NGTCP2_PATH_CHALLENGE_DATALEN);
	return 0;
}
#endif /* NGTCP2_VERSION_NUM >= 0x011600 */

static void
log_printf(void *user_data ISC_ATTR_UNUSED, const char *fmt, ...) {
	va_list ap;

	va_start(ap, fmt);
	isc_log_vwrite(ISC_LOGCATEGORY_GENERAL, ISC_LOGMODULE_OTHER,
		       ISC_LOG_DEBUG(99), fmt, ap);
	va_end(ap);
}

static void *
quic_malloc(size_t size, void *user_data) {
	return isc_mem_allocate(user_data, size);
}

static void
quic_free(void *ptr, void *user_data) {
	if (ptr != NULL) {
		isc_mem_free(user_data, ptr);
	}
}

static void *
quic_calloc(size_t nmemb, size_t size, void *user_data) {
	return isc_mem_callocate(user_data, nmemb, size);
}

static void *
quic_realloc(void *ptr, size_t size, void *user_data) {
	return isc_mem_reallocate(user_data, ptr, size);
}

isc_result_t
isc_quic_packet_info_decode(isc_constregion_t *scid, isc_constregion_t *dcid,
			    isc_constregion_t data) {
	ngtcp2_version_cid version;
	int r;

	REQUIRE(scid != NULL && dcid != NULL && data.base != NULL);

	r = ngtcp2_pkt_decode_version_cid(&version, data.base, data.length, 0);
	if (r != 0) {
		return liberr_to_result(r);
	}

	*scid = (isc_constregion_t){ version.scid, version.scidlen };
	*dcid = (isc_constregion_t){ version.dcid, version.dcidlen };

	return ISC_R_SUCCESS;
}

void
isc_quic_stream_data_destroy(isc_quic_conn_t *conn,
			     isc_quic_stream_data_t **datap) {
	isc_quic_stream_data_t *data;

	REQUIRE(conn != NULL && conn->magic == conn_magic);
	REQUIRE(datap != NULL && *datap != NULL);

	data = *datap;
	*datap = NULL;

	isc_mem_put(conn->mem.user_data, data,
		    STRUCT_FLEX_SIZE(data, bytes, data->length));
}

static void
common_settings(ngtcp2_settings *settings) {
	ngtcp2_settings_default(settings);

	settings->max_window = 6 * 1024;
	settings->max_stream_window = 6 * 1024;
	settings->cc_algo = NGTCP2_CC_ALGO_BBR;
	settings->max_tx_udp_payload_size = NGTCP2_MAX_UDP_PAYLOAD_SIZE;
	settings->preferred_versions = preferred_versions;
	settings->preferred_versionslen = ARRAY_SIZE(preferred_versions);
	/*
	 * libuv needs to expose relevant socket options for pmtud to work
	 * correctly [1].
	 * https://github.com/nodejs/node/blob/e6ef4774c202245e8daaa3cc48a44f3f38b99429/src/quic/session.cc#L348-L351
	 */
	settings->no_pmtud = 1;

	if (!isc_log_wouldlog(ISC_LOG_DEBUG(99))) {
		settings->log_printf = log_printf;
	}
}

static void
common_transport_params(ngtcp2_transport_params *params) {
	ngtcp2_transport_params_default(params);
	params->initial_max_stream_data_bidi_local = initial_max_stream_data;
	params->initial_max_stream_data_bidi_remote = initial_max_stream_data;
	params->initial_max_streams_bidi = 16;
	params->initial_max_streams_uni = 0;
	params->initial_max_data = 1024 * 1024;
	params->grease_quic_bit = 1;
}

isc_result_t
isc_quic_conn_client_create(isc_mem_t *mctx, isc_quic_cid_map_t *cidmap,
			    isc_quic_conn_callbacks_t *callbacks,
			    const isc_quic_client_conn_options_t *options,
			    isc_nanosecs_t timestamp, isc_quic_conn_t **connp) {
	ngtcp2_transport_params transport_params;
	ngtcp2_settings settings;
	isc_quic_conn_t *conn;
	ngtcp2_cid dcid, scid;
	isc_result_t result;
	isc_tls_t *tls;

	REQUIRE(connp != NULL && *connp == NULL);
	REQUIRE(options != NULL);

	common_settings(&settings);
	settings.initial_ts = timestamp;

	common_transport_params(&transport_params);

	conn = isc_mem_get(mctx, sizeof(*conn));
	*conn = (isc_quic_conn_t){
		.magic = conn_magic,
		.state = QUIC_CONN_STATE_HANDSHAKE,
		.cidmap = isc_quic_cid_map_ref(cidmap),
		.crypto_ref = { .get_conn = get_conn, .user_data = conn },
		.cb = callbacks,
		.incoming_stream_data = ISC_LIST_INITIALIZER,
		.outgoing_stream_data = ISC_LIST_INITIALIZER,
		.streams = ISC_LIST_INITIALIZER,
		.mem = { .user_data = isc_mem_ref(mctx),
			 .malloc = quic_malloc,
			 .free = quic_free,
			 .calloc = quic_calloc,
			 .realloc = quic_realloc },
		.path = { .local = { (ngtcp2_sockaddr *)&options->local->type.sa,
				     options->local->length },
			  .remote = { (ngtcp2_sockaddr *)&options->peer->type.sa,
				      options->peer->length } },
		.ccerr = { NGTCP2_CCERR_TYPE_TRANSPORT, NGTCP2_NO_ERROR, 0,
			   NULL, 0 },
	};

	tls = isc_tls_create(options->tlsctx);
	ngtcp2_crypto_ossl_ctx_new(&conn->ossl_ctx, tls);
	ngtcp2_crypto_ossl_configure_client_session(tls);
	SSL_set_connect_state(tls);
	SSL_set_app_data(tls, &conn->crypto_ref);
	SSL_set_tlsext_host_name(tls, options->sni);

	if (options->alpn.base != NULL) {
		SSL_set_alpn_protos(tls, options->alpn.base,
				    options->alpn.length);
	}

	dcid.datalen = NGTCP2_MIN_INITIAL_DCIDLEN;
	isc_random_buf(dcid.data, NGTCP2_MIN_INITIAL_DCIDLEN);
	scid.datalen = 8;
	isc_random_buf(scid.data, 8);

	if (ngtcp2_conn_client_new(&conn->inner, &dcid, &scid, &conn->path,
				   NGTCP2_PROTO_VER_V2, &client_cb, &settings,
				   &transport_params, &conn->mem, conn) != 0)
	{
		return ISC_R_FAILURE;
	}

	ngtcp2_conn_set_tls_native_handle(conn->inner, conn->ossl_ctx);

	*connp = conn;

	result = ISC_R_SUCCESS;

	return result;
}

isc_result_t
isc_quic_conn_server_create(isc_mem_t *mctx, isc_quic_cid_map_t *cidmap,
			    isc_quic_conn_callbacks_t *callbacks,
			    const isc_quic_server_conn_options_t *options,
			    isc_nanosecs_t timestamp, isc_quic_conn_t **connp) {
	ngtcp2_transport_params transport_params;
	ngtcp2_settings settings;
	isc_quic_conn_t *conn;
	ngtcp2_cid dcid, scid;
	isc_result_t result;
	isc_tls_t *tls;

	REQUIRE(connp != NULL && *connp == NULL);
	REQUIRE(options != NULL);

	scid.datalen = 8;
	isc_random_buf(scid.data, 8);
	ngtcp2_cid_init(&dcid, options->initial_scid.base,
			options->initial_scid.length);

	common_settings(&settings);
	settings.initial_ts = timestamp;

	common_transport_params(&transport_params);
	ngtcp2_cid_init(&transport_params.original_dcid,
			options->initial_dcid.base,
			options->initial_dcid.length);
	transport_params.original_dcid_present = 1;

	conn = isc_mem_get(mctx, sizeof(*conn));
	*conn = (isc_quic_conn_t){
		.magic = conn_magic,
		.state = QUIC_CONN_STATE_HANDSHAKE,
		.cidmap = isc_quic_cid_map_ref(cidmap),
		.crypto_ref = { .get_conn = get_conn, .user_data = conn },
		.cb = callbacks,
		.incoming_stream_data = ISC_LIST_INITIALIZER,
		.outgoing_stream_data = ISC_LIST_INITIALIZER,
		.streams = ISC_LIST_INITIALIZER,
		.mem = { .user_data = isc_mem_ref(mctx),
			 .malloc = quic_malloc,
			 .free = quic_free,
			 .calloc = quic_calloc,
			 .realloc = quic_realloc },
		.path = { .local = { (ngtcp2_sockaddr *)&options->local->type.sa,
				     options->local->length },
			  .remote = { (ngtcp2_sockaddr *)&options->peer->type.sa,
				      options->peer->length } },
		.ccerr = { NGTCP2_CCERR_TYPE_TRANSPORT, NGTCP2_NO_ERROR, 0,
			   NULL, 0 },
	};

	tls = isc_tls_create(options->tlsctx);
	ngtcp2_crypto_ossl_ctx_new(&conn->ossl_ctx, tls);
	ngtcp2_crypto_ossl_configure_server_session(tls);
	SSL_set_app_data(tls, &conn->crypto_ref);
	SSL_set_accept_state(tls);

	if (options->alpn.base != NULL) {
		SSL_set_alpn_protos(tls, options->alpn.base,
				    options->alpn.length);
	}

	if (ngtcp2_conn_server_new(&conn->inner, &dcid, &scid, &conn->path,
				   NGTCP2_PROTO_VER_V2, &server_cb, &settings,
				   &transport_params, &conn->mem, conn) != 0)
	{
		return ISC_R_FAILURE;
	}

	ngtcp2_conn_set_tls_native_handle(conn->inner, conn->ossl_ctx);

	*connp = conn;

	result = ISC_R_SUCCESS;

	return result;
}

isc_result_t
isc_quic_conn_pull_packet(isc_quic_conn_t *conn, uint8_t *out, size_t len,
			  size_t *written,
			  isc_nanosecs_t (*timestamp_fn)(void)) {
	REQUIRE(conn != NULL && conn->magic == conn_magic);
	REQUIRE(out != NULL && len > 0 && written != NULL &&
		timestamp_fn != NULL);
	REQUIRE(conn->state < ARRAY_SIZE(state_table));

	return state_table[conn->state].pull_packet(conn, out, len, written,
						    timestamp_fn);
}

void
isc_quic_conn_destroy(isc_quic_conn_t **connp) {
	ngtcp2_crypto_ossl_ctx *ossl_ctx;
	isc_quic_conn_t *conn;
	isc_mem_t *mctx;
	isc_tls_t *tls;

	REQUIRE(connp != NULL && *connp != NULL &&
		(*connp)->magic == conn_magic);

	conn = *connp;
	*connp = NULL;

	conn->magic = 0x00;
	mctx = conn->mem.user_data;

	ossl_ctx = ngtcp2_conn_get_tls_native_handle(conn->inner);
	tls = ngtcp2_crypto_ossl_ctx_get_ssl(ossl_ctx);

	ISC_LIST_FOREACH(conn->streams, stream, link) {
		ISC_LIST_DEQUEUE(conn->streams, stream, link);

		ISC_LIST_FOREACH(stream->ack_data, data, link) {
			ISC_LIST_DEQUEUE(stream->ack_data, data, link);
			isc_mem_put(
				mctx, data,
				STRUCT_FLEX_SIZE(data, bytes, data->length));
		}

		isc_mem_put(mctx, stream, sizeof(*stream));
	}

	ISC_LIST_FOREACH(conn->incoming_stream_data, data, link) {
		ISC_LIST_DEQUEUE(conn->incoming_stream_data, data, link);
		isc_mem_put(mctx, data,
			    STRUCT_FLEX_SIZE(data, bytes, data->length));
	}

	ISC_LIST_FOREACH(conn->outgoing_stream_data, data, link) {
		ISC_LIST_DEQUEUE(conn->outgoing_stream_data, data, link);
		isc_mem_put(mctx, data,
			    STRUCT_FLEX_SIZE(data, bytes, data->length));
	}

	SSL_set_app_data(tls, NULL);
	isc_tls_free(&tls);

	ngtcp2_crypto_ossl_ctx_del(conn->ossl_ctx);

	ngtcp2_conn_del(conn->inner);

	isc_quic_cid_map_unref(conn->cidmap);

	isc_mem_put(mctx, conn, sizeof(*conn));
	isc_mem_unref(mctx);
}

isc_nanosecs_t
isc_quic_conn_next_expiry_time(isc_quic_conn_t *conn) {
	REQUIRE(conn != NULL && conn->magic == conn_magic);
	return ngtcp2_conn_get_expiry(conn->inner);
}

isc_result_t
isc_quic_conn_handle_expiry(isc_quic_conn_t *conn, isc_nanosecs_t timestamp) {
	int r;

	REQUIRE(conn != NULL && conn->magic == conn_magic);
	REQUIRE(timestamp != isc_quic_timestamp_invalid);

	r = ngtcp2_conn_handle_expiry(conn->inner, timestamp);
	if (r >= 0) {
		return ISC_R_SUCCESS;
	} else if (r == NGTCP2_ERR_IDLE_CLOSE) {
		conn->state = QUIC_CONN_STATE_TERMINATED;
		return ISC_R_TIMEDOUT;
	}

	conn->state = QUIC_CONN_STATE_CLOSED;
	return ISC_R_CANCELED;
}

isc_result_t
isc_quic_conn_push_packet(isc_quic_conn_t *conn, isc_constregion_t packet,
			  isc_nanosecs_t timestamp) {
	int r;

	REQUIRE(conn != NULL && conn->magic == conn_magic);
	REQUIRE(packet.base != NULL);

	r = ngtcp2_conn_read_pkt(conn->inner, &conn->path, NULL, packet.base,
				 packet.length, timestamp);
	if (r != 0) {
		return liberr_to_result(r);
	}

	return ISC_R_SUCCESS;
}

bool
isc_quic_conn_handshake_complete(isc_quic_conn_t *conn) {
	REQUIRE(conn != NULL && conn->magic == conn_magic);
	return ngtcp2_conn_get_handshake_completed(conn->inner) != 0;
}

isc_result_t
isc_quic_conn_shutdown_stream(isc_quic_conn_t *conn, int64_t stream_id,
			      uint64_t application_code) {
	int r;

	REQUIRE(conn != NULL && conn->magic == conn_magic);
	REQUIRE(stream_id >= 0);

	r = ngtcp2_conn_shutdown_stream(conn->inner, 0x00, stream_id,
					application_code);
	if (r != 0) {
		return liberr_to_result(r);
	}

	return ISC_R_SUCCESS;
}

isc_result_t
isc_quic_conn_open_bidi_stream(isc_quic_conn_t *conn, int64_t *stream_idp,
			       void *user_data) {
	quic_stream_t *stream;
	int r;

	REQUIRE(conn != NULL && conn->magic == conn_magic);
	REQUIRE(stream_idp != NULL && user_data != NULL);

	CHECK_STATE(conn, QUIC_CONN_STATE_CONNECTED);

	stream = isc_mem_get(conn->mem.user_data, sizeof(*stream));

	/*
	 * To get the stream ID for `quic_stream_t`, we need to pass the
	 * `quic_stream_t` pointer to `ngtcp2_conn_open_bidi_stream`.
	 *
	 * Thus, we initialize the values of `stream` after this call.
	 */
	r = ngtcp2_conn_open_bidi_stream(conn->inner, stream_idp, stream);
	if (r != 0) {
		isc_mem_put(conn->mem.user_data, stream, sizeof(*stream));
		return liberr_to_result(r);
	}

	*stream = (quic_stream_t){
		.id = *stream_idp,
		.ack_data = ISC_LIST_INITIALIZER,
		.link = ISC_LINK_INITIALIZER,
	};

	ISC_LIST_APPEND(conn->streams, stream, link);

	return ISC_R_SUCCESS;
}

isc_result_t
isc_quic_conn_pull_stream_data(isc_quic_conn_t *conn,
			       isc_quic_stream_data_t **datap) {
	isc_quic_stream_data_t *data;

	REQUIRE(conn != NULL && conn->magic == conn_magic);
	REQUIRE(datap != NULL && *datap == NULL);

	if (ISC_LIST_EMPTY(conn->incoming_stream_data)) {
		return ISC_R_NOMORE;
	}

	data = ISC_LIST_HEAD(conn->incoming_stream_data);
	ISC_LIST_UNLINK(conn->incoming_stream_data, data, link);
	*datap = data;
	return ISC_R_SUCCESS;
}

isc_result_t
isc_quic_conn_push_stream_data(isc_quic_conn_t *conn, int64_t stream_id,
			       uint8_t *data, size_t len) {
	isc_quic_stream_data_t *outgoing;

	REQUIRE(conn != NULL && conn->magic == conn_magic);
	REQUIRE(data != NULL && len != 0);

	outgoing = isc_mem_get(conn->mem.user_data,
			       STRUCT_FLEX_SIZE(outgoing, bytes, len));
	*outgoing = (isc_quic_stream_data_t){
		.stream_id = stream_id,
		.length = len,
		.link = ISC_LINK_INITIALIZER,
	};
	memcpy(outgoing->bytes, data, len);

	ISC_LIST_APPEND(conn->outgoing_stream_data, outgoing, link);

	return ISC_R_SUCCESS;
}
