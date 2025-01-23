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

#pragma once

#include <isc/ht.h>
#include <isc/ngtcp2_crypto.h>
#include <isc/ngtcp2_utils.h>
#include <isc/quic.h>
#include <isc/refcount.h>
#include <isc/safe.h>

#define QUIC_SESSION_MAGIC    ISC_MAGIC('Q', 'U', 'I', 'C')
#define VALID_QUIC_SESSION(t) ISC_MAGIC_VALID(t, QUIC_SESSION_MAGIC)

#define QUIC_CID_MAGIC	  ISC_MAGIC('Q', 'C', 'I', 'D')
#define VALID_QUIC_CID(t) ISC_MAGIC_VALID(t, QUIC_CID_MAGIC)

#define QUIC_STREAM_MAGIC    ISC_MAGIC('Q', 'S', 'T', 'R')
#define VALID_QUIC_STREAM(t) ISC_MAGIC_VALID(t, QUIC_STREAM_MAGIC)

typedef struct isc__quic_send_req isc__quic_send_req_t;

/*
 * NOTE: for all send queues new requests are appended strictly to the
 * end
 */

typedef struct isc__quic_stream_data {
	unsigned int magic;

	int64_t stream_id;
	void *stream_user_data;

	bool close_cb_called;
	bool fin;

	struct quic_stream_sends {
		/* local send queue */
		ISC_LIST(isc__quic_send_req_t) queue;
		size_t queue_len;
		size_t pending_data;
	} sends;

	ISC_LINK(struct isc__quic_stream_data) stream_link;
} isc__quic_stream_data_t;

struct isc__quic_send_req {
	isc__quic_stream_data_t *stream;

	isc_buffer_t data;
	bool fin;

	isc_quic_send_cb_t cb;
	void *cbarg;

	ISC_LINK(struct isc__quic_send_req) conn_link;
	ISC_LINK(struct isc__quic_send_req) stream_link;
};

typedef ISC_LIST(isc__quic_stream_data_t) quic_stream_list_t;

typedef struct isc_quic_session_cids {
	isc_ht_t *idx;
	ISC_LIST(isc_quic_cid_t) list;
	size_t count;
} isc_quic_session_cids_t;

struct isc_quic_session {
	unsigned int magic;
	isc_refcount_t references;

	isc_mem_t *mctx;

	bool is_server;
	int state;

	isc_tlsctx_t *tlsctx;
	isc_tls_t *tls;

	/* client only */
	char *sni_hostname;
	isc_tlsctx_client_session_cache_t *client_sess_cache;
	bool client_sess_saved;

	isc_quic_session_interface_t cb;
	void *cbarg;

	void *user_data;

	ngtcp2_tstamp ts;

	uint64_t handshake_timeout;
	uint64_t idle_timeout;

	size_t max_uni_streams;
	size_t max_bidi_streams;

	ngtcp2_mem mem;

	uint8_t secret_storage[ISC_NGTCP2_CRYPTO_STATIC_SECRET_LEN];
	isc_buffer_t secret;

	uint32_t orig_client_chosen_version;
	uint32_t negotiated_version;

	uint32_t available_versions_list_storage[8];
	isc_buffer_t available_versions;

	uint8_t tokenbuf[ISC_NGTCP2_CRYPTO_MAX_REGULAR_TOKEN_LEN];
	isc_buffer_t regular_token;

	isc_quic_cid_t *initial_scid;
	isc_quic_cid_t *initial_dcid;

	isc_quic_cid_t *odcid;
	isc_quic_cid_t *rcid;

	ngtcp2_path_storage path_st;
	ngtcp2_path *path;
	size_t path_migrations;

	ngtcp2_conn *conn;
	ngtcp2_ccerr conn_err;

	bool closing;
	bool fin;
	isc_buffer_t *close_msg;
	isc_sockaddr_t close_local;
	isc_sockaddr_t close_peer;
	bool shuttingdown;

	size_t last_read_pkt_size;
	ngtcp2_cid last_read_pkt_dcid;
	bool resetting;

	size_t close_reset_count;
	size_t ver_neg_count;

	ngtcp2_tstamp last_expiry;
	size_t sent_before_expiry;
	bool timer_running;

	bool write_after_read;

	struct quic_session_streams {
		isc_ht_t *idx;
		quic_stream_list_t list;
		isc_mempool_t *pool;
	} streams;

	struct quic_session_sends {
		/* global send queue for all streams */
		ISC_LIST(isc__quic_send_req_t) queue;
		size_t queue_len;
		size_t pending_data;
		isc_mempool_t *pool;
	} sends;

	/* list of associated CIDs */
	isc_quic_session_cids_t dst_cids;
	isc_quic_session_cids_t src_cids;

	bool hs_confirmed;
};

struct isc_quic_cid {
	unsigned int magic;
	isc_refcount_t references;

	ngtcp2_cid cid;

	isc_mem_t *mctx;

	ISC_LINK(struct isc_quic_cid) global_link;
	ISC_LINK(struct isc_quic_cid) local_link;
};
