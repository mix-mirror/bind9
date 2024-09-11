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

#include <string.h>

#include <isc/mem.h>
#include <isc/ngtcp2_utils.h>
#include <isc/random.h>

void
isc_ngtcp2_gen_cid(ngtcp2_cid *restrict cid, const size_t size) {
	REQUIRE(cid != NULL);
	REQUIRE(size >= NGTCP2_MIN_CIDLEN && size <= NGTCP2_MAX_CIDLEN);

	cid->datalen = size;
	isc_random_buf(cid->data, cid->datalen);
}

void
isc_ngtcp2_copy_cid(ngtcp2_cid *restrict dst, const ngtcp2_cid *restrict src) {
	REQUIRE(dst != NULL);
	REQUIRE(src != NULL && src->datalen > 0);

	memmove(dst->data, src->data, src->datalen);
	dst->datalen = src->datalen;
}

void
isc_ngtcp2_copy_cid_region(ngtcp2_cid *restrict dst,
			   const isc_region_t *restrict src) {
	REQUIRE(dst != NULL);
	REQUIRE(src != NULL && src->base != NULL &&
		src->length <= NGTCP2_MAX_CIDLEN);

	memmove(dst->data, src->base, src->length);
	dst->datalen = src->length;
}

void
isc_ngtcp2_addr_init(ngtcp2_addr *restrict ngaddr,
		     const isc_sockaddr_t *restrict addr) {
	REQUIRE(ngaddr != NULL);
	REQUIRE(addr != NULL);

	*ngaddr = (ngtcp2_addr){ 0 };

	ngaddr->addr = (ngtcp2_sockaddr *)&addr->type.sa;
	ngaddr->addrlen = (ngtcp2_socklen)addr->length;
}

void
isc_ngtcp2_path_init(ngtcp2_path *restrict path,
		     const isc_sockaddr_t *restrict local,
		     const isc_sockaddr_t *restrict peer) {
	REQUIRE(path != NULL);
	REQUIRE(local != NULL);
	REQUIRE(peer != NULL);

	*path = (ngtcp2_path){ 0 };

	isc_ngtcp2_addr_init(&path->local, local);
	isc_ngtcp2_addr_init(&path->remote, peer);
}

void
isc_ngtcp2_path_storage_init(ngtcp2_path_storage *restrict path_storage,
			     const isc_sockaddr_t *restrict local,
			     const isc_sockaddr_t *restrict peer) {
	REQUIRE(path_storage != NULL);
	REQUIRE(local != NULL);
	REQUIRE(peer != NULL);

	*path_storage = (ngtcp2_path_storage){ 0 };

	INSIST(local->length <= sizeof(path_storage->local_addrbuf));
	INSIST(peer->length <= sizeof(path_storage->remote_addrbuf));

	ngtcp2_path_storage_init(
		path_storage, (ngtcp2_sockaddr *)&local->type.sa, local->length,
		(ngtcp2_sockaddr *)&peer->type.sa, peer->length, NULL);
}

void
isc_ngtcp2_path_getaddrs(const ngtcp2_path *restrict path,
			 isc_sockaddr_t *restrict local,
			 isc_sockaddr_t *restrict peer) {
	REQUIRE(path != NULL);

	if (local != NULL) {
		isc_sockaddr_fromsockaddr(local, path->local.addr);
	}

	if (peer != NULL) {
		isc_sockaddr_fromsockaddr(peer, path->remote.addr);
	}
}

static void *
isc__ngtcp2_malloc(size_t sz, isc_mem_t *mctx) {
	return isc_mem_allocate(mctx, sz);
}

static void *
isc__ngtcp2_calloc(size_t n, size_t sz, isc_mem_t *mctx) {
	return isc_mem_callocate(mctx, n, sz);
}

static void *
isc__ngtcp2_realloc(void *p, size_t newsz, isc_mem_t *mctx) {
	return isc_mem_reallocate(mctx, p, newsz);
}

static void
isc__ngtcp2_free(void *p, isc_mem_t *mctx) {
	if (p == NULL) { /* as standard free() behaves */
		return;
	}
	isc_mem_free(mctx, p);
}

void
isc_ngtcp2_mem_init(ngtcp2_mem *restrict mem, isc_mem_t *mctx) {
	REQUIRE(mem != NULL);
	REQUIRE(mctx != NULL);

	*mem = (ngtcp2_mem){ .malloc = (ngtcp2_malloc)isc__ngtcp2_malloc,
			     .calloc = (ngtcp2_calloc)isc__ngtcp2_calloc,
			     .realloc = (ngtcp2_realloc)isc__ngtcp2_realloc,
			     .free = (ngtcp2_free)isc__ngtcp2_free,
			     .user_data = (void *)mctx };
}

bool
isc_ngtcp2_is_version_available(const uint32_t version,
				const uint32_t *versions,
				const size_t versions_len) {
	REQUIRE(versions != NULL);

	if (version == 0) {
		return false;
	}

	for (size_t i = 0; i < versions_len; i++) {
		if (versions[i] == version &&
		    ngtcp2_is_supported_version(version))
		{
			return true;
		}
	}

	return false;
}

uint32_t
isc_ngtcp2_select_version(const uint32_t client_original_chosen_version,
			  const uint32_t *client_preferred_versions,
			  const size_t client_preferred_versions_len,
			  const uint32_t *server_preferred_versions,
			  const size_t server_preferred_versions_len) {
	size_t i, k;

	REQUIRE(client_preferred_versions != NULL);
	REQUIRE(server_preferred_versions != NULL);

	/*
	 * RFC RFC9368, Section 4. Version Downgrade Prevention:

	 * Clients MUST ignore any received Version Negotiation packets
	 * that contain the Original Version.
	 * ...
	 * If an endpoint receives a Chosen Version equal to zero, or any
	 * Available Version equal to zero, it MUST treat it as a parsing
	 * failure.
	 */
	for (i = 0; i < server_preferred_versions_len; i++) {
		if (server_preferred_versions[i] ==
			    client_original_chosen_version ||
		    server_preferred_versions[i] == 0)
		{
			return 0;
		}
	}

	/* Choose a protocol version prioritising client's preferences. */
	for (i = 0; i < client_preferred_versions_len; i++) {
		const uint32_t client_version = client_preferred_versions[i];
		for (k = 0; k < server_preferred_versions_len; k++) {
			const uint32_t server_version =
				server_preferred_versions[k];
			if (client_version == server_version &&
			    ngtcp2_is_supported_version(client_version) &&
			    ngtcp2_is_supported_version(server_version))
			{
				return client_version;
			}
		}
	}

	return 0;
}

isc_result_t
isc_ngtcp2_decode_pkt_header(const isc_region_t *pkt,
			     const size_t short_pkt_dcidlen, bool *pkt_long,
			     isc_region_t *pkt_scid, isc_region_t *pkt_dcid,
			     uint32_t *pkt_version) {
	ngtcp2_version_cid vc = { 0 };
	REQUIRE(pkt != NULL && pkt->base != NULL && pkt->length > 0);

	int ret = ngtcp2_pkt_decode_version_cid(&vc, pkt->base, pkt->length,
						short_pkt_dcidlen);

	/*
	 * We treat version negotiation not as an error, because our code
	 * is expected to handle it on its own.
	 */
	if (ret != NGTCP2_VERSION_NEGOTIATION_ERROR && ret != 0) {
		return ISC_R_UNEXPECTED;
	}

	SET_IF_NOT_NULL(pkt_long,
			isc_ngtcp2_pkt_header_is_long(pkt->base, pkt->length));

	isc_region_t tmp = (isc_region_t){
		.base = (uint8_t *)vc.scid,
		.length = (unsigned int)vc.scidlen,
	};
	SET_IF_NOT_NULL(pkt_scid, tmp);

	tmp = (isc_region_t){
		.base = (uint8_t *)vc.dcid,
		.length = (unsigned int)vc.dcidlen,
	};
	SET_IF_NOT_NULL(pkt_dcid, tmp);

	SET_IF_NOT_NULL(pkt_version, vc.version);

	return ISC_R_SUCCESS;
}

isc_result_t
isc_ngtcp2_decode_pkt_header_data(const uint8_t *pkt_data, const size_t pkt_len,
				  const size_t short_pkt_dcidlen,
				  bool *pkt_long, isc_region_t *pkt_scid,
				  isc_region_t *pkt_dcid,
				  uint32_t *pkt_version) {
	REQUIRE(pkt_data != NULL && pkt_len > 0);

	isc_region_t pkt = { .base = (uint8_t *)pkt_data,
			     .length = (unsigned int)pkt_len };

	return isc_ngtcp2_decode_pkt_header(&pkt, short_pkt_dcidlen, pkt_long,
					    pkt_scid, pkt_dcid, pkt_version);
}

static const uint32_t default_protocols[] = { NGTCP2_PROTO_VER_V2,
					      NGTCP2_PROTO_VER_V1 };

void
isc_ngtcp2_get_default_quic_versions(const uint32_t **protocols,
				     size_t *protocols_len) {
	REQUIRE(protocols != NULL && *protocols == NULL);
	REQUIRE(protocols_len != NULL && *protocols_len == 0);

	*protocols = default_protocols;
	*protocols_len = sizeof(default_protocols) /
			 sizeof(default_protocols[0]);
}
