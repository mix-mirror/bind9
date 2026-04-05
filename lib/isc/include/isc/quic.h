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

/*! \file isc/quic.h */

#include <stddef.h>
#include <stdint.h>

#include <isc/refcount.h>
#include <isc/region.h>
#include <isc/types.h>

/**
 *
 */
typedef struct isc_quic_conn isc_quic_conn_t;

/**
 *
 */
typedef struct isc_quic_cid isc_quic_cid_t;

/**
 *
 */
typedef struct isc_quic_cid_map isc_quic_cid_map_t;

isc_quic_cid_t *
isc_quic_cid_random_new(size_t length, isc_mem_t *mctx);
/**
 *
 */

isc_constregion_t
isc_quic_cid_bytes(isc_quic_cid_t *cid);
/**
 *
 */

void
isc_quic_cid_destroy(isc_mem_t *mctx, isc_quic_cid_t **cidp);
/**
 *
 */

void
isc_quic_cid_map_create(isc_mem_t *mctx, isc_quic_cid_map_t **mapp);
/**
 *
 */

ISC_REFCOUNT_DECL(isc_quic_cid_map);

isc_result_t
isc_quic_cid_map_find(isc_quic_cid_map_t *map, isc_constregion_t cid_bytes,
		      isc_quic_conn_t **existsp, isc_tid_t *tidp);
/**
 * Returns:
 * - #ISC_R_SUCCESS on success
 * - #ISC_R_NOTFOUND if such a connection id doesn't exist
 */

isc_result_t
isc_quic_cid_map_add(isc_quic_cid_map_t *map, isc_quic_cid_t *cid,
		     isc_quic_conn_t *conn);
/**
 * Returns:
 * - #ISC_R_SUCCESS
 * - #ISC_R_EXISTS
 */

isc_result_t
isc_quic_cid_map_add_bytes(isc_quic_cid_map_t *map, isc_constregion_t cid_bytes,
			   isc_quic_conn_t *conn);
/**
 *
 */

isc_result_t
isc_quic_cid_map_remove(isc_quic_cid_map_t *map, isc_quic_cid_t *cid);
/**
 * Returns:
 * - #ISC_R_SUCCESS on success
 * - #ISC_R_NOTFOUND if such a connection id doesn't exist
 */
