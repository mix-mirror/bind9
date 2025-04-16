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

#include <stdint.h>

#include <isc/result.h>
#include <isc/types.h>

#define ISC_SKIPLIST_INDEX_INITIALIZER \
	{                              \
		.lo = UINTPTR_MAX,     \
		.hi = UINTPTR_MAX,     \
	}

typedef struct isc_skiplist	 isc_skiplist_t;
typedef struct isc_skiplist_iter isc_skiplist_iter_t;

typedef struct isc_skiplist_index {
	uintptr_t lo;
	uintptr_t hi;
} isc_skiplist_index_t;

void
isc_skiplist_create(isc_mem_t *mctx, isc_skiplist_t **skipp);

void
isc_skiplist_destroy(isc_skiplist_t **skipp);

void
isc_skiplist_insert(isc_skiplist_t *skip, uint64_t value,
		    isc_skiplist_index_t *index);

void
isc_skiplist_remove(isc_skiplist_t *skip, isc_skiplist_index_t *index);

isc_result_t
isc_skiplist_iter_attach(isc_skiplist_t *skip, isc_skiplist_iter_t **iterp);

void
isc_skiplist_iter_destroy(isc_skiplist_iter_t **iterp);

void
isc_skiplist_iter_current(isc_skiplist_iter_t	*iter,
			  isc_skiplist_index_t **indexp);

isc_result_t
isc_skiplist_iter_next(isc_skiplist_iter_t *iter);
