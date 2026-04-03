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

/* IN class A record */
typedef struct dns_rdata_in_a {
	dns_rdatacommon_t common;
	struct in_addr in_addr;
} dns_rdata_in_a_t;

/* CH class A record */
typedef uint16_t ch_addr_t;

typedef struct dns_rdata_ch_a {
	dns_rdatacommon_t common;
	isc_mem_t *mctx;
	dns_name_t ch_addr_dom;
	ch_addr_t ch_addr;
} dns_rdata_ch_a_t;

/* HS class A record */
typedef struct dns_rdata_hs_a {
	dns_rdatacommon_t common;
	struct in_addr in_addr;
} dns_rdata_hs_a_t;
