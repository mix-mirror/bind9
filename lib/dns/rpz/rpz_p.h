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

#include <stdbool.h>

#include <isc/mem.h>
#include <isc/result.h>

#include <dns/qp.h>
#include <dns/rpz.h>

typedef struct dns_rpz_qp_name_zbits {
	dns_rpz_zbits_t qname;
	dns_rpz_zbits_t ns;
} dns_rpz_qp_name_zbits_t;

typedef struct dns_rpz_qp_name_data {
	dns_rpz_qp_name_zbits_t set;
	dns_rpz_qp_name_zbits_t wild;
} dns_rpz_qp_name_data_t;

/*
 * RPZ's wrapper around the QP summary database. Keep the underlying QP
 * implementation private so it can grow additional key and value types.
 */
struct dns_rpz_qp {
	unsigned int magic;
	isc_mem_t *mctx;
	dns_qpmulti_t *multi;
};

typedef struct dns_rpz_qp_write {
	dns_rpz_qp_t *table;
	dns_qp_t *qp;
} dns_rpz_qp_write_t;

void
dns__rpz_qp_create(isc_mem_t *mctx, dns_view_t *view, dns_rpz_qp_t **tablep);

void
dns__rpz_qp_destroy(dns_rpz_qp_t **tablep);

isc_result_t
dns__rpz_qp_find_name(dns_rpz_qp_t *table, dns_rpz_type_t type,
		      const dns_name_t *name, dns_rpz_zbits_t *zbitsp);

void
dns__rpz_qp_write(dns_rpz_qp_t *table, dns_rpz_qp_write_t *write);

isc_result_t
dns__rpz_qp_add_name(dns_rpz_qp_write_t *write, const dns_name_t *name,
		     const dns_rpz_qp_name_data_t *new_data);

isc_result_t
dns__rpz_qp_delete_name(dns_rpz_qp_write_t *write, const dns_name_t *name,
			const dns_rpz_qp_name_data_t *del_data, bool *existsp);

void
dns__rpz_qp_commit(dns_rpz_qp_write_t *write);
