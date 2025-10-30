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

/*! \file dns/zonefetch.h */

#include <isc/mem.h>
#include <isc/result.h>

#include <dns/db.h>
#include <dns/name.h>
#include <dns/rdataset.h>
#include <dns/zone.h>

/*%
 * Fetch type; various features can initiate fetching and this enum value
 * allows common code paths to differentiate between them
 */
typedef enum {
	ZONEFETCHTYPE_DSYNC,
	ZONEFETCHTYPE_KEY,
	ZONEFETCHTYPE_NS,
} dns_zonefetch_type_t;

typedef struct dns_dsyncfetch dns_dsyncfetch_t;
typedef struct dns_keyfetch   dns_keyfetch_t;
typedef struct dns_nsfetch    dns_nsfetch_t;
typedef struct dns_zonefetch  dns_zonefetch_t;

/*
 * Fetch methods.
 */
typedef struct dns_zonefetch_methods {
	void (*start_fetch)(dns_zonefetch_t *fetch);
	void (*continue_fetch)(dns_zonefetch_t *fetch);
	void (*cancel_fetch)(dns_zonefetch_t *fetch);
	isc_result_t (*done_fetch)(dns_zonefetch_t *fetch,
				   isc_result_t	    eresult);
} dns_zonefetch_methods_t;

/*
 * Fetch contexts.
 */
struct dns_dsyncfetch {
	dns_name_t dsyncname;
};

struct dns_keyfetch {
	dns_rdataset_t keydataset;
	dns_db_t      *db;
};

struct dns_nsfetch {
	dns_name_t pname;
};

typedef union dns_fetchdata {
	dns_dsyncfetch_t dsyncfetch;
	dns_keyfetch_t	 keyfetch;
	dns_nsfetch_t	 nsfetch;
} dns_zonefetch_data_t;

struct dns_zonefetch {
	/* Fetch context */
	dns_fetch_t    *fetch;
	isc_mem_t      *mctx;
	dns_zone_t     *zone;
	dns_fixedname_t name;

	/* Query */
	dns_name_t     *qname;
	dns_rdatatype_t qtype;
	unsigned int	options;

	/* Response */
	dns_rdataset_t rrset;
	dns_rdataset_t sigset;

	/* Type specific */
	dns_zonefetch_type_t	fetchtype;
	dns_zonefetch_data_t	fetchdata;
	dns_zonefetch_methods_t fetchmethods;
};

void
dns_zonefetch_run(void *arg);
/*%<
 *      Start a zone fetch. This starts a query for a given qname and qtype, and
 *recurses to answer a question. The type of fetch depends on the fetchtype.
 */

void
dns_zonefetch_done(void *arg);
/*%<
 *      Complete a zone fetch. This may trigger follow-up actions that depend on
 * the fetch type.
 */
