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

/*! \file */

#include <isc/lib.h>
#include <isc/once.h>
#include <isc/refcount.h>

#include <dns/lib.h>

#include "acl_p.h"
#include "db_p.h"
#include "dlz_p.h"
#include "dst_internal.h"
#include "dyndb_p.h"
#include "qp_p.h"
#include "qpzone_p.h"

/***
 *** Functions
 ***/

static isc_refcount_t dns__lib_references = 0;

static void
dnsinitialize(void) {
	if (isc_refcount_increment0(&dns__lib_references) > 0) {
		return;
	}

	dst__lib_initialize();
	dns__acl_initialize();
	dns__dlz_initialize();
	dns__db_initialize();
	dns__dyndb_initialize();
	dns__qp_initialize();
	dns__qpzone_initialize();
}

static void
dnsshutdown(void) {
	if (isc_refcount_decrement(&dns__lib_references) > 1) {
		return;
	}

	dns__qpzone_shutdown();
	dns__qp_shutdown();
	dns__dyndb_shutdown();
	dns__db_shutdown();
	dns__dlz_shutdown();
	dns__acl_shutdown();
	dst__lib_shutdown();
}

void
dns_lib_initialize(void) {
	isc_lib_initialize();
	dnsinitialize();
}

void
dns_lib_shutdown(void) {
	dnsshutdown();
	isc_lib_shutdown();
}
