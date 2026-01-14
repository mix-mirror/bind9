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

#include <dns/fixedname.h>
#include <dns/name.h>
#include <dns/rdataset.h>
#include <dns/types.h>

struct dns_zonecut {
	dns_fixedname_t fname;
	dns_name_t     *name;
	dns_rdataset_t	ns;
	dns_rdataset_t	nssig;
	dns_rdataset_t	glue_a;
	dns_rdataset_t	glue_aaaa;
	dns_rdataset_t	deleg;
	dns_rdataset_t	delegsig;
};

bool
dns_zonecut_isvalid(const dns_zonecut_t *zonecut);

void
dns_zonecut_clone(const dns_zonecut_t *from, dns_zonecut_t *to);

void
dns_zonecut_init(dns_zonecut_t *zonecut);

void
dns_zonecut_cleanup(dns_zonecut_t *zonecut);
