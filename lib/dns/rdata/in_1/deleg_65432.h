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

/*!
 *  \brief Per draft-wesplaap-deleg-01
 */

#include <isc/result.h>
#include <isc/region.h>

typedef struct dns_rdata_in_svcb dns_rdata_in_deleg_t;

isc_result_t
dns_rdata_in_deleg_first(dns_rdata_in_deleg_t *);

isc_result_t
dns_rdata_in_deleg_next(dns_rdata_in_deleg_t *);

void
dns_rdata_in_deleg_current(dns_rdata_in_deleg_t *, isc_region_t *);
