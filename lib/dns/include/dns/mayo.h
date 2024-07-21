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

#include <oqs/oqs.h>

#if !defined(OQS_ENABLE_SIG_mayo_2)
#error "liboqs was built without MAYO-2 support"
#endif

/*
 * MAYO variant used for DNSSEC signing (liboqs "MAYO-2", NIST level 1).
 *
 * This header pulls in <oqs/oqs.h> and must only be included by the MAYO
 * crypto backend (mayo_link.c).  Code that only needs the key and signature
 * sizes uses the DNS_*_MAYOSIZE constants from <dns/keyvalues.h>, which are
 * verified against liboqs at compile time in mayo_link.c.
 */
#define DNS_MAYO_ALG OQS_SIG_alg_mayo_2
