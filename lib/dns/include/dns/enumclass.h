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

/*
 * DNS class enumeration.  These values are fixed by the DNS protocol
 * and do not change when new rdata types are added.
 */

/* clang-format off */
#pragma once
enum {
	dns_rdataclass_reserved0 = 0,
#define dns_rdataclass_reserved0 \
	((dns_rdataclass_t)dns_rdataclass_reserved0)
	dns_rdataclass_in = 1,
#define dns_rdataclass_in ((dns_rdataclass_t)dns_rdataclass_in)
	dns_rdataclass_chaos = 3,
#define dns_rdataclass_chaos ((dns_rdataclass_t)dns_rdataclass_chaos)
	dns_rdataclass_ch = 3,
#define dns_rdataclass_ch ((dns_rdataclass_t)dns_rdataclass_ch)
	dns_rdataclass_hs = 4,
#define dns_rdataclass_hs ((dns_rdataclass_t)dns_rdataclass_hs)
	dns_rdataclass_none = 254,
#define dns_rdataclass_none ((dns_rdataclass_t)dns_rdataclass_none)
	dns_rdataclass_any = 255
#define dns_rdataclass_any ((dns_rdataclass_t)dns_rdataclass_any)
};
/* clang-format on */
