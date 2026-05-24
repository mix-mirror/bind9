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

#include <string.h>

#include <isc/buffer.h>
#include <isc/mem.h>
#include <isc/netaddr.h>
#include <isc/util.h>

#include <dns/ecs.h>
#include <dns/nsec.h>
#include <dns/rdata.h>
#include <dns/rdatatype.h>
#include <dns/result.h>
#include <dns/types.h>

void
dns_ecs_init(dns_ecs_t *ecs) {
	isc_netaddr_unspec(&ecs->addr);
	ecs->source = 0;
	ecs->scope = 0xff;
}

void
dns_ecs_format(const dns_ecs_t *ecs, char *buf, size_t size) {
	size_t len;
	char *p;

	REQUIRE(ecs != NULL);
	REQUIRE(buf != NULL);
	REQUIRE(size >= DNS_ECS_FORMATSIZE);

	isc_netaddr_format(&ecs->addr, buf, size);
	len = strlen(buf);
	p = buf + len;
	snprintf(p, size - len, "/%d/%d", ecs->source,
		 ecs->scope == 0xff ? 0 : ecs->scope);
}
