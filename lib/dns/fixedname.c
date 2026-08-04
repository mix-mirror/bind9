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

#include <dns/fixedname.h>

void
dns_fixedname_init(dns_fixedname_t *fixed) {
	dns_linkedname_init(&fixed->name_wl);
	isc_buffer_init(&fixed->buffer, fixed->data, DNS_NAME_MAXWIRE);
	dns_name_setbuffer((dns_name_t *)&fixed->name_wl, &fixed->buffer);
}

void
dns_fixedname_invalidate(dns_fixedname_t *fixed) {
	dns_name_invalidate((dns_name_t *)&fixed->name_wl);
}

dns_name_t *
dns_fixedname_name(dns_fixedname_t *fixed) {
	return (dns_name_t *)&fixed->name_wl;
}

const dns_name_t *
dns_fixedname_name_const(const dns_fixedname_t *fixed) {
	return (const dns_name_t *)&fixed->name_wl;
}

dns_name_t *
dns_fixedname_initname(dns_fixedname_t *fixed) {
	dns_fixedname_init(fixed);
	return dns_fixedname_name(fixed);
}

dns_linkedname_t *
dns_fixedname_linkedname(dns_fixedname_t *fixed) {
	return &fixed->name_wl;
}

dns_linkedname_t *
dns_fixedname_initlinkedname(dns_fixedname_t *fixed) {
	dns_fixedname_init(fixed);
	return dns_fixedname_linkedname(fixed);
}
