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

#include <dns/zonecut.h>

bool
dns_zonecut_isvalid(const dns_zonecut_t *zonecut) {
	return zonecut != NULL && zonecut->name != NULL &&
	       dns_name_hasbuffer(zonecut->name) &&
	       DNS_RDATASET_VALID(&zonecut->ns) &&
	       DNS_RDATASET_VALID(&zonecut->nssig) &&
	       DNS_RDATASET_VALID(&zonecut->glue_a) &&
	       DNS_RDATASET_VALID(&zonecut->glue_aaaa) &&
	       DNS_RDATASET_VALID(&zonecut->deleg) &&
	       DNS_RDATASET_VALID(&zonecut->delegsig);
}

void
dns_zonecut_init(dns_zonecut_t *zonecut) {
	REQUIRE(zonecut != NULL);

	zonecut->name = dns_fixedname_initname(&zonecut->fname);
	dns_rdataset_init(&zonecut->ns);
	dns_rdataset_init(&zonecut->nssig);
	dns_rdataset_init(&zonecut->glue_a);
	dns_rdataset_init(&zonecut->glue_aaaa);
	dns_rdataset_init(&zonecut->deleg);
	dns_rdataset_init(&zonecut->delegsig);
}

inline static void 
clone_associated(const dns_rdataset_t *from,
				    dns_rdataset_t *to) {
	if (dns_rdataset_isassociated(from)) {
		dns_rdataset_clone(from, to);
	}
}

void
dns_zonecut_clone(const dns_zonecut_t *from, dns_zonecut_t *to) {
	REQUIRE(dns_zonecut_isvalid(from));
	REQUIRE(dns_zonecut_isvalid(to));

	dns_name_copy(from->name, to->name);
	clone_associated(&from->ns, &to->ns);
	clone_associated(&from->nssig, &to->nssig);
	clone_associated(&from->glue_a, &to->glue_a);
	clone_associated(&from->glue_aaaa, &to->glue_aaaa);
	clone_associated(&from->deleg, &to->deleg);
	clone_associated(&from->delegsig, &to->delegsig);
}

void
dns_zonecut_cleanup(dns_zonecut_t *zonecut) {
	if (zonecut == NULL) {
		return;
	}

	REQUIRE(dns_zonecut_isvalid(zonecut));

	dns_fixedname_init(&zonecut->fname);
	dns_rdataset_cleanup(&zonecut->ns);
	dns_rdataset_cleanup(&zonecut->nssig);
	dns_rdataset_cleanup(&zonecut->glue_a);
	dns_rdataset_cleanup(&zonecut->glue_aaaa);
	dns_rdataset_cleanup(&zonecut->deleg);
	dns_rdataset_cleanup(&zonecut->delegsig);
}
