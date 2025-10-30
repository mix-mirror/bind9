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

#include <isc/loop.h>

#include <dns/resolver.h>
#include <dns/view.h>
#include <dns/zone.h>
#include <dns/zonefetch.h>

void
dns_zonefetch_run(void *arg) {
	dns_zonefetch_t *fetch = (dns_zonefetch_t *)arg;
	dns_zone_t *zone;
	dns_view_t *view;
	isc_loop_t *loop;
	isc_result_t result;
	dns_resolver_t *resolver = NULL;

	zone = fetch->zone;
	if (dns_zone_exiting(zone)) {
		result = ISC_R_SHUTTINGDOWN;
		goto cancel;
	}
	view = dns_zone_getview(zone);
	loop = dns_zone_getloop(zone);

	fetch->fetchmethods.start_fetch(fetch);

	result = dns_view_getresolver(view, &resolver);
	if (result != ISC_R_SUCCESS) {
		goto cancel;
	}

	if (isc_log_wouldlog(ISC_LOG_DEBUG(3))) {
		char namebuf[DNS_NAME_FORMATSIZE];
		char typebuf[DNS_RDATATYPE_FORMATSIZE];
		dns_name_format(fetch->qname, namebuf, sizeof(namebuf));
		dns_rdatatype_format(fetch->qtype, typebuf, sizeof(typebuf));
		dns_zone_log(zone, ISC_LOG_DEBUG(3),
			     "Do fetch for %s/%s request", namebuf, typebuf);
	}

	/*
	 * Use of DNS_FETCHOPT_NOCACHED is essential here.  If it is not
	 * set and the cache still holds a non-expired, validated version
	 * of the RRset being queried for by the time the response is
	 * received, the cached RRset will be passed to dns_zonefetch_done()
	 * instead of the one received in the response as the latter will
	 * have a lower trust level due to not being validated until
	 * dns_zonefetch_done() is called.
	 */
	INSIST((fetch->options & DNS_FETCHOPT_NOCACHED) != 0);

	result = dns_resolver_createfetch(
		resolver, fetch->qname, fetch->qtype, NULL, NULL, NULL, NULL, 0,
		fetch->options, 0, NULL, NULL, loop, dns_zonefetch_done, fetch,
		NULL, &fetch->rrset, &fetch->sigset, &fetch->fetch);

	dns_resolver_detach(&resolver);

cancel:
	if (result == ISC_R_SUCCESS) {
		return;
	} else if (result != ISC_R_SHUTTINGDOWN) {
		char namebuf[DNS_NAME_FORMATSIZE];
		char typebuf[DNS_RDATATYPE_FORMATSIZE];
		dns_name_format(fetch->qname, namebuf, sizeof(namebuf));
		dns_rdatatype_format(fetch->qtype, typebuf, sizeof(typebuf));
		dns_zone_log(zone, ISC_LOG_WARNING,
			     "Failed fetch for %s/%s request", namebuf,
			     typebuf);
	}

	/*
	 * Fetch failed, cancel.
	 */
	dns_zone_lock(zone);

	fetch->fetchmethods.cancel_fetch(fetch);

	dns_name_t *zname = dns_fixedname_name(&fetch->name);
	isc_mem_t *mctx = dns_zone_getmctx(zone);
	bool free_needed;

	isc_refcount_decrement(dns_zone_irefs(zone));
	dns_name_free(zname, mctx);
	isc_mem_putanddetach(&fetch->mctx, fetch, sizeof(*fetch));

	free_needed = dns_zone_free_check(zone);

	dns_zone_unlock(zone);

	if (free_needed) {
		dns_zone_free(zone);
	}
}

void
dns_zonefetch_done(void *arg) {
	dns_fetchresponse_t *resp = (dns_fetchresponse_t *)arg;
	isc_result_t result = ISC_R_NOMORE;
	isc_result_t eresult;
	dns_zonefetch_t *fetch = NULL;
	dns_zone_t *zone = NULL;
	dns_view_t *view = NULL;
	isc_mem_t *mctx = NULL;
	dns_name_t *zname = NULL;
	dns_rdataset_t *rrset = NULL;
	dns_rdataset_t *sigset = NULL;

	INSIST(resp != NULL);

	fetch = resp->arg;

	INSIST(fetch != NULL);

	mctx = fetch->mctx;
	zone = fetch->zone;
	zname = dns_fixedname_name(&fetch->name);
	rrset = &fetch->rrset;
	sigset = &fetch->sigset;
	view = dns_zone_getview(zone);
	eresult = resp->result;

	/* Free resources which are not of interest */
	if (resp->node != NULL) {
		dns_db_detachnode(&resp->node);
	}
	if (resp->db != NULL) {
		dns_db_detach(&resp->db);
	}
	dns_resolver_destroyfetch(&fetch->fetch);

	dns_zone_lock(zone);
	if (dns_zone_exiting(zone) || view == NULL) {
		goto cleanup;
	}

	result = fetch->fetchmethods.done_fetch(fetch, eresult);

cleanup:
	isc_refcount_decrement(dns_zone_irefs(zone));

	if (dns_rdataset_isassociated(rrset)) {
		dns_rdataset_disassociate(rrset);
	}
	if (dns_rdataset_isassociated(sigset)) {
		dns_rdataset_disassociate(sigset);
	}

	dns_resolver_freefresp(&resp);

	if (result == DNS_R_CONTINUE) {
		dns_zone_unlock(zone);
		fetch->fetchmethods.continue_fetch(fetch);
	} else {
		bool free_needed = false;
		dns_name_free(zname, mctx);
		isc_mem_putanddetach(&fetch->mctx, fetch,
				     sizeof(dns_zonefetch_t));
		free_needed = dns_zone_free_check(zone);

		dns_zone_unlock(zone);

		if (free_needed) {
			dns_zone_free(zone);
		}
	}
}
