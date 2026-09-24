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

#include <stdbool.h>

#include <isc/util.h>

#include <dns/dbiterator.h>
#include <dns/fixedname.h>
#include <dns/name.h>

void
dns__dbiterator_destroy(dns_dbiterator_t **iteratorp DNS__DB_FLARG) {
	REQUIRE(iteratorp != NULL);
	REQUIRE(DNS_DBITERATOR_VALID(*iteratorp));

	(*iteratorp)->methods->destroy(iteratorp DNS__DB_FLARG_PASS);

	ENSURE(*iteratorp == NULL);
}

isc_result_t
dns__dbiterator_first(dns_dbiterator_t *iterator DNS__DB_FLARG) {
	REQUIRE(DNS_DBITERATOR_VALID(iterator));

	isc_result_t result =
		iterator->methods->first(iterator DNS__DB_FLARG_PASS);
	ENSURE(result == ISC_R_SUCCESS || result == ISC_R_NOMORE);
	return result;
}

isc_result_t
dns__dbiterator_last(dns_dbiterator_t *iterator DNS__DB_FLARG) {
	REQUIRE(DNS_DBITERATOR_VALID(iterator));

	isc_result_t result =
		iterator->methods->last(iterator DNS__DB_FLARG_PASS);
	ENSURE(result == ISC_R_SUCCESS || result == ISC_R_NOMORE);
	return result;
}

isc_result_t
dns__dbiterator_seek(dns_dbiterator_t *iterator,
		     const dns_name_t *name DNS__DB_FLARG) {
	REQUIRE(DNS_DBITERATOR_VALID(iterator));

	return iterator->methods->seek(iterator, name DNS__DB_FLARG_PASS);
}

isc_result_t
dns__dbiterator_seek3(dns_dbiterator_t *iterator,
		      const dns_name_t *name DNS__DB_FLARG) {
	REQUIRE(DNS_DBITERATOR_VALID(iterator));

	return iterator->methods->seek3(iterator, name DNS__DB_FLARG_PASS);
}

isc_result_t
dns__dbiterator_prev(dns_dbiterator_t *iterator DNS__DB_FLARG) {
	REQUIRE(DNS_DBITERATOR_VALID(iterator));

	isc_result_t result =
		iterator->methods->prev(iterator DNS__DB_FLARG_PASS);
	ENSURE(result == ISC_R_SUCCESS || result == ISC_R_NOMORE);
	return result;
}

isc_result_t
dns__dbiterator_next(dns_dbiterator_t *iterator DNS__DB_FLARG) {
	REQUIRE(DNS_DBITERATOR_VALID(iterator));

	isc_result_t result =
		iterator->methods->next(iterator DNS__DB_FLARG_PASS);
	ENSURE(result == ISC_R_SUCCESS || result == ISC_R_NOMORE);
	return result;
}

isc_result_t
dns__dbiterator_current(dns_dbiterator_t *iterator, dns_dbnode_t **nodep,
			dns_fixedname_t *fixed_name DNS__DB_FLARG) {
	dns_name_t *name = dns_fixedname_name(fixed_name);
	REQUIRE(DNS_DBITERATOR_VALID(iterator));
	REQUIRE(nodep != NULL && *nodep == NULL);
	REQUIRE(name == NULL || DNS_NAME_VALID(name));

	return iterator->methods->current(iterator, nodep,
					  fixed_name DNS__DB_FLARG_PASS);
}

isc_result_t
dns_dbiterator_pause(dns_dbiterator_t *iterator) {
	REQUIRE(DNS_DBITERATOR_VALID(iterator));

	return iterator->methods->pause(iterator);
}

isc_result_t
dns_dbiterator_origin(dns_dbiterator_t *iterator, dns_fixedname_t *fixed_name) {
	dns_name_t *name = dns_fixedname_name(fixed_name);
	REQUIRE(DNS_DBITERATOR_VALID(iterator));
	REQUIRE(iterator->relative_names);
	REQUIRE(DNS_NAME_VALID(name));

	return iterator->methods->origin(iterator, fixed_name);
}
