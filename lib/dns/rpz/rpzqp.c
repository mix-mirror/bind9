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

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <isc/magic.h>
#include <isc/refcount.h>
#include <isc/util.h>

#include <dns/name.h>
#include <dns/view.h>

#include "rpz_p.h"

#define DNS_RPZ_QP_MAGIC	ISC_MAGIC('r', 'p', 'z', 'q')
#define DNS_RPZ_QP_VALID(table) ISC_MAGIC_VALID(table, DNS_RPZ_QP_MAGIC)

typedef enum nmdatatype {
	NMDATA_NAME,
} nmdatatype_t;

/*
 * The leaf type is stored in the QP leaf's integer value.  The complete,
 * encoded QP key, including its namespace digit, is stored here so makekey()
 * does not need the original object used to construct it.
 */
typedef struct nmdata {
	dns_rpz_qp_name_data_t data;
	isc_mem_t *mctx;
	isc_refcount_t references;
	size_t keylen;
	dns_qpshift_t key[];
} nmdata_t;

#ifdef DNS_RPZ_TRACE
#define nmdata_ref(ptr)	    nmdata__ref(ptr, __func__, __FILE__, __LINE__)
#define nmdata_detach(ptrp) nmdata__detach(ptrp, __func__, __FILE__, __LINE__)
ISC_REFCOUNT_TRACE_DECL(nmdata);
#else
ISC_REFCOUNT_DECL(nmdata);
#endif

static void
qp_attach(void *uctx, void *pval, uint32_t ival);
static void
qp_detach(void *uctx, void *pval, uint32_t ival);
static size_t
qp_makekey(dns_qpkey_t key, void *uctx, void *pval, uint32_t ival);
static void
qp_triename(void *uctx, char *buf, size_t size);

static dns_qpmethods_t qpmethods = {
	qp_attach,
	qp_detach,
	qp_makekey,
	qp_triename,
};

static nmdata_t *
new_nmdata(isc_mem_t *mctx, const dns_qpkey_t key, size_t keylen,
	   const dns_rpz_qp_name_data_t *data) {
	nmdata_t *newdata = NULL;
	size_t size;

	REQUIRE(keylen < sizeof(dns_qpkey_t));

	size = STRUCT_FLEX_SIZE(newdata, key, keylen);
	newdata = isc_mem_get(mctx, size);
	*newdata = (nmdata_t){
		.data = *data,
		.references = ISC_REFCOUNT_INITIALIZER(1),
		.keylen = keylen,
	};
	isc_mem_attach(mctx, &newdata->mctx);
	memmove(newdata->key, key, keylen);

#ifdef DNS_RPZ_TRACE
	fprintf(stderr, "new_nmdata:%s:%s:%d:%p->references = 1\n", __func__,
		__FILE__, __LINE__ + 1, newdata);
#endif

	return newdata;
}

void
dns__rpz_qp_create(isc_mem_t *mctx, dns_view_t *view, dns_rpz_qp_t **tablep) {
	dns_rpz_qp_t *table = NULL;

	REQUIRE(mctx != NULL);
	REQUIRE(view != NULL);
	REQUIRE(tablep != NULL && *tablep == NULL);

	table = isc_mem_get(mctx, sizeof(*table));
	*table = (dns_rpz_qp_t){
		.magic = DNS_RPZ_QP_MAGIC,
	};
	isc_mem_attach(mctx, &table->mctx);
	dns_qpmulti_create(mctx, &qpmethods, view, &table->multi);

	*tablep = table;
}

void
dns__rpz_qp_destroy(dns_rpz_qp_t **tablep) {
	dns_rpz_qp_t *table = NULL;
	isc_mem_t *mctx = NULL;

	REQUIRE(tablep != NULL);
	table = *tablep;
	REQUIRE(DNS_RPZ_QP_VALID(table));
	*tablep = NULL;

	dns_qpmulti_destroy(&table->multi);
	table->magic = 0;
	mctx = table->mctx;
	table->mctx = NULL;
	isc_mem_putanddetach(&mctx, table, sizeof(*table));
}

isc_result_t
dns__rpz_qp_find_name(dns_rpz_qp_t *table, dns_rpz_type_t type,
		      const dns_name_t *name, dns_rpz_zbits_t *zbitsp) {
	isc_result_t result;
	nmdata_t *data = NULL;
	dns_qpchain_t chain;
	dns_qpread_t qpr;
	int i;

	REQUIRE(DNS_RPZ_QP_VALID(table));
	REQUIRE(type == DNS_RPZ_TYPE_QNAME || type == DNS_RPZ_TYPE_NSDNAME);
	REQUIRE(name != NULL);
	REQUIRE(zbitsp != NULL);

	*zbitsp = 0;
	dns_qpmulti_query(table->multi, &qpr);
	dns_qpchain_init(&qpr, &chain);

	result = dns_qp_lookup(&qpr, name, DNS_DBNAMESPACE_NORMAL, NULL, &chain,
			       (void **)&data, NULL);
	switch (result) {
	case ISC_R_SUCCESS:
		INSIST(data != NULL);
		if (type == DNS_RPZ_TYPE_QNAME) {
			*zbitsp = data->data.set.qname;
		} else {
			*zbitsp = data->data.set.ns;
		}
		FALLTHROUGH;

	case DNS_R_PARTIALMATCH:
		i = dns_qpchain_length(&chain);
		while (i-- > 0) {
			dns_qpchain_node(&chain, i, (void **)&data, NULL);
			INSIST(data != NULL);
			if (type == DNS_RPZ_TYPE_QNAME) {
				*zbitsp |= data->data.wild.qname;
			} else {
				*zbitsp |= data->data.wild.ns;
			}
		}
		result = ISC_R_SUCCESS;
		break;

	case ISC_R_NOTFOUND:
		result = ISC_R_SUCCESS;
		break;

	default:
		break;
	}

	dns_qpread_destroy(table->multi, &qpr);
	return result;
}

void
dns__rpz_qp_write(dns_rpz_qp_t *table, dns_rpz_qp_write_t *write) {
	REQUIRE(DNS_RPZ_QP_VALID(table));
	REQUIRE(write != NULL && write->table == NULL && write->qp == NULL);

	write->table = table;
	dns_qpmulti_write(table->multi, &write->qp);
}

isc_result_t
dns__rpz_qp_add_name(dns_rpz_qp_write_t *write, const dns_name_t *name,
		     const dns_rpz_qp_name_data_t *new_data) {
	isc_result_t result;
	nmdata_t *data = NULL;
	dns_qpkey_t key;
	size_t keylen;
	uint32_t type = 0;

	REQUIRE(write != NULL && DNS_RPZ_QP_VALID(write->table));
	REQUIRE(write->qp != NULL);
	REQUIRE(name != NULL);
	REQUIRE(new_data != NULL);

	keylen = dns_qpkey_fromname(key, name, DNS_DBNAMESPACE_NORMAL);
	result = dns_qp_getkey(write->qp, key, keylen, (void **)&data, &type);
	if (result != ISC_R_SUCCESS) {
		INSIST(data == NULL);
		data = new_nmdata(write->table->mctx, key, keylen, new_data);
		result = dns_qp_insert(write->qp, data, NMDATA_NAME);
		nmdata_detach(&data);
		return result;
	}
	INSIST(type == NMDATA_NAME);

	if ((data->data.set.qname & new_data->set.qname) != 0 ||
	    (data->data.set.ns & new_data->set.ns) != 0 ||
	    (data->data.wild.qname & new_data->wild.qname) != 0 ||
	    (data->data.wild.ns & new_data->wild.ns) != 0)
	{
		result = ISC_R_EXISTS;
	}

	data->data.set.qname |= new_data->set.qname;
	data->data.set.ns |= new_data->set.ns;
	data->data.wild.qname |= new_data->wild.qname;
	data->data.wild.ns |= new_data->wild.ns;

	return result;
}

isc_result_t
dns__rpz_qp_delete_name(dns_rpz_qp_write_t *write, const dns_name_t *name,
			const dns_rpz_qp_name_data_t *del_data, bool *existsp) {
	isc_result_t result;
	nmdata_t *data = NULL;
	dns_rpz_qp_name_data_t found;
	dns_qpkey_t key;
	size_t keylen;
	uint32_t type = 0;

	REQUIRE(write != NULL && DNS_RPZ_QP_VALID(write->table));
	REQUIRE(write->qp != NULL);
	REQUIRE(name != NULL);
	REQUIRE(del_data != NULL);
	REQUIRE(existsp != NULL);

	*existsp = false;
	keylen = dns_qpkey_fromname(key, name, DNS_DBNAMESPACE_NORMAL);
	result = dns_qp_getkey(write->qp, key, keylen, (void **)&data, &type);
	if (result == ISC_R_NOTFOUND) {
		return ISC_R_SUCCESS;
	}
	if (result != ISC_R_SUCCESS) {
		return result;
	}

	INSIST(data != NULL);
	INSIST(type == NMDATA_NAME);
	found = *del_data;
	found.set.qname &= data->data.set.qname;
	found.set.ns &= data->data.set.ns;
	found.wild.qname &= data->data.wild.qname;
	found.wild.ns &= data->data.wild.ns;

	*existsp = (found.set.qname != 0 || found.set.ns != 0 ||
		    found.wild.qname != 0 || found.wild.ns != 0);

	data->data.set.qname &= ~found.set.qname;
	data->data.set.ns &= ~found.set.ns;
	data->data.wild.qname &= ~found.wild.qname;
	data->data.wild.ns &= ~found.wild.ns;

	if (data->data.set.qname == 0 && data->data.set.ns == 0 &&
	    data->data.wild.qname == 0 && data->data.wild.ns == 0)
	{
		return dns_qp_deletekey(write->qp, key, keylen, NULL, NULL);
	}

	return ISC_R_SUCCESS;
}

void
dns__rpz_qp_commit(dns_rpz_qp_write_t *write) {
	dns_rpz_qp_t *table = NULL;

	REQUIRE(write != NULL && DNS_RPZ_QP_VALID(write->table));
	REQUIRE(write->qp != NULL);

	table = write->table;
	dns_qp_compact(write->qp, DNS_QPGC_MAYBE);
	dns_qpmulti_commit(table->multi, &write->qp);
	write->table = NULL;
}

static void
destroy_nmdata(nmdata_t *data) {
	size_t size = STRUCT_FLEX_SIZE(data, key, data->keylen);
	isc_mem_putanddetach(&data->mctx, data, size);
}

#ifdef DNS_RPZ_TRACE
ISC_REFCOUNT_TRACE_IMPL(nmdata, destroy_nmdata);
#else
ISC_REFCOUNT_IMPL(nmdata, destroy_nmdata);
#endif

static void
qp_attach(void *uctx ISC_ATTR_UNUSED, void *pval, uint32_t ival) {
	nmdata_t *data = pval;
	INSIST(ival == NMDATA_NAME);
	nmdata_ref(data);
}

static void
qp_detach(void *uctx ISC_ATTR_UNUSED, void *pval, uint32_t ival) {
	nmdata_t *data = pval;
	INSIST(ival == NMDATA_NAME);
	nmdata_detach(&data);
}

static size_t
qp_makekey(dns_qpkey_t key, void *uctx ISC_ATTR_UNUSED, void *pval,
	   uint32_t ival) {
	nmdata_t *data = pval;

	INSIST(ival == NMDATA_NAME);
	INSIST(data->keylen < sizeof(dns_qpkey_t));
	memmove(key, data->key, data->keylen);
	return data->keylen;
}

static void
qp_triename(void *uctx, char *buf, size_t size) {
	dns_view_t *view = uctx;
	snprintf(buf, size, "view %s RPZs", view->name);
}
