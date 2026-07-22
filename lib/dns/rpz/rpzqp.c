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

#include <isc/bit.h>
#include <isc/magic.h>
#include <isc/refcount.h>
#include <isc/util.h>

#include <dns/name.h>
#include <dns/view.h>

#include "rpz_p.h"

#define DNS_RPZ_QP_MAGIC	ISC_MAGIC('r', 'p', 'z', 'q')
#define DNS_RPZ_QP_VALID(table) ISC_MAGIC_VALID(table, DNS_RPZ_QP_MAGIC)

typedef enum qpdatatype {
	QPDATA_NAME,
	QPDATA_CIDR,
} qpdatatype_t;

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

typedef struct cidrdata {
	dns_rpz_addr_zbits_t prefix[4];
	isc_mem_t *mctx;
	isc_refcount_t references;
	size_t keylen;
	dns_qpshift_t key[];
} cidrdata_t;

#ifdef DNS_RPZ_TRACE
#define nmdata_ref(ptr)	    nmdata__ref(ptr, __func__, __FILE__, __LINE__)
#define nmdata_detach(ptrp) nmdata__detach(ptrp, __func__, __FILE__, __LINE__)
ISC_REFCOUNT_TRACE_DECL(nmdata);
#else
ISC_REFCOUNT_DECL(nmdata);
#endif

#ifdef DNS_RPZ_TRACE
#define cidrdata_ref(ptr) cidrdata__ref(ptr, __func__, __FILE__, __LINE__)
#define cidrdata_detach(ptrp) \
	cidrdata__detach(ptrp, __func__, __FILE__, __LINE__)
ISC_REFCOUNT_TRACE_DECL(cidrdata);
#else
ISC_REFCOUNT_DECL(cidrdata);
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

static cidrdata_t *
new_cidrdata(isc_mem_t *mctx, const dns_qpkey_t key, size_t keylen) {
	cidrdata_t *newdata = NULL;
	size_t size;

	REQUIRE(keylen < sizeof(dns_qpkey_t));

	size = STRUCT_FLEX_SIZE(newdata, key, keylen);
	newdata = isc_mem_get(mctx, size);
	*newdata = (cidrdata_t){
		.references = ISC_REFCOUNT_INITIALIZER(1),
		.keylen = keylen,
	};
	isc_mem_attach(mctx, &newdata->mctx);
	memmove(newdata->key, key, keylen);

#ifdef DNS_RPZ_TRACE
	fprintf(stderr, "new_cidrdata:%s:%s:%d:%p->references = 1\n", __func__,
		__FILE__, __LINE__ + 1, newdata);
#endif

	return newdata;
}

static bool
cidr_is_ipv4(const dns_rpz_cidr_key_t *addr) {
	return addr->ipv4;
}

static unsigned int
cidr_nibble(const dns_rpz_cidr_key_t *addr, unsigned int bit) {
	unsigned int word = bit / DNS_RPZ_CIDR_WORD_BITS;
	unsigned int shift = DNS_RPZ_CIDR_WORD_BITS - 4 -
			     bit % DNS_RPZ_CIDR_WORD_BITS;

	return (addr->w[word] >> shift) & 0xf;
}

/*
 * Encode an address bucket as a relative name whose one-byte labels are the
 * address nibbles in reverse order. dns_qpkey_fromname() reverses the labels
 * again, producing:
 *
 *     <namespace><nibble><separator><nibble><separator>...
 *
 * Reusing the NSEC and NSEC3 namespace values keeps IPv4, IPv6, and ordinary
 * RPZ name keys disjoint while leaving namespace encoding to QP.
 */
static size_t
cidr_key(dns_qpkey_t key, const dns_rpz_cidr_key_t *addr,
	 dns_rpz_prefix_t prefix, unsigned int replica) {
	static const uint8_t hex[] = "0123456789abcdef";
	uint8_t wire[DNS_RPZ_CIDR_WORDS * 16];
	isc_region_t region;
	dns_name_t name;
	dns_namespace_t space;
	unsigned int addrbit, bits, nibbles, remainder;
	size_t keylen;
	bool ipv4 = cidr_is_ipv4(addr);

	if (ipv4) {
		REQUIRE(prefix > 96 && prefix <= DNS_RPZ_CIDR_KEY_BITS);
		addrbit = 96;
		bits = prefix - 96;
		space = DNS_DBNAMESPACE_NSEC;
	} else {
		REQUIRE(prefix > 0 && prefix <= DNS_RPZ_CIDR_KEY_BITS);
		addrbit = 0;
		bits = prefix;
		space = DNS_DBNAMESPACE_NSEC3;
	}

	nibbles = (bits + 3) / 4;
	remainder = (bits - 1) % 4 + 1;
	REQUIRE(replica < 1U << (4 - remainder));

	for (unsigned int n = 0; n < nibbles; n++) {
		unsigned int nibble = cidr_nibble(addr, addrbit + n * 4);
		unsigned int wireoff = (nibbles - n - 1) * 2;

		if (n == nibbles - 1) {
			nibble |= replica;
		}
		wire[wireoff] = 1;
		wire[wireoff + 1] = hex[nibble];
	}

	region = (isc_region_t){
		.base = wire,
		.length = nibbles * 2,
	};
	dns_name_init(&name);
	dns_name_fromregion(&name, &region);
	keylen = dns_qpkey_fromname(key, &name, space);
	INSIST(keylen == 1 + nibbles * 2);

	return keylen;
}

static void
cidr_shape(const dns_rpz_cidr_key_t *addr, dns_rpz_prefix_t prefix,
	   unsigned int *slotp, unsigned int *replicasp) {
	unsigned int bits;

	if (cidr_is_ipv4(addr)) {
		REQUIRE(prefix > 96 && prefix <= DNS_RPZ_CIDR_KEY_BITS);
		bits = prefix - 96;
	} else {
		REQUIRE(prefix > 0 && prefix <= DNS_RPZ_CIDR_KEY_BITS);
		bits = prefix;
	}

	*slotp = (bits - 1) % 4;
	*replicasp = 1U << (3 - *slotp);
}

static dns_rpz_zbits_t
cidr_zbits(const cidrdata_t *data, dns_rpz_type_t type, unsigned int slot) {
	REQUIRE(slot < 4);

	switch (type) {
	case DNS_RPZ_TYPE_CLIENT_IP:
		return data->prefix[slot].client_ip;
	case DNS_RPZ_TYPE_IP:
		return data->prefix[slot].ip;
	case DNS_RPZ_TYPE_NSIP:
		return data->prefix[slot].nsip;
	default:
		UNREACHABLE();
	}
}

static bool
cidrdata_empty(const cidrdata_t *data) {
	for (unsigned int slot = 0; slot < 4; slot++) {
		if (data->prefix[slot].client_ip != 0 ||
		    data->prefix[slot].ip != 0 || data->prefix[slot].nsip != 0)
		{
			return false;
		}
	}

	return true;
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

	result = dns_qp_lookup_name(&qpr, name, DNS_DBNAMESPACE_NORMAL, NULL,
				    &chain, (void **)&data, NULL);
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

dns_rpz_num_t
dns__rpz_qp_find_addr(dns_rpz_qp_t *table, dns_rpz_type_t type,
		      dns_rpz_zbits_t zbits, const dns_rpz_cidr_key_t *addr,
		      dns_rpz_prefix_t *prefixp) {
	dns_qpkey_t key;
	dns_qpchain_t chain;
	dns_qpread_t qpr;
	dns_rpz_num_t best = DNS_RPZ_INVALID_NUM;
	dns_rpz_prefix_t best_prefix = 0;
	size_t keylen;
	isc_result_t result;
	bool ipv4;

	REQUIRE(DNS_RPZ_QP_VALID(table));
	REQUIRE(type == DNS_RPZ_TYPE_CLIENT_IP || type == DNS_RPZ_TYPE_IP ||
		type == DNS_RPZ_TYPE_NSIP);
	REQUIRE(zbits != 0);
	REQUIRE(addr != NULL);
	REQUIRE(prefixp != NULL);

	ipv4 = cidr_is_ipv4(addr);
	keylen = cidr_key(key, addr, DNS_RPZ_CIDR_KEY_BITS, 0);

	dns_qpmulti_query(table->multi, &qpr);
	dns_qpchain_init(&qpr, &chain);
	result = dns_qp_lookup(&qpr, key, keylen, NULL, &chain, NULL, NULL);
	if (result != ISC_R_SUCCESS && result != DNS_R_PARTIALMATCH) {
		INSIST(result == ISC_R_NOTFOUND);
		goto done;
	}

	for (unsigned int level = 0; level < dns_qpchain_length(&chain);
	     level++)
	{
		cidrdata_t *data = NULL;
		uint32_t datatype = 0;
		unsigned int nibbles;

		dns_qpchain_node(&chain, level, (void **)&data, &datatype);
		INSIST(datatype == QPDATA_CIDR);
		INSIST(data->keylen > 1 && (data->keylen & 1) != 0);
		nibbles = (data->keylen - 1) / 2;

		for (unsigned int slot = 0; slot < 4; slot++) {
			dns_rpz_zbits_t found = cidr_zbits(data, type, slot) &
						zbits;
			dns_rpz_num_t rpz_num;
			dns_rpz_prefix_t prefix;

			if (found == 0) {
				continue;
			}
			/*
			 * Callers examine matching zones from higher numbers
			 * toward higher-priority lower numbers.  Return the
			 * highest-numbered eligible zone here, and its longest
			 * matching prefix, so a later call can continue that
			 * iteration.
			 */
			rpz_num = DNS_RPZ_MAX_ZONES - 1 -
				  (dns_rpz_num_t)stdc_leading_zeros(found);
			prefix = 4 * (nibbles - 1) + slot + 1;
			if (ipv4) {
				prefix += 96;
			}

			if (best == DNS_RPZ_INVALID_NUM || rpz_num > best ||
			    (rpz_num == best && prefix > best_prefix))
			{
				best = rpz_num;
				best_prefix = prefix;
			}
		}
	}

done:
	dns_qpread_destroy(table->multi, &qpr);
	if (best != DNS_RPZ_INVALID_NUM) {
		*prefixp = best_prefix;
	}
	return best;
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
		result = dns_qp_insert(write->qp, data, QPDATA_NAME);
		nmdata_detach(&data);
		return result;
	}
	INSIST(type == QPDATA_NAME);

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
dns__rpz_qp_add_cidr(dns_rpz_qp_write_t *write, const dns_rpz_cidr_key_t *addr,
		     dns_rpz_prefix_t prefix,
		     const dns_rpz_addr_zbits_t *new_data) {
	unsigned int replicas, slot;
	bool exists = true;

	REQUIRE(write != NULL && DNS_RPZ_QP_VALID(write->table));
	REQUIRE(write->qp != NULL);
	REQUIRE(addr != NULL);
	REQUIRE(new_data != NULL);

	cidr_shape(addr, prefix, &slot, &replicas);
	for (unsigned int replica = 0; replica < replicas; replica++) {
		cidrdata_t *data = NULL;
		dns_qpkey_t key;
		size_t keylen = cidr_key(key, addr, prefix, replica);
		uint32_t type = 0;
		isc_result_t result;

		result = dns_qp_getkey(write->qp, key, keylen, (void **)&data,
				       &type);
		if (result == ISC_R_NOTFOUND) {
			exists = false;
			data = new_cidrdata(write->table->mctx, key, keylen);
			data->prefix[slot] = *new_data;
			result = dns_qp_insert(write->qp, data, QPDATA_CIDR);
			cidrdata_detach(&data);
			if (result != ISC_R_SUCCESS) {
				return result;
			}
			continue;
		}
		if (result != ISC_R_SUCCESS) {
			return result;
		}

		INSIST(data != NULL);
		INSIST(type == QPDATA_CIDR);
		if ((data->prefix[slot].client_ip & new_data->client_ip) == 0 &&
		    (data->prefix[slot].ip & new_data->ip) == 0 &&
		    (data->prefix[slot].nsip & new_data->nsip) == 0)
		{
			exists = false;
		}
		data->prefix[slot].client_ip |= new_data->client_ip;
		data->prefix[slot].ip |= new_data->ip;
		data->prefix[slot].nsip |= new_data->nsip;
	}

	return exists ? ISC_R_EXISTS : ISC_R_SUCCESS;
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
	INSIST(type == QPDATA_NAME);
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

isc_result_t
dns__rpz_qp_delete_cidr(dns_rpz_qp_write_t *write,
			const dns_rpz_cidr_key_t *addr, dns_rpz_prefix_t prefix,
			const dns_rpz_addr_zbits_t *del_data, bool *existsp) {
	unsigned int replicas, slot;

	REQUIRE(write != NULL && DNS_RPZ_QP_VALID(write->table));
	REQUIRE(write->qp != NULL);
	REQUIRE(addr != NULL);
	REQUIRE(del_data != NULL);
	REQUIRE(existsp != NULL);

	*existsp = false;
	cidr_shape(addr, prefix, &slot, &replicas);
	for (unsigned int replica = 0; replica < replicas; replica++) {
		cidrdata_t *data = NULL;
		dns_qpkey_t key;
		dns_rpz_addr_zbits_t found;
		size_t keylen = cidr_key(key, addr, prefix, replica);
		uint32_t type = 0;
		isc_result_t result;

		result = dns_qp_getkey(write->qp, key, keylen, (void **)&data,
				       &type);
		if (result == ISC_R_NOTFOUND) {
			continue;
		}
		if (result != ISC_R_SUCCESS) {
			return result;
		}

		INSIST(data != NULL);
		INSIST(type == QPDATA_CIDR);
		found = *del_data;
		found.client_ip &= data->prefix[slot].client_ip;
		found.ip &= data->prefix[slot].ip;
		found.nsip &= data->prefix[slot].nsip;
		if (found.client_ip != 0 || found.ip != 0 || found.nsip != 0) {
			*existsp = true;
		}

		data->prefix[slot].client_ip &= ~found.client_ip;
		data->prefix[slot].ip &= ~found.ip;
		data->prefix[slot].nsip &= ~found.nsip;
		if (cidrdata_empty(data)) {
			result = dns_qp_deletekey(write->qp, key, keylen, NULL,
						  NULL);
			if (result != ISC_R_SUCCESS) {
				return result;
			}
		}
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
destroy_cidrdata(cidrdata_t *data) {
	size_t size = STRUCT_FLEX_SIZE(data, key, data->keylen);
	isc_mem_putanddetach(&data->mctx, data, size);
}

#ifdef DNS_RPZ_TRACE
ISC_REFCOUNT_TRACE_IMPL(cidrdata, destroy_cidrdata);
#else
ISC_REFCOUNT_IMPL(cidrdata, destroy_cidrdata);
#endif

static void
qp_attach(void *uctx ISC_ATTR_UNUSED, void *pval, uint32_t ival) {
	switch ((qpdatatype_t)ival) {
	case QPDATA_NAME:
		nmdata_ref(pval);
		break;
	case QPDATA_CIDR:
		cidrdata_ref(pval);
		break;
	default:
		UNREACHABLE();
	}
}

static void
qp_detach(void *uctx ISC_ATTR_UNUSED, void *pval, uint32_t ival) {
	switch ((qpdatatype_t)ival) {
	case QPDATA_NAME: {
		nmdata_t *data = pval;
		nmdata_detach(&data);
		break;
	}
	case QPDATA_CIDR: {
		cidrdata_t *data = pval;
		cidrdata_detach(&data);
		break;
	}
	default:
		UNREACHABLE();
	}
}

static size_t
qp_makekey(dns_qpkey_t key, void *uctx ISC_ATTR_UNUSED, void *pval,
	   uint32_t ival) {
	switch ((qpdatatype_t)ival) {
	case QPDATA_NAME: {
		nmdata_t *data = pval;
		INSIST(data->keylen < sizeof(dns_qpkey_t));
		memmove(key, data->key, data->keylen);
		return data->keylen;
	}
	case QPDATA_CIDR: {
		cidrdata_t *data = pval;
		INSIST(data->keylen < sizeof(dns_qpkey_t));
		memmove(key, data->key, data->keylen);
		return data->keylen;
	}
	default:
		UNREACHABLE();
	}
}

static void
qp_triename(void *uctx, char *buf, size_t size) {
	dns_view_t *view = uctx;
	snprintf(buf, size, "view %s RPZs", view->name);
}
