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
 * This is deliberately a qpzone implementation experiment, not an example of
 * how an application should use dns_db_t.  Pulling qpzone.c into this binary
 * gives the benchmark access to qpzone's concrete nodes, versions, and shared
 * QP transactions without going through the dns_db/DynDB method table.
 */

#include <inttypes.h>
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <isc/bit.h>
#include <isc/endian.h>
#include <isc/file.h>
#include <isc/iterated_hash.h>
#include <isc/lib.h>
#include <isc/md.h>
#include <isc/result.h>
#include <isc/util.h>

#include <dns/callbacks.h>
#include <dns/fixedname.h>
#include <dns/lib.h>
#include <dns/master.h>
#include <dns/name.h>
#include <dns/qp.h>
#include <dns/rdata.h>
#include <dns/rdatalist.h>
#include <dns/rdataset.h>
#include <dns/soa.h>
#include <dns/types.h>

#include "qpzone_p.h"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wshadow"
#include "qpzone.c"
#pragma GCC diagnostic pop

#define NSEC3_HASH_ALGORITHM dns_hash_sha1
#define NSEC3_ITERATIONS     0U
#define NSEC3_SALT_LENGTH    0U
#define NSEC3_HASH_LENGTH    ISC_SHA1_DIGESTLENGTH

#define U16BITMAP_MAXCOMPRESSEDSIZE (256U * (2U + 32U))

typedef uint8_t u16window_t[32];

typedef struct u16bitmap {
	uint8_t active[32];
	uint8_t bits[256][32];
} u16bitmap_t;

/*
 * Local copy of the const-iterators u16 bitmap.  In particular, it uses DNS
 * bitmap bit order and lazily clears only the windows activated since reinit.
 */
static uint8_t
window_mask(unsigned int bit) {
	return (uint8_t)(1U << (7U - (bit % 8U)));
}

static void
window_reinit(u16window_t *window) {
	memset(*window, 0, sizeof(*window));
}

static void
window_set(u16window_t *window, uint8_t value) {
	(*window)[value / 8U] |= window_mask(value);
}

static bool
window_isset(const u16window_t *window, uint8_t value) {
	return ((*window)[value / 8U] & window_mask(value)) != 0;
}

static void
window_unset(u16window_t *window, uint8_t value) {
	(*window)[value / 8U] &= (uint8_t)~window_mask(value);
}

static uint32_t
window_count(const u16window_t *window) {
	uint32_t count = 0;

	for (uint_fast8_t i = 0; i < 32; i++) {
		count += stdc_count_ones((unsigned int)(*window)[i]);
	}

	return count;
}

static uint8_t
window_length(const u16window_t *window) {
	for (size_t length = 32; length > 0; length--) {
		if ((*window)[length - 1] != 0) {
			return (uint8_t)length;
		}
	}

	return 0;
}

static int32_t
window_firstfrom(const u16window_t *window, int32_t value) {
	for (; value < 256; value++) {
		if (window_isset(window, (uint8_t)value)) {
			return value;
		}
	}

	return INT32_MAX;
}

static void
u16bitmap_reinit(u16bitmap_t *bitmap) {
	window_reinit(&bitmap->active);
}

static void
u16bitmap_set(u16bitmap_t *bitmap, uint16_t value) {
	uint8_t window = (uint8_t)(value >> 8);

	if (!window_isset(&bitmap->active, window)) {
		window_reinit(&bitmap->bits[window]);
		window_set(&bitmap->active, window);
	}

	window_set(&bitmap->bits[window], (uint8_t)value);
}

static void
u16bitmap_unset(u16bitmap_t *bitmap, uint16_t value) {
	uint8_t window = (uint8_t)(value >> 8);

	if (window_isset(&bitmap->active, window)) {
		window_unset(&bitmap->bits[window], (uint8_t)value);
	}
}

static bool
u16bitmap_isset(const u16bitmap_t *bitmap, uint16_t value) {
	uint8_t window = (uint8_t)(value >> 8);

	return window_isset(&bitmap->active, window) &&
	       window_isset(&bitmap->bits[window], (uint8_t)value);
}

static int32_t
u16bitmap_next(const u16bitmap_t *bitmap, int32_t value) {
	int32_t start = value == INT32_MAX ? INT32_MAX : value + 1;
	int32_t start_window = start >> 8;
	int32_t offset = start & 0xff;

	for (int32_t window = window_firstfrom(&bitmap->active, start_window);
	     window != INT32_MAX;
	     window = window_firstfrom(&bitmap->active, window + 1))
	{
		int32_t next = window_firstfrom(&bitmap->bits[window], offset);
		if (next != INT32_MAX) {
			return (window << 8) | next;
		}
		offset = 0;
	}

	return INT32_MAX;
}

static uint32_t
u16bitmap_count(const u16bitmap_t *bitmap) {
	uint32_t count = 0;

	for (int32_t window = window_firstfrom(&bitmap->active, 0);
	     window != INT32_MAX;
	     window = window_firstfrom(&bitmap->active, window + 1))
	{
		count += window_count(&bitmap->bits[window]);
	}

	return count;
}

static size_t
u16bitmap_compress(const u16bitmap_t *bitmap, uint8_t *target) {
	uint8_t *start = target;

	for (int32_t window = window_firstfrom(&bitmap->active, 0);
	     window != INT32_MAX;
	     window = window_firstfrom(&bitmap->active, window + 1))
	{
		uint8_t length = window_length(&bitmap->bits[window]);

		if (length == 0) {
			continue;
		}
		*target++ = (uint8_t)window;
		*target++ = length;
		memmove(target, &bitmap->bits[window], length);
		target += length;
	}

	return (size_t)(target - start);
}

typedef struct byte_vec {
	uint8_t *data;
	size_t len;
	size_t cap;
} byte_vec_t;

/*
 * The requested pointer does not fit alongside an eight-byte prefix, offset,
 * and count in 16 bytes on a 64-bit host.  Keep this hot sorting vector at 16
 * bytes and store the pointer after the variable-length type list in bytes.
 */
typedef struct nsec3_item {
	uint8_t hash_prefix[8];
	uint32_t bytes_offset;
	uint16_t type_count;
	uint16_t flags;
} nsec3_item_t;

_Static_assert(sizeof(nsec3_item_t) == 16, "nsec3_item_t must be 16 bytes");

typedef struct item_vec {
	nsec3_item_t *data;
	size_t len;
	size_t cap;
} item_vec_t;

enum {
	ITEM_APEX = 1U << 0,
	ITEM_DELEGATION = 1U << 1,
	ITEM_EMPTY = 1U << 2,
};

static void
fatal(const char *message) {
	fprintf(stderr, "nsec3-full-rebuild: %s\n", message);
	exit(EXIT_FAILURE);
}

static void
fatal_result(const char *operation, isc_result_t result) {
	fprintf(stderr, "nsec3-full-rebuild: %s: %s\n", operation,
		isc_result_totext(result));
	exit(EXIT_FAILURE);
}

static uint64_t
monotonic_ns(void) {
	struct timespec now;

	if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
		perror("clock_gettime");
		exit(EXIT_FAILURE);
	}

	return (uint64_t)now.tv_sec * 1000000000U + (uint64_t)now.tv_nsec;
}

static void
vec_reserve(void **data, size_t *capacity, size_t needed, size_t element_size) {
	size_t new_capacity = *capacity == 0 ? 1024 : *capacity;
	void *new_data = NULL;

	if (needed <= *capacity) {
		return;
	}
	while (new_capacity < needed) {
		if (new_capacity > SIZE_MAX / 2U) {
			fatal("vector capacity overflow");
		}
		new_capacity *= 2U;
	}
	if (new_capacity > SIZE_MAX / element_size) {
		fatal("vector allocation overflow");
	}
	new_data = realloc(*data, new_capacity * element_size);
	if (new_data == NULL) {
		fatal("out of memory growing vector");
	}
	*data = new_data;
	*capacity = new_capacity;
}

static void
byte_vec_append(byte_vec_t *vec, const void *source, size_t length) {
	if (length > SIZE_MAX - vec->len) {
		fatal("byte vector length overflow");
	}
	vec_reserve((void **)&vec->data, &vec->cap, vec->len + length,
		    sizeof(*vec->data));
	memmove(vec->data + vec->len, source, length);
	vec->len += length;
}

static const uint8_t *
item_hash(const byte_vec_t *bytes, const nsec3_item_t *item) {
	return bytes->data + item->bytes_offset;
}

static const uint8_t *
item_types(const byte_vec_t *bytes, const nsec3_item_t *item) {
	return item_hash(bytes, item) + NSEC3_HASH_LENGTH;
}

static qpznode_t *
item_node(const byte_vec_t *bytes, const nsec3_item_t *item) {
	qpznode_t *node = NULL;
	const uint8_t *source = item_types(bytes, item) +
				item->type_count * sizeof(uint16_t);

	memcpy(&node, source, sizeof(node));
	return node;
}

static void
item_vec_push(item_vec_t *items, byte_vec_t *bytes,
	      const uint8_t hash[NSEC3_HASH_LENGTH], const u16bitmap_t *types,
	      qpznode_t *node, uint16_t flags) {
	uint32_t type_count = u16bitmap_count(types);
	nsec3_item_t item = { .flags = flags };

	if (type_count > UINT16_MAX) {
		fatal("a node has too many distinct types");
	}
	if (bytes->len > UINT32_MAX) {
		fatal("byte vector exceeded the 32-bit item offset");
	}

	memcpy(item.hash_prefix, hash, sizeof(item.hash_prefix));
	item.bytes_offset = (uint32_t)bytes->len;
	item.type_count = (uint16_t)type_count;

	byte_vec_append(bytes, hash, NSEC3_HASH_LENGTH);
	for (int32_t type = u16bitmap_next(types, -1); type != INT32_MAX;
	     type = u16bitmap_next(types, type))
	{
		uint16_t stored_type = (uint16_t)type;
		byte_vec_append(bytes, &stored_type, sizeof(stored_type));
	}
	byte_vec_append(bytes, &node, sizeof(node));

	vec_reserve((void **)&items->data, &items->cap, items->len + 1U,
		    sizeof(*items->data));
	items->data[items->len++] = item;
}

static void
hash_name(const dns_name_t *name, uint8_t hash[NSEC3_HASH_LENGTH]) {
	static const uint8_t empty_salt[1] = { 0 };
	int length = isc_iterated_hash(
		hash, NSEC3_HASH_ALGORITHM, NSEC3_ITERATIONS, empty_salt,
		NSEC3_SALT_LENGTH, name->ndata, name->length);

	if (length != NSEC3_HASH_LENGTH) {
		fatal("SHA-1 hashing failed");
	}
}

static void
push_name(item_vec_t *items, byte_vec_t *bytes, const dns_name_t *name,
	  const u16bitmap_t *types, qpznode_t *node, uint16_t flags) {
	uint8_t hash[NSEC3_HASH_LENGTH];

	hash_name(name, hash);
	item_vec_push(items, bytes, hash, types, node, flags);
}

static void
push_empty_nonterminals(item_vec_t *items, byte_vec_t *bytes,
			const dns_name_t *previous, const dns_name_t *next) {
	u16bitmap_t no_types;
	unsigned int common_labels = 0;
	unsigned int labels = dns_name_countlabels(next);
	int order = 0;

	u16bitmap_reinit(&no_types);
	(void)dns_name_fullcompare(previous, next, &order, &common_labels);
	while (labels > common_labels + 1U) {
		dns_fixedname_t fixed;
		dns_name_t *empty = dns_fixedname_initname(&fixed);

		labels--;
		dns_name_split(next, labels, NULL, empty);
		push_name(items, bytes, empty, &no_types, NULL, ITEM_EMPTY);
	}
}

static uint32_t
gather_types(qpzonedb_t *qpdb, qpz_version_t *reader, qpznode_t *node,
	     bool apex, u16bitmap_t *types, dns_ttl_t *nsec3_ttl,
	     bool *found_soa) {
	u16bitmap_reinit(types);

	ISC_SLIST_FOREACH(top, node->next_type, next_type) {
		dns_vecheader_t *header = first_existing_header(top,
								reader->serial);
		dns_rdatatype_t type;

		if (header == NULL) {
			continue;
		}
		type = DNS_TYPEPAIR_TYPE(top->typepair);
		u16bitmap_set(types, type);

		if (apex && top->typepair == DNS_TYPEPAIR(dns_rdatatype_soa)) {
			rdatavec_iter_t iterator;
			dns_rdata_t rdata = DNS_RDATA_INIT;
			isc_result_t result = vecheader_first(
				&iterator, header, qpdb->common.rdclass);

			if (result != ISC_R_SUCCESS) {
				fatal_result("reading the apex SOA", result);
			}
			vecheader_current(&iterator, &rdata);
			*nsec3_ttl = ISC_MIN(header->ttl,
					     dns_soa_getminimum(&rdata));
			*found_soa = true;
		}
	}

	/*
	 * The reader version cannot see the pending writer version.  Add the
	 * NSEC3PARAM type virtually so the apex bitmap describes the version we
	 * are about to commit, then install that RRset in the same transaction.
	 */
	if (apex) {
		u16bitmap_set(types, dns_rdatatype_nsec3param);
	}

	return u16bitmap_count(types);
}

static void
prepare_items(qpzonedb_t *qpdb, qpz_version_t *reader, bool optout,
	      item_vec_t *items, byte_vec_t *bytes, dns_ttl_t *nsec3_ttl) {
	dns_qpread_t query = { 0 };
	dns_qpiter_t iterator = { 0 };
	dns_fixedname_t previous_fixed;
	dns_fixedname_t zonecut_fixed;
	dns_name_t *previous = NULL;
	dns_name_t *zonecut = NULL;
	bool found_soa = false;
	isc_result_t result;

	dns_qpmulti_query(qpdb->tree, &query);
	dns_qpiter_init(&query, &iterator);

	for (;;) {
		qpznode_t *node = NULL;
		dns_fixedname_t normalized_fixed;
		dns_name_t *normalized;
		u16bitmap_t types;
		uint16_t flags = 0;
		bool apex, delegation, dname;

		result = dns_qpiter_next(&iterator, (void **)&node, NULL);
		if (result != ISC_R_SUCCESS) {
			break;
		}
		if (atomic_load_acquire(&node->nspace) !=
		    DNS_DBNAMESPACE_NORMAL)
		{
			continue;
		}

		normalized = dns_fixedname_initname(&normalized_fixed);
		dns_name_downcase(&node->name, normalized);
		if (!dns_name_issubdomain(normalized, &qpdb->common.origin)) {
			continue;
		}
		if (zonecut != NULL) {
			if (dns_name_issubdomain(normalized, zonecut)) {
				continue;
			}
			zonecut = NULL;
		}

		apex = node == qpdb->origin;
		if (gather_types(qpdb, reader, node, apex, &types, nsec3_ttl,
				 &found_soa) == 0)
		{
			continue;
		}

		delegation = !apex && u16bitmap_isset(&types, dns_rdatatype_ns);
		dname = u16bitmap_isset(&types, dns_rdatatype_dname);
		if (delegation || dname) {
			zonecut = dns_fixedname_initname(&zonecut_fixed);
			dns_name_copy(normalized, zonecut);
		}
		if (optout && delegation &&
		    !u16bitmap_isset(&types, dns_rdatatype_ds))
		{
			continue;
		}

		if (previous != NULL) {
			push_empty_nonterminals(items, bytes, previous,
						normalized);
		}
		if (apex) {
			flags |= ITEM_APEX;
		}
		if (delegation) {
			flags |= ITEM_DELEGATION;
		}
		push_name(items, bytes, normalized, &types, node, flags);

		previous = dns_fixedname_initname(&previous_fixed);
		dns_name_copy(normalized, previous);
	}

	dns_qpread_destroy(qpdb->tree, &query);
	if (result != ISC_R_NOMORE) {
		fatal_result("iterating over the qpzone", result);
	}
	if (!found_soa) {
		fatal("the loaded zone has no apex SOA");
	}
	if (items->len == 0) {
		fatal("the NSEC3 membership set is empty");
	}
}

static const byte_vec_t *sort_bytes;

static int
compare_items(const void *left_pointer, const void *right_pointer) {
	const nsec3_item_t *left = left_pointer;
	const nsec3_item_t *right = right_pointer;
	int order = memcmp(left->hash_prefix, right->hash_prefix,
			   sizeof(left->hash_prefix));

	if (order != 0) {
		return order;
	}
	return memcmp(item_hash(sort_bytes, left) + sizeof(left->hash_prefix),
		      item_hash(sort_bytes, right) + sizeof(right->hash_prefix),
		      NSEC3_HASH_LENGTH - sizeof(left->hash_prefix));
}

static void
sort_items(item_vec_t *items, const byte_vec_t *bytes) {
	sort_bytes = bytes;
	qsort(items->data, items->len, sizeof(*items->data), compare_items);
	sort_bytes = NULL;

	for (size_t i = 1; i < items->len; i++) {
		if (memcmp(item_hash(bytes, &items->data[i - 1]),
			   item_hash(bytes, &items->data[i]),
			   NSEC3_HASH_LENGTH) == 0)
		{
			fatal("duplicate SHA-1 hash in NSEC3 membership set");
		}
	}
}

static const uint8_t base32hex[] = "0123456789ABCDEFGHIJKLMNOPQRSTUV";

static void
base32hex_encode_block(uint64_t block, uint8_t *target) {
	target[0] = base32hex[(block >> 59) & 0x1fU];
	target[1] = base32hex[(block >> 54) & 0x1fU];
	target[2] = base32hex[(block >> 49) & 0x1fU];
	target[3] = base32hex[(block >> 44) & 0x1fU];
	target[4] = base32hex[(block >> 39) & 0x1fU];
	target[5] = base32hex[(block >> 34) & 0x1fU];
	target[6] = base32hex[(block >> 29) & 0x1fU];
	target[7] = base32hex[(block >> 24) & 0x1fU];
}

static void
base32hex_encode_hash(const uint8_t hash[NSEC3_HASH_LENGTH],
		      uint8_t target[32]) {
	uint64_t block;

	for (size_t offset = 0; offset < 15U; offset += 5U) {
		memcpy(&block, hash + offset, sizeof(block));
		base32hex_encode_block(be64toh(block), target);
		target += 8;
	}

	/* Load bytes 12..19, then discard the first three bytes. */
	memcpy(&block, hash + 12U, sizeof(block));
	base32hex_encode_block(be64toh(block) << 24, target);
}

static isc_result_t
owner_from_hash(dns_fixedname_t *fixed, const uint8_t hash[NSEC3_HASH_LENGTH],
		const dns_name_t *origin) {
	uint8_t wire[DNS_NAME_MAXWIRE];
	isc_region_t region;
	size_t length = 1U + 32U + origin->length;

	if (length > sizeof(wire)) {
		return ISC_R_NOSPACE;
	}
	wire[0] = 32U;
	base32hex_encode_hash(hash, wire + 1U);
	memcpy(wire + 33U, origin->ndata, origin->length);

	region = (isc_region_t){ .base = wire, .length = (unsigned int)length };
	dns_fixedname_init(fixed);
	dns_name_fromregion(dns_fixedname_name(fixed), &region);
	return ISC_R_SUCCESS;
}

static void
types_to_nsec3_bitmap(const byte_vec_t *bytes, const nsec3_item_t *item,
		      u16bitmap_t *bitmap) {
	const uint8_t *stored_types = item_types(bytes, item);
	bool found = false;
	bool found_ns = false;
	bool need_rrsig = false;

	u16bitmap_reinit(bitmap);
	for (uint16_t i = 0; i < item->type_count; i++) {
		uint16_t type;

		memcpy(&type, stored_types + i * sizeof(type), sizeof(type));
		if (dns_rdatatype_isnsec(type) || type == dns_rdatatype_rrsig) {
			continue;
		}
		u16bitmap_set(bitmap, type);
		if (type == dns_rdatatype_soa || type == dns_rdatatype_ds) {
			need_rrsig = true;
		} else if (type == dns_rdatatype_ns) {
			found_ns = true;
		} else {
			found = true;
		}
	}
	if ((found && !found_ns) || need_rrsig) {
		u16bitmap_set(bitmap, dns_rdatatype_rrsig);
	}

	if ((item->flags & ITEM_DELEGATION) != 0) {
		for (int32_t type = u16bitmap_next(bitmap, -1);
		     type != INT32_MAX; type = u16bitmap_next(bitmap, type))
		{
			if (!dns_rdatatype_iszonecutauth((dns_rdatatype_t)type))
			{
				u16bitmap_unset(bitmap, (uint16_t)type);
			}
		}
	}
}

static isc_result_t
insert_rdataset(qpzonedb_t *qpdb, qpz_version_t *writer, dns_qp_t *qp,
		dns_name_t *name, dns_rdataset_t *rdataset) {
	qpznode_t *node = NULL;
	bool nsec3 = rdataset->type == dns_rdatatype_nsec3 ||
		     rdataset->covers == dns_rdatatype_nsec3;
	isc_result_t result =
		findnodeintree(qpdb, qp, name, true, nsec3,
			       (dns_dbnode_t **)&node DNS__DB_FILELINE);

	if (result == ISC_R_SUCCESS) {
		result = qpzone_addrdataset_inner(qpdb, node,
						  (dns_dbversion_t *)writer,
						  rdataset, 0, NULL, NULL);
	}
	if (node != NULL) {
		qpzone_detachnode((dns_dbnode_t **)&node DNS__DB_FILELINE);
	}
	return result;
}

static isc_result_t
insert_wire_rdata(qpzonedb_t *qpdb, qpz_version_t *writer, dns_qp_t *qp,
		  dns_name_t *owner, dns_rdatatype_t type, dns_ttl_t ttl,
		  uint8_t *wire, size_t wire_length) {
	isc_region_t region = { .base = wire,
				.length = (unsigned int)wire_length };
	dns_rdata_t rdata = DNS_RDATA_INIT;
	dns_rdatalist_t rdatalist;
	dns_rdataset_t rdataset;

	dns_rdata_fromregion(&rdata, qpdb->common.rdclass, type, &region);
	dns_rdatalist_init(&rdatalist);
	rdatalist.rdclass = qpdb->common.rdclass;
	rdatalist.type = type;
	rdatalist.ttl = ttl;
	ISC_LIST_APPEND(rdatalist.rdata, &rdata, link);
	dns_rdataset_init(&rdataset);
	dns_rdatalist_tordataset(&rdatalist, &rdataset);

	return insert_rdataset(qpdb, writer, qp, owner, &rdataset);
}

static isc_result_t
insert_nsec3param(qpzonedb_t *qpdb, qpz_version_t *writer, dns_qp_t *qp) {
	uint8_t wire[5] = {
		NSEC3_HASH_ALGORITHM,
		0, /* NSEC3PARAM flags are always zero. */
		(uint8_t)(NSEC3_ITERATIONS >> 8),
		(uint8_t)NSEC3_ITERATIONS,
		NSEC3_SALT_LENGTH,
	};

	return insert_wire_rdata(qpdb, writer, qp, &qpdb->common.origin,
				 dns_rdatatype_nsec3param, 0, wire,
				 sizeof(wire));
}

static isc_result_t
insert_nsec3(qpzonedb_t *qpdb, qpz_version_t *writer, dns_qp_t *qp,
	     const byte_vec_t *bytes, const nsec3_item_t *item,
	     const nsec3_item_t *next, bool optout, dns_ttl_t ttl) {
	uint8_t wire[6U + NSEC3_HASH_LENGTH + U16BITMAP_MAXCOMPRESSEDSIZE];
	uint8_t *cursor = wire;
	u16bitmap_t bitmap;
	dns_fixedname_t owner_fixed;
	dns_name_t *owner;
	isc_result_t result;

	/* Load and check the pointer kept in the byte vector. */
	qpznode_t *source_node = item_node(bytes, item);
	if (((item->flags & ITEM_EMPTY) != 0) != (source_node == NULL)) {
		fatal("invalid node pointer in the item byte vector");
	}

	*cursor++ = NSEC3_HASH_ALGORITHM;
	*cursor++ = optout ? DNS_NSEC3FLAG_OPTOUT : 0;
	*cursor++ = (uint8_t)(NSEC3_ITERATIONS >> 8);
	*cursor++ = (uint8_t)NSEC3_ITERATIONS;
	*cursor++ = NSEC3_SALT_LENGTH;
	*cursor++ = NSEC3_HASH_LENGTH;
	memcpy(cursor, item_hash(bytes, next), NSEC3_HASH_LENGTH);
	cursor += NSEC3_HASH_LENGTH;
	types_to_nsec3_bitmap(bytes, item, &bitmap);
	cursor += u16bitmap_compress(&bitmap, cursor);

	result = owner_from_hash(&owner_fixed, item_hash(bytes, item),
				 &qpdb->common.origin);
	if (result != ISC_R_SUCCESS) {
		return result;
	}
	owner = dns_fixedname_name(&owner_fixed);
	return insert_wire_rdata(qpdb, writer, qp, owner, dns_rdatatype_nsec3,
				 ttl, wire, (size_t)(cursor - wire));
}

static void
load_zone(qpzonedb_t *qpdb, const char *filename) {
	dns_rdatacallbacks_t callbacks;
	isc_result_t result, end_result;

	dns_rdatacallbacks_init_stdio(&callbacks);
	result = beginload((dns_db_t *)qpdb, &callbacks);
	if (result != ISC_R_SUCCESS) {
		fatal_result("beginning the qpzone load", result);
	}
	result = dns_master_loadfile(
		filename, &qpdb->common.origin, &qpdb->common.origin,
		qpdb->common.rdclass, DNS_MASTER_ZONE, 0, &callbacks, NULL,
		NULL, qpdb->common.mctx, dns_masterformat_text, 0);
	end_result = endload((dns_db_t *)qpdb, &callbacks);
	if (result != ISC_R_SUCCESS && result != DNS_R_SEENINCLUDE) {
		fatal_result("loading the zone", result);
	}
	if (end_result != ISC_R_SUCCESS) {
		fatal_result("finishing the qpzone load", end_result);
	}
}

static void
usage(void) {
	fprintf(stderr, "usage: nsec3-full-rebuild [-A] [-o origin] zonefile\n"
			"       -A  use NSEC3 opt-out\n");
}

int
main(int argc, char **argv) {
	const char *filename;
	const char *origin_text = NULL;
	bool optout = false;
	dns_fixedname_t origin_fixed;
	dns_name_t *origin;
	dns_db_t *db = NULL;
	qpzonedb_t *qpdb;
	dns_dbversion_t *writer_version = NULL;
	dns_dbversion_t *reader_version = NULL;
	qpz_version_t *writer;
	qpz_version_t *reader;
	item_vec_t items = { 0 };
	byte_vec_t bytes = { 0 };
	dns_ttl_t nsec3_ttl = 0;
	uint64_t total_start, load_stop, prepare_stop, sort_stop, insert_stop;
	isc_result_t result;
	int option;

	while ((option = getopt(argc, argv, "Ao:")) != -1) {
		switch (option) {
		case 'A':
			optout = true;
			break;
		case 'o':
			origin_text = optarg;
			break;
		default:
			usage();
			return EXIT_FAILURE;
		}
	}
	if (optind + 1 != argc) {
		usage();
		return EXIT_FAILURE;
	}
	filename = argv[optind];
	if (origin_text == NULL) {
		origin_text = isc_file_basename(filename);
	}

	origin = dns_fixedname_initname(&origin_fixed);
	result = dns_name_fromstring(origin, origin_text, dns_rootname, 0,
				     NULL);
	if (result != ISC_R_SUCCESS) {
		fatal_result("parsing the zone origin", result);
	}

	total_start = monotonic_ns();
	result = dns__qpzone_create(isc_g_mctx, origin, dns_dbtype_zone,
				    dns_rdataclass_in, 0, NULL, NULL, &db);
	if (result != ISC_R_SUCCESS) {
		fatal_result("creating the qpzone", result);
	}
	qpdb = (qpzonedb_t *)db;
	load_zone(qpdb, filename);
	load_stop = monotonic_ns();

	/* Writer first, then current reader: this reader is the latest one. */
	result = newversion(db, &writer_version);
	if (result != ISC_R_SUCCESS) {
		fatal_result("opening the qpzone writer version", result);
	}
	currentversion(db, &reader_version);
	writer = (qpz_version_t *)writer_version;
	reader = (qpz_version_t *)reader_version;
	prepare_items(qpdb, reader, optout, &items, &bytes, &nsec3_ttl);
	prepare_stop = monotonic_ns();

	sort_items(&items, &bytes);
	sort_stop = monotonic_ns();

	dns_qp_t *write_qp = begin_transaction(qpdb, NULL, true);
	result = insert_nsec3param(qpdb, writer, write_qp);
	for (size_t i = 0; result == ISC_R_SUCCESS && i < items.len; i++) {
		result = insert_nsec3(
			qpdb, writer, write_qp, &bytes, &items.data[i],
			&items.data[(i + 1U) % items.len], optout, nsec3_ttl);
	}
	if (result != ISC_R_SUCCESS) {
		dns_qpmulti_rollback(qpdb->tree, &write_qp);
		closeversion(db, &reader_version, false DNS__DB_FILELINE);
		closeversion(db, &writer_version, false DNS__DB_FILELINE);
		fatal_result("inserting the NSEC3 chain", result);
	}
	end_transaction(qpdb, write_qp, true);
	closeversion(db, &reader_version, false DNS__DB_FILELINE);
	closeversion(db, &writer_version, true DNS__DB_FILELINE);
	insert_stop = monotonic_ns();

	printf("NSEC3 records:       %zu%s\n", items.len,
	       optout ? " (opt-out)" : "");
	printf("load zone:           %.6f s\n",
	       (load_stop - total_start) / 1000000000.0);
	printf("preparation:         %.6f s\n",
	       (prepare_stop - load_stop) / 1000000000.0);
	printf("sorting:             %.6f s\n",
	       (sort_stop - prepare_stop) / 1000000000.0);
	printf("signing + insertion: %.6f s\n",
	       (insert_stop - sort_stop) / 1000000000.0);
	printf("total:               %.6f s\n",
	       (insert_stop - total_start) / 1000000000.0);

	free(bytes.data);
	free(items.data);
	isc_refcount_decrementz(&qpdb->common.references);
	qpdb_destroy(db);
	return EXIT_SUCCESS;
}
