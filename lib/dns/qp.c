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
 * For an overview, see doc/design/qp-trie.md
 */

#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <isc/atomic.h>
#include <isc/bit.h>
#include <isc/buffer.h>
#include <isc/log.h>
#include <isc/magic.h>
#include <isc/mem.h>
#include <isc/mutex.h>
#include <isc/refcount.h>
#include <isc/result.h>
#include <isc/rwlock.h>
#include <isc/tid.h>
#include <isc/time.h>
#include <isc/types.h>
#include <isc/urcu.h>
#include <isc/util.h>

#include <dns/fixedname.h>
#include <dns/name.h>
#include <dns/qp.h>
#include <dns/types.h>

#include "qp_p.h"

#ifndef DNS_QP_LOG_STATS_LEVEL
#define DNS_QP_LOG_STATS_LEVEL 3
#endif
#ifndef DNS_QP_TRACE
#define DNS_QP_TRACE 0
#endif

/*
 * very basic garbage collector statistics
 *
 * XXXFANF for now we're logging GC times, but ideally we should
 * accumulate stats more quietly and report via the statschannel
 */
static atomic_uint_fast64_t compact_time;
static atomic_uint_fast64_t recycle_time;
static atomic_uint_fast64_t rollback_time;

/* for LOG_STATS() format strings */
#define PRItime " %" PRIu64 " ns "

#if DNS_QP_LOG_STATS_LEVEL
#define LOG_STATS(...)                                            \
	isc_log_write(DNS_LOGCATEGORY_DATABASE, DNS_LOGMODULE_QP, \
		      ISC_LOG_DEBUG(DNS_QP_LOG_STATS_LEVEL), __VA_ARGS__)
#else
#define LOG_STATS(...)
#endif

#if DNS_QP_TRACE
/*
 * TRACE is generally used in allocation-related functions so it doesn't
 * trace very high-frequency ops
 */
#define TRACE(fmt, ...)                                                        \
	do {                                                                   \
		if (isc_log_wouldlog(ISC_LOG_DEBUG(7))) {                      \
			isc_log_write(DNS_LOGCATEGORY_DATABASE,                \
				      DNS_LOGMODULE_QP, ISC_LOG_DEBUG(7),      \
				      "%s:%d:%s(qp %p uctx \"%s\"):t%" PRItid  \
				      ": " fmt,                                \
				      __FILE__, __LINE__, __func__, qp,        \
				      qp ? TRIENAME(qp) : "(null)", isc_tid(), \
				      ##__VA_ARGS__);                          \
		}                                                              \
	} while (0)
#else
#define TRACE(...)
#endif

#if DNS_QPMULTI_TRACE
ISC_REFCOUNT_STATIC_TRACE_DECL(dns_qpmulti);
#define dns_qpmulti_ref(ptr) dns_qpmulti__ref(ptr, __func__, __FILE__, __LINE__)
#define dns_qpmulti_unref(ptr) \
	dns_qpmulti__unref(ptr, __func__, __FILE__, __LINE__)
#define dns_qpmulti_attach(ptr, ptrp) \
	dns_qpmulti__attach(ptr, ptrp, __func__, __FILE__, __LINE__)
#define dns_qpmulti_detach(ptrp) \
	dns_qpmulti__detach(ptrp, __func__, __FILE__, __LINE__)
#else
ISC_REFCOUNT_STATIC_DECL(dns_qpmulti);
#endif

/***********************************************************************
 *
 *  converting DNS names to trie keys
 */

/*
 * Convert the namespace value. We map namespace values to numerical
 * digits so they can be represented in a single byte in the QP key;
 * thus namespace 0 becomes '0', etc.
 */
#define ENCODE_NAMESPACE(c) dns_qp_bits_for_byte[(c) + (uint8_t)'0']
#define DECODE_NAMESPACE(c) dns_qp_byte_for_bit[(c)] - (uint8_t)'0'

#define NAME_OFFSET 1

/*
 * Number of distinct byte values, i.e. 256
 */
#define BYTE_VALUES (UINT8_MAX + 1)

/*
 * Lookup table mapping bytes in DNS names to bit positions, used
 * by dns_qpkey_fromname() to convert DNS names to qp-trie keys.
 *
 * Each element holds one or two bit positions, bit_one in the
 * lower half and bit_two in the upper half.
 *
 * For common hostname characters, bit_two is zero (which cannot
 * be a valid bit position).
 *
 * For others, bit_one is the escape bit, and bit_two is the
 * position of the character within the escaped range.
 */
uint16_t dns_qp_bits_for_byte[BYTE_VALUES] = { 0 };

/*
 * And the reverse, mapping bit positions to characters, so the tests
 * can print diagnostics involving qp-trie keys.
 *
 * This table only handles the first bit in an escape sequence; we
 * arrange that we can calculate the byte value for both bits by
 * adding the second bit to the first bit's byte value.
 */
uint8_t dns_qp_byte_for_bit[SHIFT_OFFSET] = { 0 };

/*
 * Fill in the lookup tables at program startup. (It doesn't matter
 * when this is initialized relative to other startup code.)
 */

/*
 * The bit positions for bytes inside labels have to be between
 * SHIFT_BITMAP and SHIFT_OFFSET. (SHIFT_NOBYTE separates labels.)
 *
 * Each byte range in between common hostname characters has a different
 * escape character, to preserve the correct lexical order.
 *
 * Escaped byte ranges mostly fit into the space available in the
 * bitmap, except for those above 'z' (which is mostly bytes with the
 * top bit set). So, when we reach the end of the bitmap we roll over
 * to the next escape character.
 *
 * After filling the table we ensure that the bit positions for
 * hostname characters and escape characters all fit.
 */
void
dns__qp_initialize(void) {
	/* zero common character marker not a valid shift position */
	INSIST(0 < SHIFT_BITMAP);
	/* first bit is common byte or escape byte */
	dns_qpshift_t bit_one = SHIFT_BITMAP;
	/* second bit is position in escaped range */
	dns_qpshift_t bit_two = SHIFT_BITMAP;
	bool escaping = true;

	for (unsigned int byte = 0; byte < BYTE_VALUES; byte++) {
		if (qp_common_character(byte)) {
			escaping = false;
			bit_one++;
			dns_qp_byte_for_bit[bit_one] = byte;
			dns_qp_bits_for_byte[byte] = bit_one;
		} else if ('A' <= byte && byte <= 'Z') {
			/* map upper case to lower case */
			dns_qpshift_t after_esc = bit_one + 1;
			dns_qpshift_t skip_punct = 'a' - '_';
			dns_qpshift_t letter = byte - 'A';
			dns_qpshift_t bit = after_esc + skip_punct + letter;
			dns_qp_bits_for_byte[byte] = bit;
			/* to simplify reverse conversion */
			bit_two++;
		} else {
			/* non-hostname characters need to be escaped */
			if (!escaping || bit_two >= SHIFT_OFFSET) {
				escaping = true;
				bit_one++;
				dns_qp_byte_for_bit[bit_one] = byte;
				bit_two = SHIFT_BITMAP;
			}
			dns_qp_bits_for_byte[byte] = bit_two << 8 | bit_one;
			bit_two++;
		}
	}
	ENSURE(bit_one < SHIFT_OFFSET);
}

void
dns__qp_shutdown(void) {
	/* Nothing */
}

/*
 * Convert a DNS name into a trie lookup key.
 *
 * Returns the length of the key.
 *
 * For performance we get our hands dirty in the guts of the name.
 *
 * We don't worry about the distinction between absolute and relative
 * names. When the trie is only used with absolute names, the first byte
 * of the key will always be SHIFT_NOBYTE and it will always be skipped
 * when traversing the trie. So keeping the root label costs little, and
 * it allows us to support tries of relative names too. In fact absolute
 * and relative names can be mixed in the same trie without causing
 * confusion, because the presence or absence of the initial
 * SHIFT_NOBYTE in the key disambiguates them (exactly like a trailing
 * dot in a zone file).
 */
size_t
dns_qpkey_fromname(dns_qpkey_t key, const dns_name_t *name,
		   dns_namespace_t space) {
	REQUIRE(ISC_MAGIC_VALID(name, DNS_NAME_MAGIC));

	dns_offsets_t offsets;
	size_t labels = dns_name_offsets(name, offsets);
	size_t len = 0;

	/* namespace */
	key[len++] = ENCODE_NAMESPACE(space);
	/* name */
	if (labels == 0) {
		key[len] = SHIFT_NOBYTE;
		return len;
	}

	size_t label = labels;
	while (label-- > 0) {
		const uint8_t *ldata = name->ndata + offsets[label];
		size_t label_len = *ldata++;
		while (label_len-- > 0) {
			uint16_t bits = dns_qp_bits_for_byte[*ldata++];
			key[len++] = bits & 0xFF;	/* bit_one */
			if ((bits >> 8) != 0) {		/* escape? */
				key[len++] = bits >> 8; /* bit_two */
			}
		}
		/* label terminator */
		key[len++] = SHIFT_NOBYTE;
	}
	/* mark end with a double NOBYTE */
	key[len] = SHIFT_NOBYTE;
	ENSURE(len < sizeof(dns_qpkey_t));
	return len;
}

void
dns_qpkey_toname(const dns_qpkey_t key, size_t keylen, dns_name_t *name,
		 dns_namespace_t *space) {
	size_t locs[DNS_NAME_MAXLABELS];
	size_t loc = 0;
	size_t offset = 0;

	REQUIRE(ISC_MAGIC_VALID(name, DNS_NAME_MAGIC));
	REQUIRE(name->buffer != NULL);
	REQUIRE(keylen > 0);

	dns_name_reset(name);

	SET_IF_NOT_NULL(space, DECODE_NAMESPACE(key[offset++]));

	if (keylen == NAME_OFFSET) {
		return;
	}

	/* Scan the key looking for label boundaries */
	for (; offset <= keylen; offset++) {
		INSIST(key[offset] >= SHIFT_NOBYTE &&
		       key[offset] < SHIFT_OFFSET);
		INSIST(loc < DNS_NAME_MAXLABELS);
		if (qpkey_bit(key, keylen, offset) == SHIFT_NOBYTE) {
			if (qpkey_bit(key, keylen, offset + 1) == SHIFT_NOBYTE)
			{
				locs[loc] = offset + 1;
				goto scanned;
			}
			locs[loc++] = offset + 1;
		} else if (offset == NAME_OFFSET) {
			/* This happens for a relative name */
			locs[loc++] = offset;
		}
	}
	UNREACHABLE();
scanned:

	/*
	 * In the key the labels are encoded in reverse order, so
	 * we step backward through the label boundaries, then forward
	 * through the labels, to create the DNS wire format data.
	 */
	while (loc-- > 0) {
		uint8_t len = 0, *lenp = NULL;

		/* Store the location of the length byte */
		lenp = isc_buffer_used(name->buffer);

		/* Add a length byte to the name data */
		isc_buffer_putuint8(name->buffer, 0);
		name->length++;

		/* Convert from escaped byte ranges to ASCII */
		for (offset = locs[loc]; offset < locs[loc + 1] - 1; offset++) {
			uint8_t bit = qpkey_bit(key, keylen, offset);
			uint8_t byte = dns_qp_byte_for_bit[bit];
			if (qp_common_character(byte)) {
				isc_buffer_putuint8(name->buffer, byte);
			} else {
				byte += key[++offset] - SHIFT_BITMAP;
				isc_buffer_putuint8(name->buffer, byte);
			}
			len++;
		}

		name->length += len;

		/* Write the final label length to the length byte */
		*lenp = len;
	}

	/* Add a root label for absolute names */
	if (key[NAME_OFFSET] == SHIFT_NOBYTE) {
		name->attributes.absolute = true;
		isc_buffer_putuint8(name->buffer, 0);
		name->length++;
	}

	name->ndata = isc_buffer_base(name->buffer);
}

/*
 * Sentinel value for equal keys
 */
#define QPKEY_EQUAL (~(size_t)0)

/*
 * Compare two keys and return the offset where they differ.
 *
 * This offset is used to work out where a trie search diverged: when one
 * of the keys is in the trie and one is not, the common prefix (up to the
 * offset) is the part of the unknown key that exists in the trie. This
 * matters for adding new keys or finding neighbours of missing keys.
 *
 * When the keys are different lengths it is possible (but unwise) for
 * the longer key to be the same as the shorter key but with superfluous
 * trailing SHIFT_NOBYTE elements. This makes the keys equal for the
 * purpose of traversing the trie.
 */
static size_t
qpkey_compare(const dns_qpkey_t key_a, const size_t keylen_a,
	      const dns_qpkey_t key_b, const size_t keylen_b) {
	size_t keylen = ISC_MAX(keylen_a, keylen_b);
	for (size_t offset = 0; offset < keylen; offset++) {
		if (qpkey_bit(key_a, keylen_a, offset) !=
		    qpkey_bit(key_b, keylen_b, offset))
		{
			return offset;
		}
	}
	return QPKEY_EQUAL;
}

/***********************************************************************
 *
 *  physical chunk and base ownership
 */

/*
 * A chunk's final owner has exclusive access to its contents and allocation
 * watermark. Other owners can release references concurrently, but only the
 * writer changes the watermark or appends cells while it owns the chunk.
 */
static void
chunk_release(dns_qpbase_t *base, dns_qpnode_t *nodes) {
	qp_chunk_t *chunk = chunk_fromnodes(nodes);
	if (isc_refcount_decrement(&chunk->references) != 1) {
		return;
	}
	for (dns_qpcell_t i = 0; i < chunk->used; i++) {
		dns_qpnode_t *n = &nodes[i];
		if (node_tag(n) == LEAF_TAG && node_pointer(n) != NULL) {
			base->methods->detach(base->uctx, leaf_pval(n),
					      leaf_ival(n));
		}
	}
	isc_refcount_destroy(&chunk->references);
	isc_mem_free(base->mctx, chunk);
}

static void
base_detach(dns_qpbase_t **basep) {
	dns_qpbase_t *base = *basep;
	*basep = NULL;
	if (base == NULL || isc_refcount_decrement(&base->refcount) != 1) {
		return;
	}
	/* The writer owns a reference while appending: final release cannot
	 * race with pointer initialization, and does not inspect its metadata.
	 */
	for (dns_qpchunk_t i = 0; i < base->chunk_max; i++) {
		if (base->ptr[i] != NULL) {
			chunk_release(base, base->ptr[i]);
		}
	}
	isc_refcount_destroy(&base->refcount);
	isc_mem_t *mctx = base->mctx;
	isc_mem_free(mctx, base);
	isc_mem_detach(&mctx);
}

/* Allocate the SoA storage shared by exact copies and filtered growth. */
static dns_qpbase_t *
base_alloc(const dns_qp_t *qp, dns_qpchunk_t count) {
	dns_qpbase_t *base = isc_mem_allocate(qp->mctx, base_size(count));
	memset(base, 0, base_size(count));
	*base = (dns_qpbase_t){
		.magic = QPBASE_MAGIC,
		.methods = qp->methods,
		.uctx = qp->uctx,
		.chunk_max = count,
		.free = (uint16_t *)((char *)base + base_free_offset(count)),
		.ptr = (dns_qpnode_t **)((char *)base + base_ptr_offset(count)),
	};
	isc_refcount_init(&base->refcount, 1);
	isc_mem_attach(qp->mctx, &base->mctx);
	return base;
}

/* Exact copy for snapshots, rollback setup, and same-capacity clones.
 * Acquires chunk references but never changes writer state. */
static dns_qpbase_t *
base_copy(const dns_qp_t *qp, const dns_qpbase_t *old) {
	dns_qpchunk_t count = old->chunk_max;
	dns_qpbase_t *base = base_alloc(qp, count);
	memmove(base->immutable, old->immutable, base_bitmap_size(count));
	memmove(base->free, old->free, count * sizeof(base->free[0]));
	memmove(base->ptr, old->ptr, count * sizeof(base->ptr[0]));
	for (dns_qpchunk_t i = 0; i < count; i++) {
		if (base->ptr[i] != NULL) {
			qp_chunk_t *chunk = chunk_fromnodes(base->ptr[i]);
			isc_refcount_increment(&chunk->references);
		}
	}
	return base;
}

static void
base_clone(dns_qp_t *qp) {
	dns_qpbase_t *old = qp->base;
	qp->base = base_copy(qp, old);
	qp->protected = 0;
	qp->alloc_next = 0;
	base_detach(&old);
}

/*
 * Geometric growth has already been selected. Omit dead non-bump mappings,
 * rebuild writer accounting, and start allocation at the first resulting
 * hole. The next allocation replaces the bump, which we retain here.
 */
static void
base_grow(dns_qp_t *qp, dns_qpchunk_t newmax) {
	REQUIRE(newmax > qp->chunk_max);
	dns_qpbase_t *old = qp->base;
	dns_qpbase_t *base = base_alloc(qp, newmax);
	dns_qpchunk_t oldmax = old != NULL ? old->chunk_max : 0;
	dns_qpchunk_t first = oldmax, limit = 0, count = 0, dead = 0;
	dns_qpcell_t used = 0, freed = 0, held = 0;

	if (old != NULL) {
		memmove(base->immutable, old->immutable,
			base_bitmap_size(oldmax));
	}
	for (dns_qpchunk_t i = 0; i < oldmax; i++) {
		if (old->ptr[i] != NULL) {
			qp_chunk_t *chunk = chunk_fromnodes(old->ptr[i]);
			if (i == qp->bump || chunk->used != old->free[i]) {
				base->ptr[i] = old->ptr[i];
				base->free[i] = old->free[i];
				isc_refcount_increment(&chunk->references);
				limit = i + 1;
				count++;
				used += chunk->used;
				freed += old->free[i];
				dead += chunk->used == old->free[i];
				if (chunk_immutable(base, i)) {
					held += old->free[i];
				}
			}
		}
		if (base->ptr[i] == NULL) {
			first = ISC_MIN(first, i);
			chunk_set_mutable(base, i);
		}
	}
	/* Unlink omitted mutable chunks before releasing the old base. */
	dns_qpchunk_t index = qp->mutable_head;
	dns_qpchunk_t *link = &qp->mutable_head;
	while (index != INVALID_CHUNK) {
		qp_chunk_t *chunk = chunk_fromnodes(old->ptr[index]);
		dns_qpchunk_t next = chunk->mutable_next;
		if (base->ptr[index] != NULL) {
			*link = index;
			link = &chunk->mutable_next;
		}
		index = next;
	}
	*link = INVALID_CHUNK;

	qp->base = base;
	qp->protected = 0;
	qp->alloc_next = first;
	qp->chunk_limit = limit;
	qp->chunk_count = count;
	qp->dead_count = dead;
	qp->used_count = used;
	qp->free_count = freed;
	/* The old bump's immutable bit will cover its whole allocation once
	 * the next allocation replaces it, including previously freed suffix
	 * cells. All free cells in retained immutable chunks are then held. */
	qp->hold_count = held;
	base_detach(&old);
}

/* Freeze only allocations made since the previous commit, not the base. */
static void
freeze_chunks(dns_qp_t *qp) {
	while (qp->mutable_head != INVALID_CHUNK) {
		dns_qpchunk_t index = qp->mutable_head;
		qp_chunk_t *chunk = chunk_fromnodes(qp->base->ptr[index]);
		qp->mutable_head = chunk->mutable_next;
		chunk->mutable_next = INVALID_CHUNK;
		qp->base->immutable[index / 8] |= 1U << (index % 8);
	}
}

/***********************************************************************
 *
 *  allocator
 */

/*
 * When we reuse the bump chunk across multiple write transactions,
 * it can have an immutable prefix and a mutable suffix.
 */
static inline bool
cells_immutable(dns_qp_t *qp, dns_qpref_t ref) {
	dns_qpchunk_t chunk = ref_chunk(ref);
	dns_qpcell_t cell = ref_cell(ref);
	if (chunk == qp->bump) {
		return cell < qp->fender;
	} else {
		return chunk_immutable(qp->base, chunk);
	}
}

/*
 * Find the next power that is both bigger than size and prev_capacity,
 * but still within the chunk min and max sizes.
 */
static dns_qpcell_t
next_capacity(uint32_t prev_capacity, uint32_t size) {
	/*
	 * Request size was floored at 2 because builtin_clz used to be 0.
	 * We keep this behavior because stdc_leading_zeros(0) = 32.
	 */
	size = ISC_MAX3(size, prev_capacity, 2U);
	uint32_t log2 = 32U - stdc_leading_zeros(size - 1U);

	return 1U << ISC_CLAMP(log2, QP_CHUNK_LOG_MIN, QP_CHUNK_LOG_MAX);
}

/*
 * Create a fresh bump chunk and allocate some twigs from it.
 */
static dns_qpref_t
chunk_alloc(dns_qp_t *qp, dns_qpchunk_t chunk, dns_qpweight_t size) {
	INSIST(qp->base->ptr[chunk] == NULL);
	INSIST(qp->base->free[chunk] == 0);
	INSIST(qp->chunk_capacity <= QP_CHUNK_SIZE);
	INSIST(chunk >= qp->protected);

	qp->chunk_capacity = next_capacity(qp->chunk_capacity * 2u, size);
	qp_chunk_t *physical = isc_mem_allocate(
		qp->mctx,
		STRUCT_FLEX_SIZE(physical, nodes, qp->chunk_capacity));
	isc_refcount_init(&physical->references, 1);
	physical->used = size;
	physical->capacity = qp->chunk_capacity;
	physical->mutable_next = qp->mutable_head;
	qp->mutable_head = chunk;
	qp->base->ptr[chunk] = physical->nodes;
	qp->chunk_count++;
	qp->chunk_limit = ISC_MAX(qp->chunk_limit, chunk + 1);
	chunk_set_mutable(qp->base, chunk);
	qp->used_count += size;
	if (size == 0) {
		qp->dead_count++;
	}
	qp->bump = chunk;
	qp->fender = 0;

	return make_ref(chunk, 0);
}

/*
 * Growing the base preserves the private writer's allocation metadata.
 */
static void
realloc_chunk_arrays(dns_qp_t *qp, dns_qpchunk_t newmax) {
	if (newmax > qp->chunk_max) {
		base_grow(qp, newmax);
	} else {
		base_clone(qp);
	}
	qp->chunk_max = newmax;

	TRACE("qpbase %p max %u", qp->base, qp->chunk_max);
}

/*
 * There was no space in the bump chunk, so find a place to put a fresh
 * chunk in the chunk arrays, then allocate some twigs from it.
 */
static dns_qpref_t
alloc_slow(dns_qp_t *qp, dns_qpweight_t size) {
	dns_qpchunk_t chunk;

	for (chunk = qp->alloc_next; chunk < qp->chunk_max; chunk++) {
		if (qp->base->ptr[chunk] == NULL) {
			qp->alloc_next = chunk + 1;
			return chunk_alloc(qp, chunk, size);
		}
	}
	ENSURE(chunk == qp->chunk_max);
	/* A clone can reuse holes in the protected prefix without growing. */
	dns_qpchunk_t newmax = qp->chunk_count < qp->chunk_max
				       ? qp->chunk_max
				       : GROWTH_FACTOR(qp->chunk_max);
	realloc_chunk_arrays(qp, newmax);
	return alloc_slow(qp, size);
}

/*
 * Ensure we are using a fresh bump chunk.
 */
static void
alloc_reset(dns_qp_t *qp) {
	(void)alloc_slow(qp, 0);
}

/*
 * Allocate some fresh twigs. This is the bump allocator fast path.
 */
static inline dns_qpref_t
alloc_twigs(dns_qp_t *qp, dns_qpweight_t size) {
	dns_qpchunk_t chunk = qp->bump;
	qp_chunk_t *physical = chunk_fromnodes(qp->base->ptr[chunk]);
	dns_qpcell_t cell = physical->used;

	if (cell + size <= physical->capacity) {
		if (cell == qp->base->free[chunk]) {
			INSIST(qp->dead_count > 0);
			qp->dead_count--;
		}
		physical->used += size;
		qp->used_count += size;
		return make_ref(chunk, cell);
	} else {
		return alloc_slow(qp, size);
	}
}

/*
 * Record that some twigs are no longer being used, and if possible
 * zero them to ensure that there isn't a spurious double detach when
 * the chunk is later recycled.
 *
 * Returns true if the twigs were immediately destroyed.
 *
 * NOTE: the caller is responsible for attaching or detaching any
 * leaves as required.
 */
static inline bool
free_twigs(dns_qp_t *qp, dns_qpref_t twigs, dns_qpweight_t size) {
	dns_qpchunk_t chunk = ref_chunk(twigs);

	qp->free_count += size;
	qp->base->free[chunk] += size;
	ENSURE(qp->free_count <= qp->used_count);
	ENSURE(qp->base->free[chunk] <=
	       chunk_fromnodes(qp->base->ptr[chunk])->used);
	if (qp->base->free[chunk] ==
	    chunk_fromnodes(qp->base->ptr[chunk])->used)
	{
		qp->dead_count++;
	}

	if (cells_immutable(qp, twigs)) {
		qp->hold_count += size;
		ENSURE(qp->free_count >= qp->hold_count);
		return false;
	} else {
		zero_twigs(ref_ptr(qp, twigs), size);
		return true;
	}
}

/*
 * When some twigs have been copied, and free_twigs() could not
 * immediately destroy the old copy, we need to update the refcount
 * on any leaves that were duplicated.
 */
static void
attach_twigs(dns_qp_t *qp, dns_qpnode_t *twigs, dns_qpweight_t size) {
	for (dns_qpweight_t pos = 0; pos < size; pos++) {
		if (node_tag(&twigs[pos]) == LEAF_TAG) {
			attach_leaf(qp, &twigs[pos]);
		}
	}
}

/***********************************************************************
 *
 *  chunk reclamation
 */

/*
 * Is any of this chunk still in use?
 */
static inline dns_qpcell_t
chunk_usage(dns_qp_t *qp, dns_qpchunk_t chunk) {
	return chunk_fromnodes(qp->base->ptr[chunk])->used -
	       qp->base->free[chunk];
}

/*
 * Remove a mapping from the private writer base. Other versions retain their
 * own references to the physical allocation, even if this index is reused.
 */
static void
chunk_free(dns_qp_t *qp, dns_qpchunk_t chunk) {
	INSIST(chunk >= qp->protected);
	qp_chunk_t *physical = chunk_fromnodes(qp->base->ptr[chunk]);
	INSIST(physical->used == qp->base->free[chunk]);
	INSIST(qp->dead_count > 0);
	qp->dead_count--;
	INSIST(qp->used_count >= physical->used);
	INSIST(qp->free_count >= qp->base->free[chunk]);
	qp->used_count -= physical->used;
	qp->free_count -= qp->base->free[chunk];
	chunk_release(qp->base, qp->base->ptr[chunk]);
	qp->base->ptr[chunk] = NULL;
	qp->chunk_count--;
	qp->base->free[chunk] = 0;
	chunk_set_mutable(qp->base, chunk);
	qp->alloc_next = ISC_MIN(qp->alloc_next, chunk);
	while (qp->chunk_limit > qp->protected &&
	       qp->base->ptr[qp->chunk_limit - 1] == NULL)
	{
		qp->chunk_limit--;
	}
}

/*
 * Free any chunks that we can while a trie is in use.
 */
static void
recycle(dns_qp_t *qp) {
	unsigned int nfree = 0;

	isc_nanosecs_t start = isc_time_monotonic();

	dns_qpchunk_t *link = &qp->mutable_head;
	while (*link != INVALID_CHUNK) {
		dns_qpchunk_t index = *link;
		qp_chunk_t *chunk = chunk_fromnodes(qp->base->ptr[index]);
		INSIST(!chunk_immutable(qp->base, index));
		if (index != qp->bump && chunk_usage(qp, index) == 0) {
			*link = chunk->mutable_next;
			chunk_free(qp, index);
			nfree++;
		} else {
			link = &chunk->mutable_next;
		}
	}

	isc_nanosecs_t time = isc_time_monotonic() - start;
	atomic_fetch_add_relaxed(&recycle_time, time);

	if (nfree > 0) {
		LOG_STATS("qp recycle" PRItime "free %u chunks", time, nfree);
		LOG_STATS("qp recycle leaf %u live %u used %u free %u hold %u",
			  qp->leaf_count, qp->used_count - qp->free_count,
			  qp->used_count, qp->free_count, qp->hold_count);
	}
}

/*
 * Retiring a published version needs no writer lock: all lifetime information
 * is in the retired base and its physical chunks. The multi reference keeps
 * the immutable callback metadata alive through the grace period.
 */
static void
reclaim_chunks_cb(struct rcu_head *arg) {
	qp_version_t *version = caa_container_of(arg, qp_version_t, rcu_head);
	dns_qpmulti_t *multi = version->multi;
	isc_nanosecs_t start = isc_time_monotonic();

	base_detach(&version->base);
	atomic_fetch_add_relaxed(&recycle_time, isc_time_monotonic() - start);
	isc_mem_put(multi->mctx, version, sizeof(*version));
	dns_qpmulti_detach(&multi);
}

/*
 * Discard dead mappings before publishing the private base. A bump chunk with
 * an immutable, entirely dead prefix must also be retired: otherwise a later
 * snapshot would unnecessarily retain its old leaf references.
 */
static bool
reclaim_needed(dns_qp_t *qp) {
	unsigned int empty_bump =
		chunk_fromnodes(qp->base->ptr[qp->bump])->used == 0 ? 1 : 0;
	return qp->dead_count > empty_bump;
}

static void
reclaim_chunks(dns_qp_t *qp) {
	if (reclaim_needed(qp)) {
		if (chunk_fromnodes(qp->base->ptr[qp->bump])->used != 0 &&
		    chunk_usage(qp, qp->bump) == 0)
		{
			alloc_reset(qp);
		}
		/* Unpublished dead mappings need no clone. Unlink them first.
		 */
		recycle(qp);
	}
	freeze_chunks(qp);
	if (reclaim_needed(qp)) {
		/* Previously published mappings require a private base. */
		if (qp->protected != 0) {
			base_clone(qp);
		}
		for (dns_qpchunk_t chunk = 0; chunk < qp->chunk_max; chunk++) {
			if (chunk != qp->bump && qp->base->ptr[chunk] != NULL &&
			    chunk_usage(qp, chunk) == 0)
			{
				chunk_free(qp, chunk);
			}
		}
	}
	INSIST(qp->dead_count ==
	       (chunk_fromnodes(qp->base->ptr[qp->bump])->used == 0 ? 1 : 0));
	qp->hold_count = qp->free_count;
}

/***********************************************************************
 *
 *  garbage collector
 */

/*
 * Move a branch node's twigs to the `bump` chunk, for copy-on-write
 * or for garbage collection. We don't update the node in place
 * because `compact_recursive()` does not ensure the node itself is
 * mutable until after it discovers evacuation was necessary.
 *
 * If free_twigs() could not immediately destroy the old twigs, we have
 * to re-attach to any leaves.
 */
static dns_qpref_t
evacuate(dns_qp_t *qp, dns_qpnode_t *n) {
	dns_qpweight_t size = branch_twigs_size(n);
	dns_qpref_t old_ref = branch_twigs_ref(n);
	dns_qpref_t new_ref = alloc_twigs(qp, size);
	dns_qpnode_t *old_twigs = ref_ptr(qp, old_ref);
	dns_qpnode_t *new_twigs = ref_ptr(qp, new_ref);

	move_twigs(new_twigs, old_twigs, size);
	if (!free_twigs(qp, old_ref, size)) {
		attach_twigs(qp, new_twigs, size);
	}

	return new_ref;
}

/*
 * Immutable nodes need copy-on-write. As we walk down the trie finding the
 * right place to modify, make_root_mutable() and make_twigs_mutable()
 * are called to ensure that immutable nodes on the path from the root are
 * copied to a mutable chunk.
 */

static inline dns_qpnode_t *
make_root_mutable(dns_qp_t *qp) {
	if (cells_immutable(qp, qp->root_ref)) {
		qp->root_ref = evacuate(qp, MOVABLE_ROOT(qp));
	}
	return ref_ptr(qp, qp->root_ref);
}

static inline void
make_twigs_mutable(dns_qp_t *qp, dns_qpnode_t *n) {
	if (cells_immutable(qp, branch_twigs_ref(n))) {
		*n = make_node(branch_index(n), evacuate(qp, n));
	}
}

/*
 * Compact the trie by traversing the whole thing recursively, copying
 * bottom-up as required. The aim is to avoid evacuation as much as
 * possible, but when parts of the trie are immutable, we need to evacuate
 * the paths from the root to the parts of the trie that occupy
 * fragmented chunks.
 *
 * Without the QP_MIN_USED check, the algorithm will leave the trie
 * unchanged. If the children are all leaves, the loop changes nothing,
 * so we will return this node's original ref. If all of the children
 * that are branches did not need moving, again, the loop changes
 * nothing. So the evacuation check is the only place that the
 * algorithm introduces ref changes, that then bubble up towards the
 * root through the logic inside the loop.
 */
static dns_qpref_t
compact_recursive(dns_qp_t *qp, dns_qpnode_t *parent) {
	dns_qpweight_t size = branch_twigs_size(parent);
	dns_qpref_t twigs_ref = branch_twigs_ref(parent);
	dns_qpchunk_t chunk = ref_chunk(twigs_ref);

	if (qp->compact_all ||
	    (chunk != qp->bump && chunk_usage(qp, chunk) < QP_MIN_USED))
	{
		twigs_ref = evacuate(qp, parent);
	}
	bool immutable = cells_immutable(qp, twigs_ref);
	for (dns_qpweight_t pos = 0; pos < size; pos++) {
		dns_qpnode_t *child = ref_ptr(qp, twigs_ref) + pos;
		if (!is_branch(child)) {
			continue;
		}
		dns_qpref_t old_grandtwigs = branch_twigs_ref(child);
		dns_qpref_t new_grandtwigs = compact_recursive(qp, child);
		if (old_grandtwigs == new_grandtwigs) {
			continue;
		}
		if (immutable) {
			twigs_ref = evacuate(qp, parent);
			/* the twigs have moved */
			child = ref_ptr(qp, twigs_ref) + pos;
			immutable = false;
		}
		*child = make_node(branch_index(child), new_grandtwigs);
	}
	return twigs_ref;
}

static void
compact(dns_qp_t *qp) {
	LOG_STATS("qp compact before leaf %u live %u used %u free %u hold %u",
		  qp->leaf_count, qp->used_count - qp->free_count,
		  qp->used_count, qp->free_count, qp->hold_count);

	isc_nanosecs_t start = isc_time_monotonic();

	if (qp->base->free[qp->bump] > QP_MAX_FREE) {
		alloc_reset(qp);
	}

	if (qp->leaf_count > 0) {
		qp->root_ref = compact_recursive(qp, MOVABLE_ROOT(qp));
	}
	qp->compact_all = false;

	isc_nanosecs_t time = isc_time_monotonic() - start;
	atomic_fetch_add_relaxed(&compact_time, time);

	LOG_STATS("qp compact" PRItime
		  "leaf %u live %u used %u free %u hold %u",
		  time, qp->leaf_count, qp->used_count - qp->free_count,
		  qp->used_count, qp->free_count, qp->hold_count);
}

void
dns_qp_compact(dns_qp_t *qp, dns_qpgc_t mode) {
	REQUIRE(QP_VALID(qp));
	if (mode == DNS_QPGC_MAYBE && !QP_NEEDGC(qp)) {
		return;
	}
	if (mode == DNS_QPGC_ALL) {
		alloc_reset(qp);
		qp->compact_all = true;
	}
	compact(qp);
	recycle(qp);
}

/*
 * Free some twigs and (if they were destroyed immediately so that the
 * result from QP_MAX_GARBAGE can change) compact the trie if necessary.
 *
 * This is called by the trie modification API entry points. The
 * free_twigs() function requires the caller to attach or detach any
 * leaves as necessary. Callers of squash_twigs() satisfy this
 * requirement by calling make_twigs_mutable().
 *
 * Aside: In typical garbage collectors, compaction is triggered when
 * the allocator runs out of space. But that is because typical garbage
 * collectors do not know how much memory can be recovered, so they must
 * find out by scanning the heap. The qp-trie code was originally
 * designed to use malloc() and free(), so it has more information about
 * when garbage collection might be worthwhile. Hence we can trigger
 * collection when garbage passes a threshold.
 *
 * XXXFANF: If we need to avoid latency outliers caused by compaction in
 * write transactions, we can check qp->transaction_mode here.
 */
static inline bool
squash_twigs(dns_qp_t *qp, dns_qpref_t twigs, dns_qpweight_t size) {
	bool destroyed = free_twigs(qp, twigs, size);
	if (destroyed && QP_AUTOGC(qp)) {
		compact(qp);
		recycle(qp);
		/*
		 * This shouldn't happen if the garbage collector is
		 * working correctly. We can recover at the cost of some
		 * time and space, but recovery should be cheaper than
		 * letting compact+recycle fail repeatedly.
		 */
		if (QP_AUTOGC(qp)) {
			isc_log_write(DNS_LOGCATEGORY_DATABASE,
				      DNS_LOGMODULE_QP, ISC_LOG_NOTICE,
				      "qp %p uctx \"%s\" compact/recycle "
				      "failed to recover any space, "
				      "scheduling a full compaction",
				      qp, TRIENAME(qp));
			qp->compact_all = true;
		}
	}
	return destroyed;
}

/***********************************************************************
 *
 *  public accessors for memory management internals
 */

dns_qp_memusage_t
dns_qp_memusage(dns_qp_t *qp) {
	REQUIRE(QP_VALID(qp));

	dns_qp_memusage_t memusage = {
		.uctx = qp->uctx,
		.leaves = qp->leaf_count,
		.live = qp->used_count - qp->free_count,
		.used = qp->used_count,
		.hold = qp->hold_count,
		.free = qp->free_count,
		.node_size = sizeof(dns_qpnode_t),
		.fragmented = QP_NEEDGC(qp),
	};

	size_t chunk_usage_bytes = 0;
	for (dns_qpchunk_t chunk = 0; chunk < qp->chunk_max; chunk++) {
		if (qp->base->ptr[chunk] != NULL) {
			chunk_usage_bytes +=
				sizeof(qp_chunk_t) +
				chunk_fromnodes(qp->base->ptr[chunk])->capacity *
					sizeof(dns_qpnode_t);
			memusage.chunk_count += 1;
		}
	}

	/*
	 * Describe the current writer's allocations, excluding bases/chunks
	 * retained only by old versions and snapshots.
	 */
	memusage.bytes = chunk_usage_bytes +
			 (qp->base != NULL ? base_size(qp->chunk_max) : 0);

	return memusage;
}

dns_qp_memusage_t
dns_qpmulti_memusage(dns_qpmulti_t *multi) {
	REQUIRE(QPMULTI_VALID(multi));
	LOCK(&multi->mutex);

	dns_qp_t *qp = &multi->writer;
	INSIST(QP_VALID(qp));

	dns_qp_memusage_t memusage = dns_qp_memusage(qp);

	UNLOCK(&multi->mutex);
	return memusage;
}

void
dns_qp_gctime(isc_nanosecs_t *compact_p, isc_nanosecs_t *recycle_p,
	      isc_nanosecs_t *rollback_p) {
	*compact_p = atomic_load_relaxed(&compact_time);
	*recycle_p = atomic_load_relaxed(&recycle_time);
	*rollback_p = atomic_load_relaxed(&rollback_time);
}

/***********************************************************************
 *
 *  read-write transactions
 */

static dns_qp_t *
transaction_open(dns_qpmulti_t *multi, dns_qp_t **qptp) {
	REQUIRE(QPMULTI_VALID(multi));
	REQUIRE(qptp != NULL && *qptp == NULL);

	LOCK(&multi->mutex);

	dns_qp_t *qp = &multi->writer;
	INSIST(QP_VALID(qp));

	/*
	 * Ensure QP_AUTOGC() ignores free space in immutable chunks.
	 */
	qp->hold_count = qp->free_count;

	*qptp = qp;
	return qp;
}

/*
 * a write is light
 *
 * We need to ensure we allocate from a fresh chunk if the last transaction
 * shrunk the bump chunk; but usually in a sequence of write transactions
 * we just put `fender` at the point where we started this generation.
 *
 * (Aside: Instead of keeping the previous transaction's mode, I
 * considered forcing allocation into the slow path by fiddling with
 * the bump chunk's usage counters. But that is troublesome because
 * `chunk_free()` needs to know how much of the chunk to scan.)
 */
void
dns_qpmulti_write(dns_qpmulti_t *multi, dns_qp_t **qptp) {
	dns_qp_t *qp = transaction_open(multi, qptp);
	TRACE("");

	if (qp->transaction_mode == QP_WRITE) {
		qp->fender = chunk_fromnodes(qp->base->ptr[qp->bump])->used;
	} else {
		alloc_reset(qp);
	}
	qp->transaction_mode = QP_WRITE;
}

/*
 * an update is heavier
 *
 * We always reset the allocator to the start of a fresh chunk,
 * because the previous transaction was probably an update that shrunk
 * the bump chunk. It simplifies rollback because `fender` is always zero.
 *
 * To rollback a transaction, we need to reset all the allocation
 * counters to their previous state, in particular we need to un-free
 * any nodes that were copied to make them mutable. Save the writer and
 * retain its old base, including its free counters and immutable bitmap.
 * Existing physical chunks do not receive new allocations in an update,
 * so their allocation watermarks do not need restoring.
 *
 * Set the saved transaction mode to QP_UPDATE so that the next transaction
 * after rollback starts a fresh bump chunk too. Old chunks were frozen at
 * their commit; the saved bitmap never needs to change during the update.
 */
void
dns_qpmulti_update(dns_qpmulti_t *multi, dns_qp_t **qptp) {
	dns_qp_t *qp = transaction_open(multi, qptp);
	TRACE("");

	qp->transaction_mode = QP_UPDATE;

	dns_qp_t *rollback = isc_mem_allocate(qp->mctx, sizeof(*rollback));
	memmove(rollback, qp, sizeof(*rollback));
	/* can be uninitialized on the first transaction */
	if (rollback->base != NULL) {
		INSIST(QPBASE_VALID(rollback->base));
		INSIST(qp->chunk_max > 0);
		/* paired with either _commit() or _rollback() */
		isc_refcount_increment(&rollback->base->refcount);
	}
	INSIST(multi->rollback == NULL);
	multi->rollback = rollback;

	if (qp->base != NULL) {
		base_clone(qp);
	}
	alloc_reset(qp);
}

void
dns_qpmulti_commit(dns_qpmulti_t *multi, dns_qp_t **qptp) {
	REQUIRE(QPMULTI_VALID(multi));
	REQUIRE(qptp != NULL && *qptp == &multi->writer);
	REQUIRE(multi->writer.transaction_mode == QP_WRITE ||
		multi->writer.transaction_mode == QP_UPDATE);

	dns_qp_t *qp = *qptp;
	TRACE("");

	if (qp->transaction_mode == QP_UPDATE) {
		INSIST(multi->rollback != NULL);
		base_detach(&multi->rollback->base);
		isc_mem_free(qp->mctx, multi->rollback);
		compact(qp);

		/* Only the private, mutable bump allocation may move. */
		qp_chunk_t *chunk = chunk_fromnodes(qp->base->ptr[qp->bump]);
		INSIST(isc_refcount_current(&chunk->references) == 1);
		chunk = isc_mem_reallocate(
			qp->mctx, chunk,
			STRUCT_FLEX_SIZE(chunk, nodes, chunk->used));
		qp->base->ptr[qp->bump] = chunk->nodes;
		chunk->capacity = chunk->used;
	}
	INSIST(multi->rollback == NULL);

	reclaim_chunks(qp);

	qp_version_t *version = isc_mem_get(qp->mctx, sizeof(*version));
	*version = (qp_version_t){ .base = qp->base,
				   .chunk_limit = qp->chunk_limit };
	dns_qpmulti_attach(multi, &version->multi);
	isc_refcount_increment(&version->base->refcount);
	make_reader(version->reader, multi);
	qp->protected = qp->chunk_limit;
	qp->alloc_next = qp->chunk_limit;

	dns_qpnode_t *old = rcu_dereference(multi->reader);
	rcu_assign_pointer(multi->reader, version->reader); /* COMMIT */
	if (old != NULL) {
		qp_version_t *retired = caa_container_of(old, qp_version_t,
							 reader[0]);
		call_rcu(&retired->rcu_head, reclaim_chunks_cb);
	}

	*qptp = NULL;
	UNLOCK(&multi->mutex);
}

/*
 * Throw away everything that was allocated during this transaction.
 */
void
dns_qpmulti_rollback(dns_qpmulti_t *multi, dns_qp_t **qptp) {
	REQUIRE(QPMULTI_VALID(multi));
	REQUIRE(multi->writer.transaction_mode == QP_UPDATE);
	REQUIRE(qptp != NULL && *qptp == &multi->writer);
	INSIST(multi->rollback != NULL);

	dns_qp_t *qp = *qptp;
	isc_nanosecs_t start = isc_time_monotonic();

	/* The private base owns all new allocations; old ones have other
	 * owners. */
	base_detach(&qp->base);
	memmove(qp, multi->rollback, sizeof(*qp));
	isc_mem_free(qp->mctx, multi->rollback);
	atomic_fetch_add_relaxed(&rollback_time, isc_time_monotonic() - start);

	*qptp = NULL;
	UNLOCK(&multi->mutex);
}

/***********************************************************************
 *
 *  read-only transactions
 */

static dns_qpmulti_t *
reader_open(dns_qpmulti_t *multi, dns_qpreadable_t qpr) {
	dns_qpreader_t *qp = dns_qpreader(qpr);
	dns_qpnode_t *reader = rcu_dereference(multi->reader);
	if (reader == NULL) {
		QP_INIT(qp, multi->methods, multi->uctx);
	} else {
		multi = unpack_reader(qp, reader);
	}
	return multi;
}

/*
 * a query is light
 */

void
dns_qpmulti_query(dns_qpmulti_t *multi, dns_qpread_t *qp) {
	REQUIRE(QPMULTI_VALID(multi));
	REQUIRE(qp != NULL);

	qp->tid = isc_tid();
	rcu_read_lock();

	dns_qpmulti_t *whence = reader_open(multi, qp);
	INSIST(whence == multi);
}

void
dns_qpread_destroy(dns_qpmulti_t *multi, dns_qpread_t *qp) {
	REQUIRE(QPMULTI_VALID(multi));
	REQUIRE(QP_VALID(qp));
	REQUIRE(qp->tid == isc_tid());
	*qp = (dns_qpread_t){};
	rcu_read_unlock();
}

/*
 * a snapshot is heavy
 */

void
dns_qpmulti_snapshot(dns_qpmulti_t *multi, dns_qpsnap_t **qpsp) {
	REQUIRE(QPMULTI_VALID(multi));
	REQUIRE(qpsp != NULL && *qpsp == NULL);

	rcu_read_lock();

	LOCK(&multi->mutex);

	dns_qp_t *qpw = &multi->writer;
	dns_qpsnap_t *qps = isc_mem_get(qpw->mctx, sizeof(*qps));
	*qps = (dns_qpsnap_t){};
	qps->whence = reader_open(multi, qps);
	INSIST(qps->whence == multi);
	dns_qpmulti_ref(multi);
	if (qps->base != NULL) {
		/* A private copy freezes metadata and cannot retain later
		 * appends. */
		qps->base = base_copy(qpw, qps->base);
	}
	ISC_LIST_INITANDAPPEND(multi->snapshots, qps, link);

	*qpsp = qps;
	UNLOCK(&multi->mutex);

	rcu_read_unlock();
}

void
dns_qpsnap_destroy(dns_qpmulti_t *multi, dns_qpsnap_t **qpsp) {
	REQUIRE(QPMULTI_VALID(multi));
	REQUIRE(qpsp != NULL && *qpsp != NULL);

	LOCK(&multi->mutex);

	dns_qpsnap_t *qp = *qpsp;

	/* make sure the API is being used correctly */
	REQUIRE(qp->whence == multi);

	ISC_LIST_UNLINK(multi->snapshots, qp, link);

	UNLOCK(&multi->mutex);

	base_detach(&qp->base);
	isc_mem_put(multi->mctx, qp, sizeof(*qp));
	*qpsp = NULL;
	dns_qpmulti_detach(&multi);
}

/***********************************************************************
 *
 *  constructors, destructors
 */

void
dns_qp_create(isc_mem_t *mctx, const dns_qpmethods_t *methods, void *uctx,
	      dns_qp_t **qptp) {
	REQUIRE(mctx != NULL);
	REQUIRE(methods != NULL);
	REQUIRE(qptp != NULL && *qptp == NULL);

	dns_qp_t *qp = isc_mem_get(mctx, sizeof(*qp));
	QP_INIT(qp, methods, uctx);
	qp->mutable_head = INVALID_CHUNK;
	isc_mem_attach(mctx, &qp->mctx);
	alloc_reset(qp);
	TRACE("");
	*qptp = qp;
}

void
dns_qpmulti_create(isc_mem_t *mctx, const dns_qpmethods_t *methods, void *uctx,
		   dns_qpmulti_t **qpmp) {
	REQUIRE(qpmp != NULL && *qpmp == NULL);

	dns_qpmulti_t *multi = isc_mem_get(mctx, sizeof(*multi));
	*multi = (dns_qpmulti_t){ .magic = QPMULTI_MAGIC,
				  .methods = methods,
				  .uctx = uctx,
				  .references = ISC_REFCOUNT_INITIALIZER(1) };
	isc_mem_attach(mctx, &multi->mctx);
	isc_mutex_init(&multi->mutex);
	ISC_LIST_INIT(multi->snapshots);

	/*
	 * Do not waste effort allocating a bump chunk that will be thrown
	 * away when a transaction is opened. dns_qpmulti_update() always
	 * allocates; to ensure dns_qpmulti_write() does too, pretend the
	 * previous transaction was an update
	 */
	dns_qp_t *qp = &multi->writer;
	QP_INIT(qp, methods, uctx);
	qp->mutable_head = INVALID_CHUNK;
	/* Borrow the multi's context; rollback may overwrite the writer. */
	qp->mctx = multi->mctx;
	qp->transaction_mode = QP_UPDATE;
	TRACE("");
	*qpmp = multi;
}

static void
destroy_guts(dns_qp_t *qp) {
	base_detach(&qp->base);
	qp->chunk_max = 0;
	qp->magic = 0;
}

void
dns_qp_destroy(dns_qp_t **qptp) {
	REQUIRE(qptp != NULL);
	REQUIRE(QP_VALID(*qptp));

	dns_qp_t *qp = *qptp;
	*qptp = NULL;

	/* do not try to destroy part of a dns_qpmulti_t */
	REQUIRE(qp->transaction_mode == QP_NONE);

	TRACE("");
	destroy_guts(qp);
	isc_mem_putanddetach(&qp->mctx, qp, sizeof(*qp));
}

static void
qpmulti_free_mem(dns_qpmulti_t *multi) {
	REQUIRE(QPMULTI_VALID(multi));

	isc_mutex_destroy(&multi->mutex);
	isc_mem_putanddetach(&multi->mctx, multi, sizeof(*multi));
}

#if QPMULTI_TRACE
ISC_REFCOUNT_STATIC_TRACE_IMPL(dns_qpmulti, qpmulti_free_mem)
#else
ISC_REFCOUNT_STATIC_IMPL(dns_qpmulti, qpmulti_free_mem)
#endif

static void
qpmulti_destroy_guts_cb(struct rcu_head *arg) {
	dns_qpmulti_t *multi = caa_container_of(arg, dns_qpmulti_t, rcu_head);
	/*
	 * The owner has stopped writes and snapshots. Transient readers have
	 * drained, and retired versions own their bases independently.
	 */
	dns_qpnode_t *reader = multi->reader;
	if (reader != NULL) {
		qp_version_t *version = caa_container_of(reader, qp_version_t,
							 reader[0]);
		reclaim_chunks_cb(&version->rcu_head);
	}
	destroy_guts(&multi->writer);
	dns_qpmulti_detach(&multi);
}

void
dns_qpmulti_destroy(dns_qpmulti_t **qpmp) {
	REQUIRE(qpmp != NULL);
	REQUIRE(QPMULTI_VALID(*qpmp));

	dns_qpmulti_t *multi = *qpmp;
	*qpmp = NULL;
	REQUIRE(QP_VALID(&multi->writer));
	REQUIRE(multi->rollback == NULL);
	REQUIRE(ISC_LIST_EMPTY(multi->snapshots));

	call_rcu(&multi->rcu_head, qpmulti_destroy_guts_cb);
}

/***********************************************************************
 *
 *  modification
 */

isc_result_t
dns_qp_insert(dns_qp_t *qp, void *pval, uint32_t ival) {
	dns_qpref_t new_ref, old_ref;
	dns_qpnode_t new_leaf, old_node;
	dns_qpnode_t *new_twigs = NULL, *old_twigs = NULL;
	dns_qpshift_t new_bit, old_bit;
	dns_qpweight_t old_size, new_size;
	dns_qpkey_t new_key, old_key;
	size_t new_keylen, old_keylen;
	size_t offset;
	uint64_t index;
	dns_qpshift_t bit;
	dns_qpweight_t pos;
	dns_qpnode_t *n = NULL;

	REQUIRE(QP_VALID(qp));

	new_leaf = make_leaf(pval, ival);
	new_keylen = leaf_qpkey(qp, &new_leaf, new_key);

	/* first leaf in an empty trie? */
	if (qp->leaf_count == 0) {
		new_ref = alloc_twigs(qp, 1);
		new_twigs = ref_ptr(qp, new_ref);
		*new_twigs = new_leaf;
		attach_leaf(qp, new_twigs);
		qp->leaf_count++;
		qp->root_ref = new_ref;
		return ISC_R_SUCCESS;
	}

	/*
	 * We need to keep searching down to a leaf even if our key is
	 * missing from this branch. It doesn't matter which twig we
	 * choose since the keys are all the same up to this node's
	 * offset. Note that if we simply use branch_twig_pos(n, bit)
	 * we may get an out-of-bounds access if our bit is greater
	 * than all the set bits in the node.
	 */
	n = ref_ptr(qp, qp->root_ref);
	while (is_branch(n)) {
		prefetch_twigs(qp, n);
		dns_qpref_t ref = branch_twigs_ref(n);
		bit = branch_keybit(n, new_key, new_keylen);
		pos = branch_has_twig(n, bit) ? branch_twig_pos(n, bit) : 0;
		n = ref_ptr(qp, ref + pos);
	}

	/* do the keys differ, and if so, where? */
	old_keylen = leaf_qpkey(qp, n, old_key);
	offset = qpkey_compare(new_key, new_keylen, old_key, old_keylen);
	if (offset == QPKEY_EQUAL) {
		return ISC_R_EXISTS;
	}
	new_bit = qpkey_bit(new_key, new_keylen, offset);
	old_bit = qpkey_bit(old_key, old_keylen, offset);

	/* find where to insert a branch or grow an existing branch. */
	n = make_root_mutable(qp);
	while (is_branch(n)) {
		prefetch_twigs(qp, n);
		if (offset < branch_key_offset(n)) {
			goto newbranch;
		}
		if (offset == branch_key_offset(n)) {
			goto growbranch;
		}
		make_twigs_mutable(qp, n);
		bit = branch_keybit(n, new_key, new_keylen);
		INSIST(branch_has_twig(n, bit));
		n = branch_twig_ptr(qp, n, bit);
	}
	/* fall through */

newbranch:
	new_ref = alloc_twigs(qp, 2);
	new_twigs = ref_ptr(qp, new_ref);

	/* save before overwriting. */
	old_node = *n;

	/* new branch node takes old node's place */
	index = BRANCH_TAG | (1ULL << new_bit) | (1ULL << old_bit) |
		((uint64_t)offset << SHIFT_OFFSET);
	*n = make_node(index, new_ref);

	/* populate twigs */
	new_twigs[old_bit > new_bit] = old_node;
	new_twigs[new_bit > old_bit] = new_leaf;

	attach_leaf(qp, &new_leaf);
	qp->leaf_count++;

	return ISC_R_SUCCESS;

growbranch:
	INSIST(!branch_has_twig(n, new_bit));

	/* locate twigs vectors */
	old_size = branch_twigs_size(n);
	new_size = old_size + 1;
	old_ref = branch_twigs_ref(n);
	new_ref = alloc_twigs(qp, new_size);
	old_twigs = ref_ptr(qp, old_ref);
	new_twigs = ref_ptr(qp, new_ref);

	/* embiggen branch node */
	index = branch_index(n) | (1ULL << new_bit);
	*n = make_node(index, new_ref);

	/* embiggen twigs vector */
	pos = branch_twig_pos(n, new_bit);
	move_twigs(new_twigs, old_twigs, pos);
	new_twigs[pos] = new_leaf;
	move_twigs(new_twigs + pos + 1, old_twigs + pos, old_size - pos);

	if (squash_twigs(qp, old_ref, old_size)) {
		/* old twigs destroyed, only attach to new leaf */
		attach_leaf(qp, &new_leaf);
	} else {
		/* old twigs duplicated, attach to all leaves */
		attach_twigs(qp, new_twigs, new_size);
	}
	qp->leaf_count++;

	return ISC_R_SUCCESS;
}

isc_result_t
dns_qp_deletekey(dns_qp_t *qp, const dns_qpkey_t search_key,
		 size_t search_keylen, void **pval_r, uint32_t *ival_r) {
	REQUIRE(QP_VALID(qp));
	REQUIRE(search_keylen < sizeof(dns_qpkey_t));

	if (get_root(qp) == NULL) {
		return ISC_R_NOTFOUND;
	}

	dns_qpshift_t bit = 0; /* suppress warning */
	dns_qpnode_t *parent = NULL;
	dns_qpnode_t *n = make_root_mutable(qp);
	while (is_branch(n)) {
		prefetch_twigs(qp, n);
		bit = branch_keybit(n, search_key, search_keylen);
		if (!branch_has_twig(n, bit)) {
			return ISC_R_NOTFOUND;
		}
		make_twigs_mutable(qp, n);
		parent = n;
		n = branch_twig_ptr(qp, n, bit);
	}

	dns_qpkey_t found_key;
	size_t found_keylen = leaf_qpkey(qp, n, found_key);
	if (qpkey_compare(search_key, search_keylen, found_key, found_keylen) !=
	    QPKEY_EQUAL)
	{
		return ISC_R_NOTFOUND;
	}

	SET_IF_NOT_NULL(pval_r, leaf_pval(n));
	SET_IF_NOT_NULL(ival_r, leaf_ival(n));
	detach_leaf(qp, n);
	qp->leaf_count--;

	/* trie becomes empty */
	if (qp->leaf_count == 0) {
		INSIST(parent == NULL);
		INSIST(n == get_root(qp));
		free_twigs(qp, qp->root_ref, 1);
		qp->root_ref = INVALID_REF;
		return ISC_R_SUCCESS;
	}

	/* step back to parent node */
	n = parent;
	parent = NULL;

	INSIST(bit != 0);
	dns_qpweight_t size = branch_twigs_size(n);
	dns_qpweight_t pos = branch_twig_pos(n, bit);
	dns_qpref_t ref = branch_twigs_ref(n);
	dns_qpnode_t *twigs = ref_ptr(qp, ref);

	if (size == 2) {
		/*
		 * move the other twig to the parent branch.
		 */
		*n = twigs[!pos];
		squash_twigs(qp, ref, 2);
	} else {
		/*
		 * shrink the twigs in place, to avoid using the bump
		 * chunk too fast - the gc will clean up after us
		 */
		*n = make_node(branch_index(n) & ~(1ULL << bit), ref);
		move_twigs(twigs + pos, twigs + pos + 1, size - pos - 1);
		squash_twigs(qp, ref + size - 1, 1);
	}

	return ISC_R_SUCCESS;
}

isc_result_t
dns_qp_deletename(dns_qp_t *qp, const dns_name_t *name, dns_namespace_t space,
		  void **pval_r, uint32_t *ival_r) {
	dns_qpkey_t key;
	size_t keylen = dns_qpkey_fromname(key, name, space);
	return dns_qp_deletekey(qp, key, keylen, pval_r, ival_r);
}

/***********************************************************************
 *  chains
 */
void
dns_qpchain_init(dns_qpreadable_t qpr, dns_qpchain_t *chain) {
	dns_qpreader_t *qp = dns_qpreader(qpr);
	REQUIRE(QP_VALID(qp));
	REQUIRE(chain != NULL);

	/*
	 * dns_qpchain_t contains a 2kb buffer, which is slow to
	 * zero-initialize. Therefore we avoid designated initializers, and
	 * initialize each field manually.
	 */
	chain->magic = QPCHAIN_MAGIC;
	chain->qp = qp;
	chain->len = 0;
}

unsigned int
dns_qpchain_length(dns_qpchain_t *chain) {
	REQUIRE(QPCHAIN_VALID(chain));

	return chain->len;
}

void
dns_qpchain_node(dns_qpchain_t *chain, unsigned int level, void **pval_r,
		 uint32_t *ival_r) {
	dns_qpnode_t *node = NULL;

	REQUIRE(QPCHAIN_VALID(chain));
	REQUIRE(level < chain->len);

	node = chain->chain[level].node;
	SET_IF_NOT_NULL(pval_r, leaf_pval(node));
	SET_IF_NOT_NULL(ival_r, leaf_ival(node));
}

/***********************************************************************
 *  iterators
 */

void
dns_qpiter_init(dns_qpreadable_t qpr, dns_qpiter_t *qpi) {
	dns_qpreader_t *qp = dns_qpreader(qpr);
	REQUIRE(QP_VALID(qp));
	REQUIRE(qpi != NULL);

	/*
	 * dns_qpiter_t contains a 4kb buffer, which is slow to zero-initialize.
	 * Therefore we avoid designated initializers, and initialize each
	 * field manually.
	 */
	qpi->qp = qp;
	qpi->sp = 0;
	qpi->magic = QPITER_MAGIC;
	/*
	 * The top of the stack must be initialized.
	 */
	qpi->stack[qpi->sp] = NULL;
}

/*
 * are we at the last twig in this branch (in whichever direction
 * we're iterating)?
 */
static bool
last_twig(dns_qpiter_t *qpi, bool forward) {
	dns_qpweight_t pos = 0, max = 0;
	if (qpi->sp > 0) {
		dns_qpnode_t *child = qpi->stack[qpi->sp];
		dns_qpnode_t *parent = qpi->stack[qpi->sp - 1];
		pos = child - ref_ptr(qpi->qp, branch_twigs_ref(parent));
		if (forward) {
			max = branch_twigs_size(parent) - 1;
		}
	}
	return pos == max;
}

/*
 * move a QP iterator forward or back to the next or previous leaf.
 * note: this function can go wrong when the iterator refers to
 * a mutable view of the trie which is altered while iterating
 */
static isc_result_t
iterate(bool forward, dns_qpiter_t *qpi, void **pval_r, uint32_t *ival_r) {
	dns_qpnode_t *node = NULL;
	bool initial_branch = true;

	REQUIRE(QPITER_VALID(qpi));

	dns_qpreader_t *qp = qpi->qp;

	REQUIRE(QP_VALID(qp));

	node = get_root(qp);
	if (node == NULL) {
		return ISC_R_NOMORE;
	}

	do {
		if (qpi->stack[qpi->sp] == NULL) {
			/* newly initialized iterator: use the root node */
			INSIST(qpi->sp == 0);
			qpi->stack[0] = node;
		} else if (!initial_branch) {
			/*
			 * in a prior loop, we reached a branch; from
			 * here we just need to get the highest or lowest
			 * leaf in the subtree; we don't need to bother
			 * stepping forward or backward through twigs
			 * anymore.
			 */
			INSIST(qpi->sp > 0);
		} else if (last_twig(qpi, forward)) {
			/*
			 * we've stepped to the end (or the beginning,
			 * if we're iterating backwards) of a set of twigs.
			 */
			if (qpi->sp == 0) {
				/*
				 * we've finished iterating. reinitialize
				 * the iterator, then return ISC_R_NOMORE.
				 */
				dns_qpiter_init(qpi->qp, qpi);
				return ISC_R_NOMORE;
			}

			/*
			 * pop the stack, and resume at the parent branch.
			 */
			qpi->stack[qpi->sp] = NULL;
			qpi->sp--;
			continue;
		} else {
			/*
			 * there are more twigs in the current branch,
			 * so step the node pointer forward (or back).
			 */
			qpi->stack[qpi->sp] += (forward ? 1 : -1);
			node = qpi->stack[qpi->sp];
		}

		/*
		 * if we're at a branch now, we loop down to the
		 * left- or rightmost leaf.
		 */
		if (is_branch(node)) {
			qpi->sp++;
			INSIST(qpi->sp < DNS_QP_MAXKEY);
			node = ref_ptr(qp, branch_twigs_ref(node)) +
			       (forward ? 0 : branch_twigs_size(node) - 1);
			qpi->stack[qpi->sp] = node;
			initial_branch = false;
		}
	} while (is_branch(node));

	/* we're at a leaf: return its data to the caller */
	SET_IF_NOT_NULL(pval_r, leaf_pval(node));
	SET_IF_NOT_NULL(ival_r, leaf_ival(node));
	return ISC_R_SUCCESS;
}

isc_result_t
dns_qpiter_next(dns_qpiter_t *qpi, void **pval_r, uint32_t *ival_r) {
	return iterate(true, qpi, pval_r, ival_r);
}

isc_result_t
dns_qpiter_prev(dns_qpiter_t *qpi, void **pval_r, uint32_t *ival_r) {
	return iterate(false, qpi, pval_r, ival_r);
}

isc_result_t
dns_qpiter_current(dns_qpiter_t *qpi, void **pval_r, uint32_t *ival_r) {
	dns_qpnode_t *node = NULL;

	REQUIRE(QPITER_VALID(qpi));

	node = qpi->stack[qpi->sp];
	if (node == NULL || is_branch(node)) {
		return ISC_R_FAILURE;
	}

	SET_IF_NOT_NULL(pval_r, leaf_pval(node));
	SET_IF_NOT_NULL(ival_r, leaf_ival(node));
	return ISC_R_SUCCESS;
}

/***********************************************************************
 *
 *  search
 */

isc_result_t
dns_qp_getkey(dns_qpreadable_t qpr, const dns_qpkey_t search_key,
	      size_t search_keylen, void **pval_r, uint32_t *ival_r) {
	dns_qpreader_t *qp = dns_qpreader(qpr);
	dns_qpkey_t found_key;
	size_t found_keylen;
	dns_qpshift_t bit;
	dns_qpnode_t *n = NULL;

	REQUIRE(QP_VALID(qp));
	REQUIRE(search_keylen < sizeof(dns_qpkey_t));

	n = get_root(qp);
	if (n == NULL) {
		return ISC_R_NOTFOUND;
	}

	while (is_branch(n)) {
		prefetch_twigs(qp, n);
		bit = branch_keybit(n, search_key, search_keylen);
		if (!branch_has_twig(n, bit)) {
			return ISC_R_NOTFOUND;
		}
		n = branch_twig_ptr(qp, n, bit);
	}

	found_keylen = leaf_qpkey(qp, n, found_key);
	if (qpkey_compare(search_key, search_keylen, found_key, found_keylen) !=
	    QPKEY_EQUAL)
	{
		return ISC_R_NOTFOUND;
	}

	SET_IF_NOT_NULL(pval_r, leaf_pval(n));
	SET_IF_NOT_NULL(ival_r, leaf_ival(n));
	return ISC_R_SUCCESS;
}

isc_result_t
dns_qp_getname(dns_qpreadable_t qpr, const dns_name_t *name,
	       dns_namespace_t space, void **pval_r, uint32_t *ival_r) {
	dns_qpkey_t key;
	size_t keylen = dns_qpkey_fromname(key, name, space);
	return dns_qp_getkey(qpr, key, keylen, pval_r, ival_r);
}

static inline void
add_link(dns_qpchain_t *chain, dns_qpnode_t *node, size_t offset) {
	/* prevent duplication */
	if (chain->len != 0 && chain->chain[chain->len - 1].node == node) {
		return;
	}
	chain->chain[chain->len].node = node;
	chain->chain[chain->len].offset = offset;
	chain->len++;
	INSIST(chain->len <= DNS_NAME_MAXLABELS);
}

static inline void
prevleaf(dns_qpiter_t *it) {
	isc_result_t result = dns_qpiter_prev(it, NULL, NULL);
	if (result == ISC_R_NOMORE) {
		result = dns_qpiter_prev(it, NULL, NULL);
	}
	RUNTIME_CHECK(result == ISC_R_SUCCESS);
}

static inline void
greatest_leaf(dns_qpreadable_t qpr, dns_qpnode_t *n, dns_qpiter_t *iter) {
	while (is_branch(n)) {
		dns_qpref_t ref = branch_twigs_ref(n) + branch_twigs_size(n) -
				  1;
		iter->stack[++iter->sp] = n;
		n = ref_ptr(qpr, ref);
	}
	iter->stack[++iter->sp] = n;
}

static inline dns_qpnode_t *
anyleaf(dns_qpreader_t *qp, dns_qpnode_t *n) {
	while (is_branch(n)) {
		n = branch_twigs(qp, n);
	}
	return n;
}

static inline int
twig_offset(dns_qpnode_t *n, dns_qpshift_t sbit, dns_qpshift_t kbit,
	    dns_qpshift_t fbit) {
	dns_qpweight_t pos = branch_twig_pos(n, sbit);
	if (branch_has_twig(n, sbit)) {
		return pos - (kbit < fbit);
	}
	return pos - 1;
}

/*
 * If dns_qp_lookup() was passed an iterator, we want it to point at the
 * matching name in the case of an exact match, or at the predecessor name
 * for a non-exact match.
 *
 * If there is an exact match, then there is nothing to be done. Otherwise,
 * we pop up the iterator stack until we find a parent branch with an offset
 * that is before the position where the search key differs from the found key.
 * From there we can step to the leaf that is the predecessor of the searched
 * name.
 *
 * Requires the iterator to be pointing at a leaf node.
 */
static void
fix_iterator(dns_qpreader_t *qp, dns_qpiter_t *it, dns_qpkey_t key,
	     size_t len) {
	dns_qpnode_t *n = it->stack[it->sp];

	REQUIRE(!is_branch(n));

	dns_qpkey_t found;
	size_t foundlen = leaf_qpkey(qp, n, found);
	size_t to = qpkey_compare(key, len, found, foundlen);

	/* If the keys are equal, the iterator is already at the right node. */
	if (to == QPKEY_EQUAL) {
		return;
	}

	/*
	 * Special case: if the key differs even before the root
	 * key offset, it means the name desired either precedes or
	 * follows the entire range of names in the database, and
	 * popping up the stack won't help us, so just move the
	 * iterator one step back from the origin and return.
	 */
	if (to < branch_key_offset(it->stack[0])) {
		dns_qpiter_init(qp, it);
		prevleaf(it);
		return;
	}

	/*
	 * As long as the branch offset point is after the point where the
	 * key differs, we need to branch up and find a better node.
	 */
	while (it->sp > 0) {
		dns_qpnode_t *b = it->stack[it->sp - 1];
		if (branch_key_offset(b) < to) {
			break;
		}
		it->sp--;
	}
	n = it->stack[it->sp];

	/*
	 * Either we are now at the correct branch, or we are at the
	 * first unmatched node. Determine the bit position for the
	 * twig we need (sbit).
	 */
	dns_qpshift_t kbit = qpkey_bit(key, len, to);
	dns_qpshift_t fbit = qpkey_bit(found, foundlen, to);
	dns_qpshift_t sbit = 0;

	if (is_branch(n) && branch_key_offset(n) == to) {
		/* We are on the correct branch now. */
		sbit = kbit;
	} else if (it->sp == 0) {
		/*
		 * We are on the root branch, popping up the stack won't
		 * help us, so just move the iterator one step back from the
		 * origin and return.
		 */
		dns_qpiter_init(qp, it);
		prevleaf(it);
		return;
	} else {
		/* We are at the first unmatched node, pop up the stack. */
		n = it->stack[--it->sp];
		sbit = qpkey_bit(key, len, branch_key_offset(n));
	}

	INSIST(is_branch(n));

	prefetch_twigs(qp, n);
	dns_qpnode_t *twigs = branch_twigs(qp, n);
	int toff = twig_offset(n, sbit, kbit, fbit);
	if (toff >= 0) {
		/*
		 * The name we want would've been after some twig in
		 * this branch. Walk down from that twig to the
		 * highest leaf in its subtree to get the predecessor.
		 */
		greatest_leaf(qp, twigs + toff, it);
	} else {
		/*
		 * Every leaf below this node is greater than the one we
		 * wanted, so the previous leaf is the predecessor.
		 */
		prevleaf(it);
	}
}

/*
 * When searching for a requested name in dns_qp_lookup(), we might add
 * a leaf node to the chain, then subsequently determine that it was a
 * dead end. When this happens, the chain can be left holding a node
 * that is *not* an ancestor of the requested name. We correct for that
 * here.
 */
static void
fix_chain(dns_qpchain_t *chain, size_t offset) {
	while (chain->len > 0 && chain->chain[chain->len - 1].offset >= offset)
	{
		chain->len--;
		chain->chain[chain->len].node = NULL;
		chain->chain[chain->len].offset = 0;
	}
}

isc_result_t
dns_qp_lookup(dns_qpreadable_t qpr, const dns_name_t *name,
	      dns_namespace_t space, dns_qpiter_t *iter, dns_qpchain_t *chain,
	      void **pval_r, uint32_t *ival_r) {
	dns_qpreader_t *qp = dns_qpreader(qpr);
	dns_qpkey_t search, found;
	size_t searchlen, foundlen;
	size_t offset = 0;
	dns_qpnode_t *n = NULL;
	dns_qpshift_t bit = SHIFT_NOBYTE;
	dns_qpchain_t oc;
	dns_qpiter_t it;
	bool matched = false;
	bool setiter = true;

	REQUIRE(QP_VALID(qp));

	searchlen = dns_qpkey_fromname(search, name, space);

	if (chain == NULL) {
		chain = &oc;
	}
	if (iter == NULL) {
		iter = &it;
		setiter = false;
	}
	dns_qpchain_init(qp, chain);
	dns_qpiter_init(qp, iter);

	n = get_root(qp);
	if (n == NULL) {
		return ISC_R_NOTFOUND;
	}
	iter->stack[0] = n;

	/*
	 * Like `dns_qp_insert()`, we must find a leaf. However, we don't make a
	 * second pass: instead, we keep track of any leaves with shorter keys
	 * that we discover along the way. (In general, qp-trie searches can be
	 * one-pass, by recording their traversal, or two-pass, for less stack
	 * memory usage.)
	 */
	while (is_branch(n)) {
		prefetch_twigs(qp, n);

		offset = branch_key_offset(n);
		bit = qpkey_bit(search, searchlen, offset);
		dns_qpnode_t *twigs = branch_twigs(qp, n);

		/*
		 * A shorter key that can be a parent domain always has a
		 * leaf node at SHIFT_NOBYTE (indicating end of its key)
		 * where our search key has a normal character immediately
		 * after a label separator.
		 *
		 * Note 1: It is OK if `off - 1` underflows: it will
		 * become SIZE_MAX, which is greater than `searchlen`, so
		 * `qpkey_bit()` will return SHIFT_NOBYTE, which is what we
		 * want when `off == 0`.
		 *
		 * Note 2: If SHIFT_NOBYTE twig is present, it will always
		 * be in position 0, the first location in 'twigs'.
		 */
		if (bit != SHIFT_NOBYTE && branch_has_twig(n, SHIFT_NOBYTE) &&
		    qpkey_bit(search, searchlen, offset - 1) == SHIFT_NOBYTE &&
		    !is_branch(twigs))
		{
			add_link(chain, twigs, offset);
		}

		matched = branch_has_twig(n, bit);
		if (matched) {
			/*
			 * found a match: if it's a branch, we keep
			 * searching, and if it's a leaf, we drop out of
			 * the loop.
			 */
			n = branch_twig_ptr(qp, n, bit);
		} else {
			/*
			 * this branch is a dead end, and the predecessor
			 * doesn't matter. now we just need to find a leaf
			 * to end on so that qpkey_leaf() will work below.
			 */
			n = anyleaf(qp, twigs);
		}

		iter->stack[++iter->sp] = n;
	}

	if (setiter) {
		/*
		 * we found a leaf, but it might not be the leaf we wanted.
		 * if it isn't, and if the caller passed us an iterator,
		 * then we might need to reposition it.
		 */
		fix_iterator(qp, iter, search, searchlen);
		n = iter->stack[iter->sp];
	}

	/* at this point, n can only be a leaf node */
	INSIST(!is_branch(n));

	foundlen = leaf_qpkey(qp, n, found);
	offset = qpkey_compare(search, searchlen, found, foundlen);

	/* the search ended with an exact or partial match */
	if (offset == QPKEY_EQUAL || offset == foundlen) {
		isc_result_t result = ISC_R_SUCCESS;

		if (offset == foundlen) {
			fix_chain(chain, offset);
			result = DNS_R_PARTIALMATCH;
		}
		add_link(chain, n, offset);

		SET_IF_NOT_NULL(pval_r, leaf_pval(n));
		SET_IF_NOT_NULL(ival_r, leaf_ival(n));
		return result;
	}

	/*
	 * the requested name was not found, but if an ancestor
	 * was, we can retrieve that from the chain.
	 */
	int len = chain->len;
	while (len-- > 0) {
		if (offset >= chain->chain[len].offset) {
			n = chain->chain[len].node;
			SET_IF_NOT_NULL(pval_r, leaf_pval(n));
			SET_IF_NOT_NULL(ival_r, leaf_ival(n));
			return DNS_R_PARTIALMATCH;
		} else {
			/*
			 * oops, during the search we found and added
			 * a leaf that's longer than the requested
			 * name; remove it from the chain.
			 */
			chain->len--;
		}
	}

	/* nothing was found at all */
	return ISC_R_NOTFOUND;
}

/**********************************************************************/
