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

#if FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
#include <sys/mman.h>
#include <unistd.h>
#endif

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
#define TRACE(fmt, ...)                                                       \
	do {                                                                  \
		if (isc_log_wouldlog(ISC_LOG_DEBUG(7))) {                     \
			isc_log_write(DNS_LOGCATEGORY_DATABASE,               \
				      DNS_LOGMODULE_QP, ISC_LOG_DEBUG(7),     \
				      "%s:%d:%s(qp %p uctx \"%s\"):t%" PRItid \
				      ": " fmt,                               \
				      __FILE__, __LINE__, __func__, qp,       \
				      qp ? TRIENAME(qp) : "(null)",           \
				      isc_tid(), ##__VA_ARGS__);              \
		}                                                             \
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
 *  allocator wrappers
 */

#if FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION

/*
 * Optionally (for debugging) during a copy-on-write transaction, use
 * memory protection to ensure that the shared chunks are not modified.
 * Once a chunk becomes shared, it remains read-only until it is freed.
 * POSIX says we have to use mmap() to get an allocation that we can
 * definitely pass to mprotect().
 */

static size_t
chunk_size_raw(void) {
	size_t size = (size_t)sysconf(_SC_PAGE_SIZE);
	return ISC_MAX(size, QP_CHUNK_BYTES);
}

static void *
chunk_get_raw(dns_qp_t *qp, size_t len) {
	if (qp->write_protect) {
		size_t size = chunk_size_raw();
		void *ptr = mmap(NULL, size, PROT_READ | PROT_WRITE,
				 MAP_ANON | MAP_PRIVATE, -1, 0);
		RUNTIME_CHECK(ptr != MAP_FAILED);
		return ptr;
	} else {
		return isc_mem_allocate(qp->mctx, len);
	}
}

static void
chunk_free_raw(isc_mem_t *mctx, bool write_protect, void *ptr) {
	if (write_protect) {
		RUNTIME_CHECK(munmap(ptr, chunk_size_raw()) == 0);
	} else {
		isc_mem_free(mctx, ptr);
	}
}

static void
write_protect(dns_qp_t *qp, dns_qpchunk_t chunk) {
	if (qp->write_protect) {
		/* see transaction_open() wrt this special case */
		if (qp->transaction_mode == QP_WRITE && chunk == qp->bump) {
			return;
		}
		TRACE("chunk %u", chunk);
		void *ptr = qp->base->ptr[chunk];
		size_t size = chunk_size_raw();
		RUNTIME_CHECK(mprotect(ptr, size, PROT_READ) >= 0);
	}
}

#else

#define chunk_get_raw(qp, size) isc_mem_allocate(qp->mctx, size)
#define chunk_free_raw(mctx, write_protect, ptr) isc_mem_free(mctx, ptr)

#define write_protect(qp, chunk)

#endif

/***********************************************************************
 *
 *  allocator
 */

/*
 * When we reuse the bump chunk across multiple write transactions,
 * it can have an immutable prefix and a mutable suffix.
 */
static inline bool
chunk_immutable(dns_qp_t *qp, dns_qpchunk_t chunk) {
	return qp->transaction_mode != QP_NONE &&
	       qp->usage[chunk].generation < qp->generation;
}

static inline bool
cells_immutable(dns_qp_t *qp, dns_qpref_t ref) {
	dns_qpchunk_t chunk = ref_chunk(ref);
	dns_qpcell_t cell = ref_cell(ref);
	if (qp->transaction_mode == QP_NONE) {
		return false;
	}
	if (chunk == qp->bump) {
		return cell < qp->fender;
	} else {
		return chunk_immutable(qp, chunk);
	}
}

static void
maybe_reclaim_chunk(dns_qp_t *qp, dns_qpchunk_t chunk);

static void
qp_init_writer(dns_qp_t *qp) {
	qp->reclaim_head = INVALID_CHUNK;
	qp->reclaim_tail = INVALID_CHUNK;
	qp->free_slot = INVALID_CHUNK;
	qp->chunk_frontier = 0;
	qp->compact_budget = QP_COMPACT_BUDGET;
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
	dns_qpchunk_t old_bump = qp->bump;
	bool had_old_bump = old_bump < qp->chunk_max &&
			    qp->usage[old_bump].exists;

	INSIST(qp->base->ptr[chunk] == NULL);
	INSIST(qp->usage[chunk].used == 0);
	INSIST(qp->usage[chunk].free == 0);
	INSIST(qp->chunk_capacity <= QP_CHUNK_SIZE);

	qp->chunk_capacity = next_capacity(qp->chunk_capacity * 2u, size);
	qp->base->ptr[chunk] =
		chunk_get_raw(qp, qp->chunk_capacity * sizeof(dns_qpnode_t));

	qp->usage[chunk] = (qp_usage_t){ .generation = qp->generation,
					 .reclaim_next = INVALID_CHUNK,
					 .exists = true,
					 .used = size,
					 .capacity = qp->chunk_capacity };
	qp->used_count += size;
	qp->alloc_count += size;
	qp->bump = chunk;
	qp->fender = 0;

	if (had_old_bump) {
		maybe_reclaim_chunk(qp, old_bump);
	}

	if (qp->write_protect) {
		TRACE("chunk %u base %p", chunk, qp->base->ptr[chunk]);
	}
	return make_ref(chunk, 0);
}

/*
 * This is used to grow the chunk arrays when they fill up. If the old
 * base array is in use by readers, we must make a clone, otherwise we
 * can reallocate in place.
 *
 * The isc_refcount_init() and qpbase_unref() in this function are a pair.
 */
static void
realloc_chunk_arrays(dns_qp_t *qp, dns_qpchunk_t newmax) {
	size_t oldptrs = sizeof(qp->base->ptr[0]) * qp->chunk_max;
	size_t newptrs = sizeof(qp->base->ptr[0]) * newmax;
	size_t size = STRUCT_FLEX_SIZE(qp->base, ptr, newmax);

	if (qp->base == NULL || qpbase_unref(qp)) {
		qp->base = isc_mem_reallocate(qp->mctx, qp->base, size);
	} else {
		dns_qpbase_t *oldbase = qp->base;
		qp->base = isc_mem_allocate(qp->mctx, size);
		memmove(&qp->base->ptr[0], &oldbase->ptr[0], oldptrs);
	}
	memset(&qp->base->ptr[qp->chunk_max], 0, newptrs - oldptrs);
	isc_refcount_init(&qp->base->refcount, 1);
	qp->base->magic = QPBASE_MAGIC;

	/* usage array is exclusive to the writer */
	size_t oldusage = sizeof(qp->usage[0]) * qp->chunk_max;
	size_t newusage = sizeof(qp->usage[0]) * newmax;
	qp->usage = isc_mem_reallocate(qp->mctx, qp->usage, newusage);
	memset(&qp->usage[qp->chunk_max], 0, newusage - oldusage);

	qp->chunk_max = newmax;

	TRACE("qpbase %p usage %p max %u", qp->base, qp->usage, qp->chunk_max);
}

/*
 * There was no space in the bump chunk, so find a place to put a fresh
 * chunk in the chunk arrays, then allocate some twigs from it. Slots
 * that have held a chunk before are kept on a list by chunk_detach(),
 * so this never has to scan the arrays; the rest are handed out in
 * order from the frontier.
 */
static dns_qpref_t
alloc_slow(dns_qp_t *qp, dns_qpweight_t size) {
	dns_qpchunk_t chunk = qp->free_slot;

	if (chunk != INVALID_CHUNK) {
		INSIST(chunk < qp->chunk_frontier);
		INSIST(!qp->usage[chunk].exists);
		qp->free_slot = qp->usage[chunk].reclaim_next;
		return chunk_alloc(qp, chunk, size);
	}
	if (qp->chunk_frontier == qp->chunk_max) {
		realloc_chunk_arrays(qp, GROWTH_FACTOR(qp->chunk_max));
	}
	chunk = qp->chunk_frontier++;
	return chunk_alloc(qp, chunk, size);
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
	dns_qpcell_t cell = qp->usage[chunk].used;

	if (cell + size <= qp->usage[chunk].capacity) {
		qp->usage[chunk].used += size;
		qp->used_count += size;
		qp->alloc_count += size;
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
	qp->usage[chunk].free += size;
	ENSURE(qp->free_count <= qp->used_count);
	ENSURE(qp->usage[chunk].free <= qp->usage[chunk].used);

	bool immutable = cells_immutable(qp, twigs);
	if (immutable) {
		qp->hold_count += size;
		ENSURE(qp->free_count >= qp->hold_count);
	} else {
		zero_twigs(ref_ptr(qp, twigs), size);
	}
	if (qp->usage[chunk].used == qp->usage[chunk].free) {
		maybe_reclaim_chunk(qp, chunk);
	}
	return !immutable;
}

/***********************************************************************
 *
 *  leaf references
 *
 * The trie holds one reference on a value from the insertion that put
 * it in the trie until that insertion can no longer be read by any
 * version. Copies of twigs vectors, whether made by copy-on-write or
 * by the compactor, do not touch it. A deleted value goes onto the
 * transaction's retirement batch, and its reference is released once
 * a grace period has passed since the commit and no snapshot of an
 * older version remains. In a single-threaded trie there are no
 * readers, so the reference is released at once.
 */

/*
 * How many deleted values the first batch of a transaction has room
 * for. Small, because a batch outlives the grace period only while a
 * snapshot holds it back, and then the common case is one deletion per
 * transaction; larger batches grow by doubling.
 */
#define QP_DEAD_FIRST 4

static void
retire_leaf(dns_qp_t *qp, dns_qpnode_t *n) {
	qp_deadctx_t *ctx = qp->dead;

	if (qp->transaction_mode == QP_NONE) {
		detach_leaf(qp, n);
		return;
	}
	if (ctx == NULL) {
		ctx = isc_mem_get(qp->mctx,
				  STRUCT_FLEX_SIZE(ctx, leaf, QP_DEAD_FIRST));
		*ctx = (qp_deadctx_t){
			.magic = QPDEAD_MAGIC,
			.link = ISC_LINK_INITIALIZER,
			.max = QP_DEAD_FIRST,
		};
		isc_mem_attach(qp->mctx, &ctx->mctx);
	} else if (ctx->count == ctx->max) {
		uint32_t max = ctx->max * 2;
		ctx = isc_mem_regetx(qp->mctx, ctx,
				     STRUCT_FLEX_SIZE(ctx, leaf, ctx->max),
				     STRUCT_FLEX_SIZE(ctx, leaf, max), 0);
		ctx->max = max;
	}
	ctx->leaf[ctx->count++] = (qp_deadleaf_t){
		.pval = leaf_pval(n),
		.ival = leaf_ival(n),
	};
	qp->dead = ctx;
}

/*
 * Release every leaf reachable from a version, when the version as a
 * whole is going away on destruction.
 */
static void
detach_subtree(dns_qpreader_t *qp, dns_qpnode_t *n) {
	if (is_branch(n)) {
		dns_qpweight_t size = branch_twigs_size(n);
		dns_qpnode_t *twigs = branch_twigs(qp, n);
		for (dns_qpweight_t pos = 0; pos < size; pos++) {
			detach_subtree(qp, &twigs[pos]);
		}
	} else {
		detach_leaf(qp, n);
	}
}

static void
detach_all_leaves(dns_qpreader_t *qp) {
	dns_qpnode_t *root = get_root(qp);
	if (root != NULL) {
		detach_subtree(qp, root);
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
	return qp->usage[chunk].used - qp->usage[chunk].free;
}

/*
 * Does this chunk hold enough garbage to be worth evacuating? The
 * threshold is relative to the chunk's own size, see QP_MAX_FREE. The
 * bump chunk is never evacuated; compact() abandons it instead.
 */
static inline bool
chunk_fragmented(dns_qp_t *qp, dns_qpchunk_t chunk) {
	return chunk != qp->bump &&
	       qp->usage[chunk].free > qp->usage[chunk].used / 8;
}

static void
maybe_reclaim_chunk(dns_qp_t *qp, dns_qpchunk_t chunk) {
	qp_usage_t *usage = &qp->usage[chunk];

	if (qp->transaction_mode == QP_NONE || chunk == qp->bump ||
	    !usage->exists || usage->discounted || usage->reclaim_candidate ||
	    chunk_usage(qp, chunk) != 0)
	{
		return;
	}

	usage->reclaim_candidate = true;
	usage->reclaim_next = INVALID_CHUNK;
	if (qp->reclaim_tail != INVALID_CHUNK) {
		qp->usage[qp->reclaim_tail].reclaim_next = chunk;
	} else {
		qp->reclaim_head = chunk;
	}
	qp->reclaim_tail = chunk;
	qp->reclaim_count++;
	qp->reclaim_used += usage->used;
	qp->reclaim_free += usage->free;
}

/*
 * The chunk is leaving the reclaim list; its cells are about to be
 * discounted, so stop excluding them from QP_NEEDGC().
 */
static inline void
reclaim_unlisted(dns_qp_t *qp, dns_qpchunk_t chunk) {
	INSIST(qp->reclaim_used >= qp->usage[chunk].used);
	INSIST(qp->reclaim_free >= qp->usage[chunk].free);
	qp->reclaim_used -= qp->usage[chunk].used;
	qp->reclaim_free -= qp->usage[chunk].free;
}

/*
 * We remove each empty chunk from the total counts when the chunk is
 * freed, or when it is scheduled for safe memory reclamation. We check
 * the chunk's phase to avoid discounting it twice in the latter case.
 */
static void
chunk_discount(dns_qp_t *qp, dns_qpchunk_t chunk) {
	if (qp->usage[chunk].discounted) {
		return;
	}
	INSIST(qp->used_count >= qp->usage[chunk].used);
	INSIST(qp->free_count >= qp->usage[chunk].free);
	qp->used_count -= qp->usage[chunk].used;
	qp->free_count -= qp->usage[chunk].free;
	qp->usage[chunk].discounted = true;
}

/*
 * A chunk that has been taken away from the writer, whose leaves and
 * packed readers still need detaching before its memory is freed.
 */
typedef struct qp_freechunk {
	dns_qpnode_t *base;
	dns_qpcell_t used;
} qp_freechunk_t;

/*
 * What chunk_release() needs from the trie, copied while the mutex is
 * held so that nothing is read from the writer once it is dropped.
 */
typedef struct qp_release {
	isc_mem_t *mctx;
	const dns_qpmethods_t *methods;
	void *uctx;
	bool write_protect;
} qp_release_t;

static void
release_context(dns_qp_t *qp, qp_release_t *rel) {
	*rel = (qp_release_t){
		.mctx = qp->mctx,
		.methods = qp->methods,
		.uctx = qp->uctx,
		.write_protect = qp->write_protect,
	};
}

/*
 * Take a chunk away from the writer: remove it from the total counts
 * and from the chunk arrays, so that its slot can be reused. This needs
 * the writer mutex, but the scan and free in chunk_release() do not, so
 * a caller that holds the mutex on behalf of other threads can drop it
 * in between and keep them waiting for a bounded time only.
 */
static void
chunk_detach(dns_qp_t *qp, dns_qpchunk_t chunk, qp_freechunk_t *fc) {
	if (qp->write_protect) {
		TRACE("chunk %u base %p", chunk, qp->base->ptr[chunk]);
	}
	*fc = (qp_freechunk_t){
		.base = qp->base->ptr[chunk],
		.used = qp->usage[chunk].used,
	};
	chunk_discount(qp, chunk);
	qp->base->ptr[chunk] = NULL;
	qp->usage[chunk] = (qp_usage_t){ .reclaim_next = qp->free_slot };
	qp->free_slot = chunk;
}

/*
 * When a chunk is being freed, we need to free any `base` arrays that
 * have been marked as unused. The leaves in it hold no references of
 * their own, see retire_leaf(). Nothing is read from the trie itself,
 * so once the chunk has been detached this is safe without the writer
 * mutex.
 */
static void
chunk_release(const qp_release_t *rel, const qp_freechunk_t *fc) {
	dns_qpnode_t *base = fc->base;
	dns_qpnode_t *n = base;

	for (dns_qpcell_t count = fc->used; count > 1; count--, n++) {
		if (reader_valid(n)) {
			dns_qpreader_t qpr;
			unpack_reader(&qpr, n);
			/* pairs with dns_qpmulti_commit() */
			if (qpbase_unref(&qpr)) {
				isc_mem_free(rel->mctx, qpr.base);
			}
		}
	}
	chunk_free_raw(rel->mctx, rel->write_protect, base);
}

static void
chunk_free(dns_qp_t *qp, dns_qpchunk_t chunk) {
	qp_release_t rel;
	qp_freechunk_t fc;

	release_context(qp, &rel);
	chunk_detach(qp, chunk, &fc);
	chunk_release(&rel, &fc);
}

/*
 * Free any chunks that we can while a trie is in use.
 */
static void
recycle(dns_qp_t *qp) {
	unsigned int nfree = 0;

	if (qp->transaction_mode != QP_NONE && qp->reclaim_count == 0) {
		return;
	}

	isc_nanosecs_t start = isc_time_monotonic();

	if (qp->transaction_mode == QP_NONE) {
		for (dns_qpchunk_t chunk = 0; chunk < qp->chunk_max; chunk++) {
			if (chunk != qp->bump && chunk_usage(qp, chunk) == 0 &&
			    qp->usage[chunk].exists)
			{
				chunk_free(qp, chunk);
				nfree++;
			}
		}
	} else {
		/*
		 * Recycle unpublished empty chunks before the next transaction
		 * makes them immutable. Keep shared chunks queued for RCU.
		 */
		dns_qpchunk_t *link = &qp->reclaim_head;
		qp->reclaim_tail = INVALID_CHUNK;
		while (*link != INVALID_CHUNK) {
			dns_qpchunk_t chunk = *link;
			qp_usage_t *usage = &qp->usage[chunk];

			if (chunk_immutable(qp, chunk)) {
				qp->reclaim_tail = chunk;
				link = &usage->reclaim_next;
			} else {
				*link = usage->reclaim_next;
				qp->reclaim_count--;
				reclaim_unlisted(qp, chunk);
				chunk_free(qp, chunk);
				nfree++;
			}
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
 * How many chunks the RCU callback detaches per mutex acquisition. It
 * does the expensive part, scanning and freeing a chunk, without the
 * mutex, so writers only ever wait for the bookkeeping.
 */
#define QP_RECLAIM_BATCH 32

/*
 * asynchronous cleanup, after a grace period
 */
static void
reclaim_chunks_cb(struct rcu_head *arg) {
	qp_rcuctx_t *rcuctx = caa_container_of(arg, qp_rcuctx_t, rcu_head);
	REQUIRE(QPRCU_VALID(rcuctx));
	dns_qpmulti_t *multi = rcuctx->multi;
	REQUIRE(QPMULTI_VALID(multi));
	dns_qp_t *qp = &multi->writer;
	qp_release_t rel;
	unsigned int nfree = 0;

	isc_nanosecs_t start = isc_time_monotonic();

	for (unsigned int i = 0; i < rcuctx->count; i += QP_RECLAIM_BATCH) {
		qp_freechunk_t batch[QP_RECLAIM_BATCH];
		unsigned int n = 0;

		LOCK(&multi->mutex);
		if (i == 0) {
			release_context(qp, &rel);
		}
		/*
		 * If chunk_max is zero, the trie has been destroyed and
		 * all its chunks have already been freed.
		 */
		if (qp->chunk_max != 0) {
			INSIST(QP_VALID(qp));
			for (unsigned int k = i;
			     k < i + QP_RECLAIM_BATCH && k < rcuctx->count; k++)
			{
				dns_qpchunk_t chunk = rcuctx->chunk[k];
				if (qp->usage[chunk].snapshot) {
					/* clean up when snapshot is destroyed
					 */
					qp->usage[chunk].snapfree = true;
				} else {
					chunk_detach(qp, chunk, &batch[n++]);
				}
			}
		}
		UNLOCK(&multi->mutex);

		for (unsigned int k = 0; k < n; k++) {
			chunk_release(&rel, &batch[k]);
		}
		nfree += n;
	}

	isc_nanosecs_t time = isc_time_monotonic() - start;
	atomic_fetch_add_relaxed(&recycle_time, time);

	if (nfree > 0) {
		LOG_STATS("qp reclaim" PRItime "free %u chunks", time, nfree);
	}

	dns_qpmulti_detach(&multi);
	isc_mem_putanddetach(&rcuctx->mctx, rcuctx,
			     STRUCT_FLEX_SIZE(rcuctx, chunk, rcuctx->count));
}

/*
 * At the end of a transaction, schedule empty but immutable chunks
 * for reclamation later.
 */
static void
reclaim_chunks(dns_qpmulti_t *multi) {
	dns_qp_t *qp = &multi->writer;

	if (qp->reclaim_count == 0) {
		return;
	}

	qp_rcuctx_t *rcuctx = isc_mem_get(
		qp->mctx, STRUCT_FLEX_SIZE(rcuctx, chunk, qp->reclaim_count));
	*rcuctx = (qp_rcuctx_t){
		.magic = QPRCU_MAGIC,
		.multi = multi,
		.count = qp->reclaim_count,
	};
	isc_mem_attach(qp->mctx, &rcuctx->mctx);

	unsigned int i = 0;
	for (dns_qpchunk_t chunk = qp->reclaim_head; chunk != INVALID_CHUNK;) {
		qp_usage_t *usage = &qp->usage[chunk];
		dns_qpchunk_t next = usage->reclaim_next;

		INSIST(chunk != qp->bump);
		INSIST(chunk_usage(qp, chunk) == 0);
		INSIST(usage->exists);
		INSIST(chunk_immutable(qp, chunk));
		INSIST(!usage->discounted);
		INSIST(usage->reclaim_candidate);

		usage->reclaim_candidate = false;
		usage->reclaim_next = INVALID_CHUNK;
		rcuctx->chunk[i++] = chunk;
		reclaim_unlisted(qp, chunk);
		chunk_discount(qp, chunk);
		chunk = next;
	}
	INSIST(i == rcuctx->count);
	INSIST(qp->reclaim_used == 0 && qp->reclaim_free == 0);
	qp->reclaim_head = INVALID_CHUNK;
	qp->reclaim_tail = INVALID_CHUNK;
	qp->reclaim_count = 0;

	/*
	 * Reference the qpmulti object to keep it from being
	 * freed until reclaim_chunks_cb() runs.
	 */
	dns_qpmulti_ref(multi);
	call_rcu(&rcuctx->rcu_head, reclaim_chunks_cb);

	LOG_STATS("qp will reclaim %u chunks", rcuctx->count);
}

/*
 * Deleted values are released in the order their transactions
 * committed, once each one's grace period has passed and no snapshot
 * of an older version remains. The list is in commit order, so only
 * its head needs looking at: a snapshot that holds back one entry
 * holds back everything after it, and a grace period that has not
 * passed for an older entry is waited for by the newer ones too, so
 * that a long backlog costs nothing to scan. The caller holds the
 * mutex; the values are detached by release_dead() after it is
 * dropped.
 */
static void
collect_dead(dns_qpmulti_t *multi, qp_deadlist_t *ready) {
	uint64_t oldest = UINT64_MAX;
	qp_deadctx_t *ctx = NULL;

	ISC_LIST_FOREACH(multi->snapshots, qps, link) {
		oldest = ISC_MIN(oldest, qps->generation);
	}
	while ((ctx = ISC_LIST_HEAD(multi->dead)) != NULL && ctx->grace &&
	       ctx->generation <= oldest)
	{
		ISC_LIST_UNLINK(multi->dead, ctx, link);
		ISC_LIST_APPEND(*ready, ctx, link);
	}
}

static void
deadctx_free(qp_deadctx_t *ctx) {
	dns_qpmulti_detach(&ctx->multi);
	isc_mem_putanddetach(&ctx->mctx, ctx,
			     STRUCT_FLEX_SIZE(ctx, leaf, ctx->max));
}

static void
release_dead(const qp_release_t *rel, qp_deadlist_t *ready) {
	unsigned int nfree = 0;

	ISC_LIST_FOREACH(*ready, ctx, link) {
		ISC_LIST_UNLINK(*ready, ctx, link);
		for (uint32_t k = 0; k < ctx->count; k++) {
			rel->methods->detach(rel->uctx, ctx->leaf[k].pval,
					     ctx->leaf[k].ival);
		}
		nfree += ctx->count;
		deadctx_free(ctx);
	}
	if (nfree > 0) {
		LOG_STATS("qp retire %u leaves", nfree);
	}
}

/*
 * The grace period after a commit has passed: release what it deleted,
 * and anything older that was only waiting for its grace period.
 */
static void
retire_dead_cb(struct rcu_head *arg) {
	qp_deadctx_t *ctx = caa_container_of(arg, qp_deadctx_t, rcu_head);
	REQUIRE(QPDEAD_VALID(ctx));
	dns_qpmulti_t *multi = ctx->multi;
	REQUIRE(QPMULTI_VALID(multi));
	qp_deadlist_t ready;
	qp_release_t rel;

	ISC_LIST_INIT(ready);
	LOCK(&multi->mutex);
	if (ctx->released) {
		/* the trie was destroyed first and let go of the values */
		UNLOCK(&multi->mutex);
		deadctx_free(ctx);
		return;
	}
	ctx->grace = true;
	collect_dead(multi, &ready);
	release_context(&multi->writer, &rel);
	UNLOCK(&multi->mutex);

	release_dead(&rel, &ready);
}

/*
 * At the end of a transaction, hand the deleted values over to wait
 * for a grace period.
 */
static void
retire_dead(dns_qpmulti_t *multi) {
	dns_qp_t *qp = &multi->writer;
	qp_deadctx_t *ctx = qp->dead;

	if (ctx == NULL) {
		return;
	}
	qp->dead = NULL;
	ctx->multi = multi;
	ctx->generation = qp->generation;
	ISC_LIST_APPEND(multi->dead, ctx, link);
	/* paired with deadctx_free() */
	dns_qpmulti_ref(multi);
	call_rcu(&ctx->rcu_head, retire_dead_cb);
	LOG_STATS("qp will retire %u leaves", ctx->count);
}

/*
 * When a snapshot is destroyed, clean up chunks that need free()ing
 * and are not used by any remaining snapshots.
 */
static unsigned int
marksweep_chunks(dns_qpmulti_t *multi, qp_freechunk_t **batchp) {
	unsigned int nfree = 0, n = 0;
	qp_freechunk_t *batch = NULL;

	isc_nanosecs_t start = isc_time_monotonic();

	dns_qp_t *qpw = &multi->writer;

	ISC_LIST_FOREACH(multi->snapshots, qps, link) {
		for (dns_qpchunk_t chunk = 0; chunk < qps->chunk_max; chunk++) {
			if (qps->base->ptr[chunk] != NULL) {
				INSIST(qps->base->ptr[chunk] ==
				       qpw->base->ptr[chunk]);
				qpw->usage[chunk].snapmark = true;
			}
		}
	}

	for (dns_qpchunk_t chunk = 0; chunk < qpw->chunk_max; chunk++) {
		qpw->usage[chunk].snapshot = qpw->usage[chunk].snapmark;
		qpw->usage[chunk].snapmark = false;
		if (qpw->usage[chunk].snapfree && !qpw->usage[chunk].snapshot) {
			nfree++;
		}
	}

	/*
	 * Detach the chunks now, but leave freeing them to the caller
	 * once it has dropped the mutex.
	 */
	if (nfree > 0) {
		batch = isc_mem_cget(qpw->mctx, nfree, sizeof(*batch));
		for (dns_qpchunk_t chunk = 0; chunk < qpw->chunk_max; chunk++) {
			if (qpw->usage[chunk].snapfree &&
			    !qpw->usage[chunk].snapshot)
			{
				chunk_detach(qpw, chunk, &batch[n++]);
			}
		}
		INSIST(n == nfree);
	}

	isc_nanosecs_t time = isc_time_monotonic() - start;
	atomic_fetch_add_relaxed(&recycle_time, time);

	if (nfree > 0) {
		LOG_STATS("qp marksweep" PRItime "free %u chunks", time, nfree);
		LOG_STATS(
			"qp marksweep leaf %u live %u used %u free %u hold %u",
			qpw->leaf_count, qpw->used_count - qpw->free_count,
			qpw->used_count, qpw->free_count, qpw->hold_count);
	}

	*batchp = batch;
	return nfree;
}

/***********************************************************************
 *
 *  garbage collector
 */

/*
 * Move a twigs vector to the `bump` chunk, for copy-on-write or for
 * garbage collection. We don't update the branch node in place because
 * `compact_walk()` does not ensure the node itself is mutable until
 * after it discovers evacuation was necessary.
 *
 * If free_twigs() could not immediately destroy the old twigs, we have
 * to re-attach to any leaves.
 */
static dns_qpref_t
evacuate_twigs(dns_qp_t *qp, dns_qpref_t old_ref, dns_qpweight_t size) {
	dns_qpref_t new_ref = alloc_twigs(qp, size);
	dns_qpnode_t *old_twigs = ref_ptr(qp, old_ref);
	dns_qpnode_t *new_twigs = ref_ptr(qp, new_ref);

	/*
	 * A leaf's reference belongs to its insertion, not to a cell,
	 * so copying the twigs does not touch it, whether or not the
	 * old copy stays behind for readers.
	 */
	move_twigs(new_twigs, old_twigs, size);
	(void)free_twigs(qp, old_ref, size);

	return new_ref;
}

static dns_qpref_t
evacuate(dns_qp_t *qp, dns_qpnode_t *n) {
	return evacuate_twigs(qp, branch_twigs_ref(n), branch_twigs_size(n));
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

static inline dns_qpnode_t *
anyleaf(dns_qpreader_t *qp, dns_qpnode_t *n);

/*
 * Compaction walks the trie depth-first in key order, copying bottom-up
 * as required. A twigs vector is evacuated when its chunk is fragmented;
 * when a child moves, its parent's vector is updated in place if it is
 * mutable, or evacuated too if it is immutable, so that the change
 * bubbles up towards the root. The aim is to avoid evacuation as much
 * as possible: without the chunk_fragmented() check the walk leaves the
 * trie unchanged, because that check is the only place that introduces
 * ref changes.
 *
 * In a multi-threaded trie a compaction cycle is split into steps of
 * bounded work, one per transaction, so that the writer mutex is never
 * held for a time proportional to the size of the trie. A step resumes
 * where the previous one stopped, using a saved key rather than saved
 * node pointers, because the transactions in between may have moved or
 * deleted any node. The saved key is the least leaf key under the next
 * subtree to process. When a step resumes, the path down to that key
 * is walked "on-path": at each branch on the path the twigs before the
 * key's twig were processed by earlier steps and are skipped, the key's
 * own twig is descended, and the later twigs are processed normally.
 * Because twigs are ordered by key, a step processes exactly the vectors
 * whose least leaf key is greater than or equal to the saved key, no
 * matter what was inserted or deleted in between.
 *
 * The saved key is the least leaf of a subtree that the previous step
 * did not enter, so the path down to it consists of two parts: the
 * ancestors of that subtree, which earlier steps processed, and the
 * subtree's own branch and its leftmost chain, which they did not. The
 * key offset of the subtree's branch tells them apart, even after the
 * trie has changed shape: branches above it have smaller offsets, and
 * a branch that collapses into its child leaves a larger one.
 *
 * The work budget is charged only for unprocessed vectors, for every
 * vector visited and every vector copied. The processed part of the
 * chain is copied again by every step, because the previous step
 * published it, so charging for it could exhaust the budget before
 * any new work is done; and a `compact_all` cycle must not copy it
 * again either, or it would copy the whole path on every step.
 */
typedef struct compact_ctx {
	dns_qp_t *qp;
	/*% cells of off-path work remaining; may go negative */
	int64_t budget;
	/*% stop when the budget is exhausted */
	bool bounded;
	/*% at least one off-path vector was visited by this step */
	bool progressed;
	/*% the budget ran out and a cursor was saved; unwinding */
	bool exhausted;
	/*% number of frames on the resume path (0: start from the root) */
	unsigned int onpath_depth;
	/*% first twig to process in each on-path frame */
	dns_qpweight_t start[DNS_QP_MAXKEY + 1];
} compact_ctx_t;

/*
 * Remember the least leaf key under `child`, the next subtree to process.
 */
static void
compact_save_cursor(compact_ctx_t *ctx, dns_qpnode_t *child) {
	dns_qp_t *qp = ctx->qp;
	dns_qpnode_t *leaf = anyleaf((dns_qpreader_t *)qp, child);

	if (qp->compact_key == NULL) {
		qp->compact_key = isc_mem_get(qp->mctx,
					      sizeof(*qp->compact_key));
	}
	qp->compact_keylen = leaf_qpkey(qp, leaf, *qp->compact_key);
	qp->compact_keyoffset = branch_key_offset(child);
	ctx->exhausted = true;
}

/*
 * Work out where the saved key falls in the trie as it is now, and fill
 * in the first twig to process at each level of the path down to it.
 * This is the same reasoning as fix_iterator(): follow the key as far
 * as it matches, find the leaf that lies where the key would be, then
 * let the order of the two keys decide whether the subtree in which
 * they diverge was already processed.
 *
 * Frame 0 is the root frame, whose only twig is the root node; frame
 * `level` is the twigs vector of the branch found at start[level - 1]
 * in the frame above.
 */
static void
compact_resume(compact_ctx_t *ctx) {
	dns_qp_t *qp = ctx->qp;
	dns_qpreader_t *qpr = (dns_qpreader_t *)qp;

	ctx->onpath_depth = 0;
	ctx->start[0] = 0;
	if (qp->compact_key == NULL) {
		return;
	}

	const dns_qpshift_t *key = *qp->compact_key;
	size_t keylen = qp->compact_keylen;

	/* find the leaf that lies where the key would be */
	dns_qpnode_t *n = ref_ptr(qp, qp->root_ref);
	while (is_branch(n)) {
		dns_qpshift_t bit = branch_keybit(n, key, keylen);
		if (branch_has_twig(n, bit)) {
			n = branch_twig_ptr(qpr, n, bit);
		} else {
			n = anyleaf(qpr, n);
		}
	}
	dns_qpkey_t found;
	size_t foundlen = leaf_qpkey(qp, n, found);
	size_t to = qpkey_compare(key, keylen, found, foundlen);

	unsigned int level = 1;
	n = ref_ptr(qp, qp->root_ref);
	for (;;) {
		if (!is_branch(n)) {
			/* the key's own leaf: nothing below it to process */
			ctx->onpath_depth = level;
			return;
		}
		if (to != QPKEY_EQUAL && branch_key_offset(n) > to) {
			/*
			 * The key diverges above this subtree, so all of
			 * it sorts on the same side of the key: before it
			 * (done, skip it) or after it (not yet processed,
			 * enter it from its first twig, off-path).
			 */
			if (qpkey_bit(key, keylen, to) >
			    qpkey_bit(found, foundlen, to))
			{
				ctx->start[level - 1]++;
			}
			ctx->onpath_depth = level;
			return;
		}
		dns_qpshift_t bit = branch_keybit(n, key, keylen);
		if (!branch_has_twig(n, bit)) {
			/* the key's subtree is gone; resume after its place */
			ctx->start[level] = branch_count_bitmap_before(n, bit);
			ctx->onpath_depth = level + 1;
			return;
		}
		ctx->start[level] = branch_twig_pos(n, bit);
		n = branch_twig_ptr(qpr, n, bit);
		level++;
	}
}

static dns_qpref_t
compact_walk(compact_ctx_t *ctx, dns_qpnode_t *parent, unsigned int level,
	     bool onpath) {
	dns_qp_t *qp = ctx->qp;
	dns_qpweight_t size = branch_twigs_size(parent);
	dns_qpref_t twigs_ref = branch_twigs_ref(parent);
	dns_qpchunk_t chunk = ref_chunk(twigs_ref);
	dns_qpweight_t first = onpath ? ctx->start[level] : 0;
	bool processed = onpath &&
			 branch_key_offset(parent) < qp->compact_keyoffset;

	if (!processed) {
		ctx->budget -= size;
		ctx->progressed = true;
	}
	if ((qp->compact_all && !processed) ||
	    (chunk_fragmented(qp, chunk) &&
	     qp->usage[chunk].generation < qp->compact_cutoff))
	{
		twigs_ref = evacuate_twigs(qp, twigs_ref, size);
		qp->compact_evacuated += size;
		if (!processed) {
			ctx->budget -= size;
		}
	}
	bool immutable = cells_immutable(qp, twigs_ref);
	for (dns_qpweight_t pos = first; pos < size; pos++) {
		dns_qpnode_t *child = ref_ptr(qp, twigs_ref) + pos;
		if (!is_branch(child)) {
			continue;
		}
		bool child_onpath = onpath && pos == first &&
				    level + 1 < ctx->onpath_depth;
		if (!child_onpath && ctx->bounded && ctx->budget <= 0 &&
		    ctx->progressed)
		{
			compact_save_cursor(ctx, child);
			break;
		}
		dns_qpref_t old_grandtwigs = branch_twigs_ref(child);
		dns_qpref_t new_grandtwigs = compact_walk(ctx, child, level + 1,
							  child_onpath);
		if (old_grandtwigs != new_grandtwigs) {
			if (immutable) {
				twigs_ref = evacuate_twigs(qp, twigs_ref, size);
				qp->compact_evacuated += size;
				if (!processed) {
					ctx->budget -= size;
				}
				/* the twigs have moved */
				child = ref_ptr(qp, twigs_ref) + pos;
				immutable = false;
			}
			*child = make_node(branch_index(child), new_grandtwigs);
		}
		if (ctx->exhausted) {
			break;
		}
	}
	return twigs_ref;
}

/*
 * Start a compaction cycle. Only chunks that existed before the cycle
 * started are evacuated, so that a cycle never chases its own output,
 * and a bounded cycle allocates its output in a fresh chunk for the
 * same reason. A synchronous compaction completes in one walk, so it
 * keeps its bump chunk unless that holds too much garbage; every chunk
 * of a single-threaded trie is in generation zero, so the cutoff makes
 * them all eligible.
 */
static void
compact_cycle_start(dns_qp_t *qp, bool bounded) {
	INSIST(!qp->compact_active);
	INSIST(qp->compact_key == NULL);

	LOG_STATS("qp compact start leaf %u live %u used %u free %u hold %u",
		  qp->leaf_count, qp->used_count - qp->free_count,
		  qp->used_count, qp->free_count, qp->hold_count);

	bool fresh = bounded && qp->transaction_mode != QP_NONE;
	if (fresh) {
		qp->compact_cutoff = qp->generation;
		alloc_reset(qp);
	} else {
		qp->compact_cutoff = qp->generation + 1;
		if (qp->compact_all || (qp->chunk_max > 0 &&
					qp->usage[qp->bump].free > QP_MAX_FREE))
		{
			alloc_reset(qp);
		}
	}
	qp->compact_active = true;
	qp->compact_evacuated = 0;
	qp->compact_steps = 0;
	qp->alloc_at_step = qp->alloc_count;
}

static void
compact_release_cursor(dns_qp_t *qp) {
	if (qp->compact_key != NULL) {
		isc_mem_put(qp->mctx, qp->compact_key,
			    sizeof(*qp->compact_key));
	}
	qp->compact_keylen = 0;
}

/*
 * Forget an unfinished cycle; the next cycle starts from the root again.
 */
static void
compact_abort(dns_qp_t *qp) {
	compact_release_cursor(qp);
	qp->compact_active = false;
}

static void
compact_finish(dns_qp_t *qp) {
	compact_release_cursor(qp);
	qp->compact_active = false;
	qp->compact_all = false;

	LOG_STATS("qp compact done steps %u evacuated %u leaf %u live %u "
		  "used %u free %u hold %u",
		  qp->compact_steps, qp->compact_evacuated, qp->leaf_count,
		  qp->used_count - qp->free_count, qp->used_count,
		  qp->free_count, qp->hold_count);
}

/*
 * Called after a cycle has finished and recycle() has run. This
 * shouldn't happen if the garbage collector is working correctly: the
 * trie still looks fragmented although the cycle found nothing to move.
 * Give the next cycle a chance, because the garbage may be in chunks
 * that were too young for this one, then recover by copying everything
 * at the cost of some time and space.
 */
static void
compact_check_stuck(dns_qp_t *qp, bool was_all) {
	if (was_all || qp->compact_evacuated > 0 || !QP_NEEDGC(qp)) {
		qp->compact_stuck = false;
		return;
	}
	if (!qp->compact_stuck) {
		qp->compact_stuck = true;
		return;
	}
	isc_log_write(DNS_LOGCATEGORY_DATABASE, DNS_LOGMODULE_QP,
		      ISC_LOG_NOTICE,
		      "qp %p uctx \"%s\" compaction failed to recover any "
		      "space, scheduling a full compaction",
		      qp, TRIENAME(qp));
	qp->compact_all = true;
	qp->compact_stuck = false;
}

/*
 * Compact the whole trie synchronously. A bounded cycle in progress is
 * abandoned rather than continued: its cutoff would leave out every
 * chunk allocated since it started, and a caller that asks for a
 * synchronous compaction wants the whole trie considered.
 */
static void
compact(dns_qp_t *qp) {
	bool was_all = qp->compact_all;
	isc_nanosecs_t start = isc_time_monotonic();

	compact_abort(qp);
	compact_cycle_start(qp, false);
	if (qp->leaf_count > 0) {
		compact_ctx_t ctx = { .qp = qp };
		compact_resume(&ctx);
		qp->root_ref = compact_walk(&ctx, MOVABLE_ROOT(qp), 0,
					    ctx.onpath_depth > 0);
		INSIST(!ctx.exhausted);
	}
	compact_finish(qp);

	isc_nanosecs_t time = isc_time_monotonic() - start;
	atomic_fetch_add_relaxed(&compact_time, time);

	LOG_STATS("qp compact" PRItime
		  "leaf %u live %u used %u free %u hold %u",
		  time, qp->leaf_count, qp->used_count - qp->free_count,
		  qp->used_count, qp->free_count, qp->hold_count);

	recycle(qp);
	compact_check_stuck(qp, was_all);
}

/*
 * One bounded increment of a compaction cycle; see compact_walk() for
 * the resume mechanism. The budget grows with the number of cells
 * allocated since the previous step, so that the collector keeps pace
 * with a mutator that makes large transactions.
 */
static void
compact_step(dns_qp_t *qp) {
	if (!qp->compact_active) {
		if (!qp->compact_all && !QP_NEEDGC(qp)) {
			return;
		}
		compact_cycle_start(qp, true);
	}
	bool was_all = qp->compact_all;
	bool finished = true;
	isc_nanosecs_t start = isc_time_monotonic();

	qp->compact_stepped = true;
	qp->compact_steps++;

	if (qp->leaf_count > 0) {
		uint64_t pressure = qp->alloc_count - qp->alloc_at_step;
		uint64_t budget = ISC_CLAMP(
			pressure, (uint64_t)qp->compact_budget,
			(uint64_t)qp->compact_budget * QP_COMPACT_BUDGET_MAX);
		compact_ctx_t ctx = {
			.qp = qp,
			.budget = (int64_t)budget,
			.bounded = true,
		};
		compact_resume(&ctx);
		qp->root_ref = compact_walk(&ctx, MOVABLE_ROOT(qp), 0,
					    ctx.onpath_depth > 0);
		finished = !ctx.exhausted;
	}
	qp->alloc_at_step = qp->alloc_count;
	if (finished) {
		compact_finish(qp);
	}

	isc_nanosecs_t time = isc_time_monotonic() - start;
	atomic_fetch_add_relaxed(&compact_time, time);

	LOG_STATS("qp compact step %u" PRItime
		  "leaf %u live %u used %u free %u hold %u",
		  qp->compact_steps, time, qp->leaf_count,
		  qp->used_count - qp->free_count, qp->used_count,
		  qp->free_count, qp->hold_count);

	recycle(qp);
	if (finished) {
		compact_check_stuck(qp, was_all);
	}
}

void
dns_qp_compact(dns_qp_t *qp, dns_qpgc_t mode) {
	REQUIRE(QP_VALID(qp));

	if (mode == DNS_QPGC_MAYBE) {
		/* inside a transaction, one bounded step is enough */
		if (qp->transaction_mode != QP_NONE) {
			if (!qp->compact_stepped) {
				compact_step(qp);
			}
			return;
		}
		if (!QP_NEEDGC(qp)) {
			return;
		}
	} else if (mode == DNS_QPGC_ALL) {
		compact_abort(qp);
		qp->compact_all = true;
	}
	compact(qp);
}

/*
 * Free some twigs and (if they were destroyed immediately so that the
 * result from QP_AUTOGC can change) compact the trie if necessary.
 *
 * This is called by the trie modification API entry points. The
 * free_twigs() function requires the caller to attach or detach any
 * leaves as necessary. Callers of squash_twigs() satisfy this
 * requirement by calling make_twigs_mutable().
 *
 * Compaction from here may move any reachable twigs vector, including
 * ones the caller allocated just before, so callers must not hold
 * pointers into twigs vectors across this call. A single-threaded trie
 * is compacted synchronously; inside a transaction we take at most one
 * bounded step, and the commit does the rest over time.
 *
 * Aside: In typical garbage collectors, compaction is triggered when
 * the allocator runs out of space. But that is because typical garbage
 * collectors do not know how much memory can be recovered, so they must
 * find out by scanning the heap. The qp-trie code was originally
 * designed to use malloc() and free(), so it has more information about
 * when garbage collection might be worthwhile. Hence we can trigger
 * collection when garbage passes a threshold.
 */
static inline bool
squash_twigs(dns_qp_t *qp, dns_qpref_t twigs, dns_qpweight_t size) {
	bool destroyed = free_twigs(qp, twigs, size);
	if (destroyed && QP_AUTOGC(qp)) {
		if (qp->transaction_mode == QP_NONE) {
			compact(qp);
		} else if (!qp->compact_stepped) {
			compact_step(qp);
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
			chunk_usage_bytes += qp->usage[chunk].capacity;
			memusage.chunk_count += 1;
		}
	}

	/*
	 * XXXFANF does not subtract chunks that have been shrunk,
	 * and does not count unreclaimed dns_qpbase_t objects
	 */
	memusage.bytes = chunk_usage_bytes +
			 qp->chunk_max * sizeof(qp->base->ptr[0]) +
			 qp->chunk_max * sizeof(qp->usage[0]);

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
dns_qp_gctime(isc_nanosecs_t *compact_p, isc_nanosecs_t *recycle_p) {
	*compact_p = atomic_load_relaxed(&compact_time);
	*recycle_p = atomic_load_relaxed(&recycle_time);
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
	 * Mark existing chunks as immutable by advancing the mutable
	 * generation. The bump chunk is special: in a series of write
	 * transactions the prefix up to fender is immutable, while the suffix
	 * stays mutable so the allocator can keep appending to it.
	 */
	INSIST(qp->generation < UINT64_MAX);
	qp->generation++;

	if (qp->write_protect) {
		for (dns_qpchunk_t chunk = 0; chunk < qp->chunk_max; chunk++) {
			if (qp->usage[chunk].exists) {
				write_protect(qp, chunk);
			}
		}
	}

	/*
	 * Ensure QP_AUTOGC() ignores free space in immutable chunks.
	 */
	qp->hold_count = qp->free_count;
	qp->compact_stepped = false;

	*qptp = qp;
	return qp;
}

/*
 * The first transaction on a trie has no bump chunk yet and allocates
 * one; after that a sequence of write transactions keeps the same bump
 * chunk and just puts `fender` at the point where this generation
 * started.
 */
void
dns_qpmulti_write(dns_qpmulti_t *multi, dns_qp_t **qptp) {
	dns_qp_t *qp = transaction_open(multi, qptp);
	TRACE("");

	if (qp->transaction_mode == QP_WRITE) {
		qp->fender = qp->usage[qp->bump].used;
	} else {
		alloc_reset(qp);
	}
	qp->transaction_mode = QP_WRITE;
}

void
dns_qpmulti_commit(dns_qpmulti_t *multi, dns_qp_t **qptp) {
	REQUIRE(QPMULTI_VALID(multi));
	REQUIRE(qptp != NULL && *qptp == &multi->writer);
	REQUIRE(multi->writer.transaction_mode == QP_WRITE);

	dns_qp_t *qp = *qptp;
	TRACE("");

	/* not the first commit? */
	if (multi->reader_ref != INVALID_REF) {
		INSIST(cells_immutable(qp, multi->reader_ref));
		free_twigs(qp, multi->reader_ref, READER_SIZE);
	}
	/* one bounded step of compaction, unless already taken */
	if (!qp->compact_stepped) {
		compact_step(qp);
	}
	multi->reader_ref = alloc_twigs(qp, READER_SIZE);

	/* anchor a new version of the trie */
	dns_qpnode_t *reader = ref_ptr(qp, multi->reader_ref);
	make_reader(reader, multi);
	/* paired with chunk_free() */
	isc_refcount_increment(&qp->base->refcount);

	rcu_assign_pointer(multi->reader, reader); /* COMMIT */

	/* clean up what we can right now */
	recycle(qp);

	/* schedule the rest for later */
	reclaim_chunks(multi);
	retire_dead(multi);

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
		QP_INIT(qp, multi->writer.methods, multi->writer.uctx);
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
	size_t bytes = sizeof(dns_qpsnap_t) + sizeof(dns_qpbase_t) +
		       sizeof(qpw->base->ptr[0]) * qpw->chunk_max;
	dns_qpsnap_t *qps = isc_mem_allocate(qpw->mctx, bytes);

	qps->whence = reader_open(multi, qps);
	INSIST(qps->whence == multi);
	qps->generation = qpw->generation;

	/* not a separate allocation */
	qps->base = (dns_qpbase_t *)(qps + 1);
	isc_refcount_init(&qps->base->refcount, 0);

	/*
	 * only copy base pointers of chunks we need, so we can
	 * reclaim unused memory in dns_qpsnap_destroy()
	 */
	qps->chunk_max = qpw->chunk_max;
	for (dns_qpchunk_t chunk = 0; chunk < qpw->chunk_max; chunk++) {
		if (qpw->usage[chunk].exists && chunk_usage(qpw, chunk) > 0) {
			qpw->usage[chunk].snapshot = true;
			qps->base->ptr[chunk] = qpw->base->ptr[chunk];
		} else {
			qps->base->ptr[chunk] = NULL;
		}
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

	/*
	 * eagerly reclaim chunks that are now unused, so that memory does
	 * not accumulate when a trie has a lot of updates and snapshots
	 */
	qp_release_t rel;
	qp_freechunk_t *batch = NULL;
	unsigned int nfree = marksweep_chunks(multi, &batch);

	/* and the deleted values this snapshot was holding back */
	qp_deadlist_t ready;
	ISC_LIST_INIT(ready);
	collect_dead(multi, &ready);

	release_context(&multi->writer, &rel);
	isc_mem_free(multi->writer.mctx, qp);

	*qpsp = NULL;
	UNLOCK(&multi->mutex);

	for (unsigned int i = 0; i < nfree; i++) {
		chunk_release(&rel, &batch[i]);
	}
	if (batch != NULL) {
		isc_mem_cput(rel.mctx, batch, nfree, sizeof(*batch));
	}
	release_dead(&rel, &ready);
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
	qp_init_writer(qp);
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
				  .reader_ref = INVALID_REF,
				  .references = ISC_REFCOUNT_INITIALIZER(1) };
	isc_mutex_init(&multi->mutex);
	ISC_LIST_INIT(multi->snapshots);
	ISC_LIST_INIT(multi->dead);

	/*
	 * The first write transaction allocates the bump chunk, see
	 * write_setup(), so there is no point in allocating one here.
	 */
	dns_qp_t *qp = &multi->writer;
	QP_INIT(qp, methods, uctx);
	qp_init_writer(qp);
	isc_mem_attach(mctx, &qp->mctx);
	TRACE("");
	*qpmp = multi;
}

static void
destroy_guts(dns_qp_t *qp) {
	compact_release_cursor(qp);
	INSIST(qp->dead == NULL);
	if (qp->chunk_max == 0) {
		return;
	}

	/* the live leaves hold the only references, one each */
	detach_all_leaves((dns_qpreader_t *)qp);
	qp->root_ref = INVALID_REF;

	for (dns_qpchunk_t chunk = 0; chunk < qp->chunk_max; chunk++) {
		if (qp->base->ptr[chunk] != NULL) {
			chunk_free(qp, chunk);
		}
	}
	qp->chunk_max = 0;
	ENSURE(qp->used_count == 0);
	ENSURE(qp->free_count == 0);
	ENSURE(isc_refcount_current(&qp->base->refcount) == 1);
	isc_mem_free(qp->mctx, qp->base);
	isc_mem_free(qp->mctx, qp->usage);
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

	/* reassure thread sanitizer */
	LOCK(&multi->mutex);
	dns_qp_t *qp = &multi->writer;
	/* every retirement unlinks itself before dropping its reference */
	INSIST(ISC_LIST_EMPTY(multi->dead));
	UNLOCK(&multi->mutex);

	isc_mutex_destroy(&multi->mutex);
	isc_mem_putanddetach(&qp->mctx, multi, sizeof(*multi));
}

#if QPMULTI_TRACE
ISC_REFCOUNT_STATIC_TRACE_IMPL(dns_qpmulti, qpmulti_free_mem)
#else
ISC_REFCOUNT_STATIC_IMPL(dns_qpmulti, qpmulti_free_mem)
#endif

static void
qpmulti_destroy_guts_cb(struct rcu_head *arg) {
	qp_rcuctx_t *rcuctx = caa_container_of(arg, qp_rcuctx_t, rcu_head);
	REQUIRE(QPRCU_VALID(rcuctx));
	/* only nonzero for reclaim_chunks_cb() */
	REQUIRE(rcuctx->count == 0);

	dns_qpmulti_t *multi = rcuctx->multi;
	REQUIRE(QPMULTI_VALID(multi));

	/* reassure thread sanitizer */
	LOCK(&multi->mutex);

	dns_qp_t *qp = &multi->writer;
	REQUIRE(QP_VALID(qp));

	/*
	 * Nothing can read any version now, so release the values that
	 * were still waiting for a grace period; the callbacks that have
	 * not run yet find nothing left to do.
	 */
	ISC_LIST_FOREACH(multi->dead, ctx, link) {
		ISC_LIST_UNLINK(multi->dead, ctx, link);
		for (uint32_t k = 0; k < ctx->count; k++) {
			qp->methods->detach(qp->uctx, ctx->leaf[k].pval,
					    ctx->leaf[k].ival);
		}
		if (ctx->grace) {
			deadctx_free(ctx);
		} else {
			ctx->released = true;
		}
	}

	destroy_guts(qp);

	UNLOCK(&multi->mutex);

	dns_qpmulti_detach(&multi);
	isc_mem_putanddetach(&rcuctx->mctx, rcuctx,
			     STRUCT_FLEX_SIZE(rcuctx, chunk, rcuctx->count));
}

void
dns_qpmulti_destroy(dns_qpmulti_t **qpmp) {
	dns_qp_t *qp = NULL;
	dns_qpmulti_t *multi = NULL;
	qp_rcuctx_t *rcuctx = NULL;

	REQUIRE(qpmp != NULL);
	REQUIRE(QPMULTI_VALID(*qpmp));

	multi = *qpmp;
	qp = &multi->writer;
	*qpmp = NULL;

	REQUIRE(QP_VALID(qp));
	REQUIRE(ISC_LIST_EMPTY(multi->snapshots));

	rcuctx = isc_mem_get(qp->mctx, STRUCT_FLEX_SIZE(rcuctx, chunk, 0));
	*rcuctx = (qp_rcuctx_t){
		.magic = QPRCU_MAGIC,
		.multi = multi,
	};
	isc_mem_attach(qp->mctx, &rcuctx->mctx);
	call_rcu(&rcuctx->rcu_head, qpmulti_destroy_guts_cb);
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

	/* the copied leaves keep their references either way */
	(void)squash_twigs(qp, old_ref, old_size);
	attach_leaf(qp, &new_leaf);
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
	retire_leaf(qp, n);
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
