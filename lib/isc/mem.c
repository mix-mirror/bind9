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

#include <inttypes.h>
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <isc/atomic.h>
#include <isc/backtrace.h>
#include <isc/hash.h>
#include <isc/magic.h>
#include <isc/mem.h>
#include <isc/mutex.h>
#include <isc/os.h>
#include <isc/overflow.h>
#include <isc/random.h>
#include <isc/refcount.h>
#include <isc/stdtime.h>
#include <isc/strerr.h>
#include <isc/string.h>
#include <isc/tid.h>
#include <isc/types.h>
#include <isc/urcu.h>
#include <isc/util.h>
#include <isc/uv.h>

#ifdef HAVE_LIBXML2
#include <libxml/xmlwriter.h>
#define ISC_XMLCHAR (const xmlChar *)
#endif /* HAVE_LIBXML2 */

#ifdef HAVE_JSON_C
#include <json_object.h>
#endif /* HAVE_JSON_C */

/* On DragonFly BSD the header does not provide jemalloc API */
#if defined(HAVE_MALLOC_NP_H) && !defined(__DragonFly__)
#include <malloc_np.h>
#define JEMALLOC_API_SUPPORTED 1
#elif defined(HAVE_JEMALLOC)
#include <jemalloc/jemalloc.h>
#define JEMALLOC_API_SUPPORTED 1
#else
#if defined(__GLIBC__)
#include <malloc.h>
#endif
#include "jemalloc_shim.h"
#endif

#include "mem_p.h"

#define MCTXLOCK(m)   LOCK(&m->lock)
#define MCTXUNLOCK(m) UNLOCK(&m->lock)

volatile void *isc__mem_malloc = mallocx;

isc_mem_t *isc_g_mctx = NULL;

/*
 * Constants.
 */

#define ZERO_ALLOCATION_SIZE sizeof(void *)

#ifdef JEMALLOC_API_SUPPORTED
static ssize_t default_dirty_decay_ms = 10000;
#endif

/*
 * Types.
 */

typedef struct element element;
struct element {
	element *next;
};

#define MEM_MAGIC	 ISC_MAGIC('M', 'e', 'm', 'C')
#define VALID_CONTEXT(c) ISC_MAGIC_VALID(c, MEM_MAGIC)

/* List of all active memory contexts. */

static ISC_LIST(isc_mem_t) contexts;

static isc_mutex_t contextslock;

typedef union {
	struct {
		atomic_int_fast64_t inuse;
	};
	char padding[ISC_OS_CACHELINE_SIZE];
} isc__mem_stat_t;

struct isc_mem {
	unsigned int magic;
	unsigned int jemalloc_flags;
	isc_mutex_t lock;
	bool checkfree;
	isc_refcount_t references;
	char *name;
	atomic_size_t hi_water;
	atomic_size_t lo_water;
	ISC_LIST(isc_mempool_t) pools;
	unsigned int poolcnt;

	ISC_LINK(isc_mem_t) link;

	isc__mem_stat_t *stat;
	isc__mem_stat_t stat_s[ISC_TID_MAX + 1];
};

#define MEMPOOL_MAGIC	 ISC_MAGIC('M', 'E', 'M', 'p')
#define VALID_MEMPOOL(c) ISC_MAGIC_VALID(c, MEMPOOL_MAGIC)

struct isc_mempool {
	/* always unlocked */
	unsigned int magic;
	isc_mem_t *mctx;	      /*%< our memory context */
	ISC_LINK(isc_mempool_t) link; /*%< next pool in this mem context */
	element *items;		      /*%< low water item list */
	size_t size;		      /*%< size of each item on this pool */
	size_t allocated;	      /*%< # of items currently given out */
	size_t freecount;	      /*%< # of items on reserved list */
	size_t freemax;		      /*%< # of items allowed on free list */
	size_t fillcount;	      /*%< # of items to fetch on each fill */
	/*%< Stats only. */
	size_t gets; /*%< # of requests to this pool */
	/*%< Debugging only. */
	char *name; /*%< printed name in stats reports */
};

/*
 * Private Inline-able.
 */

static size_t
total_inuse(void) {
	size_t inuse = 0;
	LOCK(&contextslock);
	ISC_LIST_FOREACH(contexts, ctx, link) {
		inuse += isc_mem_inuse(ctx);
	}
	UNLOCK(&contextslock);

	return inuse;
}

static void
write_string(int fd, const char *str) {
	int r = write(fd, str, strlen(str));
	if (r == -1) {
		abort();
	}
}

#define STRINGIFY(x) #x
#define TOSTRING(x)  STRINGIFY(x)
static void
write_size(int fd, size_t size) {
	char buf[sizeof(TOSTRING(SIZE_MAX)) + 1] = { 0 };

	char *str = buf + (sizeof(buf) - 1);

	if (size == 0) {
		*--str = '0';
	} else {
		while (size) {
			*--str = '0' + (size % 10);
			size /= 10;
		}
	}

	write_string(fd, str);
}

static void
write_errno(int fd, int errnum) {
	char buf[BUFSIZ] = { 0 };
	int ret = isc_string_strerror_r(errnum, buf, sizeof(buf));
	if (ret == 0) {
		write_string(fd, buf);
	}
}

static void
write_backtrace(int fd) {
	void *tracebuf[ISC_BACKTRACE_MAXFRAME];
	int nframes = isc_backtrace(tracebuf, ISC_BACKTRACE_MAXFRAME);

	if (nframes > 0) {
		isc_backtrace_symbols_fd(tracebuf, nframes, fd);
	}
}

#define CHECK_OOM(ptr, size) (void)((ptr != NULL) || (oom(size), false))

ISC_NORETURN static void
oom(size_t size) {
	int fd = fileno(stderr);
	write_string(fd, "Out of memory (trying to allocate ");
	write_size(fd, size);
	write_string(fd, ", total ");
	write_size(fd, total_inuse());
	write_string(fd, "): ");
	write_errno(fd, errno);
	write_string(fd, "\n");
	write_backtrace(fd);

	abort();
}

#define ADJUST_ZERO_ALLOCATION_SIZE(s)    \
	if (s == 0) {                     \
		s = ZERO_ALLOCATION_SIZE; \
	}

/*!
 * Perform a malloc, doing memory filling and overrun detection as necessary.
 */
static void *
mem_get(isc_mem_t *ctx, size_t size, int flags) {
	ADJUST_ZERO_ALLOCATION_SIZE(size);

	void *ptr = mallocx(size, flags | ctx->jemalloc_flags);
	CHECK_OOM(ptr, size);

	return ptr;
}

static thread_local size_t freed_bytes = 0;

constexpr size_t purge_threshold = (16 * 1024 * 1024);

#if defined(JEMALLOC_API_SUPPORTED) || defined(__GLIBC__)

static _Atomic(isc_stdtime_t) last_purge = 0;

static void
mem_purge(void) {
	isc_stdtime_t now = isc_stdtime_now();
	isc_stdtime_t last = atomic_load_relaxed(&last_purge);

	if (now > last &&
	    atomic_compare_exchange_strong_acq_rel(&last_purge, &last, now))
	{
#if defined(JEMALLOC_API_SUPPORTED)
		(void)mallctl("arena." STRINGIFY(MALLCTL_ARENAS_ALL) ".decay",
			      NULL, NULL, NULL, 0);
#elif defined(__GLIBC__)
		(void)malloc_trim(0);
#endif
	}
}

#else
static void
mem_purge(void) {
	/* no-op */
}

#endif

/*!
 * Perform a free, doing memory filling and overrun detection as necessary.
 */
static void
mem_put(isc_mem_t *ctx, void *mem, size_t size, int flags) {
	ADJUST_ZERO_ALLOCATION_SIZE(size);

	sdallocx(mem, size, flags | ctx->jemalloc_flags);

	freed_bytes += size;

	if (freed_bytes >= purge_threshold) {
		freed_bytes = 0;
		mem_purge();
	}
}

static void *
mem_realloc(isc_mem_t *ctx, void *old_ptr, size_t new_size, int flags) {
	void *new_ptr = NULL;

	ADJUST_ZERO_ALLOCATION_SIZE(new_size);

	new_ptr = rallocx(old_ptr, new_size, flags | ctx->jemalloc_flags);
	CHECK_OOM(new_ptr, new_size);

	return new_ptr;
}

/*!
 * Update internal counters after a memory get.
 */
static void
mem_getstats(isc_mem_t *ctx, size_t size) {
	atomic_fetch_add_relaxed(&ctx->stat[isc_tid()].inuse, size);
}

/*!
 * Update internal counters after a memory put.
 */
static void
mem_putstats(isc_mem_t *ctx, size_t size) {
	atomic_fetch_sub_relaxed(&ctx->stat[isc_tid()].inuse, size);
}

/*
 * Private.
 */

void
isc__mem_initialize(void) {
	/*
	 * Check if the values copied from jemalloc still match; the
	 * shim defines the MALLOCX_* macros too, so this holds on
	 * every allocator path.
	 */
	RUNTIME_CHECK(ISC_MEM_ZERO == MALLOCX_ZERO);
	RUNTIME_CHECK(ISC_MEM_ALIGN(sizeof(void *)) ==
		      MALLOCX_ALIGN(sizeof(void *)));
	RUNTIME_CHECK(ISC_MEM_ALIGN(ISC_OS_CACHELINE_SIZE) ==
		      MALLOCX_ALIGN(ISC_OS_CACHELINE_SIZE));

#ifdef JEMALLOC_API_SUPPORTED
	/*
	 * ignore errors — volumetric-based purge in mem_put handles the rest
	 * regardless
	 */

	(void)mallctl("background_thread", NULL, NULL, &(bool){ true },
		      sizeof(bool));

	(void)mallctl("arenas.dirty_decay_ms", NULL, NULL,
		      &default_dirty_decay_ms, sizeof(default_dirty_decay_ms));

	(void)mallctl("arena." STRINGIFY(MALLCTL_ARENAS_ALL) ".dirty_decay_ms",
		      NULL, NULL, &default_dirty_decay_ms,
		      sizeof(default_dirty_decay_ms));

#endif /* JEMALLOC_API_SUPPORTED */

	isc_mutex_init(&contextslock);
	ISC_LIST_INIT(contexts);

	isc_mem_create("default", &isc_g_mctx);
}

void
isc__mem_shutdown(void) {
	bool empty;

	rcu_barrier();

	isc_mem_detach(&isc_g_mctx);

	isc__mem_checkdestroyed();

	LOCK(&contextslock);
	empty = ISC_LIST_EMPTY(contexts);
	UNLOCK(&contextslock);

	if (empty) {
		isc_mutex_destroy(&contextslock);
	}
}

static void
mem_create(const char *name, isc_mem_t **ctxp, unsigned int jemalloc_flags) {
	isc_mem_t *ctx = NULL;

	REQUIRE(ctxp != NULL && *ctxp == NULL);
	REQUIRE(name != NULL);

	ctx = mallocx(sizeof(*ctx),
		      jemalloc_flags | ISC_MEM_ALIGN(isc_os_cacheline()));
	CHECK_OOM(ctx, sizeof(*ctx));

	*ctx = (isc_mem_t){
		.magic = MEM_MAGIC,
		.jemalloc_flags = jemalloc_flags,
		.checkfree = true,
		.name = strdup(name),
	};

	isc_mutex_init(&ctx->lock);
	isc_refcount_init(&ctx->references, 1);

	for (size_t i = 0; i < ARRAY_SIZE(ctx->stat_s); i++) {
		atomic_init(&ctx->stat_s[i].inuse, 0);
	}

	/* Reserve the [-1] index for ISC_TID_UNKNOWN */
	ctx->stat = &ctx->stat_s[1];

	atomic_init(&ctx->hi_water, 0);
	atomic_init(&ctx->lo_water, 0);

	ISC_LIST_INIT(ctx->pools);

	LOCK(&contextslock);
	ISC_LIST_INITANDAPPEND(contexts, ctx, link);
	UNLOCK(&contextslock);

	*ctxp = ctx;
}

/*
 * Public.
 */

static void
mem_destroy(isc_mem_t *ctx) {
	REQUIRE(VALID_CONTEXT(ctx));

	isc_refcount_destroy(&ctx->references);

	LOCK(&contextslock);
	ISC_LIST_UNLINK(contexts, ctx, link);
	UNLOCK(&contextslock);

	if (ctx->checkfree) {
		INSIST(isc_mem_inuse(ctx) == 0);
	}

	ctx->magic = 0;

	INSIST(ISC_LIST_EMPTY(ctx->pools));

	free(ctx->name);

	isc_mutex_destroy(&ctx->lock);

	sdallocx(ctx, sizeof(*ctx),
		 ctx->jemalloc_flags | ISC_MEM_ALIGN(isc_os_cacheline()));
}

#if ISC_MEM_TRACE
ISC_REFCOUNT_TRACE_IMPL(isc_mem, mem_destroy);
#else
ISC_REFCOUNT_IMPL(isc_mem, mem_destroy);
#endif

/*
 * isc_mem_putanddetach() is the equivalent of:
 *
 * mctx = NULL;
 * isc_mem_attach(ptr->mctx, &mctx);
 * isc_mem_detach(&ptr->mctx);
 * isc_mem_put(mctx, ptr, sizeof(*ptr);
 * isc_mem_detach(&mctx);
 */

void
isc__mem_putanddetach(isc_mem_t **ctxp, void *ptr, size_t size, int flags) {
	REQUIRE(ctxp != NULL && VALID_CONTEXT(*ctxp));
	REQUIRE(ptr != NULL);
	REQUIRE(size != 0);

	isc_mem_t *ctx = *ctxp;
	*ctxp = NULL;

	isc__mem_put(ctx, ptr, size, flags);
#if ISC_MEM_TRACE
	isc_mem__detach(&ctx, func, file, line);
#else
	isc_mem_detach(&ctx);
#endif
}

void *
isc__mem_get(isc_mem_t *ctx, size_t size, int flags) {
	void *ptr = NULL;

	REQUIRE(VALID_CONTEXT(ctx));

	ptr = mem_get(ctx, size, flags);

	mem_getstats(ctx, size);

	return ptr;
}

void
isc__mem_put(isc_mem_t *ctx, void *ptr, size_t size, int flags) {
	REQUIRE(VALID_CONTEXT(ctx));

	mem_putstats(ctx, size);
	mem_put(ctx, ptr, size, flags);
}

/*
 * Print the stats[] on the stream "out" with suitable formatting.
 */
void
isc_mem_stats(isc_mem_t *ctx, FILE *out) {
	REQUIRE(VALID_CONTEXT(ctx));

	MCTXLOCK(ctx);

	/*
	 * Note that since a pool can be locked now, these stats might
	 * be somewhat off if the pool is in active use at the time the
	 * stats are dumped.  The link fields are protected by the
	 * isc_mem_t's lock, however, so walking this list and
	 * extracting integers from stats fields is always safe.
	 */
	if (!ISC_LIST_EMPTY(ctx->pools)) {
		fprintf(out, "[Pool statistics]\n");
		fprintf(out, "%15s %10s %10s %10s %10s %10s %10s %1s\n", "name",
			"size", "allocated", "freecount", "freemax",
			"fillcount", "gets", "L");
	}
	ISC_LIST_FOREACH(ctx->pools, pool, link) {
		fprintf(out,
			"%15s %10zu %10zu %10zu %10zu %10zu %10zu %10zu %s\n",
			pool->name, pool->size, (size_t)0, pool->allocated,
			pool->freecount, pool->freemax, pool->fillcount,
			pool->gets, "N");
	}

	MCTXUNLOCK(ctx);
}

void *
isc__mem_allocate(isc_mem_t *ctx, size_t size, int flags) {
	void *ptr = NULL;

	REQUIRE(VALID_CONTEXT(ctx));

	ptr = mem_get(ctx, size, flags);

	/* Recalculate the real allocated size */
	size = sallocx(ptr, flags | ctx->jemalloc_flags);

	mem_getstats(ctx, size);

	return ptr;
}

void *
isc__mem_reget(isc_mem_t *ctx, void *old_ptr, size_t old_size, size_t new_size,
	       int flags) {
	void *new_ptr = NULL;

	if (old_ptr == NULL) {
		REQUIRE(old_size == 0);
		new_ptr = isc__mem_get(ctx, new_size, flags);
	} else if (new_size == 0) {
		isc__mem_put(ctx, old_ptr, old_size, flags);
	} else {
		mem_putstats(ctx, old_size);

		ADJUST_ZERO_ALLOCATION_SIZE(new_size);

		new_ptr = mem_realloc(ctx, old_ptr, new_size, flags);

		mem_getstats(ctx, new_size);

		/*
		 * We want to postpone the call to water in edge case
		 * where the realloc will exactly hit on the boundary of
		 * the water and we would call water twice.
		 */
	}

	return new_ptr;
}

void *
isc__mem_reallocate(isc_mem_t *ctx, void *old_ptr, size_t new_size, int flags) {
	void *new_ptr = NULL;

	REQUIRE(VALID_CONTEXT(ctx));

	if (old_ptr == NULL) {
		new_ptr = isc__mem_allocate(ctx, new_size, flags);
	} else if (new_size == 0) {
		isc__mem_free(ctx, old_ptr, flags);
	} else {
		size_t size = sallocx(old_ptr, flags | ctx->jemalloc_flags);

		mem_putstats(ctx, size);

		new_ptr = mem_realloc(ctx, old_ptr, new_size, flags);

		/* Recalculate the real allocated size */
		size = sallocx(new_ptr, flags | ctx->jemalloc_flags);

		mem_getstats(ctx, size);
	}

	return new_ptr;
}

void
isc__mem_free(isc_mem_t *ctx, void *ptr, int flags) {
	size_t size = 0;

	REQUIRE(VALID_CONTEXT(ctx));
	REQUIRE(ptr != NULL);

	size = sallocx(ptr, flags | ctx->jemalloc_flags);

	mem_putstats(ctx, size);
	mem_put(ctx, ptr, size, flags);
}

/*
 * Other useful things.
 */

char *
isc__mem_strdup(isc_mem_t *mctx, const char *s) {
	size_t len;
	char *ns = NULL;

	REQUIRE(VALID_CONTEXT(mctx));
	REQUIRE(s != NULL);

	len = strlen(s) + 1;

	ns = isc__mem_allocate(mctx, len, 0);

	strlcpy(ns, s, len);

	return ns;
}

void
isc_mem_setdestroycheck(isc_mem_t *ctx, bool flag) {
	REQUIRE(VALID_CONTEXT(ctx));

	MCTXLOCK(ctx);

	ctx->checkfree = flag;

	MCTXUNLOCK(ctx);
}

size_t
isc_mem_inuse(isc_mem_t *ctx) {
	REQUIRE(VALID_CONTEXT(ctx));

	int_fast64_t inuse = 0;

	for (ssize_t i = -1; i < isc_tid_count(); i++) {
		inuse += atomic_load_relaxed(&ctx->stat[i].inuse);
	}
	INSIST(inuse >= 0);

	return (size_t)inuse;
}

void
isc_mem_clearwater(isc_mem_t *mctx) {
	isc_mem_setwater(mctx, 0, 0);
}

void
isc_mem_setwater(isc_mem_t *ctx, size_t hiwater, size_t lowater) {
	REQUIRE(VALID_CONTEXT(ctx));
	REQUIRE(hiwater >= lowater);

	atomic_store_release(&ctx->hi_water, hiwater);
	atomic_store_release(&ctx->lo_water, lowater);

	return;
}

bool
isc_mem_isovermem(isc_mem_t *ctx) {
	REQUIRE(VALID_CONTEXT(ctx));

	size_t hiwater = atomic_load_relaxed(&ctx->hi_water);
	if (hiwater == 0) {
		return false;
	}

	size_t inuse = isc_mem_inuse(ctx);
	if (inuse >= hiwater) {
		return true;
	}

	size_t lowater = atomic_load_relaxed(&ctx->lo_water);
	if (inuse <= lowater) {
		return false;
	}

	/*
	 * Between lo_water and hi_water, return true with a probability
	 * that ramps linearly from 0 at lo_water to 1 at hi_water.  This
	 * spreads cache cleaning across many inserts instead of triggering
	 * a thundering herd once the hi_water mark is crossed.
	 */
	uint32_t prob = (uint32_t)(((uint64_t)(inuse - lowater) * 256) /
				   (hiwater - lowater));
	return isc_random8() < prob;
}

const char *
isc_mem_getname(isc_mem_t *ctx) {
	REQUIRE(VALID_CONTEXT(ctx));

	if (ctx->name[0] == 0) {
		return "";
	}

	return ctx->name;
}

/*
 * Memory pool stuff
 */

void
isc__mempool_create(isc_mem_t *restrict mctx, const size_t element_size,
		    const char *name, isc_mempool_t **restrict mpctxp) {
	isc_mempool_t *restrict mpctx = NULL;
	size_t size = element_size;

	REQUIRE(VALID_CONTEXT(mctx));
	REQUIRE(size > 0U);
	REQUIRE(mpctxp != NULL && *mpctxp == NULL);
	REQUIRE(name != NULL);

	/*
	 * Mempools are stored as a linked list of element.
	 */
	if (size < sizeof(element)) {
		size = sizeof(element);
	}

	/*
	 * Allocate space for this pool, initialize values, and if all
	 * works well, attach to the memory context.
	 */
	mpctx = isc_mem_get(mctx, sizeof(isc_mempool_t));

	*mpctx = (isc_mempool_t){
		.size = size,
		.freemax = 1,
		.fillcount = 1,
		.name = strdup(name),
	};

	isc_mem_attach(mctx, &mpctx->mctx);
	mpctx->magic = MEMPOOL_MAGIC;

	*mpctxp = (isc_mempool_t *)mpctx;

	MCTXLOCK(mctx);
	ISC_LIST_INITANDAPPEND(mctx->pools, mpctx, link);
	mctx->poolcnt++;
	MCTXUNLOCK(mctx);
}

void
isc__mempool_destroy(isc_mempool_t **restrict mpctxp) {
	isc_mempool_t *restrict mpctx = NULL;
	isc_mem_t *mctx = NULL;
	element *restrict item = NULL;

	REQUIRE(mpctxp != NULL);
	REQUIRE(VALID_MEMPOOL(*mpctxp));

	mpctx = *mpctxp;
	*mpctxp = NULL;

	mctx = mpctx->mctx;

	if (mpctx->allocated > 0) {
		UNEXPECTED_ERROR("mempool %s leaked memory", mpctx->name);
	}
	REQUIRE(mpctx->allocated == 0);

	/*
	 * Return any items on the free list
	 */
	while (mpctx->items != NULL) {
		INSIST(mpctx->freecount > 0);
		mpctx->freecount--;

		item = mpctx->items;
		mpctx->items = item->next;

		mem_putstats(mctx, mpctx->size);
		mem_put(mctx, item, mpctx->size, 0);
	}

	/*
	 * Remove our linked list entry from the memory context.
	 */
	MCTXLOCK(mctx);
	ISC_LIST_UNLINK(mctx->pools, mpctx, link);
	mctx->poolcnt--;
	MCTXUNLOCK(mctx);

	free(mpctx->name);

	mpctx->magic = 0;

	isc_mem_putanddetach(&mpctx->mctx, mpctx, sizeof(isc_mempool_t));
}

void *
isc__mempool_get(isc_mempool_t *restrict mpctx) {
	element *restrict item = NULL;

	REQUIRE(VALID_MEMPOOL(mpctx));

	mpctx->allocated++;

	if (mpctx->items == NULL) {
		isc_mem_t *mctx = mpctx->mctx;
#if !__SANITIZE_ADDRESS__
		const size_t fillcount = mpctx->fillcount;
#else
		const size_t fillcount = 1;
#endif
		/*
		 * We need to dip into the well.  Fill up our free list.
		 */
		for (size_t i = 0; i < fillcount; i++) {
			item = mem_get(mctx, mpctx->size, 0);
			mem_getstats(mctx, mpctx->size);
			item->next = mpctx->items;
			mpctx->items = item;
			mpctx->freecount++;
		}
	}

	INSIST(mpctx->items != NULL);
	item = mpctx->items;

	mpctx->items = item->next;

	INSIST(mpctx->freecount > 0);
	mpctx->freecount--;
	mpctx->gets++;

	return item;
}

void
isc__mempool_put(isc_mempool_t *restrict mpctx, void *mem) {
	element *restrict item = NULL;

	REQUIRE(VALID_MEMPOOL(mpctx));
	REQUIRE(mem != NULL);

	isc_mem_t *mctx = mpctx->mctx;
	const size_t freecount = mpctx->freecount;
#if !__SANITIZE_ADDRESS__
	const size_t freemax = mpctx->freemax;
#else
	const size_t freemax = 0;
#endif

	INSIST(mpctx->allocated > 0);
	mpctx->allocated--;

	/*
	 * If our free list is full, return this to the mctx directly.
	 */
	if (freecount >= freemax) {
		mem_putstats(mctx, mpctx->size);
		mem_put(mctx, mem, mpctx->size, 0);
		return;
	}

	/*
	 * Otherwise, attach it to our free list and bump the counter.
	 */
	item = (element *)mem;
	item->next = mpctx->items;
	mpctx->items = item;
	mpctx->freecount++;
}

/*
 * Quotas
 */

void
isc_mempool_setfreemax(isc_mempool_t *restrict mpctx,
		       const unsigned int limit) {
	REQUIRE(VALID_MEMPOOL(mpctx));
	mpctx->freemax = limit;
}

unsigned int
isc_mempool_getfreemax(isc_mempool_t *restrict mpctx) {
	REQUIRE(VALID_MEMPOOL(mpctx));

	return mpctx->freemax;
}

unsigned int
isc_mempool_getfreecount(isc_mempool_t *restrict mpctx) {
	REQUIRE(VALID_MEMPOOL(mpctx));

	return mpctx->freecount;
}

unsigned int
isc_mempool_getallocated(isc_mempool_t *restrict mpctx) {
	REQUIRE(VALID_MEMPOOL(mpctx));

	return mpctx->allocated;
}

void
isc_mempool_setfillcount(isc_mempool_t *restrict mpctx,
			 unsigned int const limit) {
	REQUIRE(VALID_MEMPOOL(mpctx));
	REQUIRE(limit > 0);

	mpctx->fillcount = limit;
}

unsigned int
isc_mempool_getfillcount(isc_mempool_t *restrict mpctx) {
	REQUIRE(VALID_MEMPOOL(mpctx));

	return mpctx->fillcount;
}

static atomic_uintptr_t checkdestroyed = 0;

void
isc_mem_checkdestroyed(FILE *file) {
	atomic_store_release(&checkdestroyed, (uintptr_t)file);
}

void
isc__mem_checkdestroyed(void) {
	FILE *file = (FILE *)atomic_load_acquire(&checkdestroyed);

	if (file == NULL) {
		return;
	}

	LOCK(&contextslock);
	INSIST(ISC_LIST_EMPTY(contexts));
	UNLOCK(&contextslock);
}

unsigned int
isc_mem_references(isc_mem_t *ctx) {
	return isc_refcount_current(&ctx->references);
}

#ifdef HAVE_LIBXML2
#define TRY0(a)                     \
	do {                        \
		xmlrc = (a);        \
		if (xmlrc < 0)      \
			goto error; \
	} while (0)
static int
xml_renderctx(isc_mem_t *ctx, size_t *inuse, xmlTextWriterPtr writer) {
	REQUIRE(VALID_CONTEXT(ctx));

	int xmlrc;

	MCTXLOCK(ctx);

	TRY0(xmlTextWriterStartElement(writer, ISC_XMLCHAR "context"));

	TRY0(xmlTextWriterStartElement(writer, ISC_XMLCHAR "id"));
	TRY0(xmlTextWriterWriteFormatString(writer, "%p", ctx));
	TRY0(xmlTextWriterEndElement(writer)); /* id */

	if (ctx->name[0] != 0) {
		TRY0(xmlTextWriterStartElement(writer, ISC_XMLCHAR "name"));
		TRY0(xmlTextWriterWriteFormatString(writer, "%s", ctx->name));
		TRY0(xmlTextWriterEndElement(writer)); /* name */
	}

	TRY0(xmlTextWriterStartElement(writer, ISC_XMLCHAR "references"));
	TRY0(xmlTextWriterWriteFormatString(
		writer, "%" PRIuFAST32,
		isc_refcount_current(&ctx->references)));
	TRY0(xmlTextWriterEndElement(writer)); /* references */

	*inuse += isc_mem_inuse(ctx);
	TRY0(xmlTextWriterStartElement(writer, ISC_XMLCHAR "inuse"));
	TRY0(xmlTextWriterWriteFormatString(writer, "%" PRIu64 "",
					    (uint64_t)isc_mem_inuse(ctx)));
	TRY0(xmlTextWriterEndElement(writer)); /* inuse */

	TRY0(xmlTextWriterStartElement(writer, ISC_XMLCHAR "malloced"));
	TRY0(xmlTextWriterWriteFormatString(writer, "%" PRIu64 "",
					    (uint64_t)isc_mem_inuse(ctx)));
	TRY0(xmlTextWriterEndElement(writer)); /* malloced */

	TRY0(xmlTextWriterStartElement(writer, ISC_XMLCHAR "pools"));
	TRY0(xmlTextWriterWriteFormatString(writer, "%u", ctx->poolcnt));
	TRY0(xmlTextWriterEndElement(writer)); /* pools */

	TRY0(xmlTextWriterStartElement(writer, ISC_XMLCHAR "hiwater"));
	TRY0(xmlTextWriterWriteFormatString(
		writer, "%" PRIu64 "",
		(uint64_t)atomic_load_relaxed(&ctx->hi_water)));
	TRY0(xmlTextWriterEndElement(writer)); /* hiwater */

	TRY0(xmlTextWriterStartElement(writer, ISC_XMLCHAR "lowater"));
	TRY0(xmlTextWriterWriteFormatString(
		writer, "%" PRIu64 "",
		(uint64_t)atomic_load_relaxed(&ctx->lo_water)));
	TRY0(xmlTextWriterEndElement(writer)); /* lowater */

	TRY0(xmlTextWriterEndElement(writer)); /* context */

error:
	MCTXUNLOCK(ctx);

	return xmlrc;
}

int
isc_mem_renderxml(void *writer0) {
	size_t inuse = 0;
	int xmlrc;
	xmlTextWriterPtr writer = (xmlTextWriterPtr)writer0;

	TRY0(xmlTextWriterStartElement(writer, ISC_XMLCHAR "contexts"));

	LOCK(&contextslock);
	ISC_LIST_FOREACH(contexts, ctx, link) {
		xmlrc = xml_renderctx(ctx, &inuse, writer);
		if (xmlrc < 0) {
			UNLOCK(&contextslock);
			goto error;
		}
	}
	UNLOCK(&contextslock);

	TRY0(xmlTextWriterEndElement(writer)); /* contexts */

	TRY0(xmlTextWriterStartElement(writer, ISC_XMLCHAR "summary"));

	TRY0(xmlTextWriterStartElement(writer, ISC_XMLCHAR "Malloced"));
	TRY0(xmlTextWriterWriteFormatString(writer, "%" PRIu64 "",
					    (uint64_t)inuse));
	TRY0(xmlTextWriterEndElement(writer)); /* malloced */

	TRY0(xmlTextWriterStartElement(writer, ISC_XMLCHAR "InUse"));
	TRY0(xmlTextWriterWriteFormatString(writer, "%" PRIu64 "",
					    (uint64_t)inuse));
	TRY0(xmlTextWriterEndElement(writer)); /* InUse */

	TRY0(xmlTextWriterEndElement(writer)); /* summary */
error:
	return xmlrc;
}

#endif /* HAVE_LIBXML2 */

#ifdef HAVE_JSON_C
#define CHECKMEM(m) RUNTIME_CHECK(m != NULL)

static isc_result_t
json_renderctx(isc_mem_t *ctx, size_t *inuse, json_object *array) {
	REQUIRE(VALID_CONTEXT(ctx));
	REQUIRE(array != NULL);

	json_object *ctxobj, *obj;
	char buf[1024];

	MCTXLOCK(ctx);

	*inuse += isc_mem_inuse(ctx);

	ctxobj = json_object_new_object();
	CHECKMEM(ctxobj);

	snprintf(buf, sizeof(buf), "%p", ctx);
	obj = json_object_new_string(buf);
	CHECKMEM(obj);
	json_object_object_add(ctxobj, "id", obj);

	if (ctx->name[0] != 0) {
		obj = json_object_new_string(ctx->name);
		CHECKMEM(obj);
		json_object_object_add(ctxobj, "name", obj);
	}

	obj = json_object_new_int64(isc_refcount_current(&ctx->references));
	CHECKMEM(obj);
	json_object_object_add(ctxobj, "references", obj);

	obj = json_object_new_int64(isc_mem_inuse(ctx));
	CHECKMEM(obj);
	json_object_object_add(ctxobj, "malloced", obj);

	obj = json_object_new_int64(isc_mem_inuse(ctx));
	CHECKMEM(obj);
	json_object_object_add(ctxobj, "inuse", obj);

	obj = json_object_new_int64(ctx->poolcnt);
	CHECKMEM(obj);
	json_object_object_add(ctxobj, "pools", obj);

	obj = json_object_new_int64(atomic_load_relaxed(&ctx->hi_water));
	CHECKMEM(obj);
	json_object_object_add(ctxobj, "hiwater", obj);

	obj = json_object_new_int64(atomic_load_relaxed(&ctx->lo_water));
	CHECKMEM(obj);
	json_object_object_add(ctxobj, "lowater", obj);

	MCTXUNLOCK(ctx);
	json_object_array_add(array, ctxobj);
	return ISC_R_SUCCESS;
}

isc_result_t
isc_mem_renderjson(void *memobj0) {
	isc_result_t result = ISC_R_SUCCESS;
	size_t inuse = 0;
	json_object *ctxarray, *obj;
	json_object *memobj = (json_object *)memobj0;

	ctxarray = json_object_new_array();
	CHECKMEM(ctxarray);

	LOCK(&contextslock);
	ISC_LIST_FOREACH(contexts, ctx, link) {
		result = json_renderctx(ctx, &inuse, ctxarray);
		if (result != ISC_R_SUCCESS) {
			UNLOCK(&contextslock);
			goto error;
		}
	}
	UNLOCK(&contextslock);

	obj = json_object_new_int64(inuse);
	CHECKMEM(obj);
	json_object_object_add(memobj, "InUse", obj);

	obj = json_object_new_int64(inuse);
	CHECKMEM(obj);
	json_object_object_add(memobj, "Malloced", obj);

	json_object_object_add(memobj, "contexts", ctxarray);
	return ISC_R_SUCCESS;

error:
	if (ctxarray != NULL) {
		json_object_put(ctxarray);
	}
	return result;
}
#endif /* HAVE_JSON_C */

void
isc__mem_create(const char *name, isc_mem_t **mctxp) {
	mem_create(name, mctxp, 0);
}
