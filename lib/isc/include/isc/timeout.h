/* ==========================================================================
 * timeout.h - Tickless hierarchical timing wheel.
 * --------------------------------------------------------------------------
 * Copyright (c) 2013, 2014  William Ahern
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to permit
 * persons to whom the Software is furnished to do so, subject to the
 * following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
 * NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
 * DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
 * OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
 * USE OR OTHER DEALINGS IN THE SOFTWARE.
 * ==========================================================================
 */
#pragma once

#include <inttypes.h>  /* PRIu64 PRIx64 PRIX64 uint64_t */
#include <stdbool.h>   /* bool */
#include <stdio.h>     /* FILE */
#include <sys/queue.h> /* TAILQ(3) */

#include <isc/list.h>
#include <isc/mem.h>
#include <isc/stdtime.h>

/*
 * I N T E G E R  T Y P E  I N T E R F A C E S
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#define timeout_error_t int /* for documentation purposes */

/*
 * T I M E O U T  I N T E R F A C E S
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#define TIMEOUT_INITIALIZER { .link = ISC_LINK_INITIALIZER }

typedef ISC_LIST(struct timeout) timeout_list_t;
typedef struct timeouts timeouts_t;

typedef struct timeout timeout_t;
struct timeout {
	isc_stdtime_t expires;
	/* absolute expiration time */

	timeout_list_t *pending;
	/* timeout list if pending on wheel or expiry queue */

	ISC_LINK(timeout_t) link;
	/* entry member for struct timeout_list lists */
}; /* timeout_t */

timeout_t *
timeout_init(timeout_t *);
/* initialize timeout structure (same as TIMEOUT_INITIALIZER) */

/*
 * T I M I N G  W H E E L  I N T E R F A C E S
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

typedef struct timeouts timeouts_t;

void
timeouts_create(isc_mem_t *mctx, timeouts_t **);
/* create a new timing wheel */

void
timeouts_destroy(timeouts_t **);
/* destroy timing wheel */

void
timeouts_update(timeouts_t *, isc_stdtime_t);
/* update timing wheel with current absolute time */

void
timeouts_step(timeouts_t *, isc_stdtime_t);
/* step timing wheel by relative time */

isc_stdtime_t
timeouts_timeout(timeouts_t *);
/* return interval to next required update */

void
timeouts_add(timeouts_t *, timeout_t *, isc_stdtime_t);
/* add timeout to timing wheel */

void
timeouts_del(timeouts_t *, timeout_t *);
/* remove timeout from any timing wheel or expired queue (okay if on neither) */

timeout_t *
timeouts_get(timeouts_t *);
/* return any expired timeout (caller should loop until NULL-return) */

bool
timeouts_pending(timeouts_t *);
/* return true if any timeouts pending on timing wheel */

bool
timeouts_expired(timeouts_t *);
/* return true if any timeouts on expired queue */

bool
timeouts_check(timeouts_t *, FILE *);
/* return true if invariants hold. describes failures to optional file handle.
 */

#define TIMEOUTS_PENDING 0x10
#define TIMEOUTS_EXPIRED 0x20
#define TIMEOUTS_ALL	 (TIMEOUTS_PENDING | TIMEOUTS_EXPIRED)
#define TIMEOUTS_CLEAR	 0x40

#define TIMEOUTS_IT_INITIALIZER(flags) { (flags), 0, 0, 0, 0 }

#define TIMEOUTS_IT_INIT(cur, _flags)    \
	{                                \
		(cur)->flags = (_flags); \
		(cur)->pc = 0;           \
	}

typedef struct timeouts_it {
	int	   flags;
	unsigned   pc, i, j;
	timeout_t *to;
} timeouts_it_t;

timeout_t *
timeouts_next(timeouts_t *, timeouts_it_t *);
/* return next timeout in pending wheel or expired queue. caller can delete
 * the returned timeout, but should not otherwise manipulate the timing
 * wheel. in particular, caller SHOULD NOT delete any other timeout as that
 * could invalidate cursor state and trigger a use-after-free.
 */

#define TIMEOUTS_FOREACH(var, T, flags)                            \
	struct timeouts_it _it = TIMEOUTS_IT_INITIALIZER((flags)); \
	while (((var) = timeouts_next((T), &_it)))
