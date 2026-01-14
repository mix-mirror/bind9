/* ==========================================================================
 * timeout.c - Tickless hierarchical timing wheel.
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
#include <errno.h>    /* errno */
#include <inttypes.h> /* UINT64_C uint64_t */
#include <limits.h>   /* CHAR_BIT */
#include <stddef.h>   /* NULL */
#include <stdio.h>    /* FILE fprintf(3) */
#include <string.h>   /* memset(3) */

#include <isc/bit.h>
#include <isc/list.h>
#include <isc/mem.h>
#include <isc/stdtime.h>
#include <isc/timeout.h>
#include <isc/util.h>

/*
 * B I T  M A N I P U L A T I O N  R O U T I N E S
 *
 * The macros and routines below implement wheel parameterization. The
 * inputs are:
 *
 *   WHEEL_BIT - The number of value bits mapped in each wheel. The
 *               lowest-order WHEEL_BIT bits index the lowest-order (highest
 *               resolution) wheel, the next group of WHEEL_BIT bits the
 *               higher wheel, etc.
 *
 *   WHEEL_NUM - The number of wheels. WHEEL_BIT * WHEEL_NUM = the number of
 *               value bits used by all the wheels. For the default of 6 and
 *               4, only the low 24 bits are processed. Any timeout value
 *               larger than this will cycle through again.
 *
 * The implementation uses bit fields to remember which slot in each wheel
 * is populated, and to generate masks of expiring slots according to the
 * current update interval (i.e. the "tickless" aspect). The slots to
 * process in a wheel are (populated-set & interval-mask).
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#define WHEEL_BIT 6

#if !defined WHEEL_NUM
#define WHEEL_NUM 4
#endif

#define WHEEL_LEN   (1U << WHEEL_BIT)
#define WHEEL_MAX   (WHEEL_LEN - 1)
#define WHEEL_MASK  (WHEEL_LEN - 1)
#define TIMEOUT_MAX ((ISC_STDTIME_C(1) << (WHEEL_BIT * WHEEL_NUM)) - 1)

#define WHEEL_C(n) UINT64_C(n)
#define WHEEL_PRIu PRIu64
#define WHEEL_PRIx PRIx64

typedef uint64_t wheel_t;

/*
 * T I M E R  R O U T I N E S
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

struct timeouts {
	isc_mem_t *mctx;

	timeout_list_t wheel[WHEEL_NUM][WHEEL_LEN], expired;

	wheel_t pending[WHEEL_NUM];

	isc_stdtime_t curtime;
};

void
timeouts_create(isc_mem_t *mctx, timeouts_t **timeoutsp) {
	REQUIRE(timeoutsp != NULL && *timeoutsp == NULL);

	timeouts_t *T = isc_mem_get(mctx, sizeof(*T));
	*T = (timeouts_t){
		.mctx = isc_mem_ref(mctx),
		.expired = ISC_LIST_INITIALIZER,
	};

	for (size_t i = 0; i < ARRAY_SIZE(T->wheel); i++) {
		for (size_t j = 0; j < ARRAY_SIZE(T->wheel[i]); j++) {
			ISC_LIST_INIT(T->wheel[i][j]);
		}
	}

	*timeoutsp = T;
}

static void
timeouts_reset(timeouts_t *T) {
	timeout_list_t reset = ISC_LIST_INITIALIZER;

	for (size_t i = 0; i < ARRAY_SIZE(T->wheel); i++) {
		for (size_t j = 0; j < ARRAY_SIZE(T->wheel[i]); j++) {
			ISC_LIST_APPENDLIST(reset, T->wheel[i][j], link);
		}
	}

	ISC_LIST_APPENDLIST(reset, T->expired, link);

	ISC_LIST_FOREACH(reset, to, link) {
		to->pending = NULL;
	}
}

void
timeouts_destroy(timeouts_t **timeoutsp) {
	REQUIRE(timeoutsp != NULL && *timeoutsp != NULL);
	timeouts_t *timeouts = *timeoutsp;
	*timeoutsp = NULL;

	/*
	 * NOTE: Delete installed timeouts so timeout_pending() and
	 * timeout_expired() worked as expected.
	 */
	timeouts_reset(timeouts);

	isc_mem_putanddetach(&timeouts->mctx, timeouts, sizeof(*timeouts));
}

bool
timeouts_del(timeouts_t *T, timeout_t *to) {
	if (!to->pending) {
		return false;
	}

	ISC_LIST_UNLINK(*(to->pending), to, link);

	if (to->pending != &T->expired && ISC_LIST_EMPTY(*to->pending)) {
		ptrdiff_t index = to->pending - &T->wheel[0][0];
		wheel_t wheel = index / WHEEL_LEN;
		int slot = index % WHEEL_LEN;

		T->pending[wheel] &= ~(WHEEL_C(1) << slot);
	}

	to->pending = NULL;

	return true;
}

static isc_stdtime_t
timeout_rem(timeouts_t *T, timeout_t *to) {
	return to->expires - T->curtime;
}

static int
timeout_wheel(isc_stdtime_t timeout) {
	/* must be called with timeout != 0, so fls input is nonzero */
	return (stdc_bit_width(ISC_MIN(timeout, TIMEOUT_MAX)) - 1) / WHEEL_BIT;
}

static int
timeout_slot(wheel_t wheel, isc_stdtime_t expires) {
	return WHEEL_MASK & ((expires >> (wheel * WHEEL_BIT)) - !!wheel);
}

static void
timeouts_sched(timeouts_t *T, timeout_t *to, isc_stdtime_t expires) {
	timeout_list_t *newpending = NULL;
	wheel_t newwheel = 0;
	int newslot = 0;

	/* Update expiration time */
	to->expires = expires;

	/* Calculate new position */
	if (expires > T->curtime) {
		isc_stdtime_t rem = timeout_rem(T, to);
		/* rem is nonzero since expires > T->curtime */
		newwheel = timeout_wheel(rem);
		newslot = timeout_slot(newwheel, to->expires);
		newpending = &T->wheel[newwheel][newslot];
	} else {
		newpending = &T->expired;
	}

	/* Fast path: if already in the correct slot, nothing to do */
	if (to->pending == newpending) {
		return;
	}

	/* Remove from old position if needed */
	timeouts_del(T, to);

	/* Insert into new position */
	to->pending = newpending;
	ISC_LIST_APPEND(*newpending, to, link);

	/* Update pending bitmask for wheel slots (not expired queue) */
	if (newpending != &T->expired) {
		T->pending[newwheel] |= WHEEL_C(1) << newslot;
	}
}

void
timeouts_add(timeouts_t *T, timeout_t *to, isc_stdtime_t timeout) {
	timeouts_sched(T, to, timeout);
}

void
timeouts_update(timeouts_t *T, isc_stdtime_t curtime) {
	isc_stdtime_t elapsed = curtime - T->curtime;
	timeout_list_t todo;

	if (elapsed == 0) {
		return;
	}

	ISC_LIST_INIT(todo);

	/*
	 * There's no avoiding looping over every wheel. It's best to keep
	 * WHEEL_NUM smallish.
	 */
	for (wheel_t wheel = 0; wheel < WHEEL_NUM; wheel++) {
		wheel_t pending;

		/*
		 * Calculate the slots expiring in this wheel
		 *
		 * If the elapsed time is greater than the maximum period of
		 * the wheel, mark every position as expiring.
		 *
		 * Otherwise, to determine the expired slots fill in all the
		 * bits between the last slot processed and the current
		 * slot, inclusive of the last slot. We'll bitwise-AND this
		 * with our pending set below.
		 *
		 * If a wheel rolls over, force a tick of the next higher
		 * wheel.
		 */
		if ((elapsed >> (wheel * WHEEL_BIT)) > WHEEL_MAX) {
			pending = (wheel_t)~WHEEL_C(0);
		} else {
			wheel_t _elapsed = WHEEL_MASK &
					   (elapsed >> (wheel * WHEEL_BIT));
			int oslot, nslot;

			/*
			 * TODO: It's likely that at least one of the
			 * following three bit fill operations is redundant
			 * or can be replaced with a simpler operation.
			 */
			oslot = WHEEL_MASK &
				(T->curtime >> (wheel * WHEEL_BIT));
			pending = ISC_ROTATE_LEFT((UINT64_C(1) << _elapsed) - 1,
						  oslot);

			nslot = WHEEL_MASK & (curtime >> (wheel * WHEEL_BIT));
			pending |= ISC_ROTATE_RIGHT(
				ISC_ROTATE_LEFT((WHEEL_C(1) << _elapsed) - 1,
						nslot),
				_elapsed);
			pending |= WHEEL_C(1) << nslot;
		}

		while (pending & T->pending[wheel]) {
			/* ctz input cannot be zero: loop condition. */
			int slot = stdc_trailing_zeros(pending &
						       T->pending[wheel]);
			ISC_LIST_APPENDLIST(todo, T->wheel[wheel][slot], link);
			T->pending[wheel] &= ~(UINT64_C(1) << slot);
		}

		if (!(0x1 & pending)) {
			break; /* break if we didn't wrap around end of wheel */
		}

		/* if we're continuing, the next wheel must tick at least once
		 */
		elapsed = ISC_MAX(elapsed, WHEEL_LEN << (wheel * WHEEL_BIT));
	}

	T->curtime = curtime;

	while (!ISC_LIST_EMPTY(todo)) {
		timeout_t *to = ISC_LIST_HEAD(todo);

		ISC_LIST_UNLINK(todo, to, link);
		to->pending = NULL;

		timeouts_sched(T, to, to->expires);
	}

	return;
}

void
timeouts_step(timeouts_t *T, isc_stdtime_t elapsed) {
	timeouts_update(T, T->curtime + elapsed);
}

bool
timeouts_pending(timeouts_t *T) {
	wheel_t pending = 0;
	int wheel;

	for (wheel = 0; wheel < WHEEL_NUM; wheel++) {
		pending |= T->pending[wheel];
	}

	return !!pending;
}

bool
timeouts_expired(timeouts_t *T) {
	return !ISC_LIST_EMPTY(T->expired);
}

/*
 * Calculate the interval before needing to process any timeouts pending on
 * any wheel.
 *
 * (This is separated from the public API routine so we can evaluate our
 * wheel invariant assertions irrespective of the expired queue.)
 *
 * This might return a timeout value sooner than any installed timeout if
 * only higher-order wheels have timeouts pending. We can only know when to
 * process a wheel, not precisely when a timeout is scheduled. Our timeout
 * accuracy could be off by 2^(N*M)-1 units where N is the wheel number and
 * M is WHEEL_BIT. Only timeouts which have fallen through to wheel 0 can be
 * known exactly.
 *
 * We should never return a timeout larger than the lowest actual timeout.
 */
static isc_stdtime_t
timeouts_int(timeouts_t *T) {
	isc_stdtime_t timeout = ~ISC_STDTIME_C(0), _timeout;
	isc_stdtime_t relmask;
	int wheel, slot;

	relmask = 0;

	for (wheel = 0; wheel < WHEEL_NUM; wheel++) {
		if (T->pending[wheel]) {
			slot = WHEEL_MASK & (T->curtime >> (wheel * WHEEL_BIT));

			/* ctz input cannot be zero: T->pending[wheel] is
			 * nonzero, so rotr() is nonzero. */
			_timeout = ((int)stdc_trailing_zeros(ISC_ROTATE_RIGHT(
					    T->pending[wheel], slot)) +
				    !!wheel)
				   << (wheel * WHEEL_BIT);
			/* +1 to higher order wheels as those timeouts are one
			 * rotation in the future (otherwise they'd be on a
			 * lower wheel or expired) */

			_timeout -= relmask & T->curtime;
			/* reduce by how much lower wheels have progressed */

			timeout = ISC_MIN(_timeout, timeout);
		}

		relmask <<= WHEEL_BIT;
		relmask |= WHEEL_MASK;
	}

	return timeout;
}

/*
 * Calculate the interval our caller can wait before needing to process
 * events.
 */
isc_stdtime_t
timeouts_timeout(timeouts_t *T) {
	if (!ISC_LIST_EMPTY(T->expired)) {
		return 0;
	}

	return timeouts_int(T);
}

timeout_t *
timeouts_get(timeouts_t *T) {
	if (!ISC_LIST_EMPTY(T->expired)) {
		timeout_t *to = ISC_LIST_HEAD(T->expired);

		ISC_LIST_UNLINK(T->expired, to, link);
		to->pending = NULL;

		return to;
	} else {
		return NULL;
	}
}

/*
 * Use dumb looping to locate the earliest timeout pending on the wheel so
 * our invariant assertions can check the result of our optimized code.
 */
static timeout_t *
timeouts_min(timeouts_t *T) {
	timeout_t *min = NULL;

	for (size_t i = 0; i < ARRAY_SIZE(T->wheel); i++) {
		for (size_t j = 0; j < ARRAY_SIZE(T->wheel[i]); j++) {
			ISC_LIST_FOREACH(T->wheel[i][j], to, link) {
				if (!min || to->expires < min->expires) {
					min = to;
				}
			}
		}
	}

	return min;
}

/*
 * Check some basic algorithm invariants. If these invariants fail then
 * something is definitely broken.
 */
#define report(...)                               \
	do {                                      \
		if ((fp))                         \
			fprintf(fp, __VA_ARGS__); \
	} while (0)

#define check(expr, ...)                     \
	do {                                 \
		if (!(expr)) {               \
			report(__VA_ARGS__); \
			return 0;            \
		}                            \
	} while (0)

bool
timeouts_check(timeouts_t *T, FILE *fp) {
	isc_stdtime_t timeout;
	timeout_t *to;

	if ((to = timeouts_min(T))) {
		check(to->expires > T->curtime,
		      "missed timeout (expires:%" ISC_STDTIME_PRIu
		      " <= curtime:%" ISC_STDTIME_PRIu ")\n",
		      to->expires, T->curtime);

		timeout = timeouts_int(T);
		check(timeout <= to->expires - T->curtime,
		      "wrong soft timeout (soft:%" ISC_STDTIME_PRIu
		      " > hard:%" ISC_STDTIME_PRIu
		      ") (expires:%" ISC_STDTIME_PRIu
		      "; curtime:%" ISC_STDTIME_PRIu ")\n",
		      timeout, to->expires - T->curtime, to->expires,
		      T->curtime);

		timeout = timeouts_timeout(T);
		check(timeout <= to->expires - T->curtime,
		      "wrong soft timeout (soft:%" ISC_STDTIME_PRIu
		      " > hard:%" ISC_STDTIME_PRIu
		      ") (expires:%" ISC_STDTIME_PRIu
		      "; curtime:%" ISC_STDTIME_PRIu ")\n",
		      timeout, to->expires - T->curtime, to->expires,
		      T->curtime);
	} else {
		timeout = timeouts_timeout(T);

		if (!ISC_LIST_EMPTY(T->expired)) {
			check(timeout == 0,
			      "wrong soft timeout (soft:%" ISC_STDTIME_PRIu
			      " != hard:%" ISC_STDTIME_PRIu ")\n",
			      timeout, ISC_STDTIME_C(0));
		} else {
			check(timeout == ~ISC_STDTIME_C(0),
			      "wrong soft timeout (soft:%" ISC_STDTIME_PRIu
			      " != hard:%" ISC_STDTIME_PRIu ")\n",
			      timeout, ~ISC_STDTIME_C(0));
		}
	}

	return 1;
} /* timeouts_check() */

#define ENTER                                    \
	do {                                     \
		static const int pc0 = __LINE__; \
		switch (pc0 + it->pc) {          \
		case __LINE__:                   \
			(void)0

#define SAVE_AND_DO(do_statement)        \
	do {                             \
		it->pc = __LINE__ - pc0; \
		do_statement;            \
	case __LINE__:                   \
		(void)0;                 \
	} while (0)

#define YIELD(rv) SAVE_AND_DO(return (rv))

#define LEAVE               \
	SAVE_AND_DO(break); \
	}                   \
	}                   \
	while (0)

timeout_t *
timeouts_next(timeouts_t *T, timeouts_it_t *it) {
	timeout_t *to;

	ENTER;

	if (it->flags & TIMEOUTS_EXPIRED) {
		if (it->flags & TIMEOUTS_CLEAR) {
			while ((to = timeouts_get(T)) != NULL) {
				YIELD(to);
			}
		} else {
			for (to = ISC_LIST_HEAD(T->expired);
			     to != NULL && (it->to = ISC_LIST_NEXT(to, link));
			     to = it->to)
			{
				YIELD(to);
			}
		}
	}

	if (it->flags & TIMEOUTS_PENDING) {
		for (it->i = 0; it->i < ARRAY_SIZE(T->wheel); it->i++) {
			for (it->j = 0; it->j < ARRAY_SIZE(T->wheel[it->i]);
			     it->j++)
			{
				for (to = ISC_LIST_HEAD(T->expired);
				     to != NULL &&
				     (it->to = ISC_LIST_NEXT(to, link));
				     to = it->to)
				{
					YIELD(to);
				}
			}
		}
	}

	LEAVE;

	return NULL;
} /* timeouts_next */

#undef LEAVE
#undef YIELD
#undef SAVE_AND_DO
#undef ENTER

/*
 * T I M E O U T  R O U T I N E S
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

timeout_t *
timeout_init(timeout_t *to) {
	*to = (timeout_t){
		.link = ISC_LINK_INITIALIZER,
	};

	return to;
}
