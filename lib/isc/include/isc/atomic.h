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

#pragma once

#include <stdatomic.h>

#include <isc/util.h>

/*
 * We define a few additional macros to make things easier
 */

/* Relaxed Memory Ordering */

#define atomic_store_relaxed(o, v) \
	atomic_store_explicit((o), (v), memory_order_relaxed)
#define atomic_load_relaxed(o) atomic_load_explicit((o), memory_order_relaxed)
#define atomic_fetch_add_relaxed(o, v) \
	atomic_fetch_add_explicit((o), (v), memory_order_relaxed)
#define atomic_fetch_sub_relaxed(o, v) \
	atomic_fetch_sub_explicit((o), (v), memory_order_relaxed)
#define atomic_fetch_or_relaxed(o, v) \
	atomic_fetch_or_explicit((o), (v), memory_order_relaxed)
#define atomic_fetch_and_relaxed(o, v) \
	atomic_fetch_and_explicit((o), (v), memory_order_relaxed)
#define atomic_exchange_relaxed(o, v) \
	atomic_exchange_explicit((o), (v), memory_order_relaxed)
#define atomic_compare_exchange_weak_relaxed(o, e, d) \
	atomic_compare_exchange_weak_explicit(        \
		(o), (e), (d), memory_order_relaxed, memory_order_relaxed)
#define atomic_compare_exchange_strong_relaxed(o, e, d) \
	atomic_compare_exchange_strong_explicit(        \
		(o), (e), (d), memory_order_relaxed, memory_order_relaxed)

/* Acquire-Release Memory Ordering */

#define atomic_store_release(o, v) \
	atomic_store_explicit((o), (v), memory_order_release)
#define atomic_load_acquire(o) atomic_load_explicit((o), memory_order_acquire)
#define atomic_fetch_add_release(o, v) \
	atomic_fetch_add_explicit((o), (v), memory_order_release)
#define atomic_fetch_sub_release(o, v) \
	atomic_fetch_sub_explicit((o), (v), memory_order_release)
#define atomic_fetch_and_release(o, v) \
	atomic_fetch_and_explicit((o), (v), memory_order_release)
#define atomic_fetch_or_release(o, v) \
	atomic_fetch_or_explicit((o), (v), memory_order_release)
#define atomic_exchange_acquire(o, v) \
	atomic_exchange_explicit((o), (v), memory_order_acquire)
#define atomic_exchange_acq_rel(o, v) \
	atomic_exchange_explicit((o), (v), memory_order_acq_rel)
#define atomic_fetch_add_acq_rel(o, v) \
	atomic_fetch_add_explicit((o), (v), memory_order_acq_rel)
#define atomic_fetch_sub_acq_rel(o, v) \
	atomic_fetch_sub_explicit((o), (v), memory_order_acq_rel)
#define atomic_fetch_and_acq_rel(o, v) \
	atomic_fetch_and_explicit((o), (v), memory_order_acq_rel)
#define atomic_fetch_or_acq_rel(o, v) \
	atomic_fetch_or_explicit((o), (v), memory_order_acq_rel)
#define atomic_compare_exchange_weak_acq_rel(o, e, d) \
	atomic_compare_exchange_weak_explicit(        \
		(o), (e), (d), memory_order_acq_rel, memory_order_acquire)
#define atomic_compare_exchange_strong_acq_rel(o, e, d) \
	atomic_compare_exchange_strong_explicit(        \
		(o), (e), (d), memory_order_acq_rel, memory_order_acquire)

/* compare/exchange that MUST succeed */
#define atomic_compare_exchange_enforced(o, e, d) \
	RUNTIME_CHECK(atomic_compare_exchange_strong_acq_rel((o), (e), (d)))

/* more comfortable atomic pointer declarations */
#define atomic_ptr(type) _Atomic(type *)

/*
 * Usage of the default seq_cst memory ordering is discouraged as it also
 * establish a single total modification order of all atomic operations that are
 * so tagged and that is never needed.
 *
 * From https://mara.nl/atomics/memory-ordering.html as Mara has a talent to
 * explain this much better:
 *
 * Sequentially Consistent Ordering
 *
 * The strongest memory ordering is sequentially consistent ordering:
 * Ordering::SeqCst. It includes all the guarantees of acquire ordering (for
 * loads) and release ordering (for stores), and also guarantees a globally
 * consistent order of operations.
 *
 * This means that every single operation using SeqCst ordering within a program
 * is part of a single total order that all threads agree on. This total order
 * is consistent with the total modification order of each individual variable.
 *
 * Since it is strictly stronger than acquire and release memory ordering, a
 * sequentially consistent load or store can take the place of an acquire-load
 * or release-store in a release-acquire pair to form a happens-before
 * relationship. In other words, an acquire-load can not only form a
 * happens-before relationship with a release-store, but also with a
 * sequentially consistent store, and similarly the other way around.
 *
 * Only when both sides of a happens-before relationship use SeqCst ordering is
 * it guaranteed to be consistent with the single total order of SeqCst
 * operations. While it might seem like the easiest memory ordering to reason
 * about, SeqCst ordering is almost never necessary in practice. In nearly all
 * cases, regular acquire and release ordering suffice.
 */

#ifndef ISC_ATOMIC_ALLOW_IMPLICIT_ORDERING
#define assert_on_implicit_ordering \
	STATIC_ASSERT(0,            \
		      "Implicit Sequentially Consistent Ordering disallowed.")
#else
#define assert_on_implicit_ordering
#endif

#undef atomic_store
#define atomic_store(obj, desired)                                         \
	{                                                                  \
		assert_on_implicit_ordering;                               \
		atomic_store_explicit(obj, desired, memory_order_seq_cst); \
	}

#undef atomic_load
#define atomic_load(obj)                                         \
	{                                                        \
		assert_on_implicit_ordering;                     \
		atomic_load_explicit(obj, memory_order_seq_cst); \
	}

#undef atomic_exchange
#define atomic_exchange(obj, desired)                                         \
	{                                                                     \
		assert_on_implicit_ordering;                                  \
		atomic_exchange_explicit(obj, desired, memory_order_seq_cst); \
	}

#undef atomic_compare_exchange_strong
#define atomic_compare_exchange_strong(obj, expected, desired)         \
	{                                                              \
		assert_on_implicit_ordering;                           \
		atomic_compare_exchange_strong_explicit(               \
			obj, expected, desired, memory_order_seq_cst); \
	}

#undef atomic_compare_exchange_weak
#define atomic_compare_exchange_weak(obj, expected, desired)                  \
	{                                                                     \
		assert_on_implicit_ordering;                                  \
		atomic_compare_exchange_weak_explicit(obj, expected, desired, \
						      memory_order_seq_cst);  \
	}

#undef atomic_fetch_add
#define atomic_fetch_add(obj, arg)                                         \
	{                                                                  \
		assert_on_implicit_ordering;                               \
		atomic_fetch_add_explicit(obj, arg, memory_order_seq_cst); \
	}

#undef atomic_fetch_sub
#define atomic_fetch_sub(obj, arg)                                         \
	{                                                                  \
		assert_on_implicit_ordering;                               \
		atomic_fetch_sub_explicit(obj, arg, memory_order_seq_cst); \
	}

#undef atomic_fetch_or
#define atomic_fetch_or(obj, arg)                                         \
	{                                                                 \
		assert_on_implicit_ordering;                              \
		atomic_fetch_or_explicit(obj, arg, memory_order_seq_cst); \
	}

#undef atomic_fetch_xor
#define atomic_fetch_xor(obj, arg)                                         \
	{                                                                  \
		assert_on_implicit_ordering;                               \
		atomic_fetch_xor_explicit(obj, arg, memory_order_seq_cst); \
	}

#undef atomic_fetch_and
#define atomic_fetch_and(obj, arg)                                         \
	{                                                                  \
		assert_on_implicit_ordering;                               \
		atomic_fetch_and_explicit(obj, arg, memory_order_seq_cst); \
	}

#undef atomic_flag_test_and_set
#define atomic_flag_test_and_set(obj)                                         \
	{                                                                     \
		assert_on_implicit_ordering;                                  \
		atomic_flag_test_and_set_explicit(obj, memory_order_seq_cst); \
	}

#undef atomic_flag_clear
#define atomic_flag_clear(obj)                                         \
	{                                                              \
		assert_on_implicit_ordering;                           \
		atomic_flag_clear_explicit(obj, memory_order_seq_cst); \
	}
