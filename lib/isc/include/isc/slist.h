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

/*! \file isc/slist.h
 * \brief
 * Implements macros for singly-linked lists.
 *
 * This module provides a generic implementation of singly-linked lists
 * similar to isc/list.h but optimized for forward-only traversal.
 */

#define ISC_SLIST_INITIALIZER \
	{                     \
		.head = NULL, \
	}

#define ISC_SLINK_INITIALIZER \
	{                     \
		.next = NULL, \
	}

#define ISC_SLIST(type)     \
	struct {            \
		type *head; \
	}

#define ISC_SLINK(type)     \
	struct {            \
		type *next; \
	}

#define ISC_SLIST_HEAD(list)  ((list).head)
#define ISC_SLIST_EMPTY(list) ((list).head == NULL)

#define ISC_SLIST_PREPEND(list, elt, link)      \
	({                                      \
		(elt)->link.next = (list).head; \
		(list).head = (elt);            \
	})

#define ISC_SLIST_INSERTAFTER(after, elt, link)        \
	({                                             \
		(elt)->link.next = (after)->link.next; \
		(after)->link.next = (elt);            \
	})

#define ISC_SLIST_NEXT(elt, link) ((elt)->link.next)

/* clang-format off */
#define ISC_SLIST_FOREACH_FROM(elt, list, link, first)                      \
	for (typeof(first) elt = first,                                      \
	     elt##_next = (elt != NULL) ? ISC_SLIST_NEXT(elt, link) : NULL; \
	     elt != NULL;                                                   \
	     elt = elt##_next,                                              \
	      elt##_next = (elt != NULL) ? ISC_SLIST_NEXT(elt, link) : NULL)

#define ISC_SLIST_FOREACH(elt, list, link) \
	ISC_SLIST_FOREACH_FROM(elt, list, link, ISC_SLIST_HEAD(list))

/* clang-format on */

/* Iteration over pointer-to-pointer for safe operations */
#define ISC_SLIST_FOREACH_PTR(p, head) \
	for (typeof(head) p = (head); *p != NULL;)

#define ISC_SLIST_PTR_REMOVE(p, elt, link_field) \
	(*(p) = ISC_SLIST_NEXT(elt, link_field))

#define ISC_SLIST_PTR_ADVANCE(p, link_field) \
	(p = &ISC_SLIST_NEXT(*p, link_field))
