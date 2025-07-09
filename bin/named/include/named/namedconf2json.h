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

typedef enum isc_result isc_result_t;
typedef struct cfg_obj cfg_obj_t;
typedef struct json_object json_object;

/*
 * Takes a valid root named configuration object and a non-NULL jconfig pointer
 * of pointer. Walks through the whole named configuration and generate an
 * equivalent JSON representation. Takes care of the allocations of json_object
 * but doesn't take any ownership so this is caller responsability to free it
 * using `json_object_put(*jconfig)`.
 */
isc_result_t
isc_namedconf2json(const cfg_obj_t *nconfig, json_object **jconfig);
