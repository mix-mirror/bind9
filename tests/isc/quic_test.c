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

/* ! \file */

#include <inttypes.h>
#include <sched.h>  /* IWYU pragma: keep */
#include <setjmp.h> /* IWYU pragma: keep */
#include <stdarg.h>
#include <stddef.h>
#include <stdlib.h> /* IWYU pragma: keep */
#include <string.h> /* IWYU pragma: keep */

#define UNIT_TESTING
#include <cmocka.h>

#include <isc/lib.h>
#include <isc/mem.h>
#include <isc/pause.h>
#include <isc/quic.h>
#include <isc/thread.h>
#include <isc/tid.h>
#include <isc/util.h>

#include <tests/isc.h>

typedef struct map_test_worker_state {
	isc_quic_cid_map_t *map;
	isc_quic_cid_t *cid[128];
} map_test_worker_state_t;

static void *
worker_map_test(void *arg) {
	map_test_worker_state_t *state = arg;
	isc_quic_cid_map_t *map = isc_quic_cid_map_ref(state->map);
	isc_quic_conn_t *conn = (void *)isc_g_mctx;
	isc_result_t result;

	for (size_t i = 0; i < ARRAY_SIZE(state->cid); i++) {
		state->cid[i] = isc_quic_cid_random_new(20, isc_g_mctx);

		result = isc_quic_cid_map_find(
			map, isc_quic_cid_bytes(state->cid[i]), NULL, NULL);
		assert_int_equal(result, ISC_R_NOTFOUND);

		result = isc_quic_cid_map_add(map, state->cid[i], conn);
		assert_int_equal(result, ISC_R_SUCCESS);

		result = isc_quic_cid_map_find(
			map, isc_quic_cid_bytes(state->cid[i]), NULL, NULL);
		assert_int_equal(result, ISC_R_SUCCESS);
	}

	isc_quic_cid_map_detach(&map);

	return NULL;
}

ISC_RUN_TEST_IMPL(isc_quic_cid_map) {
	isc_tid_t head, rest;
	isc_quic_cid_t *cid;
	isc_result_t result;

	isc_quic_cid_map_t *map = NULL;
	isc_quic_cid_map_create(isc_g_mctx, &map);

	map_test_worker_state_t *states = isc_mem_cget(isc_g_mctx, workers,
						       sizeof(*states));

	isc_thread_t *threads = isc_mem_cget(isc_g_mctx, workers,
					     sizeof(*threads));
	for (size_t i = 0; i < workers; i++) {
		states[i].map = map;
		isc_thread_create(worker_map_test, &states[i], &threads[i]);
	}
	for (size_t i = 0; i < workers; i++) {
		isc_thread_join(threads[i], NULL);
	}
	isc_mem_cput(isc_g_mctx, threads, workers, sizeof(*threads));

	for (size_t i = 0; i < workers; i++) {
		cid = states[i].cid[0];
		result = isc_quic_cid_map_find(map, isc_quic_cid_bytes(cid),
					       NULL, &head);
		assert_int_equal(result, ISC_R_SUCCESS);
		isc_quic_cid_destroy(isc_g_mctx, &cid);

		for (size_t j = 1; j < ARRAY_SIZE(states[0].cid); j++) {
			cid = states[i].cid[j];
			result = isc_quic_cid_map_find(
				map, isc_quic_cid_bytes(cid), NULL, &rest);
			assert_int_equal(result, ISC_R_SUCCESS);
			assert_int_equal(head, rest);

			isc_quic_cid_destroy(isc_g_mctx, &cid);
		}
	}

	isc_mem_cput(isc_g_mctx, states, workers, sizeof(*states));

	isc_quic_cid_map_detach(&map);
}

ISC_TEST_LIST_START
ISC_TEST_ENTRY(isc_quic_cid_map)
ISC_TEST_LIST_END

ISC_TEST_MAIN
