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

#include <inttypes.h>
#include <sched.h> /* IWYU pragma: keep */
#include <setjmp.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#ifdef HAVE_NET_ROUTE_H
#include <net/route.h>
#endif

#if defined(HAVE_LINUX_NETLINK_H) && defined(HAVE_LINUX_RTNETLINK_H)
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#endif

#define UNIT_TESTING
#include <cmocka.h>

#include <isc/loop.h>
#include <isc/netmgr.h>
#include <isc/time.h>
#include <isc/timer.h>
#include <isc/util.h>

#include <ns/interfacemgr.h>
#include <ns/server.h>

#include <tests/ns.h>

/*
 * The route socket is mocked: the test hands route_recv() whatever result
 * it likes and watches how the single-shot read gets re-armed.
 */
static ns_client_t route_handle;
static isc_nm_recv_cb_t route_recv_cb;
static void *route_recv_cbarg;
static unsigned int read_calls;
static unsigned int close_calls;

/*
 * The rescan timer is mocked as well.  The interface manager owns the only
 * isc_timer in this process, so the test can fire its callback by hand and
 * check exactly when it gets (re-)armed.
 */
static char timer_storage;
static isc_job_cb timer_cb;
static void *timer_cbarg;
static bool timer_running;
static isc_interval_t timer_interval;

isc_result_t
isc_nm_routeconnect(isc_nm_t *mgr, isc_nm_cb_t cb, void *cbarg) {
	assert_ptr_equal(mgr, netmgr);

	cb((isc_nmhandle_t *)&route_handle, ISC_R_SUCCESS, cbarg);
	return ISC_R_SUCCESS;
}

void
isc_nm_read(isc_nmhandle_t *handle, isc_nm_recv_cb_t cb, void *cbarg) {
	assert_ptr_equal(handle, &route_handle);
	/* A client read is single-shot; arming it twice is a bug. */
	assert_null(route_recv_cb);

	route_recv_cb = cb;
	route_recv_cbarg = cbarg;
	read_calls++;
}

/*
 * Deliver a read result the way the network manager would: the read is
 * consumed, and the callback has to arm a new one.
 */
static void
deliver(isc_result_t result, isc_region_t *region) {
	isc_nm_recv_cb_t cb = route_recv_cb;

	assert_non_null(cb);
	route_recv_cb = NULL;

	cb((isc_nmhandle_t *)&route_handle, result, region, route_recv_cbarg);
}

void
isc_nm_cancelread(isc_nmhandle_t *handle) {
	isc_region_t region = { 0 };

	assert_ptr_equal(handle, &route_handle);

	deliver(ISC_R_CANCELED, &region);
}

void
isc_nmhandle_close(isc_nmhandle_t *handle) {
	assert_ptr_equal(handle, &route_handle);
	close_calls++;
}

void
isc_timer_create(isc_loop_t *loop, isc_job_cb cb, void *cbarg,
		 isc_timer_t **timerp) {
	assert_ptr_equal(loop, mainloop);
	assert_null(timer_cb);
	assert_non_null(timerp);
	assert_null(*timerp);

	timer_cb = cb;
	timer_cbarg = cbarg;
	*timerp = (isc_timer_t *)(void *)&timer_storage;
}

void
isc_timer_start(isc_timer_t *timer, isc_timertype_t type,
		const isc_interval_t *interval) {
	assert_ptr_equal(timer, &timer_storage);
	assert_int_equal(type, isc_timertype_once);

	timer_running = true;
	timer_interval = *interval;
}

void
isc_timer_stop(isc_timer_t *timer) {
	assert_ptr_equal(timer, &timer_storage);

	timer_running = false;
}

void
isc_timer_destroy(isc_timer_t **timerp) {
	assert_non_null(timerp);
	assert_ptr_equal(*timerp, &timer_storage);

	*timerp = NULL;
	timer_cb = NULL;
	timer_running = false;
}

/*
 * Run the pending rescan.  Every rescan on the route socket path is
 * scheduled with a zero delay, i.e. for the next loop iteration.
 */
static void
fire_timer(void) {
	assert_true(timer_running);
	assert_int_equal(isc_interval_tonanosecs(&timer_interval), 0);

	timer_running = false;
	timer_cb(timer_cbarg);
}

/*
 * A route message that never needs a rescan by itself: a link state change.
 */
static isc_region_t
link_message(void) {
#if defined(HAVE_LINUX_NETLINK_H) && defined(HAVE_LINUX_RTNETLINK_H)
	static struct nlmsghdr msg = {
		.nlmsg_len = sizeof(struct nlmsghdr),
		.nlmsg_type = RTM_NEWLINK,
	};
#elif defined(RTM_VERSION)
	static struct rt_msghdr msg = {
		.rtm_msglen = sizeof(struct rt_msghdr),
		.rtm_version = RTM_VERSION,
		.rtm_type = RTM_IFINFO,
	};
#else
	static unsigned char msg = 0;
#endif

	return (isc_region_t){ .base = (unsigned char *)&msg,
			       .length = sizeof(msg) };
}

static void
check_shutdown(void *arg ISC_ATTR_UNUSED) {
	/*
	 * Shutting down cancelled the read, which released the route
	 * handle, and destroyed the timer.
	 */
	assert_int_equal(read_calls, 5);
	assert_int_equal(close_calls, 1);
	assert_null(route_recv_cb);
	assert_null(timer_cb);
	assert_false(timer_running);
	assert_int_equal(atomic_load(&client_refs[0]), 1);
}

ISC_LOOP_TEST_IMPL(route_overflow) {
	isc_region_t empty = { 0 };
	isc_region_t link = link_message();

	atomic_store(&client_addrs[0], (uintptr_t)&route_handle);
	atomic_store(&client_refs[0], 1);
	sctx->interface_auto = true;

	/* The timer was created along with the interface manager */
	assert_non_null(timer_cb);
	assert_false(timer_running);

	ns_interfacemgr_routeconnect(interfacemgr);
	assert_int_equal(read_calls, 1);
	assert_int_equal(close_calls, 0);

	/* A message that needs no rescan only re-arms the read */
	deliver(ISC_R_SUCCESS, &link);
	assert_int_equal(read_calls, 2);
	assert_false(timer_running);

	/* An overflow re-arms the read and schedules a rescan */
	deliver(ISC_R_NORESOURCES, &empty);
	assert_int_equal(read_calls, 3);
	assert_int_equal(close_calls, 0);
	assert_true(timer_running);

	/* The rescan stays armed while the backlog is being drained */
	fire_timer();
	assert_true(timer_running);

	/* While recovering, every message counts, even one needing no rescan */
	deliver(ISC_R_SUCCESS, &link);
	assert_int_equal(read_calls, 4);
	fire_timer();
	assert_true(timer_running);

	/* Nothing was read since the last rescan: the backlog is drained */
	fire_timer();
	assert_false(timer_running);

	/* Back to normal: the same message is ignored again */
	deliver(ISC_R_SUCCESS, &link);
	assert_int_equal(read_calls, 5);
	assert_false(timer_running);

	isc_loop_teardown(mainloop, shutdown_interfacemgr, NULL);
	isc_loop_teardown(mainloop, check_shutdown, NULL);
	isc_loopmgr_shutdown(loopmgr);
}

ISC_TEST_LIST_START
ISC_TEST_ENTRY_CUSTOM(route_overflow, setup_server, teardown_server)
ISC_TEST_LIST_END

ISC_TEST_MAIN
