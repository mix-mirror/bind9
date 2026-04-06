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

#include <assert.h>
#include <inttypes.h>
#include <unistd.h>

#include <isc/async.h>
#include <isc/atomic.h>
#include <isc/backtrace.h>
#include <isc/barrier.h>
#include <isc/buffer.h>
#include <isc/errno.h>
#include <isc/job.h>
#include <isc/list.h>
#include <isc/log.h>
#include <isc/loop.h>
#include <isc/magic.h>
#include <isc/mem.h>
#include <isc/netaddr.h>
#include <isc/netmgr.h>
#include <isc/quota.h>
#include <isc/random.h>
#include <isc/refcount.h>
#include <isc/region.h>
#include <isc/result.h>
#include <isc/sockaddr.h>
#include <isc/stats.h>
#include <isc/strerr.h>
#include <isc/thread.h>
#include <isc/tid.h>
#include <isc/tls.h>
#include <isc/util.h>
#include <isc/uv.h>

#include "../loop_p.h"
#include "../openssl_shim.h"
#include "netmgr-int.h"

isc__netmgr_t *isc__netmgr = NULL;

/*%
 * Shortcut index arrays to get access to statistics counters.
 */

static const isc_statscounter_t udp4statsindex[] = {
	isc_sockstatscounter_udp4open,
	isc_sockstatscounter_udp4openfail,
	isc_sockstatscounter_udp4close,
	isc_sockstatscounter_udp4bindfail,
	isc_sockstatscounter_udp4connectfail,
	isc_sockstatscounter_udp4connect,
	-1,
	-1,
	isc_sockstatscounter_udp4sendfail,
	isc_sockstatscounter_udp4recvfail,
	isc_sockstatscounter_udp4active,
	-1,
};

static const isc_statscounter_t udp6statsindex[] = {
	isc_sockstatscounter_udp6open,
	isc_sockstatscounter_udp6openfail,
	isc_sockstatscounter_udp6close,
	isc_sockstatscounter_udp6bindfail,
	isc_sockstatscounter_udp6connectfail,
	isc_sockstatscounter_udp6connect,
	-1,
	-1,
	isc_sockstatscounter_udp6sendfail,
	isc_sockstatscounter_udp6recvfail,
	isc_sockstatscounter_udp6active,
	-1,
};

static const isc_statscounter_t tcp4statsindex[] = {
	isc_sockstatscounter_tcp4open,	      isc_sockstatscounter_tcp4openfail,
	isc_sockstatscounter_tcp4close,	      isc_sockstatscounter_tcp4bindfail,
	isc_sockstatscounter_tcp4connectfail, isc_sockstatscounter_tcp4connect,
	isc_sockstatscounter_tcp4acceptfail,  isc_sockstatscounter_tcp4accept,
	isc_sockstatscounter_tcp4sendfail,    isc_sockstatscounter_tcp4recvfail,
	isc_sockstatscounter_tcp4active,      isc_sockstatscounter_tcp4clients,
};

static const isc_statscounter_t tcp6statsindex[] = {
	isc_sockstatscounter_tcp6open,	      isc_sockstatscounter_tcp6openfail,
	isc_sockstatscounter_tcp6close,	      isc_sockstatscounter_tcp6bindfail,
	isc_sockstatscounter_tcp6connectfail, isc_sockstatscounter_tcp6connect,
	isc_sockstatscounter_tcp6acceptfail,  isc_sockstatscounter_tcp6accept,
	isc_sockstatscounter_tcp6sendfail,    isc_sockstatscounter_tcp6recvfail,
	isc_sockstatscounter_tcp6active,      isc_sockstatscounter_tcp6clients,
};

static void
nmsocket_maybe_destroy(isc_nmsocket_t *sock FLARG);
static void
nmhandle_free(isc_nmsocket_t *sock, isc_nmhandle_t *handle);

/*%<
 * Issue a 'handle closed' callback on the socket.
 */

static void
shutdown_walk_cb(uv_handle_t *handle, void *arg);

static void
networker_teardown(void *arg) {
	isc__networker_t *worker = arg;
	isc_loop_t *loop = worker->loop;

	worker->shuttingdown = true;

	isc__netmgr_log(
		ISC_LOG_DEBUG(1),
		"Shutting down network manager worker on loop %p(%" PRItid ")",
		loop, isc_tid());

	uv_walk(&loop->loop, shutdown_walk_cb, NULL);

	isc__networker_detach(&worker);
}

static void
netmgr_teardown(void *arg ISC_ATTR_UNUSED) {
	if (atomic_compare_exchange_strong_acq_rel(&isc__netmgr->shuttingdown,
						   &(bool){ false }, true))
	{
		isc__netmgr_log(ISC_LOG_DEBUG(1),
				"Shutting down network manager");
	}
}

#if HAVE_DECL_UV_UDP_LINUX_RECVERR
#define MINIMAL_UV_VERSION UV_VERSION(1, 42, 0)
#elif HAVE_DECL_UV_UDP_MMSG_FREE
#define MINIMAL_UV_VERSION UV_VERSION(1, 40, 0)
#elif HAVE_DECL_UV_UDP_RECVMMSG
#define MAXIMAL_UV_VERSION UV_VERSION(1, 39, 99)
#define MINIMAL_UV_VERSION UV_VERSION(1, 37, 0)
#else
#define MAXIMAL_UV_VERSION UV_VERSION(1, 34, 99)
#define MINIMAL_UV_VERSION UV_VERSION(1, 34, 0)
#endif

void
isc_netmgr_create(isc_mem_t *mctx) {
	isc__netmgr_t *netmgr = NULL;
	in_port_t port_low, port_high;

#ifdef MAXIMAL_UV_VERSION
	if (uv_version() > MAXIMAL_UV_VERSION) {
		FATAL_ERROR("libuv version too new: running with libuv %s "
			    "when compiled with libuv %s will lead to "
			    "libuv failures",
			    uv_version_string(), UV_VERSION_STRING);
	}
#endif /* MAXIMAL_UV_VERSION */

	if (uv_version() < MINIMAL_UV_VERSION) {
		FATAL_ERROR("libuv version too old: running with libuv %s "
			    "when compiled with libuv %s will lead to "
			    "libuv failures",
			    uv_version_string(), UV_VERSION_STRING);
	}

	netmgr = isc_mem_get(mctx, sizeof(*netmgr));
	*netmgr = (isc__netmgr_t){
		.nloops = isc_loopmgr_nloops(),
	};

	isc_mem_attach(mctx, &netmgr->mctx);
	isc_refcount_init(&netmgr->references, 1);
	atomic_init(&netmgr->maxudp, 0);
	atomic_init(&netmgr->shuttingdown, false);
	atomic_init(&netmgr->recv_tcp_buffer_size, 0);
	atomic_init(&netmgr->send_tcp_buffer_size, 0);
	atomic_init(&netmgr->recv_udp_buffer_size, 0);
	atomic_init(&netmgr->send_udp_buffer_size, 0);
	atomic_init(&netmgr->port_low4, 0);
	atomic_init(&netmgr->port_high4, 65535);
	atomic_init(&netmgr->port_low6, 0);
	atomic_init(&netmgr->port_high6, 65535);

#if HAVE_SO_REUSEPORT_LB
	netmgr->load_balance_sockets = true;
#else
	netmgr->load_balance_sockets = false;
#endif

	/*
	 * Default TCP timeout values.
	 * May be updated by isc_nm_tcptimeouts().
	 */
	atomic_init(&netmgr->init, 30000);
	atomic_init(&netmgr->idle, 30000);
	atomic_init(&netmgr->keepalive, 30000);
	atomic_init(&netmgr->advertised, 30000);
	atomic_init(&netmgr->primaries, 30000);

	netmgr->workers = isc_mem_cget(mctx, netmgr->nloops,
				       sizeof(netmgr->workers[0]));

	isc_loopmgr_teardown(netmgr_teardown, netmgr);

	netmgr->magic = NM_MAGIC;

	for (size_t i = 0; i < netmgr->nloops; i++) {
		isc_loop_t *loop = isc_loop_get(i);
		isc__networker_t *worker = &netmgr->workers[i];

		*worker = (isc__networker_t){
			.recvbuf = isc_mem_get(loop->mctx,
					       ISC_NETMGR_RECVBUF_SIZE),
			.active_sockets = ISC_LIST_INITIALIZER,
		};

		isc__netmgr_ref(netmgr);

		isc_mem_attach(loop->mctx, &worker->mctx);

		isc_mempool_create(worker->mctx, sizeof(isc_nmsocket_t),
				   "nmsocket_pool", &worker->nmsocket_pool);
		isc_mempool_setfreemax(worker->nmsocket_pool,
				       ISC_NM_NMSOCKET_MAX);

		isc_mempool_create(worker->mctx, ISC_NMSOCKET_UDP_SIZE,
				   "nmsocket_pool_udp",
				   &worker->nmsocket_pool_udp);
		isc_mempool_setfreemax(worker->nmsocket_pool_udp,
				       ISC_NM_NMSOCKET_MAX);

		isc_mempool_create(worker->mctx, ISC_NMSOCKET_OVERLAY_SIZE,
				   "nmsocket_pool_overlay",
				   &worker->nmsocket_pool_overlay);
		isc_mempool_setfreemax(worker->nmsocket_pool_overlay,
				       ISC_NM_NMSOCKET_MAX);

		isc_mempool_create(worker->mctx, sizeof(isc__nm_uvreq_t),
				   "uvreq_pool", &worker->uvreq_pool);
		isc_mempool_setfreemax(worker->uvreq_pool, ISC_NM_UVREQS_MAX);

		isc_loop_attach(loop, &worker->loop);
		isc_loop_teardown(loop, networker_teardown, worker);
		isc_refcount_init(&worker->references, 1);
	}

	isc__netmgr = netmgr;

	/*
	 * Set the initial port range for IP_LOCAL_PORT_RANGE.
	 */
	isc_net_getportrange(AF_INET, &port_low, &port_high);
	isc_netmgr_portrange(AF_INET, port_low, port_high);

	isc_net_getportrange(AF_INET6, &port_low, &port_high);
	isc_netmgr_portrange(AF_INET6, port_low, port_high);
}

/*
 * Free the resources of the network manager.
 */
static void
netmgr_destroy(isc__netmgr_t *netmgr) {
	REQUIRE(VALID_NM(netmgr));

	isc_refcount_destroy(&netmgr->references);

	netmgr->magic = 0;

	if (netmgr->stats != NULL) {
		isc_stats_detach(&netmgr->stats);
	}

	isc_mem_cput(netmgr->mctx, netmgr->workers, netmgr->nloops,
		     sizeof(netmgr->workers[0]));
	isc_mem_putanddetach(&netmgr->mctx, netmgr, sizeof(*netmgr));
}

#if ISC_NETMGR_TRACE
ISC_REFCOUNT_TRACE_IMPL(isc__netmgr, netmgr_destroy)
#else
ISC_REFCOUNT_IMPL(isc__netmgr, netmgr_destroy);
#endif

void
isc_netmgr_destroy(void) {
	isc__netmgr_detach(&isc__netmgr);
}

void
isc_nm_maxudp(uint32_t maxudp) {
	REQUIRE(VALID_NM(isc__netmgr));

	atomic_store_relaxed(&isc__netmgr->maxudp, maxudp);
}

void
isc_nmhandle_setwritetimeout(isc_nmhandle_t *handle, uint64_t write_timeout) {
	REQUIRE(VALID_NMHANDLE(handle));
	REQUIRE(VALID_NMSOCK(handle->sock));
	REQUIRE(handle->sock->tid == isc_tid());

	if (handle->sock->ops->setwritetimeout != NULL) {
		handle->sock->ops->setwritetimeout(handle, write_timeout);
	}
}

void
isc_nm_setinitialtimeout(uint32_t timeout_ms) {
	REQUIRE(VALID_NM(isc__netmgr));

	atomic_store_relaxed(&isc__netmgr->init, timeout_ms);
}

void
isc_nm_setprimariestimeout(uint32_t timeout_ms) {
	REQUIRE(VALID_NM(isc__netmgr));

	atomic_store_relaxed(&isc__netmgr->primaries, timeout_ms);
}

void
isc_nm_setidletimeout(uint32_t timeout_ms) {
	REQUIRE(VALID_NM(isc__netmgr));

	atomic_store_relaxed(&isc__netmgr->idle, timeout_ms);
}

void
isc_nm_setkeepalivetimeout(uint32_t timeout_ms) {
	REQUIRE(VALID_NM(isc__netmgr));

	atomic_store_relaxed(&isc__netmgr->keepalive, timeout_ms);
}

void
isc_nm_setadvertisedtimeout(uint32_t timeout_ms) {
	REQUIRE(VALID_NM(isc__netmgr));

	atomic_store_relaxed(&isc__netmgr->advertised, timeout_ms);
}

void
isc_nm_setnetbuffers(int32_t recv_tcp, int32_t send_tcp, int32_t recv_udp,
		     int32_t send_udp) {
	REQUIRE(VALID_NM(isc__netmgr));

	atomic_store_relaxed(&isc__netmgr->recv_tcp_buffer_size, recv_tcp);
	atomic_store_relaxed(&isc__netmgr->send_tcp_buffer_size, send_tcp);
	atomic_store_relaxed(&isc__netmgr->recv_udp_buffer_size, recv_udp);
	atomic_store_relaxed(&isc__netmgr->send_udp_buffer_size, send_udp);
}

bool
isc_nm_getloadbalancesockets(void) {
	REQUIRE(VALID_NM(isc__netmgr));

	return isc__netmgr->load_balance_sockets;
}

void
isc_nm_setloadbalancesockets(ISC_ATTR_UNUSED bool enabled) {
	REQUIRE(VALID_NM(isc__netmgr));

#if HAVE_SO_REUSEPORT_LB
	isc__netmgr->load_balance_sockets = enabled;
#endif
}

uint32_t
isc_nm_getinitialtimeout(void) {
	REQUIRE(VALID_NM(isc__netmgr));

	return atomic_load_relaxed(&isc__netmgr->init);
}

uint32_t
isc_nm_getprimariestimeout(void) {
	REQUIRE(VALID_NM(isc__netmgr));

	return atomic_load_relaxed(&isc__netmgr->primaries);
}

uint32_t
isc_nm_getidletimeout(void) {
	REQUIRE(VALID_NM(isc__netmgr));

	return atomic_load_relaxed(&isc__netmgr->idle);
}

uint32_t
isc_nm_getkeepalivetimeout(void) {
	REQUIRE(VALID_NM(isc__netmgr));

	return atomic_load_relaxed(&isc__netmgr->keepalive);
}

uint32_t
isc_nm_getadvertisedtimeout(void) {
	REQUIRE(VALID_NM(isc__netmgr));

	return atomic_load_relaxed(&isc__netmgr->advertised);
}

bool
isc__nmsocket_active(isc_nmsocket_t *sock) {
	REQUIRE(VALID_NMSOCK(sock));

	return sock->active;
}

void
isc___nmsocket_attach(isc_nmsocket_t *sock, isc_nmsocket_t **target FLARG) {
	REQUIRE(VALID_NMSOCK(sock));
	REQUIRE(target != NULL && *target == NULL);

	isc_nmsocket_t *rsock = NULL;

	if (sock->parent != NULL) {
		rsock = sock->parent;
		INSIST(rsock->parent == NULL); /* sanity check */
	} else {
		rsock = sock;
	}

	NETMGR_TRACE_LOG("isc__nmsocket_attach():%p->references = %" PRIuFAST32
			 "\n",
			 rsock, isc_refcount_current(&rsock->references) + 1);

	isc_refcount_increment0(&rsock->references);

	*target = sock;
}

/*
 * Free all resources inside a socket (including its children if any).
 */
static void
nmsocket_cleanup(void *arg) {
	isc_nmsocket_t *sock = arg;

	REQUIRE(VALID_NMSOCK(sock));
	REQUIRE(!isc__nmsocket_active(sock));

	isc__networker_t *worker = sock->worker;

	isc_refcount_destroy(&sock->references);

	isc__nm_decstats(sock, STATID_ACTIVE);

	REQUIRE(!sock->destroying);
	sock->destroying = true;

	if (sock->parent == NULL) {
		isc_nmsocket_t **childrenp = NULL;
		switch (sock->type) {
		case isc_nm_tcplistener:
			childrenp = &sock->tcp.children;
			break;
		case isc_nm_udplistener:
			childrenp = &sock->udp.children;
			break;
		default:
			break;
		}
		if (childrenp != NULL && *childrenp != NULL) {
			for (size_t i = 0; i < sock->nchildren; i++) {
				isc_refcount_decrementz(
					&(*childrenp)[i].references);
				nmsocket_cleanup(&(*childrenp)[i]);
			}
			isc_mem_cput(sock->worker->mctx, *childrenp,
				     sock->nchildren, sizeof(*sock));
			*childrenp = NULL;
			sock->nchildren = 0;
		}
	}

	sock->statichandle = NULL;

	if (sock->outerhandle != NULL) {
		isc_nmhandle_detach(&sock->outerhandle);
	}

	if (sock->outer != NULL) {
		isc__nmsocket_detach(&sock->outer);
	}

	if (sock->type == isc_nm_udpsocket || sock->type == isc_nm_udplistener)
	{
		ISC_LIST_FOREACH(sock->udp.inactive_handles, handle,
				 inactive_link)
		{
			ISC_LIST_DEQUEUE(sock->udp.inactive_handles, handle,
					 inactive_link);
			nmhandle_free(sock, handle);
		}
	}

	INSIST(sock->server == NULL);

	isc__nm_tls_cleanup_data(sock);
#if HAVE_LIBNGHTTP2
	isc__nm_http_cleanup_data(sock);
#endif
	isc__nm_streamdns_cleanup_data(sock);
	isc__nm_proxystream_cleanup_data(sock);
	isc__nm_proxyudp_cleanup_data(sock);

	switch (sock->type) {
	case isc_nm_tcplistener:
		if (sock->tcp.barriers_initialised) {
			isc_barrier_destroy(&sock->tcp.listen_barrier);
			isc_barrier_destroy(&sock->tcp.stop_barrier);
		}
		break;
	case isc_nm_udplistener:
		if (sock->udp.barriers_initialised) {
			isc_barrier_destroy(&sock->udp.listen_barrier);
			isc_barrier_destroy(&sock->udp.stop_barrier);
		}
		break;
	default:
		break;
	}

	sock->magic = 0;

	/* Don't free child socket */
	if (sock->parent == NULL) {
		REQUIRE(sock->tid == isc_tid());

		ISC_LIST_UNLINK(worker->active_sockets, sock, active_link);

		isc_mempool_put(isc__nmsocket_getpool(worker, sock->type),
				sock);
	}

	isc__networker_detach(&worker);
}

static bool
nmsocket_has_active_handles(isc_nmsocket_t *sock) {
	if (!ISC_LIST_EMPTY(sock->active_handles)) {
		return true;
	}

	isc_nmsocket_t *children = NULL;
	switch (sock->type) {
	case isc_nm_tcplistener:
		children = sock->tcp.children;
		break;
	case isc_nm_udplistener:
		children = sock->udp.children;
		break;
	default:
		break;
	}
	if (children != NULL) {
		for (size_t i = 0; i < sock->nchildren; i++) {
			isc_nmsocket_t *csock = &children[i];
			if (!ISC_LIST_EMPTY(csock->active_handles)) {
				return true;
			}
		}
	}

	return false;
}

static void
nmsocket_maybe_destroy(isc_nmsocket_t *sock FLARG) {
	NETMGR_TRACE_LOG("%s():%p->references = %" PRIuFAST32 "\n", __func__,
			 sock, isc_refcount_current(&sock->references));

	if (sock->parent != NULL) {
		/*
		 * This is a child socket and cannot be destroyed except
		 * as a side effect of destroying the parent, so let's go
		 * see if the parent is ready to be destroyed.
		 */
		nmsocket_maybe_destroy(sock->parent FLARG_PASS);
		return;
	}

	REQUIRE(!sock->destroying);
	REQUIRE(!sock->active);

	if (!sock->closed) {
		return;
	}

	if (isc_refcount_current(&sock->references) != 0) {
		/*
		 * Using such check is valid only if we don't use
		 * isc_refcount_increment0() on the same variable.
		 */
		return;
	}

	NETMGR_TRACE_LOG("%s:%p->statichandle = %p\n", __func__, sock,
			 sock->statichandle);

	/*
	 * This is a parent socket (or a standalone). See whether the
	 * children have active handles before deciding whether to
	 * accept destruction.
	 */
	if (sock->statichandle == NULL && nmsocket_has_active_handles(sock)) {
		return;
	}

	if (sock->tid == isc_tid()) {
		nmsocket_cleanup(sock);
	} else {
		isc_async_run(sock->worker->loop, nmsocket_cleanup, sock);
	}
}

void
isc___nmsocket_prep_destroy(isc_nmsocket_t *sock FLARG) {
	REQUIRE(sock->parent == NULL);

	NETMGR_TRACE_LOG("isc___nmsocket_prep_destroy():%p->references = "
			 "%" PRIuFAST32 "\n",
			 sock, isc_refcount_current(&sock->references));

	/*
	 * The final external reference to the socket is gone. We can try
	 * destroying the socket, but we have to wait for all the inflight
	 * handles to finish first.
	 */
	sock->active = false;

	/*
	 * If the socket has children, they have been marked inactive by the
	 * shutdown uv_walk
	 */

	/*
	 * If we're here then we already stopped listening; otherwise
	 * we'd have a hanging reference from the listening process.
	 *
	 * If it's a regular socket we may need to close it.
	 */
	if (!sock->closing && !sock->closed && sock->ops->close != NULL) {
		sock->ops->close(sock);
		return;
	}

	nmsocket_maybe_destroy(sock FLARG_PASS);
}

void
isc___nmsocket_detach(isc_nmsocket_t **sockp FLARG) {
	REQUIRE(sockp != NULL && *sockp != NULL);
	REQUIRE(VALID_NMSOCK(*sockp));

	isc_nmsocket_t *sock = *sockp, *rsock = NULL;
	*sockp = NULL;

	/*
	 * If the socket is a part of a set (a child socket) we are
	 * counting references for the whole set at the parent.
	 */
	if (sock->parent != NULL) {
		rsock = sock->parent;
		INSIST(rsock->parent == NULL); /* Sanity check */
	} else {
		rsock = sock;
	}

	NETMGR_TRACE_LOG("isc__nmsocket_detach():%p->references = %" PRIuFAST32
			 "\n",
			 rsock, isc_refcount_current(&rsock->references) - 1);

	if (isc_refcount_decrement(&rsock->references) == 1) {
		isc___nmsocket_prep_destroy(rsock FLARG_PASS);
	}
}

void
isc_nmsocket_close(isc_nmsocket_t **sockp) {
	REQUIRE(sockp != NULL);
	REQUIRE(VALID_NMSOCK(*sockp));
	REQUIRE((*sockp)->type == isc_nm_udplistener ||
		(*sockp)->type == isc_nm_tcplistener ||
		(*sockp)->type == isc_nm_streamdnslistener ||
		(*sockp)->type == isc_nm_tlslistener ||
		(*sockp)->type == isc_nm_httplistener ||
		(*sockp)->type == isc_nm_proxystreamlistener ||
		(*sockp)->type == isc_nm_proxyudplistener);

	isc__nmsocket_detach(sockp);
}

void
isc___nmsocket_init(isc_nmsocket_t *sock, isc__networker_t *worker,
		    isc_nmsocket_type type, isc_sockaddr_t *iface,
		    isc_nmsocket_t *parent FLARG) {
	uint16_t family;

	REQUIRE(sock != NULL);
	REQUIRE(worker != NULL);

	/*
	 * Use memset instead of compound literal — overlay types may be
	 * allocated smaller than sizeof(isc_nmsocket_t) in the future
	 * (the transport union at the end is sized for the largest variant).
	 */
	memset(sock, 0, isc__nmsocket_alloc_size(type));
	sock->type = type;
	sock->ops = isc__nmsocket_get_ops(type);
	sock->tid = worker->loop->tid;
	sock->result = ISC_R_UNSET;
	ISC_LIST_INIT(sock->active_handles);
	sock->active_handles_max = ISC_NETMGR_MAX_STREAM_CLIENTS_PER_CONN;
	ISC_LINK_INIT(sock, active_link);
	sock->active = true;

	if (iface != NULL) {
		family = iface->type.sa.sa_family;
		sock->iface = *iface;
	} else {
		family = AF_UNSPEC;
	}

	if (parent) {
		sock->parent = parent;
	} else {
		ISC_LIST_APPEND(worker->active_sockets, sock, active_link);
	}

#if ISC_NETMGR_TRACE
	sock->backtrace_size = isc_backtrace(sock->backtrace, TRACE_SIZE);
#endif

	isc__networker_attach(worker, &sock->worker);

	switch (type) {
	case isc_nm_udpsocket:
	case isc_nm_udplistener:
		switch (family) {
		case AF_INET:
			sock->statsindex = udp4statsindex;
			break;
		case AF_INET6:
			sock->statsindex = udp6statsindex;
			break;
		case AF_UNSPEC:
			/*
			 * Route sockets are AF_UNSPEC, and don't
			 * have stats counters.
			 */
			break;
		default:
			UNREACHABLE();
		}
		break;
	case isc_nm_tcpsocket:
	case isc_nm_tcplistener:
	case isc_nm_httpsocket:
	case isc_nm_httplistener:
		switch (family) {
		case AF_INET:
			sock->statsindex = tcp4statsindex;
			break;
		case AF_INET6:
			sock->statsindex = tcp6statsindex;
			break;
		default:
			UNREACHABLE();
		}
		break;
	default:
		break;
	}

	isc_refcount_init(&sock->references, 1);

	NETMGR_TRACE_LOG("isc__nmsocket_init():%p->references = %" PRIuFAST32
			 "\n",
			 sock, isc_refcount_current(&sock->references));

	sock->magic = NMSOCK_MAGIC;

	isc__nm_incstats(sock, STATID_ACTIVE);
}

void
isc__nmsocket_clearcb(isc_nmsocket_t *sock) {
	REQUIRE(VALID_NMSOCK(sock));
	REQUIRE(sock->tid == isc_tid());

	sock->recv_cb = NULL;
	sock->recv_cbarg = NULL;
	sock->accept_cb = NULL;
	sock->accept_cbarg = NULL;
	sock->connect_cb = NULL;
	sock->connect_cbarg = NULL;
}

void
isc__nm_free_uvbuf(isc_nmsocket_t *sock, const uv_buf_t *buf) {
	REQUIRE(VALID_NMSOCK(sock));

	REQUIRE(buf->base == sock->worker->recvbuf);

	sock->worker->recvbuf_inuse = false;
}

static isc_nmhandle_t *
alloc_handle(isc_nmsocket_t *sock) {
	isc_nmhandle_t *handle = isc_mem_get(sock->worker->mctx,
					     sizeof(isc_nmhandle_t));

	*handle = (isc_nmhandle_t){
		.magic = NMHANDLE_MAGIC,
		.active_link = ISC_LINK_INITIALIZER,
		.inactive_link = ISC_LINK_INITIALIZER,
	};
	isc_refcount_init(&handle->references, 1);

	return handle;
}

static isc_nmhandle_t *
dequeue_handle(isc_nmsocket_t *sock) {
#if !__SANITIZE_ADDRESS__ && !__SANITIZE_THREAD__
	if (sock->type == isc_nm_udpsocket || sock->type == isc_nm_udplistener)
	{
		isc_nmhandle_t *handle =
			ISC_LIST_HEAD(sock->udp.inactive_handles);
		if (handle != NULL) {
			ISC_LIST_DEQUEUE(sock->udp.inactive_handles, handle,
					 inactive_link);
			sock->udp.inactive_handles_cur--;
			isc_refcount_init(&handle->references, 1);
			INSIST(VALID_NMHANDLE(handle));
			return handle;
		}
	}
#else
	if (sock->type == isc_nm_udpsocket || sock->type == isc_nm_udplistener)
	{
		INSIST(ISC_LIST_EMPTY(sock->udp.inactive_handles));
	}
#endif /* !__SANITIZE_ADDRESS__ && !__SANITIZE_THREAD__ */
	return NULL;
}

isc_nmhandle_t *
isc___nmhandle_get(isc_nmsocket_t *sock, isc_sockaddr_t const *peer,
		   isc_sockaddr_t const *local FLARG) {
	REQUIRE(VALID_NMSOCK(sock));

	isc_nmhandle_t *handle = dequeue_handle(sock);
	if (handle == NULL) {
		handle = alloc_handle(sock);
	}

	NETMGR_TRACE_LOG(
		"isc__nmhandle_get():handle %p->references = %" PRIuFAST32 "\n",
		handle, isc_refcount_current(&handle->references));

	isc___nmsocket_attach(sock, &handle->sock FLARG_PASS);

#if ISC_NETMGR_TRACE
	handle->backtrace_size = isc_backtrace(handle->backtrace, TRACE_SIZE);
#endif

	if (peer != NULL) {
		handle->peer = *peer;
	} else {
		handle->peer = sock->peer;
	}

	if (local != NULL) {
		handle->local = *local;
	} else {
		handle->local = sock->iface;
	}

	ISC_LIST_APPEND(sock->active_handles, handle, active_link);
	sock->active_handles_cur++;

	switch (sock->type) {
	case isc_nm_udpsocket:
	case isc_nm_proxyudpsocket:
		if (!sock->client) {
			break;
		}
		FALLTHROUGH;
	case isc_nm_tcpsocket:
	case isc_nm_tlssocket:
	case isc_nm_proxystreamsocket:
		INSIST(sock->statichandle == NULL);

		/*
		 * statichandle must be assigned, not attached;
		 * otherwise, if a handle was detached elsewhere
		 * it could never reach 0 references, and the
		 * handle and socket would never be freed.
		 */
		sock->statichandle = handle;
		break;
	default:
		break;
	}

#if HAVE_LIBNGHTTP2
	if (sock->type == isc_nm_httpsocket && sock->h2 != NULL &&
	    sock->h2->session)
	{
		isc__nm_httpsession_attach(sock->h2->session,
					   &handle->httpsession);
	}
#endif

	return handle;
}

bool
isc_nmhandle_is_stream(isc_nmhandle_t *handle) {
	REQUIRE(VALID_NMHANDLE(handle));

	return handle->sock->type == isc_nm_tcpsocket ||
	       handle->sock->type == isc_nm_tlssocket ||
	       handle->sock->type == isc_nm_httpsocket ||
	       handle->sock->type == isc_nm_streamdnssocket ||
	       handle->sock->type == isc_nm_proxystreamsocket;
}

static void
nmhandle_free(isc_nmsocket_t *sock, isc_nmhandle_t *handle) {
	handle->magic = 0;

	if (handle->dofree != NULL) {
		handle->dofree(handle->opaque);
	}

	isc_mem_put(sock->worker->mctx, handle, sizeof(*handle));
}

static void
nmhandle__destroy(isc_nmhandle_t *handle) {
	isc_nmsocket_t *sock = handle->sock;
	handle->sock = NULL;

#if defined(__SANITIZE_ADDRESS__) || defined(__SANITIZE_THREAD__)
	nmhandle_free(sock, handle);
#else
	if (sock->active &&
	    (sock->type == isc_nm_udpsocket ||
	     sock->type == isc_nm_udplistener) &&
	    sock->udp.inactive_handles_cur < sock->udp.inactive_handles_max)
	{
		sock->udp.inactive_handles_cur++;
		ISC_LIST_APPEND(sock->udp.inactive_handles, handle,
				inactive_link);
	} else {
		nmhandle_free(sock, handle);
	}
#endif

	isc__nmsocket_detach(&sock);
}

static void
isc__nm_closehandle_job(void *arg) {
	isc_nmhandle_t *handle = arg;
	isc_nmsocket_t *sock = handle->sock;

	sock->closehandle_cb(sock);

	nmhandle__destroy(handle);
}

static void
nmhandle_destroy(isc_nmhandle_t *handle) {
	isc_nmsocket_t *sock = handle->sock;

	if (handle->doreset != NULL) {
		handle->doreset(handle->opaque);
	}

#if HAVE_LIBNGHTTP2
	if (sock->type == isc_nm_httpsocket && handle->httpsession != NULL) {
		isc__nm_httpsession_detach(&handle->httpsession);
	}
#endif

	if (handle == sock->statichandle) {
		/* statichandle is assigned, not attached. */
		sock->statichandle = NULL;
	}

	if (handle->proxy_udphandle != NULL) {
		isc_nmhandle_detach(&handle->proxy_udphandle);
	}

	ISC_LIST_UNLINK(sock->active_handles, handle, active_link);
	INSIST(sock->active_handles_cur > 0);
	sock->active_handles_cur--;

	if (sock->closehandle_cb == NULL) {
		nmhandle__destroy(handle);
		return;
	}

	/*
	 * If the socket has a callback configured for that (e.g.,
	 * to perform cleanup after request processing), call it
	 * now asynchronously.
	 */
	isc_job_run(sock->worker->loop, &handle->job, isc__nm_closehandle_job,
		    handle);
}

#if ISC_NETMGR_TRACE
ISC_REFCOUNT_TRACE_IMPL(isc_nmhandle, nmhandle_destroy)
#else
ISC_REFCOUNT_IMPL(isc_nmhandle, nmhandle_destroy);
#endif

void *
isc_nmhandle_getdata(isc_nmhandle_t *handle) {
	REQUIRE(VALID_NMHANDLE(handle));

	return handle->opaque;
}

void
isc_nmhandle_setdata(isc_nmhandle_t *handle, void *arg,
		     isc_nm_opaquecb_t doreset, isc_nm_opaquecb_t dofree) {
	REQUIRE(VALID_NMHANDLE(handle));

	handle->opaque = arg;
	handle->doreset = doreset;
	handle->dofree = dofree;
}

void
isc__nm_failed_send_cb(isc_nmsocket_t *sock, isc__nm_uvreq_t *req,
		       isc_result_t eresult, bool async) {
	REQUIRE(VALID_NMSOCK(sock));
	REQUIRE(VALID_UVREQ(req));

	if (req->cb.send != NULL) {
		isc__nm_sendcb(sock, req, eresult, async);
	} else {
		isc__nm_uvreq_put(&req);
	}
}

void
isc__nm_failed_connect_cb(isc_nmsocket_t *sock, isc__nm_uvreq_t *req,
			  isc_result_t eresult, bool async) {
	REQUIRE(VALID_NMSOCK(sock));
	REQUIRE(VALID_UVREQ(req));
	REQUIRE(sock->tid == isc_tid());
	REQUIRE(req->cb.connect != NULL);
	REQUIRE(sock->connecting);

	sock->connecting = false;

	isc__nm_incstats(sock, STATID_CONNECTFAIL);

	isc__nmsocket_timer_stop(sock);
	uv_handle_set_data((uv_handle_t *)isc__nmsocket_timer_ptr(sock), sock);

	isc__nmsocket_clearcb(sock);
	isc__nm_connectcb(sock, req, eresult, async);

	isc__nmsocket_prep_destroy(sock);
}

void
isc__nm_failed_read_cb(isc_nmsocket_t *sock, isc_result_t result, bool async) {
	REQUIRE(VALID_NMSOCK(sock));
	UNUSED(async);
	REQUIRE(sock->ops->failed_read_cb != NULL);
	sock->ops->failed_read_cb(sock, result, async);
}

void
isc__nmsocket_connecttimeout_cb(uv_timer_t *timer) {
	uv_connect_t *uvreq = uv_handle_get_data((uv_handle_t *)timer);
	isc_nmsocket_t *sock = uv_handle_get_data((uv_handle_t *)uvreq->handle);
	isc__nm_uvreq_t *req = uv_handle_get_data((uv_handle_t *)uvreq);

	REQUIRE(VALID_NMSOCK(sock));
	REQUIRE(sock->tid == isc_tid());
	REQUIRE(VALID_UVREQ(req));
	REQUIRE(VALID_NMHANDLE(req->handle));
	REQUIRE(sock->connecting);

	isc__nmsocket_timer_stop(sock);

	/*
	 * Mark the connection as timed out and shutdown the socket.
	 */
	REQUIRE(!sock->tcp.timedout);
	sock->tcp.timedout = true;
	isc__nmsocket_shutdown(sock);
}

void
isc__nm_accept_connection_log(isc_nmsocket_t *sock, isc_result_t result,
			      bool can_log_quota) {
	int level;

	switch (result) {
	case ISC_R_SUCCESS:
	case ISC_R_NOCONN:
		return;
	case ISC_R_QUOTA:
	case ISC_R_SOFTQUOTA:
		if (!can_log_quota) {
			return;
		}
		level = ISC_LOG_INFO;
		break;
	case ISC_R_NOTCONNECTED:
		level = ISC_LOG_INFO;
		break;
	default:
		level = ISC_LOG_ERROR;
	}

	isc__nmsocket_log(sock, level, "Accepting TCP connection failed: %s",
			  isc_result_totext(result));
}

void
isc__nmsocket_writetimeout_cb(void *data, isc_result_t eresult) {
	isc__nm_uvreq_t *req = data;
	isc_nmsocket_t *sock = NULL;

	REQUIRE(eresult == ISC_R_TIMEDOUT);
	REQUIRE(VALID_UVREQ(req));
	REQUIRE(VALID_NMSOCK(req->sock));

	sock = req->sock;

	isc__nm_start_reading(sock);
	isc__nmsocket_reset(sock);
}

void
isc__nmsocket_readtimeout_cb(uv_timer_t *timer) {
	isc_nmsocket_t *sock = uv_handle_get_data((uv_handle_t *)timer);

	REQUIRE(VALID_NMSOCK(sock));
	REQUIRE(sock->tid == isc_tid());

	if (sock->client) {
		uv_timer_stop(timer);

		if (sock->recv_cb != NULL) {
			isc__nm_uvreq_t *req = isc__nm_get_read_req(sock, NULL);
			isc__nm_readcb(sock, req, ISC_R_TIMEDOUT, false);
		}

		if (!isc__nmsocket_timer_running(sock)) {
			isc__nmsocket_clearcb(sock);
			isc__nm_failed_read_cb(sock, ISC_R_TIMEDOUT, false);
		}
	} else {
		isc__nm_failed_read_cb(sock, ISC_R_TIMEDOUT, false);
	}
}

void
isc__nmsocket_timer_restart(isc_nmsocket_t *sock) {
	REQUIRE(VALID_NMSOCK(sock));

	if (sock->ops->timer_restart != NULL) {
		sock->ops->timer_restart(sock);
		return;
	}

	uv_timer_t *timer = isc__nmsocket_timer_ptr(sock);

	if (uv_is_closing((uv_handle_t *)timer)) {
		return;
	}

	if (sock->connecting) {
		int r;

		if (sock->connect_timeout == 0) {
			return;
		}

		r = uv_timer_start(timer, isc__nmsocket_connecttimeout_cb,
				   sock->connect_timeout + 10, 0);
		UV_RUNTIME_CHECK(uv_timer_start, r);

	} else {
		int r;

		if (sock->read_timeout == 0) {
			return;
		}

		r = uv_timer_start(timer, isc__nmsocket_readtimeout_cb,
				   sock->read_timeout, 0);
		UV_RUNTIME_CHECK(uv_timer_start, r);
	}
}

bool
isc__nmsocket_timer_running(isc_nmsocket_t *sock) {
	REQUIRE(VALID_NMSOCK(sock));

	if (sock->ops->timer_running != NULL) {
		return sock->ops->timer_running(sock);
	}

	return uv_is_active((uv_handle_t *)isc__nmsocket_timer_ptr(sock));
}

void
isc__nmsocket_timer_start(isc_nmsocket_t *sock) {
	REQUIRE(VALID_NMSOCK(sock));

	if (isc__nmsocket_timer_running(sock)) {
		return;
	}

	isc__nmsocket_timer_restart(sock);
}

void
isc__nmsocket_timer_stop(isc_nmsocket_t *sock) {
	int r;

	REQUIRE(VALID_NMSOCK(sock));

	if (sock->ops->timer_stop != NULL) {
		sock->ops->timer_stop(sock);
		return;
	}

	/* uv_timer_stop() is idempotent, no need to check if running */

	r = uv_timer_stop(isc__nmsocket_timer_ptr(sock));
	UV_RUNTIME_CHECK(uv_timer_stop, r);
}

isc__nm_uvreq_t *
isc___nm_get_read_req(isc_nmsocket_t *sock, isc_sockaddr_t *sockaddr FLARG) {
	isc__nm_uvreq_t *req = NULL;

	req = isc__nm_uvreq_get(sock);
	req->cb.recv = sock->recv_cb;
	req->cbarg = sock->recv_cbarg;

	switch (sock->type) {
	case isc_nm_tcpsocket:
	case isc_nm_tlssocket:
	case isc_nm_proxystreamsocket:
#if ISC_NETMGR_TRACE
		isc_nmhandle__attach(sock->statichandle,
				     &req->handle FLARG_PASS);
#else
		isc_nmhandle_attach(sock->statichandle, &req->handle);
#endif
		break;
	case isc_nm_streamdnssocket:
#if ISC_NETMGR_TRACE
		isc_nmhandle__attach(sock->recv_handle,
				     &req->handle FLARG_PASS);
#else
		isc_nmhandle_attach(sock->recv_handle, &req->handle);
#endif
		break;
	default:
		if (sock->client && sock->statichandle != NULL) {
#if ISC_NETMGR_TRACE
			isc_nmhandle__attach(sock->statichandle,
					     &req->handle FLARG_PASS);
#else
			isc_nmhandle_attach(sock->statichandle, &req->handle);
#endif
		} else {
			req->handle = isc___nmhandle_get(sock, sockaddr,
							 NULL FLARG_PASS);
		}
		break;
	}

	return req;
}

/*%<
 * Allocator callback for read operations.
 *
 * Note this doesn't actually allocate anything, it just assigns the
 * worker's receive buffer to a socket, and marks it as "in use".
 */
void
isc__nm_alloc_cb(uv_handle_t *handle, size_t size, uv_buf_t *buf) {
	isc_nmsocket_t *sock = uv_handle_get_data(handle);
	isc__networker_t *worker = NULL;

	REQUIRE(VALID_NMSOCK(sock));
	/*
	 * The size provided by libuv is only suggested size, and it always
	 * defaults to 64 * 1024 in the current versions of libuv (see
	 * src/unix/udp.c and src/unix/stream.c).
	 */
	UNUSED(size);

	worker = sock->worker;
	INSIST(!worker->recvbuf_inuse);
	INSIST(worker->recvbuf != NULL);

	switch (sock->type) {
	case isc_nm_udpsocket:
		buf->len = ISC_NETMGR_UDP_RECVBUF_SIZE;
		break;
	case isc_nm_tcpsocket:
		buf->len = ISC_NETMGR_TCP_RECVBUF_SIZE;
		break;
	default:
		UNREACHABLE();
	}

	REQUIRE(buf->len <= ISC_NETMGR_RECVBUF_SIZE);
	buf->base = worker->recvbuf;

	worker->recvbuf_inuse = true;
}

isc_result_t
isc__nm_start_reading(isc_nmsocket_t *sock) {
	isc_result_t result = ISC_R_SUCCESS;
	int r;

	if (uv_is_active(isc__nmsocket_uv_handle_ptr(sock))) {
		return ISC_R_SUCCESS;
	}

	switch (sock->type) {
	case isc_nm_udpsocket:
		r = uv_udp_recv_start(&sock->udp.uv_handle.udp,
				      isc__nm_alloc_cb, isc__nm_udp_read_cb);
		break;
	case isc_nm_tcpsocket:
		r = uv_read_start(&sock->tcp.uv_handle.stream, isc__nm_alloc_cb,
				  isc__nm_tcp_read_cb);
		break;
	default:
		UNREACHABLE();
	}
	if (r != 0) {
		result = isc_uverr2result(r);
	}

	return result;
}

void
isc__nm_stop_reading(isc_nmsocket_t *sock) {
	int r;

	if (!uv_is_active(isc__nmsocket_uv_handle_ptr(sock))) {
		return;
	}

	switch (sock->type) {
	case isc_nm_udpsocket:
		r = uv_udp_recv_stop(&sock->udp.uv_handle.udp);
		UV_RUNTIME_CHECK(uv_udp_recv_stop, r);
		break;
	case isc_nm_tcpsocket:
		r = uv_read_stop(&sock->tcp.uv_handle.stream);
		UV_RUNTIME_CHECK(uv_read_stop, r);
		break;
	default:
		UNREACHABLE();
	}
}

bool
isc__nm_closing(isc__networker_t *worker) {
	return worker->shuttingdown;
}

bool
isc__nmsocket_closing(isc_nmsocket_t *sock) {
	return !sock->active || sock->closing ||
	       isc__nm_closing(sock->worker) ||
	       (sock->server != NULL && !isc__nmsocket_active(sock->server));
}

void
isc_nmhandle_cleartimeout(isc_nmhandle_t *handle) {
	REQUIRE(VALID_NMHANDLE(handle));
	REQUIRE(VALID_NMSOCK(handle->sock));

	if (handle->sock->ops->cleartimeout != NULL) {
		handle->sock->ops->cleartimeout(handle);
		return;
	}

	/* Default for TCP/UDP: clear timeout and stop timer */
	handle->sock->read_timeout = 0;
	if (uv_is_active((uv_handle_t *)isc__nmsocket_timer_ptr(handle->sock)))
	{
		isc__nmsocket_timer_stop(handle->sock);
	}
}

void
isc_nmhandle_settimeout(isc_nmhandle_t *handle, uint32_t timeout) {
	REQUIRE(VALID_NMHANDLE(handle));
	REQUIRE(VALID_NMSOCK(handle->sock));

	if (handle->sock->ops->settimeout != NULL) {
		handle->sock->ops->settimeout(handle, timeout);
		return;
	}

	/* Default for TCP/UDP: set timeout and restart timer */
	handle->sock->read_timeout = timeout;
	isc__nmsocket_timer_restart(handle->sock);
}

void
isc_nmhandle_keepalive(isc_nmhandle_t *handle, bool value) {
	isc_nmsocket_t *sock = NULL;

	REQUIRE(VALID_NMHANDLE(handle));
	REQUIRE(VALID_NMSOCK(handle->sock));

	sock = handle->sock;

	REQUIRE(sock->tid == isc_tid());

	if (sock->ops->keepalive != NULL) {
		sock->ops->keepalive(handle, value);
	}
}

bool
isc_nmhandle_timer_running(isc_nmhandle_t *handle) {
	REQUIRE(VALID_NMHANDLE(handle));
	REQUIRE(VALID_NMSOCK(handle->sock));

	return isc__nmsocket_timer_running(handle->sock);
}

isc_sockaddr_t
isc_nmhandle_peeraddr(isc_nmhandle_t *handle) {
	REQUIRE(VALID_NMHANDLE(handle));

	return handle->peer;
}

isc_sockaddr_t
isc_nmhandle_localaddr(isc_nmhandle_t *handle) {
	isc_sockaddr_t addr;

	REQUIRE(VALID_NMHANDLE(handle));

	addr = handle->local;

#ifdef ISC_SOCKET_DETAILS
	switch (handle->sock->type) {
	case isc_nm_tcpsocket:
		uv_tcp_getsockname(&handle->sock->tcp.uv_handle.tcp,
				   (struct sockaddr *)&addr.type,
				   &(int){ sizeof(addr.type) });
		break;

	case isc_nm_udpsocket:
		uv_udp_getsockname(&handle->sock->udp.uv_handle.udp,
				   (struct sockaddr *)&addr.type,
				   &(int){ sizeof(addr.type) });
		break;

	case isc_nm_tlssocket:
	case isc_nm_httpsocket:
	case isc_nm_streamdnssocket:
		if (handle->sock->outerhandle) {
			addr = isc_nmhandle_localaddr(
				handle->sock->outerhandle);
		}
		break;

	case isc_nm_proxystreamsocket:
	case isc_nm_proxyudpsocket:
		break;

	default:
		UNREACHABLE();
	}
#endif /* ISC_SOCKET_DETAILS */

	return addr;
}

isc__nm_uvreq_t *
isc___nm_uvreq_get(isc_nmsocket_t *sock FLARG) {
	REQUIRE(VALID_NMSOCK(sock));
	REQUIRE(sock->tid == isc_tid());

	isc__networker_t *worker = sock->worker;

	isc__nm_uvreq_t *req = isc_mempool_get(worker->uvreq_pool);
	*req = (isc__nm_uvreq_t){
		.connect_tries = 3,
		.link = ISC_LINK_INITIALIZER,
		.active_link = ISC_LINK_INITIALIZER,
		.magic = UVREQ_MAGIC,
	};
	uv_handle_set_data(&req->uv_req.handle, req);

	isc___nmsocket_attach(sock, &req->sock FLARG_PASS);

	ISC_LIST_APPEND(sock->active_uvreqs, req, active_link);

	return req;
}

void
isc___nm_uvreq_put(isc__nm_uvreq_t **reqp FLARG) {
	REQUIRE(reqp != NULL && VALID_UVREQ(*reqp));

	isc__nm_uvreq_t *req = *reqp;
	isc_nmhandle_t *handle = req->handle;
	isc_nmsocket_t *sock = req->sock;

	*reqp = NULL;
	req->handle = NULL;

	REQUIRE(VALID_UVREQ(req));

	ISC_LIST_UNLINK(sock->active_uvreqs, req, active_link);

	if (handle != NULL) {
#if ISC_NETMGR_TRACE
		isc_nmhandle__detach(&handle, func, file, line);
#else
		isc_nmhandle_detach(&handle);
#endif
	}

	isc_mempool_put(sock->worker->uvreq_pool, req);

	isc___nmsocket_detach(&sock FLARG_PASS);
}

void
isc_nm_send(isc_nmhandle_t *handle, isc_region_t *region, isc_nm_cb_t cb,
	    void *cbarg) {
	REQUIRE(VALID_NMHANDLE(handle));

	REQUIRE(handle->sock->ops->send != NULL);
	handle->sock->ops->send(handle, region, cb, cbarg);
}

void
isc__nm_senddns(isc_nmhandle_t *handle, isc_region_t *region, isc_nm_cb_t cb,
		void *cbarg) {
	REQUIRE(VALID_NMHANDLE(handle));

	REQUIRE(handle->sock->ops->senddns != NULL);
	handle->sock->ops->senddns(handle, region, cb, cbarg);
}

void
isc_nm_read(isc_nmhandle_t *handle, isc_nm_recv_cb_t cb, void *cbarg) {
	REQUIRE(VALID_NMHANDLE(handle));

	REQUIRE(handle->sock->ops->read != NULL);
	handle->sock->ops->read(handle, cb, cbarg);
}

static void
cancelread_cb(void *arg) {
	isc_nmhandle_t *handle = arg;

	REQUIRE(VALID_NMHANDLE(handle));
	REQUIRE(VALID_NMSOCK(handle->sock));
	REQUIRE(handle->sock->tid == isc_tid());

	REQUIRE(handle->sock->tid == isc_tid());

	isc__nm_failed_read_cb(handle->sock, ISC_R_CANCELED, false);

	isc_nmhandle_detach(&handle);
}

void
isc_nm_cancelread(isc_nmhandle_t *handle) {
	REQUIRE(VALID_NMHANDLE(handle));
	REQUIRE(VALID_NMSOCK(handle->sock));

	/* Running this directly could cause a dead-lock */
	isc_nmhandle_ref(handle);
	isc_async_run(handle->sock->worker->loop, cancelread_cb, handle);
}

void
isc_nm_read_stop(isc_nmhandle_t *handle) {
	REQUIRE(VALID_NMHANDLE(handle));

	REQUIRE(handle->sock->ops->read_stop != NULL);
	handle->sock->ops->read_stop(handle);
}

void
isc_nmhandle_close(isc_nmhandle_t *handle) {
	REQUIRE(VALID_NMHANDLE(handle));
	REQUIRE(VALID_NMSOCK(handle->sock));

	isc__nmsocket_clearcb(handle->sock);
	isc__nmsocket_prep_destroy(handle->sock);
}

void
isc_nm_stoplistening(isc_nmsocket_t *sock) {
	REQUIRE(VALID_NMSOCK(sock));

	REQUIRE(sock->ops->stoplistening != NULL);
	sock->ops->stoplistening(sock);
}

void
isc__nmsocket_stop(isc_nmsocket_t *listener) {
	REQUIRE(VALID_NMSOCK(listener));
	REQUIRE(listener->tid == isc_tid());
	REQUIRE(listener->tid == 0);
	REQUIRE(listener->type == isc_nm_httplistener ||
		listener->type == isc_nm_tlslistener ||
		listener->type == isc_nm_streamdnslistener ||
		listener->type == isc_nm_proxystreamlistener ||
		listener->type == isc_nm_proxyudplistener);
	REQUIRE(!listener->closing);

	listener->closing = true;

	REQUIRE(listener->outer != NULL);
	isc_nm_stoplistening(listener->outer);

	listener->accept_cb = NULL;
	listener->accept_cbarg = NULL;
	listener->recv_cb = NULL;
	listener->recv_cbarg = NULL;

	isc__nmsocket_detach(&listener->outer);

	listener->closed = true;
}

void
isc__nmsocket_barrier_init(isc_nmsocket_t *listener) {
	REQUIRE(listener->nchildren > 0);

	switch (listener->type) {
	case isc_nm_tcplistener:
		isc_barrier_init(&listener->tcp.listen_barrier,
				 listener->nchildren);
		isc_barrier_init(&listener->tcp.stop_barrier,
				 listener->nchildren);
		listener->tcp.barriers_initialised = true;
		break;
	case isc_nm_udplistener:
		isc_barrier_init(&listener->udp.listen_barrier,
				 listener->nchildren);
		isc_barrier_init(&listener->udp.stop_barrier,
				 listener->nchildren);
		listener->udp.barriers_initialised = true;
		break;
	default:
		UNREACHABLE();
	}
}

static void
isc___nm_connectcb(void *arg) {
	isc__nm_uvreq_t *uvreq = arg;

	uvreq->cb.connect(uvreq->handle, uvreq->result, uvreq->cbarg);
	isc__nm_uvreq_put(&uvreq);
}

void
isc__nm_connectcb(isc_nmsocket_t *sock, isc__nm_uvreq_t *uvreq,
		  isc_result_t eresult, bool async) {
	REQUIRE(VALID_NMSOCK(sock));
	REQUIRE(VALID_UVREQ(uvreq));
	REQUIRE(VALID_NMHANDLE(uvreq->handle));
	REQUIRE(uvreq->cb.connect != NULL);

	uvreq->result = eresult;

	if (!async) {
		isc___nm_connectcb(uvreq);
		return;
	}

	isc_job_run(sock->worker->loop, &uvreq->job, isc___nm_connectcb, uvreq);
}

static void
isc___nm_readcb(void *arg) {
	isc__nm_uvreq_t *uvreq = arg;
	isc_region_t region;

	region.base = (unsigned char *)uvreq->uvbuf.base;
	region.length = uvreq->uvbuf.len;
	uvreq->cb.recv(uvreq->handle, uvreq->result, &region, uvreq->cbarg);

	isc__nm_uvreq_put(&uvreq);
}

void
isc__nm_readcb(isc_nmsocket_t *sock, isc__nm_uvreq_t *uvreq,
	       isc_result_t eresult, bool async) {
	REQUIRE(VALID_NMSOCK(sock));
	REQUIRE(VALID_UVREQ(uvreq));
	REQUIRE(VALID_NMHANDLE(uvreq->handle));

	uvreq->result = eresult;

	if (!async) {
		isc___nm_readcb(uvreq);
		return;
	}

	isc_job_run(sock->worker->loop, &uvreq->job, isc___nm_readcb, uvreq);
}

static void
isc___nm_sendcb(void *arg) {
	isc__nm_uvreq_t *uvreq = arg;

	uvreq->cb.send(uvreq->handle, uvreq->result, uvreq->cbarg);
	isc__nm_uvreq_put(&uvreq);
}

void
isc__nm_sendcb(isc_nmsocket_t *sock, isc__nm_uvreq_t *uvreq,
	       isc_result_t eresult, bool async) {
	REQUIRE(VALID_NMSOCK(sock));
	REQUIRE(VALID_UVREQ(uvreq));
	REQUIRE(VALID_NMHANDLE(uvreq->handle));

	uvreq->result = eresult;

	if (!async) {
		isc___nm_sendcb(uvreq);
		return;
	}

	isc_job_run(sock->worker->loop, &uvreq->job, isc___nm_sendcb, uvreq);
}

void
isc__nmsocket_reset(isc_nmsocket_t *sock) {
	REQUIRE(VALID_NMSOCK(sock));

	REQUIRE(sock->ops->reset != NULL);
	sock->ops->reset(sock);
}

void
isc__nmsocket_shutdown(isc_nmsocket_t *sock) {
	REQUIRE(VALID_NMSOCK(sock));
	if (sock->ops->shutdown != NULL) {
		sock->ops->shutdown(sock);
	}
}

static void
shutdown_walk_cb(uv_handle_t *handle, void *arg) {
	isc_nmsocket_t *sock = NULL;
	UNUSED(arg);

	if (uv_is_closing(handle)) {
		return;
	}

	sock = uv_handle_get_data(handle);

	switch (handle->type) {
	case UV_UDP:
		isc__nmsocket_shutdown(sock);
		return;
	case UV_TCP:
		switch (sock->type) {
		case isc_nm_tcpsocket:
			if (sock->parent == NULL) {
				/* Reset the TCP connections on shutdown */
				isc__nmsocket_reset(sock);
				return;
			}
			FALLTHROUGH;
		default:
			isc__nmsocket_shutdown(sock);
		}

		return;
	default:
		return;
	}
}

void
isc_nm_setstats(isc_stats_t *stats) {
	REQUIRE(VALID_NM(isc__netmgr));
	REQUIRE(isc__netmgr->stats == NULL);
	REQUIRE(isc_stats_ncounters(stats) == isc_sockstatscounter_max);

	isc_stats_attach(stats, &isc__netmgr->stats);
}

void
isc__nm_incstats(isc_nmsocket_t *sock, isc__nm_statid_t id) {
	REQUIRE(VALID_NMSOCK(sock));
	REQUIRE(id < STATID_MAX);

	if (sock->statsindex != NULL && isc__netmgr->stats != NULL) {
		isc_stats_increment(isc__netmgr->stats, sock->statsindex[id]);
	}
}

void
isc__nm_decstats(isc_nmsocket_t *sock, isc__nm_statid_t id) {
	REQUIRE(VALID_NMSOCK(sock));
	REQUIRE(id < STATID_MAX);

	if (sock->statsindex != NULL && isc__netmgr->stats != NULL) {
		isc_stats_decrement(isc__netmgr->stats, sock->statsindex[id]);
	}
}

isc_result_t
isc_nm_checkaddr(const isc_sockaddr_t *addr, isc_socktype_t type) {
	int proto, pf, addrlen, fd, r;

	REQUIRE(addr != NULL);

	switch (type) {
	case isc_socktype_tcp:
		proto = SOCK_STREAM;
		break;
	case isc_socktype_udp:
		proto = SOCK_DGRAM;
		break;
	default:
		return ISC_R_NOTIMPLEMENTED;
	}

	pf = isc_sockaddr_pf(addr);
	if (pf == AF_INET) {
		addrlen = sizeof(struct sockaddr_in);
	} else {
		addrlen = sizeof(struct sockaddr_in6);
	}

	fd = socket(pf, proto, 0);
	if (fd < 0) {
		return isc_errno_toresult(errno);
	}

	r = bind(fd, (const struct sockaddr *)&addr->type.sa, addrlen);
	if (r < 0) {
		close(fd);
		return isc_errno_toresult(errno);
	}

	close(fd);
	return ISC_R_SUCCESS;
}

#if defined(TCP_CONNECTIONTIMEOUT)
#define TIMEOUT_TYPE	int
#define TIMEOUT_DIV	1000
#define TIMEOUT_OPTNAME TCP_CONNECTIONTIMEOUT
#elif defined(TCP_RXT_CONNDROPTIME)
#define TIMEOUT_TYPE	int
#define TIMEOUT_DIV	1000
#define TIMEOUT_OPTNAME TCP_RXT_CONNDROPTIME
#elif defined(TCP_USER_TIMEOUT)
#define TIMEOUT_TYPE	unsigned int
#define TIMEOUT_DIV	1
#define TIMEOUT_OPTNAME TCP_USER_TIMEOUT
#elif defined(TCP_KEEPINIT)
#define TIMEOUT_TYPE	int
#define TIMEOUT_DIV	1000
#define TIMEOUT_OPTNAME TCP_KEEPINIT
#endif

void
isc__nm_set_network_buffers(uv_handle_t *handle) {
	int32_t recv_buffer_size = 0;
	int32_t send_buffer_size = 0;

	switch (handle->type) {
	case UV_TCP:
		recv_buffer_size =
			atomic_load_relaxed(&isc__netmgr->recv_tcp_buffer_size);
		send_buffer_size =
			atomic_load_relaxed(&isc__netmgr->send_tcp_buffer_size);
		break;
	case UV_UDP:
		recv_buffer_size =
			atomic_load_relaxed(&isc__netmgr->recv_udp_buffer_size);
		send_buffer_size =
			atomic_load_relaxed(&isc__netmgr->send_udp_buffer_size);
		break;
	default:
		UNREACHABLE();
	}

	if (recv_buffer_size > 0) {
		int r = uv_recv_buffer_size(handle, &recv_buffer_size);
		UV_RUNTIME_CHECK(uv_recv_buffer_size, r);
	}

	if (send_buffer_size > 0) {
		int r = uv_send_buffer_size(handle, &send_buffer_size);
		UV_RUNTIME_CHECK(uv_send_buffer_size, r);
	}
}

void
isc_nm_bad_request(isc_nmhandle_t *handle) {
	isc_nmsocket_t *sock = NULL;

	REQUIRE(VALID_NMHANDLE(handle));
	REQUIRE(VALID_NMSOCK(handle->sock));

	sock = handle->sock;

	switch (sock->type) {
	case isc_nm_udpsocket:
	case isc_nm_proxyudpsocket:
		return;
	case isc_nm_tcpsocket:
	case isc_nm_streamdnssocket:
	case isc_nm_tlssocket:
	case isc_nm_proxystreamsocket:
		REQUIRE(sock->parent == NULL);
		isc__nmsocket_reset(sock);
		return;
#if HAVE_LIBNGHTTP2
	case isc_nm_httpsocket:
		isc__nm_http_bad_request(handle);
		return;
#endif /* HAVE_LIBNGHTTP2 */
	default:
		UNREACHABLE();
		break;
	}
}

isc_result_t
isc_nm_xfr_checkperm(isc_nmhandle_t *handle) {
	isc_nmsocket_t *sock = NULL;
	isc_result_t result = ISC_R_NOPERM;

	REQUIRE(VALID_NMHANDLE(handle));
	REQUIRE(VALID_NMSOCK(handle->sock));

	sock = handle->sock;

	switch (sock->type) {
	case isc_nm_streamdnssocket:
		result = isc__nm_streamdns_xfr_checkperm(sock);
		break;
	default:
		break;
	}

	return result;
}

bool
isc_nm_is_http_handle(isc_nmhandle_t *handle) {
	REQUIRE(VALID_NMHANDLE(handle));
	REQUIRE(VALID_NMSOCK(handle->sock));

	return handle->sock->type == isc_nm_httpsocket;
}

static isc_nmhandle_t *
get_proxy_handle(isc_nmhandle_t *handle) {
	isc_nmsocket_t *sock = NULL;

	sock = handle->sock;

	switch (sock->type) {
	case isc_nm_proxystreamsocket:
	case isc_nm_proxyudpsocket:
		return handle;
#ifdef HAVE_LIBNGHTTP2
	case isc_nm_httpsocket:
		if (sock->h2 != NULL) {
			return get_proxy_handle(
				isc__nm_httpsession_handle(sock->h2->session));
		}
		return NULL;
#endif /* HAVE_LIBNGHTTP2 */
	default:
		break;
	}

	if (sock->outerhandle != NULL) {
		return get_proxy_handle(sock->outerhandle);
	}

	return NULL;
}

bool
isc_nm_is_proxy_handle(isc_nmhandle_t *handle) {
	REQUIRE(VALID_NMHANDLE(handle));
	REQUIRE(VALID_NMSOCK(handle->sock));

	return get_proxy_handle(handle) != NULL;
}

bool
isc_nm_is_proxy_unspec(isc_nmhandle_t *handle) {
	isc_nmhandle_t *proxyhandle;
	REQUIRE(VALID_NMHANDLE(handle));
	REQUIRE(VALID_NMSOCK(handle->sock));

	if (handle->sock->client) {
		return false;
	}

	proxyhandle = get_proxy_handle(handle);
	if (proxyhandle == NULL) {
		return false;
	}

	return proxyhandle->proxy_is_unspec;
}

isc_sockaddr_t
isc_nmhandle_real_peeraddr(isc_nmhandle_t *handle) {
	isc_sockaddr_t addr = { 0 };
	isc_nmhandle_t *proxyhandle;
	REQUIRE(VALID_NMHANDLE(handle));

	proxyhandle = get_proxy_handle(handle);
	if (proxyhandle == NULL) {
		return isc_nmhandle_peeraddr(handle);
	}

	INSIST(VALID_NMSOCK(proxyhandle->sock));

	if (isc_nmhandle_is_stream(proxyhandle)) {
		addr = isc_nmhandle_peeraddr(proxyhandle->sock->outerhandle);
	} else {
		INSIST(proxyhandle->sock->type == isc_nm_proxyudpsocket);
		addr = isc_nmhandle_peeraddr(proxyhandle->proxy_udphandle);
	}

	return addr;
}

isc_sockaddr_t
isc_nmhandle_real_localaddr(isc_nmhandle_t *handle) {
	isc_sockaddr_t addr = { 0 };
	isc_nmhandle_t *proxyhandle;
	REQUIRE(VALID_NMHANDLE(handle));

	proxyhandle = get_proxy_handle(handle);
	if (proxyhandle == NULL) {
		return isc_nmhandle_localaddr(handle);
	}

	INSIST(VALID_NMSOCK(proxyhandle->sock));

	if (isc_nmhandle_is_stream(proxyhandle)) {
		addr = isc_nmhandle_localaddr(proxyhandle->sock->outerhandle);
	} else {
		INSIST(proxyhandle->sock->type == isc_nm_proxyudpsocket);
		addr = isc_nmhandle_localaddr(proxyhandle->proxy_udphandle);
	}

	return addr;
}

bool
isc__nm_valid_proxy_addresses(const isc_sockaddr_t *src,
			      const isc_sockaddr_t *dst) {
	struct in_addr inv4 = { 0 };
	struct in6_addr inv6 = { 0 };
	isc_netaddr_t zerov4 = { 0 }, zerov6 = { 0 };
	isc_netaddr_t src_addr = { 0 }, dst_addr = { 0 };

	if (src == NULL || dst == NULL) {
		return false;
	}

	/*
	 * We should not allow using 0 in source addresses as well, but we
	 * have a precedent of a tool that issues port 0 in the source
	 * addresses (kdig).
	 */
	if (isc_sockaddr_getport(dst) == 0) {
		return false;
	}

	/*
	 * Anybody using zeroes in source or destination addresses is not
	 * a friend. Considering that most of the upper level code is
	 * written with consideration that bot source and destination
	 * addresses are returned by the OS and should be valid, we should
	 * discard so suspicious addresses. Also, keep in mind that both
	 * "0.0.0.0" and "::" match all interfaces when using as listener
	 * addresses.
	 */
	isc_netaddr_fromin(&zerov4, &inv4);
	isc_netaddr_fromin6(&zerov6, &inv6);

	isc_netaddr_fromsockaddr(&src_addr, src);
	isc_netaddr_fromsockaddr(&dst_addr, dst);

	INSIST(isc_sockaddr_pf(src) == isc_sockaddr_pf(dst));

	switch (isc_sockaddr_pf(src)) {
	case AF_INET:
		if (isc_netaddr_equal(&src_addr, &zerov4)) {
			return false;
		}

		if (isc_netaddr_equal(&dst_addr, &zerov4)) {
			return false;
		}
		break;
	case AF_INET6:
		if (isc_netaddr_equal(&src_addr, &zerov6)) {
			return false;
		}

		if (isc_netaddr_equal(&dst_addr, &zerov6)) {
			return false;
		}
		break;
	default:
		UNREACHABLE();
	}

	return true;
}

void
isc_nm_set_maxage(isc_nmhandle_t *handle, const uint32_t ttl) {
	isc_nmsocket_t *sock = NULL;

	REQUIRE(VALID_NMHANDLE(handle));
	REQUIRE(VALID_NMSOCK(handle->sock));
	REQUIRE(!handle->sock->client);

#if !HAVE_LIBNGHTTP2
	UNUSED(ttl);
#endif

	sock = handle->sock;
	switch (sock->type) {
#if HAVE_LIBNGHTTP2
	case isc_nm_httpsocket:
		isc__nm_http_set_maxage(handle, ttl);
		break;
#endif /* HAVE_LIBNGHTTP2 */
	case isc_nm_udpsocket:
	case isc_nm_proxyudpsocket:
	case isc_nm_streamdnssocket:
		return;
		break;
	case isc_nm_tcpsocket:
	case isc_nm_tlssocket:
	case isc_nm_proxystreamsocket:
	default:
		UNREACHABLE();
		break;
	}
}

isc_nmsocket_type
isc_nm_socket_type(const isc_nmhandle_t *handle) {
	REQUIRE(VALID_NMHANDLE(handle));
	REQUIRE(VALID_NMSOCK(handle->sock));

	return handle->sock->type;
}

isc_nm_proxy_type_t
isc_nmhandle_proxy_type(isc_nmhandle_t *handle) {
	isc_nmhandle_t *proxyhandle;

	REQUIRE(VALID_NMHANDLE(handle));
	REQUIRE(VALID_NMSOCK(handle->sock));

	proxyhandle = get_proxy_handle(handle);

	if (proxyhandle == NULL) {
		return ISC_NM_PROXY_NONE;
	}

	if (isc_nm_has_encryption(proxyhandle)) {
		return ISC_NM_PROXY_ENCRYPTED;
	}

	return ISC_NM_PROXY_PLAIN;
}

bool
isc_nm_has_encryption(const isc_nmhandle_t *handle) {
	REQUIRE(VALID_NMHANDLE(handle));
	REQUIRE(VALID_NMSOCK(handle->sock));

	if (handle->sock->ops->has_encryption != NULL) {
		return handle->sock->ops->has_encryption(handle);
	}

	return false;
}

const char *
isc_nm_verify_tls_peer_result_string(const isc_nmhandle_t *handle) {
	isc_nmsocket_t *sock = NULL;

	REQUIRE(VALID_NMHANDLE(handle));
	REQUIRE(VALID_NMSOCK(handle->sock));

	sock = handle->sock;
	if (sock->ops->verify_tls_peer != NULL) {
		return sock->ops->verify_tls_peer(handle);
	}

	return NULL;
}

typedef struct settlsctx_data {
	isc_nmsocket_t *listener;
	isc_tlsctx_t *tlsctx;
} settlsctx_data_t;

static void
settlsctx_cb(void *arg) {
	settlsctx_data_t *data = arg;
	const isc_tid_t tid = isc_tid();
	isc_nmsocket_t *listener = data->listener;
	isc_tlsctx_t *tlsctx = data->tlsctx;
	isc__networker_t *worker = isc__networker_current();

	isc_mem_put(worker->loop->mctx, data, sizeof(*data));

	REQUIRE(listener->type == isc_nm_tlslistener);

	isc__nm_async_tls_set_tlsctx(listener, tlsctx, tid);

	isc__nmsocket_detach(&listener);
	isc_tlsctx_free(&tlsctx);
}

static void
set_tlsctx_workers(isc_nmsocket_t *listener, isc_tlsctx_t *tlsctx) {
	const size_t nworkers = (size_t)isc_loopmgr_nloops();
	/* Update the TLS context reference for every worker thread. */
	for (size_t i = 0; i < nworkers; i++) {
		isc__networker_t *worker = isc__networker_get(i);
		settlsctx_data_t *data = isc_mem_cget(worker->loop->mctx, 1,
						      sizeof(*data));

		isc__nmsocket_attach(listener, &data->listener);
		isc_tlsctx_attach(tlsctx, &data->tlsctx);

		isc_async_run(worker->loop, settlsctx_cb, data);
	}
}

void
isc_nmsocket_set_tlsctx(isc_nmsocket_t *listener, isc_tlsctx_t *tlsctx) {
	REQUIRE(VALID_NMSOCK(listener));
	REQUIRE(tlsctx != NULL);

	switch (listener->type) {
#if HAVE_LIBNGHTTP2
	case isc_nm_httplistener:
		/*
		 * We handle HTTP listener sockets differently, as they rely
		 * on underlying TLS sockets for networking. The TLS context
		 * will get passed to these underlying sockets via the call to
		 * isc__nm_http_set_tlsctx().
		 */
		isc__nm_http_set_tlsctx(listener, tlsctx);
		break;
#endif /* HAVE_LIBNGHTTP2 */
	case isc_nm_tlslistener:
		set_tlsctx_workers(listener, tlsctx);
		break;
	case isc_nm_streamdnslistener:
		isc__nm_streamdns_set_tlsctx(listener, tlsctx);
		break;
	case isc_nm_proxystreamlistener:
		isc__nm_proxystream_set_tlsctx(listener, tlsctx);
		break;
	default:
		UNREACHABLE();
		break;
	};
}

void
isc_nmsocket_set_max_streams(isc_nmsocket_t *listener,
			     const uint32_t max_streams) {
	REQUIRE(VALID_NMSOCK(listener));
	switch (listener->type) {
#if HAVE_LIBNGHTTP2
	case isc_nm_httplistener:
		isc__nm_http_set_max_streams(listener, max_streams);
		break;
#endif /* HAVE_LIBNGHTTP2 */
	default:
		UNUSED(max_streams);
		break;
	};
	return;
}

void
isc__nmsocket_log_tls_session_reuse(isc_nmsocket_t *sock, isc_tls_t *tls) {
	const int log_level = ISC_LOG_DEBUG(1);
	char client_sabuf[ISC_SOCKADDR_FORMATSIZE];
	char local_sabuf[ISC_SOCKADDR_FORMATSIZE];

	REQUIRE(tls != NULL);

	if (!isc_log_wouldlog(log_level)) {
		return;
	};

	isc_sockaddr_format(&sock->peer, client_sabuf, sizeof(client_sabuf));
	isc_sockaddr_format(&sock->iface, local_sabuf, sizeof(local_sabuf));
	isc__nmsocket_log(sock, log_level, "TLS %s session %s for %s on %s",
			  SSL_is_server(tls) ? "server" : "client",
			  SSL_session_reused(tls) ? "resumed" : "created",
			  client_sabuf, local_sabuf);
}

static void
isc__networker_destroy(isc__networker_t *worker) {
	isc__netmgr_log(ISC_LOG_DEBUG(1),
			"Destroying network manager worker on loop %p(%" PRItid
			")",
			worker->loop, isc_tid());

	isc_loop_detach(&worker->loop);

	isc_mempool_destroy(&worker->uvreq_pool);
	isc_mempool_destroy(&worker->nmsocket_pool_overlay);
	isc_mempool_destroy(&worker->nmsocket_pool_udp);
	isc_mempool_destroy(&worker->nmsocket_pool);

	isc_mem_putanddetach(&worker->mctx, worker->recvbuf,
			     ISC_NETMGR_RECVBUF_SIZE);

	isc__netmgr_unref(isc__netmgr);
}

ISC_REFCOUNT_IMPL(isc__networker, isc__networker_destroy);

void
isc__netmgr_log(int level, const char *fmt, ...) {
	char msgbuf[2048];
	va_list ap;

	if (!isc_log_wouldlog(level)) {
		return;
	}

	va_start(ap, fmt);
	vsnprintf(msgbuf, sizeof(msgbuf), fmt, ap);
	va_end(ap);

	isc_log_write(ISC_LOGCATEGORY_GENERAL, ISC_LOGMODULE_NETMGR, level,
		      "netmgr %p: %s", isc__netmgr, msgbuf);
}

void
isc__nmsocket_log(const isc_nmsocket_t *sock, int level, const char *fmt, ...) {
	char msgbuf[2048];
	va_list ap;

	if (!isc_log_wouldlog(level)) {
		return;
	}

	va_start(ap, fmt);
	vsnprintf(msgbuf, sizeof(msgbuf), fmt, ap);
	va_end(ap);

	isc_log_write(ISC_LOGCATEGORY_GENERAL, ISC_LOGMODULE_NETMGR, level,
		      "socket %p: %s", sock, msgbuf);
}

void
isc__nmhandle_log(const isc_nmhandle_t *handle, int level, const char *fmt,
		  ...) {
	char msgbuf[2048];
	va_list ap;

	if (!isc_log_wouldlog(level)) {
		return;
	}

	va_start(ap, fmt);
	vsnprintf(msgbuf, sizeof(msgbuf), fmt, ap);
	va_end(ap);

	isc__nmsocket_log(handle->sock, level, "handle %p: %s", handle, msgbuf);
}

void
isc__nm_received_proxy_header_log(isc_nmhandle_t *handle,
				  const isc_proxy2_command_t cmd,
				  const int socktype,
				  const isc_sockaddr_t *restrict src_addr,
				  const isc_sockaddr_t *restrict dst_addr,
				  const isc_region_t *restrict tlvs) {
	const int log_level = ISC_LOG_DEBUG(1);
	isc_sockaddr_t real_local, real_peer;
	char real_local_fmt[ISC_SOCKADDR_FORMATSIZE] = { 0 };
	char real_peer_fmt[ISC_SOCKADDR_FORMATSIZE] = { 0 };
	char common_msg[512] = { 0 };
	const char *proto = NULL;
	const char *real_addresses_msg =
		"real source and destination addresses are used";

	if (!isc_log_wouldlog(log_level)) {
		return;
	}

	if (isc_nmhandle_is_stream(handle)) {
		proto = isc_nm_has_encryption(handle) ? "TLS" : "TCP";
	} else {
		proto = "UDP";
	}

	real_local = isc_nmhandle_real_localaddr(handle);
	real_peer = isc_nmhandle_real_peeraddr(handle);

	isc_sockaddr_format(&real_local, real_local_fmt,
			    sizeof(real_local_fmt));

	isc_sockaddr_format(&real_peer, real_peer_fmt, sizeof(real_peer_fmt));

	(void)snprintf(common_msg, sizeof(common_msg),
		       "Received a PROXYv2 header from %s on %s over %s",
		       real_peer_fmt, real_local_fmt, proto);

	if (cmd == ISC_PROXY2_CMD_LOCAL) {
		isc_log_write(ISC_LOGCATEGORY_GENERAL, ISC_LOGMODULE_NETMGR,
			      log_level, "%s: command: LOCAL (%s)", common_msg,
			      real_addresses_msg);
		return;
	} else if (cmd == ISC_PROXY2_CMD_PROXY) {
		const char *tlvs_msg = tlvs == NULL ? "no" : "yes";
		const char *socktype_name = NULL;
		const char *src_addr_msg = "(none)", *dst_addr_msg = "(none)";
		char src_addr_fmt[ISC_SOCKADDR_FORMATSIZE] = { 0 };
		char dst_addr_fmt[ISC_SOCKADDR_FORMATSIZE] = { 0 };

		switch (socktype) {
		case 0:
			isc_log_write(ISC_LOGCATEGORY_GENERAL,
				      ISC_LOGMODULE_NETMGR, log_level,
				      "%s: command: PROXY (unspecified address "
				      "and socket type, %s)",
				      common_msg, real_addresses_msg);
			return;
		case SOCK_STREAM:
			socktype_name = "SOCK_STREAM";
			break;
		case SOCK_DGRAM:
			socktype_name = "SOCK_DGRAM";
			break;
		default:
			UNREACHABLE();
		}

		if (src_addr) {
			isc_sockaddr_format(src_addr, src_addr_fmt,
					    sizeof(src_addr_fmt));
			src_addr_msg = src_addr_fmt;
		}

		if (dst_addr) {
			isc_sockaddr_format(dst_addr, dst_addr_fmt,
					    sizeof(dst_addr_fmt));
			dst_addr_msg = dst_addr_fmt;
		}

		isc_log_write(ISC_LOGCATEGORY_GENERAL, ISC_LOGMODULE_NETMGR,
			      log_level,
			      "%s: command: PROXY, socket type: %s, source: "
			      "%s, destination: %s, TLVs: %s",
			      common_msg, socktype_name, src_addr_msg,
			      dst_addr_msg, tlvs_msg);
	}
}

void
isc__nmhandle_set_manual_timer(isc_nmhandle_t *handle, const bool manual) {
	REQUIRE(VALID_NMHANDLE(handle));
	REQUIRE(VALID_NMSOCK(handle->sock));

	isc_nmsocket_t *sock = handle->sock;

	REQUIRE(sock->ops->set_manual_timer != NULL);
	sock->ops->set_manual_timer(handle, manual);
}

void
isc__nmhandle_get_selected_alpn(isc_nmhandle_t *handle,
				const unsigned char **alpn,
				unsigned int *alpnlen) {
	REQUIRE(VALID_NMHANDLE(handle));
	REQUIRE(VALID_NMSOCK(handle->sock));

	isc_nmsocket_t *sock = handle->sock;

	if (sock->ops->get_selected_alpn != NULL) {
		sock->ops->get_selected_alpn(handle, alpn, alpnlen);
	}
}

isc_result_t
isc_nmhandle_set_tcp_nodelay(isc_nmhandle_t *handle, const bool value) {
	REQUIRE(VALID_NMHANDLE(handle));
	REQUIRE(VALID_NMSOCK(handle->sock));

	isc_result_t result = ISC_R_FAILURE;
	isc_nmsocket_t *sock = handle->sock;

	REQUIRE(sock->ops->set_tcp_nodelay != NULL);
	result = sock->ops->set_tcp_nodelay(handle, value);

	return result;
}

isc_sockaddr_t
isc_nmsocket_getaddr(isc_nmsocket_t *sock) {
	REQUIRE(VALID_NMSOCK(sock));
	return sock->iface;
}

void
isc_nm_proxyheader_info_init(isc_nm_proxyheader_info_t *restrict info,
			     isc_sockaddr_t *restrict src_addr,
			     isc_sockaddr_t *restrict dst_addr,
			     isc_region_t *restrict tlv_data) {
	REQUIRE(info != NULL);
	REQUIRE(src_addr != NULL);
	REQUIRE(dst_addr != NULL);
	REQUIRE(tlv_data == NULL ||
		(tlv_data->length > 0 && tlv_data->base != NULL));

	*info = (isc_nm_proxyheader_info_t){ .proxy_info.src_addr = *src_addr,
					     .proxy_info.dst_addr = *dst_addr };
	if (tlv_data != NULL) {
		info->proxy_info.tlv_data = *tlv_data;
	}
}

void
isc_nm_proxyheader_info_init_complete(isc_nm_proxyheader_info_t *restrict info,
				      isc_region_t *restrict header_data) {
	REQUIRE(info != NULL);
	REQUIRE(header_data != NULL);
	REQUIRE(header_data->base != NULL &&
		header_data->length >= ISC_PROXY2_HEADER_SIZE);

	*info = (isc_nm_proxyheader_info_t){ .complete = true,
					     .complete_header = *header_data };
}

isc__networker_t *
isc__networker_current(void) {
	REQUIRE(VALID_NM(isc__netmgr));
	return &isc__netmgr->workers[isc_tid()];
}

isc__networker_t *
isc__networker_get(uint32_t tid) {
	REQUIRE(VALID_NM(isc__netmgr));
	return &isc__netmgr->workers[tid];
}

void
isc_netmgr_portrange(sa_family_t af, in_port_t low, in_port_t high) {
	REQUIRE(VALID_NM(isc__netmgr));
	switch (af) {
	case AF_INET:
		atomic_store_relaxed(&isc__netmgr->port_low4, low);
		atomic_store_relaxed(&isc__netmgr->port_high4, high);
		break;
	case AF_INET6:
		atomic_store_relaxed(&isc__netmgr->port_low6, low);
		atomic_store_relaxed(&isc__netmgr->port_high6, high);
		break;
	default:
		INSIST(0);
	}
}

#if ISC_NETMGR_TRACE
/*
 * Dump all active sockets in netmgr. We output to stderr
 * as the logger might be already shut down.
 */

static const char *
nmsocket_type_totext(isc_nmsocket_type type) {
	switch (type) {
	case isc_nm_udpsocket:
		return "isc_nm_udpsocket";
	case isc_nm_udplistener:
		return "isc_nm_udplistener";
	case isc_nm_tcpsocket:
		return "isc_nm_tcpsocket";
	case isc_nm_tcplistener:
		return "isc_nm_tcplistener";
	case isc_nm_tlssocket:
		return "isc_nm_tlssocket";
	case isc_nm_tlslistener:
		return "isc_nm_tlslistener";
	case isc_nm_httplistener:
		return "isc_nm_httplistener";
	case isc_nm_httpsocket:
		return "isc_nm_httpsocket";
	case isc_nm_streamdnslistener:
		return "isc_nm_streamdnslistener";
	case isc_nm_streamdnssocket:
		return "isc_nm_streamdnssocket";
	case isc_nm_proxystreamlistener:
		return "isc_nm_proxystreamlistener";
	case isc_nm_proxystreamsocket:
		return "isc_nm_proxystreamsocket";
	case isc_nm_proxyudplistener:
		return "isc_nm_proxyudplistener";
	case isc_nm_proxyudpsocket:
		return "isc_nm_proxyudpsocket";
	default:
		UNREACHABLE();
	}
}

static void
nmhandle_dump(isc_nmhandle_t *handle) {
	fprintf(stderr, "Active handle %p, refs %" PRIuFAST32 "\n", handle,
		isc_refcount_current(&handle->references));
	fprintf(stderr, "Created by:\n");
	isc_backtrace_symbols_fd(handle->backtrace, handle->backtrace_size,
				 STDERR_FILENO);
	fprintf(stderr, "\n\n");
}

static void
nmsocket_dump(isc_nmsocket_t *sock) {
	fprintf(stderr, "\n=================\n");
	fprintf(stderr, "Active %s socket %p, type %s, refs %" PRIuFAST32 "\n",
		sock->client ? "client" : "server", sock,
		nmsocket_type_totext(sock->type),
		isc_refcount_current(&sock->references));
	fprintf(stderr,
		"Parent %p, listener %p, server %p, statichandle = "
		"%p\n",
		sock->parent, sock->listener, sock->server, sock->statichandle);
	fprintf(stderr, "Flags:%s%s%s%s%s\n", sock->active ? " active" : "",
		sock->closing ? " closing" : "",
		sock->destroying ? " destroying" : "",
		sock->connecting ? " connecting" : "",
		sock->accepting ? " accepting" : "");
	fprintf(stderr, "Created by:\n");
	isc_backtrace_symbols_fd(sock->backtrace, sock->backtrace_size,
				 STDERR_FILENO);
	fprintf(stderr, "\n");

	ISC_LIST_FOREACH(sock->active_handles, handle, active_link) {
		static bool first = true;
		if (first) {
			fprintf(stderr, "Active handles:\n");
			first = false;
		}
		nmhandle_dump(handle);
	}

	fprintf(stderr, "\n");
}

void
isc__nm_dump_active(isc__networker_t *worker) {
	bool first = true;

	ISC_LIST_FOREACH(worker->active_sockets, sock, active_link) {
		if (first) {
			fprintf(stderr, "Outstanding sockets\n");
			first = false;
		}
		nmsocket_dump(sock);
	}
}

void
isc__nm_dump_active_manager(void) {
	for (size_t i = 0; i < isc__netmgr->nloops; i++) {
		isc__networker_t *worker = isc__networker_get(i);

		if (!ISC_LIST_EMPTY(worker->active_sockets)) {
			fprintf(stderr, "Worker #%zu (%p)\n", i, worker);
			isc__nm_dump_active(worker);
		}
	}
}
#endif
