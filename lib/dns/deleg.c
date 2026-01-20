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
#include <isc/magic.h>
#include <isc/mem.h>
#include <isc/netaddr.h>
#include <isc/stdtime.h>
#include <isc/uv.h>

#include <dns/deleg.h>
#include <dns/name.h>
#include <dns/qp.h>

#define DELEGDB_NODE_MAGIC	 ISC_MAGIC('D', 'e', 'G', 'N')
#define VALID_DELEGDB_NODE(node) ISC_MAGIC_VALID(node, DELEGDB_NODE_MAGIC)

#define DELEGDB_MAGIC	  ISC_MAGIC('D', 'e', 'G', 'D')
#define VALID_DELEGDB(db) ISC_MAGIC_VALID(db, DELEGDB_MAGIC)

#define DELEGDB_HASH_SIZE (1 << 12)

typedef struct delegdb_node delegdb_node_t;
struct delegdb_node {
	unsigned int magic;
	isc_mem_t *mctx;
	isc_refcount_t references;
	dns_name_t zonecut;
	dns_delegset_t *delegset;
};

static void
delegdb_node_destroy(delegdb_node_t *node) {
	REQUIRE(VALID_DELEGDB_NODE(node));

	dns_delegset_detach(&node->delegset);
	dns_name_free(&node->zonecut, node->mctx);
	isc_mem_putanddetach(&node->mctx, node, sizeof(*node));
}

ISC_REFCOUNT_STATIC_IMPL(delegdb_node, delegdb_node_destroy);

struct dns_delegdb {
	unsigned int magic;

	/*
	 * The DB uses its own memory context in order to easilly enforce
	 * overmem policies based on allocations did from this memory context.
	 * (To be done: LRU/SIEVE, API to set a watermark in the mem context and
	 * delete expired and less used nodes)
	 */
	isc_mem_t *mctx;
	isc_refcount_t references;

	dns_qpmulti_t *nodes;
};

static void
delegdb_destroy(dns_delegdb_t *db) {
	REQUIRE(VALID_DELEGDB(db));

	db->magic = 0;
	dns_qpmulti_destroy(&db->nodes);
	isc_mem_putanddetach(&db->mctx, db, sizeof(*db));
}

ISC_REFCOUNT_STATIC_IMPL(dns_delegdb, delegdb_destroy);

static void
dbnode_attach(ISC_ATTR_UNUSED void *uctx, void *pval,
	      ISC_ATTR_UNUSED uint32_t ival) {
	delegdb_node_t *node = pval;

	REQUIRE(VALID_DELEGDB_NODE(node));
	delegdb_node_ref(node);
}

static void
dbnode_detach(ISC_ATTR_UNUSED void *uctx, void *pval,
	      ISC_ATTR_UNUSED uint32_t ival) {
	delegdb_node_t *node = pval;

	REQUIRE(VALID_DELEGDB_NODE(node));
	delegdb_node_unref(node);
}

static size_t
makekey(dns_qpkey_t key, void *uctx ISC_ATTR_UNUSED, void *pval,
	uint32_t ival ISC_ATTR_UNUSED) {
	delegdb_node_t *data = pval;
	return dns_qpkey_fromname(key, &data->zonecut, DNS_DBNAMESPACE_NORMAL);
}

static void
triename(ISC_ATTR_UNUSED void *uctx, char *buf, size_t size) {
	(void)strncpy(buf, "delegdb", size);
}

static dns_qpmethods_t qpmethods = { .attach = dbnode_attach,
				     .detach = dbnode_detach,
				     .makekey = makekey,
				     .triename = triename };

void
dns_deleg_init(dns_delegdb_t **dbp) {
	isc_mem_t *mctx = NULL;
	dns_delegdb_t *db = NULL;

	REQUIRE(dbp != NULL && *dbp == NULL);

	isc_mem_create("dns_delegdb", &mctx);
	isc_mem_setdestroycheck(mctx, true);

	/*
	 * isc_mem_debugon(0) returns the memory debug flags set from
	 * environment variables, command line option, etc.
	 */
	isc_mem_setdebugging(mctx, isc_mem_debugon(0));

	db = isc_mem_get(mctx, sizeof(*db));
	*db = (dns_delegdb_t){
		.magic = DELEGDB_MAGIC,
		.references = ISC_REFCOUNT_INITIALIZER(1),
	};

	dns_qpmulti_create(mctx, &qpmethods, &db->nodes, &db->nodes);
	isc_mem_attach(mctx, &db->mctx);
	isc_mem_detach(&mctx);

	INSIST(db->nodes != NULL);
	*dbp = db;
}

void
dns_deleg_flush(dns_delegdb_t *db) {
	REQUIRE(VALID_DELEGDB(db));

	dns_qpmulti_destroy(&db->nodes);
	dns_qpmulti_create(db->mctx, &qpmethods, &db->nodes, &db->nodes);
}

void
dns_deleg_shutdownanddetach(dns_delegdb_t **db) {
	REQUIRE(db != NULL && VALID_DELEGDB(*db));

	/*
	 * For now, nothing to do really... But with LRU/SIEVE handling, things
	 * might gets more complicated here.
	 */
	dns_delegdb_detach(db);
}

inline static bool
isactive(delegdb_node_t *node, dns_ttl_t now) {
	/*
	 * Those two requires must go away, I just left them for now as I'm
	 * trying to chasse down a rare and random segfault here. (And a stack
	 * which makes no sense.)
	 */
	REQUIRE(VALID_DELEGDB_NODE(node));
	REQUIRE(DNS_DELEGSET_DBATTACHED_VALID(node->delegset));
	return node->delegset->ttl > now;
}

static void
getparentnode(dns_qpchain_t *chain, delegdb_node_t **node, dns_ttl_t now) {
	size_t len = dns_qpchain_length(chain);

	while (len >= 2) {
		*node = NULL;
		dns_qpchain_node(chain, len - 2, (void **)node, NULL);

		if (isactive(*node, now)) {
			break;
		}
		len--;
	}
}

/*
 * TODO about the `deepestzonecut`. Sounds like needed to be able to have the
 * zonecut we would have if we haven't to look up in the DNS tree (because of
 * DNS_DBFIND_NOEXACT or because of an expired node). Likely used only in qmin
 * flow.
 *
 * But there is no system test which seems to test it (i.e. if I remove the
 * `getparentnode()` logic, and simply copy the found zonecut into
 * deepestzonecut, all tests still pass). So some system tests probably need to
 * be added. Also I'm not 100% sure I followed the exact same semantic than in
 * qpcache regarding this, so this probably need to be tweaked a bit.
 */
isc_result_t
dns_deleg_lookup(dns_delegdb_t *db, const dns_name_t *name,
		 isc_stdtime_t optnow, unsigned int options,
		 dns_name_t *zonecut, dns_name_t *deepestzonecut,
		 dns_delegset_t **delegset) {
	isc_result_t result = ISC_R_SUCCESS;
	delegdb_node_t *node = NULL;
	isc_stdtime_t now = optnow > 0 ? optnow : isc_stdtime_now();
	dns_qpread_t qpr = {};
	dns_qpchain_t chain = {};
	bool noexact = options & DNS_DBFIND_NOEXACT;

	REQUIRE(VALID_DELEGDB(db));
	REQUIRE(DNS_NAME_VALID(name));
	REQUIRE(dns_name_hasbuffer(zonecut));
	REQUIRE(deepestzonecut == NULL || dns_name_hasbuffer(zonecut));

	dns_qpmulti_query(db->nodes, &qpr);

	result = dns_qp_lookup(&qpr, name, DNS_DBNAMESPACE_NORMAL, NULL, &chain,
			       (void **)&node, NULL);

	if (result != ISC_R_SUCCESS && result != DNS_R_PARTIALMATCH) {
		CLEANUP(ISC_R_NOTFOUND);
	}
	INSIST(VALID_DELEGDB_NODE(node));

	if (result == ISC_R_SUCCESS && noexact) {
		size_t len = dns_qpchain_length(&chain);
		if (len < 2) {
			CLEANUP(ISC_R_NOTFOUND);
		}
	}

	if (deepestzonecut != NULL) {
		dns_name_copy(&node->zonecut, deepestzonecut);
	}

	if (result == ISC_R_SUCCESS && (noexact || !isactive(node, now))) {
		getparentnode(&chain, &node, now);
	} else if (result == DNS_R_PARTIALMATCH && !isactive(node, now)) {
		getparentnode(&chain, &node, now);
	}

	result = isactive(node, now) ? ISC_R_SUCCESS : ISC_R_NOTFOUND;
	if (result == ISC_R_SUCCESS) {
		dns_name_copy(&node->zonecut, zonecut);
		if (delegset != NULL) {
			dns_delegset_attach(node->delegset, delegset);
			INSIST(DNS_DELEGSET_DBATTACHED_VALID(*delegset));
		}
	}

cleanup:
	dns_qpread_destroy(db->nodes, &qpr);

	return result;
}

void
dns_deleg_allocset(dns_delegdb_t *db, dns_delegset_t **delegsetp) {
	dns_delegset_t *delegset = NULL;

	REQUIRE(VALID_DELEGDB(db));
	REQUIRE(delegsetp != NULL && *delegsetp == NULL);

	delegset = isc_mem_get(db->mctx, sizeof(*delegset));
	*delegset = (dns_delegset_t){ .magic = DNS_DELEGSET_DBDETACHED_MAGIC,
				      .references = ISC_REFCOUNT_INITIALIZER(1),
				      .deleg = ISC_LIST_INITIALIZER };
	isc_mem_attach(db->mctx, &delegset->mctx);

	*delegsetp = delegset;
}

void
dns_deleg_allocdeleg(dns_delegset_t *delegset, dns_deleg_t **delegp) {
	dns_deleg_t *deleg = NULL;

	REQUIRE(DNS_DELEGSET_DBDETACHED_VALID(delegset));
	REQUIRE(delegp != NULL && *delegp == NULL);

	deleg = isc_mem_get(delegset->mctx, sizeof(*deleg));
	*deleg = (dns_deleg_t){ .address = ISC_LIST_INITIALIZER,
				.delegi = ISC_LIST_INITIALIZER,
				.nameserver = ISC_LIST_INITIALIZER,
				.link = ISC_LINK_INITIALIZER };

	ISC_LIST_APPEND(delegset->deleg, deleg, link);
	*delegp = deleg;
}

/*
 * TODO: dns_deleg_addaddr() and addname() needs to check if the new entry is
 * not already in the list.
 */
void
dns_deleg_addaddr(dns_delegset_t *delegset, dns_deleg_t *deleg,
		  const isc_netaddr_t *addr) {
	isc_netaddrlink_t *addrlink = NULL;

	REQUIRE(DNS_DELEGSET_DBDETACHED_VALID(delegset));
	REQUIRE(deleg != NULL);
	REQUIRE(addr != NULL);

	addrlink = isc_mem_get(delegset->mctx, sizeof(*addrlink));
	*addrlink = (isc_netaddrlink_t){ .addr = *addr,
					 .link = ISC_LINK_INITIALIZER };

	ISC_LIST_APPEND(deleg->address, addrlink, link);
}

static void
addname(dns_delegset_t *delegset, dns_namelist_t *list,
	const dns_name_t *name) {
	dns_name_t *clone = NULL;

	REQUIRE(DNS_DELEGSET_DBDETACHED_VALID(delegset));
	REQUIRE(DNS_NAME_VALID(name));

	clone = isc_mem_get(delegset->mctx, sizeof(*clone));
	dns_name_init(clone);
	dns_name_dup(name, delegset->mctx, clone);
	ISC_LIST_APPEND(*list, clone, link);
}

void
dns_deleg_adddelegi(dns_delegset_t *delegset, dns_deleg_t *deleg,
		    const dns_name_t *name) {
	REQUIRE(deleg != NULL);
	addname(delegset, &deleg->delegi, name);
}

void
dns_deleg_addns(dns_delegset_t *delegset, dns_deleg_t *deleg,
		const dns_name_t *name) {
	REQUIRE(deleg != NULL);
	addname(delegset, &deleg->nameserver, name);
}

void
dns_deleg_writeset(dns_delegdb_t *db, const dns_name_t *zonecut,
		   dns_ttl_t expire, dns_delegset_t **delegset) {
	isc_result_t result;
	delegdb_node_t *node = NULL;
	dns_qp_t *qp = NULL;

	REQUIRE(VALID_DELEGDB(db));
	REQUIRE(DNS_NAME_VALID(zonecut));
	REQUIRE(delegset != NULL && DNS_DELEGSET_DBDETACHED_VALID(*delegset));

	if (expire == 0) {
		expire = 1;
	}
	(*delegset)->ttl = expire + isc_stdtime_now();

	dns_qpmulti_write(db->nodes, &qp);
	result = dns_qp_lookup(qp, zonecut, DNS_DBNAMESPACE_NORMAL, NULL, NULL,
			       (void **)&node, NULL);

	if (result == ISC_R_SUCCESS) {
		/*
		 * The zonecut already exists, so let's reuse it, but
		 * replace the previous delegation set with a fresh one.
		 * (Actually, should this enforces a check that the TTL
		 * is expired? Otherwise, this is suspicious.)
		 */
		dns_delegset_detach(&node->delegset);
	} else {
		node = isc_mem_get(db->mctx, sizeof(*node));
		*node = (delegdb_node_t){
			.magic = DELEGDB_NODE_MAGIC,
			.references = ISC_REFCOUNT_INITIALIZER(1),
			.zonecut = DNS_NAME_INITEMPTY,
		};

		isc_mem_attach(db->mctx, &node->mctx);
		dns_name_dup(zonecut, db->mctx, &node->zonecut);

		result = dns_qp_insert(qp, node, 0);
		INSIST(result == ISC_R_SUCCESS);
		delegdb_node_unref(node);
	}

	dns_delegset_attach(*delegset, &node->delegset);
	(*delegset)->magic = DNS_DELEGSET_DBATTACHED_MAGIC;

	/*
	 * Probably shouldn't be run at every write?
	 */
	dns_qp_compact(qp, DNS_QPGC_MAYBE);
	dns_qpmulti_commit(db->nodes, &qp);

	dns_delegset_detach(delegset);
}

static void
delegset_destroy(dns_delegset_t *delegset) {
	REQUIRE(DNS_DELEGSET_VALID(delegset));

	delegset->magic = 0;
	ISC_LIST_FOREACH(delegset->deleg, deleg, link) {
		ISC_LIST_UNLINK(delegset->deleg, deleg, link);

		ISC_LIST_FOREACH(deleg->address, address, link) {
			ISC_LIST_UNLINK(deleg->address, address, link);
			isc_mem_put(delegset->mctx, address, sizeof(*address));
		}

		ISC_LIST_FOREACH(deleg->delegi, delegi, link) {
			ISC_LIST_UNLINK(deleg->delegi, delegi, link);
			dns_name_free(delegi, delegset->mctx);
			isc_mem_put(delegset->mctx, delegi, sizeof(*delegi));
		}

		ISC_LIST_FOREACH(deleg->nameserver, nameserver, link) {
			ISC_LIST_UNLINK(deleg->nameserver, nameserver, link);
			dns_name_free(nameserver, delegset->mctx);
			isc_mem_put(delegset->mctx, nameserver,
				    sizeof(*nameserver));
		}

		isc_mem_put(delegset->mctx, deleg, sizeof(*deleg));
	}

	isc_mem_putanddetach(&delegset->mctx, delegset, sizeof(*delegset));
}
ISC_REFCOUNT_IMPL(dns_delegset, delegset_destroy);

static void
tostring_namelist(dns_namelist_t *namelist, const char *id, isc_buffer_t *b) {
	if (!ISC_LIST_EMPTY(*namelist)) {
		isc_buffer_printf(b, "\n\t%s=\n\t\t", id);
		ISC_LIST_FOREACH(*namelist, name, link) {
			isc_buffer_t nameb;
			char bdata[DNS_NAME_MAXWIRE] = { 0 };

			isc_buffer_init(&nameb, bdata, sizeof(bdata));
			dns_name_totext(name, 0, &nameb);
			isc_buffer_putstr(b, bdata);

			if (name != ISC_LIST_TAIL(*namelist)) {
				isc_buffer_putstr(b, ",\n\t\t");
			}
		}
	}
}

static void
delegset_tostring(const dns_name_t *zonecut, dns_delegset_t *delegset,
		  isc_stdtime_t now, isc_buffer_t *b) {
	ISC_LIST_FOREACH(delegset->deleg, deleg, link) {
		bool hasv4 = false;
		bool hasv6 = false;
		isc_buffer_t zonecutb;
		char bdata[DNS_NAME_MAXWIRE];
		dns_ttl_t ttl = delegset->ttl - now;

		INSIST(ttl > 0);
		isc_buffer_init(&zonecutb, bdata, sizeof(bdata));
		dns_name_totext(zonecut, 0, &zonecutb);
		isc_buffer_printf(b, "%s DELEG %d", bdata, ttl);
		ISC_LIST_FOREACH(deleg->address, address, link) {
			if (address->addr.family == AF_INET) {
				hasv4 = true;
			} else {
				hasv6 = true;
			}
		}

		if (hasv4) {
			bool first = true;

			isc_buffer_putstr(b, "\n\tserver-ipv4=\n\t\t");
			ISC_LIST_FOREACH(deleg->address, address, link) {
				char addrstr[] = "255.255.255.255";

				if (address->addr.family == AF_INET6) {
					continue;
				}

				if (!first) {
					isc_buffer_putstr(b, ",\n\t\t");
				}
				first = false;

				inet_ntop(AF_INET, &address->addr.type, addrstr,
					  sizeof(addrstr));
				isc_buffer_putstr(b, addrstr);
			}
		}

		if (hasv6) {
			bool first = true;

			isc_buffer_putstr(b, "\n\tserver-ipv6=\n\t\t");
			ISC_LIST_FOREACH(deleg->address, address, link) {
				char addrstr[] = "FFFF:FFFF:FFFFF:FFFFF:FFFF:"
						 "FFFF:FFFFF:FFFFF";

				if (address->addr.family == AF_INET) {
					continue;
				}

				if (!first) {
					isc_buffer_putstr(b, ",\n\t\t");
				}
				first = false;

				inet_ntop(AF_INET6, &address->addr.type,
					  addrstr, sizeof(addrstr));
				isc_buffer_putstr(b, addrstr);
			}
		}

		tostring_namelist(&deleg->nameserver, "server-name", b);
		tostring_namelist(&deleg->delegi, "include-delegi", b);

		if (deleg != ISC_LIST_TAIL(delegset->deleg)) {
			isc_buffer_putuint8(b, '\n');
		}
	}
}

/*
 * TODO: This will require some small tweaks in order to have the same format
 * from `rndc dumpdb`, so a new `rndc dumpdb -deleg` output would be consistent
 * with the existing output.
 * Current formatting sort of mimic a zone file RR, but adds tabs and indents
 * make it readable when debugging the DB/integration with the resolver.
 */
void
dns_deleg_dump(dns_delegdb_t *db, const dns_name_t *name, isc_stdtime_t optnow,
	       isc_buffer_t *b) {
	dns_qpiter_t it;
	dns_qpread_t qpr = {};
	delegdb_node_t *pnode = NULL, *node = NULL;
	isc_stdtime_t now = optnow > 0 ? optnow : isc_stdtime_now();

	REQUIRE(VALID_DELEGDB(db));
	REQUIRE(ISC_BUFFER_VALID(b));

	isc_buffer_clear(b);

	if (name != NULL) {
		isc_result_t result;
		dns_delegset_t *delegset = NULL;
		dns_fixedname_t fzonecut;
		dns_name_t *zonecut = dns_fixedname_initname(&fzonecut);

		REQUIRE(DNS_NAME_VALID(name));

		result = dns_deleg_lookup(db, name, now, 0, zonecut, NULL,
					  &delegset);
		if (result == ISC_R_SUCCESS) {
			delegset_tostring(zonecut, delegset, now, b);
			dns_delegset_detach(&delegset);
		}

		isc_buffer_putuint8(b, 0);
		return;
	}

	dns_qpmulti_query(db->nodes, &qpr);
	dns_qpiter_init(&qpr, &it);
	while (dns_qpiter_next(&it, (void **)&node, NULL) == ISC_R_SUCCESS) {
		if (!isactive(node, now)) {
			continue;
		}

		if (pnode != NULL) {
			isc_buffer_putuint8(b, '\n');
		}
		delegset_tostring(&node->zonecut, node->delegset, now, b);
		pnode = node;
	}
	isc_buffer_putuint8(b, 0);
	dns_qpread_destroy(db->nodes, &qpr);
}

void
dns_deleg_fromrdataset(dns_rdataset_t *rdataset, dns_delegset_t **delegsetp) {
	dns_delegset_t *delegset = NULL;
	dns_deleg_t *deleg = NULL;

	if (rdataset == NULL || !dns_rdataset_isassociated(rdataset) ||
	    delegsetp == NULL || *delegsetp != NULL)
	{
		return;
	}

	REQUIRE(rdataset->type == dns_rdatatype_ns);

	delegset = isc_mem_get(isc_g_mctx, sizeof(*delegset));
	*delegset = (dns_delegset_t){ .magic = DNS_DELEGSET_DBDETACHED_MAGIC,
				      .references = ISC_REFCOUNT_INITIALIZER(1),
				      .deleg = ISC_LIST_INITIALIZER,
				      .ttl = rdataset->ttl,
				      .staticstub =
					      rdataset->attributes.staticstub };
	isc_mem_attach(isc_g_mctx, &delegset->mctx);

	deleg = isc_mem_get(isc_g_mctx, sizeof(*deleg));
	*deleg = (dns_deleg_t){ .address = ISC_LIST_INITIALIZER,
				.delegi = ISC_LIST_INITIALIZER,
				.nameserver = ISC_LIST_INITIALIZER,
				.link = ISC_LINK_INITIALIZER };
	ISC_LIST_APPEND(delegset->deleg, deleg, link);

	DNS_RDATASET_FOREACH(rdataset) {
		dns_rdata_t rdata = DNS_RDATA_INIT;
		dns_rdata_ns_t ns;

		dns_rdataset_current(rdataset, &rdata);
		dns_rdata_tostruct(&rdata, &ns, NULL);
		dns_deleg_addns(delegset, deleg, &ns.name);
	}

	*delegsetp = delegset;
}
