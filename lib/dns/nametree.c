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

#include <stdbool.h>

#include <isc/async.h>
#include <isc/mem.h>
#include <isc/mutex.h>
#include <isc/refcount.h>
#include <isc/result.h>
#include <isc/string.h>
#include <isc/urcu.h>
#include <isc/util.h>

#include <dns/dbkey.h>
#include <dns/fixedname.h>
#include <dns/nametree.h>

#define NAMETREE_MAGIC	   ISC_MAGIC('N', 'T', 'r', 'e')
#define VALID_NAMETREE(kt) ISC_MAGIC_VALID(kt, NAMETREE_MAGIC)

static void
print_key(dns_qpkey_t key, size_t keylen) {
	fprintf(stderr, "KEY: '");
	for (size_t i = 0; i < keylen; i++) {
		fprintf(stderr, "%02x", key[i]);
	}
	fprintf(stderr, "\n");
}

static const char *
status2str(enum cds_ft_status status) {
	switch (status) {
	case CDS_FT_STATUS_OK:
		return "CDS_FT_STATUS_OK";
	case CDS_FT_STATUS_NOT_FOUND:
		return "CDS_FT_STATUS_NOT_FOUND";
	case CDS_FT_STATUS_DUPLICATE_FOUND:
		return "CDS_FT_STATUS_DUPLICATE_FOUND";
	case CDS_FT_STATUS_INTERNAL_MATCH:
		return "CDS_FT_STATUS_INTERNAL_MATCH";

	case CDS_FT_STATUS_INVALID_ARGUMENT_ERROR:
		return "CDS_FT_STATUS_INVALID_ARGUMENT_ERROR";
	case CDS_FT_STATUS_MEMORY_ERROR:
		return "CDS_FT_STATUS_MEMORY_ERROR";
	case CDS_FT_STATUS_OVERFLOW_ERROR:
		return "CDS_FT_STATUS_OVERFLOW_ERROR";
	case CDS_FT_STATUS_BUSY_ERROR:
		return "CDS_FT_STATUS_BUSY_ERROR";
	case CDS_FT_STATUS_POPULATED_ERROR:
		return "CDS_FT_STATUS_POPULATED_ERROR";
	case CDS_FT_STATUS_INTEGRITY_ERROR:
		return "CDS_FT_STATUS_INTEGRITY_ERROR";
	case CDS_FT_STATUS_NOT_SUPPORTED:
		return "CDS_FT_STATUS_NOT_SUPPORTED";
	default:
		return "CDS_FT_STATUS_UNKNOWN";
	}
}

struct dns_nametree {
	unsigned int magic;
	isc_mem_t *mctx;
	isc_refcount_t references;
	dns_nametree_type_t type;
	isc_mutex_t writer_mutex;
	struct cds_ft_group *group;
	struct cds_ft *tree;
	struct cds_ft_iter *writer_iter;
	char name[64];
};

struct dns_ntnode {
	isc_mem_t *mctx;
	isc_refcount_t references;
	dns_name_t name;
	bool set;
	uint8_t *bits;
	uint32_t count;
	struct cds_ft_node ft_node;
	struct rcu_head rcu_head;
};

static size_t
ntkey_fromname(dns_qpkey_t key, const dns_name_t *name) {
	return dns_qpkey_fromname(key, name, DNS_DBNAMESPACE_NORMAL);
}

static void
destroy_ntnode(dns_ntnode_t *node) {
	if (node->bits != NULL) {
		isc_mem_cput(node->mctx, node->bits, node->bits[0],
			     sizeof(char));
	}
	dns_name_free(&node->name, node->mctx);
	isc_mem_putanddetach(&node->mctx, node, sizeof(dns_ntnode_t));
}

#if DNS_NAMETREE_TRACE
ISC_REFCOUNT_TRACE_IMPL(dns_ntnode, destroy_ntnode);
#else
ISC_REFCOUNT_IMPL(dns_ntnode, destroy_ntnode);
#endif

static void
ntnode_free_rcu(struct rcu_head *rcu_head) {
	dns_ntnode_t *node = caa_container_of(rcu_head, dns_ntnode_t, rcu_head);
	char namebuf[DNS_NAME_FORMATSIZE];

	dns_name_format(&node->name, namebuf, sizeof(namebuf));
	fprintf(stderr, "dns_ntnode_detach(%p, %s)\n", node, namebuf);
	dns_ntnode_detach(&node);
}

static dns_ntnode_t *
newnode(isc_mem_t *mctx, const dns_name_t *name) {
	dns_ntnode_t *node = isc_mem_get(mctx, sizeof(*node));
	*node = (dns_ntnode_t){
		.name = DNS_NAME_INITEMPTY,
		.mctx = isc_mem_ref(mctx),
		.references = 1,
	};
	dns_name_dup(name, mctx, &node->name);
	cds_ft_node_init(&node->ft_node);
	return node;
}

void
dns_nametree_create(isc_mem_t *mctx, dns_nametree_type_t type, const char *name,
		    dns_nametree_t **ntp) {
	dns_nametree_t *nametree = NULL;
	struct cds_ft_attr *attr = NULL;
	enum cds_ft_status status;

	REQUIRE(ntp != NULL && *ntp == NULL);

	nametree = isc_mem_get(mctx, sizeof(*nametree));
	*nametree = (dns_nametree_t){
		.magic = NAMETREE_MAGIC,
		.type = type,
		.mctx = isc_mem_ref(mctx),
		.references = 1,
	};
	isc_mutex_init(&nametree->writer_mutex);

	if (name != NULL) {
		strlcpy(nametree->name, name, sizeof(nametree->name));
	}

	status = cds_ft_attr_create(&attr);
	RUNTIME_CHECK(status == CDS_FT_STATUS_OK);
	status = cds_ft_group_create(attr, &nametree->group);
	RUNTIME_CHECK(status == CDS_FT_STATUS_OK);
	cds_ft_attr_destroy(attr);

	status = cds_ft_create(nametree->group, &nametree->tree);
	RUNTIME_CHECK(status == CDS_FT_STATUS_OK);

	status = cds_ft_iter_create(nametree->tree, &nametree->writer_iter);
	RUNTIME_CHECK(status == CDS_FT_STATUS_OK);

	*ntp = nametree;
}

static void
destroy_nametree(dns_nametree_t *nametree) {
	enum cds_ft_status status;
	struct cds_ft_iter *iter = NULL;

	nametree->magic = 0;

	status = cds_ft_iter_create(nametree->tree, &iter);
	RUNTIME_CHECK(status == CDS_FT_STATUS_OK);

	/*
	 * The last nametree reference is gone; no new reader can observe
	 * this nametree.  Drain any remaining entries directly: readers
	 * must hold a nametree reference to be in flight, and none can
	 * be.  The ntnode_free_rcu callbacks queued by earlier mutations
	 * do not touch the trie itself, so no grace-period wait is
	 * required here.
	 *
	 * We must NOT call synchronize_rcu() or rcu_barrier() here:
	 * destroy_nametree may itself run from a call_rcu worker thread
	 * (e.g., when a dns_view is reclaimed asynchronously), and
	 * waiting for RCU from within that thread deadlocks.
	 */
	status = cds_ft_lookup_first(nametree->tree, iter);
	fprintf(stderr, "cleaning up fractal-trie %p (iter %p) -> %s\n",
		nametree->tree, iter, status2str(status));
	while (nametree->tree == CDS_FT_STATUS_OK) {
		struct cds_ft_node *ft_node = NULL;
		status = cds_ft_remove_all(nametree->tree, iter, &ft_node);
		INSIST(status == CDS_FT_STATUS_OK);

		fprintf(stderr, "cleaning up fractal-trie %p (node %p)\n",
			nametree->tree, ft_node);

		dns_ntnode_t *node = NULL;
		struct cds_ft_node *tmp = NULL;
		cds_ft_for_each_duplicate_entry_safe_rcu(node, ft_node, tmp,
							 ft_node) {
			char namebuf[DNS_NAME_FORMATSIZE];

			dns_name_format(&node->name, namebuf, sizeof(namebuf));
			fprintf(stderr, "dns_ntnode_detach(%p, %s)\n", node,
				namebuf);

			dns_ntnode_detach(&node);
		}
		status = cds_ft_lookup_first(nametree->tree, iter);
	}

	cds_ft_iter_destroy(iter);
	cds_ft_iter_destroy(nametree->writer_iter);
	fprintf(stderr, "cds_ft_destroy(%p) start\n", nametree->tree);
	cds_ft_destroy(nametree->tree);
	fprintf(stderr, "cds_ft_destroy(%p) end\n", nametree->tree);
	cds_ft_group_destroy(nametree->group);
	isc_mutex_destroy(&nametree->writer_mutex);

	isc_mem_putanddetach(&nametree->mctx, nametree, sizeof(*nametree));
}

#if DNS_NAMETREE_TRACE
ISC_REFCOUNT_TRACE_IMPL(dns_nametree, destroy_nametree);
#else
ISC_REFCOUNT_IMPL(dns_nametree, destroy_nametree);
#endif

static bool
matchbit(unsigned char *bits, uint32_t val) {
	unsigned int len = val / 8 + 2;
	unsigned int mask = 1 << (val % 8);

	if (len <= bits[0] && (bits[len - 1] & mask) != 0) {
		return true;
	}
	return false;
}

static isc_result_t
add_bool(dns_nametree_t *nametree, const dns_name_t *name, bool value) {
	dns_qpkey_t key;
	size_t keylen = ntkey_fromname(key, name);
	struct cds_ft_node *existing = NULL;
	enum cds_ft_status status;
	dns_ntnode_t *new = newnode(nametree->mctx, name);
	char namebuf[DNS_NAME_FORMATSIZE];

	dns_name_format(&new->name, namebuf, sizeof(namebuf));

	print_key(key, keylen);

	new->set = value;
	status = cds_ft_insert_unique(nametree->tree, key, keylen,
				      &new->ft_node, &existing);
	fprintf(stderr, "cds_ft_insert_unique(%p, %p, %s) -> %s\n",
		nametree->tree, new, namebuf, status2str(status));
	if (status == CDS_FT_STATUS_DUPLICATE_FOUND) {
		dns_ntnode_detach(&new);
		return ISC_R_EXISTS;
	}
	INSIST(status == CDS_FT_STATUS_OK);
	/* The trie now holds the node's reference. */
	return ISC_R_SUCCESS;
}

static isc_result_t
add_count(dns_nametree_t *nametree, const dns_name_t *name) {
	dns_qpkey_t key;
	size_t keylen = ntkey_fromname(key, name);
	struct cds_ft_node *ft_node = NULL;
	enum cds_ft_status status;

	dns_ntnode_t *new = newnode(nametree->mctx, name);
	new->set = true;
	new->count = 1;
	rcu_read_lock();

	char namebuf[DNS_NAME_FORMATSIZE];

	dns_name_format(&new->name, namebuf, sizeof(namebuf));

	print_key(key, keylen);

	status = cds_ft_insert_unique(nametree->tree, key, keylen,
				      &new->ft_node, &ft_node);
	fprintf(stderr, "cds_ft_insert_unique(%p, %p, %s) -> %s\n",
		nametree->tree, new, namebuf, status2str(status));
	if (status == CDS_FT_STATUS_DUPLICATE_FOUND) {
		dns_ntnode_t *existing = caa_container_of(ft_node, dns_ntnode_t,
							  ft_node);
		existing->count++;
		rcu_read_unlock();
		dns_ntnode_detach(&new);
		return ISC_R_SUCCESS;
	}
	rcu_read_unlock();
	INSIST(status == CDS_FT_STATUS_OK);
	return ISC_R_SUCCESS;
}

static isc_result_t
add_bits(dns_nametree_t *nametree, const dns_name_t *name, uint32_t value) {
	dns_qpkey_t key;
	size_t keylen = ntkey_fromname(key, name);
	struct cds_ft_node *ft_node = NULL;
	struct cds_ft_node *replaced = NULL;
	enum cds_ft_status status;
	dns_ntnode_t *old = NULL;
	dns_ntnode_t *new = NULL;
	uint32_t size, pos, mask;

	pos = value / 8 + 2;
	mask = 1 << (value % 8);
	size = pos;

	rcu_read_lock();
	status = cds_ft_lookup_key(nametree->tree, key, keylen, &ft_node);
	if (status == CDS_FT_STATUS_OK) {
		old = caa_container_of(ft_node, dns_ntnode_t, ft_node);
		if (matchbit(old->bits, value)) {
			rcu_read_unlock();
			return ISC_R_SUCCESS;
		}
		if (old->bits[0] > pos) {
			size = old->bits[0];
		}
	}
	rcu_read_unlock();

	new = newnode(nametree->mctx, name);
	new->bits = isc_mem_cget(nametree->mctx, size, sizeof(char));
	if (old != NULL) {
		memmove(new->bits, old->bits, old->bits[0]);
	}
	new->bits[pos - 1] |= mask;
	new->bits[0] = size;

	print_key(key, keylen);

	status = cds_ft_insert_replace(nametree->tree, key, keylen,
				       &new->ft_node, &replaced);

	char namebuf[DNS_NAME_FORMATSIZE];

	dns_name_format(&new->name, namebuf, sizeof(namebuf));

	fprintf(stderr, "cds_ft_insert_replace(%p, %p, %s) -> %s\n",
		nametree->tree, new, namebuf, status2str(status));
	if (status == CDS_FT_STATUS_DUPLICATE_FOUND) {
		INSIST(replaced != NULL);
		dns_ntnode_t *replaced_node =
			caa_container_of(replaced, dns_ntnode_t, ft_node);
		call_rcu(&replaced_node->rcu_head, ntnode_free_rcu);
	} else {
		INSIST(status == CDS_FT_STATUS_OK);
	}
	return ISC_R_SUCCESS;
}

isc_result_t
dns_nametree_add(dns_nametree_t *nametree, const dns_name_t *name,
		 uint32_t value) {
	isc_result_t result;

	REQUIRE(VALID_NAMETREE(nametree));
	REQUIRE(name != NULL);

	LOCK(&nametree->writer_mutex);
	switch (nametree->type) {
	case DNS_NAMETREE_BOOL:
		result = add_bool(nametree, name, value);
		break;
	case DNS_NAMETREE_COUNT:
		result = add_count(nametree, name);
		break;
	case DNS_NAMETREE_BITS:
		result = add_bits(nametree, name, value);
		break;
	default:
		UNREACHABLE();
	}
	UNLOCK(&nametree->writer_mutex);

	return result;
}

isc_result_t
dns_nametree_delete(dns_nametree_t *nametree, const dns_name_t *name) {
	dns_qpkey_t key;
	size_t keylen;
	struct cds_ft_node *ft_node = NULL;
	enum cds_ft_status status;
	isc_result_t result = ISC_R_NOTFOUND;
	dns_ntnode_t *node = NULL;

	REQUIRE(VALID_NAMETREE(nametree));
	REQUIRE(name != NULL);

	keylen = ntkey_fromname(key, name);

	LOCK(&nametree->writer_mutex);
	rcu_read_lock();
	status = cds_ft_iter_set_key(nametree->writer_iter, key, keylen);
	INSIST(status == CDS_FT_STATUS_OK);
	status = cds_ft_lookup(nametree->tree, nametree->writer_iter);
	if (status != CDS_FT_STATUS_OK) {
		rcu_read_unlock();
		goto out;
	}
	ft_node = cds_ft_iter_node(nametree->writer_iter);
	node = caa_container_of(ft_node, dns_ntnode_t, ft_node);

	if (nametree->type == DNS_NAMETREE_COUNT && --node->count != 0) {
		rcu_read_unlock();
		result = ISC_R_SUCCESS;
		goto out;
	}

	fprintf(stderr, "cds_ft_delete(%p, %p)\n", nametree->tree, node);
	status = cds_ft_remove(nametree->tree, nametree->writer_iter, ft_node);
	rcu_read_unlock();
	INSIST(status == CDS_FT_STATUS_OK);

	call_rcu(&node->rcu_head, ntnode_free_rcu);
	result = ISC_R_SUCCESS;

out:
	UNLOCK(&nametree->writer_mutex);
	return result;
}

isc_result_t
dns_nametree_find(dns_nametree_t *nametree, const dns_name_t *name,
		  dns_ntnode_t **ntnodep) {
	dns_qpkey_t key;
	size_t keylen;
	struct cds_ft_node *ft_node = NULL;
	enum cds_ft_status status;
	isc_result_t result = ISC_R_NOTFOUND;

	REQUIRE(VALID_NAMETREE(nametree));
	REQUIRE(name != NULL);
	REQUIRE(ntnodep != NULL && *ntnodep == NULL);

	keylen = ntkey_fromname(key, name);

	rcu_read_lock();
	status = cds_ft_lookup_key(nametree->tree, key, keylen, &ft_node);
	if (status == CDS_FT_STATUS_OK) {
		dns_ntnode_t *node = caa_container_of(ft_node, dns_ntnode_t,
						      ft_node);
		dns_ntnode_attach(node, ntnodep);
		result = ISC_R_SUCCESS;
	}
	rcu_read_unlock();

	return result;
}

bool
dns_nametree_covered(dns_nametree_t *nametree, const dns_name_t *name,
		     dns_name_t *found, uint32_t bit) {
	dns_qpkey_t key;
	size_t keylen;
	size_t match_len;
	struct cds_ft_node *ft_node = NULL;
	enum cds_ft_status status;
	bool ret = false;

	if (nametree == NULL) {
		return false;
	}

	REQUIRE(VALID_NAMETREE(nametree));

	keylen = ntkey_fromname(key, name);

	rcu_read_lock();
	status = cds_ft_lookup_partial_key(nametree->tree, key, keylen,
					   &match_len, &ft_node);
	if (status == CDS_FT_STATUS_OK) {
		dns_ntnode_t *node = caa_container_of(ft_node, dns_ntnode_t,
						      ft_node);
		if (found != NULL) {
			dns_name_copy(&node->name, found);
		}
		switch (nametree->type) {
		case DNS_NAMETREE_BOOL:
			ret = node->set;
			break;
		case DNS_NAMETREE_COUNT:
			ret = true;
			break;
		case DNS_NAMETREE_BITS:
			ret = matchbit(node->bits, bit);
			break;
		}
	}
	rcu_read_unlock();

	return ret;
}
