<!--
Copyright (C) Internet Systems Consortium, Inc. ("ISC")

SPDX-License-Identifier: MPL-2.0

This Source Code Form is subject to the terms of the Mozilla Public
License, v. 2.0.  If a copy of the MPL was not distributed with this
file, you can obtain one at https://mozilla.org/MPL/2.0/.

See the COPYRIGHT file distributed with this work for additional
information regarding copyright ownership.
-->

## Userland Static Defined Tracing

The probes and parameters are not stable.
In general, pointers should only be used to match `_start` and `_end` probes.

### Contents

1. [libdns](#libdns)
    * [qp](#qp)
    * [qpmulti](#qpmulti)
    * [qpcache](#qpcache)
    * [rbtdb](#rbtdb)
    * [rbtdb-cache](#rbtdb-cache)

### <a name="libdns"></a>libdns

#### <a name="qp"></a>qp

- `qp_compact_start`: Fires when compation starts. This only includes the compaction phase of `dns_qp_compact`, the recycling part is fired separately.
    - `void *` qp-trie pointer
    - `uint32_t` number of leaf nodes
    - `uint32_t` number of used nodes
    - `uint32_t` number of free nodes
    - `uint32_t` number of free cells that cannot be recovered right now

- `qp_compact_done`: Fires when compaction finishes. This only includes the compaction phase of `dns_qp_compact`, the recycling part is fired separately.
    - `void *` qp-trie pointer
    - `uint32_t` number of leaf nodes
    - `uint32_t` number of used nodes
    - `uint32_t` number of free nodes
    - `uint32_t` number of free cells that cannot be recovered right now

- `qp_deletekey_start`: Fires when a node deletion by name starts.
    - `void *` qp-trie pointer
    - `void *` key pointer

- `qp_deletekey_done`: Fires when a node deletion by name finishes.
    - `void *` qp-trie pointer
    - `void *` name pointer
    - `bool` true if a leaf node is deleted

- `qp_deletename_start`: Fires when a node deletion by name starts.
    - `void *` qp-trie pointer
    - `void *` name pointer

- `qp_deletename_done`: Fires when a node deletion by name finishes.
    - `void *` qp-trie pointer
    - `void *` name pointer
    - `void *` key pointer of name

- `qp_getkey_start`: Fires when a leaf node lookup by key starts.
    - `void *` qp-trie pointer
    - `void *` key pointer

- `qp_getkey_done`: Fires when a leaf node lookup by key finishes.
    - `void *` qp-trie pointer
    - `void *` key pointer
    - `bool` true if a leaf node is found

- `qp_getname_start`: Fires when a leaf node lookup by name starts.
    - `void *` qp-trie pointer
    - `void *` name pointer

- `qp_getname_done`: Fires when a leaf node lookup by name finishes.
    - `void *` qp-trie pointer
    - `void *` name pointer
    - `void *` key pointer of name

- `qp_insert_start`: Fires when a leaf node insertion starts.
    - `void *` qp-trie pointer
    - `void *` leaf pointer
    - `uint32_t` leaf integer

- `qp_insert_done`: Fires when a leaf node insertion finishes.
    - `void *` qp-trie pointer
    - `void *` leaf pointer
    - `uint32_t` leaf integer

- `qp_lookup_start`: Fires when a leaf lookup starts.
    - `void *` qp-trie pointer
    - `void *` name pointer
    - `void *` optional iterator pointer
    - `void *` optional chain pointer

- `qp_lookup_done`: Fires when a leaf lookup finishes.
    - `void *` qp-trie pointer
    - `void *` name pointer
    - `void *` optional iterator pointer
    - `void *` optional chain pointer
    - `bool` true if an leaf is matched
    - `bool` true if it was a partial match

- `qp_reclaim_chunks_start`: Fires when chunk reclamation finishes.
    - `void *` qp-trie pointer

- `qp_reclaim_chunks_done`: Fires when chunk reclamation finishes.
    - `void *` qp-trie pointer
    - `uint32_t` number of chunks reclaimed
    - `uint32_t` number of leaf nodes
    - `uint32_t` number of used nodes
    - `uint32_t` number of free nodes
    - `uint32_t` number of free cells that cannot be recovered right now

- `qp_recycle_start`: Fires when node recycling starts.
    - `void *` qp-trie pointer

- `qp_recycle_done`: Fires when node recycling finishes.
    - `void *` qp-trie pointer
    - `uint32_t` number of nodes recycled
    - `uint32_t` number of leaf nodes
    - `uint32_t` number of used nodes
    - `uint32_t` number of free nodes
    - `uint32_t` number of free cells that cannot be recovered right now

#### <a name="qpmulti"></a>qpmulti

- `qpmulti_marksweep_start`: Fires when chunk cleanup starts.
    - `void *` qpmulti pointer
    - `void *` writer qp-trie pointer

- `qpmulti_marksweep_done`: Fires when chunk cleanup is finished.
    - `void *` qpmulti pointer
    - `void *` writer qp-trie pointer
    - `uint32_t` number of chunks freed
    - `uint32_t` number of leaf nodes
    - `uint32_t` number of used nodes
    - `uint32_t` number of free nodes
    - `uint32_t` number of free cells that cannot be recovered right now

- `qpmulti_txn_query`: Fires when a lightweight read-only transaction starts.
    - `void *` qpmulti pointer
    - `void *` read-only qp-trie pointer

- `qpmulti_txn_lockedread`: Fires when a mutex-taking read-only transaction starts.
    - `void *` qpmulti pointer
    - `void *` read-only qp-trie pointer

- `qpmulti_txn_snapshot`: Fires when a heavyweight read-only transaction starts.
    - `void *` qpmulti pointer
    - `void *` snapshot qp-trie pointer

- `qpmulti_txn_update`: Fires when a heavyweight write transaction starts.
    - `void *` qpmulti pointer
    - `void *` modifiable qp-trie pointer

- `qpmulti_txn_write`: Fires when a lightweight write transaction starts.
    - `void *` qpmulti pointer
    - `void *` modifiable qp-trie pointer

- `qpmulti_txn_commit_start`: Fires when a transaction commit starts.
    - `void *` qpmulti pointer
    - `void *` transacting qp-trie pointer

- `qpmulti_txn_commit_done`: Fires when a transaction commit is finished.
    - `void *` qpmulti pointer
    - `void *` transacting qp-trie pointer

- `qpmulti_txn_rollback_start`: Fires when a transaction rollback starts.
    - `void *` qpmulti pointer
    - `void *` transacting qp-trie pointer

- `qpmulti_txn_rollback_done`: Fires when a transaction rollback is finished.
    - `void *` qpmulti pointer
    - `void *` transacting qp-trie pointer
    - `uint32_t` number of reclaimed chunks

#### <a name="qpcache"></a>qpcache

- `qpcache_expire_ttl_start`: Fires when TTL based cleanup starts.
    - `void *` database pointer
    - `unsigned int` lock number
    - `uint32_t` cleanup timestamp

- `qpcache_expire_ttl_done`: Fires when TTL based cleanup is finished.
    - `void *` database pointer
    - `unsigned int` lock number
    - `uint32_t` cleanup timestamp
    - `size_t` number of purged entries

- `qpcache_expire_lru_start`: Fires when LRU based cleanup starts.
    - `void *` database pointer
    - `unsigned int` lock number
    - `size_t` purge target number

- `qpcache_expire_lru_done`: Fires when LRU based cleanup is finished.
    - `void *` database pointer
    - `unsigned int` lock number
    - `size_t` number of purged entries

- `qpcache_overmem_start` Fires when overmem cleanup starts.
    - `void *` database pointer

- `qpcache_overmem_done` Fires when overmem cleanup is finished.
    - `void *` database pointer
    - `size_t` number of purged entries
    - `size_t` number of passes done

- `qpcache_addrdataset_start`: Fires when a `addrdataset` DNS DB operation starts.
    - `void *` database pointer
    - `void *` node pointer
    - `void *` rdataset pointer

- `qpcache_addrdataset_done`: Fires when a `addrdataset` DNS DB operation finishes.
    - `void *` database pointer
    - `void *` node pointer
    - `void *` rdataset pointer
    - `bool` true if the cache is overmem

- `qpcache_deletedata_start`: Fires when a `deletedata` DNS DB operation starts.
    - `void *` database pointer
    - `void *` node pointer containing data to be deleted
    - `void *` data pointer

- `qpcache_deletedata_done`: Fires when a `deletedata` DNS DB operation is finished.
    - `void *` database pointer
    - `void *` node pointer containing data to be deleted
    - `void *` data pointer

- `qpcache_deleterdataset_start`: Fires when a `deleterdataset` DNS DB operation starts.
    - `void *` database pointer
    - `void *` node pointer
    - `void *` database version pointer
    - `uint16_t` opaque rdataset type value to be deleted
    - `uint16_t` opaque coverage value

- `qpcache_deleterdataset_done`: Fires when a `deleterdataset` DNS DB operation is finished.
    - `void *` database pointer
    - `void *` node pointer
    - `void *` database version pointer
    - `uint16_t` opaque rdataset type value to be deleted
    - `uint16_t` opaque coverage value
    - `int32_t` result value

- `qpcache_expiredata_start`: Fires when a `expiredata` DNS DB operation starts.
    - `void *` database pointer
    - `void *` node pointer
    - `void *` data pointer

- `qpcache_expiredata_done`: Fires when a `expiredata` DNS DB operation is finished.
    - `void *` database pointer
    - `void *` node pointer
    - `void *` data pointer

- `qpcache_find_start`: Fires a `find` DNS DB operation starts.
    - `void *` database pointer
    - `void *` name pointer
    - `uint32_t` given current timestamp
    - `unsigned int` options flag

- `qpcache_find_done`: Fires a `find` DNS DB operation is finished.
    - `void *` database pointer
    - `void *` name pointer
    - `uint32_t` given current timestamp
    - `unsigned int` options flag
    - `int32_t` result value

- `qpcache_locknode`: Fires when a `locknode` DNS DB operation is called.
    - `void *` database pointer
    - `void *` node pointer
    - `bool` true if the operation is a write lock

- `qpcache_unlocknode`: Fires when a `unlocknode` DNS DB operation is called.
    - `void *` database pointer
    - `void *` node pointer
    - `bool` true if the operation is a write lock

#### <a name="rbtdb"></a>rbtdb

- `rbtdb_addrdataset_start`: Fires when a `addrdataset` DNS DB operation starts.
    - `void *` database pointer
    - `void *` node pointer
    - `void *` rdataset

- `rbtdb_addrdataset_done`: Fires when a `addrdataset` DNS DB operation finishes.
    - `void *` database pointer
    - `void *` node pointer
    - `void *` rdataset pointer
    - `bool` true if the cache is overmem

- `rbtdb_deletedata_start`: Fires when a `deletedata` DNS DB operation starts.
    - `void *` database pointer
    - `void *` node pointer containing data to be deleted
    - `void *` data pointer

- `rbtdb_deletedata_done`: Fires when a `deletedata` DNS DB operation is finished.
    - `void *` database pointer
    - `void *` node pointer containing data to be deleted
    - `void *` data pointer

- `rbtdb_deleterdataset_start`: Fires when a `deleterdataset` DNS DB operation starts.
    - `void *` database pointer
    - `void *` node pointer
    - `void *` database version pointer
    - `uint16_t` opaque rdataset type value to be deleted
    - `uint16_t` opaque coverage value

- `rbtdb_deleterdataset_done`: Fires when a `deleterdataset` DNS DB operation is finished.
    - `void *` database pointer
    - `void *` node pointer
    - `void *` database version pointer
    - `uint16_t` opaque rdataset type value to be deleted
    - `uint16_t` opaque coverage value
    - `int32_t` result value

#### <a name="rbtdb-cache"></a>rbtdb-cache

- `rbtdb_cache_expiredata_start`: Fires when a `expiredata` DNS DB operation starts.
    - `void *` database pointer
    - `void *` node pointer
    - `void *` data pointer

- `rbtdb_cache_expiredata_done`: Fires when a `expiredata` DNS DB operation is finished.
    - `void *` database pointer
    - `void *` node pointer
    - `void *` data pointer

- `rbtdb_cache_find_start`: Fires a `find` DNS DB operation starts.
    - `void *` database pointer
    - `void *` name pointer
    - `uint32_t` given current timestamp
    - `unsigned int` options flag

- `rbtdb_cache_find_done`: Fires a `find` DNS DB operation is finished.
    - `void *` database pointer
    - `void *` name pointer
    - `uint32_t` given current timestamp
    - `unsigned int` options flag
    - `int32_t` result value
