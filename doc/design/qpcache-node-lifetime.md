<!--
Copyright (C) Internet Systems Consortium, Inc. ("ISC")

SPDX-License-Identifier: MPL-2.0

This Source Code Form is subject to the terms of the Mozilla Public
License, v. 2.0.  If a copy of the MPL was not distributed with this
file, you can obtain one at https://mozilla.org/MPL/2.0/.

See the COPYRIGHT file distributed with this work for additional
information regarding copyright ownership.
-->

qpcache node lifetime
=====================

This is a design note for removing the qpcache "reactivate node" model.
The goal is to make empty-node deletion final, while still allowing tree
readers and database iterators to hold safe references to nodes that were
found before deletion completed.


current problem
---------------

The current qpcache model allows an empty `qpcnode_t` to remain visible
in the qp-trie after the last slabheader has been removed. This happens
when the code removing the last slabheader does not have a qp write
transaction and therefore cannot unlink the node immediately.

The node is queued on `deadnodes`, and `cleanup_deadnodes()` later opens
a qp write transaction and removes it from the trie. During the window
between queuing and physical unlink, lookup can still find the empty
node. `reactivate_node()` exists to handle exactly that case: either pin
the node again or reject it if deletion already won.

This has an awkward invariant:

* "found in the trie" does not mean "live";
* "has no data" does not mean "will not be reused";
* an empty node can move back from the deadnode queue into normal use.

That reactivation behavior makes the lifetime rules harder to reason
about and keeps the node lock on paths that should only need to unlink
already-dead nodes.


desired invariant
-----------------

Once a node is selected for deletion, deletion is final. The node is no
longer acquirable by lookup, iterator, or `findnode(create=true)`.

Physical unlink from the trie may still be delayed, but that delay is
only a storage-management detail. A tombstoned node can remain visible
to old readers, snapshots, or RCU traversals, but no new external user
can acquire it.

The important distinction is:

* logical deletion: the node can no longer be acquired or reactivated;
* physical unlink: the node has been removed from the trie;
* object reclamation: the node memory has been freed after all refs and
  any required RCU grace period are gone.

These are separate state transitions. They should not be collapsed into
one overloaded `deleted` bit unless the resulting states are still
unambiguous.


node state
----------

A useful model is:

```c
bool deleted;  /* logical tombstone: never reactivate */
bool linked;   /* physical membership in the main trie */
```

or an equivalent enum. `deleted == true && linked == true` is valid: the
node is dead, but cleanup has not removed it from the trie yet.

Both `cleanup_deadnodes()` and `findnode(create=true)` may encounter
that state. They must share an idempotent unlink helper:

```c
qpcnode_unlink_if_linked(qp, node);
```

That helper removes the normal-tree entry, and if needed the auxiliary
NSEC entry, exactly once. It must be safe for async cleanup to run after
`findnode(create=true)` already unlinked the node.


acquiring a node
----------------

`urcu_ref_get_unless_zero()` is the right kind of primitive for turning
a transient pointer from a tree/RCU/snapshot traversal into a stable
reference:

```c
if (!qpcnode_try_acquire(qpdb, node)) {
        return ISC_R_NOTFOUND;
}
```

But it should not simply replace every `qpcnode_ref()`. There are two
different questions:

* is the object memory still alive?
* is the node logically live and acquirable?

Using `get_unless_zero()` on the object lifetime refcount only answers
the first question. A tombstoned-but-still-linked node can still have
object references, especially while it is visible to snapshots, queued
for cleanup, or waiting for an RCU grace period.

The acquirable state therefore needs a terminal zero. One way to model
that is to give the external-reference counter a live sentinel:

```c
/*
 * live_refs == 1: live, no external users
 * live_refs > 1: live, external users exist
 * live_refs == 0: tombstoned, no new acquisition allowed
 */
```

Acquiring from a raw tree pointer uses `urcu_ref_get_unless_zero()`:

```c
if (!urcu_ref_get_unless_zero(&node->live_refs)) {
        return false;
}

qpcnode_ref(node);
qpcache_ref(qpdb);
```

Releasing an external user decrements `live_refs` and releases the
matching cache-use reference. The release path can then check whether
only the live sentinel remains:

```c
refs = uatomic_sub_return(&node->live_refs.refcount, 1);
INSIST(refs >= 1);
last_external = (refs == 1);

qpcache_unref(qpdb);
qpcnode_unref(node);
```

The last-external decision must use the value returned by the atomic
decrement. Loading the counter afterwards is racy: another releaser can
observe the sentinel and tombstone the node with `1 -> 0` before the
current releaser performs its load.

Deleting an empty node wins only if no external users exist:

```c
if (atomic_compare_exchange(&node->live_refs, 1, 0)) {
        node->deleted = true;
        queue_or_unlink(node);
}
```

This removes the resurrection race:

* if lookup wins `1 -> 2`, deletion observes external use and backs off;
* if deletion wins `1 -> 0`, lookup fails `get_unless_zero()` and treats
  the node as not found.

The stock `urcu_ref_get_unless_zero()` returns only a boolean, so the
implementation uses one qpcache-use pin per external node reference
instead of trying to preserve first-external-user accounting.


deadnode cleanup
----------------

With final tombstoning, `qpcnode_release()` no longer needs to upgrade
the node lock just to add a tombstoned node to `deadnodes`. The queue is
backed by `cds_wfcq`, so enqueue itself does not require exclusive
access. The existing node read lock is enough producer-side coordination
when cleanup takes the bucket write lock before splicing.

The cleanup path should not call the normal `qpcnode_release()` state
machine. By the time a node is queued, logical deletion has already
happened and no new external acquisition is possible.

The shape should be:

```c
NODE_WRLOCK(bucket);
isc_queue_splice(&local, &bucket->deadnodes);
NODE_UNLOCK(bucket);

dns_qpmulti_write(tree, &qp);

for each node in local {
        qpcnode_unlink_if_linked(qp, node);
        qpcnode_drop_deadnode_ref(node);
}

dns_qpmulti_commit(tree, &qp);
```

The queued deadnode reference keeps the object alive until cleanup has
processed it. If another path already unlinked the node, cleanup only
drops that queued reference.


findnode(create=true)
---------------------

`findnode(create=true)` is the natural opportunistic cleanup point. It
already opens a qp write transaction, and it is exactly where a
tombstoned node with the requested name would block insertion of a
fresh node.

The create path should be:

```c
dns_qpmulti_write(tree, &qp);

result = dns_qp_getname(qp, name, DNS_DBNAMESPACE_NORMAL, &node, NULL);
if (result == ISC_R_SUCCESS && node->deleted) {
        qpcnode_unlink_if_linked(qp, node);
        node = NULL;
        result = ISC_R_NOTFOUND;
}

if (result != ISC_R_SUCCESS) {
        node = new_qpcnode(qpdb, name, DNS_DBNAMESPACE_NORMAL);
        result = dns_qp_insert(qp, node, 0);
        INSIST(result == ISC_R_SUCCESS);
        qpcnode_unref(node);
}

RUNTIME_CHECK(qpcnode_try_acquire(qpdb, node));
dns_qpmulti_commit(tree, &qp);
```

If async cleanup later sees the old node, it observes that it is already
unlinked and just drops the deadnode reference.


database iterators
------------------

Database iterators should hold a reference to their current
`qpcnode_t`. That reference guarantees object lifetime only; it should
not imply that the node remains present in the trie.

The old `resume_iteration()` invariant is therefore wrong:

```c
/*
 * As long as the iterator is holding a reference to qpdbiter->node,
 * the node won't be removed from the tree, so the lookup should always
 * succeed.
 */
```

The iterator already has the right split:

* qp snapshot or RCU traversal determines iteration order;
* `qpdbiter->node` holds the current qpcnode alive;
* `dbiterator_current()` returns a separate external reference to the
  caller.

`resume_iteration()` should be removed or reduced to interface state
bookkeeping. It must not perform a name lookup and assert that the
current node is still in the trie.

When an iterator sees a tombstoned node, it should attempt
`qpcnode_try_acquire()`. If acquisition fails, the iterator skips that
node and advances.


RCU requirements
----------------

`urcu_ref_get_unless_zero()` is only safe when another synchronization
mechanism guarantees that the refcount memory itself still exists. For
qpcache this can be:

* a qpmulti read transaction or snapshot, where the qp leaf storage
  keeps the node pointer valid;
* an RCU read-side critical section for a CDS-FT based cache;
* a mutex or queue reference on internal cleanup paths.

For a CDS-FT implementation, physically removed nodes must not be freed
or reinserted until both conditions are satisfied:

* the node object reference count reaches zero;
* the required RCU grace period has elapsed.

It is simpler to create a fresh node when the same name is inserted
again, and let the old tombstoned node die after refs and RCU have
drained.


summary
-------

The intended replacement for `reactivate_node()` is not "delete nodes
immediately everywhere". It is:

* make deletion final by closing the acquire path with a zero-terminal
  live reference;
* allow physical unlink to happen later;
* let `cleanup_deadnodes()` and `findnode(create=true)` share an
  idempotent unlink helper;
* keep object lifetime separate from logical liveness;
* make dbiterators hold qpcnode references without assuming trie
  membership.

That removes the reactivation race and lets cleanup unlink dead nodes
without taking the node lock for each dead node.
