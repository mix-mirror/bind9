<!--
Copyright (C) Internet Systems Consortium, Inc. ("ISC")

SPDX-License-Identifier: MPL-2.0

This Source Code Form is subject to the terms of the Mozilla Public
License, v. 2.0.  If a copy of the MPL was not distributed with this
file, you can obtain one at https://mozilla.org/MPL/2.0/.

See the COPYRIGHT file distributed with this work for additional
information regarding copyright ownership.
-->

# THIS IS ABSOLUTELY OUT-OF-DATE (concetps, API, etc).


## cfgmgr

### Concepts

cfgmgr is a library to (in-memory) store and to interact with
configuration data in a hierarchical way. A configuration clause can
be seen as a "box" holding properties accessible by name. A property
can be of various types (boolean, unsigned integer, string, sockaddr,
etc.) as well as a clause, making possible to have nested
clauses. Furthermore, a clause can be repeated: it is possible to have
several clauses of the same name (or "several instances") at the same
level (i.e. in the same parent clause).

### API

Public API usage and concepts are documented in
lib/isc/include/isc/cfgmgr.h. The API is thread-safe and transaction
based. In order to access to a clause, it must be opened (which starts
a read or read-write transaction) and eventually closed (which commit
the transaction, if read-write). Changes made during a transaction are
visible by the current thread only. Opening nested clauses doesn't
create sub-transactions: there is only one transaction at the time for
a given thread opening a top-level clause.

### Implementation

cfgmgr is essentially a wrapper abstracting LMDB, which is providing
the storage, thread-safe and transactional access. Because LMDB also
write data on disk and cfgmgr intents to be in-memory only, the LMDB
files are immediately deleted during the initialization of cfgmgr.

#### Nested and repeatable clauses

LDBM itself is "flat": it stores key-values associations. In order to
model nested clauses, cfgmgr dynamically build the key for each value
using a namespace dot based notation. For example:

```
foo {
    bar {
    	gee: 55;
    };
    baz: "abc";
};
```

is implemented with the following key-values:

```
foo.XXX.bar.YYY.gee: 55
foo.XXX.baz: "abc"
```

The "XXX" and "YYY" are random numbers identifying a specific clause
instance. Let's make the configuration a bit more complex:

```
foo {
    bar {
    	gee: 55;
    };
    bar {
    	gee: 234;
    };
    baz: "abc";
};
```

This is implemented with the following key-values:

```
foo.XXX.bar.YYY.gee: 55
foo.XXX.bar.ZZZ.gee: 234
foo.XXX.baz: "abc"
```

This makes it easy to differentiate between the two instances of the
"bar" clause: one is "bar.YYY" while the other is "bar.ZZZ".

The reason a number is used (instead of a name or something else) is
because LMDB sort the key in a lexicographical way. Also, given a key,
LMDB is able to give the first key which is equal or bigger. This is
the crux of how cfgmgr can jump to the next instance of a same clause
(function `isc_cfgmgr_nextclause`) in one lookup. It takes the key of
the current clause, increments it by one (which is way simpler than
incrementing a "string by one"), and asks LMDB to give it back the
next key equal or bigger than the new one. Example:

- current clause is `foo.1234`
- cfgmgr then creates the key prefix `foo.1235.`
- LMDB gives the first key bigger or equals to `foo.1235.`

No matter what's inside `foo.1234` (so no matter the keys starting by
`foo.1234.`, LMDB returns the first key starting by _at least_
`foo.1235`, which would be the first key of the next instance of the
same clause. (If there is no other "foo" clause, nothing is found).

### List properties

named configuration format supports properties holding a list of
values. cfgmgr approach to implement lists uses the fact that LMDB
allows duplicate keys and it stores a newly duplicated key after the
previous ones. A clause "foo" with a property "bar" holding a list of
integers is implemented by cfgmgr in the following way in LMDB:

```
foo.XXX.bar: 23
foo.XXX.bar: 43
```

(Note there would be another way as LMDB enables to store several
values for a given key, but it's not flexible enough for cfgmgr: it
requires providing ahead the size used by all the values. It means
that adding a new list element would require to allocate a buffer of
the existing size plus the size of the new element, delete the
existing key-value from LMDB, and add it again. Dup keys seems to be a
better fit here.)

### Inheritance (proposal/speculative)

Some named configuration clauses have a concept of inheritance. For
instance, if a looked-up property is not found in a "view" clause, the
property will be looked-up in the "options" clause. cfgmgr currently
doesn't support inheritance, so the following is an API/implementation
proposal to support-ish it:

- a new API `isc_cfgmgr_fallback("A")` could be called while a clause
  "B" is opened. Then, cfgmgr would know that if a looked-up property
  of a clause "B" is not found, then it would internally and
  synchronously try to lookup the same property from within the clause
  "A". So this can be seen as "B inherits A properties" from the
  caller perspective. This API could be used once-per clause (no
  "multiple inheritance"), and it would be possible to break this
  relation if needed by calling `isc_cfgmgr_fallback(NULL)`.

- internally, `isc_cfgmgr_fallback` would create a new LMDB key-value
  `B.0.fallback: "A"`. So when cfgmgr opens a clause it can figure out
  if it needs to lookup for another clause in case a looked-up
  property is not found.

- From performance perspective in would make one extra LMDB lookup
  only if a property name is not found for a clause "B" (so this is
  likely acceptable). (And of course one extra lookup when opening a
  clause to find the "clausename.0.fallback" key, but again, that's
  acceptable.)

- limitation 1: if "B" has multiple instances, only the first instance
  values would be used. (Which I think is fine for named use case:
  "options" is not a repeatable clause).

- limitation 2: There won't be any check to make sure "A" actually
  exists when `isc_cfgmgr_fallback` is called, so can be done at any
  tine even if "A" doesn't exists yet. It makes initialization time
  order-independent (so actually not really a limitation), and more
  importantly it avoids falling into a rabbit hole, for instance, to
  make sure that if we delete "A" it would remove all the
  `"other-clause-names.0.fallback: "A"` keys. This is actually the
  reason I want to call it "fallback" in the API and not
  "inheritance". It's basically just a "second-chance" if a value is
  not found, but nothing more.
