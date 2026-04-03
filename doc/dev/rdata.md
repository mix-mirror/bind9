<!--
Copyright (C) Internet Systems Consortium, Inc. ("ISC")

SPDX-License-Identifier: MPL-2.0

This Source Code Form is subject to the terms of the Mozilla Public
License, v. 2.0.  If a copy of the MPL was not distributed with this
file, you can obtain one at https://mozilla.org/MPL/2.0/.

See the COPYRIGHT file distributed with this work for additional
information regarding copyright ownership.
-->

## RDATA Types

### Overview

Each DNS rdata type is implemented as a separate C source file in
`lib/dns/rdata/`.  The type files are compiled as independent translation
units and dispatch is done through a vtable — a `dns_rdata_methods_t`
struct of function pointers registered in a sorted lookup table.

The dispatch functions in `lib/dns/rdata.c` (`dns_rdata_fromtext()`,
`dns_rdata_totext()`, `dns_rdata_fromwire()`, etc.) look up the
methods for a given (rdclass, type) pair and call through the
function pointers.  Unknown types fall back to default behavior
(binary copy/compare, RFC 3597 unknown format for text).

### File layout

```
lib/dns/rdata/
    typename_N.c          — type implementation (one per type)
lib/dns/include/dns/rdata/
    typename_N.h          — rdata struct definition (one per type)
    rdatastructpre.h      — common struct definitions (dns_rdatacommon_t)
lib/dns/include/dns/
    enumtype.h            — type code enum (hand-maintained)
    enumclass.h           — class code enum (hand-maintained)
    rdatastruct.h         — convenience header including all type .h files
lib/dns/
    rdata.c               — dispatch functions and helper implementations
    rdata_p.h             — vtable structs (dns_rdata_methods_t, dns_rdata_typedesc_t)
    rdata_helpers.h       — shared helper declarations, macros, includes
    rdata_registry.c      — sorted type descriptor table and lookup functions
```

### Adding a new RDATA type

To add a new type with IANA type code N and mnemonic NAME:

#### 1. Create the struct header

Create `lib/dns/include/dns/rdata/name_N.h`:

```c
#pragma once

typedef struct dns_rdata_name {
    dns_rdatacommon_t common;
    /* type-specific fields */
} dns_rdata_name_t;
```

#### 2. Create the implementation file

Create `lib/dns/rdata/name_N.c`:

```c
#include "../rdata_helpers.h"

#define RRTYPE_NAME_ATTRIBUTES (0)

static isc_result_t
fromtext_name(ARGS_FROMTEXT) {
    /* Parse text representation into wire format */
}

static isc_result_t
totext_name(ARGS_TOTEXT) {
    /* Convert wire format to text */
}

static isc_result_t
fromwire_name(ARGS_FROMWIRE) {
    /* Parse wire format */
}

static isc_result_t
towire_name(ARGS_TOWIRE) {
    /* Write wire format */
}

static int
compare_name(ARGS_COMPARE) {
    /* Compare two rdata for DNSSEC ordering */
}

static int
casecompare_name(ARGS_COMPARE) {
    /* Case-insensitive comparison (often delegates to compare) */
    return compare_name(rdata1, rdata2);
}

static isc_result_t
fromstruct_name(ARGS_FROMSTRUCT) {
    /* Convert from C struct to wire format */
}

static isc_result_t
tostruct_name(ARGS_TOSTRUCT) {
    /* Convert from wire format to C struct */
}

static void
freestruct_name(ARGS_FREESTRUCT) {
    /* Free memory allocated by tostruct */
}

static isc_result_t
additionaldata_name(ARGS_ADDLDATA) {
    /* Return additional section records (e.g., A for MX) */
    UNUSED(rdata);
    UNUSED(owner);
    UNUSED(add);
    UNUSED(arg);
    return ISC_R_SUCCESS;
}

static isc_result_t
digest_name(ARGS_DIGEST) {
    /* DNSSEC canonical digest */
    isc_region_t r;
    dns_rdata_toregion(rdata, &r);
    return (digest)(arg, &r);
}

static bool
checkowner_name(ARGS_CHECKOWNER) {
    /* Validate owner name constraints */
    UNUSED(name);
    UNUSED(type);
    UNUSED(rdclass);
    UNUSED(wildcard);
    return true;
}

static bool
checknames_name(ARGS_CHECKNAMES) {
    /* Validate rdata name constraints */
    UNUSED(rdata);
    UNUSED(owner);
    UNUSED(bad);
    return true;
}

const dns_rdata_typedesc_t dns__rdata_name_typedesc = {
    .type = N,
    .rdclass = 0,
    .name = "NAME",
    .attributes = RRTYPE_NAME_ATTRIBUTES,
    .methods = &(const dns_rdata_methods_t){
        .fromtext = fromtext_name,
        .totext = totext_name,
        .fromwire = fromwire_name,
        .towire = towire_name,
        .compare = compare_name,
        .casecompare = casecompare_name,
        .fromstruct = fromstruct_name,
        .tostruct = tostruct_name,
        .freestruct = freestruct_name,
        .additionaldata = additionaldata_name,
        .digest = digest_name,
        .checkowner = checkowner_name,
        .checknames = checknames_name,
    },
};
```

#### 3. Register in the type system

Edit these files:

- **`lib/dns/include/dns/enumtype.h`** — add `dns_rdatatype_name = N`
  to the enum and the corresponding `#define` cast macro.

- **`lib/dns/include/dns/rdatastruct.h`** — add
  `#include <dns/rdata/name_N.h>` in type-code order.

- **`lib/dns/rdata_registry.c`** — add an `extern` declaration for
  the type descriptor, a `[N] = &dns__rdata_name_typedesc` entry in
  the `typedesc_table[]` array, and a `NAMECMP("NAME", typedesc_table[N])`
  line in the appropriate first-character case in
  `dns__rdata_typedesc_fromtext()`.

- **`lib/dns/meson.build`** — add `'rdata/name_N.c'` to the source
  list.

#### 4. Build and test

```sh
compile-bind
meson test -C build
```

### Type attributes

The `.attributes` field in the type descriptor is a bitmask of:

| Flag | Meaning |
|------|---------|
| `DNS_RDATATYPEATTR_SINGLETON` | Only one may exist per name |
| `DNS_RDATATYPEATTR_EXCLUSIVE` | No other types may coexist |
| `DNS_RDATATYPEATTR_META` | Meta-type (not stored in zones) |
| `DNS_RDATATYPEATTR_DNSSEC` | DNSSEC type (RRSIG, NSEC, etc.) |
| `DNS_RDATATYPEATTR_ZONECUTAUTH` | Zone cut authority type |
| `DNS_RDATATYPEATTR_ATPARENT` | Present at parent side of zone cut |
| `DNS_RDATATYPEATTR_ATCNAME` | Can coexist with CNAME |
| `DNS_RDATATYPEATTR_FOLLOWADDITIONAL` | Triggers additional section processing |

### Shared type families

Some types share implementations.  The "primary" type defines
non-static `generic_*` functions that related types call:

| Primary | Shared function prefix | Used by |
|---------|----------------------|---------|
| `key_25.c` | `generic_*_key` | DNSKEY, CDNSKEY, RKEY |
| `txt_16.c` | `generic_*_txt` | SPF, AVC, NINFO, WALLET, RESINFO |
| `ds_43.c` | `generic_*_ds` | CDS, DLV, TA |
| `tlsa_52.c` | `generic_*_tlsa` | SMIMEA |
| `svcb_64.c` | `generic_*_in_svcb` | HTTPS |

These are declared in `lib/dns/rdata_helpers.h`.

### Helper functions

Type implementations use helper functions declared in
`lib/dns/rdata_helpers.h` and defined in `lib/dns/rdata.c`:

- `str_totext()`, `mem_tobuffer()` — buffer writing
- `uint{8,16,32}_tobuffer()`, `uint{8,16,32}_fromregion()` — integer I/O
- `name_prefix()`, `name_length()`, `name_tobuffer()` — DNS name helpers
- `txt_totext()`, `txt_fromtext()`, `txt_fromwire()` — TXT string helpers
- `inet_totext()` — IP address formatting
- `typemap_fromtext()`, `typemap_totext()`, `typemap_test()` — NSEC/NSEC3 type bitmaps

The `ARGS_*` macros (`ARGS_FROMTEXT`, `ARGS_TOTEXT`, etc.) define
the standard parameter lists.  The `RETTOK` and `RETERR` macros
provide error-checked returns.
