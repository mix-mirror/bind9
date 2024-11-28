# Copyright (C) Internet Systems Consortium, Inc. ("ISC")
#
# SPDX-License-Identifier: MPL-2.0
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0.  If a copy of the MPL was not distributed with this
# file, you can obtain one at https://mozilla.org/MPL/2.0/.
#
# See the COPYRIGHT file distributed with this work for additional
# information regarding copyright ownership.

executable(
    'arpaname',
    files('arpaname.c'),
    install: true,
    dependencies: [
        libisc_dep,
    ],
)

executable(
    'mdig',
    files('mdig.c'),
    install: true,
    dependencies: [
        libdns_dep,
        libisc_dep,
    ],
)

executable(
    'named-journalprint',
    files('named-journalprint.c'),
    install: true,
    dependencies: [
        libdns_dep,
        libisc_dep,
    ],
)

executable(
    'named-rrchecker',
    files('named-rrchecker.c'),
    install: true,
    dependencies: [
        libdns_dep,
        libisc_dep,
    ],
)

executable(
    'nsec3hash',
    files('nsec3hash.c'),
    install: true,
    dependencies: [
        libdns_dep,
        libisc_dep,
    ],
)

if config.has('HAVE_LMDB')
    executable(
        'named-nzd2nzf',
        files('named-nzd2nzf.c'),
        install: true,
        dependencies: [
            libdns_dep,
            libisc_dep,

            lmdb_dep,
        ],
    )
endif

if config.has('HAVE_DNSTAP')
    executable(
        'dnstap-read',
        files('dnstap-read.c'),
        install: true,
        dependencies: [
            libdns_dep,
            libisc_dep,

            dnstap_dep,
        ],
    )
endif
