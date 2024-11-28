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

libisccc_inc = include_directories('include')

libisccc = shared_library(
    'isccc',
    files(
        'alist.c',
        'base64.c',
        'cc.c',
        'ccmsg.c',
        'sexpr.c',
        'symtab.c',
    ),
    include_directories: libisccc_inc,
    install: true,
    dependencies: [
        libdns_dep,
        libisc_dep,
    ],
)

libisccc_dep = declare_dependency(
    link_with: libisccc,
    include_directories: libisccc_inc,
)
