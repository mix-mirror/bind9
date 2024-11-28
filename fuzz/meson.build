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

if fuzz_opt == 'none'
    subdir_done()
endif

executable(
    'dns_master_load',
    files('dns_master_load.c', 'main.c'),
    link_args: fuzz_link_args,
    dependencies: [
        libdns_dep,
        libisc_dep,
    ],
)

executable(
    'dns_message_checksig',
    files('dns_message_checksig.c', 'main.c'),
    link_args: fuzz_link_args,
    dependencies: [
        libdns_dep,
        libisc_dep,
    ],
)

executable(
    'dns_message_parse',
    files('dns_message_parse.c', 'main.c'),
    link_args: fuzz_link_args,
    dependencies: [
        libdns_dep,
        libisc_dep,
    ],
)

executable(
    'dns_name_fromtext_target',
    files('dns_name_fromtext_target.c', 'main.c'),
    link_args: fuzz_link_args,
    dependencies: [
        libdns_dep,
        libisc_dep,
    ],
)

executable(
    'dns_name_fromwire',
    files('dns_name_fromwire.c', 'main.c', 'old.c'),
    link_args: fuzz_link_args,
    dependencies: [
        libdns_dep,
        libisc_dep,
    ],
)

executable(
    'dns_qp',
    files('dns_qp.c', 'main.c'),
    link_args: fuzz_link_args,
    include_directories: '..' / 'lib' / 'dns',
    dependencies: [
        libdns_dep,
        libisc_dep,
        libtest_dep,
    ],
)

executable(
    'dns_qpkey_name',
    files('dns_qpkey_name.c', 'main.c'),
    link_args: fuzz_link_args,
    dependencies: [
        libdns_dep,
        libisc_dep,
        libtest_dep,
    ],
)

executable(
    'dns_rdata_fromtext',
    files('dns_rdata_fromtext.c', 'main.c'),
    link_args: fuzz_link_args,
    dependencies: [
        libdns_dep,
        libisc_dep,
    ],
)

executable(
    'dns_rdata_fromwire_text',
    files('dns_rdata_fromwire_text.c', 'main.c'),
    link_args: fuzz_link_args,
    dependencies: [
        libdns_dep,
        libisc_dep,
    ],
)

executable(
    'isc_lex_getmastertoken',
    files('isc_lex_getmastertoken.c', 'main.c'),
    link_args: fuzz_link_args,
    dependencies: [
        libdns_dep,
        libisc_dep,
    ],
)

executable(
    'isc_lex_gettoken',
    files('isc_lex_gettoken.c', 'main.c'),
    link_args: fuzz_link_args,
    dependencies: [
        libdns_dep,
        libisc_dep,
    ],
)
