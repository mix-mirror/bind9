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

man1_docs = files(
    'arpaname.rst',
    'delv.rst',
    'dig.rst',
    'dnssec-cds.rst',
    'dnssec-dsfromkey.rst',
    'dnssec-importkey.rst',
    'dnssec-keyfromlabel.rst',
    'dnssec-keygen.rst',
    'dnssec-ksr.rst',
    'dnssec-revoke.rst',
    'dnssec-settime.rst',
    'dnssec-signzone.rst',
    'dnssec-verify.rst',
    'dnstap-read.rst',
    'host.rst',
    'mdig.rst',
    'named-checkconf.rst',
    'named-checkzone.rst',
    'named-compilezone.rst',
    'named-journalprint.rst',
    'named-nzd2nzf.rst',
    'named-rrchecker.rst',
    'nsec3hash.rst',
    'nslookup.rst',
    'nsupdate.rst',
)

man8_docs = files(
    'ddns-confgen.rst',
    'filter-a.rst',
    'filter-aaaa.rst',
    'named.rst',
    'rndc-confgen.rst',
    'rndc.rst',
    'tsig-keygen.rst',
)

man1 = custom_target(
    'man1',
    build_always_stale: true,
    build_by_default: false,
    input: man1_docs,
    output: 'man1',
    install: true,
    install_dir: get_option('mandir'),
    command: [
        sphinx_build,
        sphinx_common_options,
        '-b', 'man',
        '-d', '@PRIVATE_DIR@',
        '-c', '@CURRENT_SOURCE_DIR@',
        '@CURRENT_SOURCE_DIR@',
        '@OUTPUT@',
        '@INPUT@',
    ],
)

man8 = custom_target(
    'man8',
    build_always_stale: true,
    build_by_default: false,
    input: man8_docs,
    output: 'man8',
    install: true,
    install_dir: get_option('mandir'),
    command: [
        sphinx_build,
        sphinx_common_options,
        '-b', 'man',
        '-d', '@PRIVATE_DIR@',
        '-c', '@CURRENT_SOURCE_DIR@',
        '@CURRENT_SOURCE_DIR@',
        '@OUTPUT@',
        '@INPUT@',
    ],
)

alias_target('man', man1, man8)
