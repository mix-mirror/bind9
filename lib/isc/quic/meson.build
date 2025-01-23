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

isc_srcset.add(
    when: ngtcp2_dep,
    if_true: files(
        'ngtcp2_crypto.c',
        'ngtcp2_utils.c',
        'quic_cid_map.c',
        'quic_crypto.c',
        'quic_session_manager.c',
        'tls_quic.c',
    ),
)

if config.has('HAVE_NATIVE_BORINGSSL_QUIC_API')
    isc_srcset.add(
        files(
            'quic_interface_native.c',
        ),
    )
endif

# The QUIC compatibility layer will not work on LibreSSL
# due to purposefully broken key logging functionality
if not config.has('HAVE_LIBRESSL')
    isc_srcset.add(
        when: ngtcp2_dep,
        if_true: files(
            'quic_interface_compat.c',
            'tls_keylog_parser.c',
        ),
    )
endif
