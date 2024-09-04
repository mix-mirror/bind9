#!/usr/bin/python3

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


"""
Example property-based test for dns_name_ API.
"""

import pytest

# in FIPs mode md5 fails so we need 4.41.2 or later which does not use md5
try:
    import hashlib

    hashlib.md5(b"1234")
    pytest.importorskip("hypothesis")
except ValueError:
    pytest.importorskip("hypothesis", minversion="4.41.2")

from hypothesis import assume, example, given

pytest.importorskip("dns", minversion="2.0.0")
import dns.name

from strategies import dns_names

from _name_test_cffi import ffi
from _name_test_cffi import lib as isclibs

NULL = ffi.NULL

# MCTXP = ffi.new('isc_mem_t **')
# isclibs.isc__mem_create(MCTXP)


class ISCName:
    """dns_name_t instance with a private fixed buffer"""

    def __init__(self, from_text=None):
        self.fixedname = ffi.new("dns_fixedname_t *")
        self.name = isclibs.dns_fixedname_initname(self.fixedname)
        # self.cctx = ffi.new("dns_compress_t *")
        # self.dctx = ffi.new("dns_decompress_t *")
        self.formatbuf = ffi.new("char[1024]")  # DNS_NAME_FORMATSIZE

        if from_text is not None:
            assert (
                isclibs.dns_name_fromstring(
                    self.name, from_text.encode("ascii"), NULL, 0, NULL
                )
                == 0
            )

    def format(self):
        isclibs.dns_name_format(self.name, self.formatbuf, len(self.formatbuf))
        return ffi.string(self.formatbuf).decode("ascii")


@given(pyname=dns_names(suffix=dns.name.root))
def test_totext_fromtext_roundtrip(pyname: dns.name.Name) -> None:
    """
    text formatting and parsing roundtrip must not change the name

    dnspython to_text -> ISC from_string -> ISC format -> dnspython from_text
    """
    iscname = ISCName(from_text=str(pyname))
    assert pyname == dns.name.from_text(iscname.format())


@given(pyname=dns_names(suffix=dns.name.root))
def test_downcase(pyname: dns.name.Name) -> None:
    downcased = ISCName(from_text=str(pyname))
    assert isclibs.dns_name_hash(downcased.name)

    isclibs.dns_name_downcase(downcased.name, downcased.name, NULL)
    assert not any(
        letter.isupper() for letter in downcased.format()
    ), "downcasing removes all ASCII uppercase letters"


@given(pyname=dns_names(suffix=dns.name.root))
def test_hash_downcase(pyname: dns.name.Name) -> None:
    """downcasing must not affect hash value"""
    orig = ISCName(from_text=str(pyname))
    orig_hash = isclibs.dns_name_hash(orig.name)

    downcased = ISCName(from_text=str(pyname))
    assert isclibs.dns_name_hash(downcased.name) == orig_hash, "hash is stable"

    isclibs.dns_name_downcase(downcased.name, downcased.name, NULL)
    assert not any(
        letter.isupper() for letter in downcased.format()
    ), "downcasing actually works"

    assert pyname == dns.name.from_text(
        downcased.format()
    ), "downcasing must not change semantic value"

    downcased_hash = isclibs.dns_name_hash(downcased.name)
    assert orig_hash == downcased_hash, "downcasing must not change hash value"
