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

from itertools import groupby
from typing import List, Optional
from hypothesis import assume

from hypothesis.strategies import (
    binary,
    builds,
    composite,
    integers,
    ip_addresses,
    just,
    lists,
    nothing,
    permutations,
    sampled_from,
    SearchStrategy,
)

import dns.name
import dns.message
import dns.rdataclass
import dns.rdatatype
import dns.rdataset
import dns.rdtypes.IN.A
import dns.rdtypes.IN.AAAA
import dns.rdtypes.ANY.TXT
import dns.rdtypes.ANY.NS
import dns.rrset

import isctest.name


MAX_LABEL_BYTES = 63


@composite
def dns_names(
    draw,
    suffix: dns.name.Name = dns.name.root,
    min_labels: int = None,
    max_labels: int = 127,
    max_bytes: int = 255,
) -> dns.name.Name:
    if min_labels is None:
        min_labels = len(suffix.labels) + 1
    number_of_labels_in_suffix = len(suffix.labels)
    number_of_bytes_in_suffix = sum(len(label) + 1 for label in suffix.labels)

    assert (
        number_of_labels_in_suffix < min_labels
    ), "min_labels must be greater than the number of labels in the suffix"

    two_bytes_reserved_for_label = 2

    remaining_bytes = max_bytes - number_of_bytes_in_suffix
    remaining_labels = min(remaining_bytes // two_bytes_reserved_for_label, max_labels)

    assert remaining_labels > 0, "Not enough space to generate any additional labels"

    labels_to_generate = draw(
        integers(min_labels - number_of_labels_in_suffix, remaining_labels)
    )

    remaining_bytes -= labels_to_generate * two_bytes_reserved_for_label

    maximum_bytes_to_assign = min(
        remaining_bytes, (MAX_LABEL_BYTES - 1) * labels_to_generate
    )

    bytes_to_assign_to_labels = draw(integers(0, maximum_bytes_to_assign))
    bytes_to_generate = bytes_to_assign_to_labels + labels_to_generate
    data = draw(binary(min_size=bytes_to_generate, max_size=bytes_to_generate))

    labels = []
    i = 0
    for _ in range(labels_to_generate):
        added_length = draw(
            integers(0, max(0, min(MAX_LABEL_BYTES - 1, bytes_to_assign_to_labels)))
        )
        label_length = 1 + added_length
        labels.append(data[i : i + label_length])
        i += label_length
        bytes_to_assign_to_labels -= added_length

    labels.extend(suffix.labels)
    return dns.name.Name(labels)


RDATACLASS_MAX = RDATATYPE_MAX = 65535
try:
    dns_rdataclasses = builds(dns.rdataclass.RdataClass, integers(0, RDATACLASS_MAX))
    dns_rdatatypes = builds(dns.rdatatype.RdataType, integers(0, RDATATYPE_MAX))
except AttributeError:
    # In old dnspython versions, RDataTypes and RDataClasses are int and not enums.
    dns_rdataclasses = integers(0, RDATACLASS_MAX)  # type: ignore
    dns_rdatatypes = integers(0, RDATATYPE_MAX)  # type: ignore
dns_rdataclasses_without_meta = dns_rdataclasses.filter(dns.rdataclass.is_metaclass)

# NOTE: This should really be `dns_rdatatypes_without_meta = dns_rdatatypes_without_meta.filter(dns.rdatatype.is_metatype()`,
#       but hypothesis then complains about the filter being too strict, so it is done in a “constructive” way.
dns_rdatatypes_without_meta = integers(0, dns.rdatatype.OPT - 1) | integers(dns.rdatatype.OPT + 1, 127) | integers(256, RDATATYPE_MAX)  # type: ignore


a_rdata = builds(
    dns.rdtypes.IN.A.A,
    just(dns.rdataclass.IN),
    just(dns.rdatatype.A),
    builds(str, ip_addresses(v=4)),
)

aaaa_rdata = builds(
    dns.rdtypes.IN.AAAA.AAAA,
    just(dns.rdataclass.IN),
    just(dns.rdatatype.AAAA),
    builds(str, ip_addresses(v=6)),
)

txt_rdata = builds(
    dns.rdtypes.ANY.TXT.TXT,
    just(dns.rdataclass.IN),
    just(dns.rdatatype.TXT),
    binary(),
)

ns_rdata = builds(
    dns.rdtypes.ANY.NS.NS,
    just(dns.rdataclass.IN),
    just(dns.rdatatype.NS),
    dns_names(),
)

_rdata_strategies = {
    dns.rdatatype.A: a_rdata,
    dns.rdatatype.AAAA: aaaa_rdata,
    dns.rdatatype.TXT: txt_rdata,
    dns.rdatatype.NS: ns_rdata,
}

_supported_rdata_types = list(_rdata_strategies.keys())


@composite
def rdata(draw, type_: Optional[dns.rdatatype.RdataType] = None):
    if type_ is None:
        type_ = draw(sampled_from(_supported_rdata_types))
    try:
        return draw(_rdata_strategies[type_])
    except KeyError:
        raise ValueError(f"Unsupported RdataType {type_}")


@composite
def rdataset(
    draw,
    rdatatype: Optional[dns.rdatatype.RdataType] = None,
    rdataclass: dns.rdataclass.RdataClass = dns.rdataclass.IN,
    ttl: Optional[int] = None,
):
    if rdatatype is None:
        rdatatype = draw(sampled_from(_supported_rdata_types))

    if ttl is None:
        ttl = draw(integers(0, 0xFFFFFFFF))

    rdataset = dns.rdataset.Rdataset(rdataclass, rdatatype)

    rdatas = draw(lists(rdata(rdatatype), min_size=1))

    for rdata_ in rdatas:
        rdataset.add(rdata_)

    return rdataset


@composite
def rrset(
    draw,
    origin: dns.name.Name = dns.name.root,
    rdatatype: Optional[dns.rdatatype.RdataType] = None,
    rdataclass: dns.rdataclass.RdataClass = dns.rdataclass.IN,
    ttl: Optional[int] = None,
    name_strategy: Optional[SearchStrategy[dns.name.Name]] = None,
):
    if name_strategy is None:
        name_strategy = dns_names(suffix=origin)
    name = draw(name_strategy).relativize(origin)
    rdataset_ = draw(rdataset(rdatatype, rdataclass, ttl))
    return dns.rrset.from_rdata_list(name, rdataset_.ttl, rdatas=rdataset_)


@composite
def zones(
    draw,
    auth_ip: str,
    origin: Optional[dns.name.Name] = None,
    auth_name: Optional[dns.name.Name] = None,
    primary_name: Optional[dns.name.Name] = None,
    hostmaster_name: Optional[dns.name.Name] = None,
    serial: Optional[int] = None,
    refresh: Optional[int] = None,
    retry: Optional[int] = None,
    expire: Optional[int] = None,
    minimum: Optional[int] = None,
) -> dns.zone.Zone:
    origin = draw(dns_names(max_labels=126, max_bytes=253))

    zone_names = dns_names(suffix=origin)

    if auth_name is None:
        auth_name = draw(zone_names)
    auth_name = auth_name.relativize(origin)

    if primary_name is None:
        primary_name = draw(zone_names)
    primary_name = primary_name.relativize(origin)

    if hostmaster_name is None:
        hostmaster_name = draw(zone_names)
    hostmaster_name.relativize(origin)

    if serial is None:
        serial = draw(integers(0, 0xFFFFFFFF))

    if refresh is None:
        refresh = draw(integers(0, 0xFFFFFFFF))

    if retry is None:
        retry = draw(integers(0, 0xFFFFFFFF))

    if expire is None:
        expire = draw(integers(0, 0xFFFFFFFF))

    if minimum is None:
        minimum = draw(integers(0, 0xFFFFFFFF))

    zone = dns.zone.Zone(origin)

    soa = dns.rdataset.Rdataset(dns.rdataclass.IN, dns.rdatatype.SOA)
    soa.add(
        dns.rdtypes.ANY.SOA.SOA(
            dns.rdataclass.IN,
            dns.rdatatype.SOA,
            auth_name,
            hostmaster_name,
            serial,
            refresh,
            retry,
            expire,
            minimum,
        ),
    )

    ns = dns.rdataset.Rdataset(dns.rdataclass.IN, dns.rdatatype.NS, ttl=3600)
    ns.add(dns.rdtypes.ANY.NS.NS(dns.rdataclass.IN, dns.rdatatype.NS, auth_name))

    a = dns.rdataset.Rdataset(dns.rdataclass.IN, dns.rdatatype.A)
    a.add(dns.rdtypes.IN.A.A(dns.rdataclass.IN, dns.rdatatype.A, auth_ip))

    rrsets = draw(lists(rrset(origin=origin, name_strategy=zone_names), min_size=1))

    with zone.writer() as txn:
        txn.add(dns.name.empty, soa)
        txn.add(dns.name.empty, ns)
        txn.add(auth_name, a)
        for rrset_ in rrsets:
            txn.add(rrset_)

    return zone
