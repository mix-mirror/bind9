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

from typing import List, Optional
from warnings import warn

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


@composite
def dns_names(
    draw,
    *,
    prefix: dns.name.Name = dns.name.empty,
    suffix: dns.name.Name = dns.name.root,
    min_labels: int = 1,
    max_labels: int = 128,
) -> dns.name.Name:
    """
    This is a hypothesis strategy to be used for generating DNS names with given `prefix`, `suffix`
    and with total number of labels specified by `min_labels` and `max labels`.

    For example, calling
    ```
    dns_names(
        prefix=dns.name.from_text("test"),
        suffix=dns.name.from_text("isc.org"),
        max_labels=6
    ).example()
    ```
    will result in names like `test.abc.isc.org.` or `test.abc.def.isc.org`.

    There is no attempt to make the distribution of the generated names uniform in any way.
    The strategy however minimizes towards shorter names with shorter labels.

    It can be used with to build compound strategies, like this one which generates random DNS queries.

    ```
    dns_queries = builds(
        dns.message.make_query,
        qname=dns_names(),
        rdtype=dns_rdatatypes,
        rdclass=dns_rdataclasses,
    )
    ```
    """

    prefix = prefix.relativize(dns.name.root)
    suffix = suffix.derelativize(dns.name.root)

    try:
        outer_name = prefix + suffix
        remaining_bytes = 255 - isctest.name.len_wire_uncompressed(outer_name)
        assert remaining_bytes >= 0
    except dns.name.NameTooLong:
        warn(
            "Maximal length name of name execeeded by prefix and suffix. Strategy won't generate any names.",
            RuntimeWarning,
        )
        return draw(nothing())

    minimum_number_of_labels_to_generate = max(0, min_labels - len(outer_name.labels))
    maximum_number_of_labels_to_generate = max_labels - len(outer_name.labels)
    if maximum_number_of_labels_to_generate < 0:
        warn(
            "Maximal number of labels execeeded by prefix and suffix. Strategy won't generate any names.",
            RuntimeWarning,
        )
        return draw(nothing())

    maximum_number_of_labels_to_generate = min(
        maximum_number_of_labels_to_generate, remaining_bytes // 2
    )
    if maximum_number_of_labels_to_generate < minimum_number_of_labels_to_generate:
        warn(
            f"Minimal number set to {minimum_number_of_labels_to_generate}, but in {remaining_bytes} bytes there is only space for maximum of {maximum_number_of_labels_to_generate} labels.",
            RuntimeWarning,
        )
        return draw(nothing())

    if remaining_bytes == 0 or maximum_number_of_labels_to_generate == 0:
        warn(
            f"Strategy will return only one name ({outer_name}) as it exactly matches byte or label length limit.",
            RuntimeWarning,
        )
        return draw(just(outer_name))

    chosen_number_of_labels_to_generate = draw(
        integers(
            minimum_number_of_labels_to_generate, maximum_number_of_labels_to_generate
        )
    )
    chosen_number_of_bytes_to_partion = draw(
        integers(2 * chosen_number_of_labels_to_generate, remaining_bytes)
    )
    chosen_lengths_of_labels = draw(
        _partition_bytes_to_labels(
            chosen_number_of_bytes_to_partion, chosen_number_of_labels_to_generate
        )
    )
    generated_labels = tuple(
        draw(binary(min_size=l - 1, max_size=l - 1)) for l in chosen_lengths_of_labels
    )

    return dns.name.Name(prefix.labels + generated_labels + suffix.labels)


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


@composite
def _partition_bytes_to_labels(
    draw, remaining_bytes: int, number_of_labels: int
) -> List[int]:
    two_bytes_reserved_for_label = 2

    # Reserve two bytes for each label
    partition = [two_bytes_reserved_for_label] * number_of_labels
    remaining_bytes -= two_bytes_reserved_for_label * number_of_labels

    assert remaining_bytes >= 0

    # Add a random number between 0 and the remainder to each partition
    for i in range(number_of_labels):
        added = draw(
            integers(0, min(remaining_bytes, 64 - two_bytes_reserved_for_label))
        )
        partition[i] += added
        remaining_bytes -= added

    # NOTE: Some of the remaining bytes will usually not be assigned to any label, but we don't care.

    return draw(permutations(partition))


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
    if origin is None:
        origin = draw(dns_names(max_labels=125))

    zone_names = dns_names(suffix=origin)

    if auth_name is None:
        auth_name = draw(zone_names).relativize(origin)

    if primary_name is None:
        primary_name = draw(zone_names).relativize(origin)

    if hostmaster_name is None:
        hostmaster_name = draw(zone_names).relativize(origin)

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

    ns = dns.rdataset.Rdataset(dns.rdataclass.IN, dns.rdatatype.NS, ttl=3600)
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
